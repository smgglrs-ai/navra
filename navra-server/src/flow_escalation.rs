use navra_core::protocol::CallToolResult;
use navra_protocol::compat::CallToolResultExt;
use std::collections::{HashMap, HashSet};

use crate::flow_execution::{poll_tasks_until_done, run_dag_execution};
use crate::flow_tools::{
    build_run_summary, current_bb_seq, record_task_results_to_audit, FlowContext, NodeStatus,
};

pub(crate) async fn handle_flow_escalate(
    args: serde_json::Value,
    ctx: std::sync::Arc<FlowContext>,
    agent_name: &str,
) -> CallToolResult {
    let mandate = match args.get("mandate").and_then(|v| v.as_str()) {
        Some(m) => m.to_string(),
        None => return CallToolResult::error_msg("Missing required parameter: mandate"),
    };

    // Bound mandate length to prevent context stuffing
    const MAX_MANDATE_LEN: usize = 10_000;
    if mandate.len() > MAX_MANDATE_LEN {
        return CallToolResult::error_msg(format!(
            "Mandate too long ({} chars, max {MAX_MANDATE_LEN}). Summarize your request.",
            mandate.len()
        ));
    }

    let context = args
        .get("context")
        .and_then(|v| v.as_str())
        .map(String::from);
    if let Some(ref ctx_text) = context
        && ctx_text.len() > MAX_MANDATE_LEN
    {
        return CallToolResult::error_msg(format!(
            "Context too long ({} chars, max {MAX_MANDATE_LEN}). Summarize your context.",
            ctx_text.len()
        ));
    }

    // Extract depth and model from calling agent's team
    let caller_did = agent_name;
    let (current_depth, caller_model): (u32, Option<String>) = {
        let teams = ctx
            .team_registry
            .teams
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut depth = 0u32;
        let mut model = None;
        for team in teams.values() {
            if let Some(tm) = team.teammates.get(caller_did) {
                depth = team.depth;
                model = Some(tm.model.clone());
                break;
            }
            if team.lead == *caller_did || caller_did.contains(&team.team_id) {
                depth = team.depth;
                break;
            }
        }
        (depth, model)
    };

    // Check depth limit from team budget
    let max_depth = {
        let teams = ctx
            .team_registry
            .teams
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        teams
            .values()
            .find(|t| {
                t.teammates.contains_key(caller_did)
                    || t.lead == *caller_did
                    || caller_did.contains(&t.team_id)
            })
            .map(|t| t.budget.max_depth)
            .unwrap_or(2)
    };

    let new_depth = current_depth + 1;
    if new_depth > max_depth {
        return CallToolResult::error_msg(format!(
            "Escalation depth limit reached ({new_depth}/{max_depth}). \
             Cannot create deeper subflows. Handle this task directly."
        ));
    }

    // Build the DagConfig
    let dag_config = if let Some(tasks_val) = args.get("tasks").and_then(|v| v.as_array()) {
        let mut task_defs = Vec::new();
        for t in tasks_val {
            let id = match t.get("id").and_then(|v| v.as_str()) {
                Some(id) => id.to_string(),
                None => return CallToolResult::error_msg("Each task must have an 'id'"),
            };
            let specialist = match t.get("specialist").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => return CallToolResult::error_msg("Each task must have a 'specialist'"),
            };
            let task_mandate = match t.get("mandate").and_then(|v| v.as_str()) {
                Some(m) => m.to_string(),
                None => return CallToolResult::error_msg("Each task must have a 'mandate'"),
            };
            let model = t
                .get("model")
                .and_then(|v| v.as_str())
                .map(String::from)
                .or_else(|| caller_model.clone());
            let depends_on: Vec<String> = t
                .get("depends_on")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            task_defs.push(navra_flow::TaskDefinition {
                id,
                specialist,
                model,
                mandate: task_mandate,
                depends_on,
                expected_output: None,
                success_criteria: Vec::new(),
                back_edges: Vec::new(),
                generates_tasks: false,
                verification: None,
                tools: None,
                operations: None,
                temperature: None,
                max_tokens: None,
                force_tool_iterations: None,
                approval_required: false,
            });
        }
        navra_flow::DagConfig {
            name: format!("escalation-depth{new_depth}"),
            description: Some(format!("Escalation subflow for: {mandate}")),
            parameters: HashMap::new(),
            tasks: task_defs,
            blackboard_capacity: None,
        }
    } else {
        navra_flow::generic_flow_dag(&mandate, context.as_deref())
    };

    // Register subflow
    let parent_flow_id = {
        let flows = ctx
            .flow_registry
            .flows
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        flows
            .values()
            .find(|f| {
                if let Some(ref tid) = f.team_id {
                    caller_did.contains(tid)
                } else {
                    false
                }
            })
            .map(|f| f.flow_id.clone())
            .unwrap_or_else(|| "unknown".to_string())
    };
    let flow_id = ctx
        .flow_registry
        .register_subflow(&dag_config.name, &parent_flow_id, new_depth);

    // Initialize node statuses
    let nodes: Vec<NodeStatus> = dag_config
        .tasks
        .iter()
        .map(|t| NodeStatus {
            id: t.id.clone(),
            specialist: t.specialist.clone(),
            status: "pending".to_string(),
            output: None,
            started_at: None,
            completed_at: None,
        })
        .collect();
    ctx.flow_registry.update_nodes(&flow_id, nodes);

    // Create a sub-team for this subflow
    let team_budget = crate::team_tools::TeamBudget {
        max_depth,
        max_agents: ctx
            .budget_cfg
            .max_agents
            .max(dag_config.tasks.len() as u32 + 2),
        max_iterations: ctx.budget_cfg.max_iterations,
        timeout_secs: ctx.budget_cfg.timeout_secs.max(600),
        ..Default::default()
    };
    let team_id = match ctx.team_registry.create_team(
        &dag_config.name,
        dag_config.description.as_deref(),
        caller_did,
        new_depth,
        team_budget,
    ) {
        Ok(id) => id,
        Err(e) => {
            ctx.flow_registry.fail(&flow_id, e.clone());
            return CallToolResult::error_msg(format!("Failed to create subflow team: {e}"));
        }
    };
    ctx.flow_registry.set_team_id(&flow_id, &team_id);

    tracing::info!(
        flow_id = %flow_id,
        parent = %parent_flow_id,
        depth = new_depth,
        name = %dag_config.name,
        team_id = %team_id,
        "Subflow escalation started"
    );

    // Execute the DAG synchronously (same logic as flow_start but awaited)
    let task_defs = dag_config.tasks;
    let mut completed: HashMap<String, String> = HashMap::new();
    let mut failed: HashSet<String> = HashSet::new();
    let total = task_defs.len();

    let bb_start_seq = current_bb_seq();

    loop {
        let ready: Vec<&navra_flow::TaskDefinition> = task_defs
            .iter()
            .filter(|t| {
                !completed.contains_key(&t.id)
                    && !failed.contains(&t.id)
                    && t.depends_on
                        .iter()
                        .all(|dep| completed.contains_key(dep) || failed.contains(dep))
            })
            .collect();

        if ready.is_empty() {
            if completed.len() + failed.len() >= total {
                break;
            }
            let remaining: Vec<&str> = task_defs
                .iter()
                .filter(|t| !completed.contains_key(&t.id) && !failed.contains(&t.id))
                .map(|t| t.id.as_str())
                .collect();
            if !remaining.is_empty() {
                let msg = format!(
                    "Subflow deadlocked: tasks {:?} blocked by unresolved dependencies",
                    remaining
                );
                tracing::error!(flow_id = %flow_id, "{msg}");
                ctx.flow_registry.fail(&flow_id, msg.clone());
                let _ = ctx.team_registry.shutdown(&team_id);
                return CallToolResult::error_msg(msg);
            }
            break;
        }

        // Throttle: limit concurrent tasks in subflows too
        let max_parallel = ctx.budget_cfg.max_parallel;
        let throttled: Vec<&navra_flow::TaskDefinition> =
            if max_parallel > 0 && ready.len() > max_parallel {
                ready.into_iter().take(max_parallel).collect()
            } else {
                ready
            };

        // Spawn ready tasks as teammates
        let (spawned_ids, _, spawn_failed) = crate::flow_execution::spawn_and_track_tasks(
            ctx.as_ref(),
            &team_id,
            &flow_id,
            &throttled,
            &completed,
            &failed,
            "",
            "", // no prompt or file tree injection for subflows
        )
        .await;
        failed.extend(spawn_failed);

        // Poll until all currently running tasks complete
        match poll_tasks_until_done(
            &ctx.team_registry,
            &ctx.flow_registry,
            &team_id,
            &flow_id,
            &spawned_ids,
            &mut completed,
            &mut failed,
            900, // 15 minute timeout for subflows
        )
        .await
        {
            Ok(()) => {}
            Err(msg) => {
                tracing::warn!(flow_id = %flow_id, "{}", msg);
                ctx.flow_registry.fail(&flow_id, msg.clone());
                let _ = ctx.team_registry.shutdown(&team_id);
                return CallToolResult::error_msg(msg);
            }
        }

        // Persist completed/failed task results to audit log
        record_task_results_to_audit(
            &ctx.audit_log,
            &ctx.team_registry,
            &team_id,
            &flow_id,
            &spawned_ids,
            &completed,
            &failed,
            &task_defs,
        );
    }

    // Subflow complete — return the last task's output
    let last_task_id = task_defs.last().map(|t| t.id.as_str()).unwrap_or("");
    let mut final_output = completed.get(last_task_id).cloned().unwrap_or_else(|| {
        format!(
            "Subflow completed. {} tasks done, {} failed.",
            completed.len(),
            failed.len()
        )
    });

    if !failed.is_empty() {
        final_output.push_str(&format!(
            "\n\n[Warning: {} of {} tasks failed: {:?}]",
            failed.len(),
            total,
            failed
        ));
    }

    // Build run summary
    let summary = build_run_summary(
        &ctx.team_registry,
        &team_id,
        &ctx.flow_registry,
        &flow_id,
        &task_defs,
        &completed,
        &failed,
        bb_start_seq,
    );
    final_output.push_str(&summary);

    ctx.flow_registry.complete(&flow_id, final_output.clone());
    let _ = ctx.team_registry.shutdown(&team_id);
    tracing::info!(
        flow_id = %flow_id,
        completed = completed.len(),
        failed_count = failed.len(),
        "Subflow execution finished"
    );
    CallToolResult::text(final_output)
}

pub(crate) async fn handle_flow_resume(
    args: serde_json::Value,
    ctx: std::sync::Arc<FlowContext>,
    agent_name: &str,
) -> CallToolResult {
    let flow_id = match args.get("flow_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return CallToolResult::error_msg("Missing required parameter: flow_id"),
    };

    // Try checkpoint first — it has the most complete state
    if let Some(ref cp) = ctx.checkpoint
        && let Ok(Some(cp_state)) = cp.load(&flow_id)
    {
        tracing::info!(
            flow_id = %flow_id,
            completed = cp_state.completed.len(),
            failed = cp_state.failed.len(),
            remaining = cp_state.task_defs.len(),
            "Resuming flow from checkpoint"
        );

        if cp_state.task_defs.is_empty() {
            return CallToolResult::text(format!(
                "Flow {flow_id} has no remaining tasks. {} completed, {} failed.",
                cp_state.completed.len(),
                cp_state.failed.len()
            ));
        }

        // Re-register the flow
        let new_flow_id = ctx.flow_registry.register(&format!("{flow_id}-resumed"));

        // Copy completed results to audit log for the new flow
        if let Some(ref audit) = ctx.audit_log {
            for (task_id, output) in &cp_state.completed {
                let _ = audit.record_flow_task(
                    &new_flow_id,
                    task_id,
                    None,
                    None,
                    "done",
                    Some(output),
                    None,
                    None,
                );
            }
        }

        // Publish completed outputs to blackboard so downstream tasks
        // can see their dependencies' results
        let team_budget = crate::team_tools::TeamBudget {
            max_agents: ctx
                .budget_cfg
                .max_agents
                .max(cp_state.task_defs.len() as u32 + 2),
            max_depth: ctx.budget_cfg.max_depth,
            max_iterations: ctx.budget_cfg.max_iterations,
            timeout_secs: ctx.budget_cfg.timeout_secs.max(600),
            ..Default::default()
        };
        let team_id = match ctx.team_registry.create_team(
            &format!("{flow_id}-resumed"),
            None,
            agent_name,
            0,
            team_budget,
        ) {
            Ok(id) => id,
            Err(e) => {
                return CallToolResult::error_msg(format!("Failed to create resume team: {e}"));
            }
        };
        ctx.flow_registry.set_team_id(&new_flow_id, &team_id);

        // Publish completed outputs to blackboard for dependency resolution
        for (task_id, output) in &cp_state.completed {
            ctx.team_registry.bb_publish(
                &team_id,
                &format!("findings/{task_id}"),
                output,
                task_id,
                navra_core::protocol::label::DataLabel::UNTRUSTED_PUBLIC,
            );
        }

        let final_output = run_dag_execution(
            &ctx,
            &new_flow_id,
            &team_id,
            &cp_state.prompt,
            cp_state.task_defs,
            "auto",
        )
        .await;

        // Clean up the old checkpoint
        let _ = cp.delete(&flow_id);

        if let Some(ref audit) = ctx.audit_log {
            let _ = audit.complete_flow_metadata(&new_flow_id, "completed");
        }

        return CallToolResult::text(format!(
            "Flow resumed from checkpoint.\nOriginal: {flow_id}\nResumed as: {new_flow_id}\n\
                 Previously completed: {} tasks\n\n{final_output}",
            cp_state.completed.len()
        ));
    }

    // Fall back to audit log recovery
    let metadata = match &ctx.audit_log {
        Some(audit) => match audit.load_flow_metadata(&flow_id) {
            Ok(Some(m)) => m,
            Ok(None) => {
                return CallToolResult::error_msg(format!(
                    "Flow {flow_id} not found in audit.db or checkpoint"
                ));
            }
            Err(e) => {
                return CallToolResult::error_msg(format!("Failed to load flow metadata: {e}"));
            }
        },
        None => {
            return CallToolResult::error_msg(
                "Audit log not configured and no checkpoint available",
            );
        }
    };

    // Load completed task results
    let completed_results = match &ctx.audit_log {
        Some(audit) => match audit.get_flow_results(&flow_id) {
            Ok(r) => r,
            Err(e) => {
                return CallToolResult::error_msg(format!("Failed to load flow results: {e}"));
            }
        },
        None => Vec::new(),
    };

    let already_done: HashMap<String, String> = completed_results
        .iter()
        .filter(|r| r.status == "done")
        .map(|r| {
            let output = r.output.clone().unwrap_or_default();
            (r.task_id.clone(), output)
        })
        .collect();

    let already_failed: HashSet<String> = completed_results
        .iter()
        .filter(|r| r.status == "failed")
        .map(|r| r.task_id.clone())
        .collect();

    // Re-parse the YAML to get the task definitions
    let yaml_content = match metadata.yaml_content {
        Some(ref y) => y.clone(),
        None => return CallToolResult::error_msg("Flow has no saved YAML content — cannot resume"),
    };

    let params: HashMap<String, String> = metadata
        .parameters
        .as_ref()
        .and_then(|p| serde_json::from_str(p).ok())
        .unwrap_or_default();

    let dag_config = match navra_flow::yaml_loader::load_flow_yaml(&yaml_content, &params) {
        Ok(c) => c,
        Err(e) => return CallToolResult::error_msg(format!("Failed to parse flow YAML: {e}")),
    };

    // Filter to only tasks not already completed
    let remaining: Vec<navra_flow::TaskDefinition> = dag_config
        .tasks
        .into_iter()
        .filter(|t| !already_done.contains_key(&t.id))
        .collect();

    if remaining.is_empty() {
        return CallToolResult::text(format!(
            "Flow {flow_id} has no remaining tasks. {} completed, {} failed.",
            already_done.len(),
            already_failed.len()
        ));
    }

    tracing::info!(
        flow_id = %flow_id,
        completed = already_done.len(),
        remaining = remaining.len(),
        "Resuming flow from audit log"
    );

    // Re-register the flow and run remaining tasks
    let new_flow_id = ctx
        .flow_registry
        .register(&format!("{}-resumed", metadata.name));

    // Copy completed results to the new flow
    if let Some(ref audit) = ctx.audit_log {
        for (task_id, output) in &already_done {
            let _ = audit.record_flow_task(
                &new_flow_id,
                task_id,
                None,
                None,
                "done",
                Some(output),
                None,
                None,
            );
        }
        let _ = audit.save_flow_metadata(
            &new_flow_id,
            &metadata.name,
            metadata.yaml_content.as_deref(),
            metadata.parameters.as_deref(),
        );
    }

    // Create team and run
    let team_budget = crate::team_tools::TeamBudget {
        max_agents: ctx.budget_cfg.max_agents.max(remaining.len() as u32 + 2),
        max_depth: ctx.budget_cfg.max_depth,
        max_iterations: ctx.budget_cfg.max_iterations,
        timeout_secs: ctx.budget_cfg.timeout_secs.max(600),
        ..Default::default()
    };
    let team_id =
        match ctx
            .team_registry
            .create_team(&metadata.name, None, agent_name, 0, team_budget)
        {
            Ok(id) => id,
            Err(e) => {
                return CallToolResult::error_msg(format!("Failed to create resume team: {e}"));
            }
        };
    ctx.flow_registry.set_team_id(&new_flow_id, &team_id);

    let prompt = format!("Resumed flow {flow_id}");
    let final_output = run_dag_execution(&ctx, &new_flow_id, &team_id, &prompt, remaining, "auto").await;

    if let Some(ref audit) = ctx.audit_log {
        let _ = audit.complete_flow_metadata(&new_flow_id, "completed");
    }

    CallToolResult::text(format!(
        "Flow resumed.\nOriginal: {flow_id}\nResumed as: {new_flow_id}\n\
         Previously completed: {} tasks\n\n{final_output}",
        already_done.len()
    ))
}
