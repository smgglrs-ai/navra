use navra_core::protocol::CallToolResult;
use navra_protocol::compat::CallToolResultExt;
use navra_protocol::truncate_str;
use std::collections::{HashMap, HashSet};

use crate::flow_tools::{
    FlowContext, FlowRegistry, NodeStatus, build_run_summary, current_bb_seq,
    record_task_results_to_audit,
};

const MAX_FILE_TREE_ENTRIES: usize = 200;

fn compute_file_tree(docs_root: &Option<String>) -> String {
    if let Some(root) = docs_root {
        let root_path = std::path::Path::new(root);
        if root_path.is_dir() {
            let mut files = Vec::new();
            fn collect(
                dir: &std::path::Path,
                root: &std::path::Path,
                files: &mut Vec<String>,
                limit: usize,
            ) {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    return;
                };
                for entry in entries.flatten() {
                    if files.len() >= limit {
                        return;
                    }
                    let path = entry.path();
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with('.')
                        || name_str == "target"
                        || name_str == "node_modules"
                        || name_str == ".git"
                    {
                        continue;
                    }
                    if path.is_dir() {
                        collect(&path, root, files, limit);
                    } else if path.is_file()
                        && let Ok(rel) = path.strip_prefix(root)
                    {
                        files.push(format!("  {}", rel.display()));
                    }
                }
            }
            collect(root_path, root_path, &mut files, MAX_FILE_TREE_ENTRIES);
            let total = files.len();
            files.sort();
            if total >= MAX_FILE_TREE_ENTRIES {
                format!(
                    "{total}+ files (truncated, use list_directory for full listing):\n{}",
                    files.join("\n")
                )
            } else {
                format!("{total} files:\n{}", files.join("\n"))
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn poll_tasks_until_done(
    team_reg: &std::sync::Arc<crate::team_tools::TeamRegistry>,
    flow_reg: &std::sync::Arc<FlowRegistry>,
    team_id: &str,
    flow_id: &str,
    running_ids: &[String],
    completed: &mut HashMap<String, String>,
    failed: &mut HashSet<String>,
    timeout_secs: u64,
) -> Result<(), String> {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let mut all_done = true;
        for task_id in running_ids {
            if completed.contains_key(task_id) || failed.contains(task_id) {
                continue;
            }
            let status = team_reg.get_teammate_status(team_id, task_id);
            match status.as_deref() {
                Some("done") => {
                    let output = team_reg
                        .get_teammate_output(team_id, task_id)
                        .unwrap_or_else(|| "(no output)".to_string());
                    completed.insert(task_id.clone(), output.clone());
                    flow_reg.update_node_status(flow_id, task_id, "done", Some(output));
                    tracing::info!(flow_id = %flow_id, task = %task_id, "Flow task completed");
                }
                Some("failed") => {
                    let output = team_reg
                        .get_teammate_output(team_id, task_id)
                        .unwrap_or_else(|| "(no output)".to_string());
                    failed.insert(task_id.clone());
                    flow_reg.update_node_status(flow_id, task_id, "failed", Some(output));
                    tracing::warn!(flow_id = %flow_id, task = %task_id, "Flow task failed");
                }
                _ => {
                    all_done = false;
                }
            }
        }
        if all_done {
            return Ok(());
        }

        // Check flow-level timeout
        if flow_reg
            .get_status(flow_id)
            .and_then(|s| s["elapsed_secs"].as_u64())
            .unwrap_or(0)
            > timeout_secs
        {
            return Err(format!("Flow timed out after {timeout_secs} seconds"));
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_and_track_tasks(
    ctx: &FlowContext,
    team_id: &str,
    flow_id: &str,
    ready: &[&navra_flow::TaskDefinition],
    completed: &HashMap<String, String>,
    failed: &HashSet<String>,
    prompt: &str,
    project_file_tree: &str,
) -> (Vec<String>, HashMap<String, String>, HashSet<String>) {
    let new_completed = HashMap::new();
    let mut new_failed = HashSet::new();
    let mut spawned_ids = Vec::new();

    for task in ready {
        let model = task.model.clone().unwrap_or_else(|| "auto".to_string());
        let persona = if task.specialist.is_empty() {
            None
        } else {
            Some(task.specialist.clone())
        };

        let ops = task.operations.clone().unwrap_or_else(|| {
            crate::team_tools::DEFAULT_OPERATIONS
                .iter()
                .map(|s| s.to_string())
                .collect()
        });
        let tools = task
            .tools
            .clone()
            .unwrap_or_else(|| ctx.team_registry.default_tools_for_operations(&ops));

        if let Err(e) = ctx.team_registry.add_teammate(
            team_id,
            &task.id,
            persona.as_deref(),
            &model,
            "local",
            ops,
            tools,
            task.temperature,
            task.max_tokens,
            task.force_tool_iterations,
        ) {
            tracing::error!(task = %task.id, error = %e, "Failed to add teammate for flow task");
            new_failed.insert(task.id.clone());
            ctx.flow_registry
                .update_node_status(flow_id, &task.id, "failed", Some(e));
            continue;
        }

        // Detect synthesizer tasks for special handling
        let is_synthesizer = task.specialist == "synthesizer"
            || task.specialist == "summarizer"
            || task.id == "synthesize"
            || task.id == "synthesizer";

        // Build the task message with dependency context.
        let mut message = task.mandate.clone();

        // Inject structured output requirement for specialist tasks.
        let is_specialist =
            !task.generates_tasks && !is_synthesizer && task.id != "scout" && task.id != "verify";
        if is_specialist {
            message.push_str(concat!(
                "\n\nOutput ONLY a JSON array of findings. Each finding:\n",
                "{\"file\": \"path\", \"line\": N, \"severity\": \"high|medium|low\",\n",
                " \"issue\": \"one sentence\", \"evidence\": \"quoted code or fact\"}\n",
                "If no issues found, output []. Do NOT describe the code.\n",
                "Do NOT ask questions. Do NOT offer help.",
            ));
        }

        let dep_count = task.depends_on.len();
        if dep_count > 0 {
            if is_synthesizer && dep_count > 5 {
                message.push_str(&format!(
                    "\n\n--- Specialist tasks completed ({dep_count} total) ---\n\
                     Specialist outputs are published to the team blackboard.\n\
                     Use team_bb_read to read each specialist's findings.\n\
                     Your team_id is available in your context.\n\n\
                     Available findings:\n"
                ));
                for dep_id in &task.depends_on {
                    if completed.contains_key(dep_id) {
                        message.push_str(&format!("- findings/{dep_id}: completed\n"));
                    } else if failed.contains(dep_id) {
                        message.push_str(&format!("- {dep_id}: FAILED (no output)\n"));
                    }
                }
                message.push_str(
                    "\nRead each finding from the blackboard, then write a comprehensive report.\n",
                );
            } else {
                message.push_str(&format!(
                    "\n\n--- Context from prior stages ({dep_count} outputs) ---\n\
                     Read from the team blackboard using team_bb_read:\n"
                ));
                for dep_id in &task.depends_on {
                    if completed.contains_key(dep_id) {
                        message.push_str(&format!("- findings/{dep_id}\n"));
                    } else if failed.contains(dep_id) {
                        message.push_str(&format!("- {dep_id}: FAILED\n"));
                    }
                }
            }
        }
        if !prompt.is_empty() {
            message.push_str(&format!("\n\n--- Original request ---\n{}\n", prompt));
        }
        if !project_file_tree.is_empty() && !task.generates_tasks {
            let max_tree_chars = 2000;
            let tree_slice = if project_file_tree.len() > max_tree_chars {
                let truncated = truncate_str(project_file_tree, max_tree_chars);
                if let Some(nl) = truncated.rfind('\n') {
                    &truncated[..nl]
                } else {
                    truncated
                }
            } else {
                project_file_tree
            };
            message.push_str(&format!(
                "\n\n--- Project files (verified, use file_tree for full list) ---\n{}\n\nUse file_read to read files. Use file_tree if you need the full listing.",
                tree_slice
            ));
        }

        if let Err(e) = ctx.team_registry.send_message(team_id, &task.id, &message) {
            tracing::error!(task = %task.id, error = %e, "Failed to send message to flow task");
            new_failed.insert(task.id.clone());
            ctx.flow_registry
                .update_node_status(flow_id, &task.id, "failed", Some(e));
            continue;
        }

        let spawn_ctx = crate::team_tools::TeammateSpawnContext {
            team_registry: std::sync::Arc::clone(&ctx.team_registry),
            navra_addr: ctx.navra_addr.clone(),
            signer: std::sync::Arc::clone(&ctx.signer),
            forge: ctx.forge.clone(),
            root_payload: ctx.root_payload.clone(),
            pii_filter: ctx.pii_filter.clone(),
            audit_log: ctx.audit_log.clone(),
            cognitive_core_path: ctx.cognitive_core_path.clone(),
            model_server_url: ctx.model_server_url.clone(),
            gpu_semaphore: std::sync::Arc::clone(&ctx.gpu_semaphore),
            containerized: ctx.containerized,
            agent_image: ctx.agent_image.clone(),
            container_memory: ctx.container_memory.clone(),
            container_cpus: ctx.container_cpus.clone(),
            container_pids: ctx.container_pids,
            embedding_model: ctx.embedding_model.clone(),
            openshell_gateway: ctx.openshell_gateway.clone(),
            exec_state: ctx.exec_state.clone(),
            workspace_provider: ctx.workspace_provider.clone(),
            max_tokens_per_run: ctx.budget_cfg.max_tokens_per_run,
            compression_start_ratio: ctx.budget_cfg.compression_start_ratio,
            compaction_keep_recent: ctx.budget_cfg.compaction_keep_recent,
            compaction_trigger_ratio: ctx.budget_cfg.compaction_trigger_ratio,
            compression_policy: ctx.budget_cfg.compression_policy,
            kubernetes: ctx.kubernetes.clone(),
        };
        let per_task_iters = if is_synthesizer && dep_count > 2 {
            dep_count.min(30)
        } else {
            (ctx.budget_cfg.max_iterations / ready.len().max(1)).max(10)
        };
        let handle = crate::team_tools::spawn_teammate_agent(
            &spawn_ctx,
            team_id,
            &task.id,
            &message,
            per_task_iters,
            ctx.budget_cfg.timeout_secs,
            task.generates_tasks,
        );
        ctx.team_registry.store_handle(team_id, &task.id, handle);

        ctx.flow_registry
            .update_node_status(flow_id, &task.id, "running", None);
        if let Some(ref audit) = ctx.audit_log {
            let _ = audit.record_flow_task_start(flow_id, &task.id, Some(&task.specialist));
        }
        tracing::info!(flow_id = %flow_id, task = %task.id, model = %model, "Flow task started");
        spawned_ids.push(task.id.clone());

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    (spawned_ids, new_completed, new_failed)
}

pub(crate) async fn handle_flow_start(
    args: serde_json::Value,
    ctx: std::sync::Arc<FlowContext>,
    agent_name: &str,
) -> CallToolResult {
    let prompt = match args.get("prompt").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return CallToolResult::error_msg("Missing required parameter: prompt"),
    };

    let params: HashMap<String, String> = args
        .get("parameters")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    // Resolve the flow YAML: either by name (from flow_dirs) or inline
    let yaml_content = if let Some(name) = args.get("flow_name").and_then(|v| v.as_str()) {
        // Reject path traversal: only allow alphanumeric, hyphens, underscores
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return CallToolResult::error_msg(
                "Invalid flow_name: only alphanumeric characters, hyphens, and underscores are allowed",
            );
        }
        let mut found = None;
        for dir in &ctx.flow_dirs {
            let expanded = crate::util::expand_tilde(dir);
            let path = std::path::Path::new(&expanded);
            for ext in &["yaml", "yml"] {
                let file = path.join(format!("{name}.{ext}"));
                if file.exists() {
                    match std::fs::read_to_string(&file) {
                        Ok(c) => {
                            found = Some(c);
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(path = %file.display(), error = %e, "Cannot read flow file");
                        }
                    }
                }
            }
            if found.is_some() {
                break;
            }
        }
        match found {
            Some(c) => c,
            None => {
                return CallToolResult::error_msg(format!(
                    "Flow '{name}' not found in flow_dirs. Use flow_list to see available flows."
                ));
            }
        }
    } else if let Some(def) = args.get("flow_definition").and_then(|v| v.as_str()) {
        def.to_string()
    } else {
        return CallToolResult::error_msg(
            "Provide either flow_name (from flow_list) or flow_definition (inline YAML)",
        );
    };

    // Parse the YAML flow
    let dag_config = match navra_flow::yaml_loader::load_flow_yaml(&yaml_content, &params) {
        Ok(d) => d,
        Err(e) => return CallToolResult::error_msg(format!("Invalid flow YAML: {e}")),
    };

    // Apply default_model override
    let default_model = args
        .get("default_model")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");
    let mut dag_config = dag_config;
    if default_model != "auto" {
        for task in &mut dag_config.tasks {
            if task.model.is_none() || task.model.as_deref() == Some("auto") {
                task.model = Some(default_model.to_string());
            }
        }
    }

    let flow_id = ctx.flow_registry.register(&dag_config.name);

    // Persist flow metadata for resumability
    if let Some(ref audit) = ctx.audit_log {
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        let _ = audit.save_flow_metadata(
            &flow_id,
            &dag_config.name,
            Some(&yaml_content),
            Some(&params_json),
        );
    }

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

    // Create a team for this flow
    let team_budget = crate::team_tools::TeamBudget {
        max_agents: ctx
            .budget_cfg
            .max_agents
            .max(dag_config.tasks.len() as u32 + 2),
        max_depth: ctx.budget_cfg.max_depth,
        max_iterations: ctx.budget_cfg.max_iterations,
        timeout_secs: ctx.budget_cfg.timeout_secs.max(600),
        ..Default::default()
    };
    let team_id = match ctx.team_registry.create_team(
        &dag_config.name,
        dag_config.description.as_deref(),
        agent_name,
        0,
        team_budget,
    ) {
        Ok(id) => id,
        Err(e) => {
            ctx.flow_registry.fail(&flow_id, e.clone());
            return CallToolResult::error_msg(format!("Failed to create flow team: {e}"));
        }
    };
    ctx.flow_registry.set_team_id(&flow_id, &team_id);

    tracing::info!(flow_id = %flow_id, name = %dag_config.name, team_id = %team_id, "Flow started");

    let final_output = run_dag_execution(
        &ctx,
        &flow_id,
        &team_id,
        &prompt,
        dag_config.tasks,
        default_model,
    )
    .await;

    // Mark flow complete in metadata
    if let Some(ref audit) = ctx.audit_log {
        let _ = audit.complete_flow_metadata(&flow_id, "completed");
    }

    CallToolResult::text(format!(
        "Flow completed.\nflow_id: {flow_id}\n\n{final_output}"
    ))
}

pub(crate) async fn run_dag_execution(
    ctx: &FlowContext,
    flow_id: &str,
    team_id: &str,
    prompt: &str,
    mut task_defs: Vec<navra_flow::TaskDefinition>,
    default_model: &str,
) -> String {
    let mut completed: HashMap<String, String> = HashMap::new();
    let mut failed: HashSet<String> = HashSet::new();
    let mut total = task_defs.len();

    let gpu_handle = ctx.audit_log.as_ref().map(|audit| {
        spawn_gpu_sampler(
            std::sync::Arc::clone(audit),
            flow_id.to_string(),
            std::time::Duration::from_secs(5),
        )
    });

    let project_file_tree = compute_file_tree(&ctx.docs_root);
    let bb_start_seq = current_bb_seq();
    let max_parallel = ctx.budget_cfg.max_parallel;

    loop {
        let mut ready: Vec<navra_flow::TaskDefinition> = task_defs
            .iter()
            .filter(|t| {
                !completed.contains_key(&t.id)
                    && !failed.contains(&t.id)
                    && t.depends_on
                        .iter()
                        .all(|dep| completed.contains_key(dep) || failed.contains(dep))
            })
            .cloned()
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
                    "Flow deadlocked: tasks {:?} blocked by unresolved dependencies",
                    remaining
                );
                tracing::error!(flow_id = %flow_id, "{msg}");
                ctx.flow_registry.fail(flow_id, msg.clone());
                let _ = ctx.team_registry.shutdown(team_id);
                return msg;
            }
            break;
        }

        // Throttle: limit concurrent tasks
        if max_parallel > 0 && ready.len() > max_parallel {
            ready.truncate(max_parallel);
        }

        // Spawn ready tasks as teammates
        let ready_refs: Vec<&navra_flow::TaskDefinition> = ready.iter().collect();
        let (spawned_ids, _, spawn_failed) = spawn_and_track_tasks(
            ctx,
            team_id,
            flow_id,
            &ready_refs,
            &completed,
            &failed,
            prompt,
            &project_file_tree,
        )
        .await;
        failed.extend(spawn_failed);

        // Poll until all currently running tasks complete
        match poll_tasks_until_done(
            &ctx.team_registry,
            &ctx.flow_registry,
            team_id,
            flow_id,
            &spawned_ids,
            &mut completed,
            &mut failed,
            3600, // 60 minute timeout for large flows
        )
        .await
        {
            Ok(()) => {}
            Err(msg) => {
                tracing::warn!(flow_id = %flow_id, "{}", msg);
                ctx.flow_registry.fail(flow_id, msg.clone());
                let _ = ctx.team_registry.shutdown(team_id);
                return msg;
            }
        }

        // Persist completed/failed task results to audit log
        record_task_results_to_audit(
            &ctx.audit_log,
            &ctx.team_registry,
            team_id,
            flow_id,
            &spawned_ids,
            &completed,
            &failed,
            &task_defs,
        );

        // Save checkpoint after each batch for crash resilience
        if let Some(ref cp) = ctx.checkpoint {
            let remaining: Vec<navra_flow::TaskDefinition> = task_defs
                .iter()
                .filter(|t| !completed.contains_key(&t.id) && !failed.contains(&t.id))
                .cloned()
                .collect();
            let state = navra_flow::CheckpointState {
                flow_id: flow_id.to_string(),
                completed: completed.clone(),
                failed: failed.clone(),
                task_defs: remaining,
                team_id: team_id.to_string(),
                prompt: prompt.to_string(),
                idempotency_cache: HashMap::new(),
            };
            if let Err(e) = cp.save(&state) {
                tracing::warn!(flow_id = %flow_id, error = %e, "Failed to save checkpoint");
            } else {
                tracing::debug!(flow_id = %flow_id, "Checkpoint saved");
            }
        }

        // Auto-publish specialist outputs to the team blackboard
        for task_id in &spawned_ids {
            if let Some(output) = completed.get(task_id) {
                let label = {
                    let teams = ctx
                        .team_registry
                        .teams
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    teams
                        .get(team_id)
                        .and_then(|t| t.teammates.get(task_id))
                        .map(|_| navra_core::protocol::label::DataLabel::UNTRUSTED_PUBLIC)
                        .unwrap_or(navra_core::protocol::label::DataLabel::UNTRUSTED_PUBLIC)
                };
                ctx.team_registry.bb_publish(
                    team_id,
                    &format!("findings/{task_id}"),
                    output,
                    task_id,
                    label,
                );
            }
        }

        // Dynamic task injection
        for task in &ready {
            if !task.generates_tasks {
                continue;
            }
            let output = match completed.get(&task.id) {
                Some(o) => o.clone(),
                None => continue,
            };
            let mut new_tasks = navra_flow::parse_planner_tasks(&output);
            if new_tasks.is_empty() {
                tracing::warn!(
                    flow_id = %flow_id, task = %task.id,
                    "Planner output not parseable as JSON tasks, retrying with correction"
                );
                let correction_prompt = format!(
                    "Your previous output was not valid JSON. Here is what you wrote:\n\n\
                     {output}\n\n\
                     Fix this to be ONLY a JSON array of task objects. Each object must have \
                     \"id\" (string), \"specialist\" (string), and \"mandate\" (string). \
                     Optional: \"model\" (string). Output ONLY the JSON array, nothing else."
                );
                let correction_model = task
                    .model
                    .clone()
                    .unwrap_or_else(|| "gemma4:26b".to_string());
                let mcp_url = format!("http://{}/mcp", ctx.navra_addr);
                match navra_agent::Agent::builder()
                    .endpoint(&mcp_url)
                    .await
                    .map(|b| {
                        b.model(navra_model::OpenAiBackend::new(
                            "http://localhost:11434/v1",
                            &correction_model,
                            None,
                            navra_model::Locality::Local,
                        ))
                        .system_prompt(
                            "You output ONLY valid JSON arrays. No markdown, no explanation.",
                        )
                        .max_iterations(0)
                        .max_tokens(8192)
                        .temperature(0.0)
                    }) {
                    Ok(builder) => {
                        if let Ok(mut agent) = builder.build().await
                            && let Ok(result) = agent.run(&correction_prompt).await
                        {
                            new_tasks = navra_flow::parse_planner_tasks(&result.response);
                            if !new_tasks.is_empty() {
                                tracing::info!(
                                    flow_id = %flow_id, count = new_tasks.len(),
                                    "Planner retry succeeded"
                                );
                            }
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "Correction agent build failed"),
                }
                if new_tasks.is_empty() {
                    tracing::warn!(
                        flow_id = %flow_id, task = %task.id,
                        "Planner retry also failed — no dynamic tasks injected"
                    );
                    continue;
                }
            }
            let new_ids: Vec<String> = new_tasks.iter().map(|t| t.id.clone()).collect();
            tracing::info!(
                flow_id = %flow_id,
                planner = %task.id,
                injected = new_ids.len(),
                tasks = ?new_ids,
                "Injecting dynamic tasks from planner"
            );

            for mut new_task in new_tasks {
                if default_model != "auto"
                    && (new_task.model.is_none() || new_task.model.as_deref() == Some("auto"))
                {
                    new_task.model = Some(default_model.to_string());
                }
                if new_task.depends_on.is_empty() {
                    new_task.depends_on.push(task.id.clone());
                }
                if !project_file_tree.is_empty() {
                    new_task.mandate.push_str(
                        &format!("\n\n--- Project files (verified) ---\n{project_file_tree}\n\nUse ONLY paths from this list with file_read.")
                    );
                }
                ctx.flow_registry.update_nodes(
                    flow_id,
                    vec![NodeStatus {
                        id: new_task.id.clone(),
                        specialist: new_task.specialist.clone(),
                        status: "pending".to_string(),
                        output: None,
                        started_at: None,
                        completed_at: None,
                    }],
                );
                task_defs.push(new_task);
            }

            for td in task_defs.iter_mut() {
                if td.id == "synthesize" || td.id == "synthesizer" || td.id == "verify" {
                    for nid in &new_ids {
                        if !td.depends_on.contains(nid) {
                            td.depends_on.push(nid.clone());
                        }
                    }
                }
            }

            total = task_defs.len();
        }
    }

    // Flow complete — find the last task's output as the final result
    let last_task_id = task_defs.last().map(|t| t.id.as_str()).unwrap_or("");
    let mut final_output = completed.get(last_task_id).cloned().unwrap_or_else(|| {
        format!(
            "Flow completed. {} tasks done, {} failed.",
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
        team_id,
        &ctx.flow_registry,
        flow_id,
        &task_defs,
        &completed,
        &failed,
        bb_start_seq,
    );
    final_output.push_str(&summary);

    // Delete checkpoint on successful completion
    if let Some(ref cp) = ctx.checkpoint {
        if let Err(e) = cp.delete(flow_id) {
            tracing::warn!(flow_id = %flow_id, error = %e, "Failed to delete checkpoint");
        } else {
            tracing::debug!(flow_id = %flow_id, "Checkpoint deleted (flow complete)");
        }
    }

    if let Some(handle) = gpu_handle {
        handle.abort();
    }

    ctx.flow_registry.complete(flow_id, final_output.clone());
    let _ = ctx.team_registry.shutdown(team_id);
    tracing::info!(
        flow_id = %flow_id,
        completed = completed.len(),
        failed = failed.len(),
        "Flow execution finished"
    );
    final_output
}

pub(crate) fn spawn_gpu_sampler(
    audit_log: std::sync::Arc<navra_memory::AuditLog>,
    flow_id: String,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            match sample_gpu().await {
                Some((gpu, mem, used)) => {
                    if let Err(e) = audit_log.record_gpu_sample(&flow_id, gpu, mem, used) {
                        tracing::debug!(error = %e, "Failed to record GPU sample");
                    }
                }
                None => {
                    tracing::debug!("nvidia-smi not available, stopping GPU sampler");
                    break;
                }
            }
        }
    })
}

async fn sample_gpu() -> Option<(f64, f64, f64)> {
    let output = tokio::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=utilization.gpu,utilization.memory,memory.used",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout
        .lines()
        .next()?
        .split(',')
        .map(|s| s.trim())
        .collect();
    if parts.len() < 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}
