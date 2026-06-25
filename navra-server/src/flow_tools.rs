//! MCP tools for async flow orchestration.
//!
//! Exposes `flow_start`, `flow_status`, and `flow_result` as MCP tools
//! so a planner agent can define, launch, monitor, and read results from
//! multi-agent flows — all through standard MCP tool calls.

use navra_core::protocol::{ToolDefinition};
use navra_protocol::compat::{tool_input_schema, CallToolResultExt};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Status of a flow execution.
#[derive(Debug, Clone)]
pub enum FlowRunStatus {
    Running,
    Completed,
    Failed(String),
}

/// Per-node status within a flow.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeStatus {
    pub id: String,
    pub specialist: String,
    pub status: String, // "pending", "running", "done", "failed"
    pub output: Option<String>,
    /// When the node transitioned to "running".
    #[serde(skip)]
    pub started_at: Option<Instant>,
    /// When the node transitioned to "done" or "failed".
    #[serde(skip)]
    pub completed_at: Option<Instant>,
}

/// A tracked flow execution.
#[derive(Debug)]
pub struct FlowRun {
    pub flow_id: String,
    pub name: String,
    pub status: FlowRunStatus,
    pub started_at: Instant,
    pub node_statuses: Vec<NodeStatus>,
    pub final_output: Option<String>,
    pub team_id: Option<String>,
    /// Parent flow ID for subflows (None for top-level flows).
    pub parent_flow_id: Option<String>,
    /// Nesting depth (0 for top-level flows).
    pub depth: u32,
}

/// Registry of active and completed flows.
#[derive(Default)]
pub struct FlowRegistry {
    pub(crate) flows: Mutex<HashMap<String, FlowRun>>,
}

impl FlowRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new flow and return its ID.
    pub fn register(&self, name: &str) -> String {
        let flow_id = format!(
            "flow-{}",
            uuid::Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("0")
        );

        let run = FlowRun {
            flow_id: flow_id.clone(),
            name: name.to_string(),
            status: FlowRunStatus::Running,
            started_at: Instant::now(),
            node_statuses: Vec::new(),
            final_output: None,
            team_id: None,
            parent_flow_id: None,
            depth: 0,
        };

        self.flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(flow_id.clone(), run);

        flow_id
    }

    /// Register a subflow with parent linkage and depth tracking.
    pub fn register_subflow(&self, name: &str, parent_flow_id: &str, depth: u32) -> String {
        let flow_id = format!(
            "flow-{}",
            uuid::Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("0")
        );

        let run = FlowRun {
            flow_id: flow_id.clone(),
            name: name.to_string(),
            status: FlowRunStatus::Running,
            started_at: Instant::now(),
            node_statuses: Vec::new(),
            final_output: None,
            team_id: None,
            parent_flow_id: Some(parent_flow_id.to_string()),
            depth,
        };

        self.flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(flow_id.clone(), run);

        flow_id
    }

    /// Update node statuses for a flow.
    pub fn update_nodes(&self, flow_id: &str, nodes: Vec<NodeStatus>) {
        if let Some(run) = self
            .flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(flow_id)
        {
            run.node_statuses = nodes;
        }
    }

    /// Associate a team with a flow.
    pub fn set_team_id(&self, flow_id: &str, team_id: &str) {
        if let Some(run) = self
            .flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(flow_id)
        {
            run.team_id = Some(team_id.to_string());
        }
    }

    /// Update a single node's status and output.
    ///
    /// Automatically records `started_at` when transitioning to "running"
    /// and `completed_at` when transitioning to "done" or "failed".
    pub fn update_node_status(
        &self,
        flow_id: &str,
        node_id: &str,
        status: &str,
        output: Option<String>,
    ) {
        if let Some(run) = self
            .flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(flow_id)
        {
            if let Some(node) = run.node_statuses.iter_mut().find(|n| n.id == node_id) {
                // Track timing transitions
                if status == "running" && node.started_at.is_none() {
                    node.started_at = Some(Instant::now());
                }
                if matches!(status, "done" | "failed") && node.completed_at.is_none() {
                    node.completed_at = Some(Instant::now());
                }
                node.status = status.to_string();
                if output.is_some() {
                    node.output = output;
                }
            }
        }
    }

    /// Mark a flow as completed with output.
    pub fn complete(&self, flow_id: &str, output: String) {
        if let Some(run) = self
            .flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(flow_id)
        {
            run.status = FlowRunStatus::Completed;
            run.final_output = Some(output);
        }
    }

    /// Mark a flow as failed.
    pub fn fail(&self, flow_id: &str, error: String) {
        if let Some(run) = self
            .flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(flow_id)
        {
            run.status = FlowRunStatus::Failed(error);
        }
    }

    /// Get status of a flow.
    pub fn get_status(&self, flow_id: &str) -> Option<serde_json::Value> {
        let flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        let run = flows.get(flow_id)?;
        let status_str = match &run.status {
            FlowRunStatus::Running => "running",
            FlowRunStatus::Completed => "completed",
            FlowRunStatus::Failed(_) => "failed",
        };
        Some(serde_json::json!({
            "flow_id": run.flow_id,
            "name": run.name,
            "status": status_str,
            "elapsed_secs": run.started_at.elapsed().as_secs(),
            "nodes": run.node_statuses,
            "error": match &run.status {
                FlowRunStatus::Failed(e) => Some(e.as_str()),
                _ => None,
            },
        }))
    }

    /// Build a graph JSON representation of a flow for React Flow consumption.
    ///
    /// Combines node definitions (with current status and timing) and edges
    /// inferred from the flow's node dependency chain.
    pub fn flow_graph_json(&self, flow_id: &str) -> Option<serde_json::Value> {
        let flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        let run = flows.get(flow_id)?;

        let nodes: Vec<serde_json::Value> = run
            .node_statuses
            .iter()
            .enumerate()
            .map(|(i, node)| {
                let duration_ms = match (node.started_at, node.completed_at) {
                    (Some(start), Some(end)) => {
                        Some(end.duration_since(start).as_millis() as u64)
                    }
                    (Some(start), None) => Some(start.elapsed().as_millis() as u64),
                    _ => None,
                };
                serde_json::json!({
                    "id": node.id,
                    "type": "task",
                    "label": if node.specialist.is_empty() { &node.id } else { &node.specialist },
                    "status": node.status,
                    "x": (i % 4) * 250,
                    "y": (i / 4) * 150,
                    "duration_ms": duration_ms,
                })
            })
            .collect();

        // Edges are not stored directly in FlowRun, so we produce an
        // empty edges list. Callers that need dependency edges should
        // parse the flow YAML or supply them from the DagConfig.
        Some(serde_json::json!({
            "flow_id": run.flow_id,
            "name": run.name,
            "status": match &run.status {
                FlowRunStatus::Running => "running",
                FlowRunStatus::Completed => "completed",
                FlowRunStatus::Failed(_) => "failed",
            },
            "nodes": nodes,
            "edges": [],
        }))
    }

    /// Get result of a completed flow, optionally for a specific node.
    pub fn get_result(&self, flow_id: &str, node_id: Option<&str>) -> Option<serde_json::Value> {
        let flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        let run = flows.get(flow_id)?;

        if let Some(nid) = node_id {
            // Return specific node output
            let node = run.node_statuses.iter().find(|n| n.id == nid)?;
            return Some(serde_json::json!({
                "flow_id": flow_id,
                "node": nid,
                "status": node.status,
                "output": node.output,
            }));
        }

        // Return full flow result
        Some(serde_json::json!({
            "flow_id": flow_id,
            "status": match &run.status {
                FlowRunStatus::Running => "running",
                FlowRunStatus::Completed => "completed",
                FlowRunStatus::Failed(_) => "failed",
            },
            "output": run.final_output,
            "nodes": run.node_statuses,
        }))
    }
}

/// Build a structured run summary for a completed flow or subflow.
///
/// Queries team state for timing/token data and the blackbox sqlite
/// for tool call counts. Returns a markdown block to append to the
/// flow's final output.
pub fn build_run_summary(
    team_reg: &crate::team_tools::TeamRegistry,
    team_id: &str,
    flow_reg: &FlowRegistry,
    flow_id: &str,
    task_defs: &[navra_flow::TaskDefinition],
    completed: &std::collections::HashMap<String, String>,
    failed: &std::collections::HashSet<String>,
    bb_start_seq: i64,
) -> String {
    let mut summary = String::from("\n\n---\n## Run Metrics\n");

    // Total elapsed time
    let elapsed_secs = flow_reg
        .flows
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(flow_id)
        .map(|f| f.started_at.elapsed().as_secs_f64())
        .unwrap_or(0.0);
    summary.push_str(&format!("- Total time: {:.1}s\n", elapsed_secs));

    // Agent and token counts from team
    let teams = team_reg.teams.lock().unwrap_or_else(|e| e.into_inner());
    let (agent_count, tokens_used, depth, budget) = if let Some(team) = teams.get(team_id) {
        let count = team.teammates.len();
        let tokens = team.tokens_used.load(std::sync::atomic::Ordering::Relaxed);
        (count, tokens, team.depth, team.budget.clone())
    } else {
        (0, 0, 0, crate::team_tools::TeamBudget::default())
    };

    // Count subflow agents (flows parented to this flow)
    let flows = flow_reg.flows.lock().unwrap_or_else(|e| e.into_inner());
    let subflow_count = flows
        .values()
        .filter(|f| f.parent_flow_id.as_deref() == Some(flow_id))
        .count();
    drop(flows);

    let flow_agents = task_defs.len();
    if subflow_count > 0 {
        summary.push_str(&format!(
            "- Agents spawned: {} ({} flow + {} subflow)\n",
            agent_count,
            flow_agents,
            agent_count.saturating_sub(flow_agents)
        ));
    } else {
        summary.push_str(&format!("- Agents spawned: {}\n", agent_count));
    }
    summary.push_str(&format!("- Total tokens: {}\n", tokens_used));

    // Query blackbox for tool call stats
    let bb_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/blackbox.db");
    let (total_tool_calls, files_read, tool_breakdown) = if let Ok(db) =
        rusqlite::Connection::open_with_flags(&bb_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
    {
        let total: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM blackbox WHERE seq > ?1",
                [bb_start_seq],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let files: i64 = db
            .query_row(
                "SELECT COUNT(DISTINCT tool_args) FROM blackbox WHERE seq > ?1 AND tool_name = 'file_read'",
                [bb_start_seq],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let mut breakdown: Vec<(String, i64)> = Vec::new();
        if let Ok(mut stmt) = db.prepare(
            "SELECT tool_name, COUNT(*) as cnt FROM blackbox WHERE seq > ?1 GROUP BY tool_name ORDER BY cnt DESC",
        ) {
            if let Ok(rows) = stmt.query_map([bb_start_seq], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            }) {
                for row in rows.flatten() {
                    breakdown.push(row);
                }
            }
        }

        (total, files, breakdown)
    } else {
        (0, 0, Vec::new())
    };

    if files_read > 0 {
        summary.push_str(&format!("- Files read: {} (via file_read)\n", files_read));
    }
    summary.push_str(&format!("- Tool calls: {}\n", total_tool_calls));

    // Budget usage
    summary.push_str(&format!(
        "- Budget: {}/{} agents, depth {}/{}\n",
        agent_count, budget.max_agents, depth, budget.max_depth
    ));

    // Escalations
    let flows = flow_reg.flows.lock().unwrap_or_else(|e| e.into_inner());
    let escalations: Vec<_> = flows
        .values()
        .filter(|f| f.parent_flow_id.as_deref() == Some(flow_id))
        .map(|f| (f.name.clone(), f.depth))
        .collect();
    drop(flows);

    if !escalations.is_empty() {
        let esc_list: Vec<String> = escalations
            .iter()
            .map(|(name, d)| format!("{} at depth {}", name, d))
            .collect();
        summary.push_str(&format!(
            "- Escalations: {} ({})\n",
            escalations.len(),
            esc_list.join(", ")
        ));
    }

    // Per-stage timing table
    summary.push_str("\n### Per-stage timing\n");
    summary.push_str("| Stage | Model | Time | Tokens | Status |\n");
    summary.push_str("|-------|-------|------|--------|--------|\n");

    // Collect per-teammate data from team
    if let Some(team) = teams.get(team_id) {
        for task_def in task_defs {
            let status = if completed.contains_key(&task_def.id) {
                "done"
            } else if failed.contains(&task_def.id) {
                "failed"
            } else {
                "pending"
            };

            let (model, time_str) = if let Some(tm) = team.teammates.get(&task_def.id) {
                let elapsed = tm.created_at.elapsed().as_secs_f64();
                (tm.model.as_str(), format!("{:.1}s", elapsed))
            } else {
                ("?", "-".to_string())
            };

            summary.push_str(&format!(
                "| {} | {} | {} | - | {} |\n",
                task_def.id, model, time_str, status
            ));
        }
    }
    drop(teams);

    // Tool breakdown
    if !tool_breakdown.is_empty() {
        summary.push_str("\n### Tool usage\n");
        for (tool, count) in &tool_breakdown {
            summary.push_str(&format!("- {}: {}\n", tool, count));
        }
    }

    summary
}

// --- Handler functions ---

/// Handle flow_status tool call.
pub async fn handle_flow_status(
    args: serde_json::Value,
    registry: std::sync::Arc<FlowRegistry>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;
    let flow_id = match args.get("flow_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing required parameter: flow_id"),
    };
    match registry.get_status(flow_id) {
        Some(status) => {
            CallToolResult::text(serde_json::to_string_pretty(&status).unwrap_or_default())
        }
        None => CallToolResult::error_msg(format!("Unknown flow: {flow_id}")),
    }
}

/// Handle flow_result tool call.
pub async fn handle_flow_result(
    args: serde_json::Value,
    registry: std::sync::Arc<FlowRegistry>,
    audit_log: Option<std::sync::Arc<navra_memory::AuditLog>>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;
    let flow_id = match args.get("flow_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing required parameter: flow_id"),
    };
    let node_id = args.get("node_id").and_then(|v| v.as_str());
    let include_tasks = args
        .get("include_tasks")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // Try in-memory registry first
    let mut result = match registry.get_result(flow_id, node_id) {
        Some(r) => r,
        None => {
            // Fall back to audit log for persisted results (survives restart)
            if let Some(ref audit) = audit_log {
                if let Ok(tasks) = audit.get_flow_results(flow_id) {
                    if tasks.is_empty() {
                        return CallToolResult::error_msg(format!("No results for flow: {flow_id}"));
                    }
                    if let Some(nid) = node_id {
                        if let Some(task) = tasks.iter().find(|t| t.task_id == nid) {
                            return CallToolResult::text(
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "flow_id": flow_id,
                                    "node": nid,
                                    "status": task.status,
                                    "output": task.output,
                                    "source": "persistent",
                                }))
                                .unwrap_or_default(),
                            );
                        }
                        return CallToolResult::error_msg(format!(
                            "No results for node {nid} in flow {flow_id}"
                        ));
                    }
                    let all_done = tasks
                        .iter()
                        .all(|t| t.status == "done" || t.status == "failed");
                    let status = if all_done {
                        if tasks.iter().any(|t| t.status == "failed") {
                            "failed"
                        } else {
                            "completed"
                        }
                    } else {
                        "running"
                    };
                    let task_results: Vec<serde_json::Value> = tasks
                        .iter()
                        .map(|t| {
                            serde_json::json!({
                                "task_id": t.task_id,
                                "specialist": t.specialist,
                                "model": t.model,
                                "status": t.status,
                                "output": t.output,
                                "iterations": t.iterations,
                                "tokens": t.tokens,
                            })
                        })
                        .collect();
                    return CallToolResult::text(
                        serde_json::to_string_pretty(&serde_json::json!({
                            "flow_id": flow_id,
                            "status": status,
                            "output": tasks.last().and_then(|t| t.output.as_deref()),
                            "tasks": task_results,
                            "source": "persistent",
                        }))
                        .unwrap_or_default(),
                    );
                }
            }
            return CallToolResult::error_msg(format!("No results for flow: {flow_id}"));
        }
    };

    // Enrich with persisted task outputs when available
    if include_tasks && node_id.is_none() {
        if let Some(ref audit) = audit_log {
            if let Ok(tasks) = audit.get_flow_results(flow_id) {
                if !tasks.is_empty() {
                    let task_results: Vec<serde_json::Value> = tasks
                        .iter()
                        .map(|t| {
                            serde_json::json!({
                                "task_id": t.task_id,
                                "specialist": t.specialist,
                                "model": t.model,
                                "status": t.status,
                                "output": t.output,
                                "iterations": t.iterations,
                                "tokens": t.tokens,
                            })
                        })
                        .collect();
                    if let Some(obj) = result.as_object_mut() {
                        obj.insert("tasks".to_string(), serde_json::json!(task_results));
                    }
                }
            }
        }
    }

    CallToolResult::text(serde_json::to_string_pretty(&result).unwrap_or_default())
}

/// Handle flow_list tool call.
pub async fn handle_flow_list(flow_dirs: Vec<String>) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    if flow_dirs.is_empty() {
        return CallToolResult::text(
            "No flow directories configured. \
             Set flow_dirs in config.toml to list available flows.",
        );
    }

    let mut flows = Vec::new();
    for dir in &flow_dirs {
        let expanded = if dir.starts_with('~') {
            if let Some(home) = dirs::home_dir() {
                dir.replacen('~', &home.display().to_string(), 1)
            } else {
                dir.clone()
            }
        } else {
            dir.clone()
        };
        let path = std::path::Path::new(&expanded);
        let entries = match std::fs::read_dir(path) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(dir = %expanded, error = %e, "Cannot read flow dir");
                continue;
            }
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let ext = p.extension().and_then(|e| e.to_str());
            if !matches!(ext, Some("yml" | "yaml")) {
                continue;
            }
            let content = match std::fs::read_to_string(&p) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if let Ok(envelope) =
                serde_yaml::from_str::<navra_flow::yaml_loader::FlowFile>(&content)
            {
                let params: Vec<serde_json::Value> = envelope
                    .parameters
                    .iter()
                    .map(|(k, v)| {
                        serde_json::json!({
                            "name": k,
                            "type": v.param_type,
                            "description": v.description,
                            "default": v.default,
                        })
                    })
                    .collect();
                flows.push(serde_json::json!({
                    "name": envelope.name,
                    "kind": envelope.kind,
                    "description": envelope.description,
                    "file": p.display().to_string(),
                    "parameters": params,
                }));
            }
        }
    }

    CallToolResult::text(serde_json::to_string_pretty(&flows).unwrap_or_default())
}

/// Shared context for flow operations that need team and flow registries.
pub struct FlowContext {
    pub flow_registry: std::sync::Arc<FlowRegistry>,
    pub team_registry: std::sync::Arc<crate::team_tools::TeamRegistry>,
    pub navra_addr: String,
    pub signer: std::sync::Arc<navra_core::identity::Ed25519Signer>,
    pub forge: Option<std::sync::Arc<navra_cognitive::ForgeService>>,
    pub budget_cfg: crate::config::BudgetConfig,
    pub flow_dirs: Vec<String>,
    pub docs_root: Option<String>,
    /// Root capability payload for delegated teammate tokens.
    pub root_payload: Option<navra_core::auth::capability::CapabilityPayload>,
    /// Optional PII filter for model reasoning text.
    pub pii_filter: Option<std::sync::Arc<navra_core::safety::FilterPipeline>>,
    /// Audit log for persisting flow task results.
    pub audit_log: Option<std::sync::Arc<navra_memory::AuditLog>>,
    /// Path to cognitive core directory on the host (for container mounts).
    pub cognitive_core_path: Option<String>,
    /// Shared model server endpoint for containerized agents.
    pub model_server_url: Option<String>,
    /// Semaphore limiting concurrent GPU-bound agent executions.
    pub gpu_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    /// Whether to use containerized agent execution.
    pub containerized: bool,
    /// Container image for agent sandboxes.
    pub agent_image: String,
    /// Memory limit per container (e.g., "2g").
    pub container_memory: String,
    /// CPU limit per container (e.g., "2").
    pub container_cpus: String,
    /// PID limit per container.
    pub container_pids: u32,
    /// Optional embedding model for query-aware tool output compression.
    pub embedding_model: Option<std::sync::Arc<dyn navra_model::ModelBackend>>,
    /// OpenShell compute driver gRPC endpoint.
    pub openshell_gateway: Option<String>,
    /// Shared exec state for routing exec_run calls to sandboxes.
    pub exec_state: Option<std::sync::Arc<crate::exec_tools::ExecState>>,
    /// Workspace provider for populating agent sandbox workspaces.
    pub workspace_provider: Option<std::sync::Arc<dyn crate::workspace::WorkspaceProvider>>,
    /// Optional SQLite checkpoint store for DAG crash resilience.
    pub checkpoint: Option<std::sync::Arc<navra_flow::DagCheckpoint>>,
}

/// Record completed/failed task results to the audit log.
fn record_task_results_to_audit(
    audit_log: &Option<std::sync::Arc<navra_memory::AuditLog>>,
    team_reg: &crate::team_tools::TeamRegistry,
    team_id: &str,
    flow_id: &str,
    task_ids: &[String],
    completed: &std::collections::HashMap<String, String>,
    failed: &std::collections::HashSet<String>,
    task_defs: &[navra_flow::TaskDefinition],
) {
    let Some(audit) = audit_log else { return };
    let teams = team_reg.teams.lock().unwrap_or_else(|e| e.into_inner());
    let team = teams.get(team_id);

    for task_id in task_ids {
        let task_def = task_defs.iter().find(|t| t.id == *task_id);
        let specialist = task_def.map(|t| t.specialist.as_str());
        let (model, iterations, tokens) = team
            .and_then(|t| t.teammates.get(task_id))
            .map(|tm| (Some(tm.model.as_str()), tm.iterations, tm.agent_tokens))
            .unwrap_or_else(|| {
                tracing::warn!(
                    flow_id = %flow_id, task = %task_id,
                    "Teammate not found in team registry — audit will have NULL model/iterations/tokens"
                );
                (None, None, None)
            });

        let (status, output) = if let Some(out) = completed.get(task_id) {
            ("done", Some(out.as_str()))
        } else if failed.contains(task_id) {
            let out = team
                .and_then(|t| t.teammates.get(task_id))
                .and_then(|tm| tm.output.as_deref());
            ("failed", out)
        } else {
            continue;
        };

        if let Err(e) = audit.record_flow_task(
            flow_id, task_id, specialist, model, status, output, iterations, tokens,
        ) {
            tracing::warn!(flow_id = %flow_id, task = %task_id, error = %e, "Failed to record flow task to audit");
        }

        if let Some(out) = output {
            match audit.record_flow_findings(flow_id, task_id, out) {
                Ok(n) if n > 0 => {
                    tracing::info!(flow_id = %flow_id, task = %task_id, findings = n, "Recorded structured findings");
                }
                Err(e) => {
                    tracing::debug!(flow_id = %flow_id, task = %task_id, error = %e, "Failed to parse findings");
                }
                _ => {}
            }
        }
    }
}

/// Get the current blackbox sequence number (for summary queries).
fn current_bb_seq() -> i64 {
    let bb_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/blackbox.db");
    rusqlite::Connection::open_with_flags(&bb_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .ok()
        .and_then(|db| {
            db.query_row("SELECT COALESCE(MAX(seq), 0) FROM blackbox", [], |row| {
                row.get::<_, i64>(0)
            })
            .ok()
        })
        .unwrap_or(0)
}

/// Pre-compute project file tree for injecting into specialist mandates.
fn compute_file_tree(docs_root: &Option<String>) -> String {
    if let Some(ref root) = docs_root {
        let root_path = std::path::Path::new(root);
        if root_path.is_dir() {
            let mut files = Vec::new();
            fn collect(dir: &std::path::Path, root: &std::path::Path, files: &mut Vec<String>) {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    return;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with('.')
                        || name_str == "target"
                        || name_str == "node_modules"
                    {
                        continue;
                    }
                    if path.is_dir() {
                        collect(&path, root, files);
                    } else if path.is_file() {
                        if let Ok(rel) = path.strip_prefix(root) {
                            let lines = std::fs::read_to_string(&path)
                                .map(|c| c.lines().count())
                                .unwrap_or(0);
                            files.push(format!("  {} ({} lines)", rel.display(), lines));
                        }
                    }
                }
            }
            collect(root_path, root_path, &mut files);
            files.sort();
            format!("{} files:\n{}", files.len(), files.join("\n"))
        } else {
            String::new()
        }
    } else {
        String::new()
    }
}

/// Poll until all given task IDs complete or fail, with a timeout check.
/// Returns updated completed and failed sets.
async fn poll_tasks_until_done(
    team_reg: &std::sync::Arc<crate::team_tools::TeamRegistry>,
    flow_reg: &std::sync::Arc<FlowRegistry>,
    team_id: &str,
    flow_id: &str,
    running_ids: &[String],
    completed: &mut std::collections::HashMap<String, String>,
    failed: &mut std::collections::HashSet<String>,
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

/// Spawn ready tasks as teammates and wait for them to complete.
/// Returns the IDs of tasks that were spawned.
async fn spawn_and_track_tasks(
    ctx: &FlowContext,
    team_id: &str,
    flow_id: &str,
    ready: &[&navra_flow::TaskDefinition],
    completed: &std::collections::HashMap<String, String>,
    failed: &std::collections::HashSet<String>,
    prompt: &str,
    project_file_tree: &str,
) -> (
    Vec<String>,
    std::collections::HashMap<String, String>,
    std::collections::HashSet<String>,
) {
    let new_completed = std::collections::HashMap::new();
    let mut new_failed = std::collections::HashSet::new();
    let mut spawned_ids = Vec::new();

    for task in ready {
        let model = task.model.clone().unwrap_or_else(|| "auto".to_string());
        let persona = if task.specialist.is_empty() {
            None
        } else {
            Some(task.specialist.clone())
        };

        let ops = task
            .operations
            .as_ref()
            .map(|o| o.clone())
            .unwrap_or_else(|| {
                crate::team_tools::DEFAULT_OPERATIONS
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            });
        let tools = task.tools.as_ref().map(|t| t.clone()).unwrap_or_else(|| {
            crate::team_tools::DEFAULT_TOOLS
                .iter()
                .map(|s| s.to_string())
                .collect()
        });

        if let Err(e) = ctx.team_registry.add_teammate(
            team_id,
            &task.id,
            persona.as_deref(),
            &model,
            "local",
            ops,
            tools,
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

        // Build the task message with dependency context
        let mut message = task.mandate.clone();
        let dep_count = task.depends_on.len();
        if dep_count > 0 {
            if is_synthesizer && dep_count > 5 {
                // Synthesizer with many dependencies: read from blackboard
                // (IFC taint-on-read enforced) instead of inline injection.
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
            } else if dep_count <= 3 {
                // Few dependencies: inject inline (acceptable for small
                // dep counts where IFC risk is low — typically scout/planner).
                message.push_str(&format!(
                    "\n\n--- Context from prior stages ({dep_count} outputs follow) ---\n"
                ));
                for dep_id in &task.depends_on {
                    if let Some(output) = completed.get(dep_id) {
                        message.push_str(&format!("\n## {dep_id}\n{output}\n"));
                    } else if failed.contains(dep_id) {
                        message.push_str(&format!(
                            "\n## {dep_id}\n[This stage failed — no output available.]\n"
                        ));
                    }
                }
            } else {
                // Medium dependencies: point to blackboard
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
        // Inject verified file tree into every task (capped to avoid
        // exceeding the ~1600 token limit where Ollama's tool_choice
        // breaks). Planner tasks get the full tree; specialists get
        // a truncated version.
        if !project_file_tree.is_empty() && !task.generates_tasks {
            let max_tree_chars = 2000;
            let tree_slice = if project_file_tree.len() > max_tree_chars {
                let mut end = max_tree_chars;
                while end > 0 && !project_file_tree.is_char_boundary(end) {
                    end -= 1;
                }
                // Cut at last newline to avoid partial paths
                if let Some(nl) = project_file_tree[..end].rfind('\n') {
                    &project_file_tree[..nl]
                } else {
                    &project_file_tree[..end]
                }
            } else {
                &project_file_tree
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
        };
        // Cap per-task iterations: share the budget across tasks,
        // with a minimum of 10 to allow meaningful work.
        let per_task_iters = if is_synthesizer && dep_count > 2 {
            // Synthesizer needs iterations to read specialist outputs
            // via flow:// MCP resources (one read per specialist)
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

/// Handle flow_start tool call.
pub async fn handle_flow_start(
    args: serde_json::Value,
    ctx: std::sync::Arc<FlowContext>,
    agent_name: &str,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let prompt = match args.get("prompt").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return CallToolResult::error_msg("Missing required parameter: prompt"),
    };

    let params: std::collections::HashMap<String, String> = args
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
                "Invalid flow_name: only alphanumeric characters, hyphens, and underscores are allowed"
            );
        }
        let mut found = None;
        for dir in &ctx.flow_dirs {
            let expanded = crate::expand_tilde(dir);
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
                ))
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

    // Execute the DAG synchronously — block until all tasks (including
    // dynamically injected planner tasks and subflows) complete.
    // This ensures the caller gets the full result, not just "started."
    let final_output = run_dag_execution(&ctx, &flow_id, &team_id, &prompt, dag_config.tasks).await;

    // Mark flow complete in metadata
    if let Some(ref audit) = ctx.audit_log {
        let _ = audit.complete_flow_metadata(&flow_id, "completed");
    }

    CallToolResult::text(format!(
        "Flow completed.\nflow_id: {flow_id}\n\n{final_output}"
    ))
}

/// Execute a DAG of tasks, polling for completion.
///
/// Used by both flow_start (async, in background) and flow_escalate (sync).
async fn run_dag_execution(
    ctx: &FlowContext,
    flow_id: &str,
    team_id: &str,
    prompt: &str,
    mut task_defs: Vec<navra_flow::TaskDefinition>,
) -> String {
    let mut completed: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut failed: std::collections::HashSet<String> = std::collections::HashSet::new();
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
        // Find ready tasks: dependencies satisfied (completed or failed),
        // not yet completed/failed themselves. Failed dependencies count
        // as satisfied so downstream tasks (especially synthesizers) can
        // still run with whatever partial results are available, instead
        // of deadlocking.
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
                idempotency_cache: std::collections::HashMap::new(),
            };
            if let Err(e) = cp.save(&state) {
                tracing::warn!(flow_id = %flow_id, error = %e, "Failed to save checkpoint");
            } else {
                tracing::debug!(flow_id = %flow_id, "Checkpoint saved");
            }
        }

        // Auto-publish specialist outputs to the team blackboard
        // with the session's context label (IFC taint-on-read).
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
                // Truncate to 4K for blackboard (full output in audit.db)
                let truncated = if output.len() > 4096 {
                    format!(
                        "{}...\n[truncated, {} chars total]",
                        &output[..4096],
                        output.len()
                    )
                } else {
                    output.clone()
                };
                ctx.team_registry.bb_publish(
                    team_id,
                    &format!("findings/{task_id}"),
                    &truncated,
                    task_id,
                    label,
                );
            }
        }

        // Dynamic task injection: if any completed task has generates_tasks=true,
        // parse its output as a task array and inject into the DAG.
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
                // Retry: send the failed output back with a correction prompt
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
                    .and_then(|b| {
                        Ok(b.model(navra_model::OpenAiBackend::new(
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
                        .temperature(0.0))
                    }) {
                    Ok(builder) => {
                        if let Ok(mut agent) = builder.build().await {
                            if let Ok(result) = agent.run(&correction_prompt).await {
                                new_tasks = navra_flow::parse_planner_tasks(&result.response);
                                if !new_tasks.is_empty() {
                                    tracing::info!(
                                        flow_id = %flow_id, count = new_tasks.len(),
                                        "Planner retry succeeded"
                                    );
                                }
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

            // Inject tasks — they depend on the planner
            for mut new_task in new_tasks {
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

            // Rewrite synthesizer to depend on all injected tasks
            for td in task_defs.iter_mut() {
                if td.id == "synthesize" || td.id == "synthesizer" {
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

/// Handle flow_escalate tool call.
pub async fn handle_flow_escalate(
    args: serde_json::Value,
    ctx: std::sync::Arc<FlowContext>,
    agent_name: &str,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

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
    if let Some(ref ctx_text) = context {
        if ctx_text.len() > MAX_MANDATE_LEN {
            return CallToolResult::error_msg(format!(
                "Context too long ({} chars, max {MAX_MANDATE_LEN}). Summarize your context.",
                ctx_text.len()
            ));
        }
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
            });
        }
        navra_flow::DagConfig {
            name: format!("escalation-depth{new_depth}"),
            description: Some(format!("Escalation subflow for: {mandate}")),
            parameters: std::collections::HashMap::new(),
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
    let mut completed: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut failed: std::collections::HashSet<String> = std::collections::HashSet::new();
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
        let (spawned_ids, _, spawn_failed) = spawn_and_track_tasks(
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

// --- Tool definitions ---

pub fn flow_start_tool_def() -> ToolDefinition {
    ToolDefinition::new(
        "flow_start",
        "Start a multi-agent flow. Either specify flow_name to run a \
             predefined template (from flow_list), or flow_definition to \
             define inline. Templates are recommended — they encode proven \
             orchestration patterns (e.g. scout → planner → specialists → \
             synthesizer). Returns a flow_id for tracking via flow_status \
             and flow_result.",
        tool_input_schema(
            Some(HashMap::from([
                (
                    "flow_name".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Name of a flow template from flow_list (e.g. 'security-audit'). Preferred over inline definition."
                    }),
                ),
                (
                    "flow_definition".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Inline flow definition in TOML or YAML format (alternative to flow_name)"
                    }),
                ),
                (
                    "prompt".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "The task prompt (context for the flow execution)"
                    }),
                ),
                (
                    "format".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "enum": ["toml", "yaml"],
                        "default": "yaml",
                        "description": "Format of inline flow_definition"
                    }),
                ),
                (
                    "parameters".to_string(),
                    serde_json::json!({
                        "type": "object",
                        "description": "Parameter values for the flow (e.g. {\"target_dir\": \"/app\"})",
                        "additionalProperties": { "type": "string" }
                    }),
                ),
            ])),
            Some(vec!["prompt".to_string()]),
        ),
    )
}

pub fn flow_list_tool_def() -> ToolDefinition {
    ToolDefinition::new(
        "flow_list",
        "List available YAML flow files from configured flow directories. \
             Returns flow names, descriptions, and parameter definitions.",
        tool_input_schema(
            Some(HashMap::new()),
            None,
        ),
    )
}

pub fn flow_status_tool_def() -> ToolDefinition {
    ToolDefinition::new(
        "flow_status",
        "Check the status of a running or completed flow. Returns node \
             statuses (pending/running/done/failed) and elapsed time.",
        tool_input_schema(
            Some(HashMap::from([(
                "flow_id".to_string(),
                serde_json::json!({"type": "string", "description": "Flow ID from flow_start"}),
            )])),
            Some(vec!["flow_id".to_string()]),
        ),
    )
}

pub fn flow_result_tool_def() -> ToolDefinition {
    ToolDefinition::new(
        "flow_result",
        "Get the output of a completed flow or a specific node within it. \
             Returns the full report with all task outputs if no node specified, \
             or a single node's output if node_id is given. Results are persisted \
             to disk and survive server restarts.",
        tool_input_schema(
            Some(HashMap::from([
                (
                    "flow_id".to_string(),
                    serde_json::json!({"type": "string", "description": "Flow ID from flow_start"}),
                ),
                (
                    "node_id".to_string(),
                    serde_json::json!({"type": "string", "description": "Optional: specific node to read results from"}),
                ),
                (
                    "include_tasks".to_string(),
                    serde_json::json!({"type": "boolean", "default": true, "description": "Include individual task outputs in the response (default: true)"}),
                ),
            ])),
            Some(vec!["flow_id".to_string()]),
        ),
    )
}

pub fn flow_escalate_tool_def() -> ToolDefinition {
    ToolDefinition::new(
        "flow_escalate",
        "Escalate a complex task by spawning a sub-leader. Use when your \
             task requires multiple specialists or parallel investigation. \
             Returns the synthesized result. This call blocks until the \
             subflow completes.",
        tool_input_schema(
            Some(HashMap::from([
                (
                    "mandate".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "What the sub-leader should accomplish"
                    }),
                ),
                (
                    "context".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Additional context from your current investigation (optional)"
                    }),
                ),
                (
                    "tasks".to_string(),
                    serde_json::json!({
                        "type": "array",
                        "description": "Optional explicit task list. If omitted, a generic scout-planner-worker-synthesize DAG is used.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string", "description": "Unique task identifier"},
                                "specialist": {"type": "string", "description": "Persona name for the task"},
                                "model": {"type": "string", "description": "Model override (optional)"},
                                "mandate": {"type": "string", "description": "What the specialist should accomplish"},
                                "depends_on": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Task IDs that must complete first"
                                }
                            },
                            "required": ["id", "specialist", "mandate"]
                        }
                    }),
                ),
            ])),
            Some(vec!["mandate".to_string()]),
        ),
    )
}

pub fn flow_resume_tool_def() -> ToolDefinition {
    ToolDefinition::new(
        "flow_resume",
        "Resume a timed-out or failed flow. Skips completed tasks \
             (read from audit.db) and runs only the remaining ones.",
        tool_input_schema(
            Some(HashMap::from([(
                "flow_id".to_string(),
                serde_json::json!({
                    "type": "string",
                    "description": "ID of the flow to resume"
                }),
            )])),
            Some(vec!["flow_id".to_string()]),
        ),
    )
}

/// Resume a timed-out flow by loading checkpoint state (preferred) or
/// audit.db metadata, then re-running only the remaining tasks.
pub async fn handle_flow_resume(
    args: serde_json::Value,
    ctx: std::sync::Arc<FlowContext>,
    agent_name: &str,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let flow_id = match args.get("flow_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return CallToolResult::error_msg("Missing required parameter: flow_id"),
    };

    // Try checkpoint first — it has the most complete state
    if let Some(ref cp) = ctx.checkpoint {
        if let Ok(Some(cp_state)) = cp.load(&flow_id) {
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
                    return CallToolResult::error_msg(format!("Failed to create resume team: {e}"))
                }
            };
            ctx.flow_registry.set_team_id(&new_flow_id, &team_id);

            // Publish completed outputs to blackboard for dependency resolution
            for (task_id, output) in &cp_state.completed {
                let truncated = if output.len() > 4096 {
                    format!(
                        "{}...\n[truncated, {} chars total]",
                        &output[..4096],
                        output.len()
                    )
                } else {
                    output.clone()
                };
                ctx.team_registry.bb_publish(
                    &team_id,
                    &format!("findings/{task_id}"),
                    &truncated,
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
    }

    // Fall back to audit log recovery
    let metadata = match &ctx.audit_log {
        Some(audit) => match audit.load_flow_metadata(&flow_id) {
            Ok(Some(m)) => m,
            Ok(None) => {
                return CallToolResult::error_msg(format!(
                    "Flow {flow_id} not found in audit.db or checkpoint"
                ))
            }
            Err(e) => return CallToolResult::error_msg(format!("Failed to load flow metadata: {e}")),
        },
        None => {
            return CallToolResult::error_msg("Audit log not configured and no checkpoint available")
        }
    };

    // Load completed task results
    let completed_results = match &ctx.audit_log {
        Some(audit) => match audit.get_flow_results(&flow_id) {
            Ok(r) => r,
            Err(e) => return CallToolResult::error_msg(format!("Failed to load flow results: {e}")),
        },
        None => Vec::new(),
    };

    let already_done: std::collections::HashMap<String, String> = completed_results
        .iter()
        .filter(|r| r.status == "done")
        .filter_map(|r| {
            let output = r.output.clone().unwrap_or_default();
            Some((r.task_id.clone(), output))
        })
        .collect();

    let already_failed: std::collections::HashSet<String> = completed_results
        .iter()
        .filter(|r| r.status == "failed")
        .map(|r| r.task_id.clone())
        .collect();

    // Re-parse the YAML to get the task definitions
    let yaml_content = match metadata.yaml_content {
        Some(ref y) => y.clone(),
        None => return CallToolResult::error_msg("Flow has no saved YAML content — cannot resume"),
    };

    let params: std::collections::HashMap<String, String> = metadata
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
            Err(e) => return CallToolResult::error_msg(format!("Failed to create resume team: {e}")),
        };
    ctx.flow_registry.set_team_id(&new_flow_id, &team_id);

    let prompt = format!("Resumed flow {flow_id}");
    let final_output = run_dag_execution(&ctx, &new_flow_id, &team_id, &prompt, remaining).await;

    if let Some(ref audit) = ctx.audit_log {
        let _ = audit.complete_flow_metadata(&new_flow_id, "completed");
    }

    CallToolResult::text(format!(
        "Flow resumed.\nOriginal: {flow_id}\nResumed as: {new_flow_id}\n\
         Previously completed: {} tasks\n\n{final_output}",
        already_done.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_name_rejects_path_traversal() {
        // Valid names
        assert!("security-audit"
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
        assert!("my_flow_v2"
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));

        // Path traversal attempts must be rejected
        let bad_names = vec![
            "../../etc/passwd",
            "../secret",
            "foo/bar",
            "foo\\bar",
            "name with spaces",
            "name.yaml",
            "name;rm -rf",
        ];
        for name in bad_names {
            assert!(
                !name
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
                "Expected rejection for: {name}"
            );
        }
    }

    #[test]
    fn mandate_length_limit() {
        const MAX_MANDATE_LEN: usize = 10_000;
        let short = "a".repeat(MAX_MANDATE_LEN);
        assert!(short.len() <= MAX_MANDATE_LEN);

        let long = "a".repeat(MAX_MANDATE_LEN + 1);
        assert!(long.len() > MAX_MANDATE_LEN);
    }

    #[test]
    fn flow_registry_basic_lifecycle() {
        let reg = FlowRegistry::new();

        let id = reg.register("test-flow");
        assert!(id.starts_with("flow-"));

        let status = reg.get_status(&id).unwrap();
        assert_eq!(status["status"], "running");

        reg.complete(&id, "done".to_string());
        let status = reg.get_status(&id).unwrap();
        assert_eq!(status["status"], "completed");
    }

    #[test]
    fn flow_registry_subflow_linkage() {
        let reg = FlowRegistry::new();

        let parent = reg.register("parent");
        let child = reg.register_subflow("child", &parent, 1);

        let flows = reg.flows.lock().unwrap();
        let child_flow = flows.get(&child).unwrap();
        assert_eq!(child_flow.parent_flow_id.as_deref(), Some(parent.as_str()));
        assert_eq!(child_flow.depth, 1);
    }

    #[test]
    fn flow_registry_fail() {
        let reg = FlowRegistry::new();
        let id = reg.register("fail-flow");

        reg.fail(&id, "something broke".to_string());
        let status = reg.get_status(&id).unwrap();
        assert_eq!(status["status"], "failed");
        assert_eq!(status["error"], "something broke");
    }

    #[test]
    fn node_status_update() {
        let reg = FlowRegistry::new();
        let id = reg.register("node-test");

        reg.update_nodes(
            &id,
            vec![NodeStatus {
                id: "task1".to_string(),
                specialist: "analyst".to_string(),
                status: "pending".to_string(),
                output: None,
                started_at: None,
                completed_at: None,
            }],
        );

        reg.update_node_status(&id, "task1", "done", Some("result".to_string()));

        let result = reg.get_result(&id, Some("task1")).unwrap();
        assert_eq!(result["status"], "done");
        assert_eq!(result["output"], "result");
    }
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
