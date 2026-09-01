//! MCP tools for async flow orchestration.
//!
//! Exposes `flow_start`, `flow_status`, and `flow_result` as MCP tools
//! so a planner agent can define, launch, monitor, and read results from
//! multi-agent flows — all through standard MCP tool calls.

use navra_core::protocol::ToolDefinition;
use navra_protocol::compat::{CallToolResultExt, tool_input_schema};
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
    /// Dependency edges (from depends_on in DagConfig).
    pub edges: Vec<FlowEdge>,
}

/// A dependency edge between flow nodes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FlowEdge {
    pub source: String,
    pub target: String,
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
            edges: Vec::new(),
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
            edges: Vec::new(),
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
            && let Some(node) = run.node_statuses.iter_mut().find(|n| n.id == node_id)
        {
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
                    (Some(start), Some(end)) => Some(end.duration_since(start).as_millis() as u64),
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

        let edges: Vec<serde_json::Value> = run
            .edges
            .iter()
            .map(|e| {
                serde_json::json!({
                    "source": e.source,
                    "target": e.target,
                })
            })
            .collect();

        Some(serde_json::json!({
            "flow_id": run.flow_id,
            "name": run.name,
            "status": match &run.status {
                FlowRunStatus::Running => "running",
                FlowRunStatus::Completed => "completed",
                FlowRunStatus::Failed(_) => "failed",
            },
            "nodes": nodes,
            "edges": edges,
        }))
    }

    /// List all flow runs with summary info.
    pub fn list_runs(&self) -> Vec<serde_json::Value> {
        let flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        flows
            .values()
            .map(|run| {
                serde_json::json!({
                    "flow_id": run.flow_id,
                    "name": run.name,
                    "status": match &run.status {
                        FlowRunStatus::Running => "running",
                        FlowRunStatus::Completed => "completed",
                        FlowRunStatus::Failed(_) => "failed",
                    },
                    "elapsed_secs": run.started_at.elapsed().as_secs(),
                    "node_count": run.node_statuses.len(),
                })
            })
            .collect()
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
#[allow(clippy::too_many_arguments)]
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
        )
            && let Ok(rows) = stmt.query_map([bb_start_seq], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            }) {
                for row in rows.flatten() {
                    breakdown.push(row);
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
            if let Some(ref audit) = audit_log
                && let Ok(tasks) = audit.get_flow_results(flow_id)
            {
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
            return CallToolResult::error_msg(format!("No results for flow: {flow_id}"));
        }
    };

    // Enrich with persisted task outputs when available
    if include_tasks
        && node_id.is_none()
        && let Some(ref audit) = audit_log
        && let Ok(tasks) = audit.get_flow_results(flow_id)
        && !tasks.is_empty()
    {
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_task_results_to_audit(
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
pub(crate) fn current_bb_seq() -> i64 {
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
        tool_input_schema(Some(HashMap::new()), None),
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

pub(crate) use crate::flow_escalation::{handle_flow_escalate, handle_flow_resume};
pub(crate) use crate::flow_execution::handle_flow_start;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_name_rejects_path_traversal() {
        // Valid names
        assert!(
            "security-audit"
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
        assert!(
            "my_flow_v2"
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );

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
