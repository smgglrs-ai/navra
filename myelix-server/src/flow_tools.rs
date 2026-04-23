//! MCP tools for async flow orchestration.
//!
//! Exposes `flow_start`, `flow_status`, and `flow_result` as MCP tools
//! so a planner agent can define, launch, monitor, and read results from
//! multi-agent flows — all through standard MCP tool calls.

use myelix_core::protocol::{ToolDefinition, ToolInputSchema};
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
    next_id: Mutex<u64>,
}

impl FlowRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new flow and return its ID.
    pub fn register(&self, name: &str) -> String {
        let mut id_counter = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
        *id_counter += 1;
        let flow_id = format!("flow-{}", *id_counter);

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
        let mut id_counter = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
        *id_counter += 1;
        let flow_id = format!("flow-{}", *id_counter);

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
    pub fn update_node_status(&self, flow_id: &str, node_id: &str, status: &str, output: Option<String>) {
        if let Some(run) = self
            .flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(flow_id)
        {
            if let Some(node) = run.node_statuses.iter_mut().find(|n| n.id == node_id) {
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

// --- Tool definitions ---

pub fn flow_start_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "flow_start".to_string(),
        description: Some(
            "Start a multi-agent flow. Either specify flow_name to run a \
             predefined template (from flow_list), or flow_definition to \
             define inline. Templates are recommended — they encode proven \
             orchestration patterns (e.g. scout → planner → specialists → \
             synthesizer). Returns a flow_id for tracking via flow_status \
             and flow_result."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
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
            required: Some(vec!["prompt".to_string()]),
        },
    }
}

pub fn flow_list_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "flow_list".to_string(),
        description: Some(
            "List available YAML flow files from configured flow directories. \
             Returns flow names, descriptions, and parameter definitions."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::new()),
            required: None,
        },
    }
}

pub fn flow_status_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "flow_status".to_string(),
        description: Some(
            "Check the status of a running or completed flow. Returns node \
             statuses (pending/running/done/failed) and elapsed time."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "flow_id".to_string(),
                serde_json::json!({"type": "string", "description": "Flow ID from flow_start"}),
            )])),
            required: Some(vec!["flow_id".to_string()]),
        },
    }
}

pub fn flow_result_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "flow_result".to_string(),
        description: Some(
            "Get the output of a completed flow or a specific node within it. \
             Returns the full report if no node specified, or a single node's \
             output if node_id is given. Can be called while the flow is still \
             running to read partial results from completed nodes."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "flow_id".to_string(),
                    serde_json::json!({"type": "string", "description": "Flow ID from flow_start"}),
                ),
                (
                    "node_id".to_string(),
                    serde_json::json!({"type": "string", "description": "Optional: specific node to read results from"}),
                ),
            ])),
            required: Some(vec!["flow_id".to_string()]),
        },
    }
}

pub fn flow_escalate_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "flow_escalate".to_string(),
        description: Some(
            "Escalate a complex task by spawning a sub-leader. Use when your \
             task requires multiple specialists or parallel investigation. \
             Returns the synthesized result. This call blocks until the \
             subflow completes."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
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
            required: Some(vec!["mandate".to_string()]),
        },
    }
}
