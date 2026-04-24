//! TOML-deserializable flow definitions.

use crate::verification::VerificationConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level flow definition (wraps `FlowConfig` for TOML `[flow]` section).
#[derive(Debug, Clone, Deserialize)]
pub struct FlowDefinition {
    pub flow: FlowConfig,
}

/// Flow configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct FlowConfig {
    /// Flow name.
    pub name: String,
    /// ID of the entry node (where execution starts).
    pub entry: String,
    /// Maximum number of handoff hops (default: 10).
    #[serde(default = "default_max_hops")]
    pub max_hops: usize,
    /// Capacity for agent mailboxes (default: 64). Set to enable mesh messaging.
    #[serde(default)]
    pub mailbox_capacity: Option<usize>,
    /// Capacity for the shared blackboard (default: 256). Set to enable blackboard.
    #[serde(default)]
    pub blackboard_capacity: Option<usize>,
    /// Agent nodes in the flow.
    pub nodes: Vec<NodeDefinition>,
    /// Edges defining handoff routes between nodes.
    #[serde(default)]
    pub edges: Vec<EdgeDefinition>,
}

fn default_max_hops() -> usize {
    10
}

/// Definition of an agent node in the flow.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeDefinition {
    /// Unique node identifier.
    pub id: String,
    /// MCP server endpoint URL.
    pub endpoint: String,
    /// Model API URL (OpenAI-compatible).
    pub model_url: String,
    /// Model name for the API.
    pub model_name: String,
    /// API key for the model (optional).
    #[serde(default)]
    pub api_key: Option<String>,
    /// System prompt for this node.
    #[serde(default)]
    pub system_prompt: String,
    /// Max tool-use iterations per hop (default: 10).
    #[serde(default = "default_max_iterations")]
    pub max_iterations: usize,
    /// Temperature for model calls.
    #[serde(default)]
    pub temperature: Option<f32>,
    /// Max tokens per model response.
    #[serde(default)]
    pub max_tokens: Option<u32>,
    /// IFC clearance level for this node: "public", "sensitive", or "secret" (default: "public").
    #[serde(default)]
    pub clearance: Option<String>,
}

fn default_max_iterations() -> usize {
    10
}

/// A directed edge defining a handoff route between nodes.
#[derive(Debug, Clone, Deserialize)]
pub struct EdgeDefinition {
    /// Source node ID.
    pub from: String,
    /// Target node ID.
    pub to: String,
    /// Natural-language description of when to use this route.
    pub description: String,
}

/// Top-level DAG definition (wraps `DagConfig` for TOML `[dag]` section).
#[derive(Debug, Clone, Deserialize)]
pub struct DagDefinition {
    pub dag: DagConfig,
}

/// DAG configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DagConfig {
    /// DAG name.
    #[serde(default)]
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Flow parameters (name → definition). Used by YAML loader for `{{ key }}` substitution.
    #[serde(default)]
    pub parameters: HashMap<String, ParameterDef>,
    /// Task definitions.
    pub tasks: Vec<TaskDefinition>,
    /// Capacity for the shared blackboard (default: 256). Set to enable blackboard.
    #[serde(default)]
    pub blackboard_capacity: Option<usize>,
}

/// Definition of a flow parameter for YAML-based flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterDef {
    /// Parameter type (e.g. "string", "integer", "boolean").
    #[serde(rename = "type")]
    pub param_type: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Default value (if absent, parameter is required).
    #[serde(default)]
    pub default: Option<String>,
}

/// Definition of a task in a DAG.
#[derive(Debug, Clone, Deserialize)]
pub struct TaskDefinition {
    /// Unique task identifier.
    pub id: String,
    /// Specialist (persona name) to execute this task.
    pub specialist: String,
    /// Model override for this task (e.g. "granite3.3:8b"). If absent, uses the default.
    #[serde(default)]
    pub model: Option<String>,
    /// What the specialist should accomplish.
    pub mandate: String,
    /// Task IDs that must complete before this task can run.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Expected output description.
    #[serde(default)]
    pub expected_output: Option<String>,
    /// Success criteria.
    #[serde(default)]
    pub success_criteria: Vec<String>,
    /// Conditional back-edges evaluated after task completion.
    #[serde(default)]
    pub back_edges: Vec<BackEdgeDefinition>,
    /// If true, this task's output is parsed as a JSON array of
    /// TaskDefinitions and injected into the DAG. The synthesizer
    /// task automatically depends on all injected tasks.
    #[serde(default)]
    pub generates_tasks: bool,
    /// Cross-validation configuration for high-stakes outputs.
    #[serde(default)]
    pub verification: Option<VerificationConfig>,
}

/// Parse a planner's text output into task definitions.
///
/// Multi-strategy extraction:
/// 1. Strip markdown code fences (```json ... ```)
/// 2. Find outermost `[` ... `]` in the text
/// 3. Try parsing as JSON array of TaskDefinition
/// 4. If parse fails, try each `{...}` block individually
///
/// Returns empty vec only if no JSON-like content found at all.
pub fn parse_planner_tasks(output: &str) -> Vec<TaskDefinition> {
    let trimmed = output.trim();

    // Strip ALL markdown code fences (there may be multiple)
    let mut cleaned = String::new();
    let mut in_fence = false;
    for line in trimmed.lines() {
        if line.trim().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        cleaned.push_str(line);
        cleaned.push('\n');
    }
    let json_str = if cleaned.trim().is_empty() { trimmed.to_string() } else { cleaned };

    // Find outermost [ ... ]
    let array_str = if let Some(start) = json_str.find('[') {
        if let Some(end) = json_str.rfind(']') {
            &json_str[start..=end]
        } else {
            tracing::warn!("Found '[' but no matching ']' in planner output");
            return Vec::new();
        }
    } else {
        tracing::warn!("No JSON array found in planner output ({} chars)", trimmed.len());
        return Vec::new();
    };

    // Strategy 1: parse the whole array
    match serde_json::from_str::<Vec<TaskDefinition>>(array_str) {
        Ok(tasks) if !tasks.is_empty() => {
            tracing::info!(count = tasks.len(), "Parsed planner tasks");
            return tasks;
        }
        Ok(_) => {}
        Err(e) => {
            tracing::debug!(error = %e, "Array parse failed, trying individual objects");
        }
    }

    // Strategy 2: extract individual {...} blocks and parse each
    let mut tasks = Vec::new();
    let mut depth = 0i32;
    let mut obj_start = None;
    for (i, ch) in array_str.char_indices() {
        match ch {
            '{' => {
                if depth == 0 { obj_start = Some(i); }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(start) = obj_start {
                        let obj_str = &array_str[start..=i];
                        match serde_json::from_str::<TaskDefinition>(obj_str) {
                            Ok(task) => tasks.push(task),
                            Err(e) => tracing::debug!(error = %e, "Skipping unparseable task object"),
                        }
                    }
                    obj_start = None;
                }
            }
            _ => {}
        }
    }

    if !tasks.is_empty() {
        tracing::info!(count = tasks.len(), "Parsed planner tasks (individual objects)");
    } else {
        tracing::warn!("No parseable task objects in planner output");
    }
    tasks
}

/// A conditional back-edge that can route execution backward in the DAG.
#[derive(Debug, Clone, Deserialize)]
pub struct BackEdgeDefinition {
    /// Target task ID to re-execute.
    pub target: String,
    /// Condition string: "score_below:70", "criteria_missing", "output_contains:error", "always".
    #[serde(default = "default_back_edge_condition")]
    pub condition: String,
    /// Maximum number of back-edge activations (default: 3).
    #[serde(default = "default_back_edge_max")]
    pub max_iterations: u32,
}

fn default_back_edge_condition() -> String {
    "always".to_string()
}

fn default_back_edge_max() -> u32 {
    3
}

/// Create a single-task DAG for inline subflow delegation.
///
/// This produces a minimal `DagConfig` containing exactly one task
/// with no dependencies, suitable for `spawn_subflow`-style execution
/// where an agent delegates a focused mandate to a specialist on the fly.
pub fn single_task_dag(specialist: &str, mandate: &str) -> DagConfig {
    DagConfig {
        name: format!("subflow-{specialist}"),
        description: Some(format!("Single-task subflow delegated to {specialist}")),
        parameters: HashMap::new(),
        tasks: vec![TaskDefinition {
            id: "main".to_string(),
            specialist: specialist.to_string(),
            model: None,
            mandate: mandate.to_string(),
            depends_on: Vec::new(),
            expected_output: None,
            success_criteria: Vec::new(),
            back_edges: Vec::new(),
            generates_tasks: false,
            verification: None,
        }],
        blackboard_capacity: None,
    }
}

/// Create a generic 4-stage DAG for when no YAML template matches
/// or when a specialist escalates without providing specific tasks.
///
/// Stages: scout → planner → worker → synthesize
/// - scout: explores project structure (fast model)
/// - planner: identifies 2-3 specific tasks based on scout findings
/// - worker: executes the analysis (depends on planner)
/// - synthesize: merges findings into a coherent report (depends on worker)
pub fn generic_flow_dag(mandate: &str, context: Option<&str>) -> DagConfig {
    let scout_mandate = if let Some(ctx) = context {
        format!(
            "Use docs_tree to list ALL files in the project. Return exact \
             relative paths grouped by relevance to: {mandate}\n\n\
             Additional context:\n{ctx}"
        )
    } else {
        format!(
            "Use docs_tree to list ALL files in the project. Return exact \
             relative paths grouped by relevance to: {mandate}"
        )
    };

    DagConfig {
        name: "generic-escalation".to_string(),
        description: Some(format!("Generic 4-stage escalation flow for: {mandate}")),
        parameters: HashMap::new(),
        tasks: vec![
            TaskDefinition {
                id: "scout".to_string(),
                specialist: "scout".to_string(),
                model: Some("granite3.3:8b".to_string()),
                mandate: scout_mandate,
                depends_on: Vec::new(),
                expected_output: Some("Complete file list with exact paths from docs_tree".to_string()),
                success_criteria: Vec::new(),
                back_edges: Vec::new(),
                generates_tasks: false,
                verification: None,
            },
            TaskDefinition {
                id: "planner".to_string(),
                specialist: "planner".to_string(),
                model: Some("gemma4:26b".to_string()),
                mandate: format!(
                    "Using ONLY the file paths from the scout output, identify 2-3 \
                     tasks to accomplish: {mandate}\n\
                     For each task, list the exact file paths to review. \
                     Do NOT invent paths."
                ),
                depends_on: vec!["scout".to_string()],
                expected_output: Some("Task list with exact file paths from scout".to_string()),
                success_criteria: Vec::new(),
                back_edges: Vec::new(),
                generates_tasks: false,
                verification: None,
            },
            TaskDefinition {
                id: "worker".to_string(),
                specialist: "analyst".to_string(),
                model: Some("gemma4:26b".to_string()),
                mandate: format!(
                    "Read EACH file listed in the planner's tasks using docs_read \
                     with the exact paths. Analyze for: {mandate}\n\
                     You MUST call docs_read — do not guess file contents."
                ),
                depends_on: vec!["planner".to_string()],
                expected_output: Some("Detailed analysis results".to_string()),
                success_criteria: Vec::new(),
                back_edges: Vec::new(),
                generates_tasks: false,
                verification: None,
            },
            TaskDefinition {
                id: "synthesize".to_string(),
                specialist: "synthesizer".to_string(),
                model: Some("gemma4:26b".to_string()),
                mandate: format!(
                    "Merge all findings into a coherent final report for: {mandate}"
                ),
                depends_on: vec!["worker".to_string()],
                expected_output: Some("Final synthesized report".to_string()),
                success_criteria: Vec::new(),
                back_edges: Vec::new(),
                generates_tasks: false,
                verification: None,
            },
        ],
        blackboard_capacity: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_minimal_flow() {
        let toml_str = r#"
[flow]
name = "test"
entry = "main"

[[flow.nodes]]
id = "main"
endpoint = "http://localhost:3000/mcp"
model_url = "http://localhost:11434/v1"
model_name = "granite3.3:8b"
"#;
        let def: FlowDefinition = toml::from_str(toml_str).unwrap();
        assert_eq!(def.flow.name, "test");
        assert_eq!(def.flow.entry, "main");
        assert_eq!(def.flow.max_hops, 10);
        assert_eq!(def.flow.nodes.len(), 1);
        assert_eq!(def.flow.nodes[0].id, "main");
        assert_eq!(def.flow.nodes[0].max_iterations, 10);
        assert!(def.flow.edges.is_empty());
    }

    #[test]
    fn deserialize_full_flow() {
        let toml_str = r#"
[flow]
name = "research"
entry = "router"
max_hops = 5

[[flow.nodes]]
id = "router"
endpoint = "http://localhost:3000/mcp"
model_url = "http://localhost:11434/v1"
model_name = "granite3.3:8b"
system_prompt = "You are a router."
max_iterations = 3
temperature = 0.7

[[flow.nodes]]
id = "coder"
endpoint = "http://localhost:3000/mcp"
model_url = "http://localhost:11434/v1"
model_name = "qwen2.5-coder:7b"
system_prompt = "You are a coder."
max_tokens = 2048

[[flow.edges]]
from = "router"
to = "coder"
description = "Delegate coding tasks"
"#;
        let def: FlowDefinition = toml::from_str(toml_str).unwrap();
        assert_eq!(def.flow.max_hops, 5);
        assert_eq!(def.flow.nodes.len(), 2);
        assert_eq!(def.flow.edges.len(), 1);
        assert_eq!(def.flow.edges[0].from, "router");
        assert_eq!(def.flow.edges[0].to, "coder");
        assert_eq!(def.flow.nodes[0].temperature, Some(0.7));
        assert_eq!(def.flow.nodes[1].max_tokens, Some(2048));
    }

    #[test]
    fn deserialize_dag() {
        let toml_str = r#"
[dag]
name = "security_audit"

[[dag.tasks]]
id = "analyze"
specialist = "analyst"
mandate = "Analyze the codebase for security issues"

[[dag.tasks]]
id = "fix_auth"
specialist = "developer"
mandate = "Fix the authentication vulnerability"
depends_on = ["analyze"]
success_criteria = ["Tests pass", "No regressions"]

[[dag.tasks]]
id = "review"
specialist = "reviewer"
mandate = "Review all fixes"
depends_on = ["fix_auth"]
"#;
        let def: DagDefinition = toml::from_str(toml_str).unwrap();
        assert_eq!(def.dag.name, "security_audit");
        assert_eq!(def.dag.tasks.len(), 3);
        assert_eq!(def.dag.tasks[1].depends_on, vec!["analyze"]);
        assert_eq!(def.dag.tasks[1].success_criteria.len(), 2);
    }

    #[test]
    fn single_task_dag_creates_valid_config() {
        let dag = single_task_dag("analyst", "Review the security posture");
        assert_eq!(dag.name, "subflow-analyst");
        assert_eq!(
            dag.description.as_deref(),
            Some("Single-task subflow delegated to analyst")
        );
        assert!(dag.parameters.is_empty());
        assert_eq!(dag.tasks.len(), 1);
        assert_eq!(dag.tasks[0].id, "main");
        assert_eq!(dag.tasks[0].specialist, "analyst");
        assert_eq!(dag.tasks[0].mandate, "Review the security posture");
        assert!(dag.tasks[0].depends_on.is_empty());
        assert!(dag.tasks[0].expected_output.is_none());
        assert!(dag.tasks[0].success_criteria.is_empty());
        assert!(dag.tasks[0].back_edges.is_empty());
        assert!(dag.blackboard_capacity.is_none());
    }

    #[test]
    fn single_task_dag_preserves_specialist_and_mandate() {
        let dag = single_task_dag("code-reviewer", "Check for SQL injection in auth module");
        assert_eq!(dag.tasks[0].specialist, "code-reviewer");
        assert_eq!(
            dag.tasks[0].mandate,
            "Check for SQL injection in auth module"
        );
    }

    #[test]
    fn generic_flow_dag_creates_four_stages() {
        let dag = generic_flow_dag("Audit the authentication module", None);
        assert_eq!(dag.name, "generic-escalation");
        assert_eq!(dag.tasks.len(), 4);

        let ids: Vec<&str> = dag.tasks.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["scout", "planner", "worker", "synthesize"]);

        // scout has no dependencies
        assert!(dag.tasks[0].depends_on.is_empty());
        assert_eq!(dag.tasks[0].model.as_deref(), Some("granite3.3:8b"));

        // planner depends on scout
        assert_eq!(dag.tasks[1].depends_on, vec!["scout"]);
        assert_eq!(dag.tasks[1].model.as_deref(), Some("gemma4:26b"));

        // worker depends on planner
        assert_eq!(dag.tasks[2].depends_on, vec!["planner"]);
        assert_eq!(dag.tasks[2].model.as_deref(), Some("gemma4:26b")); // worker needs reasoning

        // synthesize depends on worker
        assert_eq!(dag.tasks[3].depends_on, vec!["worker"]);
        assert_eq!(dag.tasks[3].model.as_deref(), Some("gemma4:26b"));
    }

    #[test]
    fn generic_flow_dag_includes_mandate_in_tasks() {
        let dag = generic_flow_dag("Review security posture", None);
        assert!(dag.tasks[0].mandate.contains("Review security posture"));
        assert!(dag.tasks[1].mandate.contains("Review security posture"));
        assert!(dag.tasks[2].mandate.contains("Review security posture"));
        assert!(dag.tasks[3].mandate.contains("Review security posture"));
    }

    #[test]
    fn generic_flow_dag_injects_context_into_scout() {
        let dag = generic_flow_dag("Check auth", Some("Focus on OAuth module"));
        assert!(dag.tasks[0].mandate.contains("Focus on OAuth module"));
        // Context should only be in scout, not other tasks
        assert!(!dag.tasks[1].mandate.contains("Focus on OAuth module"));
    }

    #[test]
    fn generic_flow_dag_without_context() {
        let dag = generic_flow_dag("Analyze deps", None);
        assert!(!dag.tasks[0].mandate.contains("Additional context"));
    }

    #[test]
    fn generic_flow_dag_description_includes_mandate() {
        let dag = generic_flow_dag("Fix the bug", None);
        assert_eq!(
            dag.description.as_deref(),
            Some("Generic 4-stage escalation flow for: Fix the bug")
        );
    }

    #[test]
    fn defaults_applied() {
        let toml_str = r#"
[flow]
name = "x"
entry = "a"

[[flow.nodes]]
id = "a"
endpoint = "http://x"
model_url = "http://x"
model_name = "m"
"#;
        let def: FlowDefinition = toml::from_str(toml_str).unwrap();
        let node = &def.flow.nodes[0];
        assert_eq!(node.max_iterations, 10);
        assert_eq!(node.temperature, None);
        assert_eq!(node.max_tokens, None);
        assert_eq!(node.system_prompt, "");
    }
}
