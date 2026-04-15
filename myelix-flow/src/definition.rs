//! TOML-deserializable flow definitions.

use serde::Deserialize;

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
    /// Task definitions.
    pub tasks: Vec<TaskDefinition>,
    /// Capacity for the shared blackboard (default: 256). Set to enable blackboard.
    #[serde(default)]
    pub blackboard_capacity: Option<usize>,
}

/// Definition of a task in a DAG.
#[derive(Debug, Clone, Deserialize)]
pub struct TaskDefinition {
    /// Unique task identifier.
    pub id: String,
    /// Specialist (persona name) to execute this task.
    pub specialist: String,
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
