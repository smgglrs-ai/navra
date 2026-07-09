//! Task types for DAG-based execution.

use crate::definition::{BackEdgeDefinition, TaskDefinition};
use crate::verification::VerificationConfig;
use navra_protocol::label::DataLabel;
use serde::Deserialize;
use std::collections::HashMap;

/// A task in a DAG execution plan.
#[derive(Debug, Clone, Deserialize)]
pub struct Task {
    /// Unique task identifier.
    pub id: String,
    /// Specialist (persona name or agent ID) to execute this task.
    pub specialist: String,
    /// Model override for this task (e.g. "granite3.3:8b"). If absent, uses the default.
    #[serde(default)]
    pub model: Option<String>,
    /// What the specialist should accomplish.
    pub mandate: String,
    /// Task IDs that must complete before this task can run.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Input parameters for the task.
    #[serde(default)]
    pub inputs: HashMap<String, String>,
    /// Description of expected output.
    #[serde(default)]
    pub expected_output: Option<String>,
    /// Criteria to meet for the task to be considered successful.
    #[serde(default)]
    pub success_criteria: Vec<String>,
    /// Maximum retry attempts on failure (default: 2).
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Conditional back-edges evaluated after task completion.
    #[serde(default)]
    pub back_edges: Vec<BackEdgeDefinition>,
    /// Cross-validation configuration for high-stakes outputs.
    #[serde(default)]
    pub verification: Option<VerificationConfig>,
    /// Temperature override for this task's model calls.
    #[serde(default)]
    pub temperature: Option<f32>,
    /// When true, the executor pauses before this task and waits
    /// for external approval. Used by BPMN userTask nodes.
    #[serde(default)]
    pub approval_required: bool,
}

fn default_max_retries() -> u32 {
    2
}

impl From<TaskDefinition> for Task {
    fn from(def: TaskDefinition) -> Self {
        Self {
            id: def.id,
            specialist: def.specialist,
            model: def.model,
            mandate: def.mandate,
            depends_on: def.depends_on,
            inputs: HashMap::new(),
            expected_output: def.expected_output,
            success_criteria: def.success_criteria,
            max_retries: default_max_retries(),
            back_edges: def.back_edges,
            verification: def.verification,
            temperature: def.temperature,
            approval_required: def.approval_required,
        }
    }
}

/// Status of a task in the execution plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    /// Waiting for dependencies.
    Pending,
    /// Dependencies satisfied, ready to run.
    Ready,
    /// Currently executing.
    Running,
    /// Successfully completed.
    Complete,
    /// Execution failed.
    Failed,
    /// Skipped due to failed dependencies.
    Skipped,
}

/// Result of executing a single task.
#[derive(Debug, Clone)]
pub struct TaskResult {
    /// Task ID.
    pub task_id: String,
    /// Final status.
    pub status: TaskStatus,
    /// Output text from the agent.
    pub output: String,
    /// Prompt tokens consumed.
    pub prompt_tokens: u32,
    /// Completion tokens consumed.
    pub completion_tokens: u32,
    /// Taint level from this task's execution.
    pub taint: DataLabel,
    /// Mandate validation score (0.0-100.0).
    pub validation_score: Option<f32>,
    /// Validation notes (what criteria were missed).
    pub validation_notes: Vec<String>,
}

/// A record of a failed attempt for circular fix detection.
#[derive(Debug, Clone)]
pub struct Attempt {
    /// Error message or validation failure description.
    pub error: String,
    /// Classified error type (e.g., "validation_failed", "agent_error").
    pub error_type: String,
    /// Output produced (if any).
    pub output: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_task() {
        let toml_str = r#"
id = "analyze"
specialist = "analyst"
mandate = "Analyze the codebase"
depends_on = ["setup"]
"#;
        let task: Task = toml::from_str(toml_str).unwrap();
        assert_eq!(task.id, "analyze");
        assert_eq!(task.specialist, "analyst");
        assert_eq!(task.depends_on, vec!["setup"]);
    }

    #[test]
    fn deserialize_task_minimal() {
        let toml_str = r#"
id = "simple"
specialist = "dev"
mandate = "Do something"
"#;
        let task: Task = toml::from_str(toml_str).unwrap();
        assert!(task.depends_on.is_empty());
        assert!(task.inputs.is_empty());
        assert!(task.expected_output.is_none());
    }
}
