//! Task types for DAG-based execution.

use myelix_protocol::label::DataLabel;
use serde::Deserialize;
use std::collections::HashMap;

/// A task in a DAG execution plan.
#[derive(Debug, Clone, Deserialize)]
pub struct Task {
    /// Unique task identifier.
    pub id: String,
    /// Specialist (persona name or agent ID) to execute this task.
    pub specialist: String,
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
