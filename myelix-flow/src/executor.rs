//! DAG executor: runs tasks with parallel execution of independent tasks.

use crate::dag::DependencyGraph;
use crate::error::FlowError;
use crate::recovery::{classify_failure, detect_circular_fix, get_strategy, RecoveryAction};
use crate::task::{Attempt, Task, TaskResult, TaskStatus};
use crate::validation::validate_mandate;
use myelix_agent::Agent;
use myelix_protocol::label::DataLabel;
use myelix_security::ifc::TaintTracker;
use std::collections::{HashMap, HashSet};

/// Result of executing a DAG of tasks.
#[derive(Debug)]
pub struct DagResult {
    /// Results for each task, keyed by task ID.
    pub task_results: HashMap<String, TaskResult>,
    /// Total prompt tokens consumed across all tasks.
    pub total_prompt_tokens: u32,
    /// Total completion tokens consumed across all tasks.
    pub total_completion_tokens: u32,
    /// Accumulated taint from all tasks.
    pub taint: DataLabel,
}

/// Executor for DAG-based task plans.
///
/// Holds agents keyed by specialist name. Independent tasks run
/// concurrently (up to `max_concurrent`), while dependent tasks
/// wait for their dependencies to complete.
pub struct DagExecutor {
    agents: HashMap<String, Agent>,
    max_concurrent: usize,
}

impl DagExecutor {
    /// Create a new executor.
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            max_concurrent: 4,
        }
    }

    /// Register an agent for a specialist name.
    pub fn agent(mut self, specialist: impl Into<String>, agent: Agent) -> Self {
        self.agents.insert(specialist.into(), agent);
        self
    }

    /// Set the maximum number of concurrent tasks (default: 4).
    pub fn max_concurrent(mut self, n: usize) -> Self {
        self.max_concurrent = n;
        self
    }

    /// Execute a DAG of tasks.
    ///
    /// Tasks are run in dependency order. Independent tasks execute
    /// concurrently (limited by `max_concurrent`). When a task depends
    /// on completed tasks, their outputs are injected as context.
    pub async fn run(&mut self, tasks: Vec<Task>) -> Result<DagResult, FlowError> {
        let dag = DependencyGraph::new(tasks)?;

        let mut results: HashMap<String, TaskResult> = HashMap::new();
        let mut completed: HashSet<String> = HashSet::new();
        let mut skipped: HashSet<String> = HashSet::new();
        let mut taint = TaintTracker::new();
        let mut total_prompt = 0u32;
        let mut total_completion = 0u32;

        loop {
            let ready: Vec<&Task> = dag
                .get_ready_tasks(&completed)
                .into_iter()
                .filter(|t| !skipped.contains(&t.id))
                .collect();

            if ready.is_empty() {
                break;
            }

            // Run ready tasks sequentially per specialist (agents need &mut self).
            // Group by specialist to identify which can run in parallel.
            // For v1: run all ready tasks sequentially. Parallel execution
            // across specialists would require Arc<Mutex<Agent>> which is
            // future work.
            for task in &ready {
                let agent = self.agents.get_mut(&task.specialist).ok_or_else(|| {
                    FlowError::UnknownSpecialist(task.specialist.clone())
                })?;

                tracing::info!(
                    task = %task.id,
                    specialist = %task.specialist,
                    "Executing DAG task"
                );

                let mut attempts: Vec<Attempt> = Vec::new();
                let max_retries = task.max_retries;
                let mut task_completed = false;

                for retry in 0..=max_retries {
                    // Build prompt, injecting prior failure context on retries
                    let mut prompt = build_task_prompt(task, &results);
                    if !attempts.is_empty() {
                        prompt = inject_retry_context(&prompt, &attempts);
                    }

                    let result = agent.run(&prompt).await;

                    match result {
                        Ok(tool_result) => {
                            taint.absorb(tool_result.taint);
                            total_prompt += tool_result.prompt_tokens;
                            total_completion += tool_result.completion_tokens;

                            // Validate mandate
                            let validation = validate_mandate(task, &tool_result.response);

                            if validation.passed {
                                results.insert(
                                    task.id.clone(),
                                    TaskResult {
                                        task_id: task.id.clone(),
                                        status: TaskStatus::Complete,
                                        output: tool_result.response,
                                        prompt_tokens: tool_result.prompt_tokens,
                                        completion_tokens: tool_result.completion_tokens,
                                        taint: tool_result.taint,
                                        validation_score: Some(validation.score),
                                        validation_notes: validation.notes,
                                    },
                                );
                                completed.insert(task.id.clone());
                                task_completed = true;
                                break;
                            }

                            // Validation failed — record attempt and maybe retry
                            let error_msg = format!(
                                "Mandate validation failed (score: {:.0}): {}",
                                validation.score,
                                validation.notes.join("; ")
                            );
                            tracing::warn!(
                                task = %task.id,
                                score = validation.score,
                                retry = retry,
                                "Mandate validation failed"
                            );

                            attempts.push(Attempt {
                                error: error_msg,
                                error_type: "validation_failed".to_string(),
                                output: tool_result.response,
                            });

                            if detect_circular_fix(&attempts, 3) {
                                tracing::warn!(task = %task.id, "Circular fix detected");
                                break;
                            }
                        }
                        Err(e) => {
                            let error_str = e.to_string();
                            let failure_type = classify_failure(&error_str, &attempts);
                            let strategy = get_strategy(&failure_type);

                            tracing::error!(
                                task = %task.id,
                                error = %error_str,
                                failure_type = ?failure_type,
                                "DAG task attempt failed"
                            );

                            attempts.push(Attempt {
                                error: error_str,
                                error_type: format!("{failure_type:?}").to_lowercase(),
                                output: String::new(),
                            });

                            match strategy.action {
                                RecoveryAction::Abort => {
                                    return Err(FlowError::TaskFailed {
                                        task: task.id.clone(),
                                        reason: attempts.last().unwrap().error.clone(),
                                    });
                                }
                                RecoveryAction::Skip => break,
                                RecoveryAction::RetryWithContext => {
                                    if detect_circular_fix(&attempts, 3) {
                                        tracing::warn!(task = %task.id, "Circular fix detected");
                                        break;
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                }

                if !task_completed {
                    // Task failed after all retries — mark failed and skip dependents
                    let last_error = attempts
                        .last()
                        .map(|a| a.error.clone())
                        .unwrap_or_else(|| "unknown failure".to_string());

                    results.insert(
                        task.id.clone(),
                        TaskResult {
                            task_id: task.id.clone(),
                            status: TaskStatus::Failed,
                            output: last_error,
                            prompt_tokens: 0,
                            completion_tokens: 0,
                            taint: DataLabel::TRUSTED_PUBLIC,
                            validation_score: None,
                            validation_notes: Vec::new(),
                        },
                    );

                    let to_skip = dag.all_dependents(&task.id);
                    for skip_id in &to_skip {
                        if !completed.contains(skip_id) {
                            skipped.insert(skip_id.clone());
                            results.insert(
                                skip_id.clone(),
                                TaskResult {
                                    task_id: skip_id.clone(),
                                    status: TaskStatus::Skipped,
                                    output: format!(
                                        "Skipped: dependency '{}' failed",
                                        task.id
                                    ),
                                    prompt_tokens: 0,
                                    completion_tokens: 0,
                                    taint: DataLabel::TRUSTED_PUBLIC,
                                    validation_score: None,
                                    validation_notes: Vec::new(),
                                },
                            );
                        }
                    }
                    completed.insert(task.id.clone());
                }
            }
        }

        Ok(DagResult {
            task_results: results,
            total_prompt_tokens: total_prompt,
            total_completion_tokens: total_completion,
            taint: taint.level(),
        })
    }
}

/// Build the user prompt for a task, injecting dependency outputs as context.
fn build_task_prompt(task: &Task, results: &HashMap<String, TaskResult>) -> String {
    let mut parts = Vec::new();

    // Inject dependency results as context
    let dep_outputs: Vec<(&str, &str)> = task
        .depends_on
        .iter()
        .filter_map(|dep_id| {
            results
                .get(dep_id)
                .filter(|r| r.status == TaskStatus::Complete)
                .map(|r| (dep_id.as_str(), r.output.as_str()))
        })
        .collect();

    if !dep_outputs.is_empty() {
        parts.push("## Results from dependency tasks:\n".to_string());
        for (id, output) in dep_outputs {
            parts.push(format!("### {id}:\n{output}\n"));
        }
        parts.push("---\n".to_string());
    }

    // Add input parameters
    if !task.inputs.is_empty() {
        parts.push("## Inputs:\n".to_string());
        for (key, value) in &task.inputs {
            parts.push(format!("- **{key}**: {value}\n"));
        }
        parts.push("\n".to_string());
    }

    // Add the mandate
    parts.push(format!("## Your task:\n{}", task.mandate));

    // Add success criteria
    if !task.success_criteria.is_empty() {
        parts.push("\n\n## Success criteria:".to_string());
        for criterion in &task.success_criteria {
            parts.push(format!("\n- {criterion}"));
        }
    }

    parts.join("")
}

/// Inject previous failure context into a retry prompt.
fn inject_retry_context(prompt: &str, attempts: &[Attempt]) -> String {
    let mut context = String::from("## Previous attempt(s) failed:\n\n");
    for (i, attempt) in attempts.iter().enumerate() {
        context.push_str(&format!(
            "### Attempt {} — {}\n{}\n\n",
            i + 1,
            attempt.error_type,
            attempt.error
        ));
    }
    context.push_str("Please address the issues above and try again.\n\n---\n\n");
    format!("{context}{prompt}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::Task;

    fn simple_task(id: &str, specialist: &str, deps: &[&str]) -> Task {
        Task {
            id: id.to_string(),
            specialist: specialist.to_string(),
            mandate: format!("Do task {id}"),
            depends_on: deps.iter().map(|s| s.to_string()).collect(),
            inputs: HashMap::new(),
            expected_output: None,
            success_criteria: Vec::new(),
            max_retries: 2,
        }
    }

    #[test]
    fn build_prompt_no_deps() {
        let task = simple_task("a", "dev", &[]);
        let prompt = build_task_prompt(&task, &HashMap::new());
        assert!(prompt.contains("Your task:"));
        assert!(prompt.contains("Do task a"));
        assert!(!prompt.contains("dependency"));
    }

    #[test]
    fn build_prompt_with_deps() {
        let task = simple_task("b", "dev", &["a"]);
        let mut results = HashMap::new();
        results.insert(
            "a".to_string(),
            TaskResult {
                task_id: "a".to_string(),
                status: TaskStatus::Complete,
                output: "Analysis complete: 3 issues found".to_string(),
                prompt_tokens: 0,
                completion_tokens: 0,
                taint: DataLabel::TRUSTED_PUBLIC,
                validation_score: Some(100.0),
                validation_notes: Vec::new(),
            },
        );

        let prompt = build_task_prompt(&task, &results);
        assert!(prompt.contains("Results from dependency"));
        assert!(prompt.contains("Analysis complete"));
        assert!(prompt.contains("Your task:"));
    }

    #[test]
    fn build_prompt_with_inputs_and_criteria() {
        let task = Task {
            id: "t".to_string(),
            specialist: "dev".to_string(),
            mandate: "Fix the bug".to_string(),
            depends_on: Vec::new(),
            inputs: {
                let mut m = HashMap::new();
                m.insert("file".to_string(), "main.rs".to_string());
                m
            },
            expected_output: None,
            success_criteria: vec!["Tests pass".to_string(), "No regressions".to_string()],
            max_retries: 2,
        };

        let prompt = build_task_prompt(&task, &HashMap::new());
        assert!(prompt.contains("**file**: main.rs"));
        assert!(prompt.contains("Tests pass"));
        assert!(prompt.contains("No regressions"));
    }
}
