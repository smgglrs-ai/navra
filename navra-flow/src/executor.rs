//! DAG executor: runs tasks with parallel execution of independent tasks.

use crate::backedge::{BackEdgeTracker, ConditionalEdge};
use crate::blackboard::Blackboard;
use crate::checkpoint::DagCheckpoint;
use crate::dag::DependencyGraph;
use crate::error::FlowError;
use crate::recovery::{classify_failure, detect_circular_fix, get_strategy, RecoveryAction};
use crate::task::{Attempt, Task, TaskResult, TaskStatus};
use crate::validation::validate_mandate;
use crate::verification;
use navra_agent::signal::{AgentSignal, SignalHandle};
use navra_agent::Agent;
use navra_protocol::label::DataLabel;
use navra_security::ifc::TaintTracker;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Insight produced after a task completes (success or failure).
///
/// Follows the ReasoningBank format: structured memory with a title,
/// one-sentence description, and 1-3 sentences of reasoning insights.
#[derive(Debug, Clone)]
pub struct TaskInsight {
    /// Short title (e.g. "Failure: analyze_code" or "Success: deploy_app").
    pub title: String,
    /// Structured reasoning content.
    pub content: String,
    /// Tags: `["failure", "lesson"]` or `["success", "strategy"]`.
    pub tags: Vec<String>,
    /// Confidence in this insight (0.0-1.0).
    pub confidence: f64,
    /// The task ID that produced this insight.
    pub task_id: String,
    /// The mandate of the task.
    pub mandate: String,
    /// Number of iterations/attempts the task went through.
    pub iterations: u32,
}

/// Callback invoked when the executor produces an insight from a completed task.
///
/// Implementors typically store the insight via `KnowledgeStore::store_distilled_with_generation`.
pub type InsightCallback = Arc<dyn Fn(TaskInsight) + Send + Sync>;

/// Callback to retrieve the most relevant past insight for a task mandate.
///
/// Returns `Some(content)` for the k=1 most relevant insight (ReasoningBank
/// finding: one focused memory beats multiple). Returns `None` if no
/// relevant insight exists.
pub type InsightRetriever = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

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
    signal_handles: HashMap<String, SignalHandle>,
    max_concurrent: usize,
    blackboard: Option<Blackboard>,
    insight_callback: Option<InsightCallback>,
    insight_retriever: Option<InsightRetriever>,
    /// Maximum agent-to-agent transitions in a single execution path.
    /// Prevents agent worm propagation patterns. 0 = unlimited.
    max_hops: usize,
    checkpoint: Option<(Arc<DagCheckpoint>, String)>,
    /// Per-tool failure counts and last-failure timestamps for circuit breaking.
    failure_counts: HashMap<String, (usize, std::time::Instant)>,
    /// Number of consecutive failures before a circuit opens.
    circuit_breaker_threshold: usize,
    /// How long an open circuit stays open before allowing a retry.
    circuit_breaker_cooldown: std::time::Duration,
}

impl Default for DagExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl DagExecutor {
    /// Create a new executor.
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            signal_handles: HashMap::new(),
            max_concurrent: 4,
            blackboard: None,
            max_hops: 0,
            insight_callback: None,
            insight_retriever: None,
            checkpoint: None,
            failure_counts: HashMap::new(),
            circuit_breaker_threshold: 5,
            circuit_breaker_cooldown: std::time::Duration::from_secs(60),
        }
    }

    /// Register an agent for a specialist name.
    ///
    /// Automatically installs a signal channel on the agent so the
    /// executor can deliver Interrupt/Terminate/Pause/Resume signals.
    pub fn agent(mut self, specialist: impl Into<String>, mut agent: Agent) -> Self {
        let name = specialist.into();
        let handle = agent.install_signal();
        self.signal_handles.insert(name.clone(), handle);
        self.agents.insert(name, agent);
        self
    }

    /// Send a signal to a specific agent by specialist name.
    pub fn agent_signal(&self, specialist: &str, signal: AgentSignal) -> Result<(), FlowError> {
        match self.signal_handles.get(specialist) {
            Some(handle) => {
                handle.send(signal);
                Ok(())
            }
            None => Err(FlowError::UnknownSpecialist(specialist.to_string())),
        }
    }

    /// Broadcast a signal to all registered agents.
    pub fn signal_all(&self, signal: AgentSignal) {
        for handle in self.signal_handles.values() {
            handle.send(signal.clone());
        }
    }

    /// Set the maximum number of concurrent tasks (default: 4).
    pub fn max_concurrent(mut self, n: usize) -> Self {
        self.max_concurrent = n;
        self
    }

    /// Enable the shared blackboard with the given entry limit.
    pub fn enable_blackboard(mut self, capacity: usize) -> Self {
        self.blackboard = Some(Blackboard::new(capacity));
        self
    }

    /// Set a callback for receiving task insights (ReasoningBank pattern).
    ///
    /// The callback is invoked after each task completes (success or failure)
    /// with a structured insight that can be stored in the knowledge store.
    pub fn on_insight(mut self, callback: InsightCallback) -> Self {
        self.insight_callback = Some(callback);
        self
    }

    /// Set a retriever for past insights (ReasoningBank k=1 pattern).
    ///
    /// Before starting each task, the executor queries this retriever
    /// with the task mandate and injects the most relevant past insight
    /// into the task prompt as a "lesson learned" section.
    pub fn with_insight_retriever(mut self, retriever: InsightRetriever) -> Self {
        self.insight_retriever = Some(retriever);
        self
    }

    /// Set maximum agent-to-agent transitions (hop limit).
    ///
    /// Prevents agent worm propagation patterns. When the hop limit
    /// is reached, further task execution is aborted. 0 = unlimited.
    pub fn with_max_hops(mut self, max_hops: usize) -> Self {
        self.max_hops = max_hops;
        self
    }

    /// Enable per-node checkpointing for crash recovery.
    ///
    /// After each task completes, the executor saves a checkpoint to
    /// the provided store. On resume (via `run()` with the same flow_id),
    /// completed tasks are skipped.
    pub fn with_checkpoint(mut self, store: Arc<DagCheckpoint>, flow_id: String) -> Self {
        self.checkpoint = Some((store, flow_id));
        self
    }

    /// Configure the circuit breaker threshold and cooldown.
    pub fn with_circuit_breaker(mut self, threshold: usize, cooldown: std::time::Duration) -> Self {
        self.circuit_breaker_threshold = threshold;
        self.circuit_breaker_cooldown = cooldown;
        self
    }

    /// Check whether the circuit is open (tripped) for a given tool.
    ///
    /// Returns `true` when the failure count is at or above the threshold
    /// AND the cooldown period has not yet elapsed since the last failure.
    pub fn is_circuit_open(&self, tool: &str) -> bool {
        if let Some(&(count, last_failure)) = self.failure_counts.get(tool) {
            count >= self.circuit_breaker_threshold
                && last_failure.elapsed() < self.circuit_breaker_cooldown
        } else {
            false
        }
    }

    /// Record a failure for a tool, incrementing its count and updating
    /// the last-failure timestamp.
    pub fn record_failure(&mut self, tool: &str) {
        let entry = self
            .failure_counts
            .entry(tool.to_string())
            .or_insert((0, std::time::Instant::now()));
        entry.0 += 1;
        entry.1 = std::time::Instant::now();
    }

    /// Record a success for a tool, resetting its failure count.
    pub fn record_success(&mut self, tool: &str) {
        self.failure_counts.remove(tool);
    }

    /// Execute a DAG of tasks.
    ///
    /// Tasks are run in dependency order. Independent tasks execute
    /// concurrently (limited by `max_concurrent`). When a task depends
    /// on completed tasks, their outputs are injected as context.
    pub async fn run(&mut self, tasks: Vec<Task>) -> Result<DagResult, FlowError> {
        // Parse back-edges from task definitions before constructing the DAG
        let mut back_edges: Vec<ConditionalEdge> = Vec::new();
        for task in &tasks {
            for be_def in &task.back_edges {
                let edge = ConditionalEdge::from_definition(&task.id, be_def)?;
                back_edges.push(edge);
            }
        }

        let dag = DependencyGraph::new(tasks)?;

        let mut results: HashMap<String, TaskResult> = HashMap::new();
        let mut completed: HashSet<String> = HashSet::new();
        let mut skipped: HashSet<String> = HashSet::new();
        let mut taint = TaintTracker::new();
        let mut total_prompt = 0u32;
        let mut total_completion = 0u32;
        let mut back_edge_tracker = BackEdgeTracker::new();
        let mut hop_count: usize = 0;

        // Resume from checkpoint: pre-populate completed tasks
        if let Some((ref cp, ref flow_id)) = self.checkpoint {
            if let Ok(Some(cp_state)) = cp.load(flow_id) {
                for (task_id, output) in &cp_state.completed {
                    completed.insert(task_id.clone());
                    results.insert(
                        task_id.clone(),
                        TaskResult {
                            task_id: task_id.clone(),
                            status: TaskStatus::Complete,
                            output: output.clone(),
                            prompt_tokens: 0,
                            completion_tokens: 0,
                            taint: DataLabel::TRUSTED_PUBLIC,
                            validation_score: None,
                            validation_notes: Vec::new(),
                        },
                    );
                }
                if !completed.is_empty() {
                    tracing::info!(
                        flow_id = %flow_id,
                        resumed = completed.len(),
                        "Resuming DAG from checkpoint"
                    );
                }
            }
        }

        loop {
            // Hop limit enforcement
            if self.max_hops > 0 && hop_count >= self.max_hops {
                tracing::error!(
                    hop_count,
                    max_hops = self.max_hops,
                    "DAG execution aborted — hop limit exceeded"
                );
                return Err(FlowError::Other(anyhow::anyhow!(
                    "hop limit exceeded: {} transitions (max {})",
                    hop_count,
                    self.max_hops,
                )));
            }

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
                if !self.agents.contains_key(&task.specialist) {
                    return Err(FlowError::UnknownSpecialist(task.specialist.clone()));
                }

                tracing::info!(
                    task = %task.id,
                    specialist = %task.specialist,
                    "Executing DAG task"
                );

                let mut attempts: Vec<Attempt> = Vec::new();
                let max_retries = task.max_retries;
                let mut task_completed = false;

                for retry in 0..=max_retries {
                    // Query past insights for this task (ReasoningBank k=1)
                    let past_insight = self
                        .insight_retriever
                        .as_ref()
                        .and_then(|r| r(&task.mandate));

                    // Build prompt, injecting past insight and prior failure context
                    let mut prompt =
                        build_task_prompt_with_insight(task, &results, past_insight.as_deref());
                    if !attempts.is_empty() {
                        prompt = inject_retry_context(&prompt, &attempts);
                    }

                    let result = {
                        let agent = self.agents.get_mut(&task.specialist).unwrap();
                        agent.run(&prompt).await
                    };

                    match result {
                        Ok(tool_result) => {
                            taint.absorb(tool_result.taint);
                            total_prompt += tool_result.input_tokens;
                            total_completion += tool_result.output_tokens;

                            // Validate mandate
                            let validation = validate_mandate(task, &tool_result.response);

                            if validation.passed {
                                // Cross-validation: if configured, verify the output
                                if let Some(ref ver_config) = task.verification {
                                    tracing::info!(
                                        task = %task.id,
                                        agents = ver_config.agents,
                                        threshold = ?ver_config.threshold,
                                        "Running cross-validation"
                                    );

                                    let ver_result = verification::verify_result(
                                        task,
                                        &tool_result.response,
                                        ver_config,
                                        &mut self.agents,
                                    )
                                    .await?;

                                    total_prompt += ver_result.prompt_tokens;
                                    total_completion += ver_result.completion_tokens;

                                    if !ver_result.passed {
                                        let findings_str = ver_result.findings.join("; ");
                                        let error_msg = format!(
                                            "Cross-validation failed ({}/{} verifiers rejected): {}",
                                            ver_result.verdicts.iter().filter(|v| !v.passed).count(),
                                            ver_result.verdicts.len(),
                                            findings_str
                                        );
                                        tracing::warn!(
                                            task = %task.id,
                                            "Cross-validation failed"
                                        );

                                        attempts.push(Attempt {
                                            error: error_msg,
                                            error_type: "verification_failed".to_string(),
                                            output: tool_result.response,
                                        });

                                        if detect_circular_fix(&attempts, 3) {
                                            tracing::warn!(task = %task.id, "Circular fix detected");
                                            break;
                                        }
                                        continue;
                                    }
                                }

                                let task_result = TaskResult {
                                    task_id: task.id.clone(),
                                    status: TaskStatus::Complete,
                                    output: tool_result.response,
                                    prompt_tokens: tool_result.input_tokens,
                                    completion_tokens: tool_result.output_tokens,
                                    taint: tool_result.taint,
                                    validation_score: Some(validation.score),
                                    validation_notes: validation.notes,
                                };

                                // Evaluate back-edges before marking as complete
                                let mut requeued = false;
                                for edge in &back_edges {
                                    if edge.from == task.id
                                        && back_edge_tracker.should_activate(edge, &task_result)
                                    {
                                        let count = back_edge_tracker
                                            .record_activation(&edge.from, &edge.to);
                                        tracing::info!(
                                            from = %edge.from,
                                            to = %edge.to,
                                            iteration = count,
                                            "Back-edge activated"
                                        );
                                        // Remove target and its dependents from completed
                                        completed.remove(&edge.to);
                                        results.remove(&edge.to);
                                        let dependents = dag.all_dependents(&edge.to);
                                        for dep_id in &dependents {
                                            completed.remove(dep_id);
                                            results.remove(dep_id);
                                        }
                                        requeued = true;
                                    }
                                }

                                // Emit success insight via callback
                                if let Some(ref cb) = self.insight_callback {
                                    let summary = if task_result.output.len() > 200 {
                                        format!("{}...", &task_result.output[..197])
                                    } else {
                                        task_result.output.clone()
                                    };
                                    cb(TaskInsight {
                                        title: format!("Success: {}", task.id),
                                        content: format!(
                                            "For [{}] with mandate \"{}\", \
                                             the approach succeeded in {} iteration(s). \
                                             Key outcome: {}.",
                                            task.id,
                                            task.mandate,
                                            retry + 1,
                                            summary,
                                        ),
                                        tags: vec!["success".into(), "strategy".into()],
                                        confidence: 0.85,
                                        task_id: task.id.clone(),
                                        mandate: task.mandate.clone(),
                                        iterations: retry + 1,
                                    });
                                }

                                // Per-node checkpoint
                                if let Some((ref cp, ref flow_id)) = self.checkpoint {
                                    if let Err(e) = cp.save_node(
                                        flow_id,
                                        &task.id,
                                        &task_result.output,
                                    ) {
                                        tracing::warn!(
                                            task = %task.id,
                                            error = %e,
                                            "Failed to save per-node checkpoint"
                                        );
                                    }
                                }

                                results.insert(task.id.clone(), task_result);
                                completed.insert(task.id.clone());
                                hop_count += 1;
                                task_completed = true;
                                if requeued {
                                    // Don't break — continue with the outer loop to
                                    // re-discover ready tasks including re-queued ones
                                }
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
                                        reason: attempts
                                            .last()
                                            .map(|a| a.error.clone())
                                            .unwrap_or_else(|| "unknown error".into()),
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

                    // Emit failure insight via callback
                    if let Some(ref cb) = self.insight_callback {
                        let history: Vec<String> = attempts
                            .iter()
                            .enumerate()
                            .map(|(i, a)| format!("Attempt {}: {}", i + 1, a.error))
                            .collect();
                        let history_summary = history.join(". ");

                        cb(TaskInsight {
                            title: format!("Failure: {}", task.id),
                            content: format!(
                                "When attempting [{}] with mandate \"{}\", \
                                 the approach failed because [{}]. \
                                 Attempt history: {}. \
                                 Avoid repeating this approach without addressing the root cause.",
                                task.id, task.mandate, last_error, history_summary,
                            ),
                            tags: vec!["failure".into(), "lesson".into()],
                            confidence: 0.7,
                            task_id: task.id.clone(),
                            mandate: task.mandate.clone(),
                            iterations: attempts.len() as u32,
                        });
                    }

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
                                    output: format!("Skipped: dependency '{}' failed", task.id),
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
                    hop_count += 1;
                }
            }
        }

        // Delete checkpoint on successful completion
        if let Some((ref cp, ref flow_id)) = self.checkpoint {
            if let Err(e) = cp.delete(flow_id) {
                tracing::warn!(flow_id = %flow_id, error = %e, "Failed to delete checkpoint");
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

/// Build the user prompt for a task, injecting dependency outputs and
/// an optional retrieved insight (ReasoningBank k=1) as context.
#[cfg(test)]
fn build_task_prompt(task: &Task, results: &HashMap<String, TaskResult>) -> String {
    build_task_prompt_with_insight(task, results, None)
}

/// Build a task prompt, optionally injecting a past lesson learned.
fn build_task_prompt_with_insight(
    task: &Task,
    results: &HashMap<String, TaskResult>,
    insight: Option<&str>,
) -> String {
    let mut parts = Vec::new();

    // Inject retrieved lesson learned (ReasoningBank k=1)
    if let Some(lesson) = insight {
        parts.push("## Lesson learned from past attempts:\n".to_string());
        parts.push(format!("{lesson}\n\n---\n"));
    }

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
            model: None,
            mandate: format!("Do task {id}"),
            depends_on: deps.iter().map(|s| s.to_string()).collect(),
            inputs: HashMap::new(),
            expected_output: None,
            success_criteria: Vec::new(),
            max_retries: 2,
            back_edges: Vec::new(),
            verification: None,
            temperature: None,
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
            model: None,
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
            back_edges: Vec::new(),
            verification: None,
            temperature: None,
        };

        let prompt = build_task_prompt(&task, &HashMap::new());
        assert!(prompt.contains("**file**: main.rs"));
        assert!(prompt.contains("Tests pass"));
        assert!(prompt.contains("No regressions"));
    }

    #[test]
    fn build_prompt_with_insight_injects_lesson() {
        let task = simple_task("deploy", "ops", &[]);
        let insight = "When attempting deploy, port 443 was already in use. Use port 8443 instead.";
        let prompt = build_task_prompt_with_insight(&task, &HashMap::new(), Some(insight));
        assert!(prompt.contains("Lesson learned from past attempts:"));
        assert!(prompt.contains("port 443"));
        assert!(prompt.contains("Your task:"));
    }

    #[test]
    fn build_prompt_without_insight_omits_lesson_section() {
        let task = simple_task("build", "dev", &[]);
        let prompt = build_task_prompt_with_insight(&task, &HashMap::new(), None);
        assert!(!prompt.contains("Lesson learned"));
        assert!(prompt.contains("Your task:"));
    }

    #[test]
    fn task_insight_struct_is_complete() {
        let insight = TaskInsight {
            title: "Failure: deploy".to_string(),
            content: "Port conflict".to_string(),
            tags: vec!["failure".to_string(), "lesson".to_string()],
            confidence: 0.7,
            task_id: "deploy".to_string(),
            mandate: "Deploy the app".to_string(),
            iterations: 3,
        };
        assert_eq!(insight.title, "Failure: deploy");
        assert_eq!(insight.tags.len(), 2);
        assert_eq!(insight.iterations, 3);
    }

    #[test]
    fn agent_signal_unknown_specialist_returns_error() {
        let executor = DagExecutor::new();
        let result = executor.agent_signal("ghost", AgentSignal::Interrupt);
        assert!(result.is_err());
    }

    #[test]
    fn circuit_breaker_trips_after_threshold() {
        let mut executor = DagExecutor::new()
            .with_circuit_breaker(3, std::time::Duration::from_secs(60));

        assert!(!executor.is_circuit_open("tool_a"));

        executor.record_failure("tool_a");
        executor.record_failure("tool_a");
        assert!(!executor.is_circuit_open("tool_a"));

        executor.record_failure("tool_a");
        assert!(executor.is_circuit_open("tool_a"));
    }

    #[test]
    fn circuit_breaker_resets_on_success() {
        let mut executor = DagExecutor::new()
            .with_circuit_breaker(2, std::time::Duration::from_secs(60));

        executor.record_failure("tool_b");
        executor.record_failure("tool_b");
        assert!(executor.is_circuit_open("tool_b"));

        executor.record_success("tool_b");
        assert!(!executor.is_circuit_open("tool_b"));
    }

    #[test]
    fn circuit_breaker_cooldown_expires() {
        let mut executor = DagExecutor::new()
            .with_circuit_breaker(2, std::time::Duration::from_millis(1));

        executor.record_failure("tool_c");
        executor.record_failure("tool_c");

        // Wait for cooldown to expire
        std::thread::sleep(std::time::Duration::from_millis(5));

        assert!(
            !executor.is_circuit_open("tool_c"),
            "circuit should be closed after cooldown expires"
        );
    }
}
