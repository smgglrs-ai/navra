//! Self-Harness: gateway-driven self-improvement via execution trace analysis.
//!
//! Implements the Self-Harness pattern (arxiv 2606.09498) adapted for navra:
//!
//! 1. **Weakness mining** — analyze event log traces for failure patterns
//!    (tool errors, safety violations, retry loops, timeouts)
//! 2. **Harness proposal** — generate structured improvement proposals
//!    (flow DAG edits, policy changes, hook configurations)
//! 3. **Regression validation** — verify proposals don't break passing traces
//!
//! All analysis runs out-of-band. Agents are unaware of the improvement process.

use crate::event_log::{EventLog, FlowEvent, StoredEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Category of weakness detected in execution traces.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WeaknessType {
    /// Tool calls that returned errors.
    ToolError,
    /// Node failures (agent errors, crashes).
    NodeFailure,
    /// Excessive back-edge iterations (retry loops).
    RetryLoop,
    /// Nodes that were skipped (possibly misconfigured dependencies).
    SkippedNode,
    /// High token usage relative to output (inefficiency).
    TokenInefficiency,
    /// Tool calls with very long duration.
    SlowToolCall,
}

/// A weakness finding from trace analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeaknessFinding {
    /// Type of weakness.
    pub weakness_type: WeaknessType,
    /// Human-readable description.
    pub description: String,
    /// Flow ID where this was observed.
    pub flow_id: String,
    /// Affected task/node ID.
    pub task_id: Option<String>,
    /// Affected tool name (for tool-related weaknesses).
    pub tool_name: Option<String>,
    /// Number of occurrences across analyzed traces.
    pub occurrences: u32,
    /// Severity score (0.0 = informational, 1.0 = critical).
    pub severity: f64,
    /// Evidence: relevant event sequence numbers.
    pub evidence_seqs: Vec<i64>,
}

/// Configuration for weakness mining thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningConfig {
    /// Back-edge iteration count considered excessive.
    #[serde(default = "default_retry_threshold")]
    pub retry_threshold: u32,
    /// Tool call duration (ms) considered slow.
    #[serde(default = "default_slow_tool_ms")]
    pub slow_tool_ms: u64,
    /// Completion/prompt token ratio below which output is inefficient.
    #[serde(default = "default_efficiency_ratio")]
    pub efficiency_ratio: f64,
    /// Minimum occurrences before reporting a weakness.
    #[serde(default = "default_min_occurrences")]
    pub min_occurrences: u32,
}

fn default_retry_threshold() -> u32 {
    3
}
fn default_slow_tool_ms() -> u64 {
    10_000
}
fn default_efficiency_ratio() -> f64 {
    0.1
}
fn default_min_occurrences() -> u32 {
    1
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            retry_threshold: default_retry_threshold(),
            slow_tool_ms: default_slow_tool_ms(),
            efficiency_ratio: default_efficiency_ratio(),
            min_occurrences: default_min_occurrences(),
        }
    }
}

/// Mine weaknesses from a set of flow execution traces.
pub fn mine_weaknesses(
    events: &[StoredEvent],
    config: &MiningConfig,
) -> Vec<WeaknessFinding> {
    let mut findings = Vec::new();

    let mut tool_errors: HashMap<String, Vec<i64>> = HashMap::new();
    let mut node_failures: HashMap<String, Vec<i64>> = HashMap::new();
    let mut skipped_nodes: HashMap<String, Vec<i64>> = HashMap::new();
    let mut back_edges: HashMap<(String, String), (u32, Vec<i64>)> = HashMap::new();
    let mut slow_tools: HashMap<String, Vec<(u64, i64)>> = HashMap::new();
    let mut node_tokens: HashMap<String, (u32, u32, i64)> = HashMap::new();

    for event in events {
        match &event.event {
            FlowEvent::ToolResult {
                task_id,
                tool_name,
                is_error,
                duration_ms,
            } => {
                if *is_error {
                    tool_errors
                        .entry(format!("{}:{}", task_id, tool_name))
                        .or_default()
                        .push(event.seq);
                }
                if *duration_ms > config.slow_tool_ms {
                    slow_tools
                        .entry(tool_name.clone())
                        .or_default()
                        .push((*duration_ms, event.seq));
                }
            }
            FlowEvent::NodeFailed { task_id, .. } => {
                node_failures
                    .entry(task_id.clone())
                    .or_default()
                    .push(event.seq);
            }
            FlowEvent::NodeSkipped { task_id, .. } => {
                skipped_nodes
                    .entry(task_id.clone())
                    .or_default()
                    .push(event.seq);
            }
            FlowEvent::BackEdgeActivated {
                from,
                to,
                iteration,
            } => {
                let entry = back_edges
                    .entry((from.clone(), to.clone()))
                    .or_insert((0, Vec::new()));
                entry.0 = entry.0.max(*iteration);
                entry.1.push(event.seq);
            }
            FlowEvent::NodeCompleted {
                task_id,
                prompt_tokens,
                completion_tokens,
                ..
            } => {
                node_tokens
                    .entry(task_id.clone())
                    .or_insert((0, 0, event.seq));
                let entry = node_tokens.get_mut(task_id).unwrap();
                entry.0 += prompt_tokens;
                entry.1 += completion_tokens;
                entry.2 = event.seq;
            }
            _ => {}
        }
    }

    let flow_id = events
        .first()
        .map(|e| e.flow_id.clone())
        .unwrap_or_default();

    for (key, seqs) in &tool_errors {
        if (seqs.len() as u32) < config.min_occurrences {
            continue;
        }
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        findings.push(WeaknessFinding {
            weakness_type: WeaknessType::ToolError,
            description: format!(
                "Tool '{}' in task '{}' returned errors {} times",
                parts.get(1).unwrap_or(&"?"),
                parts.first().unwrap_or(&"?"),
                seqs.len()
            ),
            flow_id: flow_id.clone(),
            task_id: parts.first().map(|s| s.to_string()),
            tool_name: parts.get(1).map(|s| s.to_string()),
            occurrences: seqs.len() as u32,
            severity: (seqs.len() as f64 / events.len() as f64).min(1.0) * 0.8,
            evidence_seqs: seqs.clone(),
        });
    }

    for (task_id, seqs) in &node_failures {
        if (seqs.len() as u32) < config.min_occurrences {
            continue;
        }
        findings.push(WeaknessFinding {
            weakness_type: WeaknessType::NodeFailure,
            description: format!("Task '{}' failed {} times", task_id, seqs.len()),
            flow_id: flow_id.clone(),
            task_id: Some(task_id.clone()),
            tool_name: None,
            occurrences: seqs.len() as u32,
            severity: 0.9,
            evidence_seqs: seqs.clone(),
        });
    }

    for (task_id, seqs) in &skipped_nodes {
        if (seqs.len() as u32) < config.min_occurrences {
            continue;
        }
        findings.push(WeaknessFinding {
            weakness_type: WeaknessType::SkippedNode,
            description: format!("Task '{}' was skipped {} times", task_id, seqs.len()),
            flow_id: flow_id.clone(),
            task_id: Some(task_id.clone()),
            tool_name: None,
            occurrences: seqs.len() as u32,
            severity: 0.3,
            evidence_seqs: seqs.clone(),
        });
    }

    for ((from, to), (max_iter, seqs)) in &back_edges {
        if *max_iter >= config.retry_threshold {
            findings.push(WeaknessFinding {
                weakness_type: WeaknessType::RetryLoop,
                description: format!(
                    "Back-edge '{from}' → '{to}' reached {max_iter} iterations (threshold: {})",
                    config.retry_threshold
                ),
                flow_id: flow_id.clone(),
                task_id: Some(from.clone()),
                tool_name: None,
                occurrences: seqs.len() as u32,
                severity: (*max_iter as f64 / (config.retry_threshold as f64 * 2.0)).min(1.0),
                evidence_seqs: seqs.clone(),
            });
        }
    }

    for (tool_name, durations) in &slow_tools {
        if (durations.len() as u32) < config.min_occurrences {
            continue;
        }
        let avg_ms: u64 = durations.iter().map(|(d, _)| d).sum::<u64>() / durations.len() as u64;
        findings.push(WeaknessFinding {
            weakness_type: WeaknessType::SlowToolCall,
            description: format!(
                "Tool '{tool_name}' averaged {avg_ms}ms across {} slow calls (>{} ms)",
                durations.len(),
                config.slow_tool_ms
            ),
            flow_id: flow_id.clone(),
            task_id: None,
            tool_name: Some(tool_name.clone()),
            occurrences: durations.len() as u32,
            severity: (avg_ms as f64 / (config.slow_tool_ms as f64 * 5.0)).min(1.0),
            evidence_seqs: durations.iter().map(|(_, s)| *s).collect(),
        });
    }

    for (task_id, (prompt, completion, seq)) in &node_tokens {
        if *prompt == 0 {
            continue;
        }
        let ratio = *completion as f64 / *prompt as f64;
        if ratio < config.efficiency_ratio {
            findings.push(WeaknessFinding {
                weakness_type: WeaknessType::TokenInefficiency,
                description: format!(
                    "Task '{task_id}' used {prompt} prompt tokens but only generated \
                     {completion} completion tokens (ratio: {ratio:.3})",
                ),
                flow_id: flow_id.clone(),
                task_id: Some(task_id.clone()),
                tool_name: None,
                occurrences: 1,
                severity: ((config.efficiency_ratio - ratio) / config.efficiency_ratio).max(0.0),
                evidence_seqs: vec![*seq],
            });
        }
    }

    findings.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap_or(std::cmp::Ordering::Equal));
    findings
}

/// Mine weaknesses from an EventLog across all flows.
pub fn mine_from_event_log(
    log: &EventLog,
    flow_ids: &[&str],
    config: &MiningConfig,
) -> Vec<WeaknessFinding> {
    let mut all_findings = Vec::new();
    for flow_id in flow_ids {
        if let Ok(events) = log.all_events(flow_id) {
            let mut findings = mine_weaknesses(&events, config);
            all_findings.append(&mut findings);
        }
    }
    all_findings.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap_or(std::cmp::Ordering::Equal));
    all_findings
}

// --- Harness proposal ---

/// Kind of improvement proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    /// Modify the flow DAG structure (add/remove/reorder nodes).
    FlowDagEdit,
    /// Change a policy or permission setting.
    PolicyChange,
    /// Modify safety hook configuration.
    HookConfig,
    /// Adjust tool parameters or timeout.
    ToolConfig,
    /// Add a back-edge condition or change iteration limits.
    BackEdgeAdjust,
}

/// A structured improvement proposal generated from weakness findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessProposal {
    /// Unique proposal identifier.
    pub id: String,
    /// Kind of change proposed.
    pub kind: ProposalKind,
    /// Human-readable description of the proposed change.
    pub description: String,
    /// The weakness findings that motivated this proposal.
    pub addresses: Vec<WeaknessType>,
    /// Expected improvement (lower bound, 0.0-1.0).
    pub expected_improvement: f64,
    /// Risk of regression (0.0 = safe, 1.0 = high risk).
    pub regression_risk: f64,
    /// Structured diff: what to change.
    pub diff: ProposalDiff,
}

/// Structured diff describing what the proposal changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProposalDiff {
    /// Change a back-edge's max iteration count.
    BackEdgeLimit {
        from: String,
        to: String,
        old_limit: u32,
        new_limit: u32,
    },
    /// Add a timeout to a tool or node.
    AddTimeout {
        target: String,
        timeout_ms: u64,
    },
    /// Skip or remove a node from the flow.
    RemoveNode {
        task_id: String,
        reason: String,
    },
    /// Add a recovery fallback for a failing node.
    AddFallback {
        task_id: String,
        fallback_specialist: String,
    },
    /// Change a tool's configuration.
    ToolConfigChange {
        tool_name: String,
        key: String,
        old_value: String,
        new_value: String,
    },
}

/// Generate improvement proposals from weakness findings.
pub fn propose_harnesses(findings: &[WeaknessFinding]) -> Vec<HarnessProposal> {
    let mut proposals = Vec::new();
    let mut proposal_id = 0u32;

    for finding in findings {
        let proposal = match &finding.weakness_type {
            WeaknessType::RetryLoop => {
                let task_id = finding.task_id.as_deref().unwrap_or("unknown");
                Some(HarnessProposal {
                    id: format!("SH-{proposal_id:04}"),
                    kind: ProposalKind::BackEdgeAdjust,
                    description: format!(
                        "Reduce back-edge iterations for '{}' or add exit condition",
                        task_id
                    ),
                    addresses: vec![WeaknessType::RetryLoop],
                    expected_improvement: 0.3,
                    regression_risk: 0.2,
                    diff: ProposalDiff::BackEdgeLimit {
                        from: task_id.to_string(),
                        to: String::new(),
                        old_limit: finding.occurrences,
                        new_limit: finding.occurrences.saturating_sub(1).max(1),
                    },
                })
            }
            WeaknessType::SlowToolCall => {
                let tool = finding.tool_name.as_deref().unwrap_or("unknown");
                Some(HarnessProposal {
                    id: format!("SH-{proposal_id:04}"),
                    kind: ProposalKind::ToolConfig,
                    description: format!("Add timeout guard for slow tool '{tool}'"),
                    addresses: vec![WeaknessType::SlowToolCall],
                    expected_improvement: 0.4,
                    regression_risk: 0.1,
                    diff: ProposalDiff::AddTimeout {
                        target: tool.to_string(),
                        timeout_ms: 30_000,
                    },
                })
            }
            WeaknessType::NodeFailure if finding.occurrences >= 2 => {
                let task = finding.task_id.as_deref().unwrap_or("unknown");
                Some(HarnessProposal {
                    id: format!("SH-{proposal_id:04}"),
                    kind: ProposalKind::FlowDagEdit,
                    description: format!(
                        "Add fallback specialist for repeatedly failing task '{task}'"
                    ),
                    addresses: vec![WeaknessType::NodeFailure],
                    expected_improvement: 0.5,
                    regression_risk: 0.3,
                    diff: ProposalDiff::AddFallback {
                        task_id: task.to_string(),
                        fallback_specialist: "general".to_string(),
                    },
                })
            }
            WeaknessType::SkippedNode if finding.occurrences >= 3 => {
                let task = finding.task_id.as_deref().unwrap_or("unknown");
                Some(HarnessProposal {
                    id: format!("SH-{proposal_id:04}"),
                    kind: ProposalKind::FlowDagEdit,
                    description: format!(
                        "Consider removing persistently skipped task '{task}'"
                    ),
                    addresses: vec![WeaknessType::SkippedNode],
                    expected_improvement: 0.1,
                    regression_risk: 0.4,
                    diff: ProposalDiff::RemoveNode {
                        task_id: task.to_string(),
                        reason: format!("Skipped {} times", finding.occurrences),
                    },
                })
            }
            _ => None,
        };

        if let Some(p) = proposal {
            proposals.push(p);
            proposal_id += 1;
        }
    }

    proposals
}

// --- Regression validation ---

/// Outcome of a trace-based validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcome {
    /// Proposal is safe: no regressions on recorded traces.
    Safe,
    /// Proposal may cause regressions.
    Regression,
    /// Insufficient historical data to validate.
    InsufficientData,
}

/// Result of validating a proposal against historical traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceValidationResult {
    /// Proposal that was validated.
    pub proposal_id: String,
    /// Overall validation outcome.
    pub outcome: ValidationOutcome,
    /// Number of historical traces checked.
    pub traces_checked: usize,
    /// Number of traces that would regress under this proposal.
    pub regressions: usize,
    /// Affected flow IDs (where regressions were detected).
    pub affected_flows: Vec<String>,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Validate a proposal against historical event log traces.
///
/// Checks whether the proposed change would have caused regressions
/// in previously-successful flow executions.
pub fn validate_proposal(
    proposal: &HarnessProposal,
    log: &EventLog,
    flow_ids: &[&str],
) -> TraceValidationResult {
    if flow_ids.is_empty() {
        return TraceValidationResult {
            proposal_id: proposal.id.clone(),
            outcome: ValidationOutcome::InsufficientData,
            traces_checked: 0,
            regressions: 0,
            affected_flows: Vec::new(),
            explanation: "No historical traces available for validation".to_string(),
        };
    }

    let mut traces_checked = 0;
    let mut regressions = 0;
    let mut affected_flows = Vec::new();

    for flow_id in flow_ids {
        let events = match log.all_events(flow_id) {
            Ok(e) if !e.is_empty() => e,
            _ => continue,
        };
        traces_checked += 1;

        let flow_succeeded = events.iter().any(|e| matches!(&e.event, FlowEvent::FlowCompleted { .. }));
        if !flow_succeeded {
            continue;
        }

        if would_regress(proposal, &events) {
            regressions += 1;
            affected_flows.push(flow_id.to_string());
        }
    }

    let outcome = if traces_checked == 0 {
        ValidationOutcome::InsufficientData
    } else if regressions > 0 {
        ValidationOutcome::Regression
    } else {
        ValidationOutcome::Safe
    };

    let explanation = match outcome {
        ValidationOutcome::Safe => format!(
            "Validated against {} successful traces — no regressions",
            traces_checked
        ),
        ValidationOutcome::Regression => format!(
            "{} of {} traces would regress: {}",
            regressions,
            traces_checked,
            affected_flows.join(", ")
        ),
        ValidationOutcome::InsufficientData => {
            "No successful historical traces available".to_string()
        }
    };

    TraceValidationResult {
        proposal_id: proposal.id.clone(),
        outcome,
        traces_checked,
        regressions,
        affected_flows,
        explanation,
    }
}

/// Check if a proposal would cause a regression in the given trace.
fn would_regress(proposal: &HarnessProposal, events: &[StoredEvent]) -> bool {
    match &proposal.diff {
        ProposalDiff::BackEdgeLimit { from, old_limit, new_limit, .. } => {
            for event in events {
                if let FlowEvent::BackEdgeActivated {
                    from: edge_from,
                    iteration,
                    ..
                } = &event.event
                    && edge_from == from && *iteration > *new_limit && *iteration <= *old_limit {
                        return true;
                    }
            }
            false
        }
        ProposalDiff::RemoveNode { task_id, .. } => {
            events.iter().any(|e| matches!(&e.event,
                FlowEvent::NodeCompleted { task_id: tid, .. } if tid == task_id
            ))
        }
        ProposalDiff::AddTimeout { .. }
        | ProposalDiff::AddFallback { .. }
        | ProposalDiff::ToolConfigChange { .. } => false,
    }
}

/// Full self-harness pipeline: mine → propose → validate.
pub fn run_self_harness(
    log: &EventLog,
    flow_ids: &[&str],
    config: &MiningConfig,
) -> SelfHarnessReport {
    let findings = mine_from_event_log(log, flow_ids, config);
    let proposals = propose_harnesses(&findings);

    let validations: Vec<TraceValidationResult> = proposals
        .iter()
        .map(|p| validate_proposal(p, log, flow_ids))
        .collect();

    let safe_proposals: Vec<&HarnessProposal> = proposals
        .iter()
        .zip(validations.iter())
        .filter(|(_, v)| v.outcome == ValidationOutcome::Safe)
        .map(|(p, _)| p)
        .collect();

    SelfHarnessReport {
        flows_analyzed: flow_ids.len(),
        weaknesses_found: findings.len(),
        proposals_generated: proposals.len(),
        proposals_safe: safe_proposals.len(),
        findings,
        proposals,
        validations,
    }
}

/// Full report from a self-harness run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfHarnessReport {
    pub flows_analyzed: usize,
    pub weaknesses_found: usize,
    pub proposals_generated: usize,
    pub proposals_safe: usize,
    pub findings: Vec<WeaknessFinding>,
    pub proposals: Vec<HarnessProposal>,
    pub validations: Vec<TraceValidationResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_events(flow_id: &str) -> Vec<StoredEvent> {
        let mut events = Vec::new();
        let mut seq = 1;

        let event = |s: &mut i64, evt: FlowEvent| -> StoredEvent {
            let e = StoredEvent {
                seq: *s,
                flow_id: flow_id.to_string(),
                event: evt,
                timestamp_ms: *s * 100,
                model_version: None,
                prompt_hash: None,
            };
            *s += 1;
            e
        };

        events.push(event(&mut seq, FlowEvent::NodeStarted {
            task_id: "analyze".into(),
            specialist: "reviewer".into(),
        }));
        events.push(event(&mut seq, FlowEvent::ToolCalled {
            task_id: "analyze".into(),
            tool_name: "file_read".into(),
            args_hash: "abc".into(),
        }));
        events.push(event(&mut seq, FlowEvent::ToolResult {
            task_id: "analyze".into(),
            tool_name: "file_read".into(),
            is_error: true,
            duration_ms: 50,
        }));
        events.push(event(&mut seq, FlowEvent::ToolResult {
            task_id: "analyze".into(),
            tool_name: "file_read".into(),
            is_error: true,
            duration_ms: 50,
        }));
        events.push(event(&mut seq, FlowEvent::NodeCompleted {
            task_id: "analyze".into(),
            output_preview: "done".into(),
            prompt_tokens: 1000,
            completion_tokens: 20,
        }));
        events.push(event(&mut seq, FlowEvent::BackEdgeActivated {
            from: "review".into(),
            to: "fix".into(),
            iteration: 5,
        }));
        events.push(event(&mut seq, FlowEvent::ToolResult {
            task_id: "fix".into(),
            tool_name: "slow_tool".into(),
            is_error: false,
            duration_ms: 15_000,
        }));
        events.push(event(&mut seq, FlowEvent::NodeFailed {
            task_id: "deploy".into(),
            error: "timeout".into(),
        }));
        events.push(event(&mut seq, FlowEvent::NodeFailed {
            task_id: "deploy".into(),
            error: "connection refused".into(),
        }));
        events.push(event(&mut seq, FlowEvent::NodeSkipped {
            task_id: "cleanup".into(),
            reason: "dependency failed".into(),
        }));
        events.push(event(&mut seq, FlowEvent::FlowCompleted {
            total_prompt_tokens: 2000,
            total_completion_tokens: 200,
        }));

        events
    }

    #[test]
    fn mine_detects_tool_errors() {
        let events = make_events("f1");
        let config = MiningConfig::default();
        let findings = mine_weaknesses(&events, &config);

        let tool_errors: Vec<_> = findings
            .iter()
            .filter(|f| f.weakness_type == WeaknessType::ToolError)
            .collect();
        assert_eq!(tool_errors.len(), 1);
        assert_eq!(tool_errors[0].occurrences, 2);
        assert!(tool_errors[0].tool_name.as_deref() == Some("file_read"));
    }

    #[test]
    fn mine_detects_node_failures() {
        let events = make_events("f1");
        let config = MiningConfig::default();
        let findings = mine_weaknesses(&events, &config);

        let failures: Vec<_> = findings
            .iter()
            .filter(|f| f.weakness_type == WeaknessType::NodeFailure)
            .collect();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].task_id.as_deref(), Some("deploy"));
        assert_eq!(failures[0].occurrences, 2);
    }

    #[test]
    fn mine_detects_retry_loops() {
        let events = make_events("f1");
        let config = MiningConfig::default();
        let findings = mine_weaknesses(&events, &config);

        let retries: Vec<_> = findings
            .iter()
            .filter(|f| f.weakness_type == WeaknessType::RetryLoop)
            .collect();
        assert_eq!(retries.len(), 1);
        assert!(retries[0].description.contains("review"));
    }

    #[test]
    fn mine_detects_slow_tools() {
        let events = make_events("f1");
        let config = MiningConfig::default();
        let findings = mine_weaknesses(&events, &config);

        let slow: Vec<_> = findings
            .iter()
            .filter(|f| f.weakness_type == WeaknessType::SlowToolCall)
            .collect();
        assert_eq!(slow.len(), 1);
        assert_eq!(slow[0].tool_name.as_deref(), Some("slow_tool"));
    }

    #[test]
    fn mine_detects_token_inefficiency() {
        let events = make_events("f1");
        let config = MiningConfig::default();
        let findings = mine_weaknesses(&events, &config);

        let inefficient: Vec<_> = findings
            .iter()
            .filter(|f| f.weakness_type == WeaknessType::TokenInefficiency)
            .collect();
        assert_eq!(inefficient.len(), 1);
        assert_eq!(inefficient[0].task_id.as_deref(), Some("analyze"));
    }

    #[test]
    fn mine_respects_min_occurrences() {
        let events = make_events("f1");
        let config = MiningConfig {
            min_occurrences: 5,
            ..Default::default()
        };
        let findings = mine_weaknesses(&events, &config);

        let tool_errors: Vec<_> = findings
            .iter()
            .filter(|f| f.weakness_type == WeaknessType::ToolError)
            .collect();
        assert!(tool_errors.is_empty());
    }

    #[test]
    fn mine_empty_events() {
        let findings = mine_weaknesses(&[], &MiningConfig::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn mine_sorted_by_severity() {
        let events = make_events("f1");
        let findings = mine_weaknesses(&events, &MiningConfig::default());

        for pair in findings.windows(2) {
            assert!(pair[0].severity >= pair[1].severity);
        }
    }

    #[test]
    fn propose_generates_from_findings() {
        let events = make_events("f1");
        let findings = mine_weaknesses(&events, &MiningConfig::default());
        let proposals = propose_harnesses(&findings);

        assert!(!proposals.is_empty());

        let kinds: Vec<_> = proposals.iter().map(|p| p.kind.clone()).collect();
        assert!(kinds.contains(&ProposalKind::BackEdgeAdjust));
        assert!(kinds.contains(&ProposalKind::ToolConfig));
        assert!(kinds.contains(&ProposalKind::FlowDagEdit));
    }

    #[test]
    fn propose_empty_findings() {
        let proposals = propose_harnesses(&[]);
        assert!(proposals.is_empty());
    }

    #[test]
    fn validate_safe_proposal() {
        let log = EventLog::open_memory().unwrap();
        log.append("f1", &FlowEvent::NodeStarted {
            task_id: "a".into(),
            specialist: "dev".into(),
        }, None, None).unwrap();
        log.append("f1", &FlowEvent::FlowCompleted {
            total_prompt_tokens: 100,
            total_completion_tokens: 50,
        }, None, None).unwrap();

        let proposal = HarnessProposal {
            id: "SH-0001".into(),
            kind: ProposalKind::ToolConfig,
            description: "Add timeout".into(),
            addresses: vec![WeaknessType::SlowToolCall],
            expected_improvement: 0.3,
            regression_risk: 0.1,
            diff: ProposalDiff::AddTimeout {
                target: "slow_tool".into(),
                timeout_ms: 30_000,
            },
        };

        let result = validate_proposal(&proposal, &log, &["f1"]);
        assert_eq!(result.outcome, ValidationOutcome::Safe);
        assert_eq!(result.traces_checked, 1);
        assert_eq!(result.regressions, 0);
    }

    #[test]
    fn validate_regression_detected() {
        let log = EventLog::open_memory().unwrap();
        log.append("f1", &FlowEvent::BackEdgeActivated {
            from: "review".into(),
            to: "fix".into(),
            iteration: 3,
        }, None, None).unwrap();
        log.append("f1", &FlowEvent::FlowCompleted {
            total_prompt_tokens: 100,
            total_completion_tokens: 50,
        }, None, None).unwrap();

        let proposal = HarnessProposal {
            id: "SH-0002".into(),
            kind: ProposalKind::BackEdgeAdjust,
            description: "Reduce iterations".into(),
            addresses: vec![WeaknessType::RetryLoop],
            expected_improvement: 0.3,
            regression_risk: 0.2,
            diff: ProposalDiff::BackEdgeLimit {
                from: "review".into(),
                to: "fix".into(),
                old_limit: 5,
                new_limit: 2,
            },
        };

        let result = validate_proposal(&proposal, &log, &["f1"]);
        assert_eq!(result.outcome, ValidationOutcome::Regression);
        assert_eq!(result.regressions, 1);
    }

    #[test]
    fn validate_insufficient_data() {
        let log = EventLog::open_memory().unwrap();
        let proposal = HarnessProposal {
            id: "SH-0003".into(),
            kind: ProposalKind::ToolConfig,
            description: "test".into(),
            addresses: vec![],
            expected_improvement: 0.1,
            regression_risk: 0.0,
            diff: ProposalDiff::AddTimeout {
                target: "t".into(),
                timeout_ms: 1000,
            },
        };

        let result = validate_proposal(&proposal, &log, &[]);
        assert_eq!(result.outcome, ValidationOutcome::InsufficientData);
    }

    #[test]
    fn validate_remove_node_regression() {
        let log = EventLog::open_memory().unwrap();
        log.append("f1", &FlowEvent::NodeCompleted {
            task_id: "cleanup".into(),
            output_preview: "cleaned".into(),
            prompt_tokens: 50,
            completion_tokens: 10,
        }, None, None).unwrap();
        log.append("f1", &FlowEvent::FlowCompleted {
            total_prompt_tokens: 100,
            total_completion_tokens: 50,
        }, None, None).unwrap();

        let proposal = HarnessProposal {
            id: "SH-0004".into(),
            kind: ProposalKind::FlowDagEdit,
            description: "Remove cleanup".into(),
            addresses: vec![WeaknessType::SkippedNode],
            expected_improvement: 0.1,
            regression_risk: 0.4,
            diff: ProposalDiff::RemoveNode {
                task_id: "cleanup".into(),
                reason: "Often skipped".into(),
            },
        };

        let result = validate_proposal(&proposal, &log, &["f1"]);
        assert_eq!(result.outcome, ValidationOutcome::Regression);
    }

    #[test]
    fn full_pipeline_runs() {
        let log = EventLog::open_memory().unwrap();
        for event in make_events("f1") {
            log.append("f1", &event.event, None, None).unwrap();
        }

        let report = run_self_harness(&log, &["f1"], &MiningConfig::default());

        assert!(report.weaknesses_found > 0);
        assert!(report.proposals_generated > 0);
        assert_eq!(report.validations.len(), report.proposals_generated);
        assert_eq!(report.flows_analyzed, 1);
    }

    #[test]
    fn report_serializable() {
        let log = EventLog::open_memory().unwrap();
        for event in make_events("f1") {
            log.append("f1", &event.event, None, None).unwrap();
        }

        let report = run_self_harness(&log, &["f1"], &MiningConfig::default());
        let json = serde_json::to_string(&report).unwrap();
        let _: SelfHarnessReport = serde_json::from_str(&json).unwrap();
    }
}
