//! Conditional back-edges for controlled loops in DAG execution.

use crate::definition::BackEdgeDefinition;
use crate::error::FlowError;
use crate::task::TaskResult;
use std::collections::HashMap;

/// Condition for activating a back-edge.
#[derive(Debug, Clone)]
pub enum EdgeCondition {
    /// Activate if validation score is below threshold.
    ScoreBelow(f32),
    /// Activate if any success criteria are missing (validation_notes is non-empty).
    CriteriaMissing,
    /// Activate if output contains the given substring.
    OutputContains(String),
    /// Always activate (useful for fixed-iteration loops).
    Always,
}

/// A resolved conditional edge (parsed from BackEdgeDefinition).
#[derive(Debug, Clone)]
pub struct ConditionalEdge {
    pub from: String,
    pub to: String,
    pub condition: EdgeCondition,
    pub max_iterations: u32,
}

/// Tracker for back-edge iteration counts.
pub struct BackEdgeTracker {
    counts: HashMap<(String, String), u32>,
}

/// Parse a condition string into an `EdgeCondition`.
pub fn parse_condition(s: &str) -> Result<EdgeCondition, FlowError> {
    if let Some(threshold) = s.strip_prefix("score_below:") {
        let value: f32 = threshold.parse().map_err(|_| {
            FlowError::InvalidFlow(format!("invalid score threshold: {threshold}"))
        })?;
        Ok(EdgeCondition::ScoreBelow(value))
    } else if s == "criteria_missing" {
        Ok(EdgeCondition::CriteriaMissing)
    } else if let Some(pattern) = s.strip_prefix("output_contains:") {
        Ok(EdgeCondition::OutputContains(pattern.to_string()))
    } else if s == "always" {
        Ok(EdgeCondition::Always)
    } else {
        Err(FlowError::InvalidFlow(format!(
            "unknown back-edge condition: {s}"
        )))
    }
}

/// Evaluate whether a condition is met for the given task result.
pub fn evaluate_condition(condition: &EdgeCondition, result: &TaskResult) -> bool {
    match condition {
        EdgeCondition::ScoreBelow(threshold) => match result.validation_score {
            Some(score) => score < *threshold,
            None => true,
        },
        EdgeCondition::CriteriaMissing => !result.validation_notes.is_empty(),
        EdgeCondition::OutputContains(pattern) => result.output.contains(pattern.as_str()),
        EdgeCondition::Always => true,
    }
}

impl ConditionalEdge {
    /// Parse a `BackEdgeDefinition` into a `ConditionalEdge`.
    pub fn from_definition(
        from_task: &str,
        def: &BackEdgeDefinition,
    ) -> Result<Self, FlowError> {
        let condition = parse_condition(&def.condition)?;
        Ok(Self {
            from: from_task.to_string(),
            to: def.target.clone(),
            condition,
            max_iterations: def.max_iterations,
        })
    }
}

impl Default for BackEdgeTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BackEdgeTracker {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    /// Check whether the back-edge should activate: condition is met and
    /// iteration count has not reached the maximum.
    pub fn should_activate(&self, edge: &ConditionalEdge, result: &TaskResult) -> bool {
        evaluate_condition(&edge.condition, result)
            && self.iteration_count(&edge.from, &edge.to) < edge.max_iterations
    }

    /// Record a back-edge activation and return the new count.
    pub fn record_activation(&mut self, from: &str, to: &str) -> u32 {
        let key = (from.to_string(), to.to_string());
        let count = self.counts.entry(key).or_insert(0);
        *count += 1;
        *count
    }

    /// Return the current iteration count for a back-edge (0 if not tracked).
    pub fn iteration_count(&self, from: &str, to: &str) -> u32 {
        let key = (from.to_string(), to.to_string());
        self.counts.get(&key).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{TaskResult, TaskStatus};
    use myelix_protocol::label::DataLabel;

    fn make_result(
        output: &str,
        validation_score: Option<f32>,
        validation_notes: Vec<String>,
    ) -> TaskResult {
        TaskResult {
            task_id: "test".to_string(),
            status: TaskStatus::Complete,
            output: output.to_string(),
            prompt_tokens: 0,
            completion_tokens: 0,
            taint: DataLabel::TRUSTED_PUBLIC,
            validation_score,
            validation_notes,
        }
    }

    #[test]
    fn score_below_activates() {
        let result = make_result("ok", Some(50.0), vec![]);
        assert!(evaluate_condition(&EdgeCondition::ScoreBelow(70.0), &result));
    }

    #[test]
    fn score_below_does_not_activate() {
        let result = make_result("ok", Some(80.0), vec![]);
        assert!(!evaluate_condition(&EdgeCondition::ScoreBelow(70.0), &result));
    }

    #[test]
    fn score_below_none_activates() {
        let result = make_result("ok", None, vec![]);
        assert!(evaluate_condition(&EdgeCondition::ScoreBelow(70.0), &result));
    }

    #[test]
    fn criteria_missing_activates() {
        let result = make_result("ok", Some(90.0), vec!["missing criterion X".to_string()]);
        assert!(evaluate_condition(&EdgeCondition::CriteriaMissing, &result));
    }

    #[test]
    fn criteria_missing_does_not_activate() {
        let result = make_result("ok", Some(90.0), vec![]);
        assert!(!evaluate_condition(&EdgeCondition::CriteriaMissing, &result));
    }

    #[test]
    fn output_contains_activates() {
        let result = make_result("there was an error here", Some(90.0), vec![]);
        assert!(evaluate_condition(
            &EdgeCondition::OutputContains("error".to_string()),
            &result
        ));
    }

    #[test]
    fn output_contains_does_not_activate() {
        let result = make_result("everything is fine", Some(90.0), vec![]);
        assert!(!evaluate_condition(
            &EdgeCondition::OutputContains("error".to_string()),
            &result
        ));
    }

    #[test]
    fn always_activates() {
        let result = make_result("ok", Some(100.0), vec![]);
        assert!(evaluate_condition(&EdgeCondition::Always, &result));
    }

    #[test]
    fn tracker_counts_correctly() {
        let mut tracker = BackEdgeTracker::new();
        tracker.record_activation("a", "b");
        tracker.record_activation("a", "b");
        tracker.record_activation("a", "b");
        assert_eq!(tracker.iteration_count("a", "b"), 3);
    }

    #[test]
    fn should_activate_respects_max_iterations() {
        let mut tracker = BackEdgeTracker::new();
        let edge = ConditionalEdge {
            from: "a".to_string(),
            to: "b".to_string(),
            condition: EdgeCondition::Always,
            max_iterations: 2,
        };
        let result = make_result("ok", Some(50.0), vec![]);

        assert!(tracker.should_activate(&edge, &result));
        tracker.record_activation("a", "b");

        assert!(tracker.should_activate(&edge, &result));
        tracker.record_activation("a", "b");

        assert!(!tracker.should_activate(&edge, &result));
    }

    #[test]
    fn parse_condition_variants() {
        assert!(matches!(
            parse_condition("score_below:70").unwrap(),
            EdgeCondition::ScoreBelow(v) if (v - 70.0).abs() < f32::EPSILON
        ));
        assert!(matches!(
            parse_condition("score_below:85.5").unwrap(),
            EdgeCondition::ScoreBelow(v) if (v - 85.5).abs() < f32::EPSILON
        ));
        assert!(matches!(
            parse_condition("criteria_missing").unwrap(),
            EdgeCondition::CriteriaMissing
        ));
        assert!(matches!(
            parse_condition("output_contains:FAILED").unwrap(),
            EdgeCondition::OutputContains(ref s) if s == "FAILED"
        ));
        assert!(matches!(
            parse_condition("always").unwrap(),
            EdgeCondition::Always
        ));
    }

    #[test]
    fn parse_condition_unknown_errors() {
        let err = parse_condition("bogus").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown back-edge condition"));
    }

    #[test]
    fn from_definition_works() {
        let def = BackEdgeDefinition {
            target: "task_a".to_string(),
            condition: "score_below:75".to_string(),
            max_iterations: 5,
        };
        let edge = ConditionalEdge::from_definition("task_b", &def).unwrap();
        assert_eq!(edge.from, "task_b");
        assert_eq!(edge.to, "task_a");
        assert_eq!(edge.max_iterations, 5);
        assert!(matches!(
            edge.condition,
            EdgeCondition::ScoreBelow(v) if (v - 75.0).abs() < f32::EPSILON
        ));
    }
}
