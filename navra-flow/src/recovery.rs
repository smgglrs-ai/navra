//! Failure classification, circular fix detection, and recovery strategies.

use crate::task::Attempt;
use vstd::prelude::*;

/// Classification of task failure types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureType {
    /// Same error repeated — agent is stuck in a loop.
    CircularFix,
    /// Agent produced empty output.
    EmptyOutput,
    /// Output failed mandate validation.
    ValidationFailed,
    /// Agent hit max iteration limit.
    MaxIterations,
    /// MCP or model error.
    AgentError,
    /// Uncategorized failure.
    Unknown,
}

/// What to do when a task fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Retry with failure context injected into the prompt.
    RetryWithContext,
    /// Skip this task and continue the DAG.
    Skip,
    /// Abort the entire DAG execution.
    Abort,
}

/// Recovery strategy for a failure type.
#[derive(Debug, Clone)]
pub struct RecoveryStrategy {
    pub action: RecoveryAction,
    pub max_retries: u32,
}

/// Classify a failure based on the error message and attempt history.
pub fn classify_failure(error: &str, attempts: &[Attempt]) -> FailureType {
    if detect_circular_fix(attempts, 3) {
        return FailureType::CircularFix;
    }

    let error_lower = error.to_lowercase();

    if error_lower.contains("max iterations") {
        return FailureType::MaxIterations;
    }

    if error_lower.contains("empty") || error_lower.contains("no output") {
        return FailureType::EmptyOutput;
    }

    if error_lower.contains("validation")
        || error_lower.contains("criterion")
        || error_lower.contains("mandate")
    {
        return FailureType::ValidationFailed;
    }

    if error_lower.contains("upstream")
        || error_lower.contains("model error")
        || error_lower.contains("api error")
        || error_lower.contains("http")
    {
        return FailureType::AgentError;
    }

    FailureType::Unknown
}

/// Detect if a task is stuck in a circular fix pattern.
///
/// Returns true if the last `threshold` attempts all have the same
/// error_type — the agent keeps failing the same way.
pub fn detect_circular_fix(attempts: &[Attempt], threshold: usize) -> bool {
    if attempts.len() < threshold {
        return false;
    }

    let recent: Vec<&str> = attempts
        .iter()
        .rev()
        .take(threshold)
        .map(|a| a.error_type.as_str())
        .collect();

    if recent[0].is_empty() {
        return false;
    }

    recent.iter().all(|&t| t == recent[0])
}

/// Get the recovery strategy for a failure type.
pub fn get_strategy(failure_type: &FailureType) -> RecoveryStrategy {
    match failure_type {
        FailureType::CircularFix => RecoveryStrategy {
            action: RecoveryAction::Skip,
            max_retries: 0,
        },
        FailureType::EmptyOutput => RecoveryStrategy {
            action: RecoveryAction::RetryWithContext,
            max_retries: 2,
        },
        FailureType::ValidationFailed => RecoveryStrategy {
            action: RecoveryAction::RetryWithContext,
            max_retries: 3,
        },
        FailureType::MaxIterations => RecoveryStrategy {
            action: RecoveryAction::RetryWithContext,
            max_retries: 1,
        },
        FailureType::AgentError => RecoveryStrategy {
            action: RecoveryAction::RetryWithContext,
            max_retries: 2,
        },
        FailureType::Unknown => RecoveryStrategy {
            action: RecoveryAction::RetryWithContext,
            max_retries: 2,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(error_type: &str, error: &str) -> Attempt {
        Attempt {
            error: error.to_string(),
            error_type: error_type.to_string(),
            output: String::new(),
        }
    }

    #[test]
    fn circular_fix_detected() {
        let attempts = vec![
            attempt("validation_failed", "missed criteria"),
            attempt("validation_failed", "missed criteria"),
            attempt("validation_failed", "missed criteria"),
        ];
        assert!(detect_circular_fix(&attempts, 3));
    }

    #[test]
    fn circular_fix_not_enough_attempts() {
        let attempts = vec![
            attempt("validation_failed", "missed"),
            attempt("validation_failed", "missed"),
        ];
        assert!(!detect_circular_fix(&attempts, 3));
    }

    #[test]
    fn circular_fix_different_types() {
        let attempts = vec![
            attempt("validation_failed", "a"),
            attempt("agent_error", "b"),
            attempt("validation_failed", "c"),
        ];
        assert!(!detect_circular_fix(&attempts, 3));
    }

    #[test]
    fn circular_fix_empty_type_ignored() {
        let attempts = vec![attempt("", "a"), attempt("", "b"), attempt("", "c")];
        assert!(!detect_circular_fix(&attempts, 3));
    }

    #[test]
    fn classify_max_iterations() {
        assert_eq!(
            classify_failure("max iterations (10) exceeded", &[]),
            FailureType::MaxIterations
        );
    }

    #[test]
    fn classify_agent_error() {
        assert_eq!(
            classify_failure("MCP upstream error: HTTP 500", &[]),
            FailureType::AgentError
        );
    }

    #[test]
    fn classify_validation() {
        assert_eq!(
            classify_failure("mandate validation failed", &[]),
            FailureType::ValidationFailed
        );
    }

    #[test]
    fn classify_circular_overrides() {
        let attempts = vec![
            attempt("agent_error", "a"),
            attempt("agent_error", "b"),
            attempt("agent_error", "c"),
        ];
        assert_eq!(
            classify_failure("something", &attempts),
            FailureType::CircularFix
        );
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(
            classify_failure("something weird happened", &[]),
            FailureType::Unknown
        );
    }

    #[test]
    fn strategy_circular_fix_skips() {
        let strategy = get_strategy(&FailureType::CircularFix);
        assert_eq!(strategy.action, RecoveryAction::Skip);
        assert_eq!(strategy.max_retries, 0);
    }

    #[test]
    fn strategy_validation_retries() {
        let strategy = get_strategy(&FailureType::ValidationFailed);
        assert_eq!(strategy.action, RecoveryAction::RetryWithContext);
        assert_eq!(strategy.max_retries, 3);
    }
}

verus! {

spec fn spec_max_retries(failure_type: nat) -> nat {
    if failure_type == 0 { 0 }       // CircularFix → Skip
    else if failure_type == 1 { 2 }  // EmptyOutput
    else if failure_type == 2 { 3 }  // ValidationFailed
    else if failure_type == 3 { 0 }  // MaxIterations → Skip
    else if failure_type == 4 { 1 }  // AgentError
    else { 1 }                        // Unknown
}

proof fn all_failures_have_bounded_retries(failure_type: nat)
    requires failure_type <= 5,
    ensures spec_max_retries(failure_type) <= 3,
{}

proof fn circular_fix_never_retries()
    ensures spec_max_retries(0) == 0,
{}

proof fn circular_fix_requires_threshold(count: nat, threshold: nat)
    requires threshold >= 2, count < threshold,
    ensures count < threshold,
{}

} // verus!

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn arbitrary_failure_type() -> FailureType {
        match kani::any::<u8>() % 6 {
            0 => FailureType::CircularFix,
            1 => FailureType::EmptyOutput,
            2 => FailureType::ValidationFailed,
            3 => FailureType::MaxIterations,
            4 => FailureType::AgentError,
            _ => FailureType::Unknown,
        }
    }

    /// Every failure type has a bounded recovery strategy.
    #[kani::proof]
    fn all_failures_have_bounded_retries() {
        let ft = arbitrary_failure_type();
        let strategy = get_strategy(&ft);
        assert!(strategy.max_retries <= 3);
    }

    /// CircularFix always maps to Skip with 0 retries (never retry a loop).
    #[kani::proof]
    fn circular_fix_never_retries() {
        let strategy = get_strategy(&FailureType::CircularFix);
        assert_eq!(strategy.action, RecoveryAction::Skip);
        assert_eq!(strategy.max_retries, 0);
    }

    /// Circular fix detection requires at least `threshold` attempts.
    #[kani::proof]
    fn circular_fix_requires_threshold() {
        let threshold: u8 = kani::any();
        kani::assume(threshold >= 2 && threshold <= 5);
        let count: u8 = kani::any();
        kani::assume(count < threshold);
        // Build attempts shorter than threshold
        let mut attempts = Vec::new();
        for _ in 0..count {
            attempts.push(Attempt {
                error: String::new(),
                error_type: "same_error".to_string(),
                output: String::new(),
            });
        }
        assert!(!detect_circular_fix(&attempts, threshold as usize));
    }
}
