//! Mandate validation: check task output against success criteria.

use crate::task::Task;

/// Passing threshold for mandate validation.
const PASS_THRESHOLD: f32 = 70.0;

/// Result of validating a task output against its mandate.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Compliance score (0.0-100.0).
    pub score: f32,
    /// Whether the output passes validation (score >= threshold).
    pub passed: bool,
    /// Notes on what criteria were missed.
    pub notes: Vec<String>,
}

/// Validate that a task's output fulfills its mandate.
///
/// Checks:
/// 1. Non-empty output (30-point penalty if empty)
/// 2. Minimum length when `expected_output` is set (20-point penalty if < 100 chars)
/// 3. Success criteria via keyword matching (15-point penalty per missed criterion)
pub fn validate_mandate(task: &Task, output: &str) -> ValidationResult {
    let mut score = 100.0_f32;
    let mut notes = Vec::new();

    // 1. Empty output check
    if output.trim().is_empty() {
        score -= 30.0;
        notes.push("Output is empty".to_string());
    }

    // 2. Minimum length when expected_output is described
    if task.expected_output.is_some() && output.len() < 100 {
        score -= 20.0;
        notes.push(format!(
            "Output too short: {} chars (expected substantial output)",
            output.len()
        ));
    }

    // 3. Success criteria keyword matching
    for criterion in &task.success_criteria {
        if !check_criterion(criterion, output) {
            score -= 15.0;
            notes.push(format!("Missing criterion: '{criterion}'"));
        }
    }

    score = score.max(0.0);

    ValidationResult {
        score,
        passed: score >= PASS_THRESHOLD,
        notes,
    }
}

/// Check if a criterion is met via keyword matching.
///
/// Extracts significant words (>3 chars) from the criterion and checks
/// if any appear in the output. This is a heuristic — future versions
/// could use LLM-as-judge for semantic matching.
fn check_criterion(criterion: &str, output: &str) -> bool {
    let keywords: Vec<&str> = criterion
        .split_whitespace()
        .filter(|w| w.len() > 3)
        .collect();
    if keywords.is_empty() {
        return true;
    }
    let output_lower = output.to_lowercase();
    keywords
        .iter()
        .any(|kw| output_lower.contains(&kw.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn task_with_criteria(criteria: Vec<&str>, expected: bool) -> Task {
        Task {
            id: "t".to_string(),
            specialist: "dev".to_string(),
            mandate: "Do work".to_string(),
            depends_on: Vec::new(),
            inputs: HashMap::new(),
            expected_output: if expected {
                Some("Detailed analysis".to_string())
            } else {
                None
            },
            success_criteria: criteria.into_iter().map(String::from).collect(),
            max_retries: 2,
        }
    }

    #[test]
    fn valid_output_scores_100() {
        let task = task_with_criteria(vec![], false);
        let result = validate_mandate(&task, "This is a valid output with enough content.");
        assert_eq!(result.score, 100.0);
        assert!(result.passed);
        assert!(result.notes.is_empty());
    }

    #[test]
    fn empty_output_penalized() {
        let task = task_with_criteria(vec![], false);
        let result = validate_mandate(&task, "");
        assert_eq!(result.score, 70.0);
        assert!(result.passed); // Barely passes at threshold
        assert!(result.notes[0].contains("empty"));
    }

    #[test]
    fn short_output_with_expected() {
        let task = task_with_criteria(vec![], true);
        let result = validate_mandate(&task, "Too short");
        assert_eq!(result.score, 80.0);
        assert!(result.passed);
        assert!(result.notes[0].contains("too short"));
    }

    #[test]
    fn empty_output_with_expected_fails() {
        let task = task_with_criteria(vec![], true);
        let result = validate_mandate(&task, "");
        assert_eq!(result.score, 50.0); // -30 (empty) -20 (short)
        assert!(!result.passed);
    }

    #[test]
    fn criteria_matched() {
        let task = task_with_criteria(vec!["tests should pass", "includes documentation"], false);
        let output = "All tests pass. The documentation has been updated.";
        let result = validate_mandate(&task, output);
        assert_eq!(result.score, 100.0);
        assert!(result.passed);
    }

    #[test]
    fn criteria_partially_missed() {
        let task = task_with_criteria(vec!["tests should pass", "security review"], false);
        let output = "All tests pass successfully.";
        let result = validate_mandate(&task, output);
        assert_eq!(result.score, 85.0); // -15 for missing security
        assert!(result.passed);
        assert_eq!(result.notes.len(), 1);
        assert!(result.notes[0].contains("security"));
    }

    #[test]
    fn all_criteria_missed() {
        let task = task_with_criteria(
            vec!["performance benchmarks", "security audit", "documentation"],
            false,
        );
        let output = "Done.";
        let result = validate_mandate(&task, output);
        assert_eq!(result.score, 55.0); // -15 * 3
        assert!(!result.passed);
    }

    #[test]
    fn score_floors_at_zero() {
        let task = task_with_criteria(
            vec![
                "performance benchmarks",
                "security audit",
                "documentation updated",
                "integration tests",
                "deployment guide",
                "rollback plan",
                "monitoring alerts",
            ],
            true,
        );
        let result = validate_mandate(&task, "");
        // -30 (empty) -20 (short with expected) -15*7 (criteria) = -155, floored to 0
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn criterion_with_short_words_ignored() {
        // Criterion "it is ok" has only short words (<= 3 chars)
        let task = task_with_criteria(vec!["it is ok"], false);
        let result = validate_mandate(&task, "Anything goes.");
        assert!(result.passed); // Short words skipped, criterion passes by default
    }
}
