//! Multi-agent cross-validation for high-stakes task outputs.
//!
//! After a task completes, spawn N verifier agents in parallel to
//! independently assess the output. Verdicts are aggregated using
//! a configurable threshold (majority, unanimous, any).

use crate::error::FlowError;
use crate::task::Task;
use navra_agent::Agent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// How many verifier agents must approve for the result to pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum VerificationThreshold {
    /// At least one verifier must approve.
    Any,
    /// More than half of verifiers must approve.
    #[default]
    Majority,
    /// All verifiers must approve.
    Unanimous,
}


/// Configuration for cross-validation of a task's output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Number of verifier agents to spawn (default: 2).
    #[serde(default = "default_verifier_count")]
    pub agents: usize,
    /// Threshold for passing verification (default: Majority).
    #[serde(default)]
    pub threshold: VerificationThreshold,
    /// Persona name for verifier agents (uses task specialist if absent).
    #[serde(default)]
    pub verifier_persona: Option<String>,
    /// Model hint for verifier agents (uses task model if absent).
    #[serde(default)]
    pub verifier_model: Option<String>,
}

fn default_verifier_count() -> usize {
    2
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            agents: default_verifier_count(),
            threshold: VerificationThreshold::default(),
            verifier_persona: None,
            verifier_model: None,
        }
    }
}

/// A single verifier's verdict on a task output.
#[derive(Debug, Clone)]
pub struct VerificationVerdict {
    /// Which verifier produced this (0-indexed).
    pub verifier_index: usize,
    /// Whether the verifier approved the output.
    pub passed: bool,
    /// Findings or issues identified by the verifier.
    pub findings: Vec<String>,
}

/// Aggregated result of cross-validation across all verifiers.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the output passed the configured threshold.
    pub passed: bool,
    /// Individual verdicts from each verifier.
    pub verdicts: Vec<VerificationVerdict>,
    /// Aggregated findings across all verifiers (deduplicated).
    pub findings: Vec<String>,
    /// Total prompt tokens consumed by verification.
    pub prompt_tokens: u32,
    /// Total completion tokens consumed by verification.
    pub completion_tokens: u32,
}

/// Build the verification prompt for a verifier agent.
fn build_verification_prompt(task: &Task, output: &str) -> String {
    let mut parts = Vec::new();

    parts.push("## Verification task\n\n".to_string());
    parts.push(
        "Review the following output for correctness, completeness, \
         and potential issues. You are an independent verifier.\n\n"
            .to_string(),
    );

    parts.push(format!("### Original mandate:\n{}\n\n", task.mandate));

    if !task.success_criteria.is_empty() {
        parts.push("### Success criteria:\n".to_string());
        for criterion in &task.success_criteria {
            parts.push(format!("- {criterion}\n"));
        }
        parts.push("\n".to_string());
    }

    if let Some(ref expected) = task.expected_output {
        parts.push(format!("### Expected output:\n{expected}\n\n"));
    }

    parts.push(format!("### Output to verify:\n{output}\n\n"));

    parts.push(
        "### Instructions:\n\
         Respond with a JSON object:\n\
         ```json\n\
         {\n  \"passed\": true/false,\n  \"findings\": [\"issue 1\", \"issue 2\"]\n}\n\
         ```\n\
         - Set `passed` to true if the output is correct, complete, and addresses the mandate.\n\
         - Set `passed` to false if there are significant issues.\n\
         - List specific findings (errors, omissions, concerns) in the `findings` array.\n\
         - If the output is acceptable, use an empty findings array."
            .to_string(),
    );

    parts.join("")
}

/// Parse a verifier's response into a verdict.
fn parse_verdict(response: &str, verifier_index: usize) -> VerificationVerdict {
    // Try to parse JSON from the response
    let json_str = extract_json_object(response);

    if let Some(json) = json_str {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json) {
            let passed = parsed
                .get("passed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let findings = parsed
                .get("findings")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            return VerificationVerdict {
                verifier_index,
                passed,
                findings,
            };
        }
    }

    // Fallback: heuristic parsing
    let lower = response.to_lowercase();
    let passed = lower.contains("pass")
        || lower.contains("approved")
        || lower.contains("correct")
            && !lower.contains("incorrect")
            && !lower.contains("not correct");

    VerificationVerdict {
        verifier_index,
        passed,
        findings: vec![format!("Verifier {verifier_index}: unparseable response")],
    }
}

/// Extract the first JSON object from text.
fn extract_json_object(text: &str) -> Option<String> {
    let mut depth = 0i32;
    let mut start = None;

    for (i, ch) in text.char_indices() {
        match ch {
            '{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start {
                        return Some(text[s..=i].to_string());
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Apply threshold logic to a set of verdicts.
fn apply_threshold(threshold: &VerificationThreshold, verdicts: &[VerificationVerdict]) -> bool {
    if verdicts.is_empty() {
        return false;
    }

    let pass_count = verdicts.iter().filter(|v| v.passed).count();

    match threshold {
        VerificationThreshold::Any => pass_count > 0,
        VerificationThreshold::Majority => pass_count > verdicts.len() / 2,
        VerificationThreshold::Unanimous => pass_count == verdicts.len(),
    }
}

/// Run cross-validation on a task result.
///
/// Spawns N verifier agents sequentially (agents require `&mut self`),
/// collects verdicts, and applies threshold logic.
pub async fn verify_result(
    task: &Task,
    output: &str,
    config: &VerificationConfig,
    agents: &mut HashMap<String, Agent>,
) -> Result<VerificationResult, FlowError> {
    let prompt = build_verification_prompt(task, output);
    let specialist = config
        .verifier_persona
        .as_deref()
        .unwrap_or(&task.specialist);

    let agent = agents
        .get_mut(specialist)
        .ok_or_else(|| FlowError::UnknownSpecialist(specialist.to_string()))?;

    let mut verdicts = Vec::with_capacity(config.agents);
    let mut total_prompt = 0u32;
    let mut total_completion = 0u32;

    for i in 0..config.agents {
        tracing::info!(
            task = %task.id,
            verifier = i,
            total = config.agents,
            "Running verifier"
        );

        match agent.run(&prompt).await {
            Ok(result) => {
                total_prompt += result.input_tokens;
                total_completion += result.output_tokens;
                let verdict = parse_verdict(&result.response, i);
                tracing::info!(
                    task = %task.id,
                    verifier = i,
                    passed = verdict.passed,
                    findings = verdict.findings.len(),
                    "Verifier complete"
                );
                verdicts.push(verdict);
            }
            Err(e) => {
                tracing::warn!(
                    task = %task.id,
                    verifier = i,
                    error = %e,
                    "Verifier failed, counting as rejection"
                );
                verdicts.push(VerificationVerdict {
                    verifier_index: i,
                    passed: false,
                    findings: vec![format!("Verifier {i} failed: {e}")],
                });
            }
        }
    }

    let passed = apply_threshold(&config.threshold, &verdicts);

    // Aggregate findings (deduplicated)
    let mut all_findings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for verdict in &verdicts {
        for finding in &verdict.findings {
            if seen.insert(finding.clone()) {
                all_findings.push(finding.clone());
            }
        }
    }

    Ok(VerificationResult {
        passed,
        verdicts,
        findings: all_findings,
        prompt_tokens: total_prompt,
        completion_tokens: total_completion,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_task() -> Task {
        Task {
            id: "test".to_string(),
            specialist: "dev".to_string(),
            model: None,
            mandate: "Analyze the module for bugs".to_string(),
            depends_on: Vec::new(),
            inputs: HashMap::new(),
            expected_output: Some("Detailed analysis report".to_string()),
            success_criteria: vec!["Tests pass".to_string()],
            max_retries: 2,
            back_edges: Vec::new(),
            verification: None,
            temperature: None,
        }
    }

    #[test]
    fn parse_verdict_json_passed() {
        let response = r#"{"passed": true, "findings": []}"#;
        let verdict = parse_verdict(response, 0);
        assert!(verdict.passed);
        assert!(verdict.findings.is_empty());
    }

    #[test]
    fn parse_verdict_json_failed() {
        let response =
            r#"{"passed": false, "findings": ["Missing error handling", "No test coverage"]}"#;
        let verdict = parse_verdict(response, 1);
        assert!(!verdict.passed);
        assert_eq!(verdict.findings.len(), 2);
        assert_eq!(verdict.findings[0], "Missing error handling");
    }

    #[test]
    fn parse_verdict_embedded_json() {
        let response = "Here is my review:\n```json\n{\"passed\": true, \"findings\": [\"Minor style issue\"]}\n```";
        let verdict = parse_verdict(response, 0);
        assert!(verdict.passed);
        assert_eq!(verdict.findings.len(), 1);
    }

    #[test]
    fn parse_verdict_fallback_pass() {
        let response = "The output is correct and complete. I approve this result.";
        let verdict = parse_verdict(response, 0);
        assert!(verdict.passed);
    }

    #[test]
    fn parse_verdict_fallback_fail() {
        let response = "This is completely wrong and needs to be redone.";
        let verdict = parse_verdict(response, 0);
        assert!(!verdict.passed);
    }

    #[test]
    fn threshold_any_one_pass() {
        let verdicts = vec![
            VerificationVerdict {
                verifier_index: 0,
                passed: false,
                findings: vec![],
            },
            VerificationVerdict {
                verifier_index: 1,
                passed: true,
                findings: vec![],
            },
        ];
        assert!(apply_threshold(&VerificationThreshold::Any, &verdicts));
    }

    #[test]
    fn threshold_any_none_pass() {
        let verdicts = vec![
            VerificationVerdict {
                verifier_index: 0,
                passed: false,
                findings: vec![],
            },
            VerificationVerdict {
                verifier_index: 1,
                passed: false,
                findings: vec![],
            },
        ];
        assert!(!apply_threshold(&VerificationThreshold::Any, &verdicts));
    }

    #[test]
    fn threshold_majority_pass() {
        let verdicts = vec![
            VerificationVerdict {
                verifier_index: 0,
                passed: true,
                findings: vec![],
            },
            VerificationVerdict {
                verifier_index: 1,
                passed: true,
                findings: vec![],
            },
            VerificationVerdict {
                verifier_index: 2,
                passed: false,
                findings: vec![],
            },
        ];
        assert!(apply_threshold(&VerificationThreshold::Majority, &verdicts));
    }

    #[test]
    fn threshold_majority_fail() {
        let verdicts = vec![
            VerificationVerdict {
                verifier_index: 0,
                passed: true,
                findings: vec![],
            },
            VerificationVerdict {
                verifier_index: 1,
                passed: false,
                findings: vec![],
            },
            VerificationVerdict {
                verifier_index: 2,
                passed: false,
                findings: vec![],
            },
        ];
        assert!(!apply_threshold(
            &VerificationThreshold::Majority,
            &verdicts
        ));
    }

    #[test]
    fn threshold_majority_two_agents_needs_both() {
        // With 2 agents, majority requires > 1, so both must pass
        let verdicts = vec![
            VerificationVerdict {
                verifier_index: 0,
                passed: true,
                findings: vec![],
            },
            VerificationVerdict {
                verifier_index: 1,
                passed: false,
                findings: vec![],
            },
        ];
        assert!(!apply_threshold(
            &VerificationThreshold::Majority,
            &verdicts
        ));
    }

    #[test]
    fn threshold_unanimous_pass() {
        let verdicts = vec![
            VerificationVerdict {
                verifier_index: 0,
                passed: true,
                findings: vec![],
            },
            VerificationVerdict {
                verifier_index: 1,
                passed: true,
                findings: vec![],
            },
        ];
        assert!(apply_threshold(
            &VerificationThreshold::Unanimous,
            &verdicts
        ));
    }

    #[test]
    fn threshold_unanimous_fail() {
        let verdicts = vec![
            VerificationVerdict {
                verifier_index: 0,
                passed: true,
                findings: vec![],
            },
            VerificationVerdict {
                verifier_index: 1,
                passed: false,
                findings: vec![],
            },
        ];
        assert!(!apply_threshold(
            &VerificationThreshold::Unanimous,
            &verdicts
        ));
    }

    #[test]
    fn threshold_empty_verdicts() {
        assert!(!apply_threshold(&VerificationThreshold::Any, &[]));
        assert!(!apply_threshold(&VerificationThreshold::Majority, &[]));
        assert!(!apply_threshold(&VerificationThreshold::Unanimous, &[]));
    }

    #[test]
    fn build_prompt_includes_mandate() {
        let task = make_task();
        let prompt = build_verification_prompt(&task, "Some output");
        assert!(prompt.contains("Analyze the module for bugs"));
        assert!(prompt.contains("Some output"));
        assert!(prompt.contains("Tests pass"));
        assert!(prompt.contains("Detailed analysis report"));
    }

    #[test]
    fn extract_json_from_text() {
        let text = "Here: {\"a\": 1} done";
        assert_eq!(extract_json_object(text), Some("{\"a\": 1}".to_string()));
    }

    #[test]
    fn extract_json_nested() {
        let text = r#"{"a": {"b": 1}, "c": 2}"#;
        assert_eq!(extract_json_object(text), Some(text.to_string()));
    }

    #[test]
    fn extract_json_none() {
        assert_eq!(extract_json_object("no json here"), None);
    }

    #[test]
    fn verification_config_defaults() {
        let config: VerificationConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.agents, 2);
        assert_eq!(config.threshold, VerificationThreshold::Majority);
        assert!(config.verifier_persona.is_none());
        assert!(config.verifier_model.is_none());
    }

    #[test]
    fn verification_config_custom() {
        let config: VerificationConfig = serde_json::from_str(
            r#"{"agents": 3, "threshold": "unanimous", "verifier_persona": "auditor"}"#,
        )
        .unwrap();
        assert_eq!(config.agents, 3);
        assert_eq!(config.threshold, VerificationThreshold::Unanimous);
        assert_eq!(config.verifier_persona.as_deref(), Some("auditor"));
    }

    #[test]
    fn findings_deduplicated() {
        let verdicts = vec![
            VerificationVerdict {
                verifier_index: 0,
                passed: false,
                findings: vec!["issue A".into(), "issue B".into()],
            },
            VerificationVerdict {
                verifier_index: 1,
                passed: false,
                findings: vec!["issue B".into(), "issue C".into()],
            },
        ];

        let mut all = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for v in &verdicts {
            for f in &v.findings {
                if seen.insert(f.clone()) {
                    all.push(f.clone());
                }
            }
        }

        assert_eq!(all.len(), 3);
        assert_eq!(all, vec!["issue A", "issue B", "issue C"]);
    }
}
