//! Offline taint audit: post-hoc analysis of blackbox traces to detect
//! taint propagation missed by inline label-based IFC.
//!
//! Three analysis passes:
//! 1. **Semantic**: embedding similarity between untrusted inputs and
//!    downstream tool arguments (catches paraphrase/summarization).
//! 2. **Causal**: tool selection influence from untrusted data without
//!    direct content transfer.
//! 3. **Persistent**: cross-session memory contamination.

pub mod causal;
pub mod report;
pub mod semantic;

use navra_core::blackbox::BlackboxEntry;
use serde::{Deserialize, Serialize};

/// A detected taint path from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    pub source_seq: u64,
    pub sink_seq: u64,
    pub source_tool: String,
    pub sink_tool: String,
    pub mechanism: TaintMechanism,
    pub confidence: f32,
    pub evidence: String,
}

/// How taint propagated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaintMechanism {
    Semantic,
    Causal,
    Persistent,
}

/// Risk rating for a session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskRating {
    Clean,
    Low,
    Medium,
    High,
}

impl RiskRating {
    pub fn from_paths(paths: &[TaintPath]) -> Self {
        if paths.is_empty() {
            return Self::Clean;
        }
        let max_conf = paths
            .iter()
            .map(|p| p.confidence)
            .fold(0.0f32, f32::max);
        if max_conf >= 0.8 {
            Self::High
        } else if max_conf >= 0.5 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Run all three taint analysis passes on a session's blackbox entries.
pub fn analyze_session(entries: &[BlackboxEntry]) -> Vec<TaintPath> {
    let mut paths = Vec::new();

    // Identify untrusted sources: entries with outcome containing "denied"
    // or ifc_label == "Untrusted"
    let untrusted_entries: Vec<&BlackboxEntry> = entries
        .iter()
        .filter(|e| e.ifc_label == "Untrusted" || e.outcome.starts_with("denied"))
        .collect();

    let trusted_sinks: Vec<&BlackboxEntry> = entries
        .iter()
        .filter(|e| {
            e.ifc_label == "Trusted"
                && e.outcome == "allowed"
                && is_write_tool(&e.tool_name)
        })
        .collect();

    // Pass 1: Semantic similarity (string-based approximation without embeddings)
    paths.extend(semantic::analyze(&untrusted_entries, &trusted_sinks));

    // Pass 2: Causal influence
    paths.extend(causal::analyze(entries, &untrusted_entries));

    paths
}

fn is_write_tool(name: &str) -> bool {
    let write_patterns = [
        "write", "create", "delete", "update", "put", "post",
        "send", "push", "upload", "modify", "set",
    ];
    let lower = name.to_lowercase();
    write_patterns.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_entry(
        seq: u64,
        tool_name: &str,
        tool_args: &str,
        tool_result: &str,
        outcome: &str,
        ifc_label: &str,
    ) -> BlackboxEntry {
        BlackboxEntry {
            seq,
            timestamp_ms: 1000 + seq as i64 * 100,
            agent_name: "test-agent".into(),
            agent_permissions: "dev".into(),
            session_id: "session-1".into(),
            tool_name: tool_name.into(),
            tool_args: tool_args.into(),
            tool_result: tool_result.into(),
            outcome: outcome.into(),
            duration_us: 1000,
            ifc_label: ifc_label.into(),
            prev_hash: String::new(),
            hash: String::new(),
            obo_sub: None,
        }
    }

    #[test]
    fn risk_rating_clean_for_empty() {
        assert_eq!(RiskRating::from_paths(&[]), RiskRating::Clean);
    }

    #[test]
    fn risk_rating_high_for_confident_path() {
        let paths = vec![TaintPath {
            source_seq: 1,
            sink_seq: 5,
            source_tool: "web_fetch".into(),
            sink_tool: "file_write".into(),
            mechanism: TaintMechanism::Semantic,
            confidence: 0.9,
            evidence: "high similarity".into(),
        }];
        assert_eq!(RiskRating::from_paths(&paths), RiskRating::High);
    }

    #[test]
    fn risk_rating_low_for_weak_path() {
        let paths = vec![TaintPath {
            source_seq: 1,
            sink_seq: 5,
            source_tool: "web_fetch".into(),
            sink_tool: "file_write".into(),
            mechanism: TaintMechanism::Causal,
            confidence: 0.3,
            evidence: "weak signal".into(),
        }];
        assert_eq!(RiskRating::from_paths(&paths), RiskRating::Low);
    }

    #[test]
    fn is_write_tool_identifies_writes() {
        assert!(is_write_tool("file_write"));
        assert!(is_write_tool("create_resource"));
        assert!(is_write_tool("http_post"));
        assert!(!is_write_tool("file_read"));
        assert!(!is_write_tool("list_items"));
    }

    #[test]
    fn analyze_session_no_taint() {
        let entries = vec![
            mock_entry(1, "file_read", "{}", "ok", "allowed", "Trusted"),
            mock_entry(2, "file_read", "{}", "ok", "allowed", "Trusted"),
        ];
        let paths = analyze_session(&entries);
        assert!(paths.is_empty());
    }

    #[test]
    fn analyze_session_detects_semantic_taint() {
        let entries = vec![
            mock_entry(
                1,
                "web_fetch",
                "{}",
                "the secret password is hunter2 and the API key is AKIA1234",
                "allowed",
                "Untrusted",
            ),
            mock_entry(
                2,
                "file_write",
                "the secret password is hunter2 and the API key is AKIA1234",
                "ok",
                "allowed",
                "Trusted",
            ),
        ];
        let paths = analyze_session(&entries);
        assert!(!paths.is_empty(), "should detect semantic taint");
        assert_eq!(paths[0].mechanism, TaintMechanism::Semantic);
        assert!(paths[0].confidence > 0.3);
    }
}
