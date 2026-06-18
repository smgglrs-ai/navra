//! Taint audit report generation.

use super::{RiskRating, TaintPath};
use serde::{Deserialize, Serialize};

/// Per-session taint analysis summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
    pub session_id: String,
    pub risk: RiskRating,
    pub taint_paths: Vec<TaintPath>,
    pub total_entries: usize,
    pub untrusted_entries: usize,
    pub remediation: Vec<String>,
}

/// Full taint audit report across multiple sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub timestamp: String,
    pub sessions: Vec<SessionReport>,
    pub summary: AuditSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub sessions_analyzed: usize,
    pub sessions_clean: usize,
    pub sessions_low: usize,
    pub sessions_medium: usize,
    pub sessions_high: usize,
    pub total_taint_paths: usize,
}

impl AuditReport {
    pub fn from_sessions(sessions: Vec<SessionReport>) -> Self {
        let summary = AuditSummary {
            sessions_analyzed: sessions.len(),
            sessions_clean: sessions.iter().filter(|s| s.risk == RiskRating::Clean).count(),
            sessions_low: sessions.iter().filter(|s| s.risk == RiskRating::Low).count(),
            sessions_medium: sessions.iter().filter(|s| s.risk == RiskRating::Medium).count(),
            sessions_high: sessions.iter().filter(|s| s.risk == RiskRating::High).count(),
            total_taint_paths: sessions.iter().map(|s| s.taint_paths.len()).sum(),
        };

        let timestamp = chrono_now();

        Self {
            timestamp,
            sessions,
            summary,
        }
    }
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}

/// Generate remediation suggestions for detected taint paths.
pub fn remediation_for(paths: &[TaintPath]) -> Vec<String> {
    use super::TaintMechanism;
    let mut suggestions = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for path in paths {
        let key = format!("{:?}-{}", path.mechanism, path.sink_tool);
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);

        match path.mechanism {
            TaintMechanism::Semantic => {
                suggestions.push(format!(
                    "Review tool '{}': content from untrusted source '{}' reached trusted write path via paraphrase/summarization. \
                     Consider adding a SafetyHook filter or IFC taint gate before this tool.",
                    path.sink_tool, path.source_tool
                ));
            }
            TaintMechanism::Causal => {
                suggestions.push(format!(
                    "Tool '{}' was first invoked after untrusted input from '{}'. \
                     Verify this tool call was not influenced by untrusted content. \
                     Consider adding a TemporalContract requiring explicit approval.",
                    path.sink_tool, path.source_tool
                ));
            }
            TaintMechanism::Persistent => {
                suggestions.push(format!(
                    "Cross-session contamination detected: untrusted data from '{}' \
                     persisted in memory and influenced '{}'. \
                     Review memory extraction hook's taint tracking.",
                    path.source_tool, path.sink_tool
                ));
            }
        }
    }

    suggestions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint_audit::{TaintMechanism, TaintPath};

    #[test]
    fn audit_report_counts_risks() {
        let sessions = vec![
            SessionReport {
                session_id: "s1".into(),
                risk: RiskRating::Clean,
                taint_paths: vec![],
                total_entries: 5,
                untrusted_entries: 0,
                remediation: vec![],
            },
            SessionReport {
                session_id: "s2".into(),
                risk: RiskRating::High,
                taint_paths: vec![TaintPath {
                    source_seq: 1,
                    sink_seq: 3,
                    source_tool: "web_fetch".into(),
                    sink_tool: "file_write".into(),
                    mechanism: TaintMechanism::Semantic,
                    confidence: 0.9,
                    evidence: "test".into(),
                }],
                total_entries: 10,
                untrusted_entries: 3,
                remediation: vec!["Review file_write".into()],
            },
        ];

        let report = AuditReport::from_sessions(sessions);
        assert_eq!(report.summary.sessions_analyzed, 2);
        assert_eq!(report.summary.sessions_clean, 1);
        assert_eq!(report.summary.sessions_high, 1);
        assert_eq!(report.summary.total_taint_paths, 1);
    }

    #[test]
    fn remediation_deduplicates() {
        let paths = vec![
            TaintPath {
                source_seq: 1,
                sink_seq: 3,
                source_tool: "web_fetch".into(),
                sink_tool: "file_write".into(),
                mechanism: TaintMechanism::Semantic,
                confidence: 0.8,
                evidence: "a".into(),
            },
            TaintPath {
                source_seq: 2,
                sink_seq: 4,
                source_tool: "web_fetch".into(),
                sink_tool: "file_write".into(),
                mechanism: TaintMechanism::Semantic,
                confidence: 0.7,
                evidence: "b".into(),
            },
        ];
        let remediation = remediation_for(&paths);
        assert_eq!(remediation.len(), 1);
    }

    #[test]
    fn remediation_per_mechanism() {
        let paths = vec![
            TaintPath {
                source_seq: 1,
                sink_seq: 3,
                source_tool: "web".into(),
                sink_tool: "write".into(),
                mechanism: TaintMechanism::Semantic,
                confidence: 0.8,
                evidence: "".into(),
            },
            TaintPath {
                source_seq: 1,
                sink_seq: 4,
                source_tool: "web".into(),
                sink_tool: "exec".into(),
                mechanism: TaintMechanism::Causal,
                confidence: 0.6,
                evidence: "".into(),
            },
        ];
        let remediation = remediation_for(&paths);
        assert_eq!(remediation.len(), 2);
    }

    #[test]
    fn report_serializes_to_json() {
        let report = AuditReport::from_sessions(vec![]);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("sessions_analyzed"));
    }
}
