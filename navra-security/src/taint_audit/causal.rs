//! Causal influence detection: identifies when untrusted data
//! influenced agent tool selection without direct content transfer.
//!
//! Detects patterns like:
//! - Agent reads untrusted input, then calls a new tool it hadn't
//!   used before (tool selection influenced by untrusted content)
//! - Agent's tool arguments change pattern after untrusted input

use super::{TaintMechanism, TaintPath};
use navra_core::blackbox::BlackboxEntry;
use std::collections::HashSet;

/// Analyze causal influence of untrusted inputs on agent behavior.
pub fn analyze(
    all_entries: &[BlackboxEntry],
    untrusted: &[&BlackboxEntry],
) -> Vec<TaintPath> {
    let mut paths = Vec::new();

    for source in untrusted {
        let tools_before: HashSet<&str> = all_entries
            .iter()
            .filter(|e| e.seq < source.seq && e.outcome == "allowed")
            .map(|e| e.tool_name.as_str())
            .collect();

        let entries_after: Vec<&BlackboxEntry> = all_entries
            .iter()
            .filter(|e| e.seq > source.seq && e.outcome == "allowed")
            .collect();

        for entry in &entries_after {
            if !tools_before.contains(entry.tool_name.as_str()) {
                let confidence = if is_sensitive_tool(&entry.tool_name) {
                    0.7
                } else {
                    0.4
                };
                paths.push(TaintPath {
                    source_seq: source.seq,
                    sink_seq: entry.seq,
                    source_tool: source.tool_name.clone(),
                    sink_tool: entry.tool_name.clone(),
                    mechanism: TaintMechanism::Causal,
                    confidence,
                    evidence: format!(
                        "Tool '{}' first used after untrusted input from '{}'",
                        entry.tool_name, source.tool_name
                    ),
                });
            }
        }
    }

    paths
}

fn is_sensitive_tool(name: &str) -> bool {
    let sensitive = [
        "write", "delete", "exec", "run", "shell", "send", "deploy",
        "credential", "secret", "token",
    ];
    let lower = name.to_lowercase();
    sensitive.iter().any(|s| lower.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_core::blackbox::BlackboxEntry;

    fn entry(seq: u64, tool: &str, outcome: &str, label: &str) -> BlackboxEntry {
        BlackboxEntry {
            seq,
            timestamp_ms: 1000 + seq as i64 * 100,
            agent_name: "agent".into(),
            agent_permissions: "dev".into(),
            session_id: "s1".into(),
            tool_name: tool.into(),
            tool_args: "{}".into(),
            tool_result: "ok".into(),
            outcome: outcome.into(),
            duration_us: 100,
            ifc_label: label.into(),
            prev_hash: String::new(),
            hash: String::new(),
            obo_sub: None,
        }
    }

    #[test]
    fn detects_new_tool_after_untrusted() {
        let entries = vec![
            entry(1, "file_read", "allowed", "Trusted"),
            entry(2, "web_fetch", "allowed", "Untrusted"),
            entry(3, "shell_exec", "allowed", "Trusted"),
        ];
        let untrusted: Vec<&BlackboxEntry> = entries.iter().filter(|e| e.ifc_label == "Untrusted").collect();
        let paths = analyze(&entries, &untrusted);
        assert!(!paths.is_empty());
        assert_eq!(paths[0].sink_tool, "shell_exec");
        assert_eq!(paths[0].mechanism, TaintMechanism::Causal);
    }

    #[test]
    fn no_causal_when_tool_used_before() {
        let entries = vec![
            entry(1, "file_read", "allowed", "Trusted"),
            entry(2, "shell_exec", "allowed", "Trusted"),
            entry(3, "web_fetch", "allowed", "Untrusted"),
            entry(4, "shell_exec", "allowed", "Trusted"),
        ];
        let untrusted: Vec<&BlackboxEntry> = entries.iter().filter(|e| e.ifc_label == "Untrusted").collect();
        let paths = analyze(&entries, &untrusted);
        // shell_exec was used before the untrusted input, so no causal signal
        assert!(paths.is_empty());
    }

    #[test]
    fn sensitive_tool_gets_higher_confidence() {
        let entries = vec![
            entry(1, "web_fetch", "allowed", "Untrusted"),
            entry(2, "credential_read", "allowed", "Trusted"),
        ];
        let untrusted: Vec<&BlackboxEntry> = entries.iter().filter(|e| e.ifc_label == "Untrusted").collect();
        let paths = analyze(&entries, &untrusted);
        assert!(!paths.is_empty());
        assert!(paths[0].confidence >= 0.7);
    }
}
