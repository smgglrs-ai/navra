//! Information Flow Control enforcement for AI agent tool calls.
//!
//! The label types (`DataLabel`, `Integrity`, `Confidentiality`) are
//! defined in `smgglrs-protocol::label` because they annotate protocol
//! messages. This module provides the enforcement logic: taint tracking,
//! write policies, and tool classification.

pub mod value_store;

pub use smgglrs_protocol::label::{Confidentiality, DataLabel, Integrity};

/// Session taint tracker.
///
/// Accumulates the highest label seen during a session.
/// Taint only rises (lattice join), never drops.
#[derive(Debug, Clone)]
pub struct TaintTracker {
    current: DataLabel,
}

impl TaintTracker {
    pub fn new() -> Self {
        Self {
            current: DataLabel::TRUSTED_PUBLIC,
        }
    }

    /// Absorb a new label (lattice join with current taint).
    pub fn absorb(&mut self, label: DataLabel) {
        self.current = self.current.join(label);
    }

    /// Current taint level.
    pub fn level(&self) -> DataLabel {
        self.current
    }

    /// Declassify: step down the confidentiality level.
    ///
    /// This is the ONLY exception to IFC monotonicity. It must only
    /// be called by trusted declassification authorities (e.g., the
    /// PII filter pipeline after full redaction).
    ///
    /// The new level must be LOWER than the current level — stepping
    /// UP via declassify is rejected (use absorb for that).
    pub fn declassify(&mut self, new_confidentiality: Confidentiality) -> bool {
        if new_confidentiality < self.current.confidentiality {
            self.current.confidentiality = new_confidentiality;
            true
        } else {
            false
        }
    }

    /// Is the session tainted with untrusted data?
    pub fn is_untrusted(&self) -> bool {
        self.current.integrity == Integrity::Untrusted
    }

    /// Is the session tainted with sensitive or higher data?
    pub fn is_sensitive(&self) -> bool {
        self.current.confidentiality >= Confidentiality::Sensitive
    }

    /// Is the session tainted with PII or higher data?
    pub fn is_pii(&self) -> bool {
        self.current.confidentiality >= Confidentiality::Pii
    }
}

impl Default for TaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// IFC policy for a permission set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintedWritePolicy {
    /// Allow writes even from tainted sessions (no IFC enforcement).
    Allow,
    /// Require human approval for writes from tainted sessions.
    Approve,
    /// Deny writes from tainted sessions entirely.
    Deny,
}

impl TaintedWritePolicy {
    pub fn from_str(s: &str) -> Self {
        match s {
            "approve" => Self::Approve,
            "deny" => Self::Deny,
            _ => Self::Allow,
        }
    }
}

/// Read clearance for a permission set (Simple Security Property).
///
/// Defines the maximum confidentiality level an agent can read.
/// Data classified above this level is blocked after the safety
/// pipeline labels it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadClearance {
    pub level: Confidentiality,
    pub policy: TaintedWritePolicy,
}

impl ReadClearance {
    pub fn new(level: Confidentiality, policy: TaintedWritePolicy) -> Self {
        Self { level, policy }
    }

    /// Default: Secret clearance, Allow policy (backward compatible).
    pub fn permissive() -> Self {
        Self {
            level: Confidentiality::Secret,
            policy: TaintedWritePolicy::Allow,
        }
    }

    pub fn from_config(level: &str, policy: &str) -> Self {
        let l = match level {
            "public" => Confidentiality::Public,
            "sensitive" => Confidentiality::Sensitive,
            "pii" => Confidentiality::Pii,
            _ => Confidentiality::Secret,
        };
        Self {
            level: l,
            policy: TaintedWritePolicy::from_str(policy),
        }
    }
}

/// Classify a tool as read-only vs write/action.
///
/// Write tools are those that modify state: file writes, git commits,
/// credential access, shell execution, A2A message sending.
pub fn is_write_tool(tool_name: &str) -> bool {
    tool_name.contains("write")
        || tool_name.contains("commit")
        || tool_name.contains("push")
        || tool_name.contains("delete")
        || tool_name.contains("edit")
        || tool_name.contains("send")
        || tool_name.contains("exec")
}

/// Check if a file path matches any trusted path pattern.
///
/// Trusted paths are user-controlled locations whose content should
/// keep its Trusted integrity label even when accessed via external
/// read tools. Supports glob patterns with tilde expansion.
pub fn is_trusted_path(path: &str, patterns: &[String]) -> bool {
    // Resolve symlinks via canonicalize; fall back to lexical normalization
    // if the path doesn't exist yet
    let normalized = std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| normalize_path(path));
    for pattern in patterns {
        let expanded = expand_tilde(pattern);
        if glob::Pattern::new(&expanded)
            .map(|p| p.matches(&normalized))
            .unwrap_or(false)
        {
            return true;
        }
        // "~/dir/**" should also match "~/dir" itself
        if let Some(prefix) = expanded.strip_suffix("/**") {
            if normalized == prefix || normalized == format!("{prefix}/") {
                return true;
            }
        }
    }
    false
}

fn expand_tilde(pattern: &str) -> String {
    if pattern.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.display(), &pattern[1..]);
        }
    }
    pattern.to_string()
}

fn normalize_path(path: &str) -> String {
    let p = std::path::Path::new(path);
    let mut components = Vec::new();
    for component in p.components() {
        match component {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::CurDir => {}
            other => components.push(other),
        }
    }
    let result: std::path::PathBuf = components.iter().collect();
    result.to_string_lossy().to_string()
}

/// Classify a tool as producing external/untrusted data.
///
/// Read tools that access external data should label their output
/// as Untrusted — the data may contain prompt injection payloads.
/// Gateway tools (smgglrs_var_*) are excluded — they return
/// kernel-managed metadata, not external data.
pub fn is_external_read_tool(tool_name: &str) -> bool {
    if tool_name.starts_with("smgglrs_var_") {
        return false;
    }
    tool_name.contains("read")
        || tool_name.contains("search")
        || tool_name.contains("list")
        || tool_name.contains("diff")
        || tool_name.contains("log")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_tracker_starts_clean() {
        let tracker = TaintTracker::new();
        assert!(!tracker.is_untrusted());
        assert!(!tracker.is_sensitive());
        assert_eq!(tracker.level(), DataLabel::TRUSTED_PUBLIC);
    }

    #[test]
    fn taint_tracker_absorbs() {
        let mut tracker = TaintTracker::new();
        tracker.absorb(DataLabel::UNTRUSTED_PUBLIC);
        assert!(tracker.is_untrusted());
        assert!(!tracker.is_sensitive());
    }

    #[test]
    fn taint_only_rises() {
        let mut tracker = TaintTracker::new();
        tracker.absorb(DataLabel::UNTRUSTED_SENSITIVE);
        tracker.absorb(DataLabel::TRUSTED_PUBLIC); // should not decrease
        assert!(tracker.is_untrusted());
        assert!(tracker.is_sensitive());
    }

    #[test]
    fn taint_tracker_pii_level() {
        let mut tracker = TaintTracker::new();
        assert!(!tracker.is_pii());

        tracker.absorb(DataLabel::UNTRUSTED_PII);
        assert!(tracker.is_pii());
        assert!(tracker.is_sensitive()); // Pii > Sensitive, so is_sensitive() is true
        assert!(tracker.is_untrusted());
    }

    #[test]
    fn pii_taint_does_not_decrease() {
        let mut tracker = TaintTracker::new();
        tracker.absorb(DataLabel::UNTRUSTED_PII);
        tracker.absorb(DataLabel::UNTRUSTED_SENSITIVE); // should not decrease
        assert!(tracker.is_pii());
        assert_eq!(tracker.level().confidentiality, Confidentiality::Pii);
    }

    #[test]
    fn pii_join_secret_becomes_secret() {
        let mut tracker = TaintTracker::new();
        tracker.absorb(DataLabel::UNTRUSTED_PII);
        tracker.absorb(DataLabel::TRUSTED_SECRET);
        assert_eq!(tracker.level().confidentiality, Confidentiality::Secret);
    }

    #[test]
    fn write_tool_classification() {
        assert!(is_write_tool("file_write"));
        assert!(is_write_tool("git_commit"));
        assert!(is_write_tool("git_push"));
        assert!(is_write_tool("file_delete"));
        assert!(is_write_tool("file_edit"));
        assert!(is_write_tool("shell_exec"));
        assert!(!is_write_tool("file_read"));
        assert!(!is_write_tool("git_status"));
        assert!(!is_write_tool("rag_search"));
    }

    #[test]
    fn external_read_classification() {
        assert!(is_external_read_tool("file_read"));
        assert!(is_external_read_tool("file_search"));
        assert!(is_external_read_tool("file_list"));
        assert!(is_external_read_tool("git_diff"));
        assert!(is_external_read_tool("git_log"));
        assert!(!is_external_read_tool("git_status"));
        assert!(!is_external_read_tool("git_commit"));
    }

    #[test]
    fn trusted_path_glob_match() {
        let patterns = vec!["/home/user/Code/**".to_string()];
        assert!(is_trusted_path("/home/user/Code/project/src/main.rs", &patterns));
        assert!(is_trusted_path("/home/user/Code", &patterns));
        assert!(!is_trusted_path("/home/user/Downloads/file.txt", &patterns));
    }

    #[test]
    fn trusted_path_exact_match() {
        let patterns = vec!["/opt/data/config.toml".to_string()];
        assert!(is_trusted_path("/opt/data/config.toml", &patterns));
        assert!(!is_trusted_path("/opt/data/other.toml", &patterns));
    }

    #[test]
    fn trusted_path_no_patterns() {
        assert!(!is_trusted_path("/any/path", &[]));
    }

    #[test]
    fn trusted_path_multiple_patterns() {
        let patterns = vec![
            "/home/user/Code/**".to_string(),
            "/home/user/Documents/**".to_string(),
        ];
        assert!(is_trusted_path("/home/user/Code/file.rs", &patterns));
        assert!(is_trusted_path("/home/user/Documents/notes.md", &patterns));
        assert!(!is_trusted_path("/tmp/scratch", &patterns));
    }

    #[test]
    fn trusted_path_normalizes_traversal() {
        let patterns = vec!["/home/user/Code/**".to_string()];
        assert!(is_trusted_path("/home/user/Code/project/../other/file.rs", &patterns));
        // After normalization: /home/user/Code/other/file.rs — still matches
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn taint_never_decreases() {
        let mut tracker = TaintTracker::new();
        let label: DataLabel = kani::any();
        let before = tracker.level();
        tracker.absorb(label);
        let after = tracker.level();
        assert!(after.integrity >= before.integrity);
        assert!(after.confidentiality >= before.confidentiality);
    }

    #[kani::proof]
    fn taint_monotonic_over_sequence() {
        let mut tracker = TaintTracker::new();
        let l1: DataLabel = kani::any();
        let l2: DataLabel = kani::any();
        let l3: DataLabel = kani::any();

        tracker.absorb(l1);
        let after1 = tracker.level();
        tracker.absorb(l2);
        let after2 = tracker.level();
        tracker.absorb(l3);
        let after3 = tracker.level();

        assert!(after2.integrity >= after1.integrity);
        assert!(after2.confidentiality >= after1.confidentiality);
        assert!(after3.integrity >= after2.integrity);
        assert!(after3.confidentiality >= after2.confidentiality);
    }

    #[kani::proof]
    fn pii_implies_sensitive() {
        let mut tracker = TaintTracker::new();
        let label: DataLabel = kani::any();
        tracker.absorb(label);
        if tracker.is_pii() {
            assert!(tracker.is_sensitive());
        }
    }

    #[kani::proof]
    fn absorb_is_join() {
        let mut tracker = TaintTracker::new();
        let l1: DataLabel = kani::any();
        let l2: DataLabel = kani::any();
        tracker.absorb(l1);
        tracker.absorb(l2);
        assert_eq!(tracker.level(), l1.join(l2));
    }
}
