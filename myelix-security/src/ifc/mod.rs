//! Information Flow Control enforcement for AI agent tool calls.
//!
//! The label types (`DataLabel`, `Integrity`, `Confidentiality`) are
//! defined in `myelix-protocol::label` because they annotate protocol
//! messages. This module provides the enforcement logic: taint tracking,
//! write policies, and tool classification.

pub mod value_store;

pub use myelix_protocol::label::{Confidentiality, DataLabel, Integrity};

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

    /// Is the session tainted with untrusted data?
    pub fn is_untrusted(&self) -> bool {
        self.current.integrity == Integrity::Untrusted
    }

    /// Is the session tainted with sensitive or secret data?
    pub fn is_sensitive(&self) -> bool {
        self.current.confidentiality >= Confidentiality::Sensitive
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

/// Classify a tool as producing external/untrusted data.
///
/// Read tools that access external data should label their output
/// as Untrusted — the data may contain prompt injection payloads.
/// Gateway tools (myelix_var_*) are excluded — they return
/// kernel-managed metadata, not external data.
pub fn is_external_read_tool(tool_name: &str) -> bool {
    if tool_name.starts_with("myelix_var_") {
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
    fn write_tool_classification() {
        assert!(is_write_tool("docs_write"));
        assert!(is_write_tool("git_commit"));
        assert!(is_write_tool("git_push"));
        assert!(is_write_tool("docs_delete"));
        assert!(is_write_tool("docs_edit"));
        assert!(is_write_tool("shell_exec"));
        assert!(!is_write_tool("docs_read"));
        assert!(!is_write_tool("git_status"));
        assert!(!is_write_tool("rag_search"));
    }

    #[test]
    fn external_read_classification() {
        assert!(is_external_read_tool("docs_read"));
        assert!(is_external_read_tool("docs_search"));
        assert!(is_external_read_tool("docs_list"));
        assert!(is_external_read_tool("git_diff"));
        assert!(is_external_read_tool("git_log"));
        assert!(!is_external_read_tool("git_status"));
        assert!(!is_external_read_tool("git_commit"));
    }
}
