//! Information Flow Control for AI agent tool calls.
//!
//! Implements a Bell-LaPadula-inspired [1] label system adapted for
//! AI agents. Every tool result carries a data label with integrity
//! and confidentiality dimensions. The session accumulates taint as
//! the agent reads data — taint only rises, never drops (the "no
//! write-down" rule prevents exfiltration of sensitive data through
//! subsequent tool calls).
//!
//! This is the AI OS equivalent of SELinux security contexts: labels
//! are assigned by the kernel (tool handlers), propagated through
//! the session (taint accumulation), and enforced at write points
//! (IFC hook).
//!
//! [1] Bell, D.E. and LaPadula, L.J. "Secure Computer Systems:
//!     Mathematical Foundations." MITRE, 1973.

use std::fmt;

/// Integrity level: can this data influence actions?
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Integrity {
    /// Data from system config, user input, or approved sources.
    Trusted = 0,
    /// Data from external sources (files, network, tool outputs).
    Untrusted = 1,
}

/// Confidentiality level: can this data leave the system?
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidentiality {
    /// Can appear in any tool output or external message.
    Public = 0,
    /// Can flow only to tools with matching clearance.
    Sensitive = 1,
    /// Cannot flow out at all (credentials, private keys).
    Secret = 2,
}

/// Data label combining integrity and confidentiality.
///
/// Assigned to tool results by the kernel. Propagated through
/// session taint accumulation. Checked by the IFC hook before
/// write operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataLabel {
    pub integrity: Integrity,
    pub confidentiality: Confidentiality,
}

impl DataLabel {
    /// Fully trusted, public data (system-generated).
    pub const TRUSTED_PUBLIC: Self = Self {
        integrity: Integrity::Trusted,
        confidentiality: Confidentiality::Public,
    };

    /// Untrusted external data, public confidentiality.
    pub const UNTRUSTED_PUBLIC: Self = Self {
        integrity: Integrity::Untrusted,
        confidentiality: Confidentiality::Public,
    };

    /// Untrusted external data, sensitive confidentiality.
    pub const UNTRUSTED_SENSITIVE: Self = Self {
        integrity: Integrity::Untrusted,
        confidentiality: Confidentiality::Sensitive,
    };

    /// Trusted but secret data (credential values).
    pub const TRUSTED_SECRET: Self = Self {
        integrity: Integrity::Trusted,
        confidentiality: Confidentiality::Secret,
    };

    /// Join two labels: take the higher (more restrictive) value
    /// on each dimension. This is the lattice join operation.
    ///
    /// Integrity: Untrusted beats Trusted (taint propagates).
    /// Confidentiality: Secret > Sensitive > Public (classification rises).
    pub fn join(self, other: Self) -> Self {
        Self {
            integrity: if self.integrity > other.integrity {
                self.integrity
            } else {
                other.integrity
            },
            confidentiality: if self.confidentiality > other.confidentiality {
                self.confidentiality
            } else {
                other.confidentiality
            },
        }
    }

    /// Check if a write from this label to a target is allowed.
    ///
    /// Bell-LaPadula "no write-down": a session tainted with
    /// Sensitive data cannot write to a Public destination.
    /// A session tainted with Untrusted data may be blocked from
    /// write operations entirely (policy-dependent).
    pub fn can_write_to(self, target: Confidentiality) -> bool {
        // No write-down: session confidentiality must be <= target
        self.confidentiality <= target
    }
}

impl Default for DataLabel {
    fn default() -> Self {
        Self::TRUSTED_PUBLIC
    }
}

impl fmt::Display for DataLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}+{:?}", self.integrity, self.confidentiality)
    }
}

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
    // Explicit write operations
    if tool_name.contains("write")
        || tool_name.contains("commit")
        || tool_name.contains("push")
        || tool_name.contains("delete")
        || tool_name.contains("edit")
        || tool_name.contains("send")
        || tool_name.contains("exec")
    {
        return true;
    }
    false
}

/// Classify a tool as producing external/untrusted data.
///
/// Read tools that access external data should label their output
/// as Untrusted — the data may contain prompt injection payloads.
pub fn is_external_read_tool(tool_name: &str) -> bool {
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
    fn label_join_takes_higher() {
        let a = DataLabel::TRUSTED_PUBLIC;
        let b = DataLabel::UNTRUSTED_SENSITIVE;
        let joined = a.join(b);
        assert_eq!(joined.integrity, Integrity::Untrusted);
        assert_eq!(joined.confidentiality, Confidentiality::Sensitive);
    }

    #[test]
    fn label_join_is_commutative() {
        let a = DataLabel::UNTRUSTED_PUBLIC;
        let b = DataLabel::TRUSTED_SECRET;
        assert_eq!(a.join(b), b.join(a));
    }

    #[test]
    fn label_join_is_idempotent() {
        let a = DataLabel::UNTRUSTED_SENSITIVE;
        assert_eq!(a.join(a), a);
    }

    #[test]
    fn no_write_down_secret_to_public() {
        let label = DataLabel::TRUSTED_SECRET;
        assert!(!label.can_write_to(Confidentiality::Public));
        assert!(!label.can_write_to(Confidentiality::Sensitive));
        assert!(label.can_write_to(Confidentiality::Secret));
    }

    #[test]
    fn no_write_down_sensitive_to_public() {
        let label = DataLabel::UNTRUSTED_SENSITIVE;
        assert!(!label.can_write_to(Confidentiality::Public));
        assert!(label.can_write_to(Confidentiality::Sensitive));
    }

    #[test]
    fn public_can_write_anywhere() {
        let label = DataLabel::TRUSTED_PUBLIC;
        assert!(label.can_write_to(Confidentiality::Public));
        assert!(label.can_write_to(Confidentiality::Sensitive));
        assert!(label.can_write_to(Confidentiality::Secret));
    }

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

    #[test]
    fn display_format() {
        assert_eq!(
            format!("{}", DataLabel::UNTRUSTED_SENSITIVE),
            "Untrusted+Sensitive"
        );
    }
}
