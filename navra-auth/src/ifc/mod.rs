//! Information Flow Control enforcement for AI agent tool calls.
//!
//! The label types (`DataLabel`, `Integrity`, `Confidentiality`) are
//! defined in `navra-protocol::label` because they annotate protocol
//! messages. This module provides the enforcement logic: taint tracking,
//! write policies, and tool classification.
//!
//! # Security Invariants (Bell-LaPadula)
//!
//! The following properties hold for any sequence of tool calls within
//! a session. Lattice algebra proofs are in `navra-protocol::label`
//! (verified by Kani model checker). Enforcement invariants are tested
//! as property-based tests below.
//!
//! **INV-1 Taint Monotonicity**: `absorb(label)` can only raise the
//! session taint level, never lower it. `taint_after >= taint_before`
//! on both dimensions. The only exception is explicit `declassify()`
//! by a trusted authority.
//!
//! **INV-2 No-Write-Down** (★-property): A session with taint level C
//! cannot write to a destination with classification < C. Enforced by
//! `is_write_tool()` + `TaintedWritePolicy::Deny` in the dispatch layer.
//!
//! **INV-3 No-Read-Up** (Simple Security Property): An agent with
//! read clearance C cannot access data classified above C. Enforced by
//! `ReadClearance` comparison after the safety pipeline labels content.
//!
//! **INV-4 Taint Propagation**: Reading untrusted external data
//! (tool results labeled `Untrusted`) raises the session integrity
//! to `Untrusted`. Subsequent write tools see this taint.
//!
//! **INV-5 Declassification Safety**: Only `declassify()` can lower
//! confidentiality. It must step DOWN, not up. And it requires a
//! trusted declassification authority (PII filter after full redaction).
//!
//! **INV-6 Join Preservation**: If either input to a tool chain is
//! restricted, the output remains restricted. Formally:
//! `!a.can_write_to(t) || !b.can_write_to(t) → !a.join(b).can_write_to(t)`
//! (proven by Kani in label.rs).

pub mod benchmark;
pub mod corpus;
pub mod value_store;
pub mod witness;

pub use navra_protocol::label::{Confidentiality, DataLabel, Integrity};
pub use witness::DeclassificationWitness;

/// Session taint tracker.
///
/// Accumulates the highest label seen during a session.
/// Taint only rises (lattice join), never drops.
#[derive(Debug, Clone)]
pub struct TaintTracker {
    current: DataLabel,
    witnesses: Vec<DeclassificationWitness>,
}

impl TaintTracker {
    pub fn new() -> Self {
        Self {
            current: DataLabel::TRUSTED_PUBLIC,
            witnesses: Vec::new(),
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
    ///
    /// Returns `Some(witness)` on success (unsigned — caller signs if
    /// they have a signer), `None` if the declassification would step UP.
    pub fn declassify(
        &mut self,
        new_confidentiality: Confidentiality,
        declassifier: &str,
        justification: &str,
    ) -> Option<DeclassificationWitness> {
        if new_confidentiality < self.current.confidentiality {
            let original_label = self.current;
            self.current.confidentiality = new_confidentiality;
            let w = DeclassificationWitness {
                original_label,
                new_label: self.current,
                declassifier: declassifier.to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                justification: justification.to_string(),
                signature: None,
            };
            self.witnesses.push(w.clone());
            Some(w)
        } else {
            None
        }
    }

    /// All declassification witnesses accumulated in this session.
    pub fn witnesses(&self) -> &[DeclassificationWitness] {
        &self.witnesses
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

/// Classify a tool as read-only vs write/action using MCP tool annotations.
///
/// When annotations are available, uses `read_only_hint` (authoritative).
/// Falls back to name-based heuristic only for tools without annotations.
pub fn is_write_tool(
    tool_name: &str,
    annotations: Option<&navra_protocol::ToolAnnotations>,
) -> bool {
    if let Some(ann) = annotations {
        if let Some(read_only) = ann.read_only_hint {
            return !read_only;
        }
        if let Some(destructive) = ann.destructive_hint {
            return destructive;
        }
    }
    // Fallback: name-based heuristic for tools without annotations
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
/// Gateway tools (navra_var_*) are excluded — they return
/// kernel-managed metadata, not external data.
pub fn is_external_read_tool(tool_name: &str) -> bool {
    if tool_name.starts_with("navra_var_") {
        return false;
    }
    tool_name.contains("read")
        || tool_name.contains("search")
        || tool_name.contains("list")
        || tool_name.contains("diff")
        || tool_name.contains("log")
        || tool_name.contains("status")
        || tool_name.contains("branch")
        || tool_name.contains("fetch")
        || tool_name.contains("pull")
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
    fn write_tool_classification_fallback() {
        // No annotations: falls back to name-based heuristic
        assert!(is_write_tool("file_write", None));
        assert!(is_write_tool("git_commit", None));
        assert!(is_write_tool("git_push", None));
        assert!(is_write_tool("file_delete", None));
        assert!(is_write_tool("file_edit", None));
        assert!(is_write_tool("shell_exec", None));
        assert!(!is_write_tool("file_read", None));
        assert!(!is_write_tool("git_status", None));
        assert!(!is_write_tool("rag_search", None));
    }

    #[test]
    fn write_tool_classification_annotations() {
        use navra_protocol::ToolAnnotations;

        let read_only = ToolAnnotations {
            read_only_hint: Some(true),
            destructive_hint: None,
            idempotent_hint: None,
            open_world_hint: None,
            title: None,
        };
        let writable = ToolAnnotations {
            read_only_hint: Some(false),
            destructive_hint: None,
            idempotent_hint: None,
            open_world_hint: None,
            title: None,
        };
        let destructive = ToolAnnotations {
            read_only_hint: None,
            destructive_hint: Some(true),
            idempotent_hint: None,
            open_world_hint: None,
            title: None,
        };

        // Annotations override name heuristic
        assert!(!is_write_tool("file_write", Some(&read_only)));
        assert!(is_write_tool("file_read", Some(&writable)));
        assert!(is_write_tool("rag_search", Some(&destructive)));
    }

    #[test]
    fn external_read_classification() {
        assert!(is_external_read_tool("file_read"));
        assert!(is_external_read_tool("file_search"));
        assert!(is_external_read_tool("file_list"));
        assert!(is_external_read_tool("git_diff"));
        assert!(is_external_read_tool("git_log"));
        assert!(is_external_read_tool("git_status"));
        assert!(!is_external_read_tool("git_commit"));
    }

    #[test]
    fn trusted_path_glob_match() {
        let patterns = vec!["/home/user/Code/**".to_string()];
        assert!(is_trusted_path(
            "/home/user/Code/project/src/main.rs",
            &patterns
        ));
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
        assert!(is_trusted_path(
            "/home/user/Code/project/../other/file.rs",
            &patterns
        ));
        // After normalization: /home/user/Code/other/file.rs — still matches
    }

    // --- Security invariant property tests (INV-1 through INV-5) ---

    #[test]
    fn inv1_taint_monotonicity() {
        let labels = [
            DataLabel::TRUSTED_PUBLIC,
            DataLabel::UNTRUSTED_PUBLIC,
            DataLabel::UNTRUSTED_SENSITIVE,
            DataLabel::UNTRUSTED_PII,
            DataLabel::TRUSTED_SECRET,
        ];
        for &first in &labels {
            for &second in &labels {
                let mut tracker = TaintTracker::new();
                tracker.absorb(first);
                let after_first = tracker.level();
                tracker.absorb(second);
                let after_second = tracker.level();
                assert!(
                    after_second.integrity >= after_first.integrity,
                    "INV-1: integrity must not decrease after absorb"
                );
                assert!(
                    after_second.confidentiality >= after_first.confidentiality,
                    "INV-1: confidentiality must not decrease after absorb"
                );
            }
        }
    }

    #[test]
    fn inv2_no_write_down() {
        let levels = [
            Confidentiality::Public,
            Confidentiality::Sensitive,
            Confidentiality::Pii,
            Confidentiality::Secret,
        ];
        for &taint_level in &levels {
            for &target_level in &levels {
                let label = DataLabel {
                    integrity: Integrity::Untrusted,
                    confidentiality: taint_level,
                };
                let can_write = label.can_write_to(target_level);
                if taint_level > target_level {
                    assert!(
                        !can_write,
                        "INV-2: taint {:?} must NOT write to {:?}",
                        taint_level, target_level
                    );
                } else {
                    assert!(
                        can_write,
                        "INV-2: taint {:?} should write to {:?}",
                        taint_level, target_level
                    );
                }
            }
        }
    }

    #[test]
    fn inv3_no_read_up() {
        let levels = [
            Confidentiality::Public,
            Confidentiality::Sensitive,
            Confidentiality::Pii,
            Confidentiality::Secret,
        ];
        for &clearance in &levels {
            for &classification in &levels {
                let can_read = DataLabel::can_read_from(clearance, classification);
                if classification > clearance {
                    assert!(
                        !can_read,
                        "INV-3: clearance {:?} must NOT read {:?}",
                        clearance, classification
                    );
                } else {
                    assert!(
                        can_read,
                        "INV-3: clearance {:?} should read {:?}",
                        clearance, classification
                    );
                }
            }
        }
    }

    #[test]
    fn inv4_taint_propagation_from_untrusted_read() {
        let mut tracker = TaintTracker::new();
        assert_eq!(tracker.level().integrity, Integrity::Trusted);
        tracker.absorb(DataLabel::UNTRUSTED_PUBLIC);
        assert_eq!(
            tracker.level().integrity,
            Integrity::Untrusted,
            "INV-4: reading untrusted data must raise integrity to Untrusted"
        );
    }

    #[test]
    fn inv5_declassify_only_steps_down() {
        let mut tracker = TaintTracker::new();
        tracker.absorb(DataLabel::UNTRUSTED_PII);
        assert_eq!(tracker.level().confidentiality, Confidentiality::Pii);

        // Cannot step UP via declassify
        assert!(
            tracker
                .declassify(Confidentiality::Secret, "test", "reason")
                .is_none(),
            "INV-5: declassify must reject stepping UP"
        );
        assert_eq!(tracker.level().confidentiality, Confidentiality::Pii);

        // Can step DOWN
        assert!(
            tracker
                .declassify(Confidentiality::Sensitive, "test", "reason")
                .is_some(),
            "INV-5: declassify should allow stepping DOWN"
        );
        assert_eq!(tracker.level().confidentiality, Confidentiality::Sensitive);
    }

    #[test]
    fn declassify_produces_witness() {
        let mut tracker = TaintTracker::new();
        tracker.absorb(DataLabel::UNTRUSTED_PII);
        let w = tracker
            .declassify(Confidentiality::Public, "pii-filter", "full redaction")
            .unwrap();
        assert_eq!(w.original_label.confidentiality, Confidentiality::Pii);
        assert_eq!(w.new_label.confidentiality, Confidentiality::Public);
        assert_eq!(w.declassifier, "pii-filter");
        assert_eq!(w.justification, "full redaction");
        assert!(w.signature.is_none());
    }

    #[test]
    fn declassify_step_up_rejected() {
        let mut tracker = TaintTracker::new();
        assert!(tracker
            .declassify(Confidentiality::Pii, "attacker", "no reason")
            .is_none());
    }

    #[test]
    fn witnesses_accumulate() {
        let mut tracker = TaintTracker::new();
        tracker.absorb(DataLabel::TRUSTED_SECRET);
        tracker.declassify(Confidentiality::Pii, "auth-a", "step 1");
        tracker.declassify(Confidentiality::Public, "auth-b", "step 2");
        assert_eq!(tracker.witnesses().len(), 2);
        assert_eq!(tracker.witnesses()[0].declassifier, "auth-a");
        assert_eq!(tracker.witnesses()[1].declassifier, "auth-b");
    }

    #[test]
    fn declassify_preserves_monotonicity() {
        let mut tracker = TaintTracker::new();
        tracker.absorb(DataLabel::UNTRUSTED_PII);
        tracker.declassify(Confidentiality::Public, "filter", "redacted");
        assert_eq!(tracker.level().confidentiality, Confidentiality::Public);
        // Re-absorb raises taint back up
        tracker.absorb(DataLabel::UNTRUSTED_SENSITIVE);
        assert_eq!(tracker.level().confidentiality, Confidentiality::Sensitive);
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

    // --- Noninterference proof ---
    // Two runs that differ only in secret input produce the same
    // public-visible write decision.

    #[kani::proof]
    fn noninterference_write_decision() {
        // Two sessions start with the same public data
        let public_label = DataLabel::TRUSTED_PUBLIC;
        let target_clearance: Confidentiality = kani::any();

        // Session A: absorbs public data only
        let mut tracker_a = TaintTracker::new();
        tracker_a.absorb(public_label);
        let can_write_a = tracker_a.level().can_write_to(target_clearance);

        // Session B: absorbs the SAME public data plus secret data
        let mut tracker_b = TaintTracker::new();
        tracker_b.absorb(public_label);
        let secret: DataLabel = kani::any();
        kani::assume(secret.confidentiality > Confidentiality::Public);
        tracker_b.absorb(secret);
        let can_write_b = tracker_b.level().can_write_to(target_clearance);

        // If A can write to public target, B must NOT be able to
        // (secret data taints the session, preventing write-down)
        if target_clearance == Confidentiality::Public && can_write_a {
            assert!(
                !can_write_b,
                "secret data must prevent write-down to public target"
            );
        }
    }

    // --- Declassification safety ---

    #[kani::proof]
    fn declassify_only_steps_down() {
        let mut tracker = TaintTracker::new();
        let label: DataLabel = kani::any();
        tracker.absorb(label);
        let before = tracker.level().confidentiality;
        let target: Confidentiality = kani::any();
        let accepted = tracker.declassify(target, "kani", "proof").is_some();
        if target >= before {
            assert!(!accepted, "declassify must reject stepping up");
        }
        if accepted {
            assert!(tracker.level().confidentiality < before);
        }
    }
}
