//! IFC-aware shared blackboard for multi-agent flows.
//!
//! A flow-level key-value store where each entry carries a `DataLabel`.
//! When an agent reads an entry, the entry's label is absorbed into
//! the reader's taint tracker (lattice join — taint only rises, never
//! drops).

use crate::error::FlowError;
use smgglrs_protocol::label::DataLabel;
use smgglrs_security::ifc::TaintTracker;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// A labeled entry in the blackboard.
#[derive(Debug, Clone)]
pub struct BlackboardEntry {
    pub key: String,
    pub value: Value,
    pub label: DataLabel,
    pub author: String,
    pub version: u64,
    pub updated_at: Instant,
}

/// Flow-level shared blackboard.
///
/// Thread-safe via `Arc<RwLock<>>`, same pattern as `ValueStore`.
/// Derives `Clone` (Arc internals) so it can be shared across agents.
#[derive(Clone)]
pub struct Blackboard {
    entries: Arc<RwLock<HashMap<String, BlackboardEntry>>>,
    max_entries: usize,
}

impl Blackboard {
    /// Create a new blackboard with the given entry limit.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
        }
    }

    /// Publish a key-value pair to the blackboard.
    ///
    /// Inserts or overwrites the entry. If overwriting, increments the
    /// version. Returns the new version number. If at `max_entries` and
    /// the key is new, returns an error.
    pub fn publish(
        &self,
        author: &str,
        key: &str,
        value: Value,
        label: DataLabel,
    ) -> Result<u64, FlowError> {
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());

        let version = if let Some(existing) = entries.get(key) {
            existing.version + 1
        } else {
            if entries.len() >= self.max_entries {
                return Err(FlowError::Other(anyhow::anyhow!(
                    "blackboard full ({} entries): cannot insert key '{}'",
                    self.max_entries,
                    key,
                )));
            }
            1
        };

        let entry = BlackboardEntry {
            key: key.to_string(),
            value,
            label,
            author: author.to_string(),
            version,
            updated_at: Instant::now(),
        };

        tracing::debug!(
            key = key,
            author = author,
            version = version,
            label = %label,
            "blackboard publish"
        );

        entries.insert(key.to_string(), entry);
        Ok(version)
    }

    /// Read an entry from the blackboard, tainting the reader.
    ///
    /// Returns a clone of the entry. Calls `reader_taint.absorb(entry.label)`
    /// to propagate IFC labels — this is the IFC integration point.
    pub fn read(
        &self,
        key: &str,
        reader_taint: &mut TaintTracker,
    ) -> Result<BlackboardEntry, FlowError> {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let entry = entries
            .get(key)
            .ok_or_else(|| FlowError::BlackboardKeyNotFound(key.to_string()))?;
        reader_taint.absorb(entry.label);
        Ok(entry.clone())
    }

    /// Read an entry if it exists, tainting the reader.
    ///
    /// Like `read` but returns `None` instead of an error if the key
    /// is missing. Still absorbs taint if the entry exists.
    pub fn read_if_exists(
        &self,
        key: &str,
        reader_taint: &mut TaintTracker,
    ) -> Option<BlackboardEntry> {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        entries.get(key).map(|entry| {
            reader_taint.absorb(entry.label);
            entry.clone()
        })
    }

    /// Returns all key names. No taint propagation (just metadata).
    pub fn keys(&self) -> Vec<String> {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        entries.keys().cloned().collect()
    }

    /// Clones all entries for orchestrator inspection.
    pub fn snapshot(&self) -> HashMap<String, BlackboardEntry> {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        entries.clone()
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        entries.len()
    }

    /// Returns true if the blackboard is empty.
    pub fn is_empty(&self) -> bool {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_and_read_round_trip() {
        let bb = Blackboard::new(10);
        let mut taint = TaintTracker::new();

        let version = bb
            .publish("agent-a", "result", serde_json::json!("hello"), DataLabel::TRUSTED_PUBLIC)
            .unwrap();
        assert_eq!(version, 1);

        let entry = bb.read("result", &mut taint).unwrap();
        assert_eq!(entry.value, serde_json::json!("hello"));
        assert_eq!(entry.author, "agent-a");
        assert_eq!(entry.version, 1);
    }

    #[test]
    fn read_taints_reader() {
        let bb = Blackboard::new(10);
        let mut taint = TaintTracker::new();
        assert_eq!(taint.level(), DataLabel::TRUSTED_PUBLIC);

        bb.publish(
            "agent-a",
            "secret",
            serde_json::json!("classified"),
            DataLabel::UNTRUSTED_SENSITIVE,
        )
        .unwrap();

        bb.read("secret", &mut taint).unwrap();
        assert_eq!(taint.level(), DataLabel::UNTRUSTED_SENSITIVE);
    }

    #[test]
    fn taint_only_rises() {
        let bb = Blackboard::new(10);
        let mut taint = TaintTracker::new();
        taint.absorb(DataLabel::UNTRUSTED_SENSITIVE);

        bb.publish("agent-a", "public", serde_json::json!("ok"), DataLabel::TRUSTED_PUBLIC)
            .unwrap();

        bb.read("public", &mut taint).unwrap();
        assert_eq!(taint.level(), DataLabel::UNTRUSTED_SENSITIVE);
    }

    #[test]
    fn version_increments_on_overwrite() {
        let bb = Blackboard::new(10);

        let v1 = bb
            .publish("agent-a", "key", serde_json::json!(1), DataLabel::TRUSTED_PUBLIC)
            .unwrap();
        assert_eq!(v1, 1);

        let v2 = bb
            .publish("agent-a", "key", serde_json::json!(2), DataLabel::TRUSTED_PUBLIC)
            .unwrap();
        assert_eq!(v2, 2);
    }

    #[test]
    fn key_not_found() {
        let bb = Blackboard::new(10);
        let mut taint = TaintTracker::new();

        let err = bb.read("missing", &mut taint).unwrap_err();
        assert!(matches!(err, FlowError::BlackboardKeyNotFound(k) if k == "missing"));
    }

    #[test]
    fn read_if_exists_returns_none() {
        let bb = Blackboard::new(10);
        let mut taint = TaintTracker::new();

        assert!(bb.read_if_exists("missing", &mut taint).is_none());
    }

    #[test]
    fn keys_no_taint_propagation() {
        let bb = Blackboard::new(10);

        bb.publish("agent-a", "alpha", serde_json::json!(1), DataLabel::TRUSTED_PUBLIC)
            .unwrap();
        bb.publish("agent-b", "beta", serde_json::json!(2), DataLabel::UNTRUSTED_SENSITIVE)
            .unwrap();

        let mut keys = bb.keys();
        keys.sort();
        assert_eq!(keys, vec!["alpha", "beta"]);
    }

    #[test]
    fn snapshot_returns_all() {
        let bb = Blackboard::new(10);

        bb.publish("a", "k1", serde_json::json!(1), DataLabel::TRUSTED_PUBLIC)
            .unwrap();
        bb.publish("b", "k2", serde_json::json!(2), DataLabel::TRUSTED_PUBLIC)
            .unwrap();
        bb.publish("c", "k3", serde_json::json!(3), DataLabel::TRUSTED_PUBLIC)
            .unwrap();

        let snap = bb.snapshot();
        assert_eq!(snap.len(), 3);
    }

    #[test]
    fn max_entries_enforced() {
        let bb = Blackboard::new(2);

        bb.publish("a", "k1", serde_json::json!(1), DataLabel::TRUSTED_PUBLIC)
            .unwrap();
        bb.publish("a", "k2", serde_json::json!(2), DataLabel::TRUSTED_PUBLIC)
            .unwrap();

        let err = bb
            .publish("a", "k3", serde_json::json!(3), DataLabel::TRUSTED_PUBLIC)
            .unwrap_err();
        assert!(matches!(err, FlowError::Other(_)));
    }
}
