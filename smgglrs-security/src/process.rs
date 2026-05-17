//! Process table for tracking active agent sessions.
//!
//! The AI OS equivalent of `/proc` — tracks which agents are
//! connected, their privilege level, request counts, and active
//! tool calls.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// A single agent process entry.
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    /// Agent name.
    pub name: String,
    /// Agent's permission set.
    pub permissions: String,
    /// DID:key identifier (if capability-token authenticated).
    pub did: Option<String>,
    /// Privilege ring level (None for legacy agents).
    pub ring: Option<u8>,
    /// On-behalf-of human subject identifier.
    pub obo_sub: Option<String>,
    /// Number of tool calls made.
    pub call_count: u64,
    /// Number of tool calls denied.
    pub denied_count: u64,
    /// Timestamp of first activity.
    pub connected_at: Instant,
    /// Timestamp of last activity.
    pub last_active: Instant,
    /// Currently active tool calls (tool name → start time).
    pub active_calls: Vec<String>,
}

/// Snapshot of a process entry for external consumption (no Instant).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessSnapshot {
    pub name: String,
    pub permissions: String,
    pub did: Option<String>,
    pub ring: Option<u8>,
    pub obo_sub: Option<String>,
    pub call_count: u64,
    pub denied_count: u64,
    pub uptime_secs: u64,
    pub idle_secs: u64,
    pub active_calls: Vec<String>,
}

/// Thread-safe process table.
#[derive(Debug, Clone, Default)]
pub struct ProcessTable {
    entries: Arc<RwLock<HashMap<String, ProcessEntry>>>,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a tool call for an agent. Creates the entry if absent.
    pub fn record_call(&self, agent_name: &str, permissions: &str, did: Option<&str>, ring: Option<u8>, tool_name: &str) {
        self.record_call_with_obo(agent_name, permissions, did, ring, tool_name, None);
    }

    /// Record a tool call with optional on-behalf-of human identity.
    pub fn record_call_with_obo(&self, agent_name: &str, permissions: &str, did: Option<&str>, ring: Option<u8>, tool_name: &str, obo_sub: Option<&str>) {
        let mut entries = self.entries.write().unwrap();
        let now = Instant::now();
        let entry = entries
            .entry(agent_name.to_string())
            .or_insert_with(|| ProcessEntry {
                name: agent_name.to_string(),
                permissions: permissions.to_string(),
                did: did.map(String::from),
                ring,
                obo_sub: obo_sub.map(String::from),
                call_count: 0,
                denied_count: 0,
                connected_at: now,
                last_active: now,
                active_calls: Vec::new(),
            });
        entry.call_count += 1;
        entry.last_active = now;
        entry.active_calls.push(tool_name.to_string());
    }

    /// Record a denied tool call.
    pub fn record_denied(&self, agent_name: &str, permissions: &str, did: Option<&str>, ring: Option<u8>) {
        self.record_denied_with_obo(agent_name, permissions, did, ring, None);
    }

    /// Record a denied tool call with optional on-behalf-of human identity.
    pub fn record_denied_with_obo(&self, agent_name: &str, permissions: &str, did: Option<&str>, ring: Option<u8>, obo_sub: Option<&str>) {
        let mut entries = self.entries.write().unwrap();
        let now = Instant::now();
        let entry = entries
            .entry(agent_name.to_string())
            .or_insert_with(|| ProcessEntry {
                name: agent_name.to_string(),
                permissions: permissions.to_string(),
                did: did.map(String::from),
                ring,
                obo_sub: obo_sub.map(String::from),
                call_count: 0,
                denied_count: 0,
                connected_at: now,
                last_active: now,
                active_calls: Vec::new(),
            });
        entry.denied_count += 1;
        entry.last_active = now;
    }

    /// Mark a tool call as completed.
    pub fn complete_call(&self, agent_name: &str, tool_name: &str) {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(agent_name) {
            if let Some(pos) = entry.active_calls.iter().position(|t| t == tool_name) {
                entry.active_calls.remove(pos);
            }
        }
    }

    /// Get a snapshot of all process entries.
    pub fn snapshot(&self) -> Vec<ProcessSnapshot> {
        let entries = self.entries.read().unwrap();
        let now = Instant::now();
        entries
            .values()
            .map(|e| ProcessSnapshot {
                name: e.name.clone(),
                permissions: e.permissions.clone(),
                did: e.did.clone(),
                ring: e.ring,
                obo_sub: e.obo_sub.clone(),
                call_count: e.call_count,
                denied_count: e.denied_count,
                uptime_secs: now.duration_since(e.connected_at).as_secs(),
                idle_secs: now.duration_since(e.last_active).as_secs(),
                active_calls: e.active_calls.clone(),
            })
            .collect()
    }

    /// Number of tracked agents.
    pub fn count(&self) -> usize {
        self.entries.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_snapshot() {
        let table = ProcessTable::new();
        table.record_call("agent-1", "dev", Some("did:key:z6Mk1"), Some(1), "file_read");

        let snap = table.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].name, "agent-1");
        assert_eq!(snap[0].call_count, 1);
        assert_eq!(snap[0].denied_count, 0);
        assert_eq!(snap[0].active_calls, vec!["file_read"]);
    }

    #[test]
    fn complete_call_removes_active() {
        let table = ProcessTable::new();
        table.record_call("a", "dev", None, None, "git_status");
        table.record_call("a", "dev", None, None, "file_read");
        assert_eq!(table.snapshot()[0].active_calls.len(), 2);

        table.complete_call("a", "git_status");
        assert_eq!(table.snapshot()[0].active_calls, vec!["file_read"]);
    }

    #[test]
    fn multiple_agents() {
        let table = ProcessTable::new();
        table.record_call("a", "dev", None, None, "t1");
        table.record_call("b", "readonly", None, Some(2), "t2");
        assert_eq!(table.count(), 2);
    }

    #[test]
    fn denied_increments() {
        let table = ProcessTable::new();
        table.record_denied("a", "dev", None, None);
        table.record_denied("a", "dev", None, None);
        let snap = table.snapshot();
        assert_eq!(snap[0].denied_count, 2);
        assert_eq!(snap[0].call_count, 0);
    }

    #[test]
    fn call_count_accumulates() {
        let table = ProcessTable::new();
        table.record_call("a", "dev", None, None, "t1");
        table.record_call("a", "dev", None, None, "t2");
        table.record_call("a", "dev", None, None, "t3");
        assert_eq!(table.snapshot()[0].call_count, 3);
    }

    #[test]
    fn empty_table() {
        let table = ProcessTable::new();
        assert_eq!(table.count(), 0);
        assert!(table.snapshot().is_empty());
    }

    #[test]
    fn complete_nonexistent_is_noop() {
        let table = ProcessTable::new();
        table.complete_call("ghost", "tool"); // should not panic
    }

    #[test]
    fn record_call_with_obo() {
        let table = ProcessTable::new();
        table.record_call_with_obo("agent-1", "dev", Some("did:key:z6Mk1"), Some(1), "file_read", Some("alice@example.com"));

        let snap = table.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].obo_sub.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn record_call_without_obo() {
        let table = ProcessTable::new();
        table.record_call("agent-1", "dev", None, None, "file_read");

        let snap = table.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(snap[0].obo_sub.is_none());
    }

    #[test]
    fn record_denied_with_obo() {
        let table = ProcessTable::new();
        table.record_denied_with_obo("agent-1", "dev", None, None, Some("bob@corp.com"));

        let snap = table.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].obo_sub.as_deref(), Some("bob@corp.com"));
        assert_eq!(snap[0].denied_count, 1);
    }
}
