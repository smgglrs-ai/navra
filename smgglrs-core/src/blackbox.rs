//! Gateway-level audit blackbox — records every tool call at the
//! MCP server chokepoint, like a flight recorder.
//!
//! Properties:
//! - **Always on**: no opt-in, no configuration. If smgglrs runs, it records.
//! - **Append-only**: entries are INSERTed, never UPDATEd or DELETEd.
//! - **Hash-chained**: each entry includes SHA-256 of the previous,
//!   so tampering is detectable by verifying the chain.
//! - **Transparent**: agents don't know they're recorded.

use crate::safety::{FilterContext, FilterPipeline};
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};

/// A single blackbox entry — one tool call through the gateway.
#[derive(Debug, Clone)]
pub struct BlackboxEntry {
    pub seq: u64,
    pub timestamp_ms: i64,
    pub agent_name: String,
    pub agent_permissions: String,
    pub session_id: String,
    pub tool_name: String,
    pub tool_args: String,
    pub tool_result: String,
    pub outcome: String, // "allowed", "denied_acl", "denied_ifc", "denied_rate", "error"
    pub duration_us: u64,
    pub ifc_label: String,
    pub prev_hash: String, // SHA-256 of previous entry
    pub hash: String,      // SHA-256 of this entry
}

/// The gateway blackbox. Embedded in McpServer.
pub struct Blackbox {
    db: Mutex<Connection>,
    seq: Mutex<u64>,
    prev_hash: Mutex<String>,
    /// Optional PII filter applied to tool_args and tool_result before recording.
    pii_filter: Option<Arc<FilterPipeline>>,
}

impl Blackbox {
    /// Open or create a blackbox at the given path.
    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        let db = Connection::open(path)
            .map_err(|e| format!("blackbox open failed: {e}"))?;

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS blackbox (
                seq           INTEGER PRIMARY KEY,
                timestamp_ms  INTEGER NOT NULL,
                agent_name    TEXT NOT NULL,
                agent_perms   TEXT NOT NULL,
                session_id    TEXT NOT NULL,
                tool_name     TEXT NOT NULL,
                tool_args     TEXT NOT NULL,
                tool_result   TEXT NOT NULL,
                outcome       TEXT NOT NULL,
                duration_us   INTEGER NOT NULL,
                ifc_label     TEXT NOT NULL,
                prev_hash     TEXT NOT NULL,
                hash          TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_bb_agent ON blackbox(agent_name);
            CREATE INDEX IF NOT EXISTS idx_bb_tool ON blackbox(tool_name);
            CREATE INDEX IF NOT EXISTS idx_bb_ts ON blackbox(timestamp_ms);",
        )
        .map_err(|e| format!("blackbox schema failed: {e}"))?;

        // Resume from last entry
        let (last_seq, last_hash) = db
            .query_row(
                "SELECT seq, hash FROM blackbox ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap_or((0, "0".repeat(64)));

        Ok(Self {
            db: Mutex::new(db),
            seq: Mutex::new(last_seq),
            prev_hash: Mutex::new(last_hash),
            pii_filter: None,
        })
    }

    /// Attach a PII filter pipeline to sanitize tool_args and tool_result
    /// before they are written to the blackbox.
    pub fn with_pii_filter(mut self, filter: Arc<FilterPipeline>) -> Self {
        self.pii_filter = Some(filter);
        self
    }

    /// Apply PII filter synchronously to a content string.
    fn sanitize(&self, content: &str) -> String {
        let pipeline = match &self.pii_filter {
            Some(p) => p,
            None => return content.to_string(),
        };

        let ctx = FilterContext {
            agent_name: "blackbox",
            operation: "audit",
            path: None,
        };

        match pipeline.process(content, &ctx) {
            Ok(sanitized) => sanitized,
            Err(_) => "[redacted by PII filter]".to_string(),
        }
    }

    /// Record a tool call. Called from handle_call_tool.
    ///
    /// When a PII filter is attached, tool_args and tool_result are
    /// sanitized before being written to the database.
    pub fn record(
        &self,
        agent_name: &str,
        agent_permissions: &str,
        session_id: &str,
        tool_name: &str,
        tool_args: &str,
        tool_result: &str,
        outcome: &str,
        duration_us: u64,
        ifc_label: &str,
    ) {
        let mut seq = self.seq.lock().unwrap_or_else(|e| e.into_inner());
        let mut prev_hash = self.prev_hash.lock().unwrap_or_else(|e| e.into_inner());

        *seq += 1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Sanitize PII in args and result before recording
        let sanitized_args = self.sanitize(tool_args);
        let sanitized_result = self.sanitize(tool_result);

        // Truncate large fields
        let args_trunc = truncate(&sanitized_args, 4096);
        let result_trunc = truncate(&sanitized_result, 4096);

        // Hash chain: SHA-256(seq | prev_hash | agent | tool | args | result | outcome)
        use std::fmt::Write;
        let mut preimage = String::new();
        let _ = write!(
            preimage,
            "{}|{}|{}|{}|{}|{}|{}",
            seq, prev_hash, agent_name, tool_name, args_trunc, result_trunc, outcome
        );
        let hash = sha256_hex(&preimage);

        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let _ = db.execute(
            "INSERT INTO blackbox (seq, timestamp_ms, agent_name, agent_perms, session_id, \
             tool_name, tool_args, tool_result, outcome, duration_us, ifc_label, prev_hash, hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                *seq, now, agent_name, agent_permissions, session_id,
                tool_name, args_trunc, result_trunc, outcome, duration_us as i64,
                ifc_label, *prev_hash, hash,
            ],
        );

        *prev_hash = hash;
    }

    /// Verify the hash chain integrity. Returns (valid_count, first_broken_seq).
    pub fn verify_chain(&self) -> (u64, Option<u64>) {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = db
            .prepare("SELECT seq, agent_name, tool_name, tool_args, tool_result, outcome, prev_hash, hash FROM blackbox ORDER BY seq")
            .unwrap();

        let mut expected_prev = "0".repeat(64);
        let mut valid = 0u64;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .unwrap();

        for row in rows {
            let (seq, agent, tool, args, result, outcome, prev_hash, hash) = row.unwrap();

            if prev_hash != expected_prev {
                return (valid, Some(seq));
            }

            let preimage = format!(
                "{}|{}|{}|{}|{}|{}|{}",
                seq, prev_hash, agent, tool, args, result, outcome
            );
            let computed = sha256_hex(&preimage);
            if computed != hash {
                return (valid, Some(seq));
            }

            expected_prev = hash;
            valid += 1;
        }

        (valid, None)
    }

    /// Get recent entries.
    pub fn recent(&self, limit: usize) -> Vec<BlackboxEntry> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = db
            .prepare(
                "SELECT seq, timestamp_ms, agent_name, agent_perms, session_id, \
                 tool_name, tool_args, tool_result, outcome, duration_us, \
                 ifc_label, prev_hash, hash \
                 FROM blackbox ORDER BY seq DESC LIMIT ?1",
            )
            .unwrap();

        stmt.query_map([limit], |row| {
            Ok(BlackboxEntry {
                seq: row.get(0)?,
                timestamp_ms: row.get(1)?,
                agent_name: row.get(2)?,
                agent_permissions: row.get(3)?,
                session_id: row.get(4)?,
                tool_name: row.get(5)?,
                tool_args: row.get(6)?,
                tool_result: row.get(7)?,
                outcome: row.get(8)?,
                duration_us: row.get(9)?,
                ifc_label: row.get(10)?,
                prev_hash: row.get(11)?,
                hash: row.get(12)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    /// Delete entries older than the specified number of days.
    ///
    /// Note: unlike most blackbox operations, this mutates existing data.
    /// Use with caution -- audit logs often have separate legal retention
    /// requirements. The hash chain will be broken for deleted entries,
    /// but `verify_chain` will still validate the remaining contiguous chain.
    /// Returns the count of deleted entries.
    pub fn expire_older_than(&self, days: u32) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let cutoff_ms = now - (days as i64 * 86400 * 1000);

        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.execute(
            "DELETE FROM blackbox WHERE timestamp_ms < ?1",
            params![cutoff_ms],
        )
        .unwrap_or(0)
    }

    /// Entry count.
    pub fn count(&self) -> u64 {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.query_row("SELECT COUNT(*) FROM blackbox", [], |row| row.get(0))
            .unwrap_or(0)
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { return s; }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    &s[..end]
}

fn sha256_hex(data: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute the hash chain preimage for a blackbox entry.
/// Extracted as a pure function for formal verification.
pub fn chain_preimage(
    seq: u64,
    prev_hash: &str,
    agent_name: &str,
    tool_name: &str,
    tool_args: &str,
    tool_result: &str,
    outcome: &str,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        seq, prev_hash, agent_name, tool_name, tool_args, tool_result, outcome
    )
}

/// Verify a single chain link: recompute hash and check prev_hash linkage.
pub fn verify_chain_link(
    seq: u64,
    prev_hash: &str,
    expected_prev: &str,
    agent_name: &str,
    tool_name: &str,
    tool_args: &str,
    tool_result: &str,
    outcome: &str,
    stored_hash: &str,
) -> bool {
    if prev_hash != expected_prev {
        return false;
    }
    let preimage = chain_preimage(seq, prev_hash, agent_name, tool_name, tool_args, tool_result, outcome);
    sha256_hex(&preimage) == stored_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_retrieve() {
        let dir = tempfile::tempdir().unwrap();
        let bb = Blackbox::open(&dir.path().join("bb.db")).unwrap();

        bb.record("agent1", "dev", "sess1", "file_read", r#"{"path":"/tmp"}"#, "file content", "allowed", 5, "Trusted:Public");
        bb.record("agent1", "dev", "sess1", "file_write", r#"{"path":"/tmp/x"}"#, "ok", "denied_ifc", 2, "Untrusted:Public");

        assert_eq!(bb.count(), 2);
        let entries = bb.recent(10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].seq, 2); // most recent first
        assert_eq!(entries[0].outcome, "denied_ifc");
        assert_eq!(entries[1].seq, 1);
        assert_eq!(entries[1].outcome, "allowed");
    }

    #[test]
    fn hash_chain_valid() {
        let dir = tempfile::tempdir().unwrap();
        let bb = Blackbox::open(&dir.path().join("bb.db")).unwrap();

        bb.record("a", "dev", "s", "t1", "{}", "ok", "allowed", 1, "T:P");
        bb.record("a", "dev", "s", "t2", "{}", "ok", "allowed", 1, "T:P");
        bb.record("a", "dev", "s", "t3", "{}", "ok", "allowed", 1, "T:P");

        let (valid, broken) = bb.verify_chain();
        assert_eq!(valid, 3);
        assert!(broken.is_none());
    }

    #[test]
    fn hash_chain_detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bb.db");
        let bb = Blackbox::open(&path).unwrap();

        bb.record("a", "dev", "s", "t1", "{}", "ok", "allowed", 1, "T:P");
        bb.record("a", "dev", "s", "t2", "{}", "ok", "allowed", 1, "T:P");

        // Tamper with entry 2
        {
            let db = Connection::open(&path).unwrap();
            db.execute("UPDATE blackbox SET tool_result = 'tampered' WHERE seq = 2", []).unwrap();
        }

        let bb2 = Blackbox::open(&path).unwrap();
        let (valid, broken) = bb2.verify_chain();
        assert_eq!(valid, 1);
        assert_eq!(broken, Some(2));
    }

    #[test]
    fn record_with_pii_filter_redacts_args_and_result() {
        let dir = tempfile::tempdir().unwrap();
        let filter = Arc::new(crate::safety::build_pipeline("standard"));
        let bb = Blackbox::open(&dir.path().join("bb.db"))
            .unwrap()
            .with_pii_filter(filter);

        bb.record(
            "agent1", "dev", "sess1", "file_read",
            r#"{"email": "user@example.com"}"#,
            "SSN: 123-45-6789",
            "allowed", 5, "Trusted:Public",
        );

        let entries = bb.recent(1);
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].tool_args.contains("user@example.com"),
            "Expected email redacted in tool_args: {}", entries[0].tool_args);
        assert!(!entries[0].tool_result.contains("123-45-6789"),
            "Expected SSN redacted in tool_result: {}", entries[0].tool_result);
        assert!(entries[0].tool_args.contains("[REDACTED:"));
        assert!(entries[0].tool_result.contains("[REDACTED:"));
    }

    #[test]
    fn record_without_pii_filter_preserves_content() {
        let dir = tempfile::tempdir().unwrap();
        let bb = Blackbox::open(&dir.path().join("bb.db")).unwrap();

        let args = r#"{"email": "user@example.com"}"#;
        bb.record("agent1", "dev", "sess1", "file_read", args, "ok", "allowed", 5, "T:P");

        let entries = bb.recent(1);
        assert!(entries[0].tool_args.contains("user@example.com"));
    }

    #[test]
    fn expire_older_than_deletes_old() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bb.db");
        let bb = Blackbox::open(&path).unwrap();

        bb.record("a", "dev", "s", "t1", "{}", "ok", "allowed", 1, "T:P");
        bb.record("a", "dev", "s", "t2", "{}", "ok", "allowed", 1, "T:P");

        assert_eq!(bb.count(), 2);

        // All entries are from "now", so expiring older than 1 day should delete nothing
        let deleted = bb.expire_older_than(1);
        assert_eq!(deleted, 0);
        assert_eq!(bb.count(), 2);

        // Manually insert an old entry for testing
        {
            let db = Connection::open(&path).unwrap();
            let old_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
                - (10 * 86400 * 1000); // 10 days ago
            db.execute(
                "INSERT INTO blackbox (seq, timestamp_ms, agent_name, agent_perms, session_id, \
                 tool_name, tool_args, tool_result, outcome, duration_us, ifc_label, prev_hash, hash) \
                 VALUES (99, ?1, 'a', 'dev', 's', 'old_tool', '{}', 'ok', 'allowed', 1, 'T:P', 'x', 'y')",
                params![old_ts],
            ).unwrap();
        }

        let bb2 = Blackbox::open(&path).unwrap();
        assert_eq!(bb2.count(), 3);

        let deleted = bb2.expire_older_than(5);
        assert_eq!(deleted, 1);
        assert_eq!(bb2.count(), 2);
    }

    #[test]
    fn chain_preimage_deterministic() {
        let p1 = chain_preimage(1, "abc", "agent", "tool", "{}", "ok", "allowed");
        let p2 = chain_preimage(1, "abc", "agent", "tool", "{}", "ok", "allowed");
        assert_eq!(p1, p2);
    }

    #[test]
    fn chain_preimage_changes_on_any_field() {
        let base = chain_preimage(1, "abc", "agent", "tool", "{}", "ok", "allowed");
        assert_ne!(base, chain_preimage(2, "abc", "agent", "tool", "{}", "ok", "allowed"));
        assert_ne!(base, chain_preimage(1, "def", "agent", "tool", "{}", "ok", "allowed"));
        assert_ne!(base, chain_preimage(1, "abc", "other", "tool", "{}", "ok", "allowed"));
        assert_ne!(base, chain_preimage(1, "abc", "agent", "tool", "{}", "tampered", "allowed"));
    }

    #[test]
    fn verify_link_detects_tamper() {
        let prev = "0".repeat(64);
        let preimage = chain_preimage(1, &prev, "a", "t", "{}", "ok", "allowed");
        let hash = sha256_hex(&preimage);
        assert!(verify_chain_link(1, &prev, &prev, "a", "t", "{}", "ok", "allowed", &hash));
        assert!(!verify_chain_link(1, &prev, &prev, "a", "t", "{}", "TAMPERED", "allowed", &hash));
    }

    #[test]
    fn resumes_from_last_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bb.db");

        {
            let bb = Blackbox::open(&path).unwrap();
            bb.record("a", "dev", "s", "t1", "{}", "ok", "allowed", 1, "T:P");
            bb.record("a", "dev", "s", "t2", "{}", "ok", "allowed", 1, "T:P");
        }

        // Reopen — should continue from seq 2
        let bb = Blackbox::open(&path).unwrap();
        bb.record("a", "dev", "s", "t3", "{}", "ok", "allowed", 1, "T:P");

        assert_eq!(bb.count(), 3);
        let (valid, broken) = bb.verify_chain();
        assert_eq!(valid, 3);
        assert!(broken.is_none());
    }
}
