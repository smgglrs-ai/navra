//! Gateway-level audit blackbox — records every tool call at the
//! MCP server chokepoint, like a flight recorder.
//!
//! Properties:
//! - **Always on**: no opt-in, no configuration. If smgglrs runs, it records.
//! - **Append-only**: entries are INSERTed, never UPDATEd or DELETEd.
//! - **Hash-chained**: each entry includes SHA-256 of the previous,
//!   so tampering is detectable by verifying the chain.
//! - **Transparent**: agents don't know they're recorded.

use rusqlite::{params, Connection};
use std::sync::Mutex;

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
        })
    }

    /// Record a tool call. Called from handle_call_tool.
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

        // Truncate large fields
        let args_trunc = truncate(tool_args, 4096);
        let result_trunc = truncate(tool_result, 4096);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_retrieve() {
        let dir = tempfile::tempdir().unwrap();
        let bb = Blackbox::open(&dir.path().join("bb.db")).unwrap();

        bb.record("agent1", "dev", "sess1", "docs_read", r#"{"path":"/tmp"}"#, "file content", "allowed", 5, "Trusted:Public");
        bb.record("agent1", "dev", "sess1", "docs_write", r#"{"path":"/tmp/x"}"#, "ok", "denied_ifc", 2, "Untrusted:Public");

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
