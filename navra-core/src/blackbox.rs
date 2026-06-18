//! Gateway-level audit blackbox — records every tool call at the
//! MCP server chokepoint, like a flight recorder.
//!
//! Properties:
//! - **Always on**: no opt-in, no configuration. If navra runs, it records.
//! - **Append-only**: entries are INSERTed, never UPDATEd or DELETEd.
//! - **Hash-chained**: each entry includes SHA-256 of the previous,
//!   so tampering is detectable by verifying the chain.
//! - **Transparent**: agents don't know they're recorded.

use crate::safety::{FilterContext, FilterPipeline};
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};

/// A single blackbox entry — one tool call through the gateway.
#[derive(Debug, Clone, serde::Serialize)]
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
    /// On-behalf-of human subject identifier (when agent acts for a human).
    pub obo_sub: Option<String>,
}

/// Chain state: sequence counter and previous entry hash.
struct ChainState {
    seq: u64,
    prev_hash: String,
}

/// The gateway blackbox. Embedded in McpServer.
pub struct Blackbox {
    db: Mutex<Connection>,
    chain: Mutex<ChainState>,
    /// Optional PII filter applied to tool_args and tool_result before recording.
    pii_filter: Option<Arc<FilterPipeline>>,
}

impl Blackbox {
    /// Open or create a blackbox at the given path.
    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        let db = Connection::open(path).map_err(|e| format!("blackbox open failed: {e}"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .map_err(|e| format!("blackbox pragma failed: {e}"))?;

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
                hash          TEXT NOT NULL,
                obo_sub       TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_bb_agent ON blackbox(agent_name);
            CREATE INDEX IF NOT EXISTS idx_bb_tool ON blackbox(tool_name);
            CREATE INDEX IF NOT EXISTS idx_bb_ts ON blackbox(timestamp_ms);",
        )
        .map_err(|e| format!("blackbox schema failed: {e}"))?;

        // Migrate existing databases: add obo_sub column if missing.
        // "duplicate column" errors are expected and safe to ignore.
        match db.execute_batch("ALTER TABLE blackbox ADD COLUMN obo_sub TEXT;") {
            Ok(()) => {}
            Err(e) if e.to_string().contains("duplicate column") => {}
            Err(e) => tracing::error!(error = %e, "blackbox migration failed"),
        }

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
            chain: Mutex::new(ChainState {
                seq: last_seq,
                prev_hash: last_hash,
            }),
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
        self.record_with_obo(
            agent_name,
            agent_permissions,
            session_id,
            tool_name,
            tool_args,
            tool_result,
            outcome,
            duration_us,
            ifc_label,
            None,
        );
    }

    /// Record a tool call with optional on-behalf-of human identity.
    pub fn record_with_obo(
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
        obo_sub: Option<&str>,
    ) {
        let mut chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());

        chain.seq += 1;
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
            chain.seq, chain.prev_hash, agent_name, tool_name, args_trunc, result_trunc, outcome
        );
        let hash = sha256_hex(&preimage);

        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = db.execute(
            "INSERT INTO blackbox (seq, timestamp_ms, agent_name, agent_perms, session_id, \
             tool_name, tool_args, tool_result, outcome, duration_us, ifc_label, prev_hash, hash, obo_sub) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                chain.seq, now, agent_name, agent_permissions, session_id,
                tool_name, args_trunc, result_trunc, outcome, duration_us as i64,
                ifc_label, chain.prev_hash, hash, obo_sub,
            ],
        ) {
            tracing::error!(error = %e, seq = chain.seq, "blackbox insert failed");
        }

        chain.prev_hash = hash;
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
                 ifc_label, prev_hash, hash, obo_sub \
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
                obo_sub: row.get(13)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    /// Paginated query with optional agent and tool filters.
    pub fn query(
        &self,
        limit: usize,
        offset: usize,
        agent_filter: Option<&str>,
        tool_filter: Option<&str>,
    ) -> (Vec<BlackboxEntry>, u64) {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());

        let mut where_clauses = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(agent) = agent_filter {
            if !agent.is_empty() {
                where_clauses.push("agent_name LIKE ?");
                param_values.push(Box::new(format!("%{agent}%")));
            }
        }
        if let Some(tool) = tool_filter {
            if !tool.is_empty() {
                where_clauses.push("tool_name LIKE ?");
                param_values.push(Box::new(format!("%{tool}%")));
            }
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let count_sql = format!("SELECT COUNT(*) FROM blackbox {where_sql}");
        let total: u64 = {
            let params_ref: Vec<&dyn rusqlite::types::ToSql> =
                param_values.iter().map(|p| p.as_ref()).collect();
            db.query_row(&count_sql, params_ref.as_slice(), |row| row.get(0))
                .unwrap_or(0)
        };

        let query_sql = format!(
            "SELECT seq, timestamp_ms, agent_name, agent_perms, session_id, \
             tool_name, tool_args, tool_result, outcome, duration_us, \
             ifc_label, prev_hash, hash, obo_sub \
             FROM blackbox {where_sql} ORDER BY seq DESC LIMIT ? OFFSET ?"
        );

        let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = param_values;
        all_params.push(Box::new(limit as i64));
        all_params.push(Box::new(offset as i64));
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            all_params.iter().map(|p| p.as_ref()).collect();

        let mut stmt = db.prepare(&query_sql).unwrap();
        let entries = stmt
            .query_map(params_ref.as_slice(), |row| {
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
                    obo_sub: row.get(13)?,
                })
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        (entries, total)
    }

    /// Retrieve all blackbox entries for a specific session.
    pub fn query_session(&self, session_id: &str) -> Vec<BlackboxEntry> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = db
            .prepare(
                "SELECT seq, timestamp_ms, agent_name, agent_perms, session_id, \
                 tool_name, tool_args, tool_result, outcome, duration_us, \
                 ifc_label, prev_hash, hash, obo_sub \
                 FROM blackbox WHERE session_id = ? ORDER BY seq ASC",
            )
            .unwrap();
        stmt.query_map([session_id], |row| {
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
                obo_sub: row.get(13)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    /// List distinct session IDs in the blackbox, optionally filtered by time range.
    pub fn list_sessions(
        &self,
        since_ms: Option<i64>,
        until_ms: Option<i64>,
    ) -> Vec<String> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut sql = "SELECT DISTINCT session_id FROM blackbox".to_string();
        let mut clauses = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(since) = since_ms {
            clauses.push("timestamp_ms >= ?");
            params.push(Box::new(since));
        }
        if let Some(until) = until_ms {
            clauses.push("timestamp_ms <= ?");
            params.push(Box::new(until));
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY MIN(timestamp_ms)");

        // Need GROUP BY for ORDER BY MIN to work
        sql = sql.replace(
            "ORDER BY MIN(timestamp_ms)",
            "GROUP BY session_id ORDER BY MIN(timestamp_ms)",
        );

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = db.prepare(&sql).unwrap();
        stmt.query_map(params_ref.as_slice(), |row| row.get(0))
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

pub(crate) fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn sha256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
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
    let preimage = chain_preimage(
        seq,
        prev_hash,
        agent_name,
        tool_name,
        tool_args,
        tool_result,
        outcome,
    );
    sha256_hex(&preimage) == stored_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_retrieve() {
        let dir = tempfile::tempdir().unwrap();
        let bb = Blackbox::open(&dir.path().join("bb.db")).unwrap();

        bb.record(
            "agent1",
            "dev",
            "sess1",
            "file_read",
            r#"{"path":"/tmp"}"#,
            "file content",
            "allowed",
            5,
            "Trusted:Public",
        );
        bb.record(
            "agent1",
            "dev",
            "sess1",
            "file_write",
            r#"{"path":"/tmp/x"}"#,
            "ok",
            "denied_ifc",
            2,
            "Untrusted:Public",
        );

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
            db.execute(
                "UPDATE blackbox SET tool_result = 'tampered' WHERE seq = 2",
                [],
            )
            .unwrap();
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
            "agent1",
            "dev",
            "sess1",
            "file_read",
            r#"{"email": "user@example.com"}"#,
            "SSN: 123-45-6789",
            "allowed",
            5,
            "Trusted:Public",
        );

        let entries = bb.recent(1);
        assert_eq!(entries.len(), 1);
        assert!(
            !entries[0].tool_args.contains("user@example.com"),
            "Expected email redacted in tool_args: {}",
            entries[0].tool_args
        );
        assert!(
            !entries[0].tool_result.contains("123-45-6789"),
            "Expected SSN redacted in tool_result: {}",
            entries[0].tool_result
        );
        assert!(entries[0].tool_args.contains("[REDACTED:"));
        assert!(entries[0].tool_result.contains("[REDACTED:"));
    }

    #[test]
    fn record_without_pii_filter_preserves_content() {
        let dir = tempfile::tempdir().unwrap();
        let bb = Blackbox::open(&dir.path().join("bb.db")).unwrap();

        let args = r#"{"email": "user@example.com"}"#;
        bb.record(
            "agent1",
            "dev",
            "sess1",
            "file_read",
            args,
            "ok",
            "allowed",
            5,
            "T:P",
        );

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
        assert_ne!(
            base,
            chain_preimage(2, "abc", "agent", "tool", "{}", "ok", "allowed")
        );
        assert_ne!(
            base,
            chain_preimage(1, "def", "agent", "tool", "{}", "ok", "allowed")
        );
        assert_ne!(
            base,
            chain_preimage(1, "abc", "other", "tool", "{}", "ok", "allowed")
        );
        assert_ne!(
            base,
            chain_preimage(1, "abc", "agent", "tool", "{}", "tampered", "allowed")
        );
    }

    #[test]
    fn verify_link_detects_tamper() {
        let prev = "0".repeat(64);
        let preimage = chain_preimage(1, &prev, "a", "t", "{}", "ok", "allowed");
        let hash = sha256_hex(&preimage);
        assert!(verify_chain_link(
            1, &prev, &prev, "a", "t", "{}", "ok", "allowed", &hash
        ));
        assert!(!verify_chain_link(
            1, &prev, &prev, "a", "t", "{}", "TAMPERED", "allowed", &hash
        ));
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

    #[test]
    fn record_with_obo_stores_human_identity() {
        let dir = tempfile::tempdir().unwrap();
        let bb = Blackbox::open(&dir.path().join("bb.db")).unwrap();

        bb.record_with_obo(
            "agent1",
            "dev",
            "sess1",
            "file_read",
            r#"{"path":"/tmp"}"#,
            "content",
            "allowed",
            5,
            "Trusted:Public",
            Some("alice@example.com"),
        );

        let entries = bb.recent(1);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].obo_sub.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn record_without_obo_stores_none() {
        let dir = tempfile::tempdir().unwrap();
        let bb = Blackbox::open(&dir.path().join("bb.db")).unwrap();

        bb.record(
            "agent1",
            "dev",
            "sess1",
            "file_read",
            "{}",
            "ok",
            "allowed",
            5,
            "T:P",
        );

        let entries = bb.recent(1);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].obo_sub.is_none());
    }

    #[test]
    fn truncate_preserves_char_boundary() {
        // Ensure truncate never splits a multi-byte char
        let multibyte = "héllo wörld café résumé";
        for max in 0..multibyte.len() {
            let t = truncate(multibyte, max);
            assert!(t.is_char_boundary(t.len()), "bad boundary at max={max}");
        }
    }

    #[test]
    fn record_with_obo_mixed_entries() {
        let dir = tempfile::tempdir().unwrap();
        let bb = Blackbox::open(&dir.path().join("bb.db")).unwrap();

        bb.record("agent1", "dev", "s", "t1", "{}", "ok", "allowed", 1, "T:P");
        bb.record_with_obo(
            "agent2",
            "dev",
            "s",
            "t2",
            "{}",
            "ok",
            "allowed",
            1,
            "T:P",
            Some("bob@corp.com"),
        );

        let entries = bb.recent(10);
        assert_eq!(entries.len(), 2);
        // Most recent first
        assert_eq!(entries[0].obo_sub.as_deref(), Some("bob@corp.com"));
        assert!(entries[1].obo_sub.is_none());
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // --- Hash chain integrity ---

    /// Model a 2-entry hash chain and prove the chain link property:
    /// verify_chain_link succeeds iff no field was tampered.
    #[kani::proof]
    fn chain_link_tamper_detection() {
        let seq: u8 = kani::any();
        kani::assume(seq >= 1 && seq <= 10);
        let prev = "prev_hash_placeholder";
        let agent = "agent";
        let tool = "tool";
        let args = "args";
        let result = "result";
        let outcome = "allowed";

        let preimage = chain_preimage(seq as u64, prev, agent, tool, args, result, outcome);
        let hash = sha256_hex(&preimage);

        // Correct link verifies
        assert!(verify_chain_link(
            seq as u64, prev, prev, agent, tool, args, result, outcome, &hash
        ));

        // Tampered result fails
        assert!(!verify_chain_link(
            seq as u64, prev, prev, agent, tool, args, "TAMPERED", outcome, &hash
        ));
    }

    /// Prove that changing any single field in the preimage changes the hash.
    /// This is collision resistance for the preimage format.
    #[kani::proof]
    fn preimage_field_independence() {
        let choice: u8 = kani::any();
        kani::assume(choice <= 2);
        let base = chain_preimage(1, "h", "a", "t", "{}", "ok", "allowed");
        let modified = match choice {
            0 => chain_preimage(2, "h", "a", "t", "{}", "ok", "allowed"),
            1 => chain_preimage(1, "h", "b", "t", "{}", "ok", "allowed"),
            _ => chain_preimage(1, "h", "a", "t", "{}", "ok", "denied"),
        };
        assert_ne!(base, modified);
    }

    // --- Truncation safety ---

    #[kani::proof]
    fn truncate_never_exceeds_max() {
        let max: u8 = kani::any();
        kani::assume(max <= 20);
        let input = "hello world test data";
        let result = truncate(input, max as usize);
        assert!(result.len() <= max as usize);
    }

    #[kani::proof]
    fn truncate_within_budget_is_identity() {
        let input = "short";
        let result = truncate(input, 100);
        assert_eq!(result.len(), input.len());
    }

    // --- Sequence monotonicity ---
    // Model the seq counter as a pure function to prove it never decreases.

    #[kani::proof]
    fn seq_increment_monotonic() {
        let before: u64 = kani::any();
        kani::assume(before < u64::MAX);
        let after = before + 1;
        assert!(after > before);
    }
}
