//! Structured audit log for agent runs, tool calls, and model calls.

use crate::error::MemoryError;
use crate::pipeline::ContentSanitizer;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

/// A tool call entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditToolCall {
    pub run_id: String,
    pub agent_id: String,
    pub iteration: u32,
    pub timestamp_ms: i64,
    pub tool_name: String,
    pub tool_args: String,
    pub tool_result: String,
    pub duration_ms: u64,
    pub acl_decision: Option<String>,
    pub ifc_label: Option<String>,
}

/// A model call entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditModelCall {
    pub run_id: String,
    pub agent_id: String,
    pub iteration: u32,
    pub timestamp_ms: i64,
    pub model_name: Option<String>,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub response_type: String,
    pub reasoning_text: Option<String>,
}

/// A run entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRun {
    pub run_id: String,
    pub agent_id: String,
    pub prompt: String,
    pub persona: Option<String>,
    pub model: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub teammates: Vec<String>,
    pub final_report: Option<String>,
    pub exit_reason: Option<String>,
}

/// Summary statistics for an audit run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub run_id: String,
    pub tool_call_count: u32,
    pub model_call_count: u32,
    pub top_tools: Vec<(String, u32)>,
    pub duration_ms: Option<i64>,
}

/// Structured audit log backed by SQLite.
pub struct AuditLog {
    db: Mutex<Connection>,
    /// Optional PII sanitizer applied to tool_args and tool_result before recording.
    sanitizer: Option<ContentSanitizer>,
}

impl AuditLog {
    /// Open audit log from a file path.
    pub fn open(path: &Path) -> Result<Self, MemoryError> {
        let db = Connection::open(path)?;
        let log = Self {
            db: Mutex::new(db),
            sanitizer: None,
        };
        log.init_schema()?;
        Ok(log)
    }

    /// Open in-memory audit log (for testing).
    pub fn open_memory() -> Result<Self, MemoryError> {
        let db = Connection::open_in_memory()?;
        let log = Self {
            db: Mutex::new(db),
            sanitizer: None,
        };
        log.init_schema()?;
        Ok(log)
    }

    /// Attach a PII sanitizer to filter tool_args and tool_result
    /// before they are written to the audit log.
    pub fn with_sanitizer(mut self, sanitizer: ContentSanitizer) -> Self {
        self.sanitizer = Some(sanitizer);
        self
    }

    /// Apply the sanitizer to a string, if configured.
    fn sanitize(&self, content: &str) -> String {
        match &self.sanitizer {
            Some(f) => f(content),
            None => content.to_string(),
        }
    }

    fn init_schema(&self) -> Result<(), MemoryError> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_runs (
                run_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                prompt TEXT NOT NULL,
                persona TEXT,
                model TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                teammates TEXT NOT NULL,
                final_report TEXT,
                exit_reason TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_runs_agent
                ON audit_runs(agent_id);

            CREATE TABLE IF NOT EXISTS audit_tool_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                iteration INTEGER NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                tool_name TEXT NOT NULL,
                tool_args TEXT NOT NULL,
                tool_result TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                acl_decision TEXT,
                ifc_label TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_tool_calls_run
                ON audit_tool_calls(run_id, iteration);

            CREATE TABLE IF NOT EXISTS audit_model_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                iteration INTEGER NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                model_name TEXT,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                response_type TEXT NOT NULL,
                reasoning_text TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_model_calls_run
                ON audit_model_calls(run_id, iteration);",
        )?;
        Ok(())
    }

    /// Insert a new run into the audit log.
    pub fn begin_run(&self, run: &AuditRun) -> Result<(), MemoryError> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let teammates_json = serde_json::to_string(&run.teammates)
            .unwrap_or_else(|_| "[]".to_string());
        db.execute(
            "INSERT INTO audit_runs (run_id, agent_id, prompt, persona, model, started_at, ended_at, teammates, final_report, exit_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                run.run_id,
                run.agent_id,
                run.prompt,
                run.persona,
                run.model,
                run.started_at,
                run.ended_at,
                teammates_json,
                run.final_report,
                run.exit_reason,
            ],
        )?;
        Ok(())
    }

    /// Log a tool call.
    ///
    /// When a PII sanitizer is attached, tool_args and tool_result are
    /// filtered before being written to the database.
    pub fn log_tool_call(&self, entry: &AuditToolCall) -> Result<(), MemoryError> {
        let sanitized_args = self.sanitize(&entry.tool_args);
        let sanitized_result = self.sanitize(&entry.tool_result);

        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.execute(
            "INSERT INTO audit_tool_calls (run_id, agent_id, iteration, timestamp_ms, tool_name, tool_args, tool_result, duration_ms, acl_decision, ifc_label)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                entry.run_id,
                entry.agent_id,
                entry.iteration,
                entry.timestamp_ms,
                entry.tool_name,
                sanitized_args,
                sanitized_result,
                entry.duration_ms as i64,
                entry.acl_decision,
                entry.ifc_label,
            ],
        )?;
        Ok(())
    }

    /// Log a model call.
    pub fn log_model_call(&self, entry: &AuditModelCall) -> Result<(), MemoryError> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.execute(
            "INSERT INTO audit_model_calls (run_id, agent_id, iteration, timestamp_ms, model_name, input_tokens, output_tokens, response_type, reasoning_text)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.run_id,
                entry.agent_id,
                entry.iteration,
                entry.timestamp_ms,
                entry.model_name,
                entry.input_tokens,
                entry.output_tokens,
                entry.response_type,
                entry.reasoning_text,
            ],
        )?;
        Ok(())
    }

    /// Update a run with end time, final report, and exit reason.
    pub fn end_run(
        &self,
        run_id: &str,
        ended_at: i64,
        final_report: Option<&str>,
        exit_reason: Option<&str>,
    ) -> Result<(), MemoryError> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let rows = db.execute(
            "UPDATE audit_runs SET ended_at = ?1, final_report = ?2, exit_reason = ?3
             WHERE run_id = ?4",
            params![ended_at, final_report, exit_reason, run_id],
        )?;
        if rows == 0 {
            return Err(MemoryError::NotFound(run_id.to_string()));
        }
        Ok(())
    }

    /// Get a run by ID.
    pub fn get_run(&self, run_id: &str) -> Result<AuditRun, MemoryError> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let run = db.query_row(
            "SELECT run_id, agent_id, prompt, persona, model, started_at, ended_at, teammates, final_report, exit_reason
             FROM audit_runs WHERE run_id = ?1",
            params![run_id],
            |row| {
                let teammates_json: String = row.get(7)?;
                let teammates: Vec<String> = serde_json::from_str(&teammates_json)
                    .unwrap_or_default();
                Ok(AuditRun {
                    run_id: row.get(0)?,
                    agent_id: row.get(1)?,
                    prompt: row.get(2)?,
                    persona: row.get(3)?,
                    model: row.get(4)?,
                    started_at: row.get(5)?,
                    ended_at: row.get(6)?,
                    teammates,
                    final_report: row.get(8)?,
                    exit_reason: row.get(9)?,
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => MemoryError::NotFound(run_id.to_string()),
            other => MemoryError::Sqlite(other),
        })?;
        Ok(run)
    }

    /// Get all tool calls for a run, ordered by iteration.
    pub fn get_tool_calls(&self, run_id: &str) -> Result<Vec<AuditToolCall>, MemoryError> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = db.prepare(
            "SELECT run_id, agent_id, iteration, timestamp_ms, tool_name, tool_args, tool_result, duration_ms, acl_decision, ifc_label
             FROM audit_tool_calls
             WHERE run_id = ?1
             ORDER BY iteration ASC",
        )?;
        let calls = stmt
            .query_map(params![run_id], |row| {
                let duration: i64 = row.get(7)?;
                Ok(AuditToolCall {
                    run_id: row.get(0)?,
                    agent_id: row.get(1)?,
                    iteration: row.get(2)?,
                    timestamp_ms: row.get(3)?,
                    tool_name: row.get(4)?,
                    tool_args: row.get(5)?,
                    tool_result: row.get(6)?,
                    duration_ms: duration as u64,
                    acl_decision: row.get(8)?,
                    ifc_label: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(calls)
    }

    /// Delete audit entries (runs, tool calls, model calls) older than
    /// the specified number of days. Returns the total number of rows deleted.
    pub fn expire_older_than(&self, days: u32) -> Result<usize, MemoryError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let cutoff = now - (days as i64 * 86400);

        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());

        // Delete tool calls for old runs
        let tc = db.execute(
            "DELETE FROM audit_tool_calls WHERE run_id IN
             (SELECT run_id FROM audit_runs WHERE started_at < ?1)",
            params![cutoff],
        )?;

        // Delete model calls for old runs
        let mc = db.execute(
            "DELETE FROM audit_model_calls WHERE run_id IN
             (SELECT run_id FROM audit_runs WHERE started_at < ?1)",
            params![cutoff],
        )?;

        // Delete old runs
        let rc = db.execute(
            "DELETE FROM audit_runs WHERE started_at < ?1",
            params![cutoff],
        )?;

        Ok(tc + mc + rc)
    }

    /// Get summary statistics for a run.
    pub fn get_summary(&self, run_id: &str) -> Result<AuditSummary, MemoryError> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());

        let tool_call_count: i64 = db.query_row(
            "SELECT COUNT(*) FROM audit_tool_calls WHERE run_id = ?1",
            params![run_id],
            |row| row.get(0),
        )?;

        let model_call_count: i64 = db.query_row(
            "SELECT COUNT(*) FROM audit_model_calls WHERE run_id = ?1",
            params![run_id],
            |row| row.get(0),
        )?;

        // Top tools by frequency
        let mut stmt = db.prepare(
            "SELECT tool_name, COUNT(*) as cnt
             FROM audit_tool_calls
             WHERE run_id = ?1
             GROUP BY tool_name
             ORDER BY cnt DESC
             LIMIT 5",
        )?;
        let top_tools: Vec<(String, u32)> = stmt
            .query_map(params![run_id], |row| {
                let name: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((name, count as u32))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Duration from run timestamps
        let duration_ms: Option<i64> = db.query_row(
            "SELECT ended_at - started_at FROM audit_runs WHERE run_id = ?1",
            params![run_id],
            |row| row.get(0),
        ).ok();

        Ok(AuditSummary {
            run_id: run_id.to_string(),
            tool_call_count: tool_call_count as u32,
            model_call_count: model_call_count as u32,
            top_tools,
            duration_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_run(run_id: &str) -> AuditRun {
        AuditRun {
            run_id: run_id.to_string(),
            agent_id: "agent-1".to_string(),
            prompt: "Do something".to_string(),
            persona: Some("developer".to_string()),
            model: "granite-3b".to_string(),
            started_at: 1000,
            ended_at: None,
            teammates: vec!["agent-2".to_string()],
            final_report: None,
            exit_reason: None,
        }
    }

    fn make_tool_call(run_id: &str, iteration: u32, tool: &str) -> AuditToolCall {
        AuditToolCall {
            run_id: run_id.to_string(),
            agent_id: "agent-1".to_string(),
            iteration,
            timestamp_ms: 1000 + iteration as i64 * 100,
            tool_name: tool.to_string(),
            tool_args: r#"{"path": "/tmp"}"#.to_string(),
            tool_result: r#"{"ok": true}"#.to_string(),
            duration_ms: 50,
            acl_decision: Some("allowed".to_string()),
            ifc_label: None,
        }
    }

    fn make_model_call(run_id: &str, iteration: u32) -> AuditModelCall {
        AuditModelCall {
            run_id: run_id.to_string(),
            agent_id: "agent-1".to_string(),
            iteration,
            timestamp_ms: 1000 + iteration as i64 * 100,
            model_name: Some("granite-3b".to_string()),
            input_tokens: 500,
            output_tokens: 200,
            response_type: "tool_calls".to_string(),
            reasoning_text: None,
        }
    }

    #[test]
    fn begin_run_and_end_run_roundtrip() {
        let log = AuditLog::open_memory().unwrap();
        let run = make_run("run-1");
        log.begin_run(&run).unwrap();

        let fetched = log.get_run("run-1").unwrap();
        assert_eq!(fetched.agent_id, "agent-1");
        assert_eq!(fetched.prompt, "Do something");
        assert_eq!(fetched.persona, Some("developer".to_string()));
        assert_eq!(fetched.teammates, vec!["agent-2".to_string()]);
        assert!(fetched.ended_at.is_none());

        log.end_run("run-1", 2000, Some("All done"), Some("completed"))
            .unwrap();

        let fetched = log.get_run("run-1").unwrap();
        assert_eq!(fetched.ended_at, Some(2000));
        assert_eq!(fetched.final_report, Some("All done".to_string()));
        assert_eq!(fetched.exit_reason, Some("completed".to_string()));
    }

    #[test]
    fn log_tool_call_and_get_tool_calls() {
        let log = AuditLog::open_memory().unwrap();
        log.begin_run(&make_run("run-1")).unwrap();

        log.log_tool_call(&make_tool_call("run-1", 1, "file_read")).unwrap();
        log.log_tool_call(&make_tool_call("run-1", 2, "git_status")).unwrap();
        log.log_tool_call(&make_tool_call("run-1", 3, "file_read")).unwrap();

        let calls = log.get_tool_calls("run-1").unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].iteration, 1);
        assert_eq!(calls[0].tool_name, "file_read");
        assert_eq!(calls[1].iteration, 2);
        assert_eq!(calls[1].tool_name, "git_status");
        assert_eq!(calls[2].iteration, 3);
        assert_eq!(calls[2].acl_decision, Some("allowed".to_string()));
    }

    #[test]
    fn log_model_call() {
        let log = AuditLog::open_memory().unwrap();
        log.begin_run(&make_run("run-1")).unwrap();

        log.log_model_call(&make_model_call("run-1", 1)).unwrap();
        log.log_model_call(&make_model_call("run-1", 2)).unwrap();

        // Verify via summary
        let summary = log.get_summary("run-1").unwrap();
        assert_eq!(summary.model_call_count, 2);
    }

    #[test]
    fn log_tool_call_with_sanitizer_redacts_args_and_result() {
        use std::sync::Arc;

        let sanitizer: ContentSanitizer = Arc::new(|content: &str| {
            content.replace("secret-value", "[REDACTED:test]")
        });

        let log = AuditLog::open_memory().unwrap().with_sanitizer(sanitizer);
        log.begin_run(&make_run("run-1")).unwrap();

        let mut call = make_tool_call("run-1", 1, "file_read");
        call.tool_args = r#"{"key": "secret-value"}"#.to_string();
        call.tool_result = "result contains secret-value here".to_string();
        log.log_tool_call(&call).unwrap();

        let calls = log.get_tool_calls("run-1").unwrap();
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].tool_args.contains("secret-value"),
            "Expected args redacted: {}", calls[0].tool_args);
        assert!(!calls[0].tool_result.contains("secret-value"),
            "Expected result redacted: {}", calls[0].tool_result);
        assert!(calls[0].tool_args.contains("[REDACTED:test]"));
        assert!(calls[0].tool_result.contains("[REDACTED:test]"));
    }

    #[test]
    fn log_tool_call_without_sanitizer_preserves_content() {
        let log = AuditLog::open_memory().unwrap();
        log.begin_run(&make_run("run-1")).unwrap();

        let mut call = make_tool_call("run-1", 1, "file_read");
        call.tool_args = r#"{"key": "secret-value"}"#.to_string();
        log.log_tool_call(&call).unwrap();

        let calls = log.get_tool_calls("run-1").unwrap();
        assert!(calls[0].tool_args.contains("secret-value"));
    }

    #[test]
    fn get_summary_returns_correct_counts() {
        let log = AuditLog::open_memory().unwrap();
        log.begin_run(&make_run("run-1")).unwrap();
        log.end_run("run-1", 2000, None, None).unwrap();

        log.log_tool_call(&make_tool_call("run-1", 1, "file_read")).unwrap();
        log.log_tool_call(&make_tool_call("run-1", 2, "file_read")).unwrap();
        log.log_tool_call(&make_tool_call("run-1", 3, "git_status")).unwrap();
        log.log_model_call(&make_model_call("run-1", 1)).unwrap();

        let summary = log.get_summary("run-1").unwrap();
        assert_eq!(summary.run_id, "run-1");
        assert_eq!(summary.tool_call_count, 3);
        assert_eq!(summary.model_call_count, 1);
        assert_eq!(summary.duration_ms, Some(1000));
        assert_eq!(summary.top_tools.len(), 2);
        assert_eq!(summary.top_tools[0], ("file_read".to_string(), 2));
        assert_eq!(summary.top_tools[1], ("git_status".to_string(), 1));
    }

    #[test]
    fn expire_older_than_deletes_old_runs() {
        let log = AuditLog::open_memory().unwrap();

        // Old run (timestamp 100 = way in the past)
        let old_run = AuditRun {
            started_at: 100,
            ..make_run("old-run")
        };
        log.begin_run(&old_run).unwrap();
        log.log_tool_call(&AuditToolCall {
            run_id: "old-run".to_string(),
            timestamp_ms: 100,
            ..make_tool_call("old-run", 1, "file_read")
        }).unwrap();
        log.log_model_call(&AuditModelCall {
            run_id: "old-run".to_string(),
            timestamp_ms: 100,
            ..make_model_call("old-run", 1)
        }).unwrap();

        // Recent run (now)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let recent_run = AuditRun {
            started_at: now,
            ..make_run("recent-run")
        };
        log.begin_run(&recent_run).unwrap();
        log.log_tool_call(&make_tool_call("recent-run", 1, "git_status")).unwrap();

        let deleted = log.expire_older_than(1).unwrap();
        // Should delete old run + tool call + model call = 3
        assert_eq!(deleted, 3);

        // Recent run should still exist
        let summary = log.get_summary("recent-run").unwrap();
        assert_eq!(summary.tool_call_count, 1);
    }
}
