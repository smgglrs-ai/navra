//! Append-only event log for DAG execution audit and replay.
//!
//! Every DAG node transition, tool call, and result is appended to an
//! ordered event log in SQLite. Events are sequence-numbered for
//! connection recovery with backfill.

use crate::error::FlowError;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

type Result<T> = std::result::Result<T, FlowError>;

/// A typed event in the DAG execution log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FlowEvent {
    NodeStarted {
        task_id: String,
        specialist: String,
    },
    NodeCompleted {
        task_id: String,
        output_preview: String,
        prompt_tokens: u32,
        completion_tokens: u32,
    },
    NodeFailed {
        task_id: String,
        error: String,
    },
    NodeSkipped {
        task_id: String,
        reason: String,
    },
    ToolCalled {
        task_id: String,
        tool_name: String,
        args_hash: String,
    },
    ToolResult {
        task_id: String,
        tool_name: String,
        is_error: bool,
        duration_ms: u64,
    },
    BackEdgeActivated {
        from: String,
        to: String,
        iteration: u32,
    },
    FlowCompleted {
        total_prompt_tokens: u32,
        total_completion_tokens: u32,
    },
}

/// A stored event with its sequence number and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub seq: i64,
    pub flow_id: String,
    pub event: FlowEvent,
    pub timestamp_ms: i64,
    pub model_version: Option<String>,
    pub prompt_hash: Option<String>,
}

/// Append-only event log backed by SQLite.
pub struct EventLog {
    db: Mutex<Connection>,
}

impl EventLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Connection::open(path)?;
        db.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;

             CREATE TABLE IF NOT EXISTS flow_events (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 flow_id TEXT NOT NULL,
                 event_json TEXT NOT NULL,
                 timestamp_ms INTEGER NOT NULL,
                 model_version TEXT,
                 prompt_hash TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_flow_events_flow_seq
                 ON flow_events(flow_id, seq);",
        )?;
        Ok(Self { db: Mutex::new(db) })
    }

    pub fn open_memory() -> Result<Self> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS flow_events (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 flow_id TEXT NOT NULL,
                 event_json TEXT NOT NULL,
                 timestamp_ms INTEGER NOT NULL,
                 model_version TEXT,
                 prompt_hash TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_flow_events_flow_seq
                 ON flow_events(flow_id, seq);",
        )?;
        Ok(Self { db: Mutex::new(db) })
    }

    /// Append an event and return its sequence number.
    pub fn append(
        &self,
        flow_id: &str,
        event: &FlowEvent,
        model_version: Option<&str>,
        prompt_hash: Option<&str>,
    ) -> Result<i64> {
        let json = serde_json::to_string(event)?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.execute(
            "INSERT INTO flow_events (flow_id, event_json, timestamp_ms, model_version, prompt_hash)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![flow_id, json, now_ms, model_version, prompt_hash],
        )?;
        Ok(db.last_insert_rowid())
    }

    /// Retrieve events for a flow since a given sequence number (exclusive).
    ///
    /// Used for SSE connection recovery: client sends its last-seen
    /// sequence, server backfills all events since.
    pub fn events_since(&self, flow_id: &str, after_seq: i64) -> Result<Vec<StoredEvent>> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = db.prepare(
            "SELECT seq, flow_id, event_json, timestamp_ms, model_version, prompt_hash
             FROM flow_events
             WHERE flow_id = ?1 AND seq > ?2
             ORDER BY seq",
        )?;

        let events = stmt
            .query_map(params![flow_id, after_seq], |row| {
                let json: String = row.get(2)?;
                let event: FlowEvent = serde_json::from_str(&json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(StoredEvent {
                    seq: row.get(0)?,
                    flow_id: row.get(1)?,
                    event,
                    timestamp_ms: row.get(3)?,
                    model_version: row.get(4)?,
                    prompt_hash: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(events)
    }

    /// Get all events for a flow.
    pub fn all_events(&self, flow_id: &str) -> Result<Vec<StoredEvent>> {
        self.events_since(flow_id, 0)
    }

    /// Get the latest sequence number for a flow.
    pub fn latest_seq(&self, flow_id: &str) -> Result<i64> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let seq: i64 = db.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM flow_events WHERE flow_id = ?1",
            params![flow_id],
            |row| row.get(0),
        )?;
        Ok(seq)
    }

    /// Check for replay divergence: if any event since `after_seq` was
    /// recorded with a different model version than `expected_model`,
    /// return a warning.
    pub fn check_divergence(
        &self,
        flow_id: &str,
        after_seq: i64,
        expected_model: &str,
    ) -> Result<Option<String>> {
        let events = self.events_since(flow_id, after_seq)?;
        for event in &events {
            if let Some(ref model) = event.model_version
                && model != expected_model
            {
                return Ok(Some(format!(
                    "Replay divergence at seq {}: model was '{}', now '{}'",
                    event.seq, model, expected_model
                )));
            }
        }
        Ok(None)
    }

    /// Count events for a flow.
    pub fn event_count(&self, flow_id: &str) -> Result<i64> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM flow_events WHERE flow_id = ?1",
            params![flow_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_retrieve() {
        let log = EventLog::open_memory().unwrap();
        let seq = log
            .append(
                "flow-1",
                &FlowEvent::NodeStarted {
                    task_id: "task-a".into(),
                    specialist: "reviewer".into(),
                },
                Some("granite3.3:8b"),
                None,
            )
            .unwrap();
        assert!(seq > 0);

        let events = log.all_events("flow-1").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, seq);
        assert_eq!(events[0].model_version.as_deref(), Some("granite3.3:8b"));
    }

    #[test]
    fn events_since_filters_correctly() {
        let log = EventLog::open_memory().unwrap();

        let s1 = log
            .append(
                "f",
                &FlowEvent::NodeStarted {
                    task_id: "a".into(),
                    specialist: "dev".into(),
                },
                None,
                None,
            )
            .unwrap();
        let _s2 = log
            .append(
                "f",
                &FlowEvent::NodeCompleted {
                    task_id: "a".into(),
                    output_preview: "ok".into(),
                    prompt_tokens: 100,
                    completion_tokens: 50,
                },
                None,
                None,
            )
            .unwrap();
        let _s3 = log
            .append(
                "f",
                &FlowEvent::NodeStarted {
                    task_id: "b".into(),
                    specialist: "qa".into(),
                },
                None,
                None,
            )
            .unwrap();

        let since = log.events_since("f", s1).unwrap();
        assert_eq!(since.len(), 2);
    }

    #[test]
    fn events_since_empty_flow() {
        let log = EventLog::open_memory().unwrap();
        let events = log.events_since("nonexistent", 0).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn latest_seq_tracks_correctly() {
        let log = EventLog::open_memory().unwrap();
        assert_eq!(log.latest_seq("f").unwrap(), 0);

        log.append(
            "f",
            &FlowEvent::NodeStarted {
                task_id: "a".into(),
                specialist: "dev".into(),
            },
            None,
            None,
        )
        .unwrap();
        assert!(log.latest_seq("f").unwrap() > 0);
    }

    #[test]
    fn divergence_detection() {
        let log = EventLog::open_memory().unwrap();
        log.append(
            "f",
            &FlowEvent::NodeCompleted {
                task_id: "a".into(),
                output_preview: "ok".into(),
                prompt_tokens: 100,
                completion_tokens: 50,
            },
            Some("granite3.3:8b"),
            None,
        )
        .unwrap();

        let warning = log.check_divergence("f", 0, "qwen2.5:7b").unwrap();
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("divergence"));

        let no_warning = log.check_divergence("f", 0, "granite3.3:8b").unwrap();
        assert!(no_warning.is_none());
    }

    #[test]
    fn event_count() {
        let log = EventLog::open_memory().unwrap();
        assert_eq!(log.event_count("f").unwrap(), 0);

        for i in 0..5 {
            log.append(
                "f",
                &FlowEvent::NodeStarted {
                    task_id: format!("t{i}"),
                    specialist: "dev".into(),
                },
                None,
                None,
            )
            .unwrap();
        }
        assert_eq!(log.event_count("f").unwrap(), 5);
    }

    #[test]
    fn multiple_flows_isolated() {
        let log = EventLog::open_memory().unwrap();
        log.append(
            "f1",
            &FlowEvent::NodeStarted {
                task_id: "a".into(),
                specialist: "dev".into(),
            },
            None,
            None,
        )
        .unwrap();
        log.append(
            "f2",
            &FlowEvent::NodeStarted {
                task_id: "b".into(),
                specialist: "qa".into(),
            },
            None,
            None,
        )
        .unwrap();
        log.append(
            "f2",
            &FlowEvent::NodeStarted {
                task_id: "c".into(),
                specialist: "qa".into(),
            },
            None,
            None,
        )
        .unwrap();

        assert_eq!(log.event_count("f1").unwrap(), 1);
        assert_eq!(log.event_count("f2").unwrap(), 2);
    }

    #[test]
    fn serialization_roundtrip() {
        let event = FlowEvent::BackEdgeActivated {
            from: "review".into(),
            to: "fix".into(),
            iteration: 2,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: FlowEvent = serde_json::from_str(&json).unwrap();
        match back {
            FlowEvent::BackEdgeActivated {
                from,
                to,
                iteration,
            } => {
                assert_eq!(from, "review");
                assert_eq!(to, "fix");
                assert_eq!(iteration, 2);
            }
            _ => panic!("wrong variant"),
        }
    }
}
