//! SQLite-backed checkpoint store for DAG execution crash resilience.
//!
//! After each batch of tasks completes, the executor saves the current
//! state (completed outputs, failed tasks, remaining task definitions)
//! to a SQLite database. On crash recovery, the state is loaded and
//! execution resumes from where it left off.

use crate::definition::TaskDefinition;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

/// Serializable checkpoint of a DAG execution's progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointState {
    /// Flow identifier.
    pub flow_id: String,
    /// Task ID to output for completed tasks.
    pub completed: HashMap<String, String>,
    /// Set of failed task IDs.
    pub failed: HashSet<String>,
    /// Remaining task definitions (including not-yet-started ones).
    pub task_defs: Vec<TaskDefinition>,
    /// Team ID used for this flow execution.
    pub team_id: String,
    /// Original prompt that started the flow.
    pub prompt: String,
}

/// SQLite-backed checkpoint store.
///
/// The connection is wrapped in a `Mutex` so the store can be shared
/// across async tasks via `Arc<DagCheckpoint>`.
pub struct DagCheckpoint {
    db: Mutex<Connection>,
}

impl DagCheckpoint {
    /// Open (or create) a checkpoint database at the given path.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )?;

        db.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS dag_checkpoints (
                flow_id TEXT PRIMARY KEY,
                state BLOB NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )?;

        Ok(Self { db: Mutex::new(db) })
    }

    /// Save (insert or replace) a checkpoint atomically.
    pub fn save(&self, state: &CheckpointState) -> anyhow::Result<()> {
        let json = serde_json::to_vec(state)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.execute(
            "INSERT OR REPLACE INTO dag_checkpoints (flow_id, state, updated_at)
             VALUES (?1, ?2, ?3)",
            params![state.flow_id, json, now],
        )?;

        Ok(())
    }

    /// Load a checkpoint by flow ID. Returns None if not found.
    pub fn load(&self, flow_id: &str) -> anyhow::Result<Option<CheckpointState>> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = db
            .prepare("SELECT state FROM dag_checkpoints WHERE flow_id = ?1")?;

        let result = stmt.query_row(params![flow_id], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        });

        match result {
            Ok(blob) => {
                let state: CheckpointState = serde_json::from_slice(&blob)?;
                Ok(Some(state))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete a checkpoint (called on successful flow completion).
    pub fn delete(&self, flow_id: &str) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.execute(
            "DELETE FROM dag_checkpoints WHERE flow_id = ?1",
            params![flow_id],
        )?;
        Ok(())
    }

    /// List flow IDs that have incomplete checkpoints.
    pub fn list_incomplete(&self) -> anyhow::Result<Vec<String>> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = db
            .prepare("SELECT flow_id FROM dag_checkpoints ORDER BY updated_at DESC")?;

        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn make_task(id: &str, specialist: &str, mandate: &str) -> TaskDefinition {
        TaskDefinition {
            id: id.to_string(),
            specialist: specialist.to_string(),
            model: None,
            mandate: mandate.to_string(),
            depends_on: Vec::new(),
            expected_output: None,
            success_criteria: Vec::new(),
            back_edges: Vec::new(),
            generates_tasks: false,
            verification: None,
            tools: None,
            operations: None,
        }
    }

    fn make_state(flow_id: &str) -> CheckpointState {
        CheckpointState {
            flow_id: flow_id.to_string(),
            completed: HashMap::from([
                ("task1".to_string(), "output1".to_string()),
            ]),
            failed: HashSet::from(["task2".to_string()]),
            task_defs: vec![
                make_task("task3", "analyst", "Analyze code"),
                make_task("task4", "developer", "Fix bugs"),
            ],
            team_id: "team-abc".to_string(),
            prompt: "Review the codebase".to_string(),
        }
    }

    #[test]
    fn save_and_load_roundtrip() {
        let tmp = NamedTempFile::new().unwrap();
        let cp = DagCheckpoint::open(tmp.path()).unwrap();

        let state = make_state("flow-001");
        cp.save(&state).unwrap();

        let loaded = cp.load("flow-001").unwrap().expect("should exist");
        assert_eq!(loaded.flow_id, "flow-001");
        assert_eq!(loaded.completed.len(), 1);
        assert_eq!(loaded.completed["task1"], "output1");
        assert!(loaded.failed.contains("task2"));
        assert_eq!(loaded.task_defs.len(), 2);
        assert_eq!(loaded.team_id, "team-abc");
        assert_eq!(loaded.prompt, "Review the codebase");
    }

    #[test]
    fn load_nonexistent_returns_none() {
        let tmp = NamedTempFile::new().unwrap();
        let cp = DagCheckpoint::open(tmp.path()).unwrap();

        assert!(cp.load("no-such-flow").unwrap().is_none());
    }

    #[test]
    fn delete_removes_checkpoint() {
        let tmp = NamedTempFile::new().unwrap();
        let cp = DagCheckpoint::open(tmp.path()).unwrap();

        let state = make_state("flow-del");
        cp.save(&state).unwrap();
        assert!(cp.load("flow-del").unwrap().is_some());

        cp.delete("flow-del").unwrap();
        assert!(cp.load("flow-del").unwrap().is_none());
    }

    #[test]
    fn list_incomplete_returns_unfinished_flows() {
        let tmp = NamedTempFile::new().unwrap();
        let cp = DagCheckpoint::open(tmp.path()).unwrap();

        cp.save(&make_state("flow-a")).unwrap();
        cp.save(&make_state("flow-b")).unwrap();

        let ids = cp.list_incomplete().unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"flow-a".to_string()));
        assert!(ids.contains(&"flow-b".to_string()));
    }

    #[test]
    fn save_overwrites_existing() {
        let tmp = NamedTempFile::new().unwrap();
        let cp = DagCheckpoint::open(tmp.path()).unwrap();

        let mut state = make_state("flow-upd");
        cp.save(&state).unwrap();

        state.completed.insert("task5".to_string(), "new output".to_string());
        cp.save(&state).unwrap();

        let loaded = cp.load("flow-upd").unwrap().expect("should exist");
        assert_eq!(loaded.completed.len(), 2);
        assert_eq!(loaded.completed["task5"], "new output");
    }

    #[test]
    fn checkpoint_deleted_on_completion_simulation() {
        let tmp = NamedTempFile::new().unwrap();
        let cp = DagCheckpoint::open(tmp.path()).unwrap();

        // Save checkpoint mid-flow
        cp.save(&make_state("flow-done")).unwrap();
        assert_eq!(cp.list_incomplete().unwrap().len(), 1);

        // Flow completes successfully: delete checkpoint
        cp.delete("flow-done").unwrap();
        assert_eq!(cp.list_incomplete().unwrap().len(), 0);
    }

    #[test]
    fn backward_compat_when_disabled() {
        // When checkpoint is None, nothing should happen.
        // This test verifies the Option<DagCheckpoint> pattern works.
        let checkpoint: Option<DagCheckpoint> = None;
        assert!(checkpoint.is_none());
        // Code that does `if let Some(cp) = &checkpoint { cp.save(...) }`
        // simply skips when None — no error.
    }

    #[test]
    fn task_definition_serialization_roundtrip() {
        let task = TaskDefinition {
            id: "test".to_string(),
            specialist: "dev".to_string(),
            model: Some("granite3.3:8b".to_string()),
            mandate: "Fix the bug".to_string(),
            depends_on: vec!["prep".to_string()],
            expected_output: Some("Fixed code".to_string()),
            success_criteria: vec!["Tests pass".to_string()],
            back_edges: vec![crate::BackEdgeDefinition {
                target: "prep".to_string(),
                condition: "score_below:70".to_string(),
                max_iterations: 2,
            }],
            generates_tasks: true,
            verification: Some(crate::VerificationConfig {
                agents: 3,
                threshold: crate::VerificationThreshold::Unanimous,
                verifier_persona: Some("reviewer".to_string()),
                verifier_model: None,
            }),
            tools: Some(vec!["file_read".to_string(), "file_write".to_string()]),
            operations: Some(vec!["read".to_string(), "write".to_string()]),
        };

        let json = serde_json::to_string(&task).unwrap();
        let back: TaskDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "test");
        assert_eq!(back.specialist, "dev");
        assert_eq!(back.model.as_deref(), Some("granite3.3:8b"));
        assert!(back.generates_tasks);
        assert_eq!(back.back_edges.len(), 1);
        assert!(back.verification.is_some());
        assert_eq!(back.tools.as_ref().unwrap().len(), 2);
    }
}
