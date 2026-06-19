//! Agent process hibernation — save and restore agent state.
//!
//! Two-tier save strategy:
//! - **Conversation tier**: turns, taint, config (always saved, ~KB)
//! - **KV cache tier**: model KV cache state (optional, ~GB)
//!
//! The KV cache tier uses Rust ownership to enforce safety:
//! - A saved cache is consumed on load (no double-restore)
//! - Cache validity is tied to model identity + quantization

use navra_model::InputItem;
use navra_protocol::label::DataLabel;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Serializable snapshot of agent conversation state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSnapshot {
    /// Unique identifier for the agent being hibernated.
    pub agent_id: String,
    /// Identifier for the current run within the agent's lifecycle.
    pub run_id: String,
    /// System prompt used to initialize the agent, if any.
    pub system_prompt: Option<String>,
    /// Full conversation history as model input items.
    pub conversation: Vec<InputItem>,
    /// Number of tool-loop iterations completed before hibernation.
    pub iteration_count: usize,
    /// Cumulative input tokens consumed across all iterations.
    pub input_tokens: u32,
    /// Cumulative output tokens generated across all iterations.
    pub output_tokens: u32,
    /// IFC taint label accumulated during the conversation.
    pub taint: DataLabel,
    /// Name of the model used for inference.
    pub model_name: String,
    /// MCP server endpoint the agent was connected to.
    pub mcp_endpoint: String,
    /// Unix timestamp (seconds) when the snapshot was captured.
    pub created_at: i64,
    /// Maximum tool-loop iterations allowed for the agent.
    pub max_iterations: usize,
    /// Sampling temperature override, if configured.
    pub temperature: Option<f32>,
    /// Maximum output tokens per inference call, if configured.
    pub max_tokens: Option<u32>,
    /// Restrict the agent to this tool subset, if set.
    pub allowed_tools: Option<Vec<String>>,
}

impl ConversationSnapshot {
    /// Timestamp for now.
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// Create a snapshot from the current tool loop state.
    pub fn capture(
        agent_id: &str,
        run_id: &str,
        system_prompt: Option<&str>,
        conversation: Vec<InputItem>,
        iteration_count: usize,
        input_tokens: u32,
        output_tokens: u32,
        taint: DataLabel,
        model_name: &str,
        mcp_endpoint: &str,
        max_iterations: usize,
        temperature: Option<f32>,
        max_tokens: Option<u32>,
        allowed_tools: Option<Vec<String>>,
    ) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            run_id: run_id.to_string(),
            system_prompt: system_prompt.map(String::from),
            conversation,
            iteration_count,
            input_tokens,
            output_tokens,
            taint,
            model_name: model_name.to_string(),
            mcp_endpoint: mcp_endpoint.to_string(),
            created_at: Self::now(),
            max_iterations,
            temperature,
            max_tokens,
            allowed_tools,
        }
    }
}

/// A saved KV cache file on disk.
///
/// This type is consumed on load — calling `take()` extracts the path
/// and disarms the cleanup, preventing double-restore. The cache is
/// only valid for the model identity it was created with.
///
/// If dropped without being consumed, the orphaned file is deleted.
pub struct KvCacheCheckpoint {
    path: Option<PathBuf>,
    model_fingerprint: String,
}

impl KvCacheCheckpoint {
    /// Create a new checkpoint reference (does not write data).
    ///
    /// The caller is responsible for writing the actual cache data to `path`.
    pub fn new(path: PathBuf, model_fingerprint: String) -> Self {
        Self {
            path: Some(path),
            model_fingerprint,
        }
    }

    /// The on-disk path of the KV cache file.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The model fingerprint this cache was created for.
    pub fn model_fingerprint(&self) -> &str {
        &self.model_fingerprint
    }

    /// Consume this checkpoint, returning the path for loading.
    ///
    /// Disarms the drop cleanup. The caller is responsible for deleting
    /// the file after successful restore.
    pub fn take(&mut self) -> Option<(PathBuf, String)> {
        self.path
            .take()
            .map(|p| (p, self.model_fingerprint.clone()))
    }

    /// Validate that this checkpoint matches the given model.
    pub fn matches_model(&self, fingerprint: &str) -> bool {
        self.model_fingerprint == fingerprint
    }
}

impl Drop for KvCacheCheckpoint {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            if path.exists() {
                tracing::warn!(
                    path = %path.display(),
                    "KV cache checkpoint dropped without being consumed — deleting orphaned file"
                );
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// Complete hibernation state: conversation + optional KV cache.
pub struct HibernationState {
    /// Serialized conversation and agent configuration.
    pub conversation: ConversationSnapshot,
    /// Optional KV cache checkpoint for faster model warm-up on restore.
    pub kv_cache: Option<KvCacheCheckpoint>,
}

/// SQLite-backed store for hibernated agent state.
pub struct HibernationStore {
    db: std::sync::Mutex<rusqlite::Connection>,
}

impl HibernationStore {
    /// Open or create a hibernation store.
    pub fn open(path: &Path) -> Result<Self, String> {
        let db = rusqlite::Connection::open(path)
            .map_err(|e| format!("hibernation store open failed: {e}"))?;

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS hibernations (
                agent_id    TEXT PRIMARY KEY,
                snapshot    BLOB NOT NULL,
                kv_path     TEXT,
                kv_model_fp TEXT,
                created_at  INTEGER NOT NULL
            );",
        )
        .map_err(|e| format!("hibernation schema failed: {e}"))?;

        Ok(Self {
            db: std::sync::Mutex::new(db),
        })
    }

    /// Open an in-memory store (for tests).
    pub fn open_memory() -> Result<Self, String> {
        Self::open(Path::new(":memory:"))
    }

    /// Save agent hibernation state.
    pub fn save(&self, state: HibernationState) -> Result<(), String> {
        let snapshot_bytes = serde_json::to_vec(&state.conversation)
            .map_err(|e| format!("snapshot serialization failed: {e}"))?;

        let (kv_path, kv_fp) = state
            .kv_cache
            .and_then(|mut kv| kv.take())
            .map(|(p, fp)| (Some(p.to_string_lossy().to_string()), Some(fp)))
            .unwrap_or((None, None));

        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.execute(
            "INSERT OR REPLACE INTO hibernations (agent_id, snapshot, kv_path, kv_model_fp, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                state.conversation.agent_id,
                snapshot_bytes,
                kv_path,
                kv_fp,
                state.conversation.created_at,
            ],
        )
        .map_err(|e| format!("hibernation save failed: {e}"))?;

        Ok(())
    }

    /// Load and remove a hibernated agent state.
    pub fn load(&self, agent_id: &str) -> Result<Option<HibernationState>, String> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());

        let result = db.query_row(
            "SELECT snapshot, kv_path, kv_model_fp FROM hibernations WHERE agent_id = ?1",
            [agent_id],
            |row| {
                let snapshot_bytes: Vec<u8> = row.get(0)?;
                let kv_path: Option<String> = row.get(1)?;
                let kv_fp: Option<String> = row.get(2)?;
                Ok((snapshot_bytes, kv_path, kv_fp))
            },
        );

        match result {
            Ok((snapshot_bytes, kv_path, kv_fp)) => {
                let conversation: ConversationSnapshot = serde_json::from_slice(&snapshot_bytes)
                    .map_err(|e| format!("snapshot deserialization failed: {e}"))?;

                let kv_cache = match (kv_path, kv_fp) {
                    (Some(path), Some(fp)) => {
                        let pb = PathBuf::from(&path);
                        if pb.exists() {
                            Some(KvCacheCheckpoint::new(pb, fp))
                        } else {
                            tracing::warn!(path = %path, "KV cache file missing — falling back to conversation-only restore");
                            None
                        }
                    }
                    _ => None,
                };

                // Remove from store after loading
                let _ = db.execute("DELETE FROM hibernations WHERE agent_id = ?1", [agent_id]);

                Ok(Some(HibernationState {
                    conversation,
                    kv_cache,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("hibernation load failed: {e}")),
        }
    }

    /// List all hibernated agent IDs with their creation timestamps.
    pub fn list(&self) -> Result<Vec<(String, i64)>, String> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = db
            .prepare("SELECT agent_id, created_at FROM hibernations ORDER BY created_at DESC")
            .map_err(|e| format!("hibernation list failed: {e}"))?;

        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| format!("hibernation query failed: {e}"))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| format!("row read failed: {e}"))?);
        }
        Ok(result)
    }

    /// Delete a hibernated state without loading it.
    pub fn delete(&self, agent_id: &str) -> Result<bool, String> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());

        // Check for KV cache file to clean up
        let kv_path: Option<String> = db
            .query_row(
                "SELECT kv_path FROM hibernations WHERE agent_id = ?1",
                [agent_id],
                |row| row.get(0),
            )
            .ok();

        if let Some(path) = &kv_path {
            let pb = PathBuf::from(path);
            if pb.exists() {
                let _ = std::fs::remove_file(&pb);
            }
        }

        let rows = db
            .execute("DELETE FROM hibernations WHERE agent_id = ?1", [agent_id])
            .map_err(|e| format!("hibernation delete failed: {e}"))?;

        Ok(rows > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip() {
        let snap = ConversationSnapshot::capture(
            "agent-1",
            "run-1",
            Some("You are helpful"),
            vec![],
            5,
            100,
            200,
            DataLabel::TRUSTED_PUBLIC,
            "granite3.3:8b",
            "http://localhost:3000/mcp",
            20,
            Some(0.7),
            Some(4096),
            None,
        );

        let json = serde_json::to_string(&snap).unwrap();
        let restored: ConversationSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.agent_id, "agent-1");
        assert_eq!(restored.iteration_count, 5);
        assert_eq!(restored.model_name, "granite3.3:8b");
    }

    #[test]
    fn store_save_and_load() {
        let store = HibernationStore::open_memory().unwrap();

        let snap = ConversationSnapshot::capture(
            "agent-1",
            "run-1",
            Some("prompt"),
            vec![],
            3,
            50,
            100,
            DataLabel::TRUSTED_PUBLIC,
            "model",
            "endpoint",
            10,
            None,
            None,
            None,
        );

        store
            .save(HibernationState {
                conversation: snap,
                kv_cache: None,
            })
            .unwrap();

        let loaded = store.load("agent-1").unwrap();
        assert!(loaded.is_some());
        let state = loaded.unwrap();
        assert_eq!(state.conversation.agent_id, "agent-1");
        assert_eq!(state.conversation.iteration_count, 3);
        assert!(state.kv_cache.is_none());

        // Should be removed after load
        let again = store.load("agent-1").unwrap();
        assert!(again.is_none());
    }

    #[test]
    fn store_list_and_delete() {
        let store = HibernationStore::open_memory().unwrap();

        for id in &["a", "b", "c"] {
            let snap = ConversationSnapshot::capture(
                id,
                "run",
                None,
                vec![],
                0,
                0,
                0,
                DataLabel::TRUSTED_PUBLIC,
                "m",
                "e",
                10,
                None,
                None,
                None,
            );
            store
                .save(HibernationState {
                    conversation: snap,
                    kv_cache: None,
                })
                .unwrap();
        }

        let list = store.list().unwrap();
        assert_eq!(list.len(), 3);

        assert!(store.delete("b").unwrap());
        assert_eq!(store.list().unwrap().len(), 2);

        assert!(!store.delete("nonexistent").unwrap());
    }

    #[test]
    fn store_load_nonexistent_returns_none() {
        let store = HibernationStore::open_memory().unwrap();
        assert!(store.load("ghost").unwrap().is_none());
    }

    #[test]
    fn kv_checkpoint_matches_model() {
        let mut kv = KvCacheCheckpoint::new(
            PathBuf::from("/tmp/test-kv.bin"),
            "sha256:abc123".to_string(),
        );
        assert!(kv.matches_model("sha256:abc123"));
        assert!(!kv.matches_model("sha256:other"));
        // Disarm the drop
        kv.take();
    }

    #[test]
    fn kv_checkpoint_take_consumes() {
        let mut kv = KvCacheCheckpoint::new(PathBuf::from("/tmp/consumed.bin"), "fp".to_string());
        let (path, fp) = kv.take().unwrap();
        assert_eq!(path, PathBuf::from("/tmp/consumed.bin"));
        assert_eq!(fp, "fp");
        // Second take returns None
        assert!(kv.take().is_none());
    }
}
