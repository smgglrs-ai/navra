//! Session-end hook that distills durable facts from a completed session.
//!
//! Runs the `DistillationPipeline` on session close: ingests working
//! memory turns, synthesizes knowledge entries (via LLM or stub), and
//! forges them into the `KnowledgeStore`. Optionally indexes facts in
//! the `TemporalTree` under a Session-type tree.

use async_trait::async_trait;
use navra_core::hooks::Hook;
use navra_memory::{KnowledgeStore, TemporalTree, TreeType, WorkingMemory};
use std::path::PathBuf;
#[allow(dead_code)]
pub struct SessionDistillationHook {
    working_path: PathBuf,
    knowledge_path: PathBuf,
    temporal_path: Option<PathBuf>,
}

#[allow(dead_code)]
impl SessionDistillationHook {
    pub fn new(working_path: PathBuf, knowledge_path: PathBuf) -> Self {
        Self {
            working_path,
            knowledge_path,
            temporal_path: None,
        }
    }

    pub fn with_temporal(mut self, path: PathBuf) -> Self {
        self.temporal_path = Some(path);
        self
    }
}

#[async_trait]
impl Hook for SessionDistillationHook {
    fn name(&self) -> &str {
        "session-distillation"
    }

    async fn on_session_end(&self, session_id: &str, agent_name: &str, tool_count: usize) {
        if tool_count == 0 {
            tracing::debug!(session_id, "Skipping distillation: no tool calls");
            return;
        }

        let session_id = session_id.to_string();
        let agent_name = agent_name.to_string();
        let working_path = self.working_path.clone();
        let knowledge_path = self.knowledge_path.clone();
        let temporal_path = self.temporal_path.clone();
        let log_session = session_id.clone();
        let log_agent = agent_name.clone();

        let result = tokio::task::spawn_blocking(move || {
            let working = WorkingMemory::open(&working_path)?;
            let knowledge = KnowledgeStore::open(&knowledge_path)?;

            let pipeline = navra_memory::DistillationPipeline::new(&working, &knowledge);

            let rt = tokio::runtime::Handle::current();
            let count = rt.block_on(pipeline.run(&session_id))?;

            if let Some(ref tree_path) = temporal_path {
                if let Ok(tree) = TemporalTree::open(tree_path) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let _ = tree.insert_fact(
                        TreeType::Session,
                        &session_id,
                        &format!(
                            "{count} facts distilled from {tool_count} tool calls (agent: {agent_name})"
                        ),
                        now,
                    );
                }
            }

            Ok::<usize, navra_memory::MemoryError>(count)
        })
        .await;

        match result {
            Ok(Ok(count)) => {
                tracing::info!(
                    session_id = log_session,
                    agent = log_agent,
                    facts = count,
                    "Session distillation complete"
                );
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    session_id = log_session,
                    agent = log_agent,
                    error = %e,
                    "Session distillation failed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    session_id = log_session,
                    agent = log_agent,
                    error = %e,
                    "Session distillation task panicked"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_memory::{Message, Role, Turn};

    fn make_turn(session_id: &str, role: Role, content: &str) -> Turn {
        Turn {
            turn_id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            agent: "test-agent".to_string(),
            messages: vec![Message {
                role,
                content: content.to_string(),
                timestamp: 0,
                metadata: None,
            }],
            created_at: 0,
            fork_id: None,
            parent_fork: None,
        }
    }

    #[tokio::test]
    async fn skips_empty_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let hook = SessionDistillationHook::new(
            dir.path().join("working.db"),
            dir.path().join("knowledge.db"),
        );
        hook.on_session_end("empty-session", "agent", 0).await;
    }

    #[tokio::test]
    async fn distills_session_with_turns() {
        let dir = tempfile::tempdir().unwrap();
        let working_path = dir.path().join("working.db");
        let knowledge_path = dir.path().join("knowledge.db");

        {
            let working = WorkingMemory::open(&working_path).unwrap();
            working
                .add_turn(&make_turn("test-session", Role::User, "What is Rust?"))
                .unwrap();
            working
                .add_turn(&make_turn(
                    "test-session",
                    Role::Assistant,
                    "Rust is a systems programming language focused on safety and performance.",
                ))
                .unwrap();
        }

        let hook = SessionDistillationHook::new(working_path, knowledge_path.clone());
        hook.on_session_end("test-session", "test-agent", 3).await;

        let knowledge = KnowledgeStore::open(&knowledge_path).unwrap();
        let results = knowledge.search("Rust").unwrap();
        assert!(
            !results.is_empty(),
            "Expected distilled facts about Rust in KnowledgeStore"
        );
    }

    #[tokio::test]
    async fn distills_with_temporal_tree() {
        let dir = tempfile::tempdir().unwrap();
        let working_path = dir.path().join("working.db");
        let knowledge_path = dir.path().join("knowledge.db");
        let tree_path = dir.path().join("tree.db");

        {
            let working = WorkingMemory::open(&working_path).unwrap();
            working
                .add_turn(&make_turn(
                    "session-1",
                    Role::User,
                    "Tell me about navra security features",
                ))
                .unwrap();
            working
                .add_turn(&make_turn(
                    "session-1",
                    Role::Assistant,
                    "Navra is a secure MCP gateway with IFC, ACLs, and safety hooks.",
                ))
                .unwrap();
        }

        let hook = SessionDistillationHook::new(working_path, knowledge_path)
            .with_temporal(tree_path.clone());

        hook.on_session_end("session-1", "claude", 5).await;

        let tree = TemporalTree::open(&tree_path).unwrap();
        let nodes = tree.browse_tree(TreeType::Session, "session-1").unwrap();
        assert!(
            !nodes.is_empty(),
            "Expected temporal tree entry for session"
        );
    }
}
