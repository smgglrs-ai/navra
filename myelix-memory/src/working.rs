//! Working memory: persistent conversation turns stored in SQLite.

use crate::error::MemoryError;
use crate::types::{Message, Role, Turn};
use rusqlite::{params, Connection};
use std::path::Path;

/// Persistent working memory backed by SQLite.
///
/// Stores conversation turns (user messages, assistant responses,
/// tool calls/results) across sessions.
pub struct WorkingMemory {
    db: Connection,
}

impl WorkingMemory {
    /// Open working memory from a file path.
    pub fn open(path: &Path) -> Result<Self, MemoryError> {
        let db = Connection::open(path)?;
        let mem = Self { db };
        mem.init_schema()?;
        Ok(mem)
    }

    /// Open in-memory working memory (for testing).
    pub fn open_memory() -> Result<Self, MemoryError> {
        let db = Connection::open_in_memory()?;
        let mem = Self { db };
        mem.init_schema()?;
        Ok(mem)
    }

    fn init_schema(&self) -> Result<(), MemoryError> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS memory_turns (
                turn_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                agent TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_turns_session
                ON memory_turns(session_id, created_at);

            CREATE TABLE IF NOT EXISTS memory_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                turn_id TEXT NOT NULL REFERENCES memory_turns(turn_id),
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                metadata TEXT,
                sort_order INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_turn
                ON memory_messages(turn_id, sort_order);",
        )?;
        Ok(())
    }

    /// Store a conversation turn with all its messages.
    pub fn add_turn(&self, turn: &Turn) -> Result<(), MemoryError> {
        let tx = self.db.unchecked_transaction()?;

        tx.execute(
            "INSERT INTO memory_turns (turn_id, session_id, agent, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![turn.turn_id, turn.session_id, turn.agent, turn.created_at],
        )?;

        for (i, msg) in turn.messages.iter().enumerate() {
            tx.execute(
                "INSERT INTO memory_messages (turn_id, role, content, timestamp, metadata, sort_order)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    turn.turn_id,
                    msg.role.as_str(),
                    msg.content,
                    msg.timestamp,
                    msg.metadata,
                    i as i64,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Get recent turns for a session and agent, newest first.
    pub fn get_recent_turns(
        &self,
        session_id: &str,
        agent: &str,
        count: usize,
    ) -> Result<Vec<Turn>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT turn_id, session_id, agent, created_at
             FROM memory_turns
             WHERE session_id = ?1 AND agent = ?2
             ORDER BY created_at DESC
             LIMIT ?3",
        )?;

        let turn_rows: Vec<(String, String, String, i64)> = stmt
            .query_map(params![session_id, agent, count as i64], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<Result<_, _>>()?;

        let mut turns = Vec::new();
        for (turn_id, session_id, agent, created_at) in turn_rows {
            let messages = self.load_messages(&turn_id)?;
            turns.push(Turn {
                turn_id,
                session_id,
                agent,
                messages,
                created_at,
            });
        }

        // Reverse to chronological order
        turns.reverse();
        Ok(turns)
    }

    /// Get all turns for a session, in chronological order.
    pub fn get_session_turns(&self, session_id: &str) -> Result<Vec<Turn>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT turn_id, session_id, agent, created_at
             FROM memory_turns
             WHERE session_id = ?1
             ORDER BY created_at ASC",
        )?;

        let turn_rows: Vec<(String, String, String, i64)> = stmt
            .query_map(params![session_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<Result<_, _>>()?;

        let mut turns = Vec::new();
        for (turn_id, session_id, agent, created_at) in turn_rows {
            let messages = self.load_messages(&turn_id)?;
            turns.push(Turn {
                turn_id,
                session_id,
                agent,
                messages,
                created_at,
            });
        }

        Ok(turns)
    }

    /// Count turns in a session.
    pub fn turn_count(&self, session_id: &str) -> Result<usize, MemoryError> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM memory_turns WHERE session_id = ?1",
            params![session_id],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Clear all turns for a session.
    pub fn clear_session(&self, session_id: &str) -> Result<(), MemoryError> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM memory_messages WHERE turn_id IN
             (SELECT turn_id FROM memory_turns WHERE session_id = ?1)",
            params![session_id],
        )?;
        tx.execute(
            "DELETE FROM memory_turns WHERE session_id = ?1",
            params![session_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn load_messages(&self, turn_id: &str) -> Result<Vec<Message>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT role, content, timestamp, metadata
             FROM memory_messages
             WHERE turn_id = ?1
             ORDER BY sort_order ASC",
        )?;

        let messages = stmt
            .query_map(params![turn_id], |row| {
                let role_str: String = row.get(0)?;
                Ok(Message {
                    role: Role::from_str(&role_str),
                    content: row.get(1)?,
                    timestamp: row.get(2)?,
                    metadata: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(messages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_turn(session: &str, agent: &str, ts: i64) -> Turn {
        Turn {
            turn_id: uuid::Uuid::new_v4().to_string(),
            session_id: session.to_string(),
            agent: agent.to_string(),
            messages: vec![
                Message {
                    role: Role::User,
                    content: format!("Question at {ts}"),
                    timestamp: ts,
                    metadata: None,
                },
                Message {
                    role: Role::Assistant,
                    content: format!("Answer at {ts}"),
                    timestamp: ts + 1,
                    metadata: None,
                },
            ],
            created_at: ts,
        }
    }

    #[test]
    fn add_and_retrieve_turn() {
        let mem = WorkingMemory::open_memory().unwrap();
        let turn = make_turn("s1", "dev", 1000);
        mem.add_turn(&turn).unwrap();

        let turns = mem.get_session_turns("s1").unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].messages.len(), 2);
        assert_eq!(turns[0].messages[0].role, Role::User);
        assert_eq!(turns[0].messages[1].role, Role::Assistant);
    }

    #[test]
    fn recent_turns_ordering() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();
        mem.add_turn(&make_turn("s1", "dev", 2000)).unwrap();
        mem.add_turn(&make_turn("s1", "dev", 3000)).unwrap();

        let turns = mem.get_recent_turns("s1", "dev", 2).unwrap();
        assert_eq!(turns.len(), 2);
        // Should be in chronological order (oldest first)
        assert!(turns[0].created_at < turns[1].created_at);
        // Should be the 2 most recent
        assert_eq!(turns[0].created_at, 2000);
        assert_eq!(turns[1].created_at, 3000);
    }

    #[test]
    fn session_isolation() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();
        mem.add_turn(&make_turn("s2", "dev", 2000)).unwrap();

        assert_eq!(mem.turn_count("s1").unwrap(), 1);
        assert_eq!(mem.turn_count("s2").unwrap(), 1);
        assert_eq!(mem.get_session_turns("s1").unwrap().len(), 1);
    }

    #[test]
    fn clear_session() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();
        mem.add_turn(&make_turn("s1", "dev", 2000)).unwrap();

        assert_eq!(mem.turn_count("s1").unwrap(), 2);
        mem.clear_session("s1").unwrap();
        assert_eq!(mem.turn_count("s1").unwrap(), 0);
    }

    #[test]
    fn agent_filtering() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();
        mem.add_turn(&make_turn("s1", "analyst", 2000)).unwrap();

        let turns = mem.get_recent_turns("s1", "dev", 10).unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].agent, "dev");
    }

    #[test]
    fn message_metadata() {
        let mem = WorkingMemory::open_memory().unwrap();
        let turn = Turn {
            turn_id: "t1".to_string(),
            session_id: "s1".to_string(),
            agent: "dev".to_string(),
            messages: vec![Message {
                role: Role::User,
                content: "Hello".to_string(),
                timestamp: 1000,
                metadata: Some(r#"{"tool": "docs_read"}"#.to_string()),
            }],
            created_at: 1000,
        };
        mem.add_turn(&turn).unwrap();

        let turns = mem.get_session_turns("s1").unwrap();
        assert_eq!(
            turns[0].messages[0].metadata.as_deref(),
            Some(r#"{"tool": "docs_read"}"#)
        );
    }
}
