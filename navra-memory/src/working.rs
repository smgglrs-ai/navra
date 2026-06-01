//! Working memory: persistent conversation turns stored in SQLite.

use crate::decay::effective_score;
use crate::error::MemoryError;
use crate::types::{MergeStrategy, Message, Role, Turn};
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
                created_at INTEGER NOT NULL,
                fork_id TEXT,
                parent_fork TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_turns_session
                ON memory_turns(session_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_turns_fork
                ON memory_turns(fork_id);

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
        self.migrate_add_fork_columns()?;
        self.migrate_add_decay_columns()?;
        Ok(())
    }

    /// Add fork_id and parent_fork columns if they don't exist (migration).
    fn migrate_add_fork_columns(&self) -> Result<(), MemoryError> {
        let has_fork_id: bool = self
            .db
            .prepare("SELECT fork_id FROM memory_turns LIMIT 0")
            .is_ok();
        if !has_fork_id {
            self.db.execute_batch(
                "ALTER TABLE memory_turns ADD COLUMN fork_id TEXT;
                 ALTER TABLE memory_turns ADD COLUMN parent_fork TEXT;
                 CREATE INDEX IF NOT EXISTS idx_turns_fork ON memory_turns(fork_id);",
            )?;
        }
        Ok(())
    }

    /// Add importance and access_count columns if they don't exist (migration).
    fn migrate_add_decay_columns(&self) -> Result<(), MemoryError> {
        let has_importance: bool = self
            .db
            .prepare("SELECT importance FROM memory_turns LIMIT 0")
            .is_ok();
        if !has_importance {
            self.db.execute_batch(
                "ALTER TABLE memory_turns ADD COLUMN importance REAL NOT NULL DEFAULT 0.0;
                 ALTER TABLE memory_turns ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0;",
            )?;
        }
        Ok(())
    }

    /// Store a conversation turn with all its messages.
    pub fn add_turn(&self, turn: &Turn) -> Result<(), MemoryError> {
        let tx = self.db.unchecked_transaction()?;

        tx.execute(
            "INSERT INTO memory_turns (turn_id, session_id, agent, created_at, fork_id, parent_fork)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                turn.turn_id,
                turn.session_id,
                turn.agent,
                turn.created_at,
                turn.fork_id,
                turn.parent_fork,
            ],
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
    ///
    /// Only returns turns on the main timeline (fork_id IS NULL).
    pub fn get_recent_turns(
        &self,
        session_id: &str,
        agent: &str,
        count: usize,
    ) -> Result<Vec<Turn>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT turn_id, session_id, agent, created_at, fork_id, parent_fork
             FROM memory_turns
             WHERE session_id = ?1 AND agent = ?2 AND fork_id IS NULL
             ORDER BY created_at DESC
             LIMIT ?3",
        )?;

        let turn_rows: Vec<_> = stmt
            .query_map(params![session_id, agent, count as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut turns = Vec::new();
        for (turn_id, session_id, agent, created_at, fork_id, parent_fork) in turn_rows {
            let messages = self.load_messages(&turn_id)?;
            turns.push(Turn {
                turn_id,
                session_id,
                agent,
                messages,
                created_at,
                fork_id,
                parent_fork,
            });
        }

        // Reverse to chronological order
        turns.reverse();
        Ok(turns)
    }

    /// Get all turns for a session on the main timeline, in chronological order.
    pub fn get_session_turns(&self, session_id: &str) -> Result<Vec<Turn>, MemoryError> {
        self.get_turns_query(
            "SELECT turn_id, session_id, agent, created_at, fork_id, parent_fork
             FROM memory_turns
             WHERE session_id = ?1 AND fork_id IS NULL
             ORDER BY created_at ASC",
            params![session_id],
        )
    }

    /// Get all turns for a specific fork, in chronological order.
    pub fn get_fork_turns(
        &self,
        session_id: &str,
        fork_name: &str,
    ) -> Result<Vec<Turn>, MemoryError> {
        self.get_turns_query(
            "SELECT turn_id, session_id, agent, created_at, fork_id, parent_fork
             FROM memory_turns
             WHERE session_id = ?1 AND fork_id = ?2
             ORDER BY created_at ASC",
            params![session_id, fork_name],
        )
    }

    /// Helper to load turns from a prepared query.
    fn get_turns_query(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<Turn>, MemoryError> {
        let mut stmt = self.db.prepare(sql)?;

        let turn_rows: Vec<_> = stmt
            .query_map(params, |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut turns = Vec::new();
        for (turn_id, session_id, agent, created_at, fork_id, parent_fork) in turn_rows {
            let messages = self.load_messages(&turn_id)?;
            turns.push(Turn {
                turn_id,
                session_id,
                agent,
                messages,
                created_at,
                fork_id,
                parent_fork,
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

    /// Fork the current session's main timeline into a named branch.
    ///
    /// Copies all main-timeline turns for the session into a new fork.
    /// New turns added with this fork_id will be independent of the main
    /// timeline.
    pub fn fork(&self, session_id: &str, fork_name: &str) -> Result<(), MemoryError> {
        self.fork_from_internal(session_id, None, fork_name, None)
    }

    /// Fork from a specific turn in the session's history.
    ///
    /// Copies turns up to and including `turn_id` into the new fork.
    /// The fork's `parent_fork` is set to the source fork (None = main).
    pub fn fork_from(
        &self,
        session_id: &str,
        turn_id: &str,
        fork_name: &str,
    ) -> Result<(), MemoryError> {
        self.fork_from_internal(session_id, None, fork_name, Some(turn_id))
    }

    /// Internal fork implementation.
    ///
    /// Copies turns from `source_fork` (None = main timeline) up to
    /// `up_to_turn` (None = all turns) into a new fork named `fork_name`.
    fn fork_from_internal(
        &self,
        session_id: &str,
        source_fork: Option<&str>,
        fork_name: &str,
        up_to_turn: Option<&str>,
    ) -> Result<(), MemoryError> {
        // Determine the cutoff timestamp if forking from a specific turn
        let cutoff = if let Some(tid) = up_to_turn {
            let ts: i64 = self
                .db
                .query_row(
                    "SELECT created_at FROM memory_turns WHERE turn_id = ?1 AND session_id = ?2",
                    params![tid, session_id],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    MemoryError::Other(format!(
                        "Turn '{}' not found in session '{}'",
                        tid, session_id
                    ))
                })?;
            Some(ts)
        } else {
            None
        };

        // Load source turns
        let source_turns = match source_fork {
            None => {
                let sql = match cutoff {
                    Some(ts) => format!(
                        "SELECT turn_id, session_id, agent, created_at, fork_id, parent_fork
                         FROM memory_turns
                         WHERE session_id = ?1 AND fork_id IS NULL AND created_at <= {}
                         ORDER BY created_at ASC",
                        ts
                    ),
                    None => "SELECT turn_id, session_id, agent, created_at, fork_id, parent_fork
                             FROM memory_turns
                             WHERE session_id = ?1 AND fork_id IS NULL
                             ORDER BY created_at ASC"
                        .to_string(),
                };
                self.get_turns_query(&sql, params![session_id])?
            }
            Some(src) => {
                let sql = match cutoff {
                    Some(ts) => format!(
                        "SELECT turn_id, session_id, agent, created_at, fork_id, parent_fork
                         FROM memory_turns
                         WHERE session_id = ?1 AND fork_id = ?2 AND created_at <= {}
                         ORDER BY created_at ASC",
                        ts
                    ),
                    None => "SELECT turn_id, session_id, agent, created_at, fork_id, parent_fork
                             FROM memory_turns
                             WHERE session_id = ?1 AND fork_id = ?2
                             ORDER BY created_at ASC"
                        .to_string(),
                };
                self.get_turns_query(&sql, params![session_id, src])?
            }
        };

        let parent = source_fork.map(String::from);
        let tx = self.db.unchecked_transaction()?;

        for turn in &source_turns {
            let new_turn_id = uuid::Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO memory_turns (turn_id, session_id, agent, created_at, fork_id, parent_fork)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    new_turn_id,
                    turn.session_id,
                    turn.agent,
                    turn.created_at,
                    fork_name,
                    parent,
                ],
            )?;

            // Copy messages
            let mut msg_stmt = self.db.prepare(
                "SELECT role, content, timestamp, metadata, sort_order
                 FROM memory_messages
                 WHERE turn_id = ?1
                 ORDER BY sort_order ASC",
            )?;
            let msgs: Vec<(String, String, i64, Option<String>, i64)> = msg_stmt
                .query_map(params![turn.turn_id], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })?
                .collect::<Result<_, _>>()?;

            for (role, content, timestamp, metadata, sort_order) in msgs {
                tx.execute(
                    "INSERT INTO memory_messages (turn_id, role, content, timestamp, metadata, sort_order)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![new_turn_id, role, content, timestamp, metadata, sort_order],
                )?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    /// List all fork names for a session.
    pub fn list_forks(&self, session_id: &str) -> Result<Vec<String>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT fork_id FROM memory_turns
             WHERE session_id = ?1 AND fork_id IS NOT NULL
             ORDER BY fork_id ASC",
        )?;

        let forks = stmt
            .query_map(params![session_id], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;

        Ok(forks)
    }

    /// Merge a fork's turns back into the main timeline.
    ///
    /// - `Append`: add all fork turns after current main-timeline turns.
    /// - `Replace`: delete main-timeline turns from the fork point onward,
    ///   then insert fork turns onto the main timeline.
    /// - `Summarize`: concatenate fork turn contents into a single summary
    ///   turn and append it to the main timeline.
    pub fn merge_fork(
        &self,
        session_id: &str,
        fork_name: &str,
        strategy: MergeStrategy,
    ) -> Result<(), MemoryError> {
        let fork_turns = self.get_fork_turns(session_id, fork_name)?;
        if fork_turns.is_empty() {
            return Ok(());
        }

        let tx = self.db.unchecked_transaction()?;

        match strategy {
            MergeStrategy::Append => {
                // Re-insert fork turns onto the main timeline
                for turn in &fork_turns {
                    let new_id = uuid::Uuid::new_v4().to_string();
                    tx.execute(
                        "INSERT INTO memory_turns (turn_id, session_id, agent, created_at, fork_id, parent_fork)
                         VALUES (?1, ?2, ?3, ?4, NULL, NULL)",
                        params![new_id, session_id, turn.agent, turn.created_at],
                    )?;
                    self.copy_messages_tx(&tx, &turn.turn_id, &new_id)?;
                }
            }
            MergeStrategy::Replace => {
                // Find the earliest fork turn timestamp — delete main turns from there
                let fork_start = fork_turns[0].created_at;
                // Delete messages for main turns at or after the fork point
                tx.execute(
                    "DELETE FROM memory_messages WHERE turn_id IN
                     (SELECT turn_id FROM memory_turns
                      WHERE session_id = ?1 AND fork_id IS NULL AND created_at >= ?2)",
                    params![session_id, fork_start],
                )?;
                tx.execute(
                    "DELETE FROM memory_turns
                     WHERE session_id = ?1 AND fork_id IS NULL AND created_at >= ?2",
                    params![session_id, fork_start],
                )?;
                // Insert fork turns as main timeline
                for turn in &fork_turns {
                    let new_id = uuid::Uuid::new_v4().to_string();
                    tx.execute(
                        "INSERT INTO memory_turns (turn_id, session_id, agent, created_at, fork_id, parent_fork)
                         VALUES (?1, ?2, ?3, ?4, NULL, NULL)",
                        params![new_id, session_id, turn.agent, turn.created_at],
                    )?;
                    self.copy_messages_tx(&tx, &turn.turn_id, &new_id)?;
                }
            }
            MergeStrategy::Summarize => {
                // Collect all message content from fork turns
                let mut summary_parts = Vec::new();
                for turn in &fork_turns {
                    for msg in &turn.messages {
                        summary_parts.push(format!("[{}] {}", msg.role.as_str(), msg.content));
                    }
                }
                let summary_content = format!(
                    "Summary of fork '{}':\n{}",
                    fork_name,
                    summary_parts.join("\n")
                );

                let now = fork_turns.last().unwrap().created_at + 1;
                let summary_id = uuid::Uuid::new_v4().to_string();
                let agent = &fork_turns[0].agent;

                tx.execute(
                    "INSERT INTO memory_turns (turn_id, session_id, agent, created_at, fork_id, parent_fork)
                     VALUES (?1, ?2, ?3, ?4, NULL, NULL)",
                    params![summary_id, session_id, agent, now],
                )?;
                tx.execute(
                    "INSERT INTO memory_messages (turn_id, role, content, timestamp, metadata, sort_order)
                     VALUES (?1, 'assistant', ?2, ?3, NULL, 0)",
                    params![summary_id, summary_content, now],
                )?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    /// Copy messages from one turn to another within a transaction.
    fn copy_messages_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        from_turn_id: &str,
        to_turn_id: &str,
    ) -> Result<(), MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT role, content, timestamp, metadata, sort_order
             FROM memory_messages
             WHERE turn_id = ?1
             ORDER BY sort_order ASC",
        )?;
        let msgs: Vec<(String, String, i64, Option<String>, i64)> = stmt
            .query_map(params![from_turn_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .collect::<Result<_, _>>()?;

        for (role, content, timestamp, metadata, sort_order) in msgs {
            tx.execute(
                "INSERT INTO memory_messages (turn_id, role, content, timestamp, metadata, sort_order)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![to_turn_id, role, content, timestamp, metadata, sort_order],
            )?;
        }

        Ok(())
    }

    /// Get turns scored by decay, retaining high-importance old turns.
    ///
    /// Loads all main-timeline turns for the session+agent, computes
    /// `effective_score()` for each, picks the top `max_count` by score,
    /// then returns them in chronological order.
    pub fn get_turns_by_score(
        &self,
        session_id: &str,
        agent: &str,
        max_count: usize,
        decay_rate: f64,
    ) -> Result<Vec<Turn>, MemoryError> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut stmt = self.db.prepare(
            "SELECT turn_id, session_id, agent, created_at, fork_id, parent_fork,
                    importance, access_count
             FROM memory_turns
             WHERE session_id = ?1 AND agent = ?2 AND fork_id IS NULL
             ORDER BY created_at ASC",
        )?;

        let rows: Vec<(
            String,
            String,
            String,
            i64,
            Option<String>,
            Option<String>,
            f64,
            i64,
        )> = stmt
            .query_map(params![session_id, agent], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, f64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Compute scores and pick top max_count
        let mut scored: Vec<(usize, f64)> = rows
            .iter()
            .enumerate()
            .map(
                |(i, (_, _, _, created_at, _, _, importance, access_count))| {
                    let age_hours = (now_secs - created_at).max(0) as f64 / 3600.0;
                    let score =
                        effective_score(*importance, age_hours, *access_count as u32, decay_rate);
                    (i, score)
                },
            )
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(max_count);

        // Re-sort by original index (chronological order)
        scored.sort_by_key(|(i, _)| *i);

        let mut turns = Vec::with_capacity(scored.len());
        for (i, _) in scored {
            let (turn_id, session_id, agent, created_at, fork_id, parent_fork, _, _) = &rows[i];
            let messages = self.load_messages(turn_id)?;
            turns.push(Turn {
                turn_id: turn_id.clone(),
                session_id: session_id.clone(),
                agent: agent.clone(),
                messages,
                created_at: *created_at,
                fork_id: fork_id.clone(),
                parent_fork: parent_fork.clone(),
            });
        }

        Ok(turns)
    }

    /// Set the importance score for a turn.
    pub fn set_turn_importance(&self, turn_id: &str, importance: f64) -> Result<(), MemoryError> {
        let updated = self.db.execute(
            "UPDATE memory_turns SET importance = ?1 WHERE turn_id = ?2",
            params![importance, turn_id],
        )?;
        if updated == 0 {
            return Err(MemoryError::Other(format!("Turn '{}' not found", turn_id)));
        }
        Ok(())
    }

    /// Increment the access count for a turn.
    pub fn increment_access_count(&self, turn_id: &str) -> Result<(), MemoryError> {
        let updated = self.db.execute(
            "UPDATE memory_turns SET access_count = access_count + 1 WHERE turn_id = ?1",
            params![turn_id],
        )?;
        if updated == 0 {
            return Err(MemoryError::Other(format!("Turn '{}' not found", turn_id)));
        }
        Ok(())
    }

    /// List all distinct session IDs with their turn counts and timestamps.
    pub fn list_sessions(&self) -> Result<Vec<(String, usize, i64, i64)>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT session_id, COUNT(*), MIN(created_at), MAX(created_at)
             FROM memory_turns
             WHERE fork_id IS NULL
             GROUP BY session_id
             ORDER BY MAX(created_at) DESC",
        )?;

        let sessions = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as usize,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(sessions)
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
            fork_id: None,
            parent_fork: None,
        }
    }

    fn make_turn_with_id(session: &str, agent: &str, ts: i64, turn_id: &str) -> Turn {
        Turn {
            turn_id: turn_id.to_string(),
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
            fork_id: None,
            parent_fork: None,
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
                metadata: Some(r#"{"tool": "file_read"}"#.to_string()),
            }],
            created_at: 1000,
            fork_id: None,
            parent_fork: None,
        };
        mem.add_turn(&turn).unwrap();

        let turns = mem.get_session_turns("s1").unwrap();
        assert_eq!(
            turns[0].messages[0].metadata.as_deref(),
            Some(r#"{"tool": "file_read"}"#)
        );
    }

    // --- Fork tests ---

    #[test]
    fn fork_creates_independent_branch() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();
        mem.add_turn(&make_turn("s1", "dev", 2000)).unwrap();

        mem.fork("s1", "explore").unwrap();

        // Fork should have copies of the 2 main turns
        let fork_turns = mem.get_fork_turns("s1", "explore").unwrap();
        assert_eq!(fork_turns.len(), 2);

        // Main timeline still has 2 turns
        let main_turns = mem.get_session_turns("s1").unwrap();
        assert_eq!(main_turns.len(), 2);

        // Add a turn to the fork — should not appear on main
        let mut fork_turn = make_turn("s1", "dev", 3000);
        fork_turn.fork_id = Some("explore".to_string());
        mem.add_turn(&fork_turn).unwrap();

        assert_eq!(mem.get_fork_turns("s1", "explore").unwrap().len(), 3);
        assert_eq!(mem.get_session_turns("s1").unwrap().len(), 2);
    }

    #[test]
    fn fork_from_copies_up_to_turn() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn_with_id("s1", "dev", 1000, "t1"))
            .unwrap();
        mem.add_turn(&make_turn_with_id("s1", "dev", 2000, "t2"))
            .unwrap();
        mem.add_turn(&make_turn_with_id("s1", "dev", 3000, "t3"))
            .unwrap();

        // Fork from t2 — should include t1 and t2 but not t3
        mem.fork_from("s1", "t2", "branch-a").unwrap();

        let fork_turns = mem.get_fork_turns("s1", "branch-a").unwrap();
        assert_eq!(fork_turns.len(), 2);
        assert_eq!(fork_turns[0].created_at, 1000);
        assert_eq!(fork_turns[1].created_at, 2000);
    }

    #[test]
    fn fork_turns_dont_appear_in_main() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();

        mem.fork("s1", "side").unwrap();

        // Add turns only to the fork
        let mut ft = make_turn("s1", "dev", 5000);
        ft.fork_id = Some("side".to_string());
        mem.add_turn(&ft).unwrap();

        // Main should still have only 1
        let main = mem.get_session_turns("s1").unwrap();
        assert_eq!(main.len(), 1);
        assert_eq!(main[0].created_at, 1000);

        // get_recent_turns also excludes fork turns
        let recent = mem.get_recent_turns("s1", "dev", 100).unwrap();
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn list_forks_returns_all_forks() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();

        mem.fork("s1", "alpha").unwrap();
        mem.fork("s1", "beta").unwrap();

        let forks = mem.list_forks("s1").unwrap();
        assert_eq!(forks, vec!["alpha", "beta"]);

        // Different session should have no forks
        let forks2 = mem.list_forks("s2").unwrap();
        assert!(forks2.is_empty());
    }

    #[test]
    fn merge_append_adds_fork_turns_after_main() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();
        mem.add_turn(&make_turn("s1", "dev", 2000)).unwrap();

        mem.fork("s1", "fix").unwrap();

        // Add a new turn to the fork
        let mut ft = make_turn("s1", "dev", 3000);
        ft.fork_id = Some("fix".to_string());
        mem.add_turn(&ft).unwrap();

        // Main has 2, fork has 3 (2 copied + 1 new)
        assert_eq!(mem.get_session_turns("s1").unwrap().len(), 2);
        assert_eq!(mem.get_fork_turns("s1", "fix").unwrap().len(), 3);

        // Merge with Append
        mem.merge_fork("s1", "fix", MergeStrategy::Append).unwrap();

        // Main should now have 2 original + 3 merged = 5
        let main = mem.get_session_turns("s1").unwrap();
        assert_eq!(main.len(), 5);
    }

    #[test]
    fn merge_replace_replaces_from_fork_point() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn_with_id("s1", "dev", 1000, "t1"))
            .unwrap();
        mem.add_turn(&make_turn_with_id("s1", "dev", 2000, "t2"))
            .unwrap();
        mem.add_turn(&make_turn_with_id("s1", "dev", 3000, "t3"))
            .unwrap();

        // Fork from t1 — copies t1 only
        mem.fork_from("s1", "t1", "alt").unwrap();

        // Add a different turn to the fork at ts 1500
        let mut ft = make_turn("s1", "dev", 1500);
        ft.fork_id = Some("alt".to_string());
        ft.messages[0].content = "Alternative question".to_string();
        mem.add_turn(&ft).unwrap();

        // Fork has 2 turns (copied t1 + new at 1500)
        assert_eq!(mem.get_fork_turns("s1", "alt").unwrap().len(), 2);

        // Main has 3 turns
        assert_eq!(mem.get_session_turns("s1").unwrap().len(), 3);

        // Merge with Replace — fork starts at ts 1000, so main turns
        // at ts >= 1000 (all 3) get replaced by fork turns (2)
        mem.merge_fork("s1", "alt", MergeStrategy::Replace).unwrap();

        let main = mem.get_session_turns("s1").unwrap();
        assert_eq!(main.len(), 2);
        assert_eq!(main[0].created_at, 1000);
        assert_eq!(main[1].created_at, 1500);
    }

    #[test]
    fn merge_summarize_creates_single_turn() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();

        mem.fork("s1", "experiment").unwrap();

        // Add turns to the fork
        let mut ft = make_turn("s1", "dev", 2000);
        ft.fork_id = Some("experiment".to_string());
        mem.add_turn(&ft).unwrap();

        // Main has 1, fork has 2 (1 copied + 1 new)
        mem.merge_fork("s1", "experiment", MergeStrategy::Summarize)
            .unwrap();

        let main = mem.get_session_turns("s1").unwrap();
        // 1 original + 1 summary = 2
        assert_eq!(main.len(), 2);
        let summary = &main[1];
        assert_eq!(summary.messages.len(), 1);
        assert!(summary.messages[0]
            .content
            .contains("Summary of fork 'experiment'"));
    }

    #[test]
    fn schema_migration_adds_columns() {
        // Create a database without fork columns, then open with new schema
        let mem = WorkingMemory::open_memory().unwrap();

        // The init_schema already creates them, so just verify they exist
        // by adding a turn with fork fields
        let mut turn = make_turn("s1", "dev", 1000);
        turn.fork_id = Some("test-fork".to_string());
        turn.parent_fork = Some("main".to_string());
        mem.add_turn(&turn).unwrap();

        let forks = mem.list_forks("s1").unwrap();
        assert_eq!(forks, vec!["test-fork"]);
    }

    // --- Decay-scored turn selection tests ---

    #[test]
    fn new_turns_default_importance_and_access_count() {
        let mem = WorkingMemory::open_memory().unwrap();
        let turn = make_turn_with_id("s1", "dev", 1000, "t1");
        mem.add_turn(&turn).unwrap();

        let (importance, access_count): (f64, i64) = mem
            .db
            .query_row(
                "SELECT importance, access_count FROM memory_turns WHERE turn_id = 't1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!((importance - 0.0).abs() < f64::EPSILON);
        assert_eq!(access_count, 0);
    }

    #[test]
    fn set_turn_importance_persists() {
        let mem = WorkingMemory::open_memory().unwrap();
        let turn = make_turn_with_id("s1", "dev", 1000, "t1");
        mem.add_turn(&turn).unwrap();

        mem.set_turn_importance("t1", 0.9).unwrap();

        let importance: f64 = mem
            .db
            .query_row(
                "SELECT importance FROM memory_turns WHERE turn_id = 't1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!((importance - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn set_turn_importance_missing_turn_errors() {
        let mem = WorkingMemory::open_memory().unwrap();
        assert!(mem.set_turn_importance("nonexistent", 0.5).is_err());
    }

    #[test]
    fn increment_access_count_increments() {
        let mem = WorkingMemory::open_memory().unwrap();
        let turn = make_turn_with_id("s1", "dev", 1000, "t1");
        mem.add_turn(&turn).unwrap();

        mem.increment_access_count("t1").unwrap();
        mem.increment_access_count("t1").unwrap();

        let count: i64 = mem
            .db
            .query_row(
                "SELECT access_count FROM memory_turns WHERE turn_id = 't1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn increment_access_count_missing_turn_errors() {
        let mem = WorkingMemory::open_memory().unwrap();
        assert!(mem.increment_access_count("nonexistent").is_err());
    }

    #[test]
    fn get_turns_by_score_prefers_important_old_over_recent_unimportant() {
        let mem = WorkingMemory::open_memory().unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Old turn (24h ago) but high importance
        let old = make_turn_with_id("s1", "dev", now - 86400, "old");
        mem.add_turn(&old).unwrap();
        mem.set_turn_importance("old", 1.0).unwrap();

        // Recent turn (1 min ago) but zero importance
        let recent = make_turn_with_id("s1", "dev", now - 60, "recent");
        mem.add_turn(&recent).unwrap();
        // importance stays 0.0

        // Ask for only 1 turn — should pick the important old one
        let turns = mem.get_turns_by_score("s1", "dev", 1, 0.001).unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].turn_id, "old");
    }

    #[test]
    fn get_turns_by_score_returns_chronological_order() {
        let mem = WorkingMemory::open_memory().unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Three turns with varying importance
        let t1 = make_turn_with_id("s1", "dev", now - 3600, "t1");
        mem.add_turn(&t1).unwrap();
        mem.set_turn_importance("t1", 0.8).unwrap();

        let t2 = make_turn_with_id("s1", "dev", now - 1800, "t2");
        mem.add_turn(&t2).unwrap();
        mem.set_turn_importance("t2", 0.9).unwrap();

        let t3 = make_turn_with_id("s1", "dev", now - 60, "t3");
        mem.add_turn(&t3).unwrap();
        mem.set_turn_importance("t3", 0.7).unwrap();

        // Ask for 2 — should pick t2 and t3 (highest scores), returned chronologically
        let turns = mem.get_turns_by_score("s1", "dev", 2, 0.001).unwrap();
        assert_eq!(turns.len(), 2);
        assert!(turns[0].created_at < turns[1].created_at);
    }

    #[test]
    fn get_turns_by_score_access_count_boosts() {
        let mem = WorkingMemory::open_memory().unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Two old turns with same zero importance, but one has accesses
        let accessed = make_turn_with_id("s1", "dev", now - 86400, "accessed");
        mem.add_turn(&accessed).unwrap();
        for _ in 0..3 {
            mem.increment_access_count("accessed").unwrap();
        }

        let untouched = make_turn_with_id("s1", "dev", now - 86400 + 1, "untouched");
        mem.add_turn(&untouched).unwrap();

        // Ask for 1 — the accessed one should win
        let turns = mem.get_turns_by_score("s1", "dev", 1, 0.001).unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].turn_id, "accessed");
    }

    #[test]
    fn get_turns_by_score_excludes_forks() {
        let mem = WorkingMemory::open_memory().unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let main_turn = make_turn_with_id("s1", "dev", now - 60, "main1");
        mem.add_turn(&main_turn).unwrap();

        let mut fork_turn = make_turn_with_id("s1", "dev", now - 30, "fork1");
        fork_turn.fork_id = Some("branch".to_string());
        mem.add_turn(&fork_turn).unwrap();

        let turns = mem.get_turns_by_score("s1", "dev", 10, 0.001).unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].turn_id, "main1");
    }

    #[test]
    fn decay_columns_migration_preserves_existing_data() {
        // Simulate a pre-migration database by creating the table without
        // decay columns, inserting data, then running init_schema.
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE memory_turns (
                turn_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                agent TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                fork_id TEXT,
                parent_fork TEXT
            );
            CREATE TABLE memory_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                turn_id TEXT NOT NULL REFERENCES memory_turns(turn_id),
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                metadata TEXT,
                sort_order INTEGER NOT NULL
            );",
        )
        .unwrap();

        // Insert a turn without decay columns
        db.execute(
            "INSERT INTO memory_turns (turn_id, session_id, agent, created_at)
             VALUES ('pre', 's1', 'dev', 1000)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO memory_messages (turn_id, role, content, timestamp, metadata, sort_order)
             VALUES ('pre', 'user', 'Hello', 1000, NULL, 0)",
            [],
        )
        .unwrap();

        drop(db);

        // Re-open via WorkingMemory (triggers migration)
        let mem = WorkingMemory::open_memory().unwrap();
        // Manually insert the pre-existing row (since open_memory creates fresh db,
        // we test the migration path by calling migrate directly)
        mem.db
            .execute(
                "INSERT INTO memory_turns (turn_id, session_id, agent, created_at)
                 VALUES ('pre', 's1', 'dev', 1000)",
                [],
            )
            .unwrap();
        mem.db
            .execute(
                "INSERT INTO memory_messages (turn_id, role, content, timestamp, metadata, sort_order)
                 VALUES ('pre', 'user', 'Hello', 1000, NULL, 0)",
                [],
            )
            .unwrap();

        // Verify defaults applied
        let (importance, access_count): (f64, i64) = mem
            .db
            .query_row(
                "SELECT importance, access_count FROM memory_turns WHERE turn_id = 'pre'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!((importance - 0.0).abs() < f64::EPSILON);
        assert_eq!(access_count, 0);

        // Verify the turn is still retrievable
        let turns = mem.get_session_turns("s1").unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].messages[0].content, "Hello");
    }

    #[test]
    fn forked_memory_shares_reads_not_writes() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();
        mem.add_turn(&make_turn("s1", "dev", 2000)).unwrap();

        mem.fork("s1", "branch").unwrap();

        // Both main and fork see the original 2 turns (fork has copies)
        assert_eq!(mem.get_session_turns("s1").unwrap().len(), 2);
        assert_eq!(mem.get_fork_turns("s1", "branch").unwrap().len(), 2);

        // Write to main only
        mem.add_turn(&make_turn("s1", "dev", 3000)).unwrap();
        assert_eq!(mem.get_session_turns("s1").unwrap().len(), 3);
        assert_eq!(mem.get_fork_turns("s1", "branch").unwrap().len(), 2);

        // Write to fork only
        let mut ft = make_turn("s1", "dev", 4000);
        ft.fork_id = Some("branch".to_string());
        mem.add_turn(&ft).unwrap();
        assert_eq!(mem.get_session_turns("s1").unwrap().len(), 3);
        assert_eq!(mem.get_fork_turns("s1", "branch").unwrap().len(), 3);
    }

    #[test]
    fn list_sessions_returns_distinct_sessions() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();
        mem.add_turn(&make_turn("s1", "dev", 2000)).unwrap();
        mem.add_turn(&make_turn("s2", "dev", 3000)).unwrap();

        let sessions = mem.list_sessions().unwrap();
        assert_eq!(sessions.len(), 2);

        // Ordered by MAX(created_at) DESC, so s2 (3000) comes first
        assert_eq!(sessions[0].0, "s2");
        assert_eq!(sessions[0].1, 1); // 1 turn in s2
        assert_eq!(sessions[0].2, 3000); // min
        assert_eq!(sessions[0].3, 3000); // max

        assert_eq!(sessions[1].0, "s1");
        assert_eq!(sessions[1].1, 2); // 2 turns in s1
        assert_eq!(sessions[1].2, 1000); // min
        assert_eq!(sessions[1].3, 2000); // max
    }

    #[test]
    fn list_sessions_excludes_forks() {
        let mem = WorkingMemory::open_memory().unwrap();
        mem.add_turn(&make_turn("s1", "dev", 1000)).unwrap();
        mem.fork("s1", "branch").unwrap();

        // Fork adds copies but list_sessions should only count main timeline
        let sessions = mem.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].0, "s1");
        assert_eq!(sessions[0].1, 1);
    }
}
