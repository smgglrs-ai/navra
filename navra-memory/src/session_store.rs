//! SQLite-backed session store.
//!
//! Implements `SessionBackend` from navra-core, persisting sessions
//! to a SQLite database so they survive server restarts.

use rusqlite::Connection;
use navra_core::auth::AgentIdentity;
use navra_core::ifc::DataLabel;
use navra_core::protocol::label::{Confidentiality, Integrity};
use navra_core::protocol::ClientInfo;
use navra_core::session::{Session, SessionBackend};
use std::sync::Mutex;

use crate::error::MemoryError;

/// SQLite-backed session store. Sessions survive restarts.
pub struct SqliteSessionBackend {
    db: Mutex<Connection>,
}

impl SqliteSessionBackend {
    /// Open or create a session store at the given path.
    pub fn open(path: &std::path::Path) -> Result<Self, MemoryError> {
        let db = Connection::open(path)?;
        let store = Self { db: Mutex::new(db) };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory store (for tests).
    pub fn open_memory() -> Result<Self, MemoryError> {
        let db = Connection::open_in_memory()?;
        let store = Self { db: Mutex::new(db) };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), MemoryError> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                agent_name TEXT NOT NULL,
                agent_permissions TEXT NOT NULL,
                agent_signing_key TEXT,
                agent_did TEXT,
                client_name TEXT NOT NULL,
                client_version TEXT,
                initialized INTEGER NOT NULL DEFAULT 1,
                integrity TEXT NOT NULL DEFAULT 'Trusted',
                confidentiality TEXT NOT NULL DEFAULT 'Public',
                created_at INTEGER NOT NULL,
                last_accessed INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_agent
                ON sessions(agent_name);
            CREATE INDEX IF NOT EXISTS idx_sessions_accessed
                ON sessions(last_accessed);",
        )?;
        Ok(())
    }

    fn now_epoch() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
}

impl SessionBackend for SqliteSessionBackend {
    fn create(&self, session: Session) {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let _ = db.execute(
            "INSERT OR REPLACE INTO sessions
             (id, agent_name, agent_permissions, agent_signing_key, agent_did,
              client_name, client_version, initialized,
              integrity, confidentiality, created_at, last_accessed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                session.id,
                session.agent.name,
                session.agent.permissions,
                session.agent.signing_key,
                session.agent.did,
                session.client_info.name,
                session.client_info.version,
                session.initialized as i32,
                format!("{:?}", session.context_label.integrity),
                format!("{:?}", session.context_label.confidentiality),
                session.created_at,
                session.last_accessed,
            ],
        );
    }

    fn get(&self, id: &str) -> Option<Session> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.query_row(
            "SELECT id, agent_name, agent_permissions, agent_signing_key, agent_did,
                    client_name, client_version, initialized,
                    integrity, confidentiality, created_at, last_accessed
             FROM sessions WHERE id = ?1",
            [id],
            |row| {
                let integrity_str: String = row.get(8)?;
                let conf_str: String = row.get(9)?;
                Ok(Session {
                    id: row.get(0)?,
                    agent: AgentIdentity {
                        name: row.get(1)?,
                        permissions: row.get(2)?,
                        signing_key: row.get(3)?,
                        did: row.get(4)?,
                        capabilities: None,
                    },
                    client_info: ClientInfo {
                        name: row.get(5)?,
                        version: row.get(6)?,
                    },
                    initialized: row.get::<_, i32>(7)? != 0,
                    context_label: DataLabel {
                        integrity: if integrity_str == "Untrusted" {
                            Integrity::Untrusted
                        } else {
                            Integrity::Trusted
                        },
                        confidentiality: match conf_str.as_str() {
                            "Secret" => Confidentiality::Secret,
                            "Sensitive" => Confidentiality::Sensitive,
                            _ => Confidentiality::Public,
                        },
                    },
                    created_at: row.get(10)?,
                    last_accessed: row.get(11)?,
                })
            },
        )
        .ok()
    }

    fn remove(&self, id: &str) -> Option<Session> {
        let session = self.get(id)?;
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let _ = db.execute("DELETE FROM sessions WHERE id = ?1", [id]);
        Some(session)
    }

    fn count(&self) -> usize {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.query_row("SELECT COUNT(*) FROM sessions", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0) as usize
    }

    fn update_context_label(&self, id: &str, label: DataLabel) {
        // Read current label, join, write back
        if let Some(session) = self.get(id) {
            let new_label = session.context_label.join(label);
            let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
            let _ = db.execute(
                "UPDATE sessions SET integrity = ?1, confidentiality = ?2 WHERE id = ?3",
                rusqlite::params![
                    format!("{:?}", new_label.integrity),
                    format!("{:?}", new_label.confidentiality),
                    id,
                ],
            );
        }
    }

    fn context_label(&self, id: &str) -> DataLabel {
        self.get(id)
            .map(|s| s.context_label)
            .unwrap_or(DataLabel::TRUSTED_PUBLIC)
    }

    fn touch(&self, id: &str) {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let _ = db.execute(
            "UPDATE sessions SET last_accessed = ?1 WHERE id = ?2",
            rusqlite::params![Self::now_epoch(), id],
        );
    }

    fn expire(&self, max_age_secs: u64) {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = Self::now_epoch() - max_age_secs as i64;
        let _ = db.execute("DELETE FROM sessions WHERE last_accessed < ?1", [cutoff]);
    }

    fn list_all(&self) -> Vec<Session> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = match db.prepare(
            "SELECT id, agent_name, agent_permissions, agent_signing_key, agent_did,
                    client_name, client_version, initialized,
                    integrity, confidentiality, created_at, last_accessed
             FROM sessions ORDER BY created_at",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], |row| {
            let integrity_str: String = row.get(8)?;
            let conf_str: String = row.get(9)?;
            Ok(Session {
                id: row.get(0)?,
                agent: AgentIdentity {
                    name: row.get(1)?,
                    permissions: row.get(2)?,
                    signing_key: row.get(3)?,
                    did: row.get(4)?,
                    capabilities: None,
                },
                client_info: ClientInfo {
                    name: row.get(5)?,
                    version: row.get(6)?,
                },
                initialized: row.get::<_, i32>(7)? != 0,
                context_label: DataLabel {
                    integrity: if integrity_str == "Untrusted" {
                        Integrity::Untrusted
                    } else {
                        Integrity::Trusted
                    },
                    confidentiality: match conf_str.as_str() {
                        "Secret" => Confidentiality::Secret,
                        "Sensitive" => Confidentiality::Sensitive,
                        _ => Confidentiality::Public,
                    },
                },
                created_at: row.get(10)?,
                last_accessed: row.get(11)?,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(id: &str) -> Session {
        let now = SqliteSessionBackend::now_epoch();
        Session {
            id: id.to_string(),
            agent: AgentIdentity::new("tester", "dev"),
            client_info: ClientInfo {
                name: "test-client".to_string(),
                version: Some("1.0".to_string()),
            },
            initialized: true,
            context_label: DataLabel::TRUSTED_PUBLIC,
            created_at: now,
            last_accessed: now,
        }
    }

    #[test]
    fn create_and_get() {
        let store = SqliteSessionBackend::open_memory().unwrap();
        store.create(test_session("s1"));
        let s = store.get("s1").unwrap();
        assert_eq!(s.id, "s1");
        assert_eq!(s.agent.name, "tester");
        assert_eq!(s.client_info.name, "test-client");
        assert_eq!(s.client_info.version.as_deref(), Some("1.0"));
        assert!(s.initialized);
    }

    #[test]
    fn get_missing() {
        let store = SqliteSessionBackend::open_memory().unwrap();
        assert!(store.get("nope").is_none());
    }

    #[test]
    fn remove_session() {
        let store = SqliteSessionBackend::open_memory().unwrap();
        store.create(test_session("s1"));
        assert_eq!(store.count(), 1);
        let removed = store.remove("s1").unwrap();
        assert_eq!(removed.id, "s1");
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn context_label_persists() {
        let store = SqliteSessionBackend::open_memory().unwrap();
        store.create(test_session("s1"));

        assert_eq!(store.context_label("s1"), DataLabel::TRUSTED_PUBLIC);

        let tainted = DataLabel {
            integrity: Integrity::Untrusted,
            confidentiality: Confidentiality::Public,
        };
        store.update_context_label("s1", tainted);

        let label = store.context_label("s1");
        assert_eq!(label.integrity, Integrity::Untrusted);
        assert_eq!(label.confidentiality, Confidentiality::Public);
    }

    #[test]
    fn expire_old_sessions() {
        let store = SqliteSessionBackend::open_memory().unwrap();
        let mut old = test_session("old");
        old.last_accessed = SqliteSessionBackend::now_epoch() - 7200;
        store.create(old);
        store.create(test_session("fresh"));
        assert_eq!(store.count(), 2);
        store.expire(3600);
        assert_eq!(store.count(), 1);
        assert!(store.get("fresh").is_some());
        assert!(store.get("old").is_none());
    }

    #[test]
    fn touch_updates_last_accessed() {
        let store = SqliteSessionBackend::open_memory().unwrap();
        let mut s = test_session("s1");
        s.last_accessed = 1000;
        store.create(s);

        store.touch("s1");
        let updated = store.get("s1").unwrap();
        assert!(updated.last_accessed > 1000);
    }

    #[test]
    fn count() {
        let store = SqliteSessionBackend::open_memory().unwrap();
        store.create(test_session("a"));
        store.create(test_session("b"));
        store.create(test_session("c"));
        assert_eq!(store.count(), 3);
    }

    #[test]
    fn list_all_returns_all_sessions() {
        let store = SqliteSessionBackend::open_memory().unwrap();
        store.create(test_session("x"));
        store.create(test_session("y"));
        let all = store.list_all();
        assert_eq!(all.len(), 2);
        let ids: std::collections::HashSet<&str> = all.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains("x"));
        assert!(ids.contains("y"));
    }

    #[test]
    fn list_all_empty() {
        let store = SqliteSessionBackend::open_memory().unwrap();
        assert!(store.list_all().is_empty());
    }
}
