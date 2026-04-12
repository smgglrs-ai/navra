//! Knowledge store: persistent key-value entries with FTS5 search.

use crate::error::MemoryError;
use crate::types::{MemoryEntry, MemoryType};
use rusqlite::{params, Connection};
use std::path::Path;

/// Persistent knowledge memory backed by SQLite with FTS5.
///
/// Stores categorized knowledge entries (user, project, feedback,
/// reference) with full-text search on title and content.
pub struct KnowledgeStore {
    db: Connection,
}

impl KnowledgeStore {
    /// Open knowledge store from a file path.
    pub fn open(path: &Path) -> Result<Self, MemoryError> {
        let db = Connection::open(path)?;
        let store = Self { db };
        store.init_schema()?;
        Ok(store)
    }

    /// Open in-memory knowledge store (for testing).
    pub fn open_memory() -> Result<Self, MemoryError> {
        let db = Connection::open_in_memory()?;
        let store = Self { db };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), MemoryError> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS memory_knowledge (
                id TEXT PRIMARY KEY,
                memory_type TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                tags_json TEXT NOT NULL DEFAULT '[]',
                created_at INTEGER NOT NULL,
                updated_at INTEGER
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS memory_knowledge_fts
                USING fts5(title, content, content=memory_knowledge, content_rowid=rowid);

            CREATE TRIGGER IF NOT EXISTS memory_knowledge_ai AFTER INSERT ON memory_knowledge BEGIN
                INSERT INTO memory_knowledge_fts(rowid, title, content)
                VALUES (new.rowid, new.title, new.content);
            END;

            CREATE TRIGGER IF NOT EXISTS memory_knowledge_ad AFTER DELETE ON memory_knowledge BEGIN
                INSERT INTO memory_knowledge_fts(memory_knowledge_fts, rowid, title, content)
                VALUES ('delete', old.rowid, old.title, old.content);
            END;

            CREATE TRIGGER IF NOT EXISTS memory_knowledge_au AFTER UPDATE ON memory_knowledge BEGIN
                INSERT INTO memory_knowledge_fts(memory_knowledge_fts, rowid, title, content)
                VALUES ('delete', old.rowid, old.title, old.content);
                INSERT INTO memory_knowledge_fts(rowid, title, content)
                VALUES (new.rowid, new.title, new.content);
            END;",
        )?;
        Ok(())
    }

    /// Store or update a memory entry (upsert by id).
    pub fn store(&self, entry: &MemoryEntry) -> Result<(), MemoryError> {
        let tags_json = serde_json::to_string(&entry.tags).unwrap_or_else(|_| "[]".to_string());
        self.db.execute(
            "INSERT INTO memory_knowledge (id, memory_type, title, content, tags_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                 title = excluded.title,
                 content = excluded.content,
                 tags_json = excluded.tags_json,
                 updated_at = excluded.updated_at",
            params![
                entry.id,
                entry.memory_type.as_str(),
                entry.title,
                entry.content,
                tags_json,
                entry.created_at,
                entry.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Get a memory entry by ID.
    pub fn get(&self, id: &str) -> Result<Option<MemoryEntry>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT id, memory_type, title, content, tags_json, created_at, updated_at
             FROM memory_knowledge WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], row_to_entry)?;
        match rows.next() {
            Some(entry) => Ok(Some(entry?)),
            None => Ok(None),
        }
    }

    /// List entries, optionally filtered by type.
    pub fn list(&self, memory_type: Option<MemoryType>) -> Result<Vec<MemoryEntry>, MemoryError> {
        if let Some(ref mt) = memory_type {
            let mut stmt = self.db.prepare(
                "SELECT id, memory_type, title, content, tags_json, created_at, updated_at
                 FROM memory_knowledge WHERE memory_type = ?1
                 ORDER BY created_at DESC",
            )?;
            let entries = stmt
                .query_map(params![mt.as_str()], row_to_entry)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(entries)
        } else {
            let mut stmt = self.db.prepare(
                "SELECT id, memory_type, title, content, tags_json, created_at, updated_at
                 FROM memory_knowledge
                 ORDER BY created_at DESC",
            )?;
            let entries = stmt
                .query_map([], row_to_entry)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(entries)
        }
    }

    /// Full-text search across title and content.
    pub fn search(&self, query: &str) -> Result<Vec<MemoryEntry>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT k.id, k.memory_type, k.title, k.content, k.tags_json, k.created_at, k.updated_at
             FROM memory_knowledge k
             JOIN memory_knowledge_fts f ON k.rowid = f.rowid
             WHERE memory_knowledge_fts MATCH ?1
             ORDER BY rank
             LIMIT 20",
        )?;
        let entries = stmt
            .query_map(params![query], row_to_entry)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    /// Delete an entry by ID. Returns true if an entry was deleted.
    pub fn delete(&self, id: &str) -> Result<bool, MemoryError> {
        let count = self
            .db
            .execute("DELETE FROM memory_knowledge WHERE id = ?1", params![id])?;
        Ok(count > 0)
    }

    /// Count total entries.
    pub fn count(&self) -> Result<usize, MemoryError> {
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM memory_knowledge", [], |row| row.get(0))?;
        Ok(count as usize)
    }
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryEntry> {
    let memory_type_str: String = row.get(1)?;
    let tags_json: String = row.get(4)?;
    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
    let memory_type = MemoryType::from_str(&memory_type_str)
        .unwrap_or(MemoryType::Reference);

    Ok(MemoryEntry {
        id: row.get(0)?,
        memory_type,
        title: row.get(2)?,
        content: row.get(3)?,
        tags,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, mt: MemoryType, title: &str, content: &str) -> MemoryEntry {
        MemoryEntry {
            id: id.to_string(),
            memory_type: mt,
            title: title.to_string(),
            content: content.to_string(),
            tags: vec!["test".to_string()],
            created_at: 1000,
            updated_at: None,
        }
    }

    #[test]
    fn store_and_get() {
        let store = KnowledgeStore::open_memory().unwrap();
        let e = entry("e1", MemoryType::User, "Role", "I am a developer");
        store.store(&e).unwrap();

        let retrieved = store.get("e1").unwrap().unwrap();
        assert_eq!(retrieved.title, "Role");
        assert_eq!(retrieved.content, "I am a developer");
        assert_eq!(retrieved.memory_type, MemoryType::User);
        assert_eq!(retrieved.tags, vec!["test"]);
    }

    #[test]
    fn upsert() {
        let store = KnowledgeStore::open_memory().unwrap();
        store
            .store(&entry("e1", MemoryType::User, "v1", "first"))
            .unwrap();
        store
            .store(&MemoryEntry {
                id: "e1".to_string(),
                memory_type: MemoryType::User,
                title: "v2".to_string(),
                content: "updated".to_string(),
                tags: Vec::new(),
                created_at: 1000,
                updated_at: Some(2000),
            })
            .unwrap();

        let retrieved = store.get("e1").unwrap().unwrap();
        assert_eq!(retrieved.title, "v2");
        assert_eq!(retrieved.content, "updated");
        assert_eq!(retrieved.updated_at, Some(2000));
    }

    #[test]
    fn list_by_type() {
        let store = KnowledgeStore::open_memory().unwrap();
        store
            .store(&entry("u1", MemoryType::User, "User", "user stuff"))
            .unwrap();
        store
            .store(&entry("p1", MemoryType::Project, "Proj", "project stuff"))
            .unwrap();
        store
            .store(&entry("p2", MemoryType::Project, "Proj2", "more project"))
            .unwrap();

        let all = store.list(None).unwrap();
        assert_eq!(all.len(), 3);

        let projects = store.list(Some(MemoryType::Project)).unwrap();
        assert_eq!(projects.len(), 2);

        let users = store.list(Some(MemoryType::User)).unwrap();
        assert_eq!(users.len(), 1);
    }

    #[test]
    fn fts5_search() {
        let store = KnowledgeStore::open_memory().unwrap();
        store
            .store(&entry("e1", MemoryType::Project, "Auth system", "OAuth2 authentication flow"))
            .unwrap();
        store
            .store(&entry("e2", MemoryType::Project, "Database", "PostgreSQL schema design"))
            .unwrap();

        let results = store.search("authentication").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "e1");

        let results = store.search("PostgreSQL").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "e2");
    }

    #[test]
    fn search_no_results() {
        let store = KnowledgeStore::open_memory().unwrap();
        store
            .store(&entry("e1", MemoryType::User, "Hello", "World"))
            .unwrap();

        let results = store.search("nonexistent").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn delete_entry() {
        let store = KnowledgeStore::open_memory().unwrap();
        store
            .store(&entry("e1", MemoryType::User, "X", "Y"))
            .unwrap();

        assert!(store.delete("e1").unwrap());
        assert!(!store.delete("e1").unwrap()); // Already gone
        assert!(store.get("e1").unwrap().is_none());
    }

    #[test]
    fn count() {
        let store = KnowledgeStore::open_memory().unwrap();
        assert_eq!(store.count().unwrap(), 0);

        store
            .store(&entry("e1", MemoryType::User, "A", "B"))
            .unwrap();
        store
            .store(&entry("e2", MemoryType::Project, "C", "D"))
            .unwrap();

        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn get_nonexistent() {
        let store = KnowledgeStore::open_memory().unwrap();
        assert!(store.get("nope").unwrap().is_none());
    }
}
