//! Knowledge store: persistent key-value entries with FTS5 search.

use crate::error::MemoryError;
use crate::types::{DistilledEntry, MemoryEntry, MemoryType};
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
    /// Borrow the underlying database connection (crate-internal).
    pub(crate) fn db(&self) -> &Connection {
        &self.db
    }

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
        self.migrate_distillation_columns()?;
        Ok(())
    }

    /// Add distillation columns if they don't already exist.
    fn migrate_distillation_columns(&self) -> Result<(), MemoryError> {
        let columns = [
            ("content_key", "TEXT"),
            ("importance", "REAL DEFAULT 0.0"),
            ("access_count", "INTEGER DEFAULT 0"),
            ("last_accessed", "INTEGER DEFAULT 0"),
            ("version", "INTEGER DEFAULT 1"),
            ("source_session", "TEXT DEFAULT ''"),
            ("confidence", "REAL DEFAULT 1.0"),
            ("has_pii", "INTEGER DEFAULT 0"),
            ("consent_basis", "TEXT DEFAULT 'not_set'"),
            ("strategy_generation", "INTEGER DEFAULT 0"),
        ];
        for (name, typ) in &columns {
            // SQLite doesn't support IF NOT EXISTS on ALTER TABLE,
            // so we check the table_info pragma instead.
            let exists: bool = self.db.query_row(
                &format!(
                    "SELECT COUNT(*) > 0 FROM pragma_table_info('memory_knowledge') WHERE name = '{name}'"
                ),
                [],
                |row| row.get(0),
            )?;
            if !exists {
                self.db.execute_batch(&format!(
                    "ALTER TABLE memory_knowledge ADD COLUMN {name} {typ};"
                ))?;
            }
        }
        // Index for content_key lookups.
        self.db.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_knowledge_content_key
                ON memory_knowledge(content_key) WHERE content_key IS NOT NULL;",
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

    /// Store a distilled entry, upserting by content_key (supersession).
    ///
    /// If an entry with the same content_key exists, its content is updated
    /// and the version is incremented. Otherwise a new entry is inserted.
    pub fn store_distilled(&self, entry: &DistilledEntry) -> Result<(), MemoryError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let tags_json = serde_json::to_string(&entry.tags).unwrap_or_else(|_| "[]".to_string());

        // Check if content_key already exists
        let existing: Option<(String, i64)> = self
            .db
            .query_row(
                "SELECT id, version FROM memory_knowledge WHERE content_key = ?1",
                params![entry.content_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        if let Some((id, version)) = existing {
            self.db.execute(
                "UPDATE memory_knowledge SET
                    title = ?1,
                    content = ?2,
                    tags_json = ?3,
                    updated_at = ?4,
                    version = ?5,
                    confidence = ?6,
                    source_session = ?7
                 WHERE id = ?8",
                params![
                    entry.title,
                    entry.content,
                    tags_json,
                    now,
                    version + 1,
                    entry.confidence,
                    entry.source_session,
                    id,
                ],
            )?;
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            self.db.execute(
                "INSERT INTO memory_knowledge
                    (id, memory_type, title, content, tags_json, created_at,
                     content_key, version, confidence, source_session,
                     importance, access_count, last_accessed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, 0.0, 0, 0)",
                params![
                    id,
                    entry.kind.as_str(),
                    entry.title,
                    entry.content,
                    tags_json,
                    now,
                    entry.content_key,
                    entry.confidence,
                    entry.source_session,
                ],
            )?;
        }
        Ok(())
    }

    /// Look up a memory entry by its content-addressed key.
    pub fn query_by_key(&self, content_key: &str) -> Result<Option<MemoryEntry>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT id, memory_type, title, content, tags_json, created_at, updated_at
             FROM memory_knowledge WHERE content_key = ?1",
        )?;
        let mut rows = stmt.query_map(params![content_key], row_to_entry)?;
        match rows.next() {
            Some(entry) => Ok(Some(entry?)),
            None => Ok(None),
        }
    }

    /// Get the version of an entry by content_key. Returns None if not found.
    pub fn version_of(&self, content_key: &str) -> Result<Option<i64>, MemoryError> {
        let result = self.db.query_row(
            "SELECT version FROM memory_knowledge WHERE content_key = ?1",
            params![content_key],
            |row| row.get(0),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Store or update a memory entry with a PII marker.
    ///
    /// Same as `store`, but also sets `has_pii = 1` on the entry so it
    /// can be efficiently queried during purge/expire operations.
    pub fn store_with_pii(&self, entry: &MemoryEntry, has_pii: bool) -> Result<(), MemoryError> {
        let tags_json = serde_json::to_string(&entry.tags).unwrap_or_else(|_| "[]".to_string());
        self.db.execute(
            "INSERT INTO memory_knowledge (id, memory_type, title, content, tags_json, created_at, updated_at, has_pii)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                 title = excluded.title,
                 content = excluded.content,
                 tags_json = excluded.tags_json,
                 updated_at = excluded.updated_at,
                 has_pii = excluded.has_pii",
            params![
                entry.id,
                entry.memory_type.as_str(),
                entry.title,
                entry.content,
                tags_json,
                entry.created_at,
                entry.updated_at,
                has_pii as i32,
            ],
        )?;
        Ok(())
    }

    /// Set the `has_pii` flag on an existing entry.
    pub fn set_pii_flag(&self, id: &str, has_pii: bool) -> Result<(), MemoryError> {
        self.db.execute(
            "UPDATE memory_knowledge SET has_pii = ?1 WHERE id = ?2",
            params![has_pii as i32, id],
        )?;
        Ok(())
    }

    /// Update the content of an existing entry in-place (for redaction).
    pub fn update_content(&self, id: &str, title: &str, content: &str) -> Result<(), MemoryError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.db.execute(
            "UPDATE memory_knowledge SET title = ?1, content = ?2, updated_at = ?3 WHERE id = ?4",
            params![title, content, now, id],
        )?;
        Ok(())
    }

    /// Delete entries older than the specified number of days.
    /// Returns the count of deleted entries.
    pub fn expire_older_than(&self, days: u32) -> Result<usize, MemoryError> {
        let cutoff = Self::days_ago_epoch(days);
        let count = self.db.execute(
            "DELETE FROM memory_knowledge WHERE created_at < ?1",
            params![cutoff],
        )?;
        Ok(count)
    }

    /// Delete entries that have `has_pii = 1` and are older than the
    /// specified number of days. Returns the count of deleted entries.
    pub fn expire_pii_older_than(&self, days: u32) -> Result<usize, MemoryError> {
        let cutoff = Self::days_ago_epoch(days);
        let count = self.db.execute(
            "DELETE FROM memory_knowledge WHERE has_pii = 1 AND created_at < ?1",
            params![cutoff],
        )?;
        Ok(count)
    }

    /// List entries that have the `has_pii` flag set.
    pub fn list_pii_entries(&self, kind: Option<MemoryType>) -> Result<Vec<MemoryEntry>, MemoryError> {
        if let Some(ref mt) = kind {
            let mut stmt = self.db.prepare(
                "SELECT id, memory_type, title, content, tags_json, created_at, updated_at
                 FROM memory_knowledge WHERE has_pii = 1 AND memory_type = ?1
                 ORDER BY created_at DESC",
            )?;
            let entries = stmt
                .query_map(params![mt.as_str()], row_to_entry)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(entries)
        } else {
            let mut stmt = self.db.prepare(
                "SELECT id, memory_type, title, content, tags_json, created_at, updated_at
                 FROM memory_knowledge WHERE has_pii = 1
                 ORDER BY created_at DESC",
            )?;
            let entries = stmt
                .query_map([], row_to_entry)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(entries)
        }
    }

    fn days_ago_epoch(days: u32) -> i64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        now - (days as i64 * 86400)
    }

    /// Set the consent basis for an existing entry.
    ///
    /// Valid values: "legitimate_interest", "consent", "legal_obligation",
    /// "vital_interest", "public_task", "not_set".
    pub fn set_consent_basis(&self, id: &str, basis: &str) -> Result<bool, MemoryError> {
        let count = self.db.execute(
            "UPDATE memory_knowledge SET consent_basis = ?1 WHERE id = ?2",
            params![basis, id],
        )?;
        Ok(count > 0)
    }

    /// Get the consent basis for an entry. Returns None if the entry does not exist.
    pub fn get_consent_basis(&self, id: &str) -> Result<Option<String>, MemoryError> {
        let result = self.db.query_row(
            "SELECT consent_basis FROM memory_knowledge WHERE id = ?1",
            params![id],
            |row| row.get(0),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List entries filtered by consent basis.
    pub fn list_by_consent(&self, basis: &str) -> Result<Vec<MemoryEntry>, MemoryError> {
        let mut stmt = self.db.prepare(
            "SELECT id, memory_type, title, content, tags_json, created_at, updated_at
             FROM memory_knowledge WHERE consent_basis = ?1
             ORDER BY created_at DESC",
        )?;
        let entries = stmt
            .query_map(params![basis], row_to_entry)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    /// Count entries flagged as containing PII.
    pub fn count_pii_entries(&self) -> Result<usize, MemoryError> {
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM memory_knowledge WHERE has_pii = 1", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Full-text search filtered to entries whose tags include ALL of the given tags.
    pub fn search_with_tags(
        &self,
        query: &str,
        required_tags: &[&str],
    ) -> Result<Vec<MemoryEntry>, MemoryError> {
        let all = self.search(query)?;
        Ok(all
            .into_iter()
            .filter(|e| {
                required_tags
                    .iter()
                    .all(|tag| e.tags.iter().any(|t| t == tag))
            })
            .collect())
    }

    /// Get the strategy_generation for an entry by content_key.
    pub fn strategy_generation_of(&self, content_key: &str) -> Result<Option<i64>, MemoryError> {
        let result = self.db.query_row(
            "SELECT strategy_generation FROM memory_knowledge WHERE content_key = ?1",
            params![content_key],
            |row| row.get(0),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Store a distilled entry, incrementing strategy_generation on supersession.
    ///
    /// Like `store_distilled`, but also increments the strategy_generation
    /// counter when an entry with the same content_key is superseded. This
    /// tracks how many times a strategy has evolved (ReasoningBank pattern).
    pub fn store_distilled_with_generation(
        &self,
        entry: &DistilledEntry,
    ) -> Result<i64, MemoryError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let tags_json = serde_json::to_string(&entry.tags).unwrap_or_else(|_| "[]".to_string());

        let existing: Option<(String, i64, i64)> = self
            .db
            .query_row(
                "SELECT id, version, strategy_generation FROM memory_knowledge WHERE content_key = ?1",
                params![entry.content_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();

        if let Some((id, version, gen)) = existing {
            let new_gen = gen + 1;
            self.db.execute(
                "UPDATE memory_knowledge SET
                    title = ?1,
                    content = ?2,
                    tags_json = ?3,
                    updated_at = ?4,
                    version = ?5,
                    confidence = ?6,
                    source_session = ?7,
                    strategy_generation = ?8
                 WHERE id = ?9",
                params![
                    entry.title,
                    entry.content,
                    tags_json,
                    now,
                    version + 1,
                    entry.confidence,
                    entry.source_session,
                    new_gen,
                    id,
                ],
            )?;
            Ok(new_gen)
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            self.db.execute(
                "INSERT INTO memory_knowledge
                    (id, memory_type, title, content, tags_json, created_at,
                     content_key, version, confidence, source_session,
                     importance, access_count, last_accessed, strategy_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, 0.0, 0, 0, 1)",
                params![
                    id,
                    entry.kind.as_str(),
                    entry.title,
                    entry.content,
                    tags_json,
                    now,
                    entry.content_key,
                    entry.confidence,
                    entry.source_session,
                ],
            )?;
            Ok(1)
        }
    }

    /// Update access_count and last_accessed timestamp for an entry.
    pub fn touch(&self, id: &str) -> Result<(), MemoryError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.db.execute(
            "UPDATE memory_knowledge SET
                access_count = access_count + 1,
                last_accessed = ?1
             WHERE id = ?2",
            params![now, id],
        )?;
        Ok(())
    }
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryEntry> {
    let memory_type_str: String = row.get(1)?;
    let tags_json: String = row.get(4)?;
    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
    let memory_type = MemoryType::from_str(&memory_type_str)
        .unwrap_or(MemoryType::Fact);

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

    #[test]
    fn store_distilled_and_query_by_key() {
        let store = KnowledgeStore::open_memory().unwrap();
        let entry = DistilledEntry::new(
            MemoryType::Fact,
            "Rust ownership".to_string(),
            "Rust uses ownership for memory safety".to_string(),
            vec!["rust".to_string()],
            0.9,
            "session-1".to_string(),
        );
        store.store_distilled(&entry).unwrap();

        let retrieved = store.query_by_key(&entry.content_key).unwrap().unwrap();
        assert_eq!(retrieved.title, "Rust ownership");
        assert_eq!(retrieved.content, "Rust uses ownership for memory safety");
    }

    #[test]
    fn supersession_increments_version() {
        let store = KnowledgeStore::open_memory().unwrap();
        let entry = DistilledEntry::new(
            MemoryType::Fact,
            "Favorite color".to_string(),
            "Blue".to_string(),
            vec![],
            0.8,
            "s1".to_string(),
        );
        store.store_distilled(&entry).unwrap();
        assert_eq!(store.version_of(&entry.content_key).unwrap(), Some(1));

        // Store again with same content_key but updated content
        let updated = DistilledEntry {
            content: "Green".to_string(),
            confidence: 0.95,
            source_session: "s2".to_string(),
            ..entry.clone()
        };
        store.store_distilled(&updated).unwrap();
        assert_eq!(store.version_of(&entry.content_key).unwrap(), Some(2));

        // Only one entry should exist
        assert_eq!(store.count().unwrap(), 1);
        let retrieved = store.query_by_key(&entry.content_key).unwrap().unwrap();
        assert_eq!(retrieved.content, "Green");
    }

    #[test]
    fn touch_updates_access() {
        let store = KnowledgeStore::open_memory().unwrap();
        let e = entry("e1", MemoryType::User, "Title", "Content");
        store.store(&e).unwrap();

        // Touch twice
        store.touch("e1").unwrap();
        store.touch("e1").unwrap();

        // Verify access_count via raw query
        let count: i64 = store.db.query_row(
            "SELECT access_count FROM memory_knowledge WHERE id = 'e1'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn store_with_pii_flag() {
        let store = KnowledgeStore::open_memory().unwrap();
        let e = entry("e1", MemoryType::Fact, "PII entry", "Contains email");
        store.store_with_pii(&e, true).unwrap();

        let pii_entries = store.list_pii_entries(None).unwrap();
        assert_eq!(pii_entries.len(), 1);
        assert_eq!(pii_entries[0].id, "e1");
    }

    #[test]
    fn store_without_pii_flag_not_in_pii_list() {
        let store = KnowledgeStore::open_memory().unwrap();
        let e = entry("e1", MemoryType::Fact, "Clean entry", "No PII here");
        store.store_with_pii(&e, false).unwrap();

        let pii_entries = store.list_pii_entries(None).unwrap();
        assert!(pii_entries.is_empty());
    }

    #[test]
    fn set_pii_flag() {
        let store = KnowledgeStore::open_memory().unwrap();
        let e = entry("e1", MemoryType::Fact, "Entry", "Content");
        store.store(&e).unwrap();

        // Initially not PII
        assert!(store.list_pii_entries(None).unwrap().is_empty());

        // Mark as PII
        store.set_pii_flag("e1", true).unwrap();
        assert_eq!(store.list_pii_entries(None).unwrap().len(), 1);

        // Unmark
        store.set_pii_flag("e1", false).unwrap();
        assert!(store.list_pii_entries(None).unwrap().is_empty());
    }

    #[test]
    fn update_content_in_place() {
        let store = KnowledgeStore::open_memory().unwrap();
        let e = entry("e1", MemoryType::Fact, "Original", "Original content");
        store.store(&e).unwrap();

        store.update_content("e1", "Redacted", "[REDACTED]").unwrap();

        let retrieved = store.get("e1").unwrap().unwrap();
        assert_eq!(retrieved.title, "Redacted");
        assert_eq!(retrieved.content, "[REDACTED]");
        assert!(retrieved.updated_at.is_some());
    }

    #[test]
    fn expire_older_than_deletes_old() {
        let store = KnowledgeStore::open_memory().unwrap();
        // Entry from 100 days ago
        let old = MemoryEntry {
            id: "old".to_string(),
            memory_type: MemoryType::Fact,
            title: "Old".to_string(),
            content: "Old stuff".to_string(),
            tags: vec![],
            created_at: KnowledgeStore::days_ago_epoch(100) - 1,
            updated_at: None,
        };
        store.store(&old).unwrap();

        // Recent entry
        let recent = entry("recent", MemoryType::Fact, "Recent", "New stuff");
        let recent = MemoryEntry { created_at: KnowledgeStore::days_ago_epoch(0), ..recent };
        store.store(&recent).unwrap();

        let deleted = store.expire_older_than(90).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.count().unwrap(), 1);
        assert!(store.get("recent").unwrap().is_some());
        assert!(store.get("old").unwrap().is_none());
    }

    #[test]
    fn expire_pii_older_than_only_deletes_pii() {
        let store = KnowledgeStore::open_memory().unwrap();
        let old_ts = KnowledgeStore::days_ago_epoch(40) - 1;

        // Old PII entry
        let pii_entry = MemoryEntry {
            id: "pii".to_string(),
            memory_type: MemoryType::Fact,
            title: "PII".to_string(),
            content: "Has PII".to_string(),
            tags: vec![],
            created_at: old_ts,
            updated_at: None,
        };
        store.store_with_pii(&pii_entry, true).unwrap();

        // Old clean entry
        let clean_entry = MemoryEntry {
            id: "clean".to_string(),
            memory_type: MemoryType::Fact,
            title: "Clean".to_string(),
            content: "No PII".to_string(),
            tags: vec![],
            created_at: old_ts,
            updated_at: None,
        };
        store.store_with_pii(&clean_entry, false).unwrap();

        let deleted = store.expire_pii_older_than(30).unwrap();
        assert_eq!(deleted, 1);
        assert!(store.get("pii").unwrap().is_none());
        assert!(store.get("clean").unwrap().is_some());
    }

    #[test]
    fn list_pii_entries_by_kind() {
        let store = KnowledgeStore::open_memory().unwrap();
        let e1 = entry("e1", MemoryType::Fact, "PII fact", "email");
        store.store_with_pii(&e1, true).unwrap();
        let e2 = entry("e2", MemoryType::Event, "PII event", "phone");
        store.store_with_pii(&e2, true).unwrap();

        let facts = store.list_pii_entries(Some(MemoryType::Fact)).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].id, "e1");

        let all = store.list_pii_entries(None).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn consent_basis_default_is_not_set() {
        let store = KnowledgeStore::open_memory().unwrap();
        let e = entry("e1", MemoryType::Fact, "Title", "Content");
        store.store(&e).unwrap();

        let basis = store.get_consent_basis("e1").unwrap().unwrap();
        assert_eq!(basis, "not_set");
    }

    #[test]
    fn set_and_get_consent_basis() {
        let store = KnowledgeStore::open_memory().unwrap();
        let e = entry("e1", MemoryType::Fact, "Title", "Content");
        store.store(&e).unwrap();

        assert!(store.set_consent_basis("e1", "consent").unwrap());
        assert_eq!(store.get_consent_basis("e1").unwrap().unwrap(), "consent");

        assert!(store.set_consent_basis("e1", "legitimate_interest").unwrap());
        assert_eq!(store.get_consent_basis("e1").unwrap().unwrap(), "legitimate_interest");
    }

    #[test]
    fn set_consent_basis_nonexistent_returns_false() {
        let store = KnowledgeStore::open_memory().unwrap();
        assert!(!store.set_consent_basis("nope", "consent").unwrap());
    }

    #[test]
    fn get_consent_basis_nonexistent_returns_none() {
        let store = KnowledgeStore::open_memory().unwrap();
        assert!(store.get_consent_basis("nope").unwrap().is_none());
    }

    #[test]
    fn list_by_consent() {
        let store = KnowledgeStore::open_memory().unwrap();
        store.store(&entry("e1", MemoryType::Fact, "A", "a")).unwrap();
        store.store(&entry("e2", MemoryType::Fact, "B", "b")).unwrap();
        store.store(&entry("e3", MemoryType::Fact, "C", "c")).unwrap();

        store.set_consent_basis("e1", "consent").unwrap();
        store.set_consent_basis("e2", "consent").unwrap();
        store.set_consent_basis("e3", "legitimate_interest").unwrap();

        let consented = store.list_by_consent("consent").unwrap();
        assert_eq!(consented.len(), 2);

        let legit = store.list_by_consent("legitimate_interest").unwrap();
        assert_eq!(legit.len(), 1);
        assert_eq!(legit[0].id, "e3");

        let not_set = store.list_by_consent("not_set").unwrap();
        assert!(not_set.is_empty());
    }

    #[test]
    fn count_pii_entries() {
        let store = KnowledgeStore::open_memory().unwrap();
        let e1 = entry("e1", MemoryType::Fact, "PII", "email");
        store.store_with_pii(&e1, true).unwrap();
        let e2 = entry("e2", MemoryType::Fact, "Clean", "ok");
        store.store(&e2).unwrap();

        assert_eq!(store.count_pii_entries().unwrap(), 1);
    }
}
