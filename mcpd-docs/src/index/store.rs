use rusqlite::{params, Connection};
use std::path::Path;

/// Metadata for an indexed document.
#[derive(Debug, Clone)]
pub struct DocumentMeta {
    pub id: i64,
    pub path: String,
    pub mime_type: String,
    pub size: i64,
    pub modified_at: String,
    pub indexed_at: String,
    pub checksum: String,
}

/// A search result from FTS5.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub path: String,
    pub title: String,
    pub snippet: String,
    pub rank: f64,
}

/// SQLite-backed document index with FTS5.
pub struct IndexStore {
    conn: Connection,
}

impl IndexStore {
    /// Open or create the index database at the given path.
    pub fn open(db_path: &str) -> rusqlite::Result<Self> {
        let path = Path::new(db_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(db_path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS documents (
                id          INTEGER PRIMARY KEY,
                path        TEXT UNIQUE NOT NULL,
                title       TEXT NOT NULL DEFAULT '',
                content     TEXT NOT NULL DEFAULT '',
                mime_type   TEXT NOT NULL,
                size        INTEGER NOT NULL,
                modified_at TEXT NOT NULL,
                indexed_at  TEXT NOT NULL,
                checksum    TEXT NOT NULL
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                path, title, content,
                content=documents,
                content_rowid=id,
                tokenize='porter unicode61'
            );
            ",
        )
    }

    /// Insert or update a document in the index.
    pub fn upsert(
        &self,
        path: &str,
        mime_type: &str,
        size: i64,
        modified_at: &str,
        checksum: &str,
        title: &str,
        content: &str,
    ) -> rusqlite::Result<i64> {
        let now = chrono_now();

        // Delete old FTS entry if exists
        if let Ok(old_id) = self.conn.query_row(
            "SELECT id FROM documents WHERE path = ?1",
            params![path],
            |row| row.get::<_, i64>(0),
        ) {
            self.conn.execute(
                "DELETE FROM documents_fts WHERE rowid = ?1",
                params![old_id],
            )?;
        }

        self.conn.execute(
            "INSERT INTO documents (path, title, content, mime_type, size, modified_at, indexed_at, checksum)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(path) DO UPDATE SET
                 title = excluded.title,
                 content = excluded.content,
                 mime_type = excluded.mime_type,
                 size = excluded.size,
                 modified_at = excluded.modified_at,
                 indexed_at = excluded.indexed_at,
                 checksum = excluded.checksum",
            params![path, title, content, mime_type, size, modified_at, now, checksum],
        )?;

        let id = self.conn.query_row(
            "SELECT id FROM documents WHERE path = ?1",
            params![path],
            |row| row.get::<_, i64>(0),
        )?;

        self.conn.execute(
            "INSERT INTO documents_fts (rowid, path, title, content)
             VALUES (?1, ?2, ?3, ?4)",
            params![id, path, title, content],
        )?;

        Ok(id)
    }

    /// Full-text search.
    pub fn search(&self, query: &str, limit: usize) -> rusqlite::Result<Vec<SearchResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, title, snippet(documents_fts, 2, '<b>', '</b>', '...', 32), rank
             FROM documents_fts
             WHERE documents_fts MATCH ?1
             ORDER BY rank
             LIMIT ?2",
        )?;

        let results = stmt
            .query_map(params![query, limit as i64], |row| {
                Ok(SearchResult {
                    path: row.get(0)?,
                    title: row.get(1)?,
                    snippet: row.get(2)?,
                    rank: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(results)
    }

    /// Get document metadata by path.
    pub fn get_by_path(&self, path: &str) -> rusqlite::Result<Option<DocumentMeta>> {
        let result = self.conn.query_row(
            "SELECT id, path, mime_type, size, modified_at, indexed_at, checksum
             FROM documents WHERE path = ?1",
            params![path],
            |row| {
                Ok(DocumentMeta {
                    id: row.get(0)?,
                    path: row.get(1)?,
                    mime_type: row.get(2)?,
                    size: row.get(3)?,
                    modified_at: row.get(4)?,
                    indexed_at: row.get(5)?,
                    checksum: row.get(6)?,
                })
            },
        );
        match result {
            Ok(meta) => Ok(Some(meta)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Count total indexed documents.
    pub fn count(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM documents", [], |row| row.get(0))
    }

    /// Delete a document from the index.
    pub fn delete(&self, path: &str) -> rusqlite::Result<bool> {
        if let Ok(id) = self.conn.query_row(
            "SELECT id FROM documents WHERE path = ?1",
            params![path],
            |row| row.get::<_, i64>(0),
        ) {
            self.conn.execute(
                "DELETE FROM documents_fts WHERE rowid = ?1",
                params![id],
            )?;
            self.conn
                .execute("DELETE FROM documents WHERE id = ?1", params![id])?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn chrono_now() -> String {
    // Simple ISO 8601 timestamp without chrono dependency
    use std::time::SystemTime;
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    format!("{}", since_epoch.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> IndexStore {
        IndexStore::open_memory().unwrap()
    }

    #[test]
    fn create_schema() {
        let store = test_store();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn upsert_and_get() {
        let store = test_store();
        let id = store
            .upsert(
                "/home/user/doc.md",
                "text/markdown",
                1234,
                "2025-01-01T00:00:00Z",
                "abc123",
                "My Document",
                "This is the content of my document.",
            )
            .unwrap();

        assert!(id > 0);

        let meta = store.get_by_path("/home/user/doc.md").unwrap().unwrap();
        assert_eq!(meta.path, "/home/user/doc.md");
        assert_eq!(meta.mime_type, "text/markdown");
        assert_eq!(meta.size, 1234);
        assert_eq!(meta.checksum, "abc123");
    }

    #[test]
    fn upsert_updates_existing() {
        let store = test_store();
        store
            .upsert("/doc.md", "text/markdown", 100, "t1", "hash1", "v1", "old content")
            .unwrap();
        store
            .upsert("/doc.md", "text/markdown", 200, "t2", "hash2", "v2", "new content")
            .unwrap();

        assert_eq!(store.count().unwrap(), 1);
        let meta = store.get_by_path("/doc.md").unwrap().unwrap();
        assert_eq!(meta.size, 200);
        assert_eq!(meta.checksum, "hash2");
    }

    #[test]
    fn full_text_search() {
        let store = test_store();
        store
            .upsert("/a.md", "text/markdown", 10, "t", "h", "Alpha", "rust programming language")
            .unwrap();
        store
            .upsert("/b.md", "text/markdown", 10, "t", "h", "Beta", "python programming language")
            .unwrap();
        store
            .upsert("/c.md", "text/markdown", 10, "t", "h", "Gamma", "cooking recipes")
            .unwrap();

        let results = store.search("programming", 10).unwrap();
        assert_eq!(results.len(), 2);

        let results = store.search("rust", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "/a.md");

        let results = store.search("cooking", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "/c.md");
    }

    #[test]
    fn search_no_results() {
        let store = test_store();
        store
            .upsert("/a.md", "text/markdown", 10, "t", "h", "Title", "some content")
            .unwrap();

        let results = store.search("nonexistent", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn delete_document() {
        let store = test_store();
        store
            .upsert("/a.md", "text/markdown", 10, "t", "h", "Title", "content")
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);

        assert!(store.delete("/a.md").unwrap());
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.get_by_path("/a.md").unwrap().is_none());

        // Search should also return nothing
        let results = store.search("content", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn delete_nonexistent() {
        let store = test_store();
        assert!(!store.delete("/nope.md").unwrap());
    }

    #[test]
    fn get_nonexistent() {
        let store = test_store();
        assert!(store.get_by_path("/nope.md").unwrap().is_none());
    }
}
