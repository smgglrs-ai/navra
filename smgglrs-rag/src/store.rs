//! SQLite-backed chunk store for RAG vector search.
//!
//! Opens the same database as `smgglrs-mod-docs` IndexStore, adding
//! `chunks` and `chunk_vectors` tables alongside the existing
//! `documents` and `documents_fts` tables.

use crate::cache::{QueryCache, QueryCacheConfig};
use crate::chunk::Chunk;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Once};
use zerocopy::IntoBytes;

/// A search result from chunk search.
///
/// For vector-only search (`search`), `distance` is the vector distance
/// (lower = more similar). For hybrid search (`search_hybrid`), `distance`
/// is repurposed as the RRF fusion score (higher = more relevant).
#[derive(Debug, Clone)]
pub struct ChunkResult {
    /// Path of the source document.
    pub path: String,
    /// Chunk content.
    pub content: String,
    /// Chunk index within the document.
    pub chunk_index: i64,
    /// Similarity score. Semantics depend on search method:
    /// - `search()`: vector distance (lower = more similar)
    /// - `search_hybrid()`: RRF fusion score (higher = more relevant)
    pub distance: f64,
}

/// Index statistics.
#[derive(Debug, Clone)]
pub struct IndexStats {
    /// Total number of indexed documents with chunks.
    pub document_count: i64,
    /// Total number of chunks across all documents.
    pub chunk_count: i64,
    /// Embedding dimensions (0 if not enabled).
    pub dimensions: usize,
}

/// Register sqlite-vec extension.
static INIT_VEC: Once = Once::new();

fn init_sqlite_vec() {
    INIT_VEC.call_once(|| {
        // SAFETY: sqlite3_vec_init has the signature expected by sqlite3_auto_extension
        // (i.e., it is an SQLite extension entry point: `fn(*mut sqlite3, *mut *mut c_char,
        // *const sqlite3_api_routines) -> c_int`). The transmute casts the concrete
        // function pointer to the generic Option<unsafe extern "C" fn()> type required
        // by the SQLite C API. This is the documented way to register compile-time
        // SQLite extensions and is safe as long as the function signature matches the
        // sqlite3_auto_extension ABI contract, which sqlite-vec guarantees.
        unsafe {
            rusqlite::ffi::sqlite3_auto_extension(Some(std::mem::transmute(
                sqlite_vec::sqlite3_vec_init as *const (),
            )));
        }
    });
}

/// SQLite-backed chunk store with vector search.
pub struct ChunkStore {
    conn: Mutex<Connection>,
    dimensions: usize,
    query_cache: Option<Arc<QueryCache>>,
}

impl ChunkStore {
    /// Open or create the chunk store at the given database path.
    ///
    /// This should be the same path as the docs module's index.db
    /// so both modules share one SQLite file.
    pub fn open(db_path: &str, dimensions: usize) -> rusqlite::Result<Self> {
        init_sqlite_vec();
        let path = std::path::Path::new(db_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        let store = Self {
            conn: Mutex::new(conn),
            dimensions,
            query_cache: None,
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory store (for testing).
    pub fn open_memory(dimensions: usize) -> rusqlite::Result<Self> {
        init_sqlite_vec();
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
            dimensions,
            query_cache: None,
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Enable semantic query caching on this store.
    pub fn with_query_cache(mut self, config: QueryCacheConfig) -> Self {
        self.query_cache = Some(Arc::new(QueryCache::new(config)));
        self
    }

    /// Search with optional semantic query caching.
    ///
    /// If caching is enabled, the query embedding is compared against
    /// cached query embeddings. On a cache hit (cosine similarity above
    /// the configured threshold), the cached results are returned
    /// without touching SQLite.
    pub fn cached_search(
        &self,
        query_text: &str,
        query_embedding: &[f32],
        limit: usize,
    ) -> rusqlite::Result<Vec<ChunkResult>> {
        if let Some(ref cache) = self.query_cache {
            if let Some(results) = cache.lookup(query_text, query_embedding) {
                return Ok(results);
            }
        }

        let results = self.search(query_embedding, limit)?;

        if let Some(ref cache) = self.query_cache {
            cache.insert(
                query_text.to_string(),
                query_embedding.to_vec(),
                results.clone(),
            );
        }

        Ok(results)
    }

    /// Get the query cache, if enabled.
    pub fn query_cache(&self) -> Option<&Arc<QueryCache>> {
        self.query_cache.as_ref()
    }

    fn init_schema(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS rag_chunks (
                id          INTEGER PRIMARY KEY,
                path        TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                content     TEXT NOT NULL,
                start_byte  INTEGER NOT NULL,
                end_byte    INTEGER NOT NULL,
                UNIQUE(path, chunk_index)
            );

            CREATE INDEX IF NOT EXISTS idx_rag_chunks_path
                ON rag_chunks(path);
            ",
        )?;

        if self.dimensions > 0 {
            conn.execute_batch(&format!(
                "CREATE VIRTUAL TABLE IF NOT EXISTS rag_chunk_vectors \
                 USING vec0(embedding float[{}])",
                self.dimensions
            ))?;
        }

        conn.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS rag_chunks_fts \
             USING fts5(content, content=rag_chunks, content_rowid=id);

             CREATE TRIGGER IF NOT EXISTS rag_chunks_fts_ai \
             AFTER INSERT ON rag_chunks BEGIN \
                 INSERT INTO rag_chunks_fts(rowid, content) \
                 VALUES (new.id, new.content); \
             END;

             CREATE TRIGGER IF NOT EXISTS rag_chunks_fts_ad \
             AFTER DELETE ON rag_chunks BEGIN \
                 INSERT INTO rag_chunks_fts(rag_chunks_fts, rowid, content) \
                 VALUES ('delete', old.id, old.content); \
             END;

             CREATE TRIGGER IF NOT EXISTS rag_chunks_fts_au \
             AFTER UPDATE ON rag_chunks BEGIN \
                 INSERT INTO rag_chunks_fts(rag_chunks_fts, rowid, content) \
                 VALUES ('delete', old.id, old.content); \
                 INSERT INTO rag_chunks_fts(rowid, content) \
                 VALUES (new.id, new.content); \
             END;",
        )?;

        Ok(())
    }

    /// Index a document: store chunks and their embeddings.
    ///
    /// Removes any previous chunks for this path before inserting.
    pub fn index_document(
        &self,
        path: &str,
        chunks: &[Chunk],
        embeddings: &[Vec<f32>],
    ) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();

        // Remove old chunks for this path
        self.delete_chunks_inner(&conn, path)?;

        let mut count = 0;
        for (chunk, embedding) in chunks.iter().zip(embeddings.iter()) {
            conn.execute(
                "INSERT INTO rag_chunks (path, chunk_index, content, start_byte, end_byte)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    path,
                    chunk.index as i64,
                    chunk.content,
                    chunk.start_byte as i64,
                    chunk.end_byte as i64,
                ],
            )?;

            let chunk_id = conn.last_insert_rowid();

            if self.dimensions > 0 && !embedding.is_empty() {
                conn.execute(
                    "INSERT INTO rag_chunk_vectors(rowid, embedding) VALUES (?1, ?2)",
                    params![chunk_id, embedding.as_bytes()],
                )?;
            }

            count += 1;
        }

        Ok(count)
    }

    /// Search for chunks similar to the query embedding.
    pub fn search(
        &self,
        query_embedding: &[f32],
        limit: usize,
    ) -> rusqlite::Result<Vec<ChunkResult>> {
        if self.dimensions == 0 {
            return Ok(Vec::new());
        }

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT c.path, c.content, c.chunk_index, v.distance
             FROM rag_chunk_vectors v
             JOIN rag_chunks c ON c.id = v.rowid
             WHERE v.embedding MATCH ?1
               AND k = ?2
             ORDER BY v.distance",
        )?;

        let results = stmt
            .query_map(params![query_embedding.as_bytes(), limit as i64], |row| {
                Ok(ChunkResult {
                    path: row.get(0)?,
                    content: row.get(1)?,
                    chunk_index: row.get(2)?,
                    distance: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(results)
    }

    /// Full-text search using FTS5 BM25 ranking.
    fn search_fts(&self, query: &str, limit: usize) -> rusqlite::Result<Vec<ChunkResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT c.path, c.content, c.chunk_index, rank \
             FROM rag_chunks_fts f \
             JOIN rag_chunks c ON c.id = f.rowid \
             WHERE rag_chunks_fts MATCH ?1 \
             ORDER BY rank \
             LIMIT ?2",
        )?;

        // FTS5 rank is negative (more negative = better match).
        let results = stmt
            .query_map(params![query, limit as i64], |row| {
                let rank: f64 = row.get(3)?;
                Ok(ChunkResult {
                    path: row.get(0)?,
                    content: row.get(1)?,
                    chunk_index: row.get(2)?,
                    distance: -rank,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(results)
    }

    /// Hybrid search: FTS5 BM25 + vector similarity, fused with RRF.
    ///
    /// Runs both full-text and vector searches, then combines results
    /// using Reciprocal Rank Fusion (k=60). Returns results sorted by
    /// fused RRF score (highest first).
    pub fn search_hybrid(
        &self,
        query: &str,
        query_embedding: &[f32],
        limit: usize,
    ) -> rusqlite::Result<Vec<ChunkResult>> {
        let k = 60.0_f64;
        let fetch_limit = limit * 3;

        let fts_results = self.search_fts(query, fetch_limit)?;
        let vec_results = self.search(query_embedding, fetch_limit)?;

        let mut scores: HashMap<String, f64> = HashMap::new();
        let mut entries: HashMap<String, ChunkResult> = HashMap::new();

        for (rank, result) in fts_results.into_iter().enumerate() {
            let key = format!("{}:{}", result.path, result.chunk_index);
            *scores.entry(key.clone()).or_insert(0.0) += 1.0 / (k + rank as f64 + 1.0);
            entries.entry(key).or_insert(result);
        }

        for (rank, result) in vec_results.into_iter().enumerate() {
            let key = format!("{}:{}", result.path, result.chunk_index);
            *scores.entry(key.clone()).or_insert(0.0) += 1.0 / (k + rank as f64 + 1.0);
            entries.entry(key).or_insert(result);
        }

        let mut fused: Vec<ChunkResult> = scores
            .into_iter()
            .filter_map(|(key, score)| {
                entries.remove(&key).map(|mut r| {
                    r.distance = score;
                    r
                })
            })
            .collect();
        fused.sort_by(|a, b| {
            b.distance
                .partial_cmp(&a.distance)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        fused.truncate(limit);

        Ok(fused)
    }

    /// Hybrid search with optional semantic query caching.
    pub fn cached_search_hybrid(
        &self,
        query_text: &str,
        query_embedding: &[f32],
        limit: usize,
    ) -> rusqlite::Result<Vec<ChunkResult>> {
        if let Some(ref cache) = self.query_cache {
            if let Some(results) = cache.lookup(query_text, query_embedding) {
                return Ok(results);
            }
        }

        let results = self.search_hybrid(query_text, query_embedding, limit)?;

        if let Some(ref cache) = self.query_cache {
            cache.insert(
                query_text.to_string(),
                query_embedding.to_vec(),
                results.clone(),
            );
        }

        Ok(results)
    }

    /// Find chunks from documents similar to the given document path.
    pub fn find_similar_documents(
        &self,
        path: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<ChunkResult>> {
        if self.dimensions == 0 {
            return Ok(Vec::new());
        }

        let conn = self.conn.lock().unwrap();

        // Get the first chunk's embedding for this document
        let chunk_id: i64 = match conn.query_row(
            "SELECT id FROM rag_chunks WHERE path = ?1 AND chunk_index = 0",
            params![path],
            |row| row.get(0),
        ) {
            Ok(id) => id,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        // Get that chunk's embedding
        let embedding: Vec<u8> = match conn.query_row(
            "SELECT embedding FROM rag_chunk_vectors WHERE rowid = ?1",
            params![chunk_id],
            |row| row.get(0),
        ) {
            Ok(e) => e,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        // Search for similar chunks, excluding the source document.
        // Fetch extra results to account for filtering out the source.
        let fetch_limit = (limit + 10) as i64;
        let mut stmt = conn.prepare(
            "SELECT c.path, c.content, c.chunk_index, v.distance
             FROM rag_chunk_vectors v
             JOIN rag_chunks c ON c.id = v.rowid
             WHERE v.embedding MATCH ?1
               AND k = ?2
             ORDER BY v.distance",
        )?;

        let results: Vec<ChunkResult> = stmt
            .query_map(params![embedding, fetch_limit], |row| {
                Ok(ChunkResult {
                    path: row.get(0)?,
                    content: row.get(1)?,
                    chunk_index: row.get(2)?,
                    distance: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter(|r| r.path != path)
            .take(limit)
            .collect();

        Ok(results)
    }

    /// Remove all chunks for a document.
    pub fn delete_document(&self, path: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        self.delete_chunks_inner(&conn, path)
    }

    fn delete_chunks_inner(&self, conn: &Connection, path: &str) -> rusqlite::Result<bool> {
        if self.dimensions > 0 {
            // Delete embeddings for chunks of this path
            conn.execute(
                "DELETE FROM rag_chunk_vectors WHERE rowid IN \
                 (SELECT id FROM rag_chunks WHERE path = ?1)",
                params![path],
            )?;
        }
        let deleted = conn.execute(
            "DELETE FROM rag_chunks WHERE path = ?1",
            params![path],
        )?;
        Ok(deleted > 0)
    }

    /// Get index statistics.
    pub fn stats(&self) -> rusqlite::Result<IndexStats> {
        let conn = self.conn.lock().unwrap();
        let chunk_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM rag_chunks", [], |row| row.get(0))?;
        let document_count: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT path) FROM rag_chunks",
            [],
            |row| row.get(0),
        )?;

        Ok(IndexStats {
            document_count,
            chunk_count,
            dimensions: self.dimensions,
        })
    }

    /// Check if a document is already indexed.
    pub fn is_indexed(&self, path: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM rag_chunks WHERE path = ?1",
            params![path],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Delete all chunks whose source/document path matches `source_id`.
    ///
    /// This is the cascade entry point for memory erasure: when a
    /// knowledge entry is deleted, call this with the entry's ID to
    /// remove any associated embedding vectors.
    ///
    /// Returns the number of chunks deleted.
    pub fn delete_by_source(&self, source_id: &str) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        if self.dimensions > 0 {
            conn.execute(
                "DELETE FROM rag_chunk_vectors WHERE rowid IN \
                 (SELECT id FROM rag_chunks WHERE path = ?1)",
                params![source_id],
            )?;
        }
        let deleted = conn.execute(
            "DELETE FROM rag_chunks WHERE path = ?1",
            params![source_id],
        )?;
        Ok(deleted)
    }

    /// Delete all chunks whose content contains the given query string.
    ///
    /// Used for right-to-erasure when you need to purge vectors
    /// containing a person's name or other PII, regardless of which
    /// source document they came from.
    ///
    /// Returns the number of chunks deleted.
    pub fn delete_by_content_match(&self, query: &str) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        if self.dimensions > 0 {
            conn.execute(
                "DELETE FROM rag_chunk_vectors WHERE rowid IN \
                 (SELECT id FROM rag_chunks WHERE content LIKE '%' || ?1 || '%')",
                params![query],
            )?;
        }
        let deleted = conn.execute(
            "DELETE FROM rag_chunks WHERE content LIKE '%' || ?1 || '%'",
            params![query],
        )?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> ChunkStore {
        ChunkStore::open_memory(4).unwrap()
    }

    fn sample_chunks() -> Vec<Chunk> {
        vec![
            Chunk {
                content: "First chunk".to_string(),
                start_byte: 0,
                end_byte: 11,
                index: 0,
            },
            Chunk {
                content: "Second chunk".to_string(),
                start_byte: 12,
                end_byte: 24,
                index: 1,
            },
        ]
    }

    fn sample_embeddings() -> Vec<Vec<f32>> {
        vec![vec![1.0, 0.0, 0.0, 0.0], vec![0.0, 1.0, 0.0, 0.0]]
    }

    #[test]
    fn index_and_stats() {
        let store = test_store();
        let count = store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();
        assert_eq!(count, 2);

        let stats = store.stats().unwrap();
        assert_eq!(stats.document_count, 1);
        assert_eq!(stats.chunk_count, 2);
        assert_eq!(stats.dimensions, 4);
    }

    #[test]
    fn reindex_replaces_chunks() {
        let store = test_store();
        store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();

        let new_chunks = vec![Chunk {
            content: "Replacement".to_string(),
            start_byte: 0,
            end_byte: 11,
            index: 0,
        }];
        let new_embeddings = vec![vec![0.0, 0.0, 1.0, 0.0]];
        store
            .index_document("/doc.md", &new_chunks, &new_embeddings)
            .unwrap();

        let stats = store.stats().unwrap();
        assert_eq!(stats.chunk_count, 1);
    }

    #[test]
    fn search_finds_similar() {
        let store = test_store();
        store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();

        let query = vec![0.9, 0.1, 0.0, 0.0]; // close to first chunk
        let results = store.search(&query, 5).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].path, "/doc.md");
        assert_eq!(results[0].chunk_index, 0);
    }

    #[test]
    fn delete_document_removes_chunks() {
        let store = test_store();
        store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();

        assert!(store.delete_document("/doc.md").unwrap());
        assert_eq!(store.stats().unwrap().chunk_count, 0);
    }

    #[test]
    fn is_indexed() {
        let store = test_store();
        assert!(!store.is_indexed("/doc.md").unwrap());

        store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();
        assert!(store.is_indexed("/doc.md").unwrap());
    }

    #[test]
    fn find_similar_documents() {
        let store = test_store();
        store
            .index_document("/a.md", &sample_chunks(), &sample_embeddings())
            .unwrap();

        let other_chunks = vec![Chunk {
            content: "Similar to first".to_string(),
            start_byte: 0,
            end_byte: 16,
            index: 0,
        }];
        let other_embeddings = vec![vec![0.9, 0.1, 0.0, 0.0]]; // close to /a.md chunk 0
        store
            .index_document("/b.md", &other_chunks, &other_embeddings)
            .unwrap();

        let results = store.find_similar_documents("/a.md", 5).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].path, "/b.md");
    }

    #[test]
    fn delete_by_source_removes_chunks_and_vectors() {
        let store = test_store();
        store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();
        assert_eq!(store.stats().unwrap().chunk_count, 2);

        let deleted = store.delete_by_source("/doc.md").unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(store.stats().unwrap().chunk_count, 0);

        // Search should return nothing
        let results = store.search(&[1.0, 0.0, 0.0, 0.0], 5).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn delete_by_source_unknown_returns_zero() {
        let store = test_store();
        store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();

        let deleted = store.delete_by_source("/nonexistent.md").unwrap();
        assert_eq!(deleted, 0);
        // Original chunks untouched
        assert_eq!(store.stats().unwrap().chunk_count, 2);
    }

    #[test]
    fn delete_by_content_match_removes_matching() {
        let store = test_store();
        store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();
        assert_eq!(store.stats().unwrap().chunk_count, 2);

        // Delete only chunks containing "First"
        let deleted = store.delete_by_content_match("First").unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.stats().unwrap().chunk_count, 1);

        // Remaining chunk should be the second one
        let results = store.search(&[0.0, 1.0, 0.0, 0.0], 5).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "Second chunk");
    }

    #[test]
    fn delete_by_content_match_no_match_returns_zero() {
        let store = test_store();
        store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();

        let deleted = store.delete_by_content_match("nonexistent text").unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(store.stats().unwrap().chunk_count, 2);
    }

    #[test]
    fn search_fts_finds_matching_text() {
        let store = test_store();
        store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();

        let results = store.search_fts("First", 5).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "First chunk");
    }

    #[test]
    fn search_fts_empty_index() {
        let store = test_store();
        let results = store.search_fts("anything", 5).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn search_hybrid_combines_channels() {
        let store = test_store();

        let chunks = vec![
            Chunk {
                content: "Rust ownership and borrowing".to_string(),
                start_byte: 0,
                end_byte: 28,
                index: 0,
            },
            Chunk {
                content: "Python garbage collection".to_string(),
                start_byte: 29,
                end_byte: 54,
                index: 1,
            },
        ];
        let embeddings = vec![vec![1.0, 0.0, 0.0, 0.0], vec![0.0, 1.0, 0.0, 0.0]];
        store
            .index_document("/lang.md", &chunks, &embeddings)
            .unwrap();

        // Query text matches "Rust" but embedding is close to second chunk
        let query_embedding = vec![0.1, 0.9, 0.0, 0.0];
        let results = store
            .search_hybrid("Rust", &query_embedding, 5)
            .unwrap();

        assert_eq!(results.len(), 2);
        // Both chunks should appear (one from FTS, one from vector)
    }

    #[test]
    fn search_hybrid_deduplication_boosts_score() {
        let store = test_store();

        let chunks = vec![
            Chunk {
                content: "Rust ownership rules".to_string(),
                start_byte: 0,
                end_byte: 20,
                index: 0,
            },
            Chunk {
                content: "Python memory model".to_string(),
                start_byte: 21,
                end_byte: 40,
                index: 1,
            },
        ];
        let embeddings = vec![vec![1.0, 0.0, 0.0, 0.0], vec![0.0, 1.0, 0.0, 0.0]];
        store
            .index_document("/doc.md", &chunks, &embeddings)
            .unwrap();

        // Query matches "Rust" by text AND embedding is close to first chunk.
        // First chunk should rank higher (matched by both channels).
        let query_embedding = vec![0.95, 0.05, 0.0, 0.0];
        let results = store
            .search_hybrid("Rust", &query_embedding, 5)
            .unwrap();

        assert!(!results.is_empty());
        assert_eq!(results[0].content, "Rust ownership rules");
        // First result has higher RRF score because it appeared in both channels
        if results.len() > 1 {
            assert!(results[0].distance > results[1].distance);
        }
    }

    #[test]
    fn search_hybrid_respects_limit() {
        let store = test_store();

        let mut chunks = Vec::new();
        let mut embeddings = Vec::new();
        for i in 0..10 {
            chunks.push(Chunk {
                content: format!("Chunk number {i} about Rust"),
                start_byte: i * 30,
                end_byte: (i + 1) * 30,
                index: i,
            });
            let mut emb = vec![0.0; 4];
            emb[i % 4] = 1.0;
            embeddings.push(emb);
        }
        store
            .index_document("/big.md", &chunks, &embeddings)
            .unwrap();

        let results = store
            .search_hybrid("Rust", &[1.0, 0.0, 0.0, 0.0], 3)
            .unwrap();
        assert!(results.len() <= 3);
    }

    #[test]
    fn fts_sync_on_delete() {
        let store = test_store();
        store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();

        let results = store.search_fts("First", 5).unwrap();
        assert_eq!(results.len(), 1);

        store.delete_document("/doc.md").unwrap();

        let results = store.search_fts("First", 5).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn fts_sync_on_reindex() {
        let store = test_store();
        store
            .index_document("/doc.md", &sample_chunks(), &sample_embeddings())
            .unwrap();

        let results = store.search_fts("First", 5).unwrap();
        assert_eq!(results.len(), 1);

        // Reindex with different content
        let new_chunks = vec![Chunk {
            content: "Completely new text".to_string(),
            start_byte: 0,
            end_byte: 19,
            index: 0,
        }];
        store
            .index_document("/doc.md", &new_chunks, &[vec![0.5, 0.5, 0.0, 0.0]])
            .unwrap();

        // Old content gone
        let results = store.search_fts("First", 5).unwrap();
        assert!(results.is_empty());

        // New content searchable
        let results = store.search_fts("Completely", 5).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "Completely new text");
    }

    #[test]
    fn delete_by_content_match_across_documents() {
        let store = test_store();
        store
            .index_document("/a.md", &sample_chunks(), &sample_embeddings())
            .unwrap();

        let other_chunks = vec![Chunk {
            content: "First paragraph of another doc".to_string(),
            start_byte: 0,
            end_byte: 30,
            index: 0,
        }];
        let other_embeddings = vec![vec![0.5, 0.5, 0.0, 0.0]];
        store
            .index_document("/b.md", &other_chunks, &other_embeddings)
            .unwrap();

        // Delete all chunks containing "First" across all documents
        let deleted = store.delete_by_content_match("First").unwrap();
        assert_eq!(deleted, 2); // one from /a.md, one from /b.md
        assert_eq!(store.stats().unwrap().chunk_count, 1); // only "Second chunk" remains
    }
}
