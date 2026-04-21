//! Memory decay: score entries by recency and archive stale ones.

use crate::error::MemoryError;
use crate::knowledge::KnowledgeStore;
use rusqlite::params;

/// Compute the effective score of a memory entry.
///
/// Uses exponential decay on importance, boosted by access frequency:
///   score = importance * e^(-decay_rate * age_hours) + relevance_boost
/// where relevance_boost = min(access_count * 0.1, 0.3).
pub fn effective_score(importance: f64, age_hours: f64, access_count: u32, decay_rate: f64) -> f64 {
    let relevance_boost = (access_count as f64 * 0.1).min(0.3);
    importance * (-decay_rate * age_hours).exp() + relevance_boost
}

/// Archive entries whose effective_score falls below `threshold`.
///
/// Archived entries are moved to a `memory_archive` table (created if
/// it does not exist). Returns the number of entries archived.
pub fn cleanup_decayed(store: &KnowledgeStore, threshold: f64) -> Result<u32, MemoryError> {
    let db = store.db();

    // Create archive table if needed.
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS memory_archive (
            id TEXT PRIMARY KEY,
            memory_type TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            tags_json TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL,
            updated_at INTEGER,
            content_key TEXT,
            importance REAL DEFAULT 0.0,
            access_count INTEGER DEFAULT 0,
            last_accessed INTEGER DEFAULT 0,
            version INTEGER DEFAULT 1,
            source_session TEXT DEFAULT '',
            confidence REAL DEFAULT 1.0,
            archived_at INTEGER NOT NULL
        )",
    )?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Fetch candidates with decay-relevant columns.
    let mut stmt = db.prepare(
        "SELECT id, importance, created_at, access_count FROM memory_knowledge",
    )?;

    let candidates: Vec<(String, f64)> = stmt
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let importance: f64 = row.get(1)?;
            let created_at: i64 = row.get(2)?;
            let access_count: i64 = row.get(3)?;
            let age_hours = (now_secs - created_at).max(0) as f64 / 3600.0;
            let score = effective_score(importance, age_hours, access_count as u32, 0.001);
            Ok((id, score))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut archived = 0u32;
    for (id, score) in &candidates {
        if *score < threshold {
            // Move to archive.
            db.execute(
                "INSERT OR REPLACE INTO memory_archive
                    (id, memory_type, title, content, tags_json, created_at, updated_at,
                     content_key, importance, access_count, last_accessed,
                     version, source_session, confidence, archived_at)
                 SELECT id, memory_type, title, content, tags_json, created_at, updated_at,
                        content_key, importance, access_count, last_accessed,
                        version, source_session, confidence, ?1
                 FROM memory_knowledge WHERE id = ?2",
                params![now_secs, id],
            )?;
            db.execute("DELETE FROM memory_knowledge WHERE id = ?1", params![id])?;
            archived += 1;
        }
    }

    Ok(archived)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MemoryEntry, MemoryType};

    #[test]
    fn fresh_entry_score_near_one() {
        let score = effective_score(1.0, 0.0, 0, 0.001);
        assert!(
            (score - 1.0).abs() < 0.01,
            "fresh entry with importance=1.0 should score ~1.0, got {score}"
        );
    }

    #[test]
    fn old_entry_score_lower() {
        let fresh = effective_score(0.5, 0.0, 0, 0.001);
        let old = effective_score(0.5, 720.0, 0, 0.001);
        assert!(
            old < fresh,
            "30-day-old entry ({old}) should score lower than fresh ({fresh})"
        );
        // 0.5 * e^(-0.72) ≈ 0.244
        assert!(old < 0.3, "old entry should have decayed significantly, got {old}");
    }

    #[test]
    fn access_count_boosts_score() {
        let no_access = effective_score(0.5, 720.0, 0, 0.001);
        let with_access = effective_score(0.5, 720.0, 5, 0.001);
        assert!(
            with_access > no_access,
            "access_count should boost score: {with_access} > {no_access}"
        );
    }

    #[test]
    fn relevance_boost_caps_at_0_3() {
        let score_10 = effective_score(0.0, 0.0, 10, 0.001);
        let score_100 = effective_score(0.0, 0.0, 100, 0.001);
        assert!(
            (score_10 - 0.3).abs() < f64::EPSILON,
            "boost should cap at 0.3 with 10 accesses, got {score_10}"
        );
        assert!(
            (score_100 - 0.3).abs() < f64::EPSILON,
            "boost should cap at 0.3 with 100 accesses, got {score_100}"
        );
    }

    #[test]
    fn cleanup_decayed_archives_below_threshold() {
        let store = KnowledgeStore::open_memory().unwrap();

        // Insert two entries: one with high importance, one with zero.
        let high = MemoryEntry {
            id: "high".to_string(),
            memory_type: MemoryType::Fact,
            title: "Important".to_string(),
            content: "Very important fact".to_string(),
            tags: vec![],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            updated_at: None,
        };
        store.store(&high).unwrap();
        // Set importance high via raw SQL.
        store
            .db()
            .execute(
                "UPDATE memory_knowledge SET importance = 1.0 WHERE id = 'high'",
                [],
            )
            .unwrap();

        let low = MemoryEntry {
            id: "low".to_string(),
            memory_type: MemoryType::Fact,
            title: "Trivial".to_string(),
            content: "Not important".to_string(),
            tags: vec![],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            updated_at: None,
        };
        store.store(&low).unwrap();
        // importance stays 0.0 (default)

        // threshold 0.5 should archive the low-importance entry
        let archived = cleanup_decayed(&store, 0.5).unwrap();
        assert_eq!(archived, 1);

        // "high" should still be in the main table
        assert!(store.get("high").unwrap().is_some());
        // "low" should be gone from main table
        assert!(store.get("low").unwrap().is_none());

        // "low" should exist in archive
        let in_archive: bool = store
            .db()
            .query_row(
                "SELECT COUNT(*) > 0 FROM memory_archive WHERE id = 'low'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(in_archive, "low-importance entry should be in archive");
    }
}
