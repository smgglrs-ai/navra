//! Retrieval with RRF fusion across multiple channels.
//!
//! Channels:
//! - FTS5: full-text search on title + content
//! - Key: exact content_key lookup
//! - Vector: semantic similarity (stub — returns empty)
//! - HyDE: hypothetical document embeddings (stub — returns empty)

use crate::error::MemoryError;
use crate::knowledge::KnowledgeStore;
use crate::types::MemoryEntry;
use std::collections::HashMap;

/// A scored retrieval result.
#[derive(Debug, Clone)]
pub struct ScoredEntry {
    pub entry: MemoryEntry,
    pub score: f64,
}

/// Multi-channel retriever with Reciprocal Rank Fusion.
pub struct MemoryRetriever<'a> {
    store: &'a KnowledgeStore,
}

impl<'a> MemoryRetriever<'a> {
    pub fn new(store: &'a KnowledgeStore) -> Self {
        Self { store }
    }

    /// Retrieve top-N entries by fusing results from all channels with RRF.
    ///
    /// RRF score = sum(1 / (k + rank)) across channels, where k = 60.
    pub fn retrieve(&self, query: &str, top_n: usize) -> Result<Vec<ScoredEntry>, MemoryError> {
        let k = 60.0_f64;

        // Channel 1: FTS5
        let fts_results = self.store.search(query)?;
        // Channel 2: exact key lookup (treat query as potential content_key)
        let key_results = self.channel_key(query)?;
        // Channel 3: vector (stub)
        let vector_results = self.channel_vector(query)?;
        // Channel 4: HyDE (stub)
        let hyde_results = self.channel_hyde(query)?;

        // Collect all channels: Vec<Vec<MemoryEntry>>
        let channels: Vec<Vec<MemoryEntry>> =
            vec![fts_results, key_results, vector_results, hyde_results];

        // Fuse with RRF: accumulate scores by entry id, keep first entry seen.
        let mut scores: HashMap<String, f64> = HashMap::new();
        let mut entries: HashMap<String, MemoryEntry> = HashMap::new();

        for channel in &channels {
            for (rank, entry) in channel.iter().enumerate() {
                let rrf_score = 1.0 / (k + rank as f64 + 1.0);
                *scores.entry(entry.id.clone()).or_insert(0.0) += rrf_score;
                entries.entry(entry.id.clone()).or_insert_with(|| entry.clone());
            }
        }

        // Sort by descending score
        let mut results: Vec<ScoredEntry> = scores
            .into_iter()
            .filter_map(|(id, score)| {
                entries.remove(&id).map(|entry| ScoredEntry { entry, score })
            })
            .collect();
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(top_n);

        Ok(results)
    }

    fn channel_key(&self, query: &str) -> Result<Vec<MemoryEntry>, MemoryError> {
        match self.store.query_by_key(query) {
            Ok(Some(entry)) => Ok(vec![entry]),
            Ok(None) => Ok(vec![]),
            Err(e) => Err(e),
        }
    }

    /// Stub: vector similarity channel. Returns empty until embeddings are wired.
    fn channel_vector(&self, _query: &str) -> Result<Vec<MemoryEntry>, MemoryError> {
        Ok(vec![])
    }

    /// Stub: HyDE channel. Returns empty until model backend is wired.
    fn channel_hyde(&self, _query: &str) -> Result<Vec<MemoryEntry>, MemoryError> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MemoryType;

    fn make_entry(id: &str, title: &str, content: &str) -> MemoryEntry {
        MemoryEntry {
            id: id.to_string(),
            memory_type: MemoryType::Fact,
            title: title.to_string(),
            content: content.to_string(),
            tags: vec![],
            created_at: 1000,
            updated_at: None,
        }
    }

    #[test]
    fn rrf_fusion_merges_channels() {
        let store = KnowledgeStore::open_memory().unwrap();
        // Insert entries that will appear in FTS
        store.store(&make_entry("e1", "Rust language", "Rust is a systems programming language")).unwrap();
        store.store(&make_entry("e2", "Rust ownership", "Ownership model in Rust")).unwrap();
        store.store(&make_entry("e3", "Python language", "Python is interpreted")).unwrap();

        let retriever = MemoryRetriever::new(&store);
        let results = retriever.retrieve("Rust", 10).unwrap();

        // Should find the two Rust entries
        assert!(results.len() >= 2);
        // Scores should be positive
        for r in &results {
            assert!(r.score > 0.0);
        }
    }

    #[test]
    fn rrf_returns_empty_for_no_matches() {
        let store = KnowledgeStore::open_memory().unwrap();
        let retriever = MemoryRetriever::new(&store);
        let results = retriever.retrieve("nonexistent", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn rrf_respects_top_n() {
        let store = KnowledgeStore::open_memory().unwrap();
        for i in 0..10 {
            store.store(&make_entry(
                &format!("e{i}"),
                &format!("Topic {i} about testing"),
                &format!("Content about testing number {i}"),
            )).unwrap();
        }

        let retriever = MemoryRetriever::new(&store);
        let results = retriever.retrieve("testing", 3).unwrap();
        assert!(results.len() <= 3);
    }
}
