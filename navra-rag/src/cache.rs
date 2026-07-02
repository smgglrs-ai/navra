//! Semantic query cache for RAG search.
//!
//! Detects paraphrased queries by comparing embedding vectors with cosine
//! similarity. When a new query is semantically close enough to a recently
//! cached query, the cached results are returned without re-running the
//! full vector search pipeline.

use crate::store::ChunkResult;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Configuration for the query cache.
#[derive(Debug, Clone)]
pub struct QueryCacheConfig {
    /// Maximum number of cached entries.
    pub capacity: usize,
    /// Time-to-live for each cache entry.
    pub ttl: Duration,
    /// Minimum cosine similarity to consider a cache hit.
    pub similarity_threshold: f32,
}

impl Default for QueryCacheConfig {
    fn default() -> Self {
        Self {
            capacity: 256,
            ttl: Duration::from_secs(300),
            similarity_threshold: 0.92,
        }
    }
}

/// A single cached query with its embedding and results.
struct CacheEntry {
    /// Original query text (for exact-match fast path).
    query: String,
    /// Embedding vector of the query.
    embedding: Vec<f32>,
    /// Cached search results.
    results: Vec<ChunkResult>,
    /// When this entry was inserted.
    inserted_at: Instant,
}

/// Cache hit/miss metrics.
#[derive(Debug, Clone)]
pub struct CacheMetrics {
    /// Total number of cache lookups.
    pub lookups: u64,
    /// Number of cache hits.
    pub hits: u64,
    /// Current number of entries in the cache.
    pub entries: usize,
    /// Cache capacity.
    pub capacity: usize,
}

impl CacheMetrics {
    /// Hit rate as a fraction (0.0 to 1.0). Returns 0.0 if no lookups.
    pub fn hit_rate(&self) -> f64 {
        if self.lookups == 0 {
            0.0
        } else {
            self.hits as f64 / self.lookups as f64
        }
    }
}

/// Thread-safe semantic query cache.
pub struct QueryCache {
    config: QueryCacheConfig,
    entries: RwLock<Vec<CacheEntry>>,
    lookups: AtomicU64,
    hits: AtomicU64,
}

impl QueryCache {
    /// Create a new query cache with the given configuration.
    pub fn new(config: QueryCacheConfig) -> Self {
        Self {
            entries: RwLock::new(Vec::with_capacity(config.capacity)),
            lookups: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            config,
        }
    }

    /// Look up a query in the cache by comparing its embedding against
    /// cached embeddings using cosine similarity.
    ///
    /// Returns `Some(results)` on a cache hit, `None` on a miss.
    pub fn lookup(&self, query: &str, query_embedding: &[f32]) -> Option<Vec<ChunkResult>> {
        self.lookups.fetch_add(1, Ordering::Relaxed);

        let entries = self.entries.read().unwrap();
        let now = Instant::now();

        let mut best_sim = f32::NEG_INFINITY;
        let mut best_idx = None;

        for (i, entry) in entries.iter().enumerate() {
            // Skip expired entries during lookup
            if now.duration_since(entry.inserted_at) > self.config.ttl {
                continue;
            }

            // Exact text match is an immediate hit
            if entry.query == query {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(entry.results.clone());
            }

            // Compare embeddings
            let sim = cosine_similarity(&entry.embedding, query_embedding);
            if sim > best_sim {
                best_sim = sim;
                best_idx = Some(i);
            }
        }

        if best_sim >= self.config.similarity_threshold
            && let Some(idx) = best_idx
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entries[idx].results.clone());
        }

        None
    }

    /// Insert a query and its results into the cache.
    ///
    /// Evicts expired entries first, then evicts the oldest entry if
    /// the cache is at capacity.
    pub fn insert(&self, query: String, embedding: Vec<f32>, results: Vec<ChunkResult>) {
        let mut entries = self.entries.write().unwrap();
        let now = Instant::now();

        // Evict expired entries
        entries.retain(|e| now.duration_since(e.inserted_at) <= self.config.ttl);

        // Evict oldest if at capacity
        if entries.len() >= self.config.capacity {
            // Find the oldest entry
            if let Some(oldest_idx) = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.inserted_at)
                .map(|(i, _)| i)
            {
                entries.swap_remove(oldest_idx);
            }
        }

        entries.push(CacheEntry {
            query,
            embedding,
            results,
            inserted_at: now,
        });
    }

    /// Get current cache metrics.
    pub fn metrics(&self) -> CacheMetrics {
        let entries = self.entries.read().unwrap();
        CacheMetrics {
            lookups: self.lookups.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            entries: entries.len(),
            capacity: self.config.capacity,
        }
    }

    /// Clear all cached entries and reset metrics.
    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.clear();
        self.lookups.store(0, Ordering::Relaxed);
        self.hits.store(0, Ordering::Relaxed);
    }
}

/// Cosine similarity between two vectors.
///
/// Returns a value in [-1.0, 1.0]. Returns 0.0 if either vector has
/// zero magnitude.
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;

    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }

    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 { 0.0 } else { dot / denom }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache(config: QueryCacheConfig) -> QueryCache {
        QueryCache::new(config)
    }

    fn sample_results() -> Vec<ChunkResult> {
        vec![ChunkResult {
            path: "/doc.md".to_string(),
            content: "sample content".to_string(),
            chunk_index: 0,
            distance: 0.1,
        }]
    }

    #[test]
    fn exact_match_hit() {
        let cache = make_cache(QueryCacheConfig::default());
        let embedding = vec![1.0, 0.0, 0.0, 0.0];
        let results = sample_results();

        cache.insert(
            "hello world".to_string(),
            embedding.clone(),
            results.clone(),
        );

        let hit = cache.lookup("hello world", &embedding);
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.len(), results.len());
        assert_eq!(hit[0].path, "/doc.md");

        let metrics = cache.metrics();
        assert_eq!(metrics.lookups, 1);
        assert_eq!(metrics.hits, 1);
        assert!((metrics.hit_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn similar_query_hit() {
        let config = QueryCacheConfig {
            similarity_threshold: 0.90,
            ..QueryCacheConfig::default()
        };
        let cache = make_cache(config);

        // Cache a query with embedding [1.0, 0.0, 0.0, 0.0]
        let embedding = vec![1.0, 0.0, 0.0, 0.0];
        cache.insert("what is rust".to_string(), embedding, sample_results());

        // Query with a very similar embedding (cosine sim ~0.995)
        let similar_embedding = vec![0.99, 0.1, 0.0, 0.0];
        let hit = cache.lookup("tell me about rust", &similar_embedding);
        assert!(hit.is_some(), "similar query should hit the cache");

        let metrics = cache.metrics();
        assert_eq!(metrics.hits, 1);
    }

    #[test]
    fn dissimilar_query_miss() {
        let cache = make_cache(QueryCacheConfig::default());

        let embedding = vec![1.0, 0.0, 0.0, 0.0];
        cache.insert("what is rust".to_string(), embedding, sample_results());

        // Orthogonal embedding → cosine similarity = 0.0
        let orthogonal = vec![0.0, 1.0, 0.0, 0.0];
        let hit = cache.lookup("how to cook pasta", &orthogonal);
        assert!(hit.is_none(), "dissimilar query should miss the cache");

        let metrics = cache.metrics();
        assert_eq!(metrics.lookups, 1);
        assert_eq!(metrics.hits, 0);
    }

    #[test]
    fn ttl_expiry() {
        let config = QueryCacheConfig {
            ttl: Duration::from_millis(0), // immediate expiry
            ..QueryCacheConfig::default()
        };
        let cache = make_cache(config);

        let embedding = vec![1.0, 0.0, 0.0, 0.0];
        cache.insert("hello".to_string(), embedding.clone(), sample_results());

        // Even an exact text match should miss because TTL is 0ms
        std::thread::sleep(Duration::from_millis(1));
        let hit = cache.lookup("hello", &embedding);
        assert!(hit.is_none(), "expired entry should not be returned");
    }

    #[test]
    fn capacity_eviction() {
        let config = QueryCacheConfig {
            capacity: 2,
            ..QueryCacheConfig::default()
        };
        let cache = make_cache(config);

        // Fill to capacity
        cache.insert(
            "first".to_string(),
            vec![1.0, 0.0, 0.0, 0.0],
            sample_results(),
        );
        cache.insert(
            "second".to_string(),
            vec![0.0, 1.0, 0.0, 0.0],
            sample_results(),
        );
        // This should evict the oldest entry ("first")
        cache.insert(
            "third".to_string(),
            vec![0.0, 0.0, 1.0, 0.0],
            sample_results(),
        );

        let metrics = cache.metrics();
        assert_eq!(metrics.entries, 2, "cache should not exceed capacity");

        // "third" should still be present
        let hit = cache.lookup("third", &[0.0, 0.0, 1.0, 0.0]);
        assert!(hit.is_some());
    }

    #[test]
    fn clear_resets_everything() {
        let cache = make_cache(QueryCacheConfig::default());
        let embedding = vec![1.0, 0.0, 0.0, 0.0];
        cache.insert("hello".to_string(), embedding.clone(), sample_results());
        cache.lookup("hello", &embedding);

        cache.clear();

        let metrics = cache.metrics();
        assert_eq!(metrics.entries, 0);
        assert_eq!(metrics.lookups, 0);
        assert_eq!(metrics.hits, 0);
    }

    #[test]
    fn cosine_similarity_unit_vectors() {
        // Identical vectors
        assert!((cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
        // Orthogonal vectors
        assert!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
        // Opposite vectors
        assert!((cosine_similarity(&[1.0, 0.0], &[-1.0, 0.0]) + 1.0).abs() < 1e-6);
        // Empty vectors
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
        // Mismatched lengths
        assert_eq!(cosine_similarity(&[1.0], &[1.0, 0.0]), 0.0);
    }

    #[test]
    fn metrics_hit_rate_zero_lookups() {
        let cache = make_cache(QueryCacheConfig::default());
        let metrics = cache.metrics();
        assert_eq!(metrics.hit_rate(), 0.0);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn cosine_similarity_zero_magnitude_safe() {
        let a = [0.0f32; 3];
        let b: [f32; 3] = [kani::any(), kani::any(), kani::any()];
        let sim = cosine_similarity(&a, &b);
        assert!(sim == 0.0);
    }

    #[kani::proof]
    fn cosine_similarity_symmetric() {
        let a: [f32; 2] = [kani::any(), kani::any()];
        let b: [f32; 2] = [kani::any(), kani::any()];
        kani::assume(a[0].is_finite() && a[1].is_finite());
        kani::assume(b[0].is_finite() && b[1].is_finite());
        let ab = cosine_similarity(&a, &b);
        let ba = cosine_similarity(&b, &a);
        assert!(ab == ba);
    }
}
