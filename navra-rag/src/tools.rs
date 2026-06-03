//! RAG module tools for navra.
//!
//! Provides semantic search over chunked documents using vector embeddings.
//! Tools:
//! - `rag_index` — chunk a document, embed chunks, store vectors
//! - `rag_query` — embed a query and find similar chunks (KNN)
//! - `rag_similar` — find documents similar to a given document
//! - `rag_status` — show index statistics

use crate::chunk::{chunk_text, predict_chunk_value, ChunkConfig};
use crate::rerank::{NoopReranker, Reranker};
use crate::store::{CascadeConfig, ChunkStore};
use navra_core::auth::CallContext;
use navra_core::models::ModelBackend;
use navra_core::permissions::{PermissionEngine, PermissionResult};
use navra_core::protocol::CallToolResult;
use navra_core::Module;
use navra_macros::tool;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Over-fetch factor for reranking. When a reranker is active, fetch
/// this many times the requested limit from the vector index to give
/// the cross-encoder enough candidates to work with.
const RERANK_OVERFETCH_FACTOR: usize = 4;

/// RAG module for semantic document search.
pub struct RagModule {
    state: Arc<RagState>,
}

struct RagState {
    store: Arc<ChunkStore>,
    embedding_model: Arc<dyn ModelBackend>,
    chunk_config: ChunkConfig,
    perm_engine: Arc<PermissionEngine>,
    reranker: Arc<dyn Reranker>,
    cascade: CascadeConfig,
    metrics: Option<Arc<navra_core::metrics::Metrics>>,
}

impl RagModule {
    /// Create a new RAG module.
    pub fn new(
        store: Arc<ChunkStore>,
        embedding_model: Arc<dyn ModelBackend>,
        perm_engine: Arc<PermissionEngine>,
    ) -> Self {
        Self {
            state: Arc::new(RagState {
                store,
                embedding_model,
                chunk_config: ChunkConfig::default(),
                perm_engine,
                reranker: Arc::new(NoopReranker),
                cascade: CascadeConfig::default(),
                metrics: None,
            }),
        }
    }

    /// Create a RAG module with custom chunk configuration.
    pub fn with_config(
        store: Arc<ChunkStore>,
        embedding_model: Arc<dyn ModelBackend>,
        chunk_config: ChunkConfig,
        perm_engine: Arc<PermissionEngine>,
    ) -> Self {
        Self {
            state: Arc::new(RagState {
                store,
                embedding_model,
                chunk_config,
                perm_engine,
                reranker: Arc::new(NoopReranker),
                cascade: CascadeConfig::default(),
                metrics: None,
            }),
        }
    }

    /// Create a RAG module with a cross-encoder reranker.
    ///
    /// When a reranker is provided, `rag_query` will over-fetch
    /// candidates from the vector index and rerank them with the
    /// cross-encoder before returning the top-N results.
    pub fn with_reranker(
        store: Arc<ChunkStore>,
        embedding_model: Arc<dyn ModelBackend>,
        chunk_config: ChunkConfig,
        perm_engine: Arc<PermissionEngine>,
        reranker: Arc<dyn Reranker>,
    ) -> Self {
        Self {
            state: Arc::new(RagState {
                store,
                embedding_model,
                chunk_config,
                perm_engine,
                reranker,
                cascade: CascadeConfig::default(),
                metrics: None,
            }),
        }
    }

    pub fn with_cascade(mut self, cascade: CascadeConfig) -> Self {
        Arc::get_mut(&mut self.state).unwrap().cascade = cascade;
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<navra_core::metrics::Metrics>) -> Self {
        Arc::get_mut(&mut self.state).unwrap().metrics = Some(metrics);
        self
    }
}

impl Module for RagModule {
    fn name(&self) -> &str {
        "rag"
    }

    fn tools(
        &self,
    ) -> Vec<(
        navra_core::protocol::ToolDefinition,
        navra_core::ToolHandler,
    )> {
        let s = self.state.clone();
        vec![
            handle_index_handler(s.clone()),
            handle_query_handler(s.clone()),
            handle_similar_handler(s.clone()),
            handle_status_handler(s.clone()),
        ]
    }
}

// --- Path helpers ---

fn resolve_path(raw: &str) -> Result<PathBuf, String> {
    let expanded = if raw.starts_with("~/") {
        match dirs::home_dir() {
            Some(home) => home.join(&raw[2..]),
            None => return Err("Cannot resolve home directory".to_string()),
        }
    } else {
        PathBuf::from(raw)
    };

    if !expanded.is_absolute() {
        return Err(format!("Path must be absolute: {raw}"));
    }

    expanded
        .canonicalize()
        .map_err(|e| format!("Cannot resolve path {raw}: {e}"))
}

// --- Permission check ---

fn check_perm(
    state: &RagState,
    ctx: &CallContext,
    op: &str,
    path: &Path,
) -> Result<(), CallToolResult> {
    match state.perm_engine.check_with_capabilities(
        &ctx.agent.permissions,
        op,
        path,
        ctx.agent.capabilities.as_ref(),
    ) {
        PermissionResult::Allowed => Ok(()),
        PermissionResult::DeniedPath => Err(CallToolResult::error(format!(
            "Access denied: {}",
            path.display()
        ))),
        PermissionResult::DeniedOperation => Err(CallToolResult::error(format!(
            "Operation '{}' not permitted for agent '{}'",
            op, ctx.agent.name
        ))),
        PermissionResult::DeniedUnknown => Err(CallToolResult::error(format!(
            "Unknown permission set: {}",
            ctx.agent.permissions
        ))),
        PermissionResult::NeedsApproval => Err(CallToolResult::error(format!(
            "Approval required: {} on {}",
            op,
            path.display()
        ))),
    }
}

// --- Tool implementations ---

#[tool(
    name = "rag_index",
    description = "Index a document for semantic search. Splits into chunks, generates embeddings, and stores vectors."
)]
async fn handle_index(
    #[arg(description = "Absolute path to document")] path: String,
    ctx: CallContext,
    #[state] state: Arc<RagState>,
) -> CallToolResult {
    let resolved = match resolve_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &resolved) {
        return e;
    }

    if !resolved.is_file() {
        return CallToolResult::error(format!("Not a file: {}", resolved.display()));
    }

    let content = match std::fs::read_to_string(&resolved) {
        Ok(c) => c,
        Err(e) => {
            return CallToolResult::error(format!("Failed to read {}: {e}", resolved.display()))
        }
    };

    // Chunk the document
    let mut chunks = chunk_text(&content, &state.chunk_config);
    if chunks.is_empty() {
        return CallToolResult::text(format!("No indexable content in {}", resolved.display()));
    }

    // Graphability filter: skip low-value chunks
    let total_before = chunks.len();
    if let Some(threshold) = state.chunk_config.graphability_threshold {
        chunks.retain(|c| predict_chunk_value(c, &state.chunk_config) >= threshold);
        let skipped = total_before - chunks.len();
        if let Some(ref m) = state.metrics {
            m.rag_chunks_skipped
                .fetch_add(skipped as u64, std::sync::atomic::Ordering::Relaxed);
        }
        if chunks.is_empty() {
            return CallToolResult::text(format!(
                "All {} chunks below graphability threshold in {}",
                total_before,
                resolved.display()
            ));
        }
    }
    if let Some(ref m) = state.metrics {
        m.rag_chunks_indexed
            .fetch_add(chunks.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    // Generate embeddings for each chunk
    let mut embeddings = Vec::with_capacity(chunks.len());
    for chunk in &chunks {
        let request = navra_core::models::EmbedRequest {
            text: chunk.content.clone(),
        };
        match state.embedding_model.embed(&request).await {
            Ok(response) => embeddings.push(response.embedding),
            Err(e) => {
                return CallToolResult::error(format!(
                    "Embedding failed for chunk {}: {e}",
                    chunk.index
                ))
            }
        }
    }

    // Store chunks and embeddings
    let path_str = resolved.to_string_lossy();
    match state.store.index_document(&path_str, &chunks, &embeddings) {
        Ok(count) => CallToolResult::text(format!(
            "Indexed {} ({} chunks, {} dimensions)",
            resolved.display(),
            count,
            embeddings.first().map(|e| e.len()).unwrap_or(0),
        )),
        Err(e) => CallToolResult::error(format!("Failed to index {}: {e}", resolved.display())),
    }
}

#[tool(
    name = "rag_query",
    description = "Semantic search across indexed documents. Finds chunks with similar meaning to the query using vector similarity."
)]
async fn handle_query(
    #[arg(description = "Natural language query")] query: String,
    #[arg(description = "Max results (default 5)", default = "5")] limit: Option<u64>,
    ctx: CallContext,
    #[state] state: Arc<RagState>,
) -> CallToolResult {
    if let Err(e) = check_perm(&state, &ctx, "search", Path::new("/")) {
        return e;
    }

    if query.is_empty() {
        return CallToolResult::error("Missing required parameter: query");
    }

    let limit = limit.unwrap_or(5) as usize;

    // Embed the query
    let request = navra_core::models::EmbedRequest {
        text: query.clone(),
    };
    let embed_response = match state.embedding_model.embed(&request).await {
        Ok(r) => r,
        Err(e) => return CallToolResult::error(format!("Embedding failed: {e}")),
    };

    if let Some(ref m) = state.metrics {
        m.rag_queries_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    let fetch_limit = if state.reranker.is_active() {
        limit * RERANK_OVERFETCH_FACTOR
    } else {
        limit
    };

    // Hybrid search with cascading confidence gates
    match state.store.search_hybrid_cascading(
        &query,
        &embed_response.embedding,
        fetch_limit,
        &state.cascade,
    ) {
        Ok((candidates, vector_skipped, rerank_skipped)) => {
            if let Some(ref m) = state.metrics {
                if vector_skipped {
                    m.rag_vector_skips
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                if rerank_skipped {
                    m.rag_rerank_skips
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }

            if candidates.is_empty() {
                return CallToolResult::text("No results found.");
            }

            let results: Vec<_> = if rerank_skipped || !state.reranker.is_active() {
                candidates.into_iter().take(limit).collect()
            } else {
                state
                    .reranker
                    .rerank(&query, candidates)
                    .into_iter()
                    .take(limit)
                    .collect()
            };

            let mut output = format!("Found {} result(s):\n", results.len());
            for (i, r) in results.iter().enumerate() {
                let preview: String = r.content.chars().take(200).collect();
                output.push_str(&format!(
                    "\n{}. **{}** (chunk {}, distance: {:.4})\n   {}\n",
                    i + 1,
                    r.path,
                    r.chunk_index,
                    r.distance,
                    preview.replace('\n', "\n   "),
                ));
            }
            CallToolResult::text(output)
        }
        Err(e) => CallToolResult::error(format!("Search failed: {e}")),
    }
}

#[tool(
    name = "rag_similar",
    description = "Find documents similar to a given document. The document must already be indexed."
)]
async fn handle_similar(
    #[arg(description = "Path of indexed document to find similar to")] path: String,
    #[arg(description = "Max results (default 5)", default = "5")] limit: Option<u64>,
    ctx: CallContext,
    #[state] state: Arc<RagState>,
) -> CallToolResult {
    let resolved = match resolve_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    let limit = limit.unwrap_or(5) as usize;

    if let Err(e) = check_perm(&state, &ctx, "read", &resolved) {
        return e;
    }

    let path_str = resolved.to_string_lossy().to_string();
    if !state.store.is_indexed(&path_str).unwrap_or(false) {
        return CallToolResult::error(format!(
            "Document not indexed: {}. Run rag_index first.",
            resolved.display()
        ));
    }

    match state.store.find_similar_documents(&path_str, limit) {
        Ok(results) => {
            if results.is_empty() {
                return CallToolResult::text("No similar documents found.");
            }

            let mut output = format!("Found {} similar document(s):\n", results.len());
            for (i, r) in results.iter().enumerate() {
                output.push_str(&format!(
                    "\n{}. {} (distance: {:.4})\n",
                    i + 1,
                    r.path,
                    r.distance,
                ));
            }
            CallToolResult::text(output)
        }
        Err(e) => CallToolResult::error(format!("Search failed: {e}")),
    }
}

#[tool(
    name = "rag_status",
    description = "Show RAG index statistics (document count, chunk count, dimensions)."
)]
async fn handle_status(ctx: CallContext, #[state] state: Arc<RagState>) -> CallToolResult {
    if let Err(e) = check_perm(&state, &ctx, "read", Path::new("/")) {
        return e;
    }

    match state.store.stats() {
        Ok(stats) => CallToolResult::text(format!(
            "RAG Index Status:\n\
             Documents: {}\n\
             Chunks:    {}\n\
             Dimensions: {}",
            stats.document_count, stats.chunk_count, stats.dimensions,
        )),
        Err(e) => CallToolResult::error(format!("Failed to get stats: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_core::auth::AgentIdentity;
    use navra_core::permissions::PathAcl;
    use std::collections::HashSet;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("test", "dev"), "test")
    }

    fn test_perm_engine() -> PermissionEngine {
        let mut engine = PermissionEngine::new();
        engine.add_permission_set(
            "dev".to_string(),
            PathAcl {
                ring: None,
                allow: vec!["/**".to_string()],
                deny: vec![],
                operations: ["read", "search"].into_iter().map(String::from).collect(),
                requires_approval: HashSet::new(),
            },
        );
        engine
    }

    #[test]
    fn module_provides_all_tools() {
        use navra_core::models::{EmbedRequest, EmbedResponse, ModelBackend, ModelError};

        struct FakeModel;
        impl ModelBackend for FakeModel {
            fn embed(
                &self,
                _req: &EmbedRequest,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<EmbedResponse, ModelError>> + Send + '_,
                >,
            > {
                Box::pin(async {
                    Ok(EmbedResponse {
                        embedding: vec![0.0; 4],
                        dimensions: 4,
                    })
                })
            }
        }

        let store = Arc::new(ChunkStore::open_memory(4).unwrap());
        let model: Arc<dyn ModelBackend> = Arc::new(FakeModel);
        let module = RagModule::new(
            store,
            model,
            Arc::new(navra_core::permissions::PermissionEngine::new()),
        );

        assert_eq!(module.name(), "rag");
        let tools = module.tools();
        let names: Vec<_> = tools.iter().map(|(def, _)| def.name.as_str()).collect();
        assert!(names.contains(&"rag_index"));
        assert!(names.contains(&"rag_query"));
        assert!(names.contains(&"rag_similar"));
        assert!(names.contains(&"rag_status"));
        assert_eq!(tools.len(), 4);
    }

    #[tokio::test]
    async fn status_shows_empty_index() {
        use navra_core::models::{EmbedRequest, EmbedResponse, ModelBackend, ModelError};

        struct FakeModel;
        impl ModelBackend for FakeModel {
            fn embed(
                &self,
                _req: &EmbedRequest,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<EmbedResponse, ModelError>> + Send + '_,
                >,
            > {
                Box::pin(async {
                    Ok(EmbedResponse {
                        embedding: vec![0.0; 4],
                        dimensions: 4,
                    })
                })
            }
        }

        let store = Arc::new(ChunkStore::open_memory(4).unwrap());
        let state = Arc::new(RagState {
            store,
            embedding_model: Arc::new(FakeModel),
            chunk_config: ChunkConfig::default(),
            perm_engine: Arc::new(test_perm_engine()),
            reranker: Arc::new(NoopReranker),
            cascade: CascadeConfig::default(),
            metrics: None,
        });

        let (_, handler) = handle_status_handler(state);
        let result = handler(serde_json::json!({}), test_ctx()).await;
        assert!(!result.is_error);
        match &result.content[0] {
            navra_core::protocol::Content::Text(t) => {
                assert!(t.text.contains("Documents: 0"));
                assert!(t.text.contains("Chunks:    0"));
            }
            _ => panic!("expected text content"),
        }
    }

    // --- Pipeline integration tests: reranking + caching ---

    use crate::cache::QueryCacheConfig;
    use crate::store::ChunkResult;
    use navra_core::models::{EmbedRequest, EmbedResponse, ModelBackend, ModelError};
    use std::time::Duration;

    /// A reranker that reverses the order of candidates, for testing.
    struct ReversingReranker;

    impl Reranker for ReversingReranker {
        fn rerank(&self, _query: &str, mut candidates: Vec<ChunkResult>) -> Vec<ChunkResult> {
            candidates.reverse();
            let len = candidates.len();
            for (i, c) in candidates.iter_mut().enumerate() {
                c.distance = -(len as f64 - i as f64);
            }
            candidates
        }

        fn is_active(&self) -> bool {
            true
        }
    }

    /// Fake embedding model that returns a fixed vector per query text.
    struct FixedEmbedModel;

    impl ModelBackend for FixedEmbedModel {
        fn embed(
            &self,
            req: &EmbedRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<EmbedResponse, ModelError>> + Send + '_>,
        > {
            // Hash the query text to a deterministic embedding
            let hash = req.text.len() as f32 / 100.0;
            Box::pin(async move {
                Ok(EmbedResponse {
                    embedding: vec![0.9 + hash * 0.001, 0.1, 0.0, 0.0],
                    dimensions: 4,
                })
            })
        }
    }

    fn make_indexed_store(with_cache: bool) -> Arc<ChunkStore> {
        let store = if with_cache {
            ChunkStore::open_memory(4)
                .unwrap()
                .with_query_cache(QueryCacheConfig {
                    capacity: 100,
                    ttl: Duration::from_secs(300),
                    similarity_threshold: 0.92,
                })
        } else {
            ChunkStore::open_memory(4).unwrap()
        };

        let chunks = vec![
            crate::chunk::Chunk {
                content: "Alpha document about Rust".to_string(),
                start_byte: 0,
                end_byte: 25,
                index: 0,
                breadcrumb: None,
                section_start_byte: None,
                section_end_byte: None,
            },
            crate::chunk::Chunk {
                content: "Beta document about Python".to_string(),
                start_byte: 26,
                end_byte: 52,
                index: 1,
                breadcrumb: None,
                section_start_byte: None,
                section_end_byte: None,
            },
            crate::chunk::Chunk {
                content: "Gamma document about Go".to_string(),
                start_byte: 53,
                end_byte: 76,
                index: 2,
                breadcrumb: None,
                section_start_byte: None,
                section_end_byte: None,
            },
        ];
        let embeddings = vec![
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
        ];
        store
            .index_document("/test.md", &chunks, &embeddings)
            .unwrap();

        Arc::new(store)
    }

    #[tokio::test]
    async fn query_with_reversing_reranker_changes_order() {
        let store = make_indexed_store(false);

        let state = Arc::new(RagState {
            store,
            embedding_model: Arc::new(FixedEmbedModel),
            chunk_config: ChunkConfig::default(),
            perm_engine: Arc::new(test_perm_engine()),
            reranker: Arc::new(ReversingReranker),
            cascade: CascadeConfig::default(),
            metrics: None,
        });

        let (_, handler) = handle_query_handler(state);
        let result = handler(
            serde_json::json!({"query": "test query", "limit": 3}),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            navra_core::protocol::Content::Text(t) => {
                // The reversing reranker should put the last vector-search
                // result first. With our fixed embedding close to [1,0,0,0],
                // the original order is Alpha, Beta, Gamma. Reversed: Gamma first.
                let gamma_pos = t.text.find("Gamma").expect("Gamma should appear");
                let alpha_pos = t.text.find("Alpha").expect("Alpha should appear");
                assert!(
                    gamma_pos < alpha_pos,
                    "Reversing reranker should put Gamma before Alpha"
                );
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn query_without_reranker_preserves_vector_order() {
        let store = make_indexed_store(false);

        let state = Arc::new(RagState {
            store,
            embedding_model: Arc::new(FixedEmbedModel),
            chunk_config: ChunkConfig::default(),
            perm_engine: Arc::new(test_perm_engine()),
            reranker: Arc::new(NoopReranker),
            cascade: CascadeConfig::default(),
            metrics: None,
        });

        let (_, handler) = handle_query_handler(state);
        let result = handler(
            serde_json::json!({"query": "test query", "limit": 3}),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            navra_core::protocol::Content::Text(t) => {
                // With noop reranker and embedding close to [1,0,0,0],
                // Alpha (embedding [1,0,0,0]) should come first.
                let alpha_pos = t.text.find("Alpha").expect("Alpha should appear");
                let gamma_pos = t.text.find("Gamma").expect("Gamma should appear");
                assert!(
                    alpha_pos < gamma_pos,
                    "Without reranker, Alpha should come before Gamma"
                );
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn query_cache_hit_returns_cached_results() {
        let store = make_indexed_store(true);
        let emb = vec![1.0, 0.0, 0.0, 0.0];

        // First query via cached_search — cache miss
        let _ = store.cached_search("test query", &emb, 3).unwrap();
        let cache = store.query_cache().expect("cache should be configured");
        let metrics = cache.metrics();
        assert_eq!(metrics.lookups, 1, "first query should trigger a lookup");
        assert_eq!(metrics.hits, 0, "first query should be a cache miss");

        // Second query with same text — cache hit
        let _ = store.cached_search("test query", &emb, 3).unwrap();
        let metrics = cache.metrics();
        assert_eq!(metrics.lookups, 2, "second query should trigger a lookup");
        assert_eq!(metrics.hits, 1, "second query should be a cache hit");
    }

    #[tokio::test]
    async fn query_cache_miss_for_different_queries() {
        let store = make_indexed_store(true);
        let emb1 = vec![1.0, 0.0, 0.0, 0.0];
        let emb2 = vec![0.0, 1.0, 0.0, 0.0];

        let _ = store.cached_search("alpha query", &emb1, 3).unwrap();
        let _ = store.cached_search("beta query", &emb2, 3).unwrap();

        let cache = store.query_cache().expect("cache should be configured");
        let metrics = cache.metrics();
        assert_eq!(metrics.lookups, 2);
        assert!(metrics.entries >= 1, "at least one entry should be cached");
    }

    #[tokio::test]
    async fn reranker_overfetch_factor_applied() {
        // Verify that when a reranker is active, the pipeline fetches more
        // candidates than the requested limit.
        let store = make_indexed_store(false);

        let state = Arc::new(RagState {
            store,
            embedding_model: Arc::new(FixedEmbedModel),
            chunk_config: ChunkConfig::default(),
            perm_engine: Arc::new(test_perm_engine()),
            reranker: Arc::new(ReversingReranker),
            cascade: CascadeConfig::default(),
            metrics: None,
        });

        // Request limit=1, but RERANK_OVERFETCH_FACTOR=4 so it should
        // fetch 4 candidates then return 1 after reranking.
        let (_, handler) = handle_query_handler(state);
        let result = handler(serde_json::json!({"query": "test", "limit": 1}), test_ctx()).await;

        assert!(!result.is_error);
        match &result.content[0] {
            navra_core::protocol::Content::Text(t) => {
                assert!(
                    t.text.contains("Found 1 result"),
                    "Should return exactly 1 result despite overfetching"
                );
            }
            _ => panic!("expected text content"),
        }
    }
}
