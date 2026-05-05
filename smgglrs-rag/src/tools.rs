//! RAG module tools for smgglrs.
//!
//! Provides semantic search over chunked documents using vector embeddings.
//! Tools:
//! - `rag_index` — chunk a document, embed chunks, store vectors
//! - `rag_query` — embed a query and find similar chunks (KNN)
//! - `rag_similar` — find documents similar to a given document
//! - `rag_status` — show index statistics

use crate::chunk::{chunk_text, ChunkConfig};
use crate::rerank::{NoopReranker, Reranker};
use crate::store::ChunkStore;
use smgglrs_core::auth::CallContext;
use smgglrs_core::models::ModelBackend;
use smgglrs_core::permissions::{PermissionEngine, PermissionResult};
use smgglrs_core::protocol::{CallToolResult, ToolDefinition, ToolInputSchema};
use smgglrs_core::{Module, ToolHandler};
use std::collections::HashMap;
use std::future::Future;
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
            }),
        }
    }
}

impl Module for RagModule {
    fn name(&self) -> &str {
        "rag"
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        let s = self.state.clone();
        vec![
            make_tool(index_tool_def(), s.clone(), handle_index),
            make_tool(query_tool_def(), s.clone(), handle_query),
            make_tool(similar_tool_def(), s.clone(), handle_similar),
            make_tool(status_tool_def(), s.clone(), handle_status),
        ]
    }
}

fn make_tool<F>(
    def: ToolDefinition,
    state: Arc<RagState>,
    handler: fn(serde_json::Value, CallContext, Arc<RagState>) -> F,
) -> (ToolDefinition, ToolHandler)
where
    F: Future<Output = CallToolResult> + Send + 'static,
{
    let h: ToolHandler = Arc::new(move |args, ctx| {
        let s = state.clone();
        Box::pin(handler(args, ctx, s))
    });
    (def, h)
}

// --- Tool definitions ---

fn index_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "rag_index".to_string(),
        description: Some(
            "Index a document for semantic search. Splits into chunks, \
             generates embeddings, and stores vectors."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!({"type": "string", "description": "Absolute path to document"}),
            )])),
            required: Some(vec!["path".to_string()]),
        },
        annotations: None,
    }
}

fn query_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "rag_query".to_string(),
        description: Some(
            "Semantic search across indexed documents. Finds chunks with \
             similar meaning to the query using vector similarity."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "query".to_string(),
                    serde_json::json!({"type": "string", "description": "Natural language query"}),
                ),
                (
                    "limit".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max results (default 5)", "default": 5}),
                ),
            ])),
            required: Some(vec!["query".to_string()]),
        },
        annotations: None,
    }
}

fn similar_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "rag_similar".to_string(),
        description: Some(
            "Find documents similar to a given document. The document \
             must already be indexed."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Path of indexed document to find similar to"}),
                ),
                (
                    "limit".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max results (default 5)", "default": 5}),
                ),
            ])),
            required: Some(vec!["path".to_string()]),
        },
        annotations: None,
    }
}

fn status_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "rag_status".to_string(),
        description: Some("Show RAG index statistics (document count, chunk count, dimensions).".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: None,
            required: None,
        },
        annotations: None,
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
        &ctx.agent.permissions, op, path, ctx.agent.capabilities.as_ref(),
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

// --- Tool handlers ---

async fn handle_index(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<RagState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path(raw_path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &path) {
        return e;
    }

    if !path.is_file() {
        return CallToolResult::error(format!("Not a file: {}", path.display()));
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => return CallToolResult::error(format!("Failed to read {}: {e}", path.display())),
    };

    // Chunk the document
    let chunks = chunk_text(&content, &state.chunk_config);
    if chunks.is_empty() {
        return CallToolResult::text(format!(
            "No indexable content in {}",
            path.display()
        ));
    }

    // Generate embeddings for each chunk
    let mut embeddings = Vec::with_capacity(chunks.len());
    for chunk in &chunks {
        let request = smgglrs_core::models::EmbedRequest {
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
    let path_str = path.to_string_lossy();
    match state.store.index_document(&path_str, &chunks, &embeddings) {
        Ok(count) => CallToolResult::text(format!(
            "Indexed {} ({} chunks, {} dimensions)",
            path.display(),
            count,
            embeddings.first().map(|e| e.len()).unwrap_or(0),
        )),
        Err(e) => CallToolResult::error(format!("Failed to index {}: {e}", path.display())),
    }
}

async fn handle_query(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<RagState>,
) -> CallToolResult {
    if let Err(e) = check_perm(&state, &ctx, "search", Path::new("/")) {
        return e;
    }

    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) if !q.is_empty() => q,
        _ => return CallToolResult::error("Missing required parameter: query"),
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(5) as usize;

    // Embed the query
    let request = smgglrs_core::models::EmbedRequest {
        text: query.to_string(),
    };
    let embed_response = match state.embedding_model.embed(&request).await {
        Ok(r) => r,
        Err(e) => return CallToolResult::error(format!("Embedding failed: {e}")),
    };

    // Over-fetch when a reranker is active so the cross-encoder has
    // enough candidates to reshuffle.
    let fetch_limit = if state.reranker.is_active() {
        limit * RERANK_OVERFETCH_FACTOR
    } else {
        limit
    };

    // Search for similar chunks (with optional query cache)
    match state.store.cached_search(query, &embed_response.embedding, fetch_limit) {
        Ok(candidates) => {
            if candidates.is_empty() {
                return CallToolResult::text("No results found.");
            }

            // Rerank and truncate to the requested limit
            let results: Vec<_> = state
                .reranker
                .rerank(query, candidates)
                .into_iter()
                .take(limit)
                .collect();

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

async fn handle_similar(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<RagState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(5) as usize;

    let path = match resolve_path(raw_path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &path) {
        return e;
    }

    let path_str = path.to_string_lossy().to_string();
    if !state.store.is_indexed(&path_str).unwrap_or(false) {
        return CallToolResult::error(format!(
            "Document not indexed: {}. Run rag_index first.",
            path.display()
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

async fn handle_status(
    _args: serde_json::Value,
    ctx: CallContext,
    state: Arc<RagState>,
) -> CallToolResult {
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
    use smgglrs_core::auth::AgentIdentity;
    use smgglrs_core::permissions::PathAcl;
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
                operations: ["read", "search"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                requires_approval: HashSet::new(),
            },
        );
        engine
    }

    #[test]
    fn module_provides_all_tools() {
        use smgglrs_core::models::{EmbedRequest, EmbedResponse, ModelBackend, ModelError};

        struct FakeModel;
        impl ModelBackend for FakeModel {
            fn embed(
                &self,
                _req: &EmbedRequest,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<EmbedResponse, ModelError>>
                        + Send
                        + '_,
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
        let module = RagModule::new(store, model, Arc::new(smgglrs_core::permissions::PermissionEngine::new()));

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
        use smgglrs_core::models::{EmbedRequest, EmbedResponse, ModelBackend, ModelError};

        struct FakeModel;
        impl ModelBackend for FakeModel {
            fn embed(
                &self,
                _req: &EmbedRequest,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<EmbedResponse, ModelError>>
                        + Send
                        + '_,
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
        });

        let result = handle_status(serde_json::json!({}), test_ctx(), state).await;
        assert!(!result.is_error);
        match &result.content[0] {
            smgglrs_core::protocol::Content::Text(t) => {
                assert!(t.text.contains("Documents: 0"));
                assert!(t.text.contains("Chunks:    0"));
            }
            _ => panic!("expected text content"),
        }
    }
}
