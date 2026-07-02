//! Standalone RAG retrieval service.
//!
//! Provides two HTTP endpoints:
//! - `POST /index` — index a document (chunk, embed, store)
//! - `POST /retrieve` — retrieve relevant chunks for a query
//! - `GET /status` — index statistics
//! - `GET /metrics` — Prometheus counters
//!
//! Consumed as middleware by navra, Rendra, or any HTTP client.
//! Not an MCP server — retrieval is a pipeline stage, not a tool.
//!
//! ```bash
//! navra-rag --db /path/to/rag.db \
//!           --embedding-url http://localhost:11434/v1 \
//!           --embedding-model granite3.3:8b \
//!           --dimensions 4096 \
//!           --listen 127.0.0.1:9316
//! ```

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use navra_mcp::models::{Locality, ModelBackend, OpenAiBackend};
use navra_rag::chunk::{ChunkConfig, inject_breadcrumbs, predict_chunk_value};
use navra_rag::{CascadeConfig, ChunkStore, NoopReranker, Reranker};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "navra-rag", about = "Standalone RAG retrieval service")]
struct Args {
    /// SQLite database path.
    #[arg(long, default_value = "rag.db")]
    db: String,

    /// OpenAI-compatible embedding API URL.
    #[arg(long, default_value = "http://localhost:11434/v1")]
    embedding_url: String,

    /// Model name for embeddings.
    #[arg(long, default_value = "granite3.3:8b")]
    embedding_model: String,

    /// Embedding dimensions.
    #[arg(long, default_value = "4096")]
    dimensions: usize,

    /// Listen address. Use "unix:/path/to/socket" for Unix socket,
    /// or "host:port" for TCP. Defaults to Unix socket under XDG_RUNTIME_DIR.
    #[arg(long)]
    listen: Option<String>,

    /// Graphability threshold (0.0–1.0).
    #[arg(long, default_value = "0.3")]
    graphability_threshold: f32,

    /// Directories to watch for automatic indexing (comma-separated).
    #[arg(long)]
    watch: Option<String>,
}

struct AppState {
    store: Arc<ChunkStore>,
    embedding_model: Arc<dyn ModelBackend>,
    reranker: Arc<dyn Reranker>,
    cascade: CascadeConfig,
    chunk_config: ChunkConfig,
}

#[derive(serde::Deserialize)]
struct IndexRequest {
    path: String,
    content: String,
}

#[derive(serde::Deserialize)]
struct RetrieveRequest {
    query: String,
    #[serde(default = "default_limit")]
    max_results: usize,
    #[serde(default = "default_max_tokens")]
    max_tokens: usize,
}

fn default_limit() -> usize {
    5
}
fn default_max_tokens() -> usize {
    4096
}

#[derive(serde::Serialize)]
struct RetrieveResult {
    path: String,
    content: String,
    score: f64,
    chunk_index: i64,
}

#[derive(serde::Serialize)]
struct RetrieveResponse {
    results: Vec<RetrieveResult>,
    vector_skipped: bool,
    rerank_skipped: bool,
}

#[derive(serde::Serialize)]
struct IndexResponse {
    chunks_indexed: usize,
    chunks_skipped: usize,
}

async fn handle_retrieve(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RetrieveRequest>,
) -> Json<RetrieveResponse> {
    let embed_req = navra_mcp::models::EmbedRequest {
        text: req.query.clone(),
    };
    let embedding = match state.embedding_model.embed(&embed_req).await {
        Ok(r) => r.embedding,
        Err(e) => {
            tracing::error!(error = %e, "Embedding failed");
            return Json(RetrieveResponse {
                results: Vec::new(),
                vector_skipped: false,
                rerank_skipped: false,
            });
        }
    };

    let fetch_limit = if state.reranker.is_active() {
        req.max_results * 4
    } else {
        req.max_results
    };

    let (candidates, vector_skipped, rerank_skipped) = match state.store.search_hybrid_cascading(
        &req.query,
        &embedding,
        fetch_limit,
        &state.cascade,
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Search failed");
            return Json(RetrieveResponse {
                results: Vec::new(),
                vector_skipped: false,
                rerank_skipped: false,
            });
        }
    };

    let ranked = if rerank_skipped || !state.reranker.is_active() {
        candidates
    } else {
        state.reranker.rerank(&req.query, candidates)
    };

    let max_chars = req.max_tokens * 4;
    let mut total_chars = 0;
    let results: Vec<RetrieveResult> = ranked
        .into_iter()
        .take(req.max_results)
        .take_while(|r| {
            total_chars += r.content.len();
            total_chars <= max_chars
        })
        .map(|r| RetrieveResult {
            path: r.path,
            content: r.content,
            score: r.distance,
            chunk_index: r.chunk_index,
        })
        .collect();

    Json(RetrieveResponse {
        results,
        vector_skipped,
        rerank_skipped,
    })
}

async fn handle_index(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IndexRequest>,
) -> Json<IndexResponse> {
    let mut chunks = navra_rag::chunk::chunk_text(&req.content, &state.chunk_config);
    inject_breadcrumbs(&mut chunks, &req.content);

    let total = chunks.len();
    if let Some(threshold) = state.chunk_config.graphability_threshold {
        chunks.retain(|c| predict_chunk_value(c, &state.chunk_config) >= threshold);
    }
    let skipped = total - chunks.len();

    let mut embeddings = Vec::with_capacity(chunks.len());
    for chunk in &chunks {
        let embed_req = navra_mcp::models::EmbedRequest {
            text: chunk.content.clone(),
        };
        match state.embedding_model.embed(&embed_req).await {
            Ok(r) => embeddings.push(r.embedding),
            Err(e) => {
                tracing::error!(chunk = chunk.index, error = %e, "Embedding failed");
                return Json(IndexResponse {
                    chunks_indexed: 0,
                    chunks_skipped: skipped,
                });
            }
        }
    }

    match state.store.index_document(&req.path, &chunks, &embeddings) {
        Ok(count) => Json(IndexResponse {
            chunks_indexed: count,
            chunks_skipped: skipped,
        }),
        Err(e) => {
            tracing::error!(error = %e, "Index failed");
            Json(IndexResponse {
                chunks_indexed: 0,
                chunks_skipped: skipped,
            })
        }
    }
}

async fn handle_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    match state.store.stats() {
        Ok(stats) => Json(serde_json::json!({
            "documents": stats.document_count,
            "chunks": stats.chunk_count,
            "dimensions": stats.dimensions,
        })),
        Err(e) => Json(serde_json::json!({"error": e.to_string()})),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    let embedding_model: Arc<dyn ModelBackend> = Arc::new(OpenAiBackend::new(
        &args.embedding_url,
        &args.embedding_model,
        None,
        Locality::Local,
    ));

    let store = Arc::new(ChunkStore::open(&args.db, args.dimensions)?);
    tracing::info!(db = %args.db, dims = args.dimensions, "RAG store opened");

    let state = Arc::new(AppState {
        store,
        embedding_model,
        reranker: Arc::new(NoopReranker),
        cascade: CascadeConfig {
            bm25_skip_vector_threshold: Some(0.0000001),
            vector_skip_rerank_threshold: Some(2.0),
        },
        chunk_config: ChunkConfig {
            graphability_threshold: Some(args.graphability_threshold),
            ..ChunkConfig::default()
        },
    });

    let router = Router::new()
        .route("/retrieve", post(handle_retrieve))
        .route("/index", post(handle_index))
        .route("/status", get(handle_status))
        .with_state(state);

    let listen = args.listen.unwrap_or_else(|| {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
        format!("unix:{runtime_dir}/navra/rag.sock")
    });

    let shutdown = async {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Shutting down");
    };

    if let Some(path) = listen.strip_prefix("unix:") {
        let path = std::path::Path::new(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        // Remove stale socket
        std::fs::remove_file(path).ok();
        let listener = tokio::net::UnixListener::bind(path)?;
        tracing::info!(socket = %path.display(), "navra-rag retrieval service ready (Unix socket)");
        axum::serve(listener, router.into_make_service())
            .with_graceful_shutdown(shutdown)
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&listen).await?;
        tracing::info!(listen = %listen, "navra-rag retrieval service ready (TCP)");
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await?;
    }

    Ok(())
}
