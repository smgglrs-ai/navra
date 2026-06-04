//! Standalone RAG server — MCP-compatible vector search service.
//!
//! Runs navra-rag as an independent MCP server that any client can
//! connect to for document indexing and semantic search.
//!
//! ```bash
//! navra-rag --db /path/to/rag.db \
//!           --embedding-url http://localhost:11434/v1 \
//!           --embedding-model granite3.3:8b \
//!           --dimensions 4096 \
//!           --listen 127.0.0.1:9316
//! ```

use clap::Parser;
use navra_core::models::{Locality, OpenAiBackend};
use navra_core::McpServer;
use navra_rag::{CascadeConfig, ChunkConfig, ChunkStore, RagModule};
use navra_core::permissions::PermissionEngine;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "navra-rag", about = "Standalone RAG MCP server")]
struct Args {
    /// SQLite database path for the RAG index.
    #[arg(long, default_value = "rag.db")]
    db: String,

    /// OpenAI-compatible embedding API URL (Ollama, vLLM, etc.).
    #[arg(long, default_value = "http://localhost:11434/v1")]
    embedding_url: String,

    /// Model name for embedding requests.
    #[arg(long, default_value = "granite3.3:8b")]
    embedding_model: String,

    /// Embedding dimensions.
    #[arg(long, default_value = "4096")]
    dimensions: usize,

    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:9316")]
    listen: String,

    /// Graphability threshold (0.0–1.0). Chunks below this are skipped.
    #[arg(long, default_value = "0.3")]
    graphability_threshold: f32,

    /// Allow read access to these paths (glob patterns, comma-separated).
    #[arg(long, default_value = "/**")]
    allow: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    let embedding_model: Arc<dyn navra_core::models::ModelBackend> = Arc::new(OpenAiBackend::new(
        &args.embedding_url,
        &args.embedding_model,
        None,
        Locality::Local,
    ));

    let store = Arc::new(ChunkStore::open(&args.db, args.dimensions)?);
    tracing::info!(db = %args.db, dims = args.dimensions, "RAG store opened");

    let mut perm_engine = PermissionEngine::new();
    let allow_patterns: Vec<String> = args.allow.split(',').map(|s| s.trim().to_string()).collect();
    perm_engine.add_permission_set(
        "readonly".to_string(),
        navra_core::permissions::PathAcl {
            ring: None,
            allow: allow_patterns,
            deny: Vec::new(),
            operations: ["read", "list", "search", "tree", "grep"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            requires_approval: std::collections::HashSet::new(),
        },
    );

    let chunk_config = ChunkConfig {
        graphability_threshold: Some(args.graphability_threshold),
        ..ChunkConfig::default()
    };
    let cascade = CascadeConfig {
        bm25_skip_vector_threshold: Some(0.0000001),
        vector_skip_rerank_threshold: Some(2.0),
    };

    let rag = RagModule::with_config(
        store,
        embedding_model,
        chunk_config,
        Arc::new(perm_engine),
    )
    .with_cascade(cascade);

    let server = Arc::new(
        McpServer::builder()
            .name("navra-rag")
            .version(env!("CARGO_PKG_VERSION"))
            .allow_anonymous()
            .module(rag)
            .build(),
    );

    let tool_count = server.tool_count();
    let router = navra_core::transport::build_router(server);

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(
        listen = %args.listen,
        tools = tool_count,
        "navra-rag server ready"
    );

    let shutdown = async {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Shutting down");
    };

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}
