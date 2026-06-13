//! Retrieval-augmented generation for navra.
//!
//! Hybrid FTS5 + sqlite-vec vector search with RRF fusion, breadcrumb
//! chunking, cross-encoder reranking (batched), and cascading confidence
//! gates. Can run as a standalone MCP server for composable deployment.

pub mod agentic;
pub mod cache;
pub mod chunk;
pub mod rerank;
mod store;
mod tools;

pub use agentic::{
    apply_fts5_negation, classify_strategy, decompose_query, detect_numeric_predicate,
    AgenticResult, AgenticRetriever, NumericOp, NumericPredicate, SearchStrategy, SubQuery,
};
pub use cache::{CacheMetrics, QueryCache, QueryCacheConfig};
pub use chunk::ChunkConfig;
pub use rerank::{
    load_reranker, ConfidenceGate, CrossEncoderReranker, GatedReranker, NoopReranker, Reranker,
};
pub use store::{CascadeConfig, ChunkStore, SearchFilter};
pub use tools::RagModule;
