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

pub use agentic::{AgenticResult, AgenticRetriever, SearchStrategy, SubQuery, decompose_query};
pub use cache::{CacheMetrics, QueryCache, QueryCacheConfig};
pub use chunk::ChunkConfig;
pub use rerank::{load_reranker, ConfidenceGate, CrossEncoderReranker, GatedReranker, NoopReranker, Reranker};
pub use store::{CascadeConfig, ChunkStore};
pub use tools::RagModule;
