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
