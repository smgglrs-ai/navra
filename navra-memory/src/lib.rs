//! navra-memory: Persistent agent memory.
//!
//! Two storage layers backed by SQLite:
//! - **Working memory**: Conversation turns that survive sessions
//! - **Knowledge memory**: Categorized entries with FTS5 search
//!
//! # Quick start
//!
//! ```rust,no_run
//! use navra_memory::{WorkingMemory, KnowledgeStore};
//! use std::path::Path;
//!
//! let working = WorkingMemory::open(Path::new("memory.db")).unwrap();
//! let knowledge = KnowledgeStore::open(Path::new("knowledge.db")).unwrap();
//! ```

pub mod audit;
pub mod decay;
pub mod entity_graph;
mod error;
mod knowledge;
pub mod pipeline;
pub mod retrieval;
pub mod session_store;
pub mod temporal;
pub mod tools;
mod types;
mod working;

pub use audit::{
    AuditLog, AuditModelCall, AuditRun, AuditSummary, AuditToolCall, FlowSummary, FlowTaskResult,
};
pub use decay::{cleanup_decayed, effective_score};
pub use entity_graph::{EntityGraph, Relationship};
pub use error::MemoryError;
// Tag/PII sanitization helpers for the memory write path. The
// underlying implementation lives in navra-safety (via navra-core's
// re-export); re-exported here so the server's memory tools can
// gate tags with the rest of the memory API.
pub use knowledge::KnowledgeStore;
pub use navra_core::safety::{sanitize_tags, tags_have_pii, text_has_pii};
pub use pipeline::{
    ContentSanitizer, DistillationPipeline, extract_failure_insight, extract_success_insight,
};
pub use retrieval::{MemoryRetriever, ScoredEntry};
pub use session_store::SqliteSessionBackend;
pub use temporal::{TemporalTree, TreeNode, TreeType};
pub use tools::KnowledgeModule;
pub use types::{
    DistilledEntry, MemoryEntry, MemoryScope, MemoryType, MergeStrategy, Message, Role, Turn,
};
pub use working::WorkingMemory;
