//! smgglrs-memory: Persistent agent memory.
//!
//! Two storage layers backed by SQLite:
//! - **Working memory**: Conversation turns that survive sessions
//! - **Knowledge memory**: Categorized entries with FTS5 search
//!
//! # Quick start
//!
//! ```rust,no_run
//! use smgglrs_memory::{WorkingMemory, KnowledgeStore};
//! use std::path::Path;
//!
//! let working = WorkingMemory::open(Path::new("memory.db")).unwrap();
//! let knowledge = KnowledgeStore::open(Path::new("knowledge.db")).unwrap();
//! ```

pub mod audit;
pub mod decay;
mod error;
mod knowledge;
pub mod pipeline;
pub mod retrieval;
pub mod session_store;
mod types;
mod working;

pub use error::MemoryError;
pub use knowledge::KnowledgeStore;
pub use pipeline::{
    extract_failure_insight, extract_success_insight, ContentSanitizer, DistillationPipeline,
};
pub use retrieval::{MemoryRetriever, ScoredEntry};
pub use session_store::SqliteSessionBackend;
pub use types::{DistilledEntry, MemoryEntry, MemoryType, MergeStrategy, Message, Role, Turn};
pub use audit::{AuditLog, AuditModelCall, AuditRun, AuditSummary, AuditToolCall, FlowSummary, FlowTaskResult};
pub use decay::{cleanup_decayed, effective_score};
pub use working::WorkingMemory;
