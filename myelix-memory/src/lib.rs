//! myelix-memory: Persistent agent memory.
//!
//! Two storage layers backed by SQLite:
//! - **Working memory**: Conversation turns that survive sessions
//! - **Knowledge memory**: Categorized entries with FTS5 search
//!
//! # Quick start
//!
//! ```rust,no_run
//! use myelix_memory::{WorkingMemory, KnowledgeStore};
//! use std::path::Path;
//!
//! let working = WorkingMemory::open(Path::new("memory.db")).unwrap();
//! let knowledge = KnowledgeStore::open(Path::new("knowledge.db")).unwrap();
//! ```

mod error;
mod knowledge;
mod types;
mod working;

pub use error::MemoryError;
pub use knowledge::KnowledgeStore;
pub use types::{MemoryEntry, MemoryType, Message, Role, Turn};
pub use working::WorkingMemory;
