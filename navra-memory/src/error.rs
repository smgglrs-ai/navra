//! Error types for the memory crate.

/// Error type for memory operations.
#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("entry not found: '{0}'")]
    NotFound(String),

    #[error("invalid memory type: '{0}'")]
    InvalidType(String),

    #[error("{0}")]
    Other(String),
}
