//! Hub error types.

/// Errors from model hub operations.
#[derive(Debug, thiserror::Error)]
pub enum HubError {
    #[error("invalid model URI: {0}")]
    InvalidUri(String),

    #[error("model not found: {0}")]
    NotFound(String),

    #[error("download failed: {0}")]
    Download(String),

    #[error("cache error: {0}")]
    Cache(String),

    #[error("registry error: {0}")]
    Registry(String),

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}
