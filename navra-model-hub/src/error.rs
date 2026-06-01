//! Hub error types.

/// Errors from model hub operations.
#[derive(Debug, thiserror::Error)]
pub enum HubError {
    /// The model URI could not be parsed.
    #[error("invalid model URI: {0}")]
    InvalidUri(String),

    /// The requested model was not found in the registry or cache.
    #[error("model not found: {0}")]
    NotFound(String),

    /// Model download failed.
    #[error("download failed: {0}")]
    Download(String),

    /// Error reading from or writing to the local cache.
    #[error("cache error: {0}")]
    Cache(String),

    /// Error communicating with the model registry.
    #[error("registry error: {0}")]
    Registry(String),

    /// Downloaded content hash does not match expected hash.
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected content hash.
        expected: String,
        /// Actual content hash of the downloaded data.
        actual: String,
    },

    /// Filesystem I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}
