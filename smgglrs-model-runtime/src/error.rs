//! Runtime error types.

/// Errors from model runtime operations.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("no suitable runtime found: {0}")]
    NoRuntime(String),

    #[error("failed to start model server: {0}")]
    Start(String),

    #[error("model server exited unexpectedly: {0}")]
    Exited(String),

    #[error("health check failed: {0}")]
    Health(String),

    #[error("failed to stop model server: {0}")]
    Stop(String),

    #[error("container error: {0}")]
    Container(String),

    #[error("GPU detection error: {0}")]
    Gpu(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}
