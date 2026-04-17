//! Error types for the agent SDK.

use myelix_protocol::upstream::UpstreamError;

/// Error type for agent operations.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Error communicating with an MCP upstream server.
    #[error("MCP upstream error: {0}")]
    Upstream(#[from] UpstreamError),

    /// Error from the model backend (inference, connection, etc.).
    #[error("model error: {0}")]
    Model(#[from] myelix_model::ModelError),

    /// Information Flow Control violation (taint level exceeded).
    #[error("IFC violation: {0}")]
    IfcViolation(String),

    /// The tool-use loop exceeded the configured iteration limit.
    #[error("max iterations ({0}) exceeded")]
    MaxIterations(usize),

    /// Invalid or missing configuration (e.g. no endpoint or model set).
    #[error("configuration error: {0}")]
    Config(String),

    /// Catch-all for other errors.
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
