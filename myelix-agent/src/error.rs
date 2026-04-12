//! Error types for the agent SDK.

use myelix_protocol::upstream::UpstreamError;

/// Error type for agent operations.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("MCP upstream error: {0}")]
    Upstream(#[from] UpstreamError),

    #[error("model error: {0}")]
    Model(#[from] myelix_model::ModelError),

    #[error("IFC violation: {0}")]
    IfcViolation(String),

    #[error("max iterations ({0}) exceeded")]
    MaxIterations(usize),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
