//! Error types for the flow engine.

/// Error type for flow operations.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("agent error in node '{node}': {source}")]
    Agent {
        node: String,
        source: myelix_agent::AgentError,
    },

    #[error("invalid flow: {0}")]
    InvalidFlow(String),

    #[error("max hops ({0}) exceeded")]
    MaxHops(usize),

    #[error("unknown handoff target: '{0}'")]
    UnknownTarget(String),

    #[error("no entry node defined")]
    NoEntry,

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
