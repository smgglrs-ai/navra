//! Error types for the flow engine.

/// Error type for flow operations.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("agent error in node '{node}': {source}")]
    Agent {
        node: String,
        source: smgglrs_agent::AgentError,
    },

    #[error("invalid flow: {0}")]
    InvalidFlow(String),

    #[error("max hops ({0}) exceeded")]
    MaxHops(usize),

    #[error("unknown handoff target: '{0}'")]
    UnknownTarget(String),

    #[error("no entry node defined")]
    NoEntry,

    #[error("cyclic dependency: {0}")]
    CyclicDependency(String),

    #[error("task '{task}' failed: {reason}")]
    TaskFailed { task: String, reason: String },

    #[error("unknown specialist: '{0}'")]
    UnknownSpecialist(String),

    #[error("IFC violation: agent '{sender}' cannot write to agent '{target}': {reason}")]
    IfcViolation {
        sender: String,
        target: String,
        reason: String,
    },

    #[error("unknown agent: '{0}'")]
    UnknownAgent(String),

    #[error("mailbox full for agent '{0}'")]
    MailboxFull(String),

    #[error("blackboard key not found: '{0}'")]
    BlackboardKeyNotFound(String),

    #[error("back-edge exhausted: '{from}' → '{to}' after {iterations} iterations")]
    BackEdgeExhausted {
        from: String,
        to: String,
        iterations: u32,
    },

    #[error("unknown task dependency: '{0}'")]
    UnknownDependency(String),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
