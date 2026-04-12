//! Error types for the cognitive core.

/// Error type for cognitive operations.
#[derive(Debug, thiserror::Error)]
pub enum CognitiveError {
    #[error("persona not found: '{0}'")]
    PersonaNotFound(String),

    #[error("heuristic module not found: '{0}'")]
    HeuristicNotFound(String),

    #[error("directive not found: '{0}'")]
    DirectiveNotFound(String),

    #[error("specialization not found: '{0}'")]
    SpecializationNotFound(String),

    #[error("facet '{facet}' not found in heuristic module '{module}'")]
    FacetNotFound { module: String, facet: String },

    #[error("YAML parse error in {path}: {source}")]
    Yaml {
        path: String,
        source: serde_yaml::Error,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
