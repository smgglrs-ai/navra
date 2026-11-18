//! Error types for the cognitive core.

/// Error type for cognitive operations.
#[derive(Debug, thiserror::Error)]
pub enum CognitiveError {
    /// The requested persona was not found in the cognitive core.
    #[error("persona not found: '{0}'")]
    PersonaNotFound(String),

    /// The requested heuristic module was not found.
    #[error("heuristic module not found: '{0}'")]
    HeuristicNotFound(String),

    /// The requested directive was not found.
    #[error("directive not found: '{0}'")]
    DirectiveNotFound(String),

    /// The requested specialization was not found.
    #[error("specialization not found: '{0}'")]
    SpecializationNotFound(String),

    /// A facet was not found within a heuristic module.
    #[error("facet '{facet}' not found in heuristic module '{module}'")]
    FacetNotFound {
        /// Heuristic module name.
        module: String,
        /// Facet name within the module.
        facet: String,
    },

    /// Failed to parse a YAML cognitive artifact file.
    #[error("YAML parse error in {path}: {source}")]
    Yaml {
        /// Path to the file that failed to parse.
        path: String,
        /// Underlying YAML parse error.
        source: serde_yaml::Error,
    },

    /// Cognitive core integrity failure: missing or unreadable
    /// `checksums.sha256`, an untracked file in a checksummed core,
    /// or a hash mismatch.
    #[error("integrity check failed for cognitive core at {path}: {message}")]
    Integrity {
        /// Cognitive core directory that failed the check.
        path: String,
        /// What failed and how to fix it.
        message: String,
    },

    /// Filesystem I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
