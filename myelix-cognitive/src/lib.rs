//! myelix-cognitive: Cognitive core for AI agent identity.
//!
//! Loads persona, directive, and heuristic YAML files from a cognitive
//! core directory, then assembles them into structured prompts via the
//! Weaver. Compatible with the Python Myelix cognitive core format.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use myelix_cognitive::{ForgeService, assemble};
//! use std::path::Path;
//!
//! let forge = ForgeService::load(Path::new("cognitive_core")).unwrap();
//! let output = assemble(&forge, "developer", "Fix the login bug", None, None).unwrap();
//! println!("{}", output.system_prompt());
//! ```

mod error;
mod forge;
mod types;
mod weaver;

pub use error::CognitiveError;
pub use forge::ForgeService;
pub use types::{
    Directive, Example, Facet, HeuristicModule, HeuristicRef, Persona, Reference, Scope,
    Specialization,
};
pub use weaver::{assemble, WeaverOutput};
