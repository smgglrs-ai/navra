#![warn(missing_docs)]
//! navra-cognitive: Cognitive core for AI agent identity.
//!
//! Loads persona, directive, and heuristic YAML files from a cognitive
//! core directory, then assembles them into structured prompts via the
//! Weaver. Compatible with the the original Python prototype cognitive core format.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use navra_cognitive::{ForgeService, assemble};
//! use std::path::Path;
//!
//! let forge = ForgeService::load(Path::new("cognitive_core")).unwrap();
//! let output = assemble(&forge, "developer", "Fix the login bug", None, None).unwrap();
//! println!("{}", output.system_prompt());
//! ```

pub mod bridge;
pub mod budget;
mod error;
pub mod evolution;
pub mod fast_path;
mod forge;
pub mod skill_lifecycle;
pub mod skill_pipeline;
mod types;
mod weaver;

pub use budget::{
    CompactionStrategy, ContextBudget, apply_compaction, compact_history, estimate_tokens,
    recommended_strategy, truncate_to_budget,
};
pub use error::CognitiveError;
pub use evolution::{TraitStore, TraitVector};
pub use forge::{
    ForgeService, Severity, SpecializationMeta, ValidationFinding, generate_checksums,
};
pub use skill_lifecycle::{
    Skill, SkillError, SkillMemoryEntry, SkillOutcome, SkillRegistry, SkillTest, TestStatus,
    validate_skill,
};
pub use skill_pipeline::{DirectorySource, SkillPipeline, SkillSource};
pub use types::{
    Directive, Example, Facet, HeuristicModule, HeuristicRef, InjectPosition, McpPersonaSource,
    McpPromptRef, Persona, Reference, ResolvedPrompt, Scope, SkillCard, Specialization,
};
pub use weaver::{
    WeaverOutput, assemble, assemble_full, assemble_with_phase, format_skill_cards,
    load_skill_cards, select_skill_cards,
};
