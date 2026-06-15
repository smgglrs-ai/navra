//! navra-safety-hooks: Content hooks and integrity monitoring for the navra gateway.
//!
//! - **safety** — Re-exported from the standalone `navra-safety` crate
//! - **hooks** — Pre/post tool-call pipeline (`HookPipeline`)
//! - **integrity_monitor** — Cognitive file integrity monitoring
//! - **bridge** — Bridges between `navra-safety` types and navra workspace types

pub use navra_safety as safety;
pub mod bridge;
pub mod hooks;
pub mod integrity_monitor;
