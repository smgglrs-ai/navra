//! Validation framework for flow execution.
//!
//! - **mandate**: Check task output against success criteria
//! - **trace**: Capture execution traces for analysis
//! - **pta**: Prefix Tree Acceptor for generalizing valid execution sequences
//! - **dominator**: Dominator-based extraction of mandatory milestones

pub mod dominator;
mod mandate;
pub mod pta;
pub mod trace;

pub use dominator::{extract_dominators, validate_against_dominators, DominatorTree};
pub use mandate::{validate_mandate, ValidationResult};
pub use pta::PrefixTreeAcceptor;
pub use trace::{ExecutionTrace, TraceEvent};
