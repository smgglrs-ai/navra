//! Validation framework for flow execution.
//!
//! - **mandate**: Check task output against success criteria
//! - **trace**: Capture execution traces for analysis
//! - **pta**: Prefix Tree Acceptor for generalizing valid execution sequences
//! - **dominator**: Dominator-based extraction of mandatory milestones

mod mandate;
pub mod trace;
pub mod pta;
pub mod dominator;

pub use mandate::{validate_mandate, ValidationResult};
pub use trace::{ExecutionTrace, TraceEvent};
pub use pta::PrefixTreeAcceptor;
pub use dominator::{DominatorTree, extract_dominators, validate_against_dominators};
