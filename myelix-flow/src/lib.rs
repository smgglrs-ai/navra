//! myelix-flow: Multi-agent flow engine.
//!
//! Two execution modes:
//! - **Handoff flows**: Directed graph of agents with model-driven routing
//! - **DAG execution**: Parallel task graphs with dependency resolution
//!
//! # Quick start
//!
//! ```rust,no_run
//! use myelix_flow::Flow;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let toml = std::fs::read_to_string("flow.toml")?;
//!     let mut flow = Flow::from_toml(&toml).await?;
//!     let result = flow.run("Analyze the codebase").await?;
//!     println!("{}", result.response);
//!     Ok(())
//! }
//! ```

mod backedge;
mod blackboard;
mod builder;
mod dag;
mod definition;
mod engine;
mod error;
mod executor;
mod handoff;
pub mod iterative;
mod mailbox;
mod mesh_tools;
mod recovery;
mod task;
mod validation;
pub mod yaml_loader;

pub use backedge::{BackEdgeTracker, ConditionalEdge, EdgeCondition};
pub use blackboard::{Blackboard, BlackboardEntry};
pub use builder::FlowBuilder;
pub use dag::DependencyGraph;
pub use definition::{
    BackEdgeDefinition, DagConfig, DagDefinition, EdgeDefinition, FlowConfig, FlowDefinition,
    NodeDefinition, ParameterDef, TaskDefinition,
};
pub use engine::{Flow, FlowNode, FlowResult};
pub use error::FlowError;
pub use executor::{DagExecutor, DagResult};
pub use handoff::HANDOFF_TOOL_NAME;
pub use iterative::{Finding, IterativeConfig, IterativeExecutor, IterativeResult, RoundMetric};
pub use mailbox::{MailboxMessage, MailboxRegistry};
pub use recovery::{
    classify_failure, detect_circular_fix, FailureType, RecoveryAction, RecoveryStrategy,
};
pub use task::{Attempt, Task, TaskResult, TaskStatus};
pub use validation::{validate_mandate, ValidationResult};
