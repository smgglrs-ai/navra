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

mod builder;
mod dag;
mod definition;
mod engine;
mod error;
mod executor;
mod handoff;
mod task;

pub use builder::FlowBuilder;
pub use dag::DependencyGraph;
pub use definition::{
    DagConfig, DagDefinition, EdgeDefinition, FlowConfig, FlowDefinition, NodeDefinition,
    TaskDefinition,
};
pub use engine::{Flow, FlowNode, FlowResult};
pub use error::FlowError;
pub use executor::{DagExecutor, DagResult};
pub use handoff::HANDOFF_TOOL_NAME;
pub use task::{Task, TaskResult, TaskStatus};
