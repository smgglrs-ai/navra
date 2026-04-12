//! myelix-flow: Declarative multi-agent flow engine.
//!
//! Define agent topologies as directed graphs with natural-language
//! routing. Agents hand off tasks to specialists via model-driven
//! decisions, with IFC taint tracking across the entire flow.
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
mod definition;
mod engine;
mod error;
mod handoff;

pub use builder::FlowBuilder;
pub use definition::{EdgeDefinition, FlowConfig, FlowDefinition, NodeDefinition};
pub use engine::{Flow, FlowNode, FlowResult};
pub use error::FlowError;
pub use handoff::HANDOFF_TOOL_NAME;
