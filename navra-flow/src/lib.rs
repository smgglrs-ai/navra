//! navra-flow: Multi-agent flow engine.
//!
//! Two execution modes:
//! - **Handoff flows**: Directed graph of agents with model-driven routing
//! - **DAG execution**: Parallel task graphs with dependency resolution
//!
//! # Quick start
//!
//! ```rust,no_run
//! use navra_flow::Flow;
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
pub mod causal_graph;
pub mod checkpoint;
mod dag;
mod definition;
mod engine;
mod error;
pub mod eval;
pub mod event_log;
mod executor;
mod handoff;
pub mod iterative;
mod mailbox;
pub mod mesh;
pub mod mesh_tools;
mod recovery;
pub mod sdb;
mod task;
mod validation;
pub mod verification;
pub mod yaml_loader;

pub use backedge::{BackEdgeTracker, ConditionalEdge, EdgeCondition};
pub use blackboard::{Blackboard, BlackboardEntry};
pub use builder::FlowBuilder;
pub use checkpoint::{CheckpointState, DagCheckpoint};
pub use dag::DependencyGraph;
pub use definition::{
    BackEdgeDefinition, DagConfig, DagDefinition, EdgeDefinition, FlowConfig, FlowDefinition,
    NodeDefinition, ParameterDef, TaskDefinition, generic_flow_dag, parse_planner_tasks,
    single_task_dag,
};
pub use engine::{Flow, FlowNode, FlowResult};
pub use error::FlowError;
pub use executor::{DagExecutor, DagResult, InsightCallback, InsightRetriever, TaskInsight};
pub use handoff::HANDOFF_TOOL_NAME;
pub use iterative::{Finding, IterativeConfig, IterativeExecutor, IterativeResult, RoundMetric};
pub use mailbox::{MailboxMessage, MailboxRegistry, MessageBody};
pub use mesh::{AgentCardDirectory, MeshRouter, TeammateLocation};
pub use mesh_tools::{FLOW_KILL, flow_kill_tool_def};
pub use recovery::{
    FailureType, RecoveryAction, RecoveryStrategy, classify_failure, detect_circular_fix,
};
pub use task::{Attempt, Task, TaskResult, TaskStatus};
pub use validation::{
    DominatorTree, ExecutionTrace, PrefixTreeAcceptor, TraceEvent, ValidationResult,
    extract_dominators, validate_against_dominators, validate_mandate,
};
pub use verification::{
    VerificationConfig, VerificationResult, VerificationThreshold, VerificationVerdict,
    verify_result,
};
pub use yaml_loader::{LoadedFlow, YamlLoadError};
