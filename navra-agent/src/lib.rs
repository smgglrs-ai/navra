#![warn(missing_docs)]
//! navra-agent: SDK for building AI agents that connect to MCP servers.
//!
//! Provides a high-level [`Agent`] with a builder pattern, an MCP
//! [`McpClient`] with IFC taint tracking, and a tool-use loop
//! implementing the ReAct pattern.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use navra_agent::{Agent, OpenAiBackend, Locality};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let model = OpenAiBackend::new(
//!         "http://localhost:11434/v1",
//!         "granite3.3:8b",
//!         None,
//!         Locality::Local,
//!     );
//!
//!     let mut agent = Agent::builder()
//!         .endpoint("http://localhost:3000/mcp")
//!         .await?
//!         .model(model)
//!         .system_prompt("You are a helpful assistant.")
//!         .build().await?;
//!
//!     let result = agent.run("List the git status").await?;
//!     println!("{}", result.response);
//!     Ok(())
//! }
//! ```

/// Typed agent action model for classification, risk assessment, and audit.
pub mod action;
mod agent;
/// Audit sink trait for recording tool and model calls from the tool loop.
pub mod audit;
pub mod block;
mod client;
mod convert;
mod error;
/// Agent process hibernation — save and restore agent state.
pub mod hibernate;
/// Per-agent token quotas for fair scheduling.
pub mod quota;
/// Deterministic replay for repetitive tool-loop tasks.
pub mod replay;
/// Upstream MCP prompt resolution utilities.
pub mod resolve;
/// Cooperative signal delivery for running agents.
pub mod signal;
mod tool_loop;
/// Hermes-format trace export for agent conversations.
pub mod trace;

pub use action::{ActionRecord, AgentAction, RiskLevel};
pub use agent::{Agent, AgentBuilder};
pub use block::{BlockStatus, ToolBlock};
pub use client::McpClient;
pub use error::AgentError;
pub use resolve::{resolve_mcp_prompts, resolve_persona, resolve_persona_source};
pub use signal::{AgentSignal, SignalHandle, SignalReceiver};
pub use tool_loop::{
    extract_text, run_tool_loop, ContextRetriever, ToolLoopConfig, ToolLoopResult,
};
pub use trace::{
    ContentSanitizer, HermesMessage, HermesTrace, ToolCallEntry, ToolResponseEntry, TraceExporter,
    TraceMetadata, TraceRecord,
};

// SDK facade: external consumers (e.g. agent binaries) depend only on
// navra-agent and reach protocol/model/security types through these
// re-exports.  Internal workspace crates (flow, engine) have direct
// deps and import from the source crates instead.
pub use audit::{AuditSink, SharedAuditSink};
pub use convert::tool_def_to_response;
pub use navra_auth::identity::{load_or_create_file_identity, CapSigner, Ed25519Signer};
pub use navra_auth::ifc::TaintTracker;
pub use navra_model::{
    AnthropicBackend, CreateResponseRequest, FunctionCallItem, FunctionCallOutputContent,
    FunctionCallOutputItem, InputContent, InputItem, ItemStatus, Locality, MessageItem,
    MessageRole, ModelBackend, ModelResponse, OpenAiBackend, OutputContent, OutputItem,
    ReasoningItem, ResponseFormat, ResponseStatus, ResponseTool, ResponseToolChoice, StreamEvent,
};
pub use navra_protocol::label::DataLabel;
pub use navra_protocol::{
    CallToolParams, CallToolResult, Content, PromptDefinition, ResourceDefinition, ToolDefinition,
};
pub use navra_safety_hooks::safety::FilterPipeline;
