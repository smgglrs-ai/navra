#![warn(missing_docs)]
//! smgglrs-agent: SDK for building AI agents that connect to MCP servers.
//!
//! Provides a high-level [`Agent`] with a builder pattern, an MCP
//! [`McpClient`] with IFC taint tracking, and a tool-use loop
//! implementing the ReAct pattern.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use smgglrs_agent::{Agent, OpenAiBackend, Locality};
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
pub mod block;
mod client;
mod convert;
mod error;
/// Upstream MCP prompt resolution utilities.
pub mod resolve;
mod tool_loop;
/// Hermes-format trace export for agent conversations.
pub mod trace;

pub use agent::{Agent, AgentBuilder};
pub use block::{BlockStatus, ToolBlock};
pub use client::McpClient;
pub use error::AgentError;
pub use resolve::{resolve_mcp_prompts, resolve_persona, resolve_persona_source};
pub use action::{AgentAction, ActionRecord, RiskLevel};
pub use tool_loop::{extract_text, run_tool_loop, ToolLoopConfig, ToolLoopResult};
pub use trace::{HermesMessage, HermesTrace, ToolCallEntry, ToolResponseEntry, TraceExporter};

// SDK facade: external consumers (e.g. agent binaries) depend only on
// smgglrs-agent and reach protocol/model/security types through these
// re-exports.  Internal workspace crates (flow, engine) have direct
// deps and import from the source crates instead.
pub use smgglrs_protocol::{
    CallToolParams, CallToolResult, Content, ToolDefinition, PromptDefinition,
    ResourceDefinition, Upstream,
};
pub use smgglrs_protocol::label::DataLabel;
pub use smgglrs_model::{
    AnthropicBackend, ModelBackend, OpenAiBackend, Locality,
    CreateResponseRequest, ModelResponse, ResponseTool, ResponseToolChoice,
    InputItem, OutputItem, MessageItem, FunctionCallItem, FunctionCallOutputItem,
    FunctionCallOutputContent, ReasoningItem, MessageRole, ItemStatus,
    InputContent, OutputContent, StreamEvent, ResponseStatus, ResponseFormat,
};
pub use convert::tool_def_to_response;
pub use smgglrs_security::identity::{CapSigner, Ed25519Signer, load_or_create_file_identity};
pub use smgglrs_security::ifc::TaintTracker;
pub use smgglrs_security::safety::FilterPipeline;
