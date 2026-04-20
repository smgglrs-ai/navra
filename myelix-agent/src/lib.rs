#![warn(missing_docs)]
//! myelix-agent: SDK for building AI agents that connect to MCP servers.
//!
//! Provides a high-level [`Agent`] with a builder pattern, an MCP
//! [`McpClient`] with IFC taint tracking, and a tool-use loop
//! implementing the ReAct pattern.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use myelix_agent::{Agent, OpenAiBackend, Locality};
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
//!         .build()?;
//!
//!     let result = agent.run("List the git status").await?;
//!     println!("{}", result.response);
//!     Ok(())
//! }
//! ```

mod agent;
mod client;
mod convert;
mod error;
mod tool_loop;

pub use agent::{Agent, AgentBuilder};
pub use client::McpClient;
pub use error::AgentError;
pub use tool_loop::{extract_text, run_tool_loop, AuditCallback, ToolLoopConfig, ToolLoopResult};

// Re-export key types so users don't need direct deps on protocol/model/security.
pub use myelix_protocol::{
    CallToolParams, CallToolResult, Content, ToolDefinition, PromptDefinition,
    ResourceDefinition, Upstream,
};
pub use myelix_protocol::label::DataLabel;
pub use myelix_model::{
    AnthropicBackend, ModelBackend, OpenAiBackend, Locality,
    CreateResponseRequest, ModelResponse, ResponseTool, ResponseToolChoice,
    InputItem, OutputItem, MessageItem, FunctionCallItem, FunctionCallOutputItem,
    FunctionCallOutputContent, ReasoningItem, MessageRole, ItemStatus,
    InputContent, OutputContent, StreamEvent, ResponseStatus, ResponseFormat,
};
pub use myelix_security::identity::{CapSigner, Ed25519Signer, load_or_create_file_identity};
pub use myelix_security::ifc::TaintTracker;
