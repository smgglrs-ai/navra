#![allow(dead_code)]
//! smgglrs-protocol: Wire types for MCP, A2A, and JSON-RPC.
//!
//! Provides serializable request/response types for the protocols
//! that smgglrs speaks:
//!
//! - **MCP** — `ToolDefinition`, `CallToolParams`, `CallToolResult`,
//!   `PromptDefinition`, `ResourceDefinition`, and capability negotiation
//! - **JSON-RPC 2.0** — `JsonRpcRequest`, `JsonRpcResponse`, `JsonRpcError`,
//!   `BatchRequest`, and standard error codes
//! - **A2A** — `AgentCard`, `Task`, `Message`, and agent-to-agent protocol types
//! - **IFC labels** — `DataLabel` with `Integrity` and `Confidentiality` levels
//! - **Upstream** — `Upstream` config for proxied MCP servers with `RetryConfig`
//!
//! This crate has no smgglrs dependencies and sits at the bottom of
//! the dependency graph.

pub mod a2a;
pub mod a2a_client;
pub mod label;
pub mod permissions;
pub mod upstream;

mod jsonrpc;
mod mcp;

pub use jsonrpc::{
    BatchRequest, ErrorCode, ErrorData, JsonRpcError, JsonRpcNotification, JsonRpcRequest,
    JsonRpcResponse, RequestId,
};
pub use mcp::{
    CallToolParams, CallToolResult, ClientCapabilities, ClientInfo, Content, ContentType,
    GetPromptParams, GetPromptResult, InitializeParams, InitializeResult, ListPromptsResult,
    ListResourcesResult, ListToolsResult, PaginatedRequest, PromptArgument, PromptDefinition,
    PromptMessage, PromptRole, PromptsCapability, ReadResourceParams, ReadResourceResult,
    ResourceContent, ResourceDefinition, ResourcesCapability, ServerCapabilities, ServerInfo,
    TextContent, ToolDefinition, ToolInputSchema, ToolsCapability,
    ProgressParams, RequestMeta, ResourceUpdatedParams,
    DEFAULT_PAGE_SIZE, PROTOCOL_VERSION, encode_cursor, paginate,
    NOTIFY_TOOLS_LIST_CHANGED, NOTIFY_RESOURCES_LIST_CHANGED,
    NOTIFY_RESOURCES_UPDATED, NOTIFY_PROMPTS_LIST_CHANGED,
    NOTIFY_PROGRESS, NOTIFY_INITIALIZED,
};
pub use upstream::{RetryConfig, Upstream};
