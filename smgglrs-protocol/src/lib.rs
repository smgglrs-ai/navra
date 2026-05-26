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
    JsonRpcResponse, RequestId, CONTENT_TOO_LARGE, REQUEST_CANCELLED,
};
pub use mcp::{
    encode_cursor, paginate, CallToolParams, CallToolResult, ClientCapabilities, ClientInfo,
    CompleteParams, CompleteResult, CompletionArgument, Content, ContentType, GetPromptParams,
    GetPromptResult, InitializeParams, InitializeResult, ListPromptsResult,
    ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, LoggingLevel,
    LoggingMessageNotification, PaginatedRequest, ProgressParams, PromptArgument, PromptDefinition,
    PromptMessage, PromptRole, PromptsCapability, ReadResourceParams, ReadResourceResult,
    RequestMeta, ResourceContent, ResourceDefinition, ResourceTemplate, ResourceUpdatedParams,
    ResourcesCapability, ServerCapabilities, ServerInfo, SetLevelParams, TextContent,
    ToolAnnotations, ToolDefinition, ToolInputSchema, ToolsCapability, DEFAULT_PAGE_SIZE,
    NOTIFY_INITIALIZED, NOTIFY_PROGRESS, NOTIFY_PROMPTS_LIST_CHANGED,
    NOTIFY_RESOURCES_LIST_CHANGED, NOTIFY_RESOURCES_UPDATED, NOTIFY_TOOLS_LIST_CHANGED,
    PROTOCOL_VERSION,
};
pub use upstream::{RetryConfig, TlsConfig, Upstream};
