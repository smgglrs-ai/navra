#![allow(dead_code)]
//! navra-protocol: Wire types for MCP, A2A, and JSON-RPC.
//!
//! MCP types are re-exported from the `rmcp` SDK. navra-specific
//! convenience constructors live in [`compat`].
//!
//! - **MCP** — re-exported from `rmcp::model`
//! - **JSON-RPC 2.0** — navra's own untyped request/response types
//! - **A2A** — `AgentCard`, `Task`, `Message`, and agent-to-agent protocol types
//! - **IFC labels** — `DataLabel` with `Integrity` and `Confidentiality` levels
//! - **Upstream** — `Upstream` config for proxied MCP servers with `RetryConfig`

pub mod a2a;
pub mod a2a_client;
pub mod a2ui;
pub mod compat;
pub mod label;
pub mod permissions;
pub mod upstream_config;

mod jsonrpc;
mod mcp;

pub use jsonrpc::{
    BatchRequest, ErrorCode, ErrorData as JsonRpcErrorData, JsonRpcError, JsonRpcNotification,
    JsonRpcRequest, JsonRpcResponse, RequestId, CONTENT_TOO_LARGE, REQUEST_CANCELLED,
};
pub use mcp::{
    // rmcp re-exports (MCP domain types)
    AudioContent, CallToolParams, CallToolResult, ClientCapabilities, ClientInfo, CompleteParams,
    CompleteResult, CompletionArgument, Content, EmbeddedResourceContent,
    GetPromptParams, GetPromptResult, ImageContent, InitializeParams, InitializeResult, ProtocolVersion,
    ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult,
    LoggingLevel, LoggingMessageNotification, ProgressParams, PromptArgument, PromptDefinition,
    PromptMessage, PromptMessageContent, PromptRole, PromptsCapability, RawContent,
    ReadResourceParams,
    RawResource, RawResourceTemplate,
    ReadResourceResult, RequestMeta, ResourceContent, ResourceDefinition, ResourceTemplate,
    ResourceUpdatedParams, ResourcesCapability, ServerInfo, SetLevelParams, TextContent,
    ToolAnnotations, ToolDefinition, ToolsCapability,
    Annotated,
    // navra-specific types
    ContentType, PaginatedRequest, ServerCapabilities, DEFAULT_PAGE_SIZE, NOTIFY_INITIALIZED,
    NOTIFY_PROGRESS, NOTIFY_PROMPTS_LIST_CHANGED, NOTIFY_RESOURCES_LIST_CHANGED,
    NOTIFY_RESOURCES_UPDATED, NOTIFY_TOOLS_LIST_CHANGED, PROTOCOL_VERSION, PROTOCOL_VERSION_2026,
    encode_cursor, paginate,
};
pub use upstream_config::{RetryConfig, TlsConfig};

// Re-export rmcp for downstream crates that need direct access.
pub use rmcp;
