use crate::auth::CallContext;
use crate::module::{PromptHandler, ResourceHandler};
use crate::protocol::{CallToolResult, PromptDefinition, ResourceDefinition, ToolDefinition};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Async tool handler function type.
pub type ToolHandler = Arc<
    dyn Fn(serde_json::Value, CallContext) -> Pin<Box<dyn Future<Output = CallToolResult> + Send>>
        + Send
        + Sync,
>;

/// Registered tool: definition + handler.
pub(super) struct RegisteredTool {
    pub definition: ToolDefinition,
    pub handler: ToolHandler,
}

/// Registered prompt: definition + handler.
pub(super) struct RegisteredPrompt {
    pub definition: PromptDefinition,
    pub handler: PromptHandler,
}

/// Registered resource: definition + handler.
pub(super) struct RegisteredResource {
    pub definition: ResourceDefinition,
    pub handler: ResourceHandler,
}

/// Registered resource template: template definition + handler that receives the full URI.
pub(super) struct RegisteredResourceTemplate {
    pub template: crate::protocol::ResourceTemplate,
    pub handler: ResourceHandler,
}
