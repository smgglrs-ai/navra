use crate::protocol::{PromptDefinition, ResourceDefinition, ToolDefinition};
use navra_mcp::{PromptHandler, ResourceHandler, ToolHandler};

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
