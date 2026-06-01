use crate::auth::AgentIdentity;
use crate::protocol::{
    GetPromptResult, PromptDefinition, ReadResourceResult, ResourceDefinition, ToolDefinition,
};
use crate::server::{McpServer, ToolHandler};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Async prompt handler function type.
///
/// Takes prompt arguments (name→value) and returns the rendered prompt.
pub type PromptHandler = Arc<
    dyn Fn(HashMap<String, String>) -> Pin<Box<dyn Future<Output = GetPromptResult> + Send>>
        + Send
        + Sync,
>;

/// Async resource handler function type.
///
/// Takes the resource URI and returns the resource content.
pub type ResourceHandler =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = ReadResourceResult> + Send>> + Send + Sync>;

/// A feature module that contributes tools and prompts to the MCP server.
///
/// Modules are the unit of composition in navra. Each module provides
/// a set of tools and/or prompts with their handlers. The server collects
/// them from all enabled modules and presents them to agents.
///
/// # Naming convention
///
/// Tool names should be prefixed with the module name to avoid
/// collisions: `file_read`, `git_status`, `shell_exec`.
///
/// Operations for the permission engine follow the same pattern:
/// `"read"`, `"write"` (docs), `"git.status"`, `"git.commit"` (git).
pub trait Module: Send + Sync + 'static {
    /// Module name, used in config and logging.
    fn name(&self) -> &str;

    /// Return the tools this module provides.
    ///
    /// Called once at server startup. Each tool is a (definition, handler) pair.
    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)>;

    /// Return the prompts this module provides.
    ///
    /// Called once at server startup. Each prompt is a (definition, handler) pair.
    /// Default implementation returns no prompts.
    fn prompts(&self) -> Vec<(PromptDefinition, PromptHandler)> {
        Vec::new()
    }

    /// Return the resources this module provides.
    ///
    /// Called once at server startup. Each resource is a (definition, handler) pair.
    /// Default implementation returns no resources.
    fn resources(&self) -> Vec<(ResourceDefinition, ResourceHandler)> {
        Vec::new()
    }
}

/// Serve a module as a standalone MCP server over stdin/stdout.
///
/// Builds a minimal `McpServer` with anonymous auth and runs the
/// stdio transport. All diagnostic output goes to stderr via tracing.
///
/// This is the entry point for tool crates that want to run as
/// independent MCP servers (out-of-process microkernel modules).
/// The gateway handles auth/ACLs/IFC/safety on the proxy layer.
pub async fn serve_module(
    module: impl Module,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let name = module.name().to_string();
    let server = Arc::new(
        McpServer::builder()
            .name(&name)
            .version(env!("CARGO_PKG_VERSION"))
            .allow_anonymous()
            .module(module)
            .build(),
    );
    let agent = AgentIdentity::new("gateway", "default");
    crate::transport::run_stdio_server(server, agent).await
}
