pub use navra_mcp::{Module, PromptHandler, ResourceHandler};

use crate::auth::AgentIdentity;
use crate::server::McpServer;
use std::sync::Arc;

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
