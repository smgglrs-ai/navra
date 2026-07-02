use crate::server::McpServer;
use crate::server::navra_handler::NavraHandler;
use rmcp::service::ServiceExt;
use std::sync::Arc;

/// Run the MCP server over stdin/stdout via rmcp's transport runtime.
///
/// Creates a `NavraHandler` wrapping the `McpServer` and serves it on
/// rmcp's stdio transport. rmcp handles the JSON-RPC framing, request
/// dispatch, and response serialization. The full navra security
/// pipeline (ACL, Cedar, IFC, hooks) runs inside `NavraHandler`.
pub async fn run_stdio_server(
    server: Arc<McpServer>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Stdio transport ready (rmcp)");
    let handler = NavraHandler::new(server);
    let service = handler
        .serve(rmcp::transport::io::stdio())
        .await
        .map_err(|e| format!("Failed to initialize MCP stdio service: {e}"))?;
    service
        .waiting()
        .await
        .map_err(|e| format!("MCP stdio service error: {e}"))?;
    tracing::info!("Stdio transport shut down");
    Ok(())
}
