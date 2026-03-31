//! Transport trait for upstream MCP communication.

use super::UpstreamError;
use async_trait::async_trait;

/// A transport sends a JSON-RPC request and receives a JSON-RPC response.
///
/// Implementations handle the wire protocol (stdio, HTTP, SSE) while
/// `Upstream` handles MCP semantics (initialize, discover, proxy).
#[async_trait]
pub trait Transport: Send + 'static {
    /// Send a JSON-RPC request and return the raw response.
    async fn request(
        &mut self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError>;

    /// Shut down the transport (close connections, kill processes).
    fn shutdown(&mut self);
}
