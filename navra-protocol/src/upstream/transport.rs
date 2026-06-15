//! Transport trait for upstream MCP communication.

use super::UpstreamError;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Notifications received from an upstream MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamNotification {
    ToolsListChanged,
}

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

    /// Set the notification sender for forwarding server-initiated notifications.
    fn set_notification_sender(&mut self, _tx: mpsc::UnboundedSender<UpstreamNotification>) {}
}
