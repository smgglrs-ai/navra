//! In-process MCP transport that dispatches JSON-RPC directly to McpServer.
//!
//! Provides `connect_direct_peer()` which creates an in-memory duplex
//! between a NavraHandler (server-side) and an rmcp client, returning
//! a `Peer<RoleClient>` without any network I/O.

use navra_core::auth::AgentIdentity;
use navra_core::McpServer;
use navra_core::NavraHandler;
use rmcp::service::ServiceExt;
use std::sync::Arc;

pub(crate) struct DirectTransport {
    server: Arc<McpServer>,
    _agent: AgentIdentity,
}

impl DirectTransport {
    pub fn new(server: Arc<McpServer>, agent: AgentIdentity) -> Self {
        Self {
            server,
            _agent: agent,
        }
    }
}

/// Connect to an in-process McpServer via rmcp duplex and return the
/// client-side `Peer<RoleClient>`.
pub(crate) async fn connect_direct_peer(
    transport: DirectTransport,
) -> Result<rmcp::Peer<rmcp::RoleClient>, String> {
    let handler = NavraHandler::new(transport.server);
    let (server_io, client_io) = tokio::io::duplex(65536);
    tokio::spawn(async move {
        if let Ok(svc) = handler.serve(server_io).await {
            let _ = svc.waiting().await;
        }
    });
    let client = <() as ServiceExt<rmcp::RoleClient>>::serve((), client_io)
        .await
        .map_err(|e| format!("rmcp connect failed: {e}"))?;
    let peer = client.peer().clone();
    tokio::spawn(async move {
        let _ = client.waiting().await;
    });
    Ok(peer)
}
