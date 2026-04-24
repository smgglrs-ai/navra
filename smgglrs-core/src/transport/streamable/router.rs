use crate::server::McpServer;
use crate::transport::a2a::A2aState;
use crate::transport::sse::SseBroadcaster;
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;

use super::handlers::*;

/// Shared state for the axum router.
#[derive(Clone)]
pub(super) struct AppState {
    pub server: Arc<McpServer>,
    pub broadcaster: SseBroadcaster,
    /// AID (Agent Identity & Discovery) record, served at /.well-known/agent.
    pub aid_record: Option<serde_json::Value>,
    /// MCP Registry entries, served at /v0.1/servers.
    pub registry_entries: Vec<serde_json::Value>,
    /// Endpoint URL for A2A Agent Card (None = A2A disabled).
    pub a2a_endpoint: Option<String>,
    /// Root DID for Agent Card identity.
    pub root_did: Option<String>,
}

/// Build an axum Router for the MCP Streamable HTTP transport.
pub fn build_router(server: Arc<McpServer>) -> Router {
    let state = AppState {
        server,
        broadcaster: SseBroadcaster::new(),
        aid_record: None,
        registry_entries: Vec::new(),
        a2a_endpoint: None,
        root_did: None,
    };
    Router::new()
        .route("/mcp", post(handle_post))
        .route("/mcp", get(handle_get))
        .route("/.well-known/mcp.json", get(handle_server_card))
        .route("/sys/status", get(handle_sys_status))
        .with_state(state)
}

/// Build an axum Router with a provided SSE broadcaster (for external notification injection).
pub fn build_router_with_broadcaster(
    server: Arc<McpServer>,
    broadcaster: SseBroadcaster,
) -> Router {
    let state = AppState {
        server,
        broadcaster,
        aid_record: None,
        registry_entries: Vec::new(),
        a2a_endpoint: None,
        root_did: None,
    };
    Router::new()
        .route("/mcp", post(handle_post))
        .route("/mcp", get(handle_get))
        .route("/.well-known/mcp.json", get(handle_server_card))
        .route("/sys/status", get(handle_sys_status))
        .with_state(state)
}

/// Build a router with full discovery: AID, A2A, registry, SSE.
pub fn build_router_with_discovery(
    server: Arc<McpServer>,
    broadcaster: SseBroadcaster,
    aid_record: Option<serde_json::Value>,
    registry_entries: Vec<serde_json::Value>,
    a2a_endpoint: Option<String>,
    root_did: Option<String>,
) -> Router {
    let a2a_enabled = a2a_endpoint.is_some();

    // Build A2A state before moving server into AppState
    let a2a_state = if a2a_enabled {
        Some(A2aState {
            server: server.clone(),
            task_store: server.task_store().clone(),
        })
    } else {
        None
    };

    let state = AppState {
        server,
        broadcaster,
        aid_record,
        registry_entries,
        a2a_endpoint,
        root_did,
    };

    let mut router = Router::new()
        .route("/mcp", post(handle_post))
        .route("/mcp", get(handle_get))
        .route("/.well-known/mcp.json", get(handle_server_card))
        .route("/v0.1/servers", get(handle_registry))
        .route("/sys/status", get(handle_sys_status));

    if state.aid_record.is_some() {
        router = router.route("/.well-known/agent", get(handle_aid_record));
    }
    if state.a2a_endpoint.is_some() {
        router = router.route("/.well-known/agent.json", get(handle_agent_card));
    }

    let mut router = router.with_state(state);

    // Mount A2A JSON-RPC endpoint when A2A is enabled
    if let Some(a2a_state) = a2a_state {
        router = router.merge(
            Router::new()
                .route("/a2a", post(crate::transport::a2a::handle_a2a_post))
                .with_state(a2a_state),
        );
    }

    router
}
