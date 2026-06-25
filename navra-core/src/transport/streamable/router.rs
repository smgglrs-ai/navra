use crate::server::navra_handler::NavraHandler;
use crate::server::McpServer;
use crate::transport::a2a::A2aState;
use crate::transport::sse::SseBroadcaster;
use axum::routing::{get, post};
use axum::Router;
use rmcp::transport::StreamableHttpService;
use std::sync::Arc;

use super::handlers::*;

/// Shared state for the axum router (non-MCP routes).
#[derive(Clone)]
pub(crate) struct AppState {
    pub server: Arc<McpServer>,
    #[allow(dead_code)]
    pub broadcaster: SseBroadcaster,
    pub aid_record: Option<serde_json::Value>,
    pub registry_entries: Vec<serde_json::Value>,
    pub a2a_endpoint: Option<String>,
    pub root_did: Option<String>,
    pub oauth: Option<Arc<navra_auth::auth::oauth::OAuthProvider>>,
    pub metrics: Arc<crate::metrics::Metrics>,
    pub ws_ping_interval_secs: u64,
    pub ws_idle_timeout_secs: u64,
}

fn build_mcp_service(
    server: Arc<McpServer>,
) -> StreamableHttpService<
    NavraHandler,
    rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
> {
    let server_for_factory = server.clone();
    let config = rmcp::transport::StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .disable_allowed_hosts();
    StreamableHttpService::new(
        move || Ok(NavraHandler::new(server_for_factory.clone())),
        rmcp::transport::streamable_http_server::session::local::LocalSessionManager::default()
            .into(),
        config,
    )
}

/// Build an axum Router for the MCP Streamable HTTP transport.
pub fn build_router(server: Arc<McpServer>) -> Router {
    let metrics = server.metrics().clone();
    let mcp_service = build_mcp_service(server.clone());
    let state = AppState {
        server,
        broadcaster: SseBroadcaster::new(),
        aid_record: None,
        registry_entries: Vec::new(),
        a2a_endpoint: None,
        root_did: None,
        oauth: None,
        metrics,
        ws_ping_interval_secs: 30,
        ws_idle_timeout_secs: 600,
    };
    Router::new()
        .nest_service("/mcp", mcp_service)
        .route("/ws", get(crate::transport::websocket::handle_ws_upgrade))
        .route("/.well-known/mcp.json", get(handle_server_card))
        .route("/sys/status", get(handle_sys_status))
        .route("/metrics", get(handle_metrics))
        .with_state(state)
}

/// Build an axum Router with a provided SSE broadcaster (for external notification injection).
pub fn build_router_with_broadcaster(
    server: Arc<McpServer>,
    broadcaster: SseBroadcaster,
) -> Router {
    let metrics = server.metrics().clone();
    let mcp_service = build_mcp_service(server.clone());
    let state = AppState {
        server,
        broadcaster,
        aid_record: None,
        registry_entries: Vec::new(),
        a2a_endpoint: None,
        root_did: None,
        oauth: None,
        metrics,
        ws_ping_interval_secs: 30,
        ws_idle_timeout_secs: 600,
    };
    Router::new()
        .nest_service("/mcp", mcp_service)
        .route("/ws", get(crate::transport::websocket::handle_ws_upgrade))
        .route("/.well-known/mcp.json", get(handle_server_card))
        .route("/sys/status", get(handle_sys_status))
        .route("/metrics", get(handle_metrics))
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

    let a2a_state = if a2a_enabled {
        Some(A2aState {
            server: server.clone(),
            task_store: server.task_store().clone(),
        })
    } else {
        None
    };

    let metrics = server.metrics().clone();
    let mcp_service = build_mcp_service(server.clone());
    let state = AppState {
        server,
        broadcaster,
        aid_record,
        registry_entries,
        a2a_endpoint,
        root_did,
        oauth: None,
        metrics,
        ws_ping_interval_secs: 30,
        ws_idle_timeout_secs: 600,
    };

    let mut router = Router::new()
        .nest_service("/mcp", mcp_service)
        .route("/ws", get(crate::transport::websocket::handle_ws_upgrade))
        .route("/metrics", get(handle_metrics))
        .route("/.well-known/mcp.json", get(handle_server_card))
        .route("/v0.1/servers", get(handle_registry))
        .route("/sys/status", get(handle_sys_status));

    if state.aid_record.is_some() {
        router = router.route("/.well-known/agent", get(handle_aid_record));
    }
    if state.a2a_endpoint.is_some() {
        router = router.route("/.well-known/agent.json", get(handle_agent_card));
    }

    if state.oauth.is_some() {
        router = router
            .route(
                "/.well-known/oauth-authorization-server",
                get(handle_oauth_metadata),
            )
            .route("/oauth/token", post(handle_oauth_token))
            .route("/oauth/register", post(handle_oauth_register));
    }

    let mut router = router.with_state(state);

    if let Some(a2a_state) = a2a_state {
        router = router.merge(
            Router::new()
                .route("/a2a", post(crate::transport::a2a::handle_a2a_post))
                .with_state(a2a_state),
        );
    }

    router
}

/// Set the OAuth provider on an existing router's state.
#[allow(dead_code)]
pub fn set_oauth(state: &mut AppState, provider: Arc<navra_auth::auth::oauth::OAuthProvider>) {
    state.oauth = Some(provider);
}
