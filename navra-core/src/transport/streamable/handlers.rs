use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use super::router::AppState;

/// Serve the MCP Server Card — static metadata about this server.
///
/// Available at `GET /.well-known/mcp.json` without authentication.
/// Enables client autoconfiguration without a full initialize handshake.
pub(super) async fn handle_server_card(State(state): State<AppState>) -> impl IntoResponse {
    let mut card = state.server.server_card();
    // Redact internal tools from public server card
    let internal_prefixes = ["cap_delegate", "sys_", "navra_var_"];
    if let Some(tools) = card.get_mut("tools").and_then(|t| t.as_array_mut()) {
        tools.retain(|t| {
            let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("");
            !internal_prefixes.iter().any(|p| name.starts_with(p))
        });
    }
    Json(card)
}

/// Query parameters for the registry endpoint.
#[derive(Debug, serde::Deserialize)]
pub(super) struct RegistryQuery {
    #[serde(default = "default_registry_limit")]
    limit: usize,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    search: Option<String>,
}

fn default_registry_limit() -> usize {
    96
}

/// Serve the MCP Registry API.
///
/// `GET /v0.1/servers` — paginated, searchable list of MCP servers.
/// Compatible with the official MCP Registry API format.
pub(super) async fn handle_registry(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<RegistryQuery>,
) -> impl IntoResponse {
    let entries = &state.registry_entries;

    // Filter by search term (matches name or description)
    let filtered: Vec<&serde_json::Value> = if let Some(ref search) = query.search {
        let search_lower = search.to_lowercase();
        entries
            .iter()
            .filter(|e| {
                let name = e["server"]["name"].as_str().unwrap_or("");
                let desc = e["server"]["description"].as_str().unwrap_or("");
                name.to_lowercase().contains(&search_lower)
                    || desc.to_lowercase().contains(&search_lower)
            })
            .collect()
    } else {
        entries.iter().collect()
    };

    // Pagination via cursor (cursor = index as string)
    let start = query
        .cursor
        .as_ref()
        .and_then(|c| c.parse::<usize>().ok())
        .unwrap_or(0)
        .min(filtered.len());

    let limit = query.limit.min(100);

    let page: Vec<&serde_json::Value> = filtered.into_iter().skip(start).take(limit).collect();

    let next_cursor = start
        .checked_add(limit)
        .filter(|&next| next < entries.len())
        .map(|next| next.to_string());

    Json(serde_json::json!({
        "servers": page,
        "metadata": {
            "nextCursor": next_cursor,
        }
    }))
}

/// Serve the A2A Agent Card.
///
/// Available at `GET /.well-known/agent.json` without authentication.
/// Describes navra's tools as A2A skills for agent-to-agent discovery.
pub(super) async fn handle_agent_card(State(state): State<AppState>) -> impl IntoResponse {
    match &state.a2a_endpoint {
        Some(url) => Json(state.server.agent_card(url, state.root_did.as_deref())).into_response(),
        None => (StatusCode::NOT_FOUND, "A2A not configured").into_response(),
    }
}

/// Serve the AID (Agent Identity & Discovery) record.
///
/// Available at `GET /.well-known/agent` without authentication.
/// Returns the AID JSON fallback per the AID specification.
pub(super) async fn handle_aid_record(State(state): State<AppState>) -> impl IntoResponse {
    match &state.aid_record {
        Some(record) => (StatusCode::OK, Json(record.clone())).into_response(),
        None => (StatusCode::NOT_FOUND, "AID not configured").into_response(),
    }
}

/// Serve the AI OS process table.
///
/// Available at `GET /sys/status`. Returns a JSON array of active
/// agent sessions with call counts, ring levels, and active tools.
pub(super) async fn handle_sys_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Require authentication — process table contains sensitive operational data
    if state.server.authenticator().authenticate(&headers).is_err() {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Authentication required for /sys/status"})),
        )
            .into_response();
    }
    let snapshot = state.server.process_table().snapshot();
    Json(serde_json::json!({
        "agents": snapshot,
        "session_count": state.server.sessions.count(),
    }))
    .into_response()
}

pub(super) async fn handle_metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.render(),
    )
}

// --- OAuth 2.0 endpoints ---

pub(super) async fn handle_oauth_metadata(
    State(state): State<AppState>,
) -> axum::response::Response {
    match &state.oauth {
        Some(provider) => axum::Json(provider.metadata()).into_response(),
        None => (axum::http::StatusCode::NOT_FOUND, "OAuth not enabled").into_response(),
    }
}

pub(super) async fn handle_oauth_token(
    State(state): State<AppState>,
    axum::Json(request): axum::Json<navra_auth::auth::oauth::TokenRequest>,
) -> axum::response::Response {
    let provider = match &state.oauth {
        Some(p) => p,
        None => return (axum::http::StatusCode::NOT_FOUND, "OAuth not enabled").into_response(),
    };
    match provider.issue_token(&request) {
        Ok(response) => axum::Json(response).into_response(),
        Err(msg) => (axum::http::StatusCode::BAD_REQUEST, msg).into_response(),
    }
}

pub(super) async fn handle_oauth_register(
    State(state): State<AppState>,
    axum::Json(request): axum::Json<navra_auth::auth::oauth::ClientRegistrationRequest>,
) -> axum::response::Response {
    let provider = match &state.oauth {
        Some(p) => p,
        None => return (axum::http::StatusCode::NOT_FOUND, "OAuth not enabled").into_response(),
    };
    let reg = provider.register_dynamic(&request);
    (axum::http::StatusCode::CREATED, axum::Json(reg)).into_response()
}
