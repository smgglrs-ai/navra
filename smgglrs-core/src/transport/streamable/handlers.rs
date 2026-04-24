use crate::protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::Json;
use futures_util::stream::Stream;
use std::convert::Infallible;

use super::dispatch::dispatch;
use super::router::AppState;

pub(super) const SESSION_HEADER: &str = "mcp-session-id";

pub(super) async fn handle_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let server = &state.server;
    // Authenticate
    let agent = match server.authenticator().authenticate(&headers) {
        Ok(agent) => agent,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(JsonRpcResponse::error(
                    request.id,
                    JsonRpcError::new(
                        crate::protocol::ErrorCode::Custom(-32000),
                        "Authentication failed",
                    ),
                )),
            )
                .into_response();
        }
    };

    // Validate jsonrpc version
    if request.jsonrpc != "2.0" {
        return (
            StatusCode::BAD_REQUEST,
            Json(JsonRpcResponse::error(
                request.id,
                JsonRpcError::invalid_request("Expected jsonrpc: \"2.0\""),
            )),
        )
            .into_response();
    }

    // Extract session ID from request header (for non-initialize requests)
    let session_id = headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let (response, new_session_id) = dispatch(state.server.clone(), request, agent, session_id).await;

    let mut resp = Json(&response).into_response();
    // Include session ID in response header (set on initialize, echoed otherwise)
    if let Some(sid) = new_session_id {
        if let Ok(val) = sid.parse() {
            resp.headers_mut().insert(SESSION_HEADER, val);
        }
    }

    resp
}

pub(super) async fn handle_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Authenticate before session lookup
    if state.server.authenticator().authenticate(&headers).is_err() {
        return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response();
    }

    // GET is used for SSE streaming (server-to-client).
    // Requires a valid session.
    let session_id = match headers.get(SESSION_HEADER) {
        Some(v) => match v.to_str() {
            Ok(s) if !s.is_empty() => s.to_string(),
            _ => {
                return (StatusCode::BAD_REQUEST, "Invalid session header").into_response();
            }
        },
        None => {
            return (StatusCode::BAD_REQUEST, "Missing mcp-session-id header").into_response();
        }
    };

    // Validate session exists
    if state.server.sessions().get(&session_id).is_none() {
        return (StatusCode::NOT_FOUND, "Unknown session").into_response();
    }

    // Subscribe to the session's SSE channel
    let rx = state.broadcaster.subscribe(&session_id);

    let stream = make_sse_stream(rx);
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Serve the MCP Server Card — static metadata about this server.
///
/// Available at `GET /.well-known/mcp.json` without authentication.
/// Enables client autoconfiguration without a full initialize handshake.
pub(super) async fn handle_server_card(State(state): State<AppState>) -> impl IntoResponse {
    let mut card = state.server.server_card();
    // Redact internal tools from public server card
    let internal_prefixes = ["cap_delegate", "sys_", "smgglrs_var_"];
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

    let page: Vec<&serde_json::Value> = filtered
        .into_iter()
        .skip(start)
        .take(limit)
        .collect();

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
/// Describes smgglrs's tools as A2A skills for agent-to-agent discovery.
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
        ).into_response();
    }
    let snapshot = state.server.process_table().snapshot();
    Json(serde_json::json!({
        "agents": snapshot,
        "session_count": state.server.sessions.count(),
    })).into_response()
}

/// Convert a broadcast receiver into an SSE event stream.
fn make_sse_stream(
    mut rx: tokio::sync::broadcast::Receiver<crate::transport::sse::SseEvent>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(sse_event) => {
                    let event = Event::default()
                        .event(sse_event.event)
                        .data(sse_event.data);
                    yield Ok(event);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "SSE client lagged, dropped events");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    }
}
