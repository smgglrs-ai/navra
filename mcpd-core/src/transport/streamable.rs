use crate::auth::CallContext;
use crate::protocol::{
    CallToolParams, GetPromptParams, InitializeParams, JsonRpcError, JsonRpcRequest,
    JsonRpcResponse, ReadResourceParams,
};
use crate::server::McpServer;
use crate::transport::a2a::A2aState;
use crate::transport::sse::SseBroadcaster;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::Stream;
use std::convert::Infallible;
use std::sync::Arc;

const SESSION_HEADER: &str = "mcp-session-id";

/// Shared state for the axum router.
#[derive(Clone)]
struct AppState {
    server: Arc<McpServer>,
    broadcaster: SseBroadcaster,
    /// AID (Agent Identity & Discovery) record, served at /.well-known/agent.
    aid_record: Option<serde_json::Value>,
    /// MCP Registry entries, served at /v0.1/servers.
    registry_entries: Vec<serde_json::Value>,
    /// Endpoint URL for A2A Agent Card (None = A2A disabled).
    a2a_endpoint: Option<String>,
    /// Root DID for Agent Card identity.
    root_did: Option<String>,
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

async fn handle_post(
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

async fn handle_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
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
async fn handle_server_card(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.server.server_card())
}

/// Query parameters for the registry endpoint.
#[derive(Debug, serde::Deserialize)]
struct RegistryQuery {
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
async fn handle_registry(
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
        .unwrap_or(0);

    let page: Vec<&serde_json::Value> = filtered
        .into_iter()
        .skip(start)
        .take(query.limit)
        .collect();

    let next_cursor = if start + query.limit < entries.len() {
        Some((start + query.limit).to_string())
    } else {
        None
    };

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
/// Describes mcpd's tools as A2A skills for agent-to-agent discovery.
async fn handle_agent_card(State(state): State<AppState>) -> impl IntoResponse {
    match &state.a2a_endpoint {
        Some(url) => Json(state.server.agent_card(url, state.root_did.as_deref())).into_response(),
        None => (StatusCode::NOT_FOUND, "A2A not configured").into_response(),
    }
}

/// Serve the AID (Agent Identity & Discovery) record.
///
/// Available at `GET /.well-known/agent` without authentication.
/// Returns the AID JSON fallback per the AID specification.
async fn handle_aid_record(State(state): State<AppState>) -> impl IntoResponse {
    match &state.aid_record {
        Some(record) => (StatusCode::OK, Json(record.clone())).into_response(),
        None => (StatusCode::NOT_FOUND, "AID not configured").into_response(),
    }
}

/// Serve the AI OS process table.
///
/// Available at `GET /sys/status`. Returns a JSON array of active
/// agent sessions with call counts, ring levels, and active tools.
async fn handle_sys_status(State(state): State<AppState>) -> impl IntoResponse {
    let snapshot = state.server.process_table().snapshot();
    Json(serde_json::json!({
        "agents": snapshot,
        "session_count": state.server.sessions.count(),
    }))
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

/// Returns (response, optional_session_id_for_header).
async fn dispatch(
    server: Arc<McpServer>,
    request: JsonRpcRequest,
    agent: crate::auth::AgentIdentity,
    session_id: Option<String>,
) -> (JsonRpcResponse, Option<String>) {
    let id = request.id.clone();

    match request.method.as_str() {
        "initialize" => {
            let params: InitializeParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return (
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Invalid initialize params"),
                        ),
                        None,
                    );
                }
            };
            let (result, new_session_id) = server.handle_initialize(params, agent);
            let value = serde_json::to_value(result).unwrap();
            (
                JsonRpcResponse::success(id, value),
                Some(new_session_id),
            )
        }

        "notifications/initialized" => {
            // No response needed for notifications, but since this comes
            // as a request with an id via HTTP, acknowledge it.
            (
                JsonRpcResponse::success(id, serde_json::json!({})),
                session_id,
            )
        }

        "tools/list" => {
            let result = server.handle_list_tools();
            (
                JsonRpcResponse::success(id, serde_json::to_value(result).unwrap()),
                session_id,
            )
        }

        "tools/call" => {
            let params: CallToolParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return (
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Invalid tool call params"),
                        ),
                        session_id,
                    );
                }
            };
            let ctx = CallContext::new(agent, session_id.clone().unwrap_or_default());
            let result = server.handle_call_tool(params, ctx).await;
            (
                JsonRpcResponse::success(id, serde_json::to_value(result).unwrap()),
                session_id,
            )
        }

        "resources/list" => {
            let result = server.handle_list_resources();
            (
                JsonRpcResponse::success(id, serde_json::to_value(result).unwrap()),
                session_id,
            )
        }

        "resources/read" => {
            let params: ReadResourceParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return (
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Invalid resource read params"),
                        ),
                        session_id,
                    );
                }
            };
            let resp = match server.handle_read_resource(params).await {
                Ok(result) => {
                    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
                }
                Err(msg) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
            };
            (resp, session_id)
        }

        "prompts/list" => {
            let result = server.handle_list_prompts();
            (
                JsonRpcResponse::success(id, serde_json::to_value(result).unwrap()),
                session_id,
            )
        }

        "prompts/get" => {
            let params: GetPromptParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return (
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Invalid prompt get params"),
                        ),
                        session_id,
                    );
                }
            };
            let resp = match server.handle_get_prompt(params).await {
                Ok(result) => {
                    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
                }
                Err(msg) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
            };
            (resp, session_id)
        }

        _ => (
            JsonRpcResponse::error(id, JsonRpcError::method_not_found(&request.method)),
            session_id,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AgentIdentity, NoAuthenticator};
    use crate::protocol::{RequestId, ToolDefinition, ToolInputSchema, CallToolResult};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    use crate::module::{Module, PromptHandler, ResourceHandler};

    struct TestPromptModule;

    impl Module for TestPromptModule {
        fn name(&self) -> &str { "test_prompt" }
        fn tools(&self) -> Vec<(ToolDefinition, crate::server::ToolHandler)> { vec![] }
        fn prompts(&self) -> Vec<(crate::protocol::PromptDefinition, PromptHandler)> {
            vec![(
                crate::protocol::PromptDefinition {
                    name: "greet".to_string(),
                    description: Some("A greeting".to_string()),
                    arguments: vec![],
                },
                std::sync::Arc::new(|_args: std::collections::HashMap<String, String>| {
                    Box::pin(async {
                        crate::protocol::GetPromptResult {
                            description: Some("Greeting".to_string()),
                            messages: vec![crate::protocol::PromptMessage {
                                role: crate::protocol::PromptRole::User,
                                content: crate::protocol::Content::text("Hello!"),
                            }],
                        }
                    })
                }),
            )]
        }
    }

    struct TestResourceModule;

    impl Module for TestResourceModule {
        fn name(&self) -> &str { "test_resource" }
        fn tools(&self) -> Vec<(ToolDefinition, crate::server::ToolHandler)> { vec![] }
        fn resources(&self) -> Vec<(crate::protocol::ResourceDefinition, ResourceHandler)> {
            vec![(
                crate::protocol::ResourceDefinition {
                    uri: "info://version".to_string(),
                    name: "Version".to_string(),
                    description: Some("Server version".to_string()),
                    mime_type: Some("text/plain".to_string()),
                },
                std::sync::Arc::new(|uri: String| {
                    Box::pin(async move {
                        crate::protocol::ReadResourceResult {
                            contents: vec![crate::protocol::ResourceContent {
                                uri,
                                mime_type: Some("text/plain".to_string()),
                                text: Some("0.1.0".to_string()),
                                blob: None,
                            }],
                        }
                    })
                }),
            )]
        }
    }

    fn test_server() -> Arc<McpServer> {
        Arc::new(
            McpServer::builder()
                .name("test-server")
                .version("0.1.0")
                .authenticator(NoAuthenticator {
                    default_identity: AgentIdentity::new("tester", "dev"),
                })
                .tool(
                    ToolDefinition {
                        name: "ping".to_string(),
                        description: Some("Returns pong".to_string()),
                        input_schema: ToolInputSchema {
                            schema_type: "object".to_string(),
                            properties: None,
                            required: None,
                        },
                    },
                    |_args, _ctx| Box::pin(async { CallToolResult::text("pong") }),
                )
                .module(TestPromptModule)
                .module(TestResourceModule)
                .build(),
        )
    }

    async fn post_json(
        router: &Router,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn initialize_returns_capabilities() {
        let router = build_router(test_server());
        let (status, json) = post_json(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "initialize",
                "id": 1,
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test"}
                }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(json["result"]["serverInfo"]["name"], "test-server");
    }

    #[tokio::test]
    async fn tools_list_returns_registered_tools() {
        let router = build_router(test_server());
        let (status, json) = post_json(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 2
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let tools = json["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "ping");
    }

    #[tokio::test]
    async fn tools_call_invokes_handler() {
        let router = build_router(test_server());
        let (status, json) = post_json(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": 3,
                "params": {
                    "name": "ping",
                    "arguments": {}
                }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["result"]["content"][0]["text"], "pong");
    }

    #[tokio::test]
    async fn unknown_method_returns_error() {
        let router = build_router(test_server());
        let (_, json) = post_json(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "unknown/method",
                "id": 4
            }),
        )
        .await;

        assert_eq!(json["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn call_unknown_tool_returns_tool_error() {
        let router = build_router(test_server());
        let (_, json) = post_json(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": 5,
                "params": {"name": "nonexistent", "arguments": {}}
            }),
        )
        .await;

        assert!(json["result"]["isError"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn prompts_list_returns_registered_prompts() {
        let router = build_router(test_server());
        let (status, json) = post_json(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "prompts/list",
                "id": 6
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let prompts = json["result"]["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0]["name"], "greet");
    }

    #[tokio::test]
    async fn prompts_get_invokes_handler() {
        let router = build_router(test_server());
        let (status, json) = post_json(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "prompts/get",
                "id": 7,
                "params": {
                    "name": "greet",
                    "arguments": {}
                }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["result"]["description"], "Greeting");
        assert_eq!(json["result"]["messages"][0]["role"], "user");
        assert_eq!(json["result"]["messages"][0]["content"]["text"], "Hello!");
    }

    #[tokio::test]
    async fn prompts_get_unknown_returns_error() {
        let router = build_router(test_server());
        let (_, json) = post_json(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "prompts/get",
                "id": 8,
                "params": {"name": "nonexistent", "arguments": {}}
            }),
        )
        .await;

        assert!(json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Unknown prompt"));
    }

    #[tokio::test]
    async fn resources_list_returns_registered_resources() {
        let router = build_router(test_server());
        let (status, json) = post_json(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "resources/list",
                "id": 9
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let resources = json["result"]["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0]["uri"], "info://version");
    }

    #[tokio::test]
    async fn resources_read_invokes_handler() {
        let router = build_router(test_server());
        let (status, json) = post_json(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "resources/read",
                "id": 10,
                "params": {
                    "uri": "info://version"
                }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["result"]["contents"][0]["text"], "0.1.0");
        assert_eq!(json["result"]["contents"][0]["uri"], "info://version");
    }

    #[tokio::test]
    async fn resources_read_unknown_returns_error() {
        let router = build_router(test_server());
        let (_, json) = post_json(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "resources/read",
                "id": 11,
                "params": {"uri": "info://nonexistent"}
            }),
        )
        .await;

        assert!(json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Unknown resource"));
    }

    /// Post JSON and return status, headers, and body.
    async fn post_json_full(
        router: &Router,
        body: serde_json::Value,
        session_id: Option<&str>,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let mut req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json");

        if let Some(sid) = session_id {
            req = req.header(SESSION_HEADER, sid);
        }

        let req = req
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, headers, json)
    }

    #[tokio::test]
    async fn initialize_returns_session_header() {
        let router = build_router(test_server());
        let (status, headers, json) = post_json_full(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "initialize",
                "id": 1,
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test"}
                }
            }),
            None,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["result"]["protocolVersion"], "2025-03-26");

        // Session header must be present and non-empty
        let session_id = headers.get(SESSION_HEADER).expect("missing session header");
        let sid = session_id.to_str().unwrap();
        assert!(!sid.is_empty());
        // Should be a valid UUID
        assert!(uuid::Uuid::parse_str(sid).is_ok());
    }

    #[tokio::test]
    async fn server_card_returns_metadata() {
        let router = build_router(test_server());
        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/mcp.json")
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Server info
        assert_eq!(json["serverInfo"]["name"], "test-server");
        assert_eq!(json["serverInfo"]["version"], "0.1.0");

        // Protocol version
        assert_eq!(json["protocolVersion"], "2025-03-26");

        // Tools
        let tools = json["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "ping");
        assert_eq!(tools[0]["description"], "Returns pong");

        // Prompts
        let prompts = json["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0]["name"], "greet");

        // Resources
        let resources = json["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0]["uri"], "info://version");

        // Capabilities
        assert!(json["capabilities"]["tools"].is_object());
        assert!(json["capabilities"]["prompts"].is_object());
        assert!(json["capabilities"]["resources"].is_object());
    }

    #[tokio::test]
    async fn aid_record_served_when_configured() {
        let aid = serde_json::json!({
            "v": "aid1",
            "u": "https://tools.example.com/mcp",
            "p": "mcp",
            "a": "pat",
            "s": "Example MCP Tools",
        });
        let router = build_router_with_discovery(
            test_server(),
            SseBroadcaster::new(),
            Some(aid),
            Vec::new(),
            None,
            None,
        );

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/agent")
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["v"], "aid1");
        assert_eq!(json["u"], "https://tools.example.com/mcp");
        assert_eq!(json["p"], "mcp");
        assert_eq!(json["a"], "pat");
        assert_eq!(json["s"], "Example MCP Tools");
    }

    #[tokio::test]
    async fn aid_record_not_served_when_unconfigured() {
        let router = build_router(test_server());

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/agent")
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        // Route doesn't exist when AID is not configured
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn registry_returns_entries() {
        let entries = vec![
            serde_json::json!({
                "server": {
                    "name": "my-tools",
                    "description": "My MCP tools",
                    "remotes": [{"type": "streamable-http", "url": "https://tools.example.com/mcp"}],
                },
                "_meta": {"source": "self"},
            }),
            serde_json::json!({
                "server": {
                    "name": "approved-server",
                    "description": "Approved external server",
                    "remotes": [{"type": "sse", "url": "https://external.example.com/sse"}],
                },
                "_meta": {"source": "whitelist"},
            }),
        ];
        let router = build_router_with_discovery(
            test_server(),
            SseBroadcaster::new(),
            None,
            entries,
            None,
            None,
        );

        let req = Request::builder()
            .method("GET")
            .uri("/v0.1/servers")
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let servers = json["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0]["server"]["name"], "my-tools");
        assert_eq!(servers[1]["server"]["name"], "approved-server");
        assert!(json["metadata"]["nextCursor"].is_null());
    }

    #[tokio::test]
    async fn registry_supports_search() {
        let entries = vec![
            serde_json::json!({"server": {"name": "docs-server", "description": "Document tools"}}),
            serde_json::json!({"server": {"name": "git-server", "description": "Git tools"}}),
            serde_json::json!({"server": {"name": "code-helper", "description": "Code review"}}),
        ];
        let router = build_router_with_discovery(
            test_server(),
            SseBroadcaster::new(),
            None,
            entries,
            None,
            None,
        );

        let req = Request::builder()
            .method("GET")
            .uri("/v0.1/servers?search=git")
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let servers = json["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["server"]["name"], "git-server");
    }

    #[tokio::test]
    async fn agent_card_returns_a2a_skills() {
        let router = build_router_with_discovery(
            test_server(),
            SseBroadcaster::new(),
            None,
            Vec::new(),
            Some("https://tools.example.com/mcp".to_string()),
            None,
        );

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/agent.json")
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["name"], "test-server");
        assert_eq!(json["version"], "0.1.0");
        assert_eq!(json["url"], "https://tools.example.com/mcp");
        assert!(json["capabilities"]["streaming"].as_bool().unwrap());

        let skills = json["skills"].as_array().unwrap();
        assert!(!skills.is_empty());
        // The test server has a "ping" tool
        let ping = skills.iter().find(|s| s["id"] == "ping").unwrap();
        assert_eq!(ping["name"], "ping");
        assert_eq!(ping["description"], "Returns pong");
        assert!(ping["tags"].as_array().unwrap().contains(&serde_json::json!("ping")));
    }

    #[tokio::test]
    async fn registry_supports_pagination() {
        let entries: Vec<serde_json::Value> = (0..5)
            .map(|i| serde_json::json!({"server": {"name": format!("server-{i}"), "description": ""}}))
            .collect();
        let router = build_router_with_discovery(
            test_server(),
            SseBroadcaster::new(),
            None,
            entries,
            None,
            None,
        );

        // First page
        let req = Request::builder()
            .method("GET")
            .uri("/v0.1/servers?limit=2")
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let servers = json["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0]["server"]["name"], "server-0");
        assert_eq!(json["metadata"]["nextCursor"], "2");

        // Second page
        let req = Request::builder()
            .method("GET")
            .uri("/v0.1/servers?limit=2&cursor=2")
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let servers = json["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0]["server"]["name"], "server-2");
    }

    #[tokio::test]
    async fn session_header_not_in_initialize_body() {
        let router = build_router(test_server());
        let (_, _, json) = post_json_full(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "initialize",
                "id": 1,
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test"}
                }
            }),
            None,
        )
        .await;

        // The _sessionId internal field should NOT leak into the response body
        assert!(json["result"]["_sessionId"].is_null());
    }
}
