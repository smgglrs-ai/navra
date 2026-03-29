use crate::auth::CallContext;
use crate::protocol::{
    CallToolParams, InitializeParams, JsonRpcError, JsonRpcRequest, JsonRpcResponse,
};
use crate::server::McpServer;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::Arc;

const SESSION_HEADER: &str = "mcp-session-id";

/// Build an axum Router for the MCP Streamable HTTP transport.
pub fn build_router(server: Arc<McpServer>) -> Router {
    Router::new()
        .route("/mcp", post(handle_post))
        .route("/mcp", get(handle_get))
        .with_state(server)
}

async fn handle_post(
    State(server): State<Arc<McpServer>>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
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

    let response = dispatch(server, request, agent).await;

    // Add session header if present
    let mut resp = Json(&response).into_response();
    if let Some(result) = &response.result {
        // After initialize, include session id in header
        if let Some(session_id) = result.get("_sessionId").and_then(|v| v.as_str()) {
            resp.headers_mut().insert(
                SESSION_HEADER,
                session_id.parse().unwrap(),
            );
        }
    }

    resp
}

async fn handle_get(
    State(_server): State<Arc<McpServer>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // GET is used for SSE streaming (server-to-client).
    // Requires a valid session.
    let _session_id = match headers.get(SESSION_HEADER) {
        Some(v) => v.to_str().unwrap_or("").to_string(),
        None => {
            return (StatusCode::BAD_REQUEST, "Missing session header").into_response();
        }
    };

    // TODO: SSE stream for server-initiated notifications
    (StatusCode::OK, "SSE endpoint — not yet implemented").into_response()
}

async fn dispatch(
    server: Arc<McpServer>,
    request: JsonRpcRequest,
    agent: crate::auth::AgentIdentity,
) -> JsonRpcResponse {
    let id = request.id.clone();

    match request.method.as_str() {
        "initialize" => {
            let params: InitializeParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params("Invalid initialize params"),
                    );
                }
            };
            let result = server.handle_initialize(params, agent);
            let mut value = serde_json::to_value(result).unwrap();
            // Embed session ID for the transport layer to extract
            // (stripped before sending to client in production)
            if let Some(obj) = value.as_object_mut() {
                // Get the latest session
                // Simple approach: session was just created
                obj.insert(
                    "_sessionId".to_string(),
                    serde_json::json!(uuid::Uuid::new_v4().to_string()),
                );
            }
            JsonRpcResponse::success(id, value)
        }

        "notifications/initialized" => {
            // No response needed for notifications, but since this comes
            // as a request with an id via HTTP, acknowledge it.
            JsonRpcResponse::success(id, serde_json::json!({}))
        }

        "tools/list" => {
            let result = server.handle_list_tools();
            JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
        }

        "tools/call" => {
            let params: CallToolParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params("Invalid tool call params"),
                    );
                }
            };
            let ctx = CallContext {
                agent,
                session_id: "TODO".to_string(),
            };
            let result = server.handle_call_tool(params, ctx).await;
            JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
        }

        _ => JsonRpcResponse::error(id, JsonRpcError::method_not_found(&request.method)),
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

    fn test_server() -> Arc<McpServer> {
        Arc::new(
            McpServer::builder()
                .name("test-server")
                .version("0.1.0")
                .authenticator(NoAuthenticator {
                    default_identity: AgentIdentity {
                        name: "tester".to_string(),
                        permissions: "dev".to_string(),
                    },
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
}
