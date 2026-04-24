//! ACP (Agent Client Protocol) HTTP transport handler.
//!
//! ACP is JSON-RPC 2.0 over Streamable HTTP (single `POST /acp` endpoint).
//! Same transport as MCP, different method set. Enables Myelix agents to
//! appear in Zed and JetBrains IDEs.
//!
//! Methods:
//! - `acp/initialize` — returns server capabilities (tools list)
//! - `acp/session/new` — creates a new session, returns session_id
//! - `acp/session/prompt` — streaming prompt (stub)

use crate::protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use crate::server::McpServer;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use std::sync::Arc;

/// Shared state for the ACP router.
#[derive(Clone)]
struct AcpState {
    server: Arc<McpServer>,
}

/// Build an axum Router for the ACP transport.
///
/// Exposes a single `POST /acp` endpoint that dispatches JSON-RPC
/// requests to ACP method handlers. Re-uses the server's authenticator.
pub fn build_acp_router(server: Arc<McpServer>) -> Router {
    let state = AcpState { server };
    Router::new()
        .route("/acp", post(handle_acp_post))
        .with_state(state)
}

/// Handle `POST /acp` — ACP JSON-RPC endpoint.
async fn handle_acp_post(
    State(state): State<AcpState>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let server = &state.server;

    // Authenticate using the server's authenticator
    let _agent = match server.authenticator().authenticate(&headers) {
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

    let id = request.id.clone();

    let response = match request.method.as_str() {
        "acp/initialize" => {
            let tools: Vec<serde_json::Value> = server
                .handle_list_tools(&_agent)
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                    })
                })
                .collect();

            JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "protocolVersion": "0.1.0",
                    "serverInfo": server.server_info(),
                    "capabilities": {
                        "tools": tools,
                    },
                }),
            )
        }

        "acp/session/new" => {
            let session_id = uuid::Uuid::new_v4().to_string();
            JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "sessionId": session_id,
                }),
            )
        }

        "acp/session/prompt" => JsonRpcResponse::error(
            id,
            JsonRpcError::new(
                crate::protocol::ErrorCode::Custom(-32001),
                "ACP prompt not yet implemented",
            ),
        ),

        _ => JsonRpcResponse::error(id, JsonRpcError::method_not_found(&request.method)),
    };

    Json(response).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AgentIdentity, NoAuthenticator};
    use crate::protocol::{CallToolResult, ToolDefinition, ToolInputSchema};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    fn test_server() -> Arc<McpServer> {
        Arc::new(
            McpServer::builder()
                .name("acp-test")
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
                .build(),
        )
    }

    async fn post_acp(
        router: &Router,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri("/acp")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn acp_initialize_returns_capabilities() {
        let router = build_acp_router(test_server());
        let (status, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/initialize",
                "id": 1
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["jsonrpc"], "2.0");
        assert!(json["result"]["capabilities"]["tools"].is_array());
        assert_eq!(json["result"]["serverInfo"]["name"], "acp-test");
    }

    #[tokio::test]
    async fn acp_session_new_returns_session_id() {
        let router = build_acp_router(test_server());
        let (status, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/new",
                "id": 2
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let session_id = json["result"]["sessionId"].as_str().unwrap();
        assert!(!session_id.is_empty());
        assert!(uuid::Uuid::parse_str(session_id).is_ok());
    }

    #[tokio::test]
    async fn acp_session_prompt_returns_not_implemented() {
        let router = build_acp_router(test_server());
        let (status, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/prompt",
                "id": 3
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["error"]["code"], -32001);
        assert!(json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not yet implemented"));
    }

    #[tokio::test]
    async fn acp_unknown_method_returns_error() {
        let router = build_acp_router(test_server());
        let (status, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/unknown",
                "id": 4
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["error"]["code"], -32601);
    }
}
