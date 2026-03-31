use crate::auth::CallContext;
use crate::protocol::{
    CallToolParams, GetPromptParams, InitializeParams, JsonRpcError, JsonRpcRequest,
    JsonRpcResponse, ReadResourceParams,
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

        "resources/list" => {
            let result = server.handle_list_resources();
            JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
        }

        "resources/read" => {
            let params: ReadResourceParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params("Invalid resource read params"),
                    );
                }
            };
            match server.handle_read_resource(params).await {
                Ok(result) => {
                    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
                }
                Err(msg) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
            }
        }

        "prompts/list" => {
            let result = server.handle_list_prompts();
            JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
        }

        "prompts/get" => {
            let params: GetPromptParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params("Invalid prompt get params"),
                    );
                }
            };
            match server.handle_get_prompt(params).await {
                Ok(result) => {
                    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
                }
                Err(msg) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
            }
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
}
