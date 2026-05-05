//! ACP (Agent Client Protocol) HTTP transport handler.
//!
//! ACP is JSON-RPC 2.0 over Streamable HTTP (single `POST /acp` endpoint).
//! Same transport as MCP, different method set. Enables smgglrs agents to
//! appear in Zed and JetBrains IDEs.
//!
//! Methods:
//! - `acp/initialize` — returns server capabilities (tools list)
//! - `acp/session/new` — creates a new session, returns session_id
//! - `acp/session/load` — reconnect to an existing session
//! - `acp/session/prompt` — streaming prompt execution via SSE

use crate::auth::CallContext;
use crate::protocol::{CallToolParams, JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use crate::server::McpServer;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use std::convert::Infallible;
use std::sync::Arc;

/// Session ID header used by ACP (mirrors MCP convention).
const ACP_SESSION_HEADER: &str = "acp-session-id";

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
///
/// Most methods return a plain JSON-RPC response. `acp/session/prompt`
/// returns `text/event-stream` (SSE) with incremental results.
async fn handle_acp_post(
    State(state): State<AcpState>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let server = &state.server;

    // Authenticate using the server's authenticator
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

    let id = request.id.clone();

    match request.method.as_str() {
        "acp/initialize" => {
            let tools: Vec<serde_json::Value> = server
                .handle_list_tools(&agent)
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                    })
                })
                .collect();

            Json(JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "protocolVersion": "0.1.0",
                    "serverInfo": server.server_info(),
                    "capabilities": {
                        "streaming": true,
                        "tools": tools,
                    },
                }),
            ))
            .into_response()
        }

        "acp/session/new" => {
            let session_id = uuid::Uuid::new_v4().to_string();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let session = crate::session::Session {
                id: session_id.clone(),
                agent: agent.clone(),
                client_info: crate::protocol::ClientInfo {
                    name: "acp-client".to_string(),
                    version: None,
                },
                initialized: true,
                context_label: crate::ifc::DataLabel::TRUSTED_PUBLIC,
                created_at: now,
                last_accessed: now,
            };
            server.sessions().create(session);

            let mut resp = Json(JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "sessionId": session_id,
                }),
            ))
            .into_response();
            if let Ok(val) = session_id.parse() {
                resp.headers_mut().insert(ACP_SESSION_HEADER, val);
            }
            resp
        }

        "acp/session/load" => {
            let session_id = request
                .params
                .as_ref()
                .and_then(|p| p.get("sessionId"))
                .and_then(|v| v.as_str())
                .or_else(|| {
                    headers
                        .get(ACP_SESSION_HEADER)
                        .and_then(|v| v.to_str().ok())
                });

            match session_id {
                Some(sid) => match server.sessions().get(sid) {
                    Some(session) => {
                        if session.agent.name != agent.name {
                            return Json(JsonRpcResponse::error(
                                id,
                                JsonRpcError::new(
                                    crate::protocol::ErrorCode::Custom(-32000),
                                    "Session does not belong to this agent",
                                ),
                            ))
                            .into_response();
                        }
                        server.sessions().touch(sid);
                        let mut resp = Json(JsonRpcResponse::success(
                            id,
                            serde_json::json!({
                                "sessionId": sid,
                                "resumed": true,
                            }),
                        ))
                        .into_response();
                        if let Ok(val) = sid.parse() {
                            resp.headers_mut().insert(ACP_SESSION_HEADER, val);
                        }
                        resp
                    }
                    None => Json(JsonRpcResponse::error(
                        id,
                        JsonRpcError::new(
                            crate::protocol::ErrorCode::Custom(-32001),
                            "Session not found — it may have expired",
                        ),
                    ))
                    .into_response(),
                },
                None => Json(JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(
                        "Missing sessionId in params or acp-session-id header",
                    ),
                ))
                .into_response(),
            }
        }

        "acp/session/prompt" => {
            handle_session_prompt(state.server.clone(), id, request.params, agent, &headers)
                .await
                .into_response()
        }

        _ => Json(JsonRpcResponse::error(
            id,
            JsonRpcError::method_not_found(&request.method),
        ))
        .into_response(),
    }
}

/// Parameters for `acp/session/prompt`.
#[derive(Debug, serde::Deserialize)]
struct PromptParams {
    /// Session to execute the prompt in.
    #[serde(rename = "sessionId")]
    session_id: String,
    /// The prompt message(s). Each entry has a `role` and `content`.
    messages: Vec<PromptMessage>,
    /// Optional: tools the agent is allowed to call during this prompt.
    /// If omitted, all tools are available.
    #[serde(default)]
    tools: Option<Vec<String>>,
}

/// A single message in an ACP prompt request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PromptMessage {
    role: String,
    content: String,
}

/// Handle `acp/session/prompt` — streaming prompt execution.
///
/// Validates the session, iterates over the prompt messages, calls
/// any referenced tools, and streams results back as SSE events.
///
/// SSE event types:
/// - `acp.prompt.started` — prompt accepted, streaming begins
/// - `acp.tool.calling` — about to call a tool
/// - `acp.tool.result` — tool call completed with result
/// - `acp.prompt.completed` — all processing finished, final response
/// - `acp.prompt.failed` — an error occurred during processing
async fn handle_session_prompt(
    server: Arc<McpServer>,
    id: crate::protocol::RequestId,
    params: Option<serde_json::Value>,
    agent: crate::auth::AgentIdentity,
    headers: &HeaderMap,
) -> impl IntoResponse {
    // Parse prompt params
    let prompt_params: PromptParams = match params.and_then(|p| serde_json::from_value(p).ok()) {
        Some(p) => p,
        None => {
            return Json(JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params(
                    "Expected params: { sessionId, messages: [{ role, content }] }",
                ),
            ))
            .into_response();
        }
    };

    // Allow session ID from params or header
    let session_id = if !prompt_params.session_id.is_empty() {
        prompt_params.session_id.clone()
    } else {
        match headers
            .get(ACP_SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
        {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => {
                return Json(JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params("Missing sessionId"),
                ))
                .into_response();
            }
        }
    };

    // Validate session exists and belongs to this agent
    match server.sessions().get(&session_id) {
        Some(session) => {
            if session.agent.name != agent.name {
                return Json(JsonRpcResponse::error(
                    id,
                    JsonRpcError::new(
                        crate::protocol::ErrorCode::Custom(-32000),
                        "Session does not belong to this agent",
                    ),
                ))
                .into_response();
            }
            server.sessions().touch(&session_id);
        }
        None => {
            return Json(JsonRpcResponse::error(
                id,
                JsonRpcError::new(
                    crate::protocol::ErrorCode::Custom(-32001),
                    "Session not found — it may have expired",
                ),
            ))
            .into_response();
        }
    }

    let messages = prompt_params.messages;
    let allowed_tools = prompt_params.tools;
    let request_id = id;

    // Build the SSE stream
    let stream = async_stream::stream! {
        // Event: prompt started
        let started = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "acp/session/prompt",
            "id": request_id,
            "type": "acp.prompt.started",
            "sessionId": session_id,
            "messageCount": messages.len(),
        });
        yield Ok::<Event, Infallible>(
            Event::default()
                .event("acp.prompt.started")
                .data(serde_json::to_string(&started).unwrap_or_default())
        );

        // Process each user message. Extract tool call requests from
        // messages that match the pattern: `/tool <tool_name> <args_json>`
        let mut results: Vec<serde_json::Value> = Vec::new();
        let mut error_occurred = false;

        for (msg_idx, message) in messages.iter().enumerate() {
            let content = message.content.trim();

            // Check if this is a tool call request
            if let Some(tool_call) = parse_tool_call(content) {
                // Check if the tool is in the allowed list (if specified)
                if let Some(ref allowed) = allowed_tools {
                    if !allowed.iter().any(|t| t == &tool_call.tool_name) {
                        let err_data = serde_json::json!({
                            "type": "acp.prompt.failed",
                            "error": format!("Tool '{}' not in allowed tools list", tool_call.tool_name),
                            "messageIndex": msg_idx,
                        });
                        yield Ok(Event::default()
                            .event("acp.prompt.failed")
                            .data(serde_json::to_string(&err_data).unwrap_or_default()));
                        error_occurred = true;
                        break;
                    }
                }

                // Notify: about to call tool
                let calling = serde_json::json!({
                    "type": "acp.tool.calling",
                    "tool": tool_call.tool_name,
                    "arguments": tool_call.arguments,
                    "messageIndex": msg_idx,
                });
                yield Ok(Event::default()
                    .event("acp.tool.calling")
                    .data(serde_json::to_string(&calling).unwrap_or_default()));

                // Execute the tool call
                let ctx = CallContext::new(agent.clone(), session_id.clone());
                let call_params = CallToolParams {
                    name: tool_call.tool_name.clone(),
                    arguments: tool_call.arguments.clone(),
                };
                let tool_result = server.handle_call_tool(call_params, ctx).await;

                // Stream the result
                let result_content: Vec<String> = tool_result.content.iter().filter_map(|c| {
                    match c {
                        crate::protocol::Content::Text(t) => Some(t.text.clone()),
                        _ => None,
                    }
                }).collect();

                let result_data = serde_json::json!({
                    "type": "acp.tool.result",
                    "tool": tool_call.tool_name,
                    "messageIndex": msg_idx,
                    "isError": tool_result.is_error,
                    "content": result_content,
                });
                yield Ok(Event::default()
                    .event("acp.tool.result")
                    .data(serde_json::to_string(&result_data).unwrap_or_default()));

                results.push(result_data);
            } else {
                // Non-tool message: echo it back as an acknowledgement
                let ack = serde_json::json!({
                    "type": "acp.message.received",
                    "messageIndex": msg_idx,
                    "role": message.role,
                    "contentLength": content.len(),
                });
                yield Ok(Event::default()
                    .event("acp.message.received")
                    .data(serde_json::to_string(&ack).unwrap_or_default()));

                results.push(serde_json::json!({
                    "type": "message",
                    "role": message.role,
                    "content": content,
                }));
            }
        }

        // Event: prompt completed (or failed)
        if error_occurred {
            // Already sent the failure event above
        } else {
            let completed = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/prompt",
                "id": request_id,
                "type": "acp.prompt.completed",
                "sessionId": session_id,
                "results": results,
            });
            yield Ok(Event::default()
                .event("acp.prompt.completed")
                .data(serde_json::to_string(&completed).unwrap_or_default()));
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// A parsed tool call from a prompt message.
struct ToolCall {
    tool_name: String,
    arguments: serde_json::Value,
}

/// Parse a tool call from a message content string.
///
/// Supports two formats:
/// 1. `/tool <name> <json_args>` — inline command
/// 2. JSON object with `"tool"` and `"arguments"` fields
fn parse_tool_call(content: &str) -> Option<ToolCall> {
    let trimmed = content.trim();

    // Format 1: /tool <name> <json>
    if let Some(rest) = trimmed.strip_prefix("/tool ") {
        let mut parts = rest.splitn(2, ' ');
        let name = parts.next()?.to_string();
        let args_str = parts.next().unwrap_or("{}");
        let arguments = serde_json::from_str(args_str).unwrap_or(serde_json::json!({}));
        return Some(ToolCall {
            tool_name: name,
            arguments,
        });
    }

    // Format 2: { "tool": "name", "arguments": { ... } }
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(tool_name) = obj.get("tool").and_then(|v| v.as_str()) {
            let arguments = obj
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            return Some(ToolCall {
                tool_name: tool_name.to_string(),
                arguments,
            });
        }
    }

    None
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
                        annotations: None,
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

    async fn post_acp_raw(router: &Router, body: serde_json::Value) -> (StatusCode, String) {
        let req = Request::builder()
            .method("POST")
            .uri("/acp")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes).to_string();
        (status, text)
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
        assert_eq!(json["result"]["capabilities"]["streaming"], true);
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
    async fn acp_session_new_creates_real_session() {
        let server = test_server();
        let router = build_acp_router(server.clone());
        let (_, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/new",
                "id": 1
            }),
        )
        .await;

        let session_id = json["result"]["sessionId"].as_str().unwrap();
        // Session should exist in the store
        assert!(server.sessions().get(session_id).is_some());
    }

    #[tokio::test]
    async fn acp_session_load_existing() {
        let server = test_server();
        let router = build_acp_router(server.clone());

        // Create a session first
        let (_, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/new",
                "id": 1
            }),
        )
        .await;
        let session_id = json["result"]["sessionId"].as_str().unwrap().to_string();

        // Load it
        let (status, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/load",
                "id": 2,
                "params": { "sessionId": session_id }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["result"]["sessionId"].as_str().unwrap(), session_id);
        assert_eq!(json["result"]["resumed"], true);
    }

    #[tokio::test]
    async fn acp_session_load_nonexistent() {
        let router = build_acp_router(test_server());
        let (status, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/load",
                "id": 1,
                "params": { "sessionId": "does-not-exist" }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["error"]["code"], -32001);
    }

    #[tokio::test]
    async fn acp_session_prompt_streams_tool_result() {
        let server = test_server();
        let router = build_acp_router(server.clone());

        // Create a session
        let (_, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/new",
                "id": 1
            }),
        )
        .await;
        let session_id = json["result"]["sessionId"].as_str().unwrap().to_string();

        // Send a prompt with a tool call
        let (status, body) = post_acp_raw(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/prompt",
                "id": 3,
                "params": {
                    "sessionId": session_id,
                    "messages": [
                        { "role": "user", "content": "/tool ping {}" }
                    ]
                }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        // SSE body should contain the expected event types
        assert!(body.contains("event:acp.prompt.started") || body.contains("event: acp.prompt.started"),
            "Expected prompt.started event in SSE body: {}", body);
        assert!(body.contains("event:acp.tool.calling") || body.contains("event: acp.tool.calling"),
            "Expected tool.calling event in SSE body: {}", body);
        assert!(body.contains("event:acp.tool.result") || body.contains("event: acp.tool.result"),
            "Expected tool.result event in SSE body: {}", body);
        assert!(body.contains("event:acp.prompt.completed") || body.contains("event: acp.prompt.completed"),
            "Expected prompt.completed event in SSE body: {}", body);
        // The tool result should contain "pong"
        assert!(body.contains("pong"), "Expected 'pong' in tool result: {}", body);
    }

    #[tokio::test]
    async fn acp_session_prompt_streams_message_ack() {
        let server = test_server();
        let router = build_acp_router(server.clone());

        // Create a session
        let (_, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/new",
                "id": 1
            }),
        )
        .await;
        let session_id = json["result"]["sessionId"].as_str().unwrap().to_string();

        // Send a plain text message (no tool call)
        let (status, body) = post_acp_raw(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/prompt",
                "id": 2,
                "params": {
                    "sessionId": session_id,
                    "messages": [
                        { "role": "user", "content": "Hello, world" }
                    ]
                }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("acp.message.received"),
            "Expected message.received event: {}", body);
        assert!(body.contains("acp.prompt.completed"),
            "Expected prompt.completed event: {}", body);
    }

    #[tokio::test]
    async fn acp_session_prompt_json_tool_format() {
        let server = test_server();
        let router = build_acp_router(server.clone());

        // Create a session
        let (_, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/new",
                "id": 1
            }),
        )
        .await;
        let session_id = json["result"]["sessionId"].as_str().unwrap().to_string();

        // Send a prompt using JSON tool call format
        let (status, body) = post_acp_raw(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/prompt",
                "id": 2,
                "params": {
                    "sessionId": session_id,
                    "messages": [
                        { "role": "user", "content": "{\"tool\": \"ping\", \"arguments\": {}}" }
                    ]
                }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("pong"), "Expected 'pong' in tool result: {}", body);
    }

    #[tokio::test]
    async fn acp_session_prompt_invalid_session() {
        let router = build_acp_router(test_server());
        let (status, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/prompt",
                "id": 1,
                "params": {
                    "sessionId": "nonexistent-session",
                    "messages": [
                        { "role": "user", "content": "hello" }
                    ]
                }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["error"]["code"], -32001);
    }

    #[tokio::test]
    async fn acp_session_prompt_missing_params() {
        let router = build_acp_router(test_server());
        let (status, json) = post_acp(
            &router,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "acp/session/prompt",
                "id": 1
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(json["error"]["code"].as_i64().is_some());
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

    #[test]
    fn parse_tool_call_slash_format() {
        let tc = parse_tool_call("/tool ping {}").unwrap();
        assert_eq!(tc.tool_name, "ping");
        assert_eq!(tc.arguments, serde_json::json!({}));
    }

    #[test]
    fn parse_tool_call_slash_with_args() {
        let tc = parse_tool_call(r#"/tool file_read {"path": "/tmp/test.txt"}"#).unwrap();
        assert_eq!(tc.tool_name, "file_read");
        assert_eq!(tc.arguments["path"], "/tmp/test.txt");
    }

    #[test]
    fn parse_tool_call_json_format() {
        let tc = parse_tool_call(r#"{"tool": "ping", "arguments": {"key": "val"}}"#).unwrap();
        assert_eq!(tc.tool_name, "ping");
        assert_eq!(tc.arguments["key"], "val");
    }

    #[test]
    fn parse_tool_call_plain_text_returns_none() {
        assert!(parse_tool_call("Hello world").is_none());
        assert!(parse_tool_call("").is_none());
    }
}
