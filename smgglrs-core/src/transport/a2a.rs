//! A2A HTTP transport handler.
//!
//! Handles `POST /a2a` for A2A JSON-RPC requests. Dispatches to
//! `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`.

use crate::a2a::TaskStore;
use crate::protocol::a2a::{MessageSendParams, TaskIdParams, TaskQueryParams};
use crate::protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use crate::server::McpServer;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::Json;
use std::convert::Infallible;
use std::sync::Arc;

/// Shared state for A2A endpoints.
#[derive(Clone)]
pub(crate) struct A2aState {
    pub server: Arc<McpServer>,
    pub task_store: TaskStore,
}

/// Handle `POST /a2a` — A2A JSON-RPC endpoint.
pub(crate) async fn handle_a2a_post(
    State(state): State<A2aState>,
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

    let id = request.id.clone();

    match request.method.as_str() {
        "message/send" => {
            let params: MessageSendParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return Json(JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params("Invalid message/send params"),
                    ))
                    .into_response();
                }
            };

            match crate::a2a::handle_message_send(server, &state.task_store, params, agent).await {
                Ok(task) => {
                    Json(JsonRpcResponse::success(
                        id,
                        serde_json::to_value(task).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "A2A serialization failed");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                    ))
                    .into_response()
                }
                Err(err) => Json(JsonRpcResponse::error(id, err)).into_response(),
            }
        }

        "message/stream" => {
            let params: MessageSendParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return Json(JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params("Invalid message/stream params"),
                    ))
                    .into_response();
                }
            };

            let events = crate::a2a::handle_message_stream(
                server,
                &state.task_store,
                params,
                agent,
                id,
            )
            .await;

            let stream = futures_util::stream::iter(events.into_iter().map(|resp| {
                let data = serde_json::to_string(&resp).unwrap_or_default();
                Ok::<_, Infallible>(Event::default().data(data))
            }));

            Sse::new(stream)
                .keep_alive(KeepAlive::default())
                .into_response()
        }

        "tasks/get" => {
            let params: TaskQueryParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return Json(JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params("Invalid tasks/get params"),
                    ))
                    .into_response();
                }
            };

            match crate::a2a::handle_tasks_get(&state.task_store, params, &agent) {
                Ok(task) => Json(JsonRpcResponse::success(
                    id,
                    serde_json::to_value(task).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "A2A serialization failed");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ))
                .into_response(),
                Err(err) => Json(JsonRpcResponse::error(id, err)).into_response(),
            }
        }

        "tasks/cancel" => {
            let params: TaskIdParams = match request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
            {
                Some(p) => p,
                None => {
                    return Json(JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params("Invalid tasks/cancel params"),
                    ))
                    .into_response();
                }
            };

            match crate::a2a::handle_tasks_cancel(&state.task_store, params, &agent) {
                Ok(task) => Json(JsonRpcResponse::success(
                    id,
                    serde_json::to_value(task).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "A2A serialization failed");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ))
                .into_response(),
                Err(err) => Json(JsonRpcResponse::error(id, err)).into_response(),
            }
        }

        _ => Json(JsonRpcResponse::error(
            id,
            JsonRpcError::method_not_found(&request.method),
        ))
        .into_response(),
    }
}
