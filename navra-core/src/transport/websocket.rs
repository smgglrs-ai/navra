use crate::protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use crate::transport::streamable::dispatch::dispatch;
use crate::transport::streamable::router::AppState;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) async fn handle_ws_upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let agent = match state.server.authenticator().authenticate(&headers) {
        Ok(agent) => agent,
        Err(_) => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                "Authentication failed",
            )
                .into_response();
        }
    };

    ws.on_upgrade(move |socket| handle_ws_connection(socket, state, agent))
}

async fn handle_ws_connection(
    socket: WebSocket,
    state: AppState,
    agent: crate::auth::AgentIdentity,
) {
    let (ws_sender, mut ws_receiver) = socket.split();
    let ws_sender = Arc::new(Mutex::new(ws_sender));
    let session_id: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let notify_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>> = Arc::new(Mutex::new(None));

    while let Some(msg) = ws_receiver.next().await {
        let msg = match msg {
            Ok(msg) => msg,
            Err(e) => {
                tracing::debug!(error = %e, "WebSocket receive error");
                break;
            }
        };

        match msg {
            Message::Text(text) => {
                let request: JsonRpcRequest = match serde_json::from_str(&text) {
                    Ok(r) => r,
                    Err(_) => {
                        let resp = JsonRpcResponse::error(
                            crate::protocol::RequestId::Number(0),
                            JsonRpcError::parse_error(),
                        );
                        let json = serde_json::to_string(&resp).unwrap_or_default();
                        let mut sender = ws_sender.lock().await;
                        if sender.send(Message::Text(json.into())).await.is_err() {
                            tracing::debug!("WebSocket client disconnected during parse-error response");
                            break;
                        }
                        continue;
                    }
                };

                if request.jsonrpc != "2.0" {
                    let resp = JsonRpcResponse::error(
                        request.id,
                        JsonRpcError::invalid_request("Expected jsonrpc: \"2.0\""),
                    );
                    let json = serde_json::to_string(&resp).unwrap_or_default();
                    let mut sender = ws_sender.lock().await;
                    if sender.send(Message::Text(json.into())).await.is_err() {
                        tracing::debug!("WebSocket client disconnected during invalid-request response");
                        break;
                    }
                    continue;
                }

                let sid = session_id.lock().await.clone();
                let (response, new_sid) =
                    dispatch(state.server.clone(), request, agent.clone(), sid).await;

                // On initialize, start forwarding notifications for this session
                if let Some(ref new_id) = new_sid {
                    let mut sid_guard = session_id.lock().await;
                    if sid_guard.is_none() {
                        *sid_guard = Some(new_id.clone());

                        let rx = state.broadcaster.subscribe(new_id);
                        let sender_clone = ws_sender.clone();
                        let handle = tokio::spawn(forward_notifications(rx, sender_clone));
                        *notify_handle.lock().await = Some(handle);
                    }
                }

                let json = serde_json::to_string(&response).unwrap_or_default();
                let mut sender = ws_sender.lock().await;
                if sender.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            Message::Ping(data) => {
                let mut sender = ws_sender.lock().await;
                if sender.send(Message::Pong(data)).await.is_err() {
                    tracing::debug!("WebSocket client disconnected during pong");
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    if let Some(handle) = notify_handle.lock().await.take() {
        handle.abort();
    }
    tracing::debug!("WebSocket connection closed");
}

async fn forward_notifications(
    mut rx: tokio::sync::broadcast::Receiver<crate::transport::sse::SseEvent>,
    ws_sender: Arc<Mutex<futures_util::stream::SplitSink<WebSocket, Message>>>,
) {
    while let Ok(event) = rx.recv().await {
        let mut sender = ws_sender.lock().await;
        if sender.send(Message::Text(event.data.into())).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::McpServer;
    use crate::transport::sse::SseBroadcaster;

    fn make_state() -> AppState {
        let server = Arc::new(
            McpServer::builder()
                .name("ws-test")
                .allow_anonymous()
                .build(),
        );
        AppState {
            server,
            broadcaster: SseBroadcaster::new(),
            aid_record: None,
            registry_entries: Vec::new(),
            a2a_endpoint: None,
            root_did: None,
            oauth: None,
            metrics: Arc::new(crate::metrics::Metrics::new()),
        }
    }

    #[test]
    fn state_can_be_constructed() {
        let state = make_state();
        assert_eq!(state.server.server_info().name, "ws-test");
    }
}
