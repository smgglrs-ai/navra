use crate::protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use crate::transport::streamable::dispatch::dispatch;
use crate::transport::streamable::router::AppState;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::Ordering;
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
    state
        .metrics
        .websocket_connections
        .fetch_add(1, Ordering::Relaxed);

    let (ws_sender, mut ws_receiver) = socket.split();
    let ws_sender = Arc::new(Mutex::new(ws_sender));
    let session_id: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let notify_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>> =
        Arc::new(Mutex::new(None));

    let last_activity = Arc::new(tokio::sync::Notify::new());
    let missed_pongs = Arc::new(std::sync::atomic::AtomicU32::new(0));

    // Server-initiated ping task
    let ping_sender = ws_sender.clone();
    let ping_missed = missed_pongs.clone();
    let ping_interval = std::time::Duration::from_secs(state.ws_ping_interval_secs);
    let ping_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(ping_interval);
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            if ping_missed.load(Ordering::Relaxed) >= 3 {
                tracing::info!("WebSocket closing: 3 missed pongs");
                let mut sender = ping_sender.lock().await;
                let _ = sender.send(Message::Close(None)).await;
                break;
            }
            ping_missed.fetch_add(1, Ordering::Relaxed);
            let mut sender = ping_sender.lock().await;
            if sender.send(Message::Ping(vec![].into())).await.is_err() {
                break;
            }
        }
    });

    // Idle timeout task
    let idle_sender = ws_sender.clone();
    let idle_notify = last_activity.clone();
    let idle_timeout = std::time::Duration::from_secs(state.ws_idle_timeout_secs);
    let idle_handle = tokio::spawn(async move {
        loop {
            let timed_out = tokio::time::timeout(idle_timeout, idle_notify.notified()).await;
            if timed_out.is_err() {
                tracing::info!(timeout_secs = idle_timeout.as_secs(), "WebSocket closing: idle timeout");
                let mut sender = idle_sender.lock().await;
                let _ = sender.send(Message::Close(None)).await;
                break;
            }
        }
    });

    while let Some(msg) = ws_receiver.next().await {
        let msg = match msg {
            Ok(msg) => msg,
            Err(e) => {
                tracing::debug!(error = %e, "WebSocket receive error");
                break;
            }
        };

        last_activity.notify_one();

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
                        break;
                    }
                    continue;
                }

                // Concurrent dispatch: spawn each request as a task
                let state_clone = state.clone();
                let agent_clone = agent.clone();
                let sender_clone = ws_sender.clone();
                let session_clone = session_id.clone();
                let notify_clone = notify_handle.clone();
                let broadcaster = state.broadcaster.clone();

                tokio::spawn(async move {
                    let sid = session_clone.lock().await.clone();
                    let (response, new_sid) =
                        dispatch(state_clone.server.clone(), request, agent_clone, sid).await;

                    if let Some(ref new_id) = new_sid {
                        let mut sid_guard = session_clone.lock().await;
                        if sid_guard.is_none() {
                            *sid_guard = Some(new_id.clone());

                            let rx = broadcaster.subscribe(new_id);
                            let fwd_sender = sender_clone.clone();
                            let handle = tokio::spawn(forward_notifications(rx, fwd_sender));
                            *notify_clone.lock().await = Some(handle);
                        }
                    }

                    let json = serde_json::to_string(&response).unwrap_or_default();
                    let mut sender = sender_clone.lock().await;
                    let _ = sender.send(Message::Text(json.into())).await;
                });
            }
            Message::Pong(_) => {
                missed_pongs.store(0, Ordering::Relaxed);
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

    ping_handle.abort();
    idle_handle.abort();

    if let Some(handle) = notify_handle.lock().await.take() {
        handle.abort();
    }

    state
        .metrics
        .websocket_connections
        .fetch_sub(1, Ordering::Relaxed);

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
            ws_ping_interval_secs: 30,
            ws_idle_timeout_secs: 600,
        }
    }

    #[test]
    fn state_can_be_constructed() {
        let state = make_state();
        assert_eq!(state.server.server_info().name, "ws-test");
    }

    #[test]
    fn ws_config_defaults() {
        let state = make_state();
        assert_eq!(state.ws_ping_interval_secs, 30);
        assert_eq!(state.ws_idle_timeout_secs, 600);
    }

    #[test]
    fn metrics_initial_zero() {
        let state = make_state();
        assert_eq!(
            state.metrics.websocket_connections.load(Ordering::Relaxed),
            0
        );
    }
}
