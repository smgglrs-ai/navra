use crate::server::navra_handler::NavraHandler;
use crate::transport::streamable::router::AppState;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use rmcp::service::ServiceExt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

    let last_activity = Arc::new(tokio::sync::Notify::new());
    let missed_pongs = Arc::new(std::sync::atomic::AtomicU32::new(0));

    // Server-initiated ping task
    let ping_sender = ws_sender.clone();
    let ping_missed = missed_pongs.clone();
    let ping_interval = std::time::Duration::from_secs(state.ws_ping_interval_secs);
    let ping_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(ping_interval);
        interval.tick().await;
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
                tracing::info!(
                    timeout_secs = idle_timeout.as_secs(),
                    "WebSocket closing: idle timeout"
                );
                let mut sender = idle_sender.lock().await;
                let _ = sender.send(Message::Close(None)).await;
                break;
            }
        }
    });

    // Create a duplex pair: one side for NavraHandler (rmcp), one for us to bridge
    let (server_io, bridge_io) = tokio::io::duplex(65536);

    // Serve NavraHandler on the server side of the duplex
    let handler = NavraHandler::new(state.server.clone());
    let rmcp_handle = tokio::spawn(async move {
        match handler.serve(server_io).await {
            Ok(service) => {
                if let Err(e) = service.waiting().await {
                    tracing::debug!(error = %e, "rmcp WebSocket service error");
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "rmcp WebSocket service init error");
            }
        }
    });

    // Bridge: read lines from the duplex and send as WebSocket text messages
    let (bridge_read, bridge_write) = tokio::io::split(bridge_io);
    let bridge_write = Arc::new(Mutex::new(bridge_write));
    let fwd_sender = ws_sender.clone();
    let forward_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_read);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim_end();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let mut sender = fwd_sender.lock().await;
                    if sender
                        .send(Message::Text(trimmed.to_string().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "Bridge read error");
                    break;
                }
            }
        }
    });

    // Main loop: receive WebSocket messages and write to the duplex bridge
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
                let mut writer = bridge_write.lock().await;
                if writer.write_all(text.as_bytes()).await.is_err() {
                    break;
                }
                if !text.ends_with('\n') {
                    if writer.write_all(b"\n").await.is_err() {
                        break;
                    }
                }
                if writer.flush().await.is_err() {
                    break;
                }
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

    // Shut down bridge write side to signal EOF to rmcp
    drop(bridge_write);

    ping_handle.abort();
    idle_handle.abort();
    forward_handle.abort();
    rmcp_handle.abort();

    state
        .metrics
        .websocket_connections
        .fetch_sub(1, Ordering::Relaxed);

    tracing::debug!("WebSocket connection closed");
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
