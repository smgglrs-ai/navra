//! WebSocket transport: JSON-RPC over WebSocket for upstream MCP connections.
//!
//! Connects to an MCP server's `/ws` endpoint via WebSocket and sends
//! JSON-RPC requests as text frames. Supports server-initiated notifications
//! and keepalive pong handling.

use super::transport::{Transport, UpstreamNotification};
use super::UpstreamError;
use async_trait::async_trait;
#[cfg(feature = "webmcp")]
use std::collections::HashMap;
#[cfg(feature = "webmcp")]
use std::sync::Arc;
use tokio::sync::mpsc;
#[cfg(feature = "webmcp")]
use tokio::sync::{oneshot, Mutex};

#[cfg(feature = "webmcp")]
use {
    futures_util::{SinkExt, StreamExt},
    tokio_tungstenite::tungstenite::Message as WsMessage,
};

/// WebSocket transport for upstream MCP server connections.
pub struct WebSocketTransport {
    name: String,
    url: String,
    #[cfg(feature = "webmcp")]
    connection: Option<WsConnection>,
    notification_tx: Option<mpsc::UnboundedSender<UpstreamNotification>>,
}

#[cfg(feature = "webmcp")]
struct WsConnection {
    write_tx: mpsc::UnboundedSender<String>,
    pending: Arc<Mutex<HashMap<i64, oneshot::Sender<serde_json::Value>>>>,
    reader_handle: tokio::task::JoinHandle<()>,
}

impl WebSocketTransport {
    /// Create a new WebSocket transport pointing at the given MCP WebSocket URL.
    pub fn new(name: &str, url: &str) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
            #[cfg(feature = "webmcp")]
            connection: None,
            notification_tx: None,
        }
    }

    /// Connect to the MCP server's WebSocket endpoint.
    #[cfg(feature = "webmcp")]
    pub async fn connect(&mut self) -> Result<(), UpstreamError> {
        use tokio_tungstenite::connect_async;

        let (ws_stream, _) =
            connect_async(&self.url)
                .await
                .map_err(|e| UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: format!("WebSocket connection failed: {e}"),
                })?;

        let (write, mut read) = ws_stream.split();
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<String>();

        let pending: Arc<Mutex<HashMap<i64, oneshot::Sender<serde_json::Value>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_clone = pending.clone();
        let notif_tx = self.notification_tx.clone();

        // Writer task
        let write = Arc::new(Mutex::new(write));
        let write_clone = write.clone();
        tokio::spawn(async move {
            while let Some(msg) = write_rx.recv().await {
                let mut w = write_clone.lock().await;
                if w.send(WsMessage::Text(msg)).await.is_err() {
                    break;
                }
            }
        });

        // Reader task: routes responses to pending waiters, forwards notifications
        let reader_handle = tokio::spawn(async move {
            while let Some(Ok(msg)) = read.next().await {
                match msg {
                    WsMessage::Text(text) => {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            // Check if it's a notification (method present, no id)
                            if json.get("method").is_some() && json.get("id").is_none() {
                                if let Some(ref tx) = notif_tx {
                                    if let Some(method) = json["method"].as_str() {
                                        if method == "notifications/tools/list_changed" {
                                            let _ = tx.send(UpstreamNotification::ToolsListChanged);
                                        }
                                    }
                                }
                                continue;
                            }

                            // Route response to pending waiter
                            if let Some(id) = json.get("id").and_then(|v| v.as_i64()) {
                                let mut pending = pending_clone.lock().await;
                                if let Some(tx) = pending.remove(&id) {
                                    let _ = tx.send(json);
                                }
                            }
                        }
                    }
                    WsMessage::Ping(data) => {
                        let mut w = write.lock().await;
                        let _ = w.send(WsMessage::Pong(data)).await;
                    }
                    WsMessage::Close(_) => break,
                    _ => {}
                }
            }
        });

        self.connection = Some(WsConnection {
            write_tx,
            pending,
            reader_handle,
        });

        tracing::info!(name = %self.name, url = %self.url, "WebSocket transport connected");
        Ok(())
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn request(
        &mut self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        #[cfg(feature = "webmcp")]
        {
            let conn = self
                .connection
                .as_ref()
                .ok_or_else(|| UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: "WebSocket not connected. Call connect() first.".to_string(),
                })?;

            let id = body.get("id").and_then(|v| v.as_i64()).unwrap_or(0);

            let (tx, rx) = oneshot::channel();
            {
                let mut pending = conn.pending.lock().await;
                pending.insert(id, tx);
            }

            let msg = serde_json::to_string(&body).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;

            conn.write_tx
                .send(msg)
                .map_err(|_| UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: "WebSocket writer closed".to_string(),
                })?;

            tokio::time::timeout(std::time::Duration::from_secs(30), rx)
                .await
                .map_err(|_| UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: "WebSocket response timed out after 30s".to_string(),
                })?
                .map_err(|_| UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: "WebSocket response channel dropped".to_string(),
                })
        }

        #[cfg(not(feature = "webmcp"))]
        {
            let _ = body;
            Err(UpstreamError::Protocol {
                name: self.name.clone(),
                message: "WebSocket feature not enabled. Build with --features webmcp".to_string(),
            })
        }
    }

    fn shutdown(&mut self) {
        #[cfg(feature = "webmcp")]
        {
            if let Some(conn) = self.connection.take() {
                conn.reader_handle.abort();
            }
        }
    }

    fn set_notification_sender(&mut self, tx: mpsc::UnboundedSender<UpstreamNotification>) {
        self.notification_tx = Some(tx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_transport() {
        let t = WebSocketTransport::new("test-ws", "ws://localhost:9315/ws");
        assert_eq!(t.name, "test-ws");
        assert_eq!(t.url, "ws://localhost:9315/ws");
    }

    #[tokio::test]
    async fn request_without_connect_fails() {
        let mut t = WebSocketTransport::new("test", "ws://localhost:9315/ws");
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        });

        let err = t.request(request).await.unwrap_err();
        match err {
            UpstreamError::Protocol { message, .. } => {
                assert!(
                    message.contains("not connected") || message.contains("not enabled"),
                    "unexpected error: {message}"
                );
            }
            other => panic!("expected Protocol error, got: {other:?}"),
        }
    }

    #[test]
    fn shutdown_is_safe_without_connection() {
        let mut t = WebSocketTransport::new("test", "ws://localhost:9315/ws");
        t.shutdown();
    }
}
