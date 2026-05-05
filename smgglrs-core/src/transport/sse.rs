//! SSE broadcaster for server-initiated notifications.
//!
//! Each MCP session can have one active SSE stream. The `SseBroadcaster`
//! manages per-session channels. When the server needs to push a
//! notification (e.g., tools/list_changed), it sends to all active
//! sessions or a specific session.

use crate::protocol::JsonRpcNotification;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

/// Default channel capacity per session.
const CHANNEL_CAPACITY: usize = 64;

/// A server-sent event payload (serialized JSON-RPC notification).
#[derive(Debug, Clone)]
pub struct SseEvent {
    /// The SSE event type (e.g., "message").
    pub event: String,
    /// The JSON-RPC notification serialized as a string.
    pub data: String,
}

/// Manages per-session SSE broadcast channels.
///
/// Each session gets its own broadcast channel. Multiple SSE connections
/// to the same session share the channel. Notifications can be sent to
/// all sessions or a specific one.
#[derive(Clone)]
pub struct SseBroadcaster {
    channels: Arc<RwLock<HashMap<String, broadcast::Sender<SseEvent>>>>,
}

impl SseBroadcaster {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribe to SSE events for a session. Creates the channel if needed.
    /// Returns a broadcast receiver.
    pub fn subscribe(&self, session_id: &str) -> broadcast::Receiver<SseEvent> {
        let mut channels = self.channels.write().unwrap_or_else(|e| e.into_inner());
        let tx = channels
            .entry(session_id.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0);
        tx.subscribe()
    }

    /// Remove a session's channel (called when session ends).
    pub fn remove_session(&self, session_id: &str) {
        let mut channels = self.channels.write().unwrap_or_else(|e| e.into_inner());
        channels.remove(session_id);
    }

    /// Send a notification to a specific session.
    /// Returns false if the session has no active channel.
    pub fn send_to_session(&self, session_id: &str, notification: &JsonRpcNotification) -> bool {
        let channels = self.channels.read().unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = channels.get(session_id) {
            let event = SseEvent {
                event: "message".to_string(),
                data: serde_json::to_string(notification).unwrap_or_default(),
            };
            // send() returns Err only if there are no receivers — that's fine
            let _ = tx.send(event);
            true
        } else {
            false
        }
    }

    /// Broadcast a notification to all active sessions.
    pub fn broadcast(&self, notification: &JsonRpcNotification) {
        let channels = self.channels.read().unwrap_or_else(|e| e.into_inner());
        let event = SseEvent {
            event: "message".to_string(),
            data: serde_json::to_string(notification).unwrap_or_default(),
        };
        for tx in channels.values() {
            let _ = tx.send(event.clone());
        }
    }

    /// Number of active session channels.
    pub fn session_count(&self) -> usize {
        self.channels.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for SseBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a JSON-RPC notification for the given method.
pub fn make_notification(method: &str, params: Option<serde_json::Value>) -> JsonRpcNotification {
    JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_creates_channel() {
        let broadcaster = SseBroadcaster::new();
        let _rx = broadcaster.subscribe("session-1");
        assert_eq!(broadcaster.session_count(), 1);
    }

    #[test]
    fn multiple_subscribers_same_session() {
        let broadcaster = SseBroadcaster::new();
        let _rx1 = broadcaster.subscribe("session-1");
        let _rx2 = broadcaster.subscribe("session-1");
        assert_eq!(broadcaster.session_count(), 1);
    }

    #[test]
    fn remove_session() {
        let broadcaster = SseBroadcaster::new();
        let _rx = broadcaster.subscribe("session-1");
        broadcaster.remove_session("session-1");
        assert_eq!(broadcaster.session_count(), 0);
    }

    #[tokio::test]
    async fn send_to_session() {
        let broadcaster = SseBroadcaster::new();
        let mut rx = broadcaster.subscribe("session-1");

        let notif = make_notification("notifications/tools/list_changed", None);
        assert!(broadcaster.send_to_session("session-1", &notif));

        let event = rx.recv().await.unwrap();
        assert_eq!(event.event, "message");
        assert!(event.data.contains("tools/list_changed"));
    }

    #[tokio::test]
    async fn broadcast_to_all() {
        let broadcaster = SseBroadcaster::new();
        let mut rx1 = broadcaster.subscribe("session-1");
        let mut rx2 = broadcaster.subscribe("session-2");

        let notif = make_notification("notifications/tools/list_changed", None);
        broadcaster.broadcast(&notif);

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        assert!(e1.data.contains("tools/list_changed"));
        assert!(e2.data.contains("tools/list_changed"));
    }

    #[test]
    fn send_to_nonexistent_session() {
        let broadcaster = SseBroadcaster::new();
        let notif = make_notification("test", None);
        assert!(!broadcaster.send_to_session("no-such-session", &notif));
    }

    #[test]
    fn make_notification_structure() {
        let notif = make_notification("notifications/test", Some(serde_json::json!({"key": 1})));
        assert_eq!(notif.jsonrpc, "2.0");
        assert_eq!(notif.method, "notifications/test");
        assert!(notif.params.is_some());
    }
}
