//! WebMCP transport: JSON-RPC over Chrome DevTools Protocol (NAVRA-139).
//!
//! Connects to a Chrome browser via CDP (Chrome DevTools Protocol) and
//! translates MCP JSON-RPC calls into JavaScript `navigator.modelContext`
//! API calls executed in the browser page context.
//!
//! WebMCP protocol flow:
//! 1. Transport connects to Chrome's CDP WebSocket endpoint
//! 2. On `tools/list`, evaluates `navigator.modelContext.tools` in the page
//! 3. On `tools/call`, evaluates `navigator.modelContext.callTool()` in the page
//! 4. Results are wrapped back into JSON-RPC response format

use super::transport::Transport;
use super::UpstreamError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

#[cfg(feature = "webmcp")]
use {
    futures_util::{SinkExt, StreamExt},
    tokio_tungstenite::tungstenite::Message as WsMessage,
};

/// WebMCP transport backed by Chrome DevTools Protocol.
///
/// Connects to a Chrome browser's CDP WebSocket endpoint and executes
/// `navigator.modelContext` API calls to interact with browser-native
/// WebMCP tools.
pub struct WebMcpTransport {
    name: String,
    cdp_url: String,
    target_id: Option<String>,
    next_cdp_id: i64,
    #[cfg(feature = "webmcp")]
    connection: Option<CdpConnection>,
}

#[cfg(feature = "webmcp")]
struct CdpConnection {
    write_tx: mpsc::UnboundedSender<String>,
    pending: Arc<Mutex<HashMap<i64, oneshot::Sender<serde_json::Value>>>>,
    reader_handle: tokio::task::JoinHandle<()>,
}

impl WebMcpTransport {
    /// Create a new WebMCP transport pointing at the given CDP WebSocket URL.
    ///
    /// The URL should be a CDP WebSocket endpoint, typically obtained from
    /// `http://127.0.0.1:9222/json` (Chrome's DevTools discovery endpoint).
    pub fn new(name: &str, cdp_url: &str) -> Self {
        Self {
            name: name.to_string(),
            cdp_url: cdp_url.to_string(),
            target_id: None,
            next_cdp_id: 1,
            #[cfg(feature = "webmcp")]
            connection: None,
        }
    }

    /// Set the CDP target ID (page) to evaluate JavaScript in.
    pub fn with_target(mut self, target_id: impl Into<String>) -> Self {
        self.target_id = Some(target_id.into());
        self
    }

    /// Connect to the CDP WebSocket endpoint.
    #[cfg(feature = "webmcp")]
    pub async fn connect(&mut self) -> Result<(), UpstreamError> {
        use tokio_tungstenite::connect_async;

        let (ws_stream, _) =
            connect_async(&self.cdp_url)
                .await
                .map_err(|e| UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: format!("CDP WebSocket connection failed: {e}"),
                })?;

        let (write, mut read) = ws_stream.split();
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<String>();

        let pending: Arc<Mutex<HashMap<i64, oneshot::Sender<serde_json::Value>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_clone = pending.clone();

        // Writer task: forwards queued messages to the WebSocket
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

        // Reader task: routes CDP responses to pending waiters
        let reader_handle = tokio::spawn(async move {
            while let Some(Ok(msg)) = read.next().await {
                if let WsMessage::Text(text) = msg {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(id) = json.get("id").and_then(|v| v.as_i64()) {
                            let mut pending = pending_clone.lock().await;
                            if let Some(tx) = pending.remove(&id) {
                                let _ = tx.send(json);
                            }
                        }
                    }
                }
            }
        });

        self.connection = Some(CdpConnection {
            write_tx,
            pending,
            reader_handle,
        });

        tracing::info!(name = %self.name, url = %self.cdp_url, "CDP WebSocket connected");
        Ok(())
    }

    /// Evaluate a JavaScript expression in the browser page context via CDP.
    async fn cdp_evaluate(&mut self, expression: &str) -> Result<serde_json::Value, UpstreamError> {
        let cdp_id = self.next_cdp_id;
        self.next_cdp_id += 1;

        let cdp_request = serde_json::json!({
            "id": cdp_id,
            "method": "Runtime.evaluate",
            "params": {
                "expression": expression,
                "returnByValue": true,
                "awaitPromise": true,
            }
        });

        #[cfg(feature = "webmcp")]
        {
            let conn = self
                .connection
                .as_ref()
                .ok_or_else(|| UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: "CDP WebSocket not connected. Call connect() first.".to_string(),
                })?;

            let (tx, rx) = oneshot::channel();
            {
                let mut pending = conn.pending.lock().await;
                pending.insert(cdp_id, tx);
            }

            let msg = serde_json::to_string(&cdp_request).map_err(|e| UpstreamError::Protocol {
                name: self.name.clone(),
                message: format!("Failed to serialize CDP request: {e}"),
            })?;

            conn.write_tx
                .send(msg)
                .map_err(|_| UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: "CDP WebSocket writer closed".to_string(),
                })?;

            let response = tokio::time::timeout(std::time::Duration::from_secs(30), rx)
                .await
                .map_err(|_| UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: "CDP response timed out after 30s".to_string(),
                })?
                .map_err(|_| UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: "CDP response channel dropped".to_string(),
                })?;

            // Extract the result from the CDP response
            if let Some(error) = response.get("error") {
                return Err(UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: format!("CDP error: {}", error),
                });
            }

            let result = response
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            // CDP Runtime.evaluate wraps the result in { result: { type, value } }
            if let Some(exception) = result.get("exceptionDetails") {
                let text = exception
                    .get("exception")
                    .and_then(|e| e.get("description"))
                    .and_then(|d| d.as_str())
                    .unwrap_or("Unknown exception");
                return Err(UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: format!("JavaScript exception: {text}"),
                });
            }

            let value = result
                .get("result")
                .and_then(|r| r.get("value"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            // The JS expression returns JSON.stringify(...), so parse the string
            if let Some(s) = value.as_str() {
                serde_json::from_str(s).map_err(|e| UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: format!("Failed to parse JS result: {e}"),
                })
            } else {
                Ok(value)
            }
        }

        #[cfg(not(feature = "webmcp"))]
        {
            let _ = cdp_request;
            Err(UpstreamError::Protocol {
                name: self.name.clone(),
                message: "WebMCP feature not enabled. Build with --features webmcp".to_string(),
            })
        }
    }

    fn js_list_tools() -> &'static str {
        r#"
        (async () => {
            if (!navigator.modelContext) {
                throw new Error('navigator.modelContext is not available');
            }
            const tools = await navigator.modelContext.tools();
            return JSON.stringify({ tools });
        })()
        "#
    }

    fn js_call_tool(tool_name: &str, arguments: &serde_json::Value) -> String {
        let args_json = serde_json::to_string(arguments).unwrap_or_else(|_| "{}".to_string());
        format!(
            r#"
            (async () => {{
                if (!navigator.modelContext) {{
                    throw new Error('navigator.modelContext is not available');
                }}
                const result = await navigator.modelContext.callTool("{tool_name}", {args_json});
                return JSON.stringify(result);
            }})()
            "#
        )
    }

    async fn route_request(
        &mut self,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = body.get("id").cloned().unwrap_or(serde_json::Value::Null);

        match method {
            "initialize" => Ok(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {
                        "tools": { "listChanged": false }
                    },
                    "serverInfo": {
                        "name": "webmcp-browser",
                        "version": "0.1.0"
                    }
                }
            })),

            "notifications/initialized" => Ok(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {}
            })),

            "tools/list" => {
                let result = self.cdp_evaluate(Self::js_list_tools()).await?;
                Ok(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result
                }))
            }

            "tools/call" => {
                let params = body.get("params").cloned().unwrap_or_default();
                let tool_name = params.get("name").and_then(|n| n.as_str()).ok_or_else(|| {
                    UpstreamError::Protocol {
                        name: self.name.clone(),
                        message: "tools/call missing 'name' parameter".to_string(),
                    }
                })?;
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));

                let js = Self::js_call_tool(tool_name, &arguments);
                let result = self.cdp_evaluate(&js).await?;
                Ok(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result
                }))
            }

            _ => Err(UpstreamError::Protocol {
                name: self.name.clone(),
                message: format!("unsupported method for WebMCP transport: {method}"),
            }),
        }
    }
}

#[async_trait]
impl Transport for WebMcpTransport {
    async fn request(
        &mut self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        self.route_request(&body).await
    }

    fn shutdown(&mut self) {
        #[cfg(feature = "webmcp")]
        {
            if let Some(conn) = self.connection.take() {
                conn.reader_handle.abort();
            }
        }
        self.target_id = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_transport() {
        let t = WebMcpTransport::new("test-browser", "ws://127.0.0.1:9222/devtools/page/ABC");
        assert_eq!(t.name, "test-browser");
        assert_eq!(t.cdp_url, "ws://127.0.0.1:9222/devtools/page/ABC");
        assert!(t.target_id.is_none());
    }

    #[test]
    fn construct_with_target() {
        let t = WebMcpTransport::new("test", "ws://127.0.0.1:9222/devtools/page/ABC")
            .with_target("page-123");
        assert_eq!(t.target_id.as_deref(), Some("page-123"));
    }

    #[tokio::test]
    async fn initialize_returns_synthetic_capabilities() {
        let mut t = WebMcpTransport::new("test", "ws://127.0.0.1:9222/devtools/page/ABC");
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "0.1.0" }
            }
        });

        let response = t.request(request).await.unwrap();
        let result = response.get("result").unwrap();
        assert!(result.get("capabilities").is_some());
        assert_eq!(
            result["serverInfo"]["name"].as_str().unwrap(),
            "webmcp-browser"
        );
    }

    #[tokio::test]
    async fn notifications_initialized_succeeds() {
        let mut t = WebMcpTransport::new("test", "ws://127.0.0.1:9222/devtools/page/ABC");
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "id": 2
        });

        let response = t.request(request).await.unwrap();
        assert!(response.get("result").is_some());
    }

    #[tokio::test]
    async fn tools_list_fails_without_connection() {
        let mut t = WebMcpTransport::new("test", "ws://127.0.0.1:9222/devtools/page/ABC");
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 3
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

    #[tokio::test]
    async fn tools_call_fails_without_connection() {
        let mut t = WebMcpTransport::new("test", "ws://127.0.0.1:9222/devtools/page/ABC");
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 4,
            "params": {
                "name": "browser_search",
                "arguments": { "query": "hello" }
            }
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

    #[tokio::test]
    async fn tools_call_missing_name_returns_error() {
        let mut t = WebMcpTransport::new("test", "ws://127.0.0.1:9222/devtools/page/ABC");
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 5,
            "params": {
                "arguments": { "query": "hello" }
            }
        });

        let err = t.request(request).await.unwrap_err();
        match err {
            UpstreamError::Protocol { message, .. } => {
                assert!(message.contains("missing 'name' parameter"));
            }
            other => panic!("expected Protocol error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unsupported_method_returns_error() {
        let mut t = WebMcpTransport::new("test", "ws://127.0.0.1:9222/devtools/page/ABC");
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "resources/list",
            "id": 6
        });

        let err = t.request(request).await.unwrap_err();
        match err {
            UpstreamError::Protocol { message, .. } => {
                assert!(message.contains("unsupported method"));
            }
            other => panic!("expected Protocol error, got: {other:?}"),
        }
    }

    #[test]
    fn js_list_tools_is_valid() {
        let js = WebMcpTransport::js_list_tools();
        assert!(js.contains("navigator.modelContext"));
        assert!(js.contains("tools"));
    }

    #[test]
    fn js_call_tool_includes_name_and_args() {
        let args = serde_json::json!({"query": "test"});
        let js = WebMcpTransport::js_call_tool("browser_search", &args);
        assert!(js.contains("browser_search"));
        assert!(js.contains("query"));
        assert!(js.contains("navigator.modelContext.callTool"));
    }

    #[test]
    fn shutdown_clears_target() {
        let mut t = WebMcpTransport::new("test", "ws://127.0.0.1:9222/devtools/page/ABC")
            .with_target("page-123");
        assert!(t.target_id.is_some());
        t.shutdown();
        assert!(t.target_id.is_none());
    }

    /// Mock CDP WebSocket server for integration testing.
    #[cfg(feature = "webmcp")]
    mod mock_cdp {
        use super::*;
        use tokio::net::TcpListener;

        async fn start_mock_cdp_server() -> (String, tokio::task::JoinHandle<()>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let url = format!("ws://127.0.0.1:{}", addr.port());

            let handle = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let ws_stream = tokio_tungstenite::accept_async(stream).await.unwrap();
                    let (mut write, mut read) = ws_stream.split();

                    while let Some(Ok(msg)) = read.next().await {
                        if let WsMessage::Text(text) = msg {
                            if let Ok(req) = serde_json::from_str::<serde_json::Value>(&text) {
                                let id = req.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                                let method =
                                    req.get("method").and_then(|m| m.as_str()).unwrap_or("");

                                let response = match method {
                                    "Runtime.evaluate" => {
                                        let expr = req
                                            .get("params")
                                            .and_then(|p| p.get("expression"))
                                            .and_then(|e| e.as_str())
                                            .unwrap_or("");

                                        if expr.contains("tools()") {
                                            serde_json::json!({
                                                "id": id,
                                                "result": {
                                                    "result": {
                                                        "type": "string",
                                                        "value": r#"{"tools":[{"name":"mock_tool","description":"A mock tool","inputSchema":{"type":"object","properties":{}}}]}"#
                                                    }
                                                }
                                            })
                                        } else if expr.contains("callTool") {
                                            serde_json::json!({
                                                "id": id,
                                                "result": {
                                                    "result": {
                                                        "type": "string",
                                                        "value": r#"{"content":[{"type":"text","text":"mock result"}]}"#
                                                    }
                                                }
                                            })
                                        } else {
                                            serde_json::json!({
                                                "id": id,
                                                "result": {
                                                    "result": {
                                                        "type": "undefined"
                                                    }
                                                }
                                            })
                                        }
                                    }
                                    _ => serde_json::json!({
                                        "id": id,
                                        "error": {
                                            "code": -32601,
                                            "message": "Method not found"
                                        }
                                    }),
                                };

                                let resp_text = serde_json::to_string(&response).unwrap();
                                if write.send(WsMessage::Text(resp_text)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            });

            (url, handle)
        }

        #[tokio::test]
        async fn connect_and_list_tools() {
            let (url, server) = start_mock_cdp_server().await;
            let mut t = WebMcpTransport::new("test", &url);
            t.connect().await.unwrap();

            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 1
            });

            let response = t.request(request).await.unwrap();
            let result = response.get("result").unwrap();
            let tools = result.get("tools").unwrap().as_array().unwrap();
            assert_eq!(tools.len(), 1);
            assert_eq!(tools[0]["name"].as_str().unwrap(), "mock_tool");

            t.shutdown();
            server.abort();
        }

        #[tokio::test]
        async fn connect_and_call_tool() {
            let (url, server) = start_mock_cdp_server().await;
            let mut t = WebMcpTransport::new("test", &url);
            t.connect().await.unwrap();

            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": 2,
                "params": {
                    "name": "mock_tool",
                    "arguments": {}
                }
            });

            let response = t.request(request).await.unwrap();
            let result = response.get("result").unwrap();
            let content = result.get("content").unwrap().as_array().unwrap();
            assert_eq!(content[0]["text"].as_str().unwrap(), "mock result");

            t.shutdown();
            server.abort();
        }

        #[tokio::test]
        async fn connect_failure_returns_error() {
            let mut t = WebMcpTransport::new("test", "ws://127.0.0.1:1/nonexistent");
            let err = t.connect().await.unwrap_err();
            match err {
                UpstreamError::Protocol { message, .. } => {
                    assert!(message.contains("CDP WebSocket connection failed"));
                }
                other => panic!("expected Protocol error, got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn shutdown_aborts_cleanly() {
            let (url, server) = start_mock_cdp_server().await;
            let mut t = WebMcpTransport::new("test", &url);
            t.connect().await.unwrap();
            t.shutdown();
            assert!(t.target_id.is_none());

            // Calling tools after shutdown should fail
            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 3
            });
            let err = t.request(request).await.unwrap_err();
            match err {
                UpstreamError::Protocol { .. } => {}
                other => panic!("expected Protocol error after shutdown, got: {other:?}"),
            }

            server.abort();
        }
    }
}
