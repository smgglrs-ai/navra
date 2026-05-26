//! WebMCP transport: JSON-RPC over Chrome DevTools Protocol.
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

/// WebMCP transport backed by Chrome DevTools Protocol.
///
/// Connects to a Chrome browser's CDP WebSocket endpoint and executes
/// `navigator.modelContext` API calls to interact with browser-native
/// WebMCP tools.
pub struct WebMcpTransport {
    name: String,
    /// CDP WebSocket URL (e.g., `ws://127.0.0.1:9222/devtools/page/...`)
    cdp_url: String,
    /// CDP session/target ID for the page context
    target_id: Option<String>,
    /// Next CDP message ID
    next_cdp_id: i64,
    // TODO: Replace with actual CDP WebSocket client (e.g., tokio-tungstenite)
    // ws: Option<WebSocketStream>,
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
        }
    }

    /// Set the CDP target ID (page) to evaluate JavaScript in.
    ///
    /// If not set, the transport will use the first available page target
    /// discovered from the CDP endpoint.
    pub fn with_target(mut self, target_id: impl Into<String>) -> Self {
        self.target_id = Some(target_id.into());
        self
    }

    /// Evaluate a JavaScript expression in the browser page context via CDP.
    ///
    /// Sends a `Runtime.evaluate` CDP command and returns the result.
    async fn cdp_evaluate(&mut self, expression: &str) -> Result<serde_json::Value, UpstreamError> {
        let cdp_id = self.next_cdp_id;
        self.next_cdp_id += 1;

        // TODO: Send this over the CDP WebSocket connection
        let _cdp_request = serde_json::json!({
            "id": cdp_id,
            "method": "Runtime.evaluate",
            "params": {
                "expression": expression,
                "returnByValue": true,
                "awaitPromise": true,
            }
        });

        // TODO: Read response from CDP WebSocket and extract result.value
        // For now, return a stub error indicating CDP is not yet connected.
        Err(UpstreamError::Protocol {
            name: self.name.clone(),
            message: "CDP WebSocket client not yet implemented".to_string(),
        })
    }

    /// Build JavaScript expression to list WebMCP tools from the page.
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

    /// Build JavaScript expression to call a WebMCP tool in the page.
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

    /// Route a JSON-RPC MCP request to the appropriate WebMCP API call.
    async fn route_request(
        &mut self,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");

        let id = body.get("id").cloned().unwrap_or(serde_json::Value::Null);

        match method {
            "initialize" => {
                // WebMCP doesn't need initialization — return synthetic capabilities
                Ok(serde_json::json!({
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
                }))
            }

            "notifications/initialized" => {
                // Acknowledge — no response needed for notifications
                Ok(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {}
                }))
            }

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
        // TODO: Close the CDP WebSocket connection
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
    async fn tools_list_fails_without_cdp_connection() {
        let mut t = WebMcpTransport::new("test", "ws://127.0.0.1:9222/devtools/page/ABC");
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 3
        });

        let err = t.request(request).await.unwrap_err();
        match err {
            UpstreamError::Protocol { message, .. } => {
                assert!(message.contains("CDP WebSocket client not yet implemented"));
            }
            other => panic!("expected Protocol error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn tools_call_fails_without_cdp_connection() {
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
                assert!(message.contains("CDP WebSocket client not yet implemented"));
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
}
