//! In-process MCP transport that dispatches JSON-RPC directly to McpServer.
//!
//! Avoids network loopback by calling server handler methods directly.
//! Used by both the web UI agent and ACP agent-driven runs.

use navra_core::auth::AgentIdentity;
use navra_core::upstream::Transport;
use navra_core::McpServer;
use std::sync::Arc;

pub(crate) struct DirectTransport {
    server: Arc<McpServer>,
    agent: AgentIdentity,
    session_id: std::sync::Mutex<Option<String>>,
}

impl DirectTransport {
    pub fn new(server: Arc<McpServer>, agent: AgentIdentity) -> Self {
        Self {
            server,
            agent,
            session_id: std::sync::Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl Transport for DirectTransport {
    async fn request(
        &mut self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, navra_core::upstream::UpstreamError> {
        let method = body["method"].as_str().unwrap_or("");
        let params = body.get("params").cloned();
        let id = body.get("id").cloned().unwrap_or(serde_json::json!(1));

        match method {
            "initialize" => {
                let init_params = navra_core::protocol::InitializeParams::new(
                    Default::default(),
                    navra_core::protocol::ClientInfo::new(
                        format!("navra-{}", self.agent.name),
                        env!("CARGO_PKG_VERSION"),
                    ),
                );
                match self
                    .server
                    .handle_initialize(init_params, self.agent.clone())
                {
                    Ok((result, sid)) => {
                        *self.session_id.lock().unwrap() = Some(sid);
                        let value = serde_json::to_value(&result).unwrap_or_default();
                        Ok(serde_json::json!({"jsonrpc": "2.0", "result": value, "id": id}))
                    }
                    Err(msg) => Ok(serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {"code": -32600, "message": msg},
                        "id": id
                    })),
                }
            }

            "notifications/initialized" => {
                Ok(serde_json::json!({"jsonrpc": "2.0", "result": {}, "id": id}))
            }

            "tools/list" => {
                let pagination: navra_core::protocol::PaginatedRequest = params
                    .and_then(|p| serde_json::from_value(p).ok())
                    .unwrap_or_default();
                let result = self.server.handle_list_tools(&self.agent, &pagination);
                let value = serde_json::to_value(&result).unwrap_or_default();
                Ok(serde_json::json!({"jsonrpc": "2.0", "result": value, "id": id}))
            }

            "tools/call" => {
                let call_params: navra_core::protocol::CallToolParams =
                    match params.and_then(|p| serde_json::from_value(p).ok()) {
                        Some(p) => p,
                        None => {
                            return Ok(serde_json::json!({
                                "jsonrpc": "2.0",
                                "error": {"code": -32602, "message": "invalid params"},
                                "id": id
                            }));
                        }
                    };

                let sid = self.session_id.lock().unwrap().clone().unwrap_or_default();
                let ctx = navra_core::auth::CallContext::new(self.agent.clone(), sid);
                let result = self.server.handle_call_tool(call_params, ctx).await;
                let value = serde_json::to_value(&result).unwrap_or_default();
                Ok(serde_json::json!({"jsonrpc": "2.0", "result": value, "id": id}))
            }

            _ => Ok(serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": format!("method not found: {method}")},
                "id": id
            })),
        }
    }

    fn shutdown(&mut self) {}
}
