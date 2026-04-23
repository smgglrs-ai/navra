//! Upstream MCP server client with pluggable transports.
//!
//! An `Upstream` connects to an external MCP server via a `Transport`
//! (stdio, HTTP, or SSE), handles initialization and capability discovery,
//! and proxies MCP requests.

pub mod http;
pub mod retry;
pub mod sse;
pub mod stdio;
mod transport;

pub use retry::{RetryConfig, TransportFactory};
pub use transport::Transport;

use crate::mcp::{
    CallToolParams, CallToolResult, GetPromptParams, GetPromptResult, ListPromptsResult,
    ListResourcesResult, ListToolsResult, PromptDefinition, ReadResourceParams,
    ReadResourceResult, ResourceDefinition, ToolDefinition, PROTOCOL_VERSION,
};
use std::sync::atomic::{AtomicI64, Ordering};

/// Error type for upstream operations.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("failed to spawn upstream '{name}': {source}")]
    Spawn {
        name: String,
        source: std::io::Error,
    },

    #[error("upstream '{name}' has no stdin/stdout")]
    NoStdio { name: String },

    #[error("upstream '{name}': {message}")]
    Protocol { name: String, message: String },

    #[error("upstream '{name}': I/O error: {source}")]
    Io {
        name: String,
        source: std::io::Error,
    },

    #[error("upstream '{name}': JSON error: {source}")]
    Json {
        name: String,
        source: serde_json::Error,
    },

    #[error("upstream '{name}': JSON-RPC error {code}: {message}")]
    JsonRpc {
        name: String,
        code: i64,
        message: String,
    },
}

impl UpstreamError {
    /// Returns true if this error is permanent and should NOT be retried.
    pub fn is_permanent(&self) -> bool {
        match self {
            UpstreamError::Spawn { source, .. } => {
                source.kind() == std::io::ErrorKind::NotFound
            }
            UpstreamError::Protocol { message, .. } => {
                message.contains("HTTP 401")
                    || message.contains("HTTP 403")
                    || message.contains("HTTP 404")
            }
            UpstreamError::NoStdio { .. } => true,
            _ => false,
        }
    }
}

/// An MCP client connected to an upstream server.
pub struct Upstream {
    name: String,
    transport: Box<dyn Transport>,
    next_id: AtomicI64,
}

impl Upstream {
    /// Create an upstream from a transport and initialize the MCP connection.
    pub async fn connect(
        name: &str,
        transport: impl Transport,
    ) -> Result<Self, UpstreamError> {
        let mut upstream = Self {
            name: name.to_string(),
            transport: Box::new(transport),
            next_id: AtomicI64::new(1),
        };
        upstream.initialize().await?;
        Ok(upstream)
    }

    /// Spawn a subprocess (stdio transport) and initialize.
    pub async fn spawn(
        name: &str,
        command: &[String],
        cwd: Option<&str>,
    ) -> Result<Self, UpstreamError> {
        let transport = stdio::StdioTransport::spawn(name, command, cwd)?;
        Self::connect(name, transport).await
    }

    /// Connect via HTTP (streamable-http transport) and initialize.
    pub async fn http(name: &str, url: &str) -> Result<Self, UpstreamError> {
        let transport = http::HttpTransport::new(name, url);
        Self::connect(name, transport).await
    }

    /// Connect via HTTP with an authentication token and initialize.
    pub async fn http_with_auth(name: &str, url: &str, token: &str) -> Result<Self, UpstreamError> {
        let transport = http::HttpTransport::new(name, url).with_auth(token);
        Self::connect(name, transport).await
    }

    /// Connect via SSE and initialize.
    pub async fn sse(name: &str, url: &str) -> Result<Self, UpstreamError> {
        let transport = sse::SseTransport::new(name, url);
        Self::connect(name, transport).await
    }

    /// Spawn a subprocess with resilient reconnection and initialize.
    pub async fn spawn_resilient(
        name: &str,
        command: &[String],
        cwd: Option<&str>,
        config: RetryConfig,
    ) -> Result<Self, UpstreamError> {
        let factory = retry::StdioTransportFactory::new(name, command, cwd);
        let transport = retry::ResilientTransport::from_factory(
            name,
            Box::new(factory),
            config,
        )
        .await?;
        Self::connect(name, transport).await
    }

    /// Connect via HTTP with resilient reconnection and initialize.
    pub async fn http_resilient(
        name: &str,
        url: &str,
        config: RetryConfig,
    ) -> Result<Self, UpstreamError> {
        let factory = retry::HttpTransportFactory::new(name, url);
        let transport = retry::ResilientTransport::from_factory(
            name,
            Box::new(factory),
            config,
        )
        .await?;
        Self::connect(name, transport).await
    }

    /// Connect via SSE with resilient reconnection and initialize.
    pub async fn sse_resilient(
        name: &str,
        url: &str,
        config: RetryConfig,
    ) -> Result<Self, UpstreamError> {
        let factory = retry::SseTransportFactory::new(name, url);
        let transport = retry::ResilientTransport::from_factory(
            name,
            Box::new(factory),
            config,
        )
        .await?;
        Self::connect(name, transport).await
    }

    /// Send an initialize request and notifications/initialized.
    async fn initialize(&mut self) -> Result<(), UpstreamError> {
        let params = serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "mcpd",
                "version": "0.1.0"
            }
        });

        let _result = self.call("initialize", Some(params)).await?;

        let _ack = self
            .call("notifications/initialized", None)
            .await
            .ok();

        Ok(())
    }

    /// Send a JSON-RPC request and extract the result.
    pub async fn call(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, UpstreamError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let mut request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "id": id,
        });
        if let Some(p) = params {
            request["params"] = p;
        }

        let response = self.transport.request(request).await?;

        // Check for JSON-RPC error
        if let Some(error) = response.get("error") {
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return Err(UpstreamError::JsonRpc {
                name: self.name.clone(),
                code,
                message,
            });
        }

        if let Some(result) = response.get("result") {
            return Ok(result.clone());
        }

        Err(UpstreamError::Protocol {
            name: self.name.clone(),
            message: "response has neither result nor error".to_string(),
        })
    }

    pub async fn list_tools(&mut self) -> Result<Vec<ToolDefinition>, UpstreamError> {
        let result = self.call("tools/list", None).await?;
        let parsed: ListToolsResult =
            serde_json::from_value(result).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        Ok(parsed.tools)
    }

    pub async fn list_prompts(&mut self) -> Result<Vec<PromptDefinition>, UpstreamError> {
        let result = self.call("prompts/list", None).await?;
        let parsed: ListPromptsResult =
            serde_json::from_value(result).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        Ok(parsed.prompts)
    }

    pub async fn list_resources(&mut self) -> Result<Vec<ResourceDefinition>, UpstreamError> {
        let result = self.call("resources/list", None).await?;
        let parsed: ListResourcesResult =
            serde_json::from_value(result).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        Ok(parsed.resources)
    }

    pub async fn call_tool(
        &mut self,
        params: CallToolParams,
    ) -> Result<CallToolResult, UpstreamError> {
        let value =
            serde_json::to_value(&params).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        let result = self.call("tools/call", Some(value)).await?;
        serde_json::from_value(result).map_err(|e| UpstreamError::Json {
            name: self.name.clone(),
            source: e,
        })
    }

    pub async fn get_prompt(
        &mut self,
        params: GetPromptParams,
    ) -> Result<GetPromptResult, UpstreamError> {
        let value =
            serde_json::to_value(&params).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        let result = self.call("prompts/get", Some(value)).await?;
        serde_json::from_value(result).map_err(|e| UpstreamError::Json {
            name: self.name.clone(),
            source: e,
        })
    }

    pub async fn read_resource(
        &mut self,
        params: ReadResourceParams,
    ) -> Result<ReadResourceResult, UpstreamError> {
        let value =
            serde_json::to_value(&params).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        let result = self.call("resources/read", Some(value)).await?;
        serde_json::from_value(result).map_err(|e| UpstreamError::Json {
            name: self.name.clone(),
            source: e,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn shutdown(&mut self) {
        self.transport.shutdown();
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.shutdown();
    }
}
