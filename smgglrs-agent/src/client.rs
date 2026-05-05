//! MCP client with authentication and IFC taint tracking.

use crate::error::AgentError;
use smgglrs_protocol::label::{DataLabel, Integrity};
use smgglrs_protocol::{
    CallToolParams, CallToolResult, GetPromptParams, GetPromptResult, PromptDefinition,
    ReadResourceParams, ReadResourceResult, ResourceDefinition, ToolDefinition, Upstream,
};
use smgglrs_security::ifc::{is_external_read_tool, TaintTracker};
use std::collections::HashMap;

/// MCP client wrapping [`Upstream`] with authentication and IFC taint tracking.
///
/// Tracks data labels from tool results across the session. External read
/// tools automatically label their output as Untrusted (mirroring server-side
/// IFC enforcement).
pub struct McpClient {
    upstream: Upstream,
    taint: TaintTracker,
    auth_token: Option<String>,
}

impl McpClient {
    /// Create from an already-connected [`Upstream`].
    pub fn new(upstream: Upstream) -> Self {
        Self {
            upstream,
            taint: TaintTracker::new(),
            auth_token: None,
        }
    }

    /// Set authentication token (Bearer or capability token).
    pub fn with_auth(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// List available tools from the MCP server.
    pub async fn list_tools(&mut self) -> Result<Vec<ToolDefinition>, AgentError> {
        Ok(self.upstream.list_tools().await?)
    }

    /// Call a tool and track IFC labels from the result.
    ///
    /// If the tool is classified as an external read (via [`is_external_read_tool`]),
    /// its result is labeled Untrusted. The label is absorbed into the session
    /// taint tracker.
    pub async fn call_tool(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<CallToolResult, AgentError> {
        let params = CallToolParams {
            name: name.to_string(),
            arguments,
            meta: None,
        };
        let mut result = self.upstream.call_tool(params).await?;

        // CallToolResult.label is #[serde(skip)] so it deserializes as default
        // (TRUSTED_PUBLIC). Apply client-side classification to mirror server behavior.
        if is_external_read_tool(name) && result.label.integrity == Integrity::Trusted {
            result.label = DataLabel::UNTRUSTED_PUBLIC;
        }

        self.taint.absorb(result.label);
        Ok(result)
    }

    /// List prompts from the MCP server.
    pub async fn list_prompts(&mut self) -> Result<Vec<PromptDefinition>, AgentError> {
        Ok(self.upstream.list_prompts().await?)
    }

    /// Get a prompt by name with arguments.
    pub async fn get_prompt(
        &mut self,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> Result<GetPromptResult, AgentError> {
        let params = GetPromptParams {
            name: name.to_string(),
            arguments,
        };
        Ok(self.upstream.get_prompt(params).await?)
    }

    /// List resources from the MCP server.
    pub async fn list_resources(&mut self) -> Result<Vec<ResourceDefinition>, AgentError> {
        Ok(self.upstream.list_resources().await?)
    }

    /// Read a resource by URI.
    pub async fn read_resource(&mut self, uri: &str) -> Result<ReadResourceResult, AgentError> {
        let params = ReadResourceParams {
            uri: uri.to_string(),
        };
        Ok(self.upstream.read_resource(params).await?)
    }

    /// Current accumulated taint level.
    pub fn taint(&self) -> DataLabel {
        self.taint.level()
    }

    /// Access the underlying [`Upstream`] for low-level operations.
    pub fn upstream(&mut self) -> &mut Upstream {
        &mut self.upstream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use smgglrs_protocol::label::Integrity;
    use smgglrs_protocol::upstream::{Transport, UpstreamError};

    /// Mock transport that returns scripted responses.
    struct MockTransport {
        responses: std::sync::Mutex<Vec<serde_json::Value>>,
    }

    impl MockTransport {
        fn new(responses: Vec<serde_json::Value>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses),
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn request(
            &mut self,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, UpstreamError> {
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Ok(serde_json::json!({"jsonrpc": "2.0", "result": {}, "id": 1}))
            } else {
                Ok(responses.remove(0))
            }
        }

        fn shutdown(&mut self) {}
    }

    async fn mock_client(responses: Vec<serde_json::Value>) -> McpClient {
        // First two responses are for initialize + notifications/initialized
        let mut all = vec![
            serde_json::json!({
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "serverInfo": {"name": "test", "version": "0.1.0"}
                },
                "id": 1
            }),
            serde_json::json!({"jsonrpc": "2.0", "result": {}, "id": 2}),
        ];
        all.extend(responses);
        let transport = MockTransport::new(all);
        let upstream = Upstream::connect("test", transport).await.unwrap();
        McpClient::new(upstream)
    }

    #[tokio::test]
    async fn taint_starts_clean() {
        let client = mock_client(vec![]).await;
        assert_eq!(client.taint(), DataLabel::TRUSTED_PUBLIC);
    }

    #[tokio::test]
    async fn call_tool_tracks_external_read_taint() {
        let mut client = mock_client(vec![serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": "file contents"}],
                "isError": false
            },
            "id": 3
        })])
        .await;

        let _result = client.call_tool("file_read", serde_json::json!({})).await.unwrap();
        assert_eq!(client.taint().integrity, Integrity::Untrusted);
    }

    #[tokio::test]
    async fn call_tool_non_read_stays_trusted() {
        let mut client = mock_client(vec![serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": "ok"}],
                "isError": false
            },
            "id": 3
        })])
        .await;

        let _result = client
            .call_tool("git_status", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(client.taint(), DataLabel::TRUSTED_PUBLIC);
    }
}
