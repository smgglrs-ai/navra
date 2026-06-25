//! MCP client with authentication and IFC taint tracking.

use crate::error::AgentError;
use navra_auth::ifc::{is_external_read_tool, TaintTracker};
use navra_protocol::label::DataLabel;
use navra_protocol::{
    CallToolParams, CallToolResult, GetPromptParams, GetPromptResult, PromptDefinition,
    ReadResourceParams, ReadResourceResult, ResourceDefinition, ToolDefinition,
};
use std::collections::HashMap;

/// MCP client wrapping an rmcp [`Peer<RoleClient>`](rmcp::Peer) with
/// authentication and IFC taint tracking.
///
/// Tracks data labels from tool results across the session. External read
/// tools automatically label their output as Untrusted (mirroring server-side
/// IFC enforcement).
pub struct McpClient {
    peer: rmcp::Peer<rmcp::RoleClient>,
    taint: TaintTracker,
    auth_token: Option<String>,
}

impl McpClient {
    /// Create from an already-connected rmcp peer.
    pub fn new(peer: rmcp::Peer<rmcp::RoleClient>) -> Self {
        Self {
            peer,
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
    pub async fn list_tools(&self) -> Result<Vec<ToolDefinition>, AgentError> {
        Ok(self.peer.list_all_tools().await?)
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
        let mut params = CallToolParams::new(name.to_string());
        params.arguments = Some(
            serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(arguments)
                .unwrap_or_default(),
        );
        let result = self.peer.call_tool(params).await?;

        if is_external_read_tool(name) {
            self.taint.absorb(DataLabel::UNTRUSTED_PUBLIC);
        }

        Ok(result)
    }

    /// List prompts from the MCP server.
    pub async fn list_prompts(&self) -> Result<Vec<PromptDefinition>, AgentError> {
        Ok(self.peer.list_all_prompts().await?)
    }

    /// Get a prompt by name with arguments.
    pub async fn get_prompt(
        &self,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> Result<GetPromptResult, AgentError> {
        let mut params = GetPromptParams::new(name);
        if !arguments.is_empty() {
            let map: serde_json::Map<String, serde_json::Value> = arguments
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            params.arguments = Some(map);
        }
        Ok(self.peer.get_prompt(params).await?)
    }

    /// List resources from the MCP server.
    pub async fn list_resources(&self) -> Result<Vec<ResourceDefinition>, AgentError> {
        Ok(self.peer.list_all_resources().await?)
    }

    /// Read a resource by URI.
    pub async fn read_resource(&self, uri: &str) -> Result<ReadResourceResult, AgentError> {
        let params = ReadResourceParams::new(uri);
        Ok(self.peer.read_resource(params).await?)
    }

    /// Current accumulated taint level.
    pub fn taint(&self) -> DataLabel {
        self.taint.level()
    }

    /// Access the underlying rmcp peer for low-level operations.
    pub fn peer(&self) -> &rmcp::Peer<rmcp::RoleClient> {
        &self.peer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_protocol::compat::CallToolResultExt;
    use navra_protocol::label::Integrity;
    use rmcp::model::*;
    use rmcp::service::ServiceExt;
    use std::sync::Arc;

    struct MockServer {
        tools: Vec<Tool>,
        call_response: Arc<dyn Fn(&str) -> CallToolResult + Send + Sync>,
    }

    impl MockServer {
        fn new() -> Self {
            let mut schema = serde_json::Map::new();
            schema.insert("type".into(), serde_json::json!("object"));
            Self {
                tools: vec![Tool::new("echo", "Echo back", schema)],
                call_response: Arc::new(|_| CallToolResult::text("ok")),
            }
        }

        fn with_call_response(
            mut self,
            f: impl Fn(&str) -> CallToolResult + Send + Sync + 'static,
        ) -> Self {
            self.call_response = Arc::new(f);
            self
        }
    }

    impl rmcp::ServerHandler for MockServer {
        fn get_info(&self) -> ServerInfo {
            InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
                .with_server_info(Implementation::new("mock", "0.1.0"))
        }

        fn list_tools(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: rmcp::service::RequestContext<rmcp::RoleServer>,
        ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::Error>> + Send + '_
        {
            async {
                Ok(ListToolsResult {
                    meta: None,
                    tools: self.tools.clone(),
                    next_cursor: None,
                })
            }
        }

        fn call_tool(
            &self,
            request: CallToolRequestParams,
            _context: rmcp::service::RequestContext<rmcp::RoleServer>,
        ) -> impl std::future::Future<Output = Result<CallToolResult, rmcp::Error>> + Send + '_
        {
            let resp = (self.call_response)(request.name.as_ref());
            async move { Ok(resp) }
        }
    }

    async fn mock_client_with(server: MockServer) -> McpClient {
        let (server_io, client_io) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            if let Ok(svc) = server.serve(server_io).await {
                let _ = svc.waiting().await;
            }
        });
        let client = <() as ServiceExt<rmcp::RoleClient>>::serve((), client_io)
            .await
            .expect("client connect");
        let peer = client.peer().clone();
        tokio::spawn(async move {
            let _ = client.waiting().await;
        });
        McpClient::new(peer)
    }

    async fn mock_client() -> McpClient {
        mock_client_with(MockServer::new()).await
    }

    #[tokio::test]
    async fn taint_starts_clean() {
        let client = mock_client().await;
        assert_eq!(client.taint(), DataLabel::TRUSTED_PUBLIC);
    }

    #[tokio::test]
    async fn call_tool_tracks_external_read_taint() {
        let server =
            MockServer::new().with_call_response(|_| CallToolResult::text("file contents"));
        let mut client = mock_client_with(server).await;

        let _result = client
            .call_tool("file_read", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(client.taint().integrity, Integrity::Untrusted);
    }

    #[tokio::test]
    async fn call_tool_git_status_taints_session() {
        let server = MockServer::new().with_call_response(|_| CallToolResult::text("ok"));
        let mut client = mock_client_with(server).await;

        let _result = client
            .call_tool("git_status", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(client.taint(), DataLabel::UNTRUSTED_PUBLIC);
    }
}
