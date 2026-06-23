//! NavraHandler — wraps McpServer as an rmcp ServerHandler.
//!
//! Translates between rmcp's `ServerHandler` trait and navra's
//! `McpServer` methods, preserving the full 10-gate security pipeline.
//! This adapter enables navra to run on rmcp's transport runtime
//! (stdio, streamable HTTP) while keeping all IFC, ACL, Cedar, and
//! hook enforcement intact.

use std::sync::Arc;

use navra_protocol::{
    InitializeResult, ListPromptsResult, ListResourcesResult, ListToolsResult, PaginatedRequest,
};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, ErrorData, GetPromptRequestParams, GetPromptResult,
    ReadResourceRequestParams, ReadResourceResult,
};
use rmcp::service::{RequestContext, RoleServer};

use super::McpServer;
use crate::auth::{AgentIdentity, CallContext};

/// Thin adapter that implements rmcp's `ServerHandler` by delegating
/// to navra's `McpServer` methods.
pub struct NavraHandler {
    server: Arc<McpServer>,
}

impl NavraHandler {
    pub fn new(server: Arc<McpServer>) -> Self {
        Self { server }
    }

    pub fn server(&self) -> &McpServer {
        &self.server
    }

    fn agent_from_context(ctx: &RequestContext<RoleServer>) -> AgentIdentity {
        ctx.extensions
            .get::<AgentIdentity>()
            .cloned()
            .unwrap_or_else(|| {
                let name = ctx
                    .peer
                    .peer_info()
                    .map(|info| info.client_info.name.clone())
                    .unwrap_or_else(|| "anonymous".to_string());
                AgentIdentity::new(&name, "default")
            })
    }

    fn session_id_for(agent: &AgentIdentity) -> String {
        format!("rmcp:{}", agent.name)
    }

    fn pagination(params: &Option<rmcp::model::PaginatedRequestParams>) -> PaginatedRequest {
        PaginatedRequest {
            cursor: params.as_ref().and_then(|p| p.cursor.clone()),
        }
    }
}

impl ServerHandler for NavraHandler {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        let navra_caps = self.server.capabilities();
        let mut rmcp_caps = rmcp::model::ServerCapabilities::default();
        rmcp_caps.tools = navra_caps.tools;
        rmcp_caps.resources = navra_caps.resources;
        rmcp_caps.prompts = navra_caps.prompts;

        let mut result =
            InitializeResult::new(rmcp_caps).with_server_info(self.server.server_info());
        result.protocol_version = rmcp::model::ProtocolVersion::V_2026_07_28;
        result
    }

    async fn initialize(
        &self,
        request: rmcp::model::InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        let agent = Self::agent_from_context(&context);
        let session_id = Self::session_id_for(&agent);
        // Remove any prior session for this agent (clean slate on re-init)
        self.server.sessions().remove(&session_id);
        match self.server.handle_initialize(request, agent) {
            Ok((result, _navra_sid)) => Ok(result),
            Err(msg) => Err(ErrorData::invalid_params(msg, None)),
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let agent = Self::agent_from_context(&context);
        let session_id = Self::session_id_for(&agent);

        // Ensure a navra session exists (auto-create for stateless mode)
        self.server.ensure_session(&session_id, &agent);

        let mut ctx = CallContext::new(agent, session_id.clone());
        let persisted_label = self.server.sessions().context_label(&session_id);
        ctx.taint.absorb(persisted_label);

        let result = self.server.handle_call_tool(request, ctx).await;
        Ok(result)
    }

    async fn list_tools(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let agent = Self::agent_from_context(&context);
        let pagination = Self::pagination(&request);
        Ok(self.server.handle_list_tools(&agent, &pagination))
    }

    async fn list_prompts(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let agent = Self::agent_from_context(&context);
        let pagination = Self::pagination(&request);
        Ok(self.server.handle_list_prompts(&agent, &pagination))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, ErrorData> {
        let agent = Self::agent_from_context(&context);
        let session_id = Self::session_id_for(&agent);
        self.server
            .handle_get_prompt(request, &agent, &session_id)
            .await
            .map_err(|msg| ErrorData::invalid_params(msg, None))
    }

    async fn list_resources(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let agent = Self::agent_from_context(&context);
        let pagination = Self::pagination(&request);
        Ok(self.server.handle_list_resources(&agent, &pagination))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let agent = Self::agent_from_context(&context);
        let session_id = Self::session_id_for(&agent);
        self.server
            .handle_read_resource(request, &agent, &session_id)
            .await
            .map_err(|msg| ErrorData::invalid_params(msg, None))
    }
}
