//! NavraHandler — wraps McpServer as an rmcp ServerHandler.
//!
//! Translates between rmcp's `ServerHandler` trait and navra's
//! `McpServer` methods, preserving the full 10-gate security pipeline.
//! This adapter enables navra to run on rmcp's transport runtime
//! (stdio, streamable HTTP) while keeping all IFC, ACL, Cedar, and
//! hook enforcement intact.

use std::sync::Arc;

use navra_protocol::{
    CallToolResult, InitializeResult, ListPromptsResult, ListResourcesResult, ListToolsResult,
    PaginatedRequest,
};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ErrorData, GetPromptRequestParams, GetPromptResponse,
    ReadResourceRequestParams, ReadResourceResponse,
};
use rmcp::service::{RequestContext, RoleServer};

use navra_protocol::compat::CallToolResultExt;

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

    fn agent_from_context(ctx: &RequestContext<RoleServer>, server: &McpServer) -> AgentIdentity {
        if let Some(id) = ctx.extensions.get::<AgentIdentity>() {
            return id.clone();
        }
        if let Some(parts) = ctx.extensions.get::<axum::http::request::Parts>()
            && let Ok(id) = server.authenticator().authenticate(&parts.headers)
        {
            return id;
        }
        let name = ctx
            .peer
            .peer_info()
            .map(|info| info.client_info.name.clone())
            .unwrap_or_else(|| "anonymous".to_string());
        AgentIdentity::new(&name, "default")
    }

    fn session_id_for(agent: &AgentIdentity) -> String {
        format!("rmcp:{}", agent.name)
    }

    /// Does the requesting peer support SEP-2322 `input_required`
    /// results? Only peers that negotiated 2026-07-28 or newer may
    /// receive them. Initialize-handshake peers have their negotiated
    /// version in `peer_info`; HTTP stateless peers get `peer_info`
    /// from the `MCP-Protocol-Version` header; discover-based
    /// duplex/stdio peers carry the version per-request in `_meta`.
    fn peer_supports_mrtr(context: &RequestContext<RoleServer>) -> bool {
        if let Some(info) = context.peer.peer_info() {
            return info.protocol_version >= rmcp::model::ProtocolVersion::V_2026_07_28;
        }
        context
            .meta
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28)
    }

    fn pagination(params: &Option<rmcp::model::PaginatedRequestParams>) -> PaginatedRequest {
        PaginatedRequest {
            cursor: params.as_ref().and_then(|p| p.cursor.clone()),
        }
    }
}

// ========================================================================
// subscriptions/listen (MCP 2026-07-28)
// ========================================================================

/// Map a broadcaster event's serialized JSON-RPC notification to its
/// (method, uri) pair; `None` for unparsable events.
fn notification_method_uri(data: &str) -> Option<(String, Option<String>)> {
    let value: serde_json::Value = serde_json::from_str(data).ok()?;
    let method = value.get("method")?.as_str()?.to_string();
    let uri = value
        .pointer("/params/uri")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    Some((method, uri))
}

impl ServerHandler for NavraHandler {
    fn get_info(&self) -> rmcp::model::ServerConfig {
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
        let agent = Self::agent_from_context(&context, &self.server);
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
    ) -> Result<CallToolResponse, ErrorData> {
        let agent = Self::agent_from_context(&context, &self.server);
        let session_id = Self::session_id_for(&agent);

        // Ensure a navra session exists (auto-create for stateless mode)
        self.server.ensure_session(&session_id, &agent);

        let mut ctx = CallContext::new(agent, session_id.clone());
        let persisted_label = self.server.sessions().context_label(&session_id);
        ctx.taint.absorb(persisted_label);

        let response = self.server.handle_call_tool(request, ctx).await;
        // SEP-2322 `input_required` is only valid on the wire for peers
        // that negotiated 2026-07-28 or newer — rmcp rejects it for
        // legacy peers. Downgrade to a tool-level error for them so
        // agent loops keep receiving an error result (rather than a
        // protocol error aborting the run).
        Ok(match response {
            CallToolResponse::InputRequired(_) if !Self::peer_supports_mrtr(&context) => {
                CallToolResponse::Complete(CallToolResult::error_msg(
                    "upstream requested interactive input (MCP input_required), \
                     which requires protocol version 2026-07-28 and an \
                     MRTR-capable client",
                ))
            }
            other => other,
        })
    }

    async fn list_tools(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let agent = Self::agent_from_context(&context, &self.server);
        let pagination = Self::pagination(&request);
        Ok(self.server.handle_list_tools(&agent, &pagination))
    }

    async fn list_prompts(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let agent = Self::agent_from_context(&context, &self.server);
        let pagination = Self::pagination(&request);
        Ok(self.server.handle_list_prompts(&agent, &pagination))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let agent = Self::agent_from_context(&context, &self.server);
        let session_id = Self::session_id_for(&agent);
        self.server
            .handle_get_prompt(request, &agent, &session_id)
            .await
            .map(GetPromptResponse::Complete)
            .map_err(|msg| ErrorData::invalid_params(msg, None))
    }

    async fn list_resources(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let agent = Self::agent_from_context(&context, &self.server);
        let pagination = Self::pagination(&request);
        Ok(self.server.handle_list_resources(&agent, &pagination))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let agent = Self::agent_from_context(&context, &self.server);
        let session_id = Self::session_id_for(&agent);
        self.server
            .handle_read_resource(request, &agent, &session_id)
            .await
            .map(ReadResourceResponse::Complete)
            .map_err(|msg| ErrorData::invalid_params(msg, None))
    }

    // --- subscriptions/listen (MCP 2026-07-28) ---

    fn accepted_subscription_filter(
        &self,
        requested: &rmcp::model::SubscriptionFilter,
    ) -> Option<rmcp::model::SubscriptionFilter> {
        // subscriptions/listen taps the internal notification bus
        // (the SSE broadcaster); without it there is nothing to
        // deliver, so leave the method unimplemented.
        self.server.broadcaster()?;

        let mut accepted = rmcp::model::SubscriptionFilter::new();
        // navra emits tools/prompts/resources list_changed (upstream
        // registry swaps) and resources/updated (upstream forwards).
        accepted.tools_list_changed = requested.tools_list_changed;
        accepted.prompts_list_changed = requested.prompts_list_changed;
        accepted.resources_list_changed = requested.resources_list_changed;
        accepted.resource_subscriptions = requested.resource_subscriptions.as_ref().map(|uris| {
            uris.iter()
                .filter(|uri| self.server.resource_exists(uri))
                .cloned()
                .collect()
        });
        Some(accepted)
    }

    async fn listen(
        &self,
        context: rmcp::service::SubscriptionContext,
    ) -> Result<(), rmcp::model::ErrorData> {
        let server = Arc::clone(&self.server);
        let accepted = context.accepted().clone();

        // The subscription registers under a synthetic session key in
        // navra's existing machinery: resource URIs go into the
        // resource-subscription map, and the broadcaster channel under
        // the same key receives both targeted resource updates and
        // gateway-wide list_changed broadcasts.
        let session_key = format!("subscription:{}", uuid::Uuid::new_v4());
        if let Some(uris) = accepted.resource_subscriptions.as_ref() {
            for uri in uris {
                server
                    .handle_resource_subscribe(uri, &session_key)
                    .map_err(|msg| ErrorData::invalid_params(msg, None))?;
            }
        }
        let broadcaster = server
            .broadcaster()
            .expect("accepted_subscription_filter checked the broadcaster");
        let mut rx = broadcaster.subscribe(&session_key);
        let sink = context.sink().clone();

        let outcome = loop {
            tokio::select! {
                _ = context.cancelled() => break Ok(()),
                event = rx.recv() => match event {
                    Ok(event) => {
                        let Some((method, uri)) = notification_method_uri(&event.data) else {
                            continue;
                        };
                        let send = match method.as_str() {
                            crate::protocol::NOTIFY_TOOLS_LIST_CHANGED => {
                                sink.notify_tool_list_changed().await
                            }
                            crate::protocol::NOTIFY_PROMPTS_LIST_CHANGED => {
                                sink.notify_prompt_list_changed().await
                            }
                            crate::protocol::NOTIFY_RESOURCES_LIST_CHANGED => {
                                sink.notify_resource_list_changed().await
                            }
                            crate::protocol::NOTIFY_RESOURCES_UPDATED => {
                                let Some(uri) = uri else { continue };
                                sink.notify_resource_updated(uri).await
                            }
                            // Other notifications (e.g. progress) are not
                            // part of an accepted filter; the sink would
                            // reject them, so skip.
                            _ => continue,
                        };
                        if let Err(e) = send {
                            tracing::warn!(error = %e, "subscription notification dropped");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break Ok(());
                    }
                }
            }
        };

        // Tear the registration down on every exit path.
        if let Some(uris) = accepted.resource_subscriptions.as_ref() {
            for uri in uris {
                let _ = server.handle_resource_unsubscribe(uri, &session_key);
            }
        }
        broadcaster.remove_session(&session_key);
        outcome
    }
}
