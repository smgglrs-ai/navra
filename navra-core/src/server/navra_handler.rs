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
    /// Identity authenticated out-of-band before the rmcp session was
    /// established (e.g. the WebSocket upgrade handshake). Used when
    /// the request carries no HTTP parts to authenticate against.
    default_identity: Option<AgentIdentity>,
    /// Per-connection nonce. Anonymous identities (NoAuthenticator)
    /// share one default identity across every client, so their
    /// session key incorporates this nonce: two anonymous clients on
    /// separate connections must never share sessions, dynamic
    /// grants, or IFC taint state.
    connection_nonce: String,
}

impl NavraHandler {
    pub fn new(server: Arc<McpServer>) -> Self {
        Self {
            server,
            default_identity: None,
            connection_nonce: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Build a handler with a pre-authenticated identity for
    /// transports that authenticate before the rmcp session starts
    /// (WebSocket upgrade, in-process direct transports).
    pub fn with_default_identity(server: Arc<McpServer>, identity: AgentIdentity) -> Self {
        Self {
            server,
            default_identity: Some(identity),
            connection_nonce: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub fn server(&self) -> &McpServer {
        &self.server
    }

    /// Resolve the calling agent's identity.
    ///
    /// Fail-closed: when an authenticator is configured and
    /// authentication fails, the request is rejected (mirroring the
    /// ACP transport). The anonymous fallback is only honored when a
    /// `NoAuthenticator` is explicitly in the chain (dev mode), since
    /// it authenticates every request successfully.
    fn agent_from_context(
        ctx: &RequestContext<RoleServer>,
        server: &McpServer,
        default_identity: Option<&AgentIdentity>,
    ) -> Result<AgentIdentity, ErrorData> {
        if let Some(id) = ctx.extensions.get::<AgentIdentity>() {
            return Ok(id.clone());
        }
        if let Some(parts) = ctx.extensions.get::<axum::http::request::Parts>() {
            return server
                .authenticator()
                .authenticate(&parts.headers)
                .map_err(|_| {
                    ErrorData::invalid_request(
                        "Authentication required: invalid or missing credentials",
                        None,
                    )
                });
        }
        // No HTTP parts (stdio / in-memory duplex): use the
        // transport-level identity when one was authenticated
        // out-of-band, otherwise authenticate against empty headers
        // (NoAuthenticator in dev mode passes; real authenticators
        // fail closed).
        if let Some(id) = default_identity {
            return Ok(id.clone());
        }
        let empty = axum::http::HeaderMap::new();
        server.authenticator().authenticate(&empty).map_err(|_| {
            ErrorData::invalid_request(
                "Authentication required: invalid or missing credentials",
                None,
            )
        })
    }

    /// Derive the stateless session key from the *authenticated*
    /// identity — never from client-controlled `clientInfo.name`.
    /// Two clients claiming the same name but holding different
    /// identities must not share taint state.
    ///
    /// - DID-bearing identities key on the DID.
    /// - Anonymous identities (the NoAuthenticator default — every
    ///   anonymous client resolves to the same agent) get a
    ///   per-connection nonce so separate connections never share
    ///   sessions, grants, or taint.
    /// - Everything else keys on the (permission set, name) pair,
    ///   JSON-encoded so the pair is collision-free.
    fn session_id_for(&self, agent: &AgentIdentity) -> String {
        match &agent.did {
            Some(did) => format!("rmcp:did:{did}"),
            None if Self::is_anonymous_identity(&self.server, agent) => format!(
                "rmcp:anon:{}:{}",
                self.connection_nonce,
                super::handlers::identity_key(&agent.permissions, &agent.name)
            ),
            None => format!(
                "rmcp:{}",
                super::handlers::identity_key(&agent.permissions, &agent.name)
            ),
        }
    }

    /// Is this agent the identity an anonymous (credential-free)
    /// request resolves to? True when the configured authenticator
    /// accepts empty headers and returns exactly this agent — i.e.
    /// the agent was not distinguished by any credential.
    fn is_anonymous_identity(server: &McpServer, agent: &AgentIdentity) -> bool {
        let empty = axum::http::HeaderMap::new();
        matches!(server.authenticator().authenticate(&empty), Ok(anon) if &anon == agent)
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

    /// Re-create a removed session, carrying its accumulated IFC
    /// context label (taint) forward across re-initialization.
    ///
    /// A protocol-level re-init is NOT a declassification: taint is
    /// monotone (INV-1) and must survive, otherwise a tainted client
    /// launders its label simply by re-initializing. Anonymous
    /// identities are keyed per connection (see [`Self::session_id_for`]),
    /// so each new connection still starts clean.
    fn restore_prior_session(server: &McpServer, prior: Option<crate::session::Session>) {
        if let Some(mut session) = prior {
            session.initialized = true;
            session.last_accessed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            server.sessions().create(session);
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
        let agent =
            Self::agent_from_context(&context, &self.server, self.default_identity.as_ref())?;
        let session_id = self.session_id_for(&agent);
        // Drop the prior session object for this agent, then restore
        // it after the handshake with its IFC taint intact (see
        // `restore_prior_session`).
        let prior_session = self.server.sessions().remove(&session_id);
        match self.server.handle_initialize(request, agent) {
            Ok((result, _navra_sid)) => {
                Self::restore_prior_session(&self.server, prior_session);
                Ok(result)
            }
            Err(msg) => {
                // A failed re-init must not destroy the existing
                // session either — restore it.
                Self::restore_prior_session(&self.server, prior_session);
                Err(ErrorData::invalid_params(msg, None))
            }
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let agent =
            Self::agent_from_context(&context, &self.server, self.default_identity.as_ref())?;
        let session_id = self.session_id_for(&agent);

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
        let agent =
            Self::agent_from_context(&context, &self.server, self.default_identity.as_ref())?;
        let pagination = Self::pagination(&request);
        Ok(self.server.handle_list_tools(&agent, &pagination))
    }

    async fn list_prompts(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let agent =
            Self::agent_from_context(&context, &self.server, self.default_identity.as_ref())?;
        let pagination = Self::pagination(&request);
        Ok(self.server.handle_list_prompts(&agent, &pagination))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let agent =
            Self::agent_from_context(&context, &self.server, self.default_identity.as_ref())?;
        let session_id = self.session_id_for(&agent);
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
        let agent =
            Self::agent_from_context(&context, &self.server, self.default_identity.as_ref())?;
        let pagination = Self::pagination(&request);
        Ok(self.server.handle_list_resources(&agent, &pagination))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let agent =
            Self::agent_from_context(&context, &self.server, self.default_identity.as_ref())?;
        let session_id = self.session_id_for(&agent);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AgentIdentity;
    use crate::ifc::DataLabel;
    use std::sync::Arc;

    fn anon_server() -> Arc<McpServer> {
        Arc::new(McpServer::builder().allow_anonymous().build())
    }

    #[test]
    fn anonymous_session_keys_are_unique_per_connection() {
        // The NoAuthenticator default identity is shared by every
        // anonymous client; two connections must not share a session
        // (grants, taint, value stores).
        let server = anon_server();
        let h1 = NavraHandler::new(Arc::clone(&server));
        let h2 = NavraHandler::new(Arc::clone(&server));
        let agent = AgentIdentity::new("anonymous", "readonly");
        let k1 = h1.session_id_for(&agent);
        let k2 = h2.session_id_for(&agent);
        assert_ne!(k1, k2, "separate connections must not share session keys");
        // Stable within one connection.
        assert_eq!(k1, h1.session_id_for(&agent));
    }

    #[test]
    fn did_session_keys_are_stable_across_connections() {
        // DID-bearing identities are credential-bound: the same DID
        // keeps its (tainted) session across connections.
        let server = anon_server();
        let h1 = NavraHandler::new(Arc::clone(&server));
        let h2 = NavraHandler::new(Arc::clone(&server));
        let mut agent = AgentIdentity::new("someone", "dev");
        agent.did = Some("did:key:z6MkTest".to_string());
        assert_eq!(h1.session_id_for(&agent), h2.session_id_for(&agent));
    }

    #[test]
    fn identity_key_encoding_is_collision_free() {
        // The legacy "{perms}:{name}" format let ("a:b","c") and
        // ("a","b:c") collide; the JSON encoding must not.
        assert_ne!(
            super::super::handlers::identity_key("a:b", "c"),
            super::super::handlers::identity_key("a", "b:c")
        );
    }

    #[test]
    fn restore_prior_session_preserves_ifc_taint() {
        // A re-initialize must not reset the session's accumulated
        // IFC context label — taint is monotone (INV-1).
        let server = anon_server();
        let agent = AgentIdentity::new("anonymous", "readonly");
        let key = "rmcp:test:session";
        server.ensure_session(key, &agent);
        server
            .sessions()
            .update_context_label(key, DataLabel::UNTRUSTED_PUBLIC);
        let prior = server.sessions().remove(key);
        assert!(prior.is_some());
        NavraHandler::restore_prior_session(&server, prior);
        assert_eq!(
            server.sessions().context_label(key),
            DataLabel::UNTRUSTED_PUBLIC,
            "re-init must carry the context label forward"
        );
    }

    #[test]
    fn restore_prior_session_with_no_prior_session_is_noop() {
        let server = anon_server();
        NavraHandler::restore_prior_session(&server, None);
        assert_eq!(server.sessions().count(), 0);
    }
}
