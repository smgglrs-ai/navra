use crate::auth::CallContext;
use crate::protocol::{
    CallToolParams, CallToolResult, Content, GetPromptParams, GetPromptResult, InitializeParams,
    InitializeResult, ListPromptsResult, ListResourcesResult, ListToolsResult,
    ReadResourceParams, ReadResourceResult,
};
use crate::safety::{FilterContext, FilterPipeline};
use crate::session::Session;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::McpServer;

impl McpServer {
    pub fn server_info(&self) -> crate::protocol::ServerInfo {
        crate::protocol::ServerInfo {
            name: self.name.clone(),
            version: Some(self.version.clone()),
        }
    }

    pub fn capabilities(&self) -> crate::protocol::ServerCapabilities {
        crate::protocol::ServerCapabilities {
            tools: if self.tools.is_empty() {
                None
            } else {
                Some(crate::protocol::ToolsCapability { list_changed: true })
            },
            resources: if self.resources.is_empty() {
                None
            } else {
                Some(crate::protocol::ResourcesCapability {
                    subscribe: false,
                    list_changed: false,
                })
            },
            prompts: if self.prompts.is_empty() {
                None
            } else {
                Some(crate::protocol::PromptsCapability { list_changed: false })
            },
            permissions: Some(smgglrs_protocol::permissions::PermissionsCapability {}),
        }
    }

    /// Handle an initialize request. Returns the result and the session ID.
    pub fn handle_initialize(&self, params: InitializeParams, agent_identity: crate::auth::AgentIdentity) -> (InitializeResult, String) {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let session = Session {
            id: session_id.clone(),
            agent: agent_identity,
            client_info: params.client_info,
            initialized: true,
            context_label: crate::ifc::DataLabel::TRUSTED_PUBLIC,
            created_at: now,
            last_accessed: now,
        };
        self.sessions.create(session);

        let result = InitializeResult {
            protocol_version: crate::protocol::PROTOCOL_VERSION.to_string(),
            capabilities: self.capabilities(),
            server_info: self.server_info(),
        };
        (result, session_id)
    }

    pub fn handle_list_tools(&self, _agent: &crate::auth::AgentIdentity) -> ListToolsResult {
        let tools = self.tools.values().map(|t| t.definition.clone()).collect();
        ListToolsResult { tools }
    }

    pub async fn handle_call_tool(
        &self,
        params: CallToolParams,
        mut ctx: CallContext,
    ) -> CallToolResult {
        // Reject all tool calls when paused
        if self.paused.load(Ordering::Relaxed) {
            return CallToolResult::error(
                "Server is paused. Resume from the system tray to continue.".to_string(),
            );
        }

        // Rate limit check (kernel-enforced)
        if self.quota_engine.has_limits()
            && !self.quota_engine.check(&ctx.agent.name, &ctx.agent.permissions) {
                return CallToolResult::error(format!(
                    "Rate limit exceeded for agent '{}'",
                    ctx.agent.name
                ));
            }

        // Extract process table fields from context
        let agent_ring = ctx.agent.capabilities.as_ref().map(|c| c.ring);
        let agent_did = ctx.agent.did.as_deref();

        // Per-tool permission check (before calling handler).
        // Capability tokens carry their own tool globs; legacy agents
        // use the configured ToolPermissions.
        if let Some(ref caps) = ctx.agent.capabilities {
            let tool_allowed = caps.tools.iter().any(|pattern| {
                glob::Pattern::new(pattern)
                    .map(|p| p.matches(&params.name))
                    .unwrap_or(false)
            });
            if !tool_allowed {
                self.process_table.record_denied(
                    &ctx.agent.name, &ctx.agent.permissions, agent_did, agent_ring,
                );
                return CallToolResult::error(format!(
                    "Permission denied: tool '{}' not in capability token grants",
                    params.name
                ));
            }
        } else if let Some(tp) = self.tool_permissions.get(&ctx.agent.permissions) {
            match tp.check(&params.name) {
                crate::permissions::tool_rules::ToolPolicy::Deny => {
                    // Check if a dynamic session grant overrides the denial
                    if !self.session_permissions.check_tool(&ctx.session_id, &params.name) {
                        self.process_table.record_denied(
                            &ctx.agent.name, &ctx.agent.permissions, agent_did, agent_ring,
                        );
                        return CallToolResult::error(format!(
                            "Permission denied: tool '{}' is blocked for permission set '{}'",
                            params.name, ctx.agent.permissions
                        ));
                    }
                    tracing::info!(
                        tool = %params.name,
                        session_id = %ctx.session_id,
                        "Tool allowed via dynamic session grant"
                    );
                }
                crate::permissions::tool_rules::ToolPolicy::Approve => {
                    // Check if a dynamic session grant overrides the approval requirement
                    if !self.session_permissions.check_tool(&ctx.session_id, &params.name) {
                        self.process_table.record_denied(
                            &ctx.agent.name, &ctx.agent.permissions, agent_did, agent_ring,
                        );
                        return CallToolResult::error(format!(
                            "Approval required: tool '{}' requires approval for permission set '{}'",
                            params.name, ctx.agent.permissions
                        ));
                    }
                    tracing::info!(
                        tool = %params.name,
                        session_id = %ctx.session_id,
                        "Tool approval bypassed via dynamic session grant"
                    );
                }
                crate::permissions::tool_rules::ToolPolicy::Allow => {}
            }
        }

        // IFC: resolve variable references in arguments
        let session_store = self.value_stores.get_or_create(&ctx.session_id);
        let resolved = match crate::ifc::value_store::resolve_variable_refs(
            &params.arguments,
            &session_store,
        ) {
            Ok(r) => r,
            Err(msg) => {
                self.process_table.record_denied(
                    &ctx.agent.name, &ctx.agent.permissions, agent_did, agent_ring,
                );
                return CallToolResult::error(msg);
            }
        };

        // IFC pre-check: per-value write blocking (Bell-LaPadula no-write-down).
        if crate::ifc::is_write_tool(&params.name) {
            let check_label = if resolved.referenced_vars.is_empty() {
                // No var:// refs — fall back to session context label
                ctx.taint.level()
            } else {
                // Per-value: use effective label from referenced variables
                resolved.effective_label
            };

            if check_label.integrity == crate::ifc::Integrity::Untrusted {
                let policy = self.ifc_policies.get(&ctx.agent.permissions);
                match policy {
                    Some(crate::ifc::TaintedWritePolicy::Deny) => {
                        self.process_table.record_denied(
                            &ctx.agent.name, &ctx.agent.permissions, agent_did, agent_ring,
                        );
                        tracing::info!(
                            agent = %ctx.agent.name,
                            tool = %params.name,
                            label = %check_label,
                            var_refs = ?resolved.referenced_vars,
                            "IFC: tainted write denied"
                        );
                        return CallToolResult::error(format!(
                            "IFC: write tool '{}' denied — data tainted with untrusted content",
                            params.name
                        ));
                    }
                    Some(crate::ifc::TaintedWritePolicy::Approve) => {
                        self.process_table.record_denied(
                            &ctx.agent.name, &ctx.agent.permissions, agent_did, agent_ring,
                        );
                        return CallToolResult::error(format!(
                            "IFC: write tool '{}' requires approval — data tainted with untrusted content",
                            params.name
                        ));
                    }
                    _ => {} // Allow or no policy
                }
            }
        }

        // Record tool call in process table
        self.process_table.record_call(
            &ctx.agent.name, &ctx.agent.permissions, agent_did, agent_ring, &params.name,
        );

        // Run pre-hooks (may modify arguments or block execution)
        let arguments = if self.hooks.has_hooks() {
            match self.hooks.run_pre(&params.name, resolved.arguments, &ctx).await {
                Ok(args) => args,
                Err(reason) => {
                    self.process_table.complete_call(&ctx.agent.name, &params.name);
                    return CallToolResult::error(reason);
                }
            }
        } else {
            resolved.arguments
        };

        let tool_start = std::time::Instant::now();
        let mut result = match self.tools.get(&params.name) {
            Some(tool) => (tool.handler)(arguments.clone(), ctx.clone()).await,
            None => {
                self.process_table.complete_call(&ctx.agent.name, &params.name);
                if let Some(ref bb) = self.blackbox {
                    bb.record(
                        &ctx.agent.name, &ctx.agent.permissions, &ctx.session_id,
                        &params.name, &arguments.to_string(), "Unknown tool",
                        "error", 0, "N/A",
                    );
                }
                return CallToolResult::error(format!("Unknown tool: {}", params.name));
            }
        };
        let tool_duration_us = tool_start.elapsed().as_micros() as u64;

        // IFC: auto-label external read tool outputs as Untrusted,
        // unless the tool's path argument matches a trusted path pattern.
        // Only escalates the integrity dimension — confidentiality is
        // preserved from whatever the tool handler set (Public by default,
        // Sensitive/Secret if the handler knows the content is confidential).
        if crate::ifc::is_external_read_tool(&params.name)
            && result.label.integrity == crate::ifc::Integrity::Trusted
        {
            let path_arg = arguments.get("path").and_then(|v| v.as_str());
            let is_trusted = path_arg.is_some_and(|p| {
                self.trusted_paths
                    .get(&ctx.agent.permissions)
                    .is_some_and(|patterns| crate::ifc::is_trusted_path(p, patterns))
            });
            if !is_trusted {
                result.label.integrity = crate::ifc::Integrity::Untrusted;
            }
        }

        // IFC: absorb tool result label into session taint
        ctx.taint.absorb(result.label);
        // Persist taint to session for cross-request persistence
        self.sessions.update_context_label(&ctx.session_id, result.label);

        // IFC: auto-store result as a labeled variable
        let var_id = crate::ifc::value_store::generate_var_id();
        session_store.store(crate::ifc::value_store::StoredValue {
            id: var_id.clone(),
            content: result.content.clone(),
            label: result.label,
            source_tool: params.name.clone(),
            created_at: std::time::Instant::now(),
            is_error: result.is_error,
        });
        // Append variable metadata to result content
        result.content.push(crate::protocol::Content::text(
            format!("\n---\n_var: {} (label: {})_", var_id, result.label),
        ));

        // Mark call complete in process table
        self.process_table.complete_call(&ctx.agent.name, &params.name);

        // Record in blackbox
        if let Some(ref bb) = self.blackbox {
            let result_text = result.content.iter().map(|c| match c {
                crate::protocol::Content::Text(t) => t.text.as_str(),
            }).collect::<Vec<_>>().join("");
            let result_trunc = if result_text.len() > 4096 {
                let mut end = 4096;
                while end > 0 && !result_text.is_char_boundary(end) {
                    end -= 1;
                }
                &result_text[..end]
            } else {
                &result_text
            };
            bb.record(
                &ctx.agent.name, &ctx.agent.permissions, &ctx.session_id,
                &params.name, &arguments.to_string(),
                result_trunc,
                if result.is_error { "error" } else { "allowed" },
                tool_duration_us,
                &format!("{:?}", result.label),
            );
        }

        // Run post-hooks (includes safety filtering if wired as a hook)
        if self.hooks.has_hooks() {
            return self.hooks.run_post(&params.name, &arguments, result, &ctx).await;
        }

        // Legacy path: apply safety filters directly when no hooks are configured
        if let Some(pipeline) = self.safety_pipelines.get(&ctx.agent.permissions) {
            if pipeline.has_filters() {
                return self.apply_safety_filter(pipeline, result, &ctx, &params.name);
            }
        }

        result
    }

    fn apply_safety_filter(
        &self,
        pipeline: &FilterPipeline,
        mut result: CallToolResult,
        ctx: &CallContext,
        tool_name: &str,
    ) -> CallToolResult {
        let filter_ctx = FilterContext {
            agent_name: &ctx.agent.name,
            operation: tool_name,
            path: None,
        };

        let mut filtered_content = Vec::new();
        let mut has_pii = false;
        for content in result.content.drain(..) {
            match content {
                Content::Text(text) => {
                    // Use the sync path: scan for findings first to detect PII
                    let findings = pipeline.scan_sync(&text.text, &filter_ctx);
                    if findings.iter().any(|f| crate::safety::is_pii_category(&f.category)) {
                        has_pii = true;
                    }
                    match pipeline.process(&text.text, &filter_ctx) {
                        Ok(processed) => {
                            filtered_content.push(Content::text(processed));
                        }
                        Err(reason) => {
                            return CallToolResult::error(reason);
                        }
                    }
                }
            }
        }
        result.content = filtered_content;
        // Elevate IFC label to Pii if PII was detected
        if has_pii && result.label.confidentiality < crate::ifc::Confidentiality::Pii {
            result.label.confidentiality = crate::ifc::Confidentiality::Pii;
        }
        result
    }

    pub fn handle_list_prompts(&self, _agent: &crate::auth::AgentIdentity) -> ListPromptsResult {
        let prompts = self.prompts.values().map(|p| p.definition.clone()).collect();
        ListPromptsResult { prompts }
    }

    pub async fn handle_get_prompt(
        &self,
        params: GetPromptParams,
        _agent: &crate::auth::AgentIdentity,
    ) -> Result<GetPromptResult, String> {
        match self.prompts.get(&params.name) {
            Some(prompt) => Ok((prompt.handler)(params.arguments).await),
            None => Err(format!("Unknown prompt: {}", params.name)),
        }
    }

    pub fn prompt_count(&self) -> usize {
        self.prompts.len()
    }

    pub fn handle_list_resources(&self, _agent: &crate::auth::AgentIdentity) -> ListResourcesResult {
        let resources = self
            .resources
            .values()
            .map(|r| r.definition.clone())
            .collect();
        ListResourcesResult { resources }
    }

    pub async fn handle_read_resource(
        &self,
        params: ReadResourceParams,
        _agent: &crate::auth::AgentIdentity,
    ) -> Result<ReadResourceResult, String> {
        match self.resources.get(&params.uri) {
            Some(resource) => Ok((resource.handler)(params.uri).await),
            None => Err(format!("Unknown resource: {}", params.uri)),
        }
    }

    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    // --- Permission negotiation handlers ---

    /// Handle a permissions/request: register a pending permission request.
    pub fn handle_permission_request(
        &self,
        params: smgglrs_protocol::permissions::PermissionRequestParams,
        session_id: &str,
    ) -> smgglrs_protocol::permissions::PermissionRequestResult {
        let mut pending = self
            .pending_permission_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pending.insert(
            params.id.clone(),
            super::PendingPermissionRequest {
                session_id: session_id.to_string(),
                scope: params.scope,
                duration_secs: params.duration_secs,
            },
        );
        tracing::info!(
            request_id = %params.id,
            session_id = %session_id,
            reason = %params.reason,
            "Permission request registered"
        );
        smgglrs_protocol::permissions::PermissionRequestResult {
            id: params.id,
            status: "pending".to_string(),
        }
    }

    /// Handle a permissions/grant: resolve a pending request and add a dynamic grant.
    pub fn handle_permission_grant(
        &self,
        params: smgglrs_protocol::permissions::PermissionGrantParams,
        agent_name: &str,
    ) -> Result<smgglrs_protocol::permissions::PermissionGrantResult, String> {
        let pending_req = {
            let mut pending = self
                .pending_permission_requests
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            pending
                .remove(&params.request_id)
                .ok_or_else(|| format!("No pending request with id '{}'", params.request_id))?
        };

        let expires_at = pending_req.duration_secs.map(|d| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + d
        });

        self.session_permissions.add_grant(
            &pending_req.session_id,
            params.request_id.clone(),
            pending_req.scope.clone(),
            expires_at,
            agent_name.to_string(),
        );

        tracing::info!(
            request_id = %params.request_id,
            session_id = %pending_req.session_id,
            agent = %agent_name,
            "Permission granted"
        );

        Ok(smgglrs_protocol::permissions::PermissionGrantResult {
            request_id: params.request_id,
            scope: pending_req.scope,
            expires_at,
            granted_by: agent_name.to_string(),
        })
    }

    /// Handle a permissions/deny: remove the pending request.
    pub fn handle_permission_deny(
        &self,
        params: smgglrs_protocol::permissions::PermissionDenyParams,
    ) -> Result<smgglrs_protocol::permissions::PermissionDenyResult, String> {
        let mut pending = self
            .pending_permission_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if pending.remove(&params.request_id).is_none() {
            return Err(format!(
                "No pending request with id '{}'",
                params.request_id
            ));
        }

        tracing::info!(
            request_id = %params.request_id,
            reason = params.reason.as_deref().unwrap_or("(none)"),
            "Permission denied"
        );

        Ok(smgglrs_protocol::permissions::PermissionDenyResult {
            request_id: params.request_id,
        })
    }

    /// Handle a permissions/list: return active grants for the session.
    pub fn handle_permission_list(
        &self,
        session_id: &str,
    ) -> smgglrs_protocol::permissions::PermissionListResult {
        let grants = self.session_permissions.list(session_id);
        smgglrs_protocol::permissions::PermissionListResult { grants }
    }

    /// Get the session permission store (for checking dynamic grants in tool dispatch).
    pub fn session_permission_store(&self) -> &crate::permissions::SessionPermissionStore {
        &self.session_permissions
    }

    pub fn sessions(&self) -> &crate::session::SessionStore {
        &self.sessions
    }

    pub fn authenticator(&self) -> &dyn crate::auth::Authenticator {
        self.authenticator.as_ref()
    }

    pub fn task_store(&self) -> &crate::a2a::TaskStore {
        &self.task_store
    }

    pub fn process_table(&self) -> &crate::process::ProcessTable {
        &self.process_table
    }

    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Returns the shared pause flag. Use this to wire pause/resume
    /// from external sources (e.g., system tray).
    pub fn pause_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.paused.clone()
    }

    /// Pause the server — tool calls will be rejected until resumed.
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    /// Resume the server — tool calls will be accepted again.
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    /// Returns true if the server is currently paused.
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Get the per-session value store map (for IFC variable tracking).
    pub fn value_stores(&self) -> &crate::ifc::value_store::ValueStoreMap {
        &self.value_stores
    }
}
