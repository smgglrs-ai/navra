use crate::auth::CallContext;
use crate::protocol::{
    CallToolParams, CallToolResult, Content, GetPromptParams, GetPromptResult, InitializeParams,
    InitializeResult, ListPromptsResult, ListResourcesResult, ListToolsResult, PaginatedRequest,
    ReadResourceParams, ReadResourceResult, ToolDefinition,
};
use crate::safety::{FilterContext, FilterPipeline};
use crate::session::Session;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::McpServer;

/// Dynamic tool filter applied during `tools/list`.
///
/// Filters run after static disclosure rules and can hide tools
/// based on runtime state (e.g., session taint, quota, time-of-day).
pub trait ToolFilter: Send + Sync {
    fn filter(&self, tools: Vec<ToolDefinition>, ctx: &CallContext) -> Vec<ToolDefinition>;
}

/// IFC-aware tool filter that hides write tools when the session is tainted.
///
/// Prevents agents from even discovering write capabilities once their
/// context has been contaminated with untrusted data.
pub struct IFCToolFilter;

impl ToolFilter for IFCToolFilter {
    fn filter(&self, tools: Vec<ToolDefinition>, ctx: &CallContext) -> Vec<ToolDefinition> {
        if ctx.taint.level().integrity == crate::ifc::Integrity::Untrusted {
            tools
                .into_iter()
                .filter(|t| !crate::ifc::is_write_tool(&t.name, t.annotations.as_ref()))
                .collect()
        } else {
            tools
        }
    }
}

/// Usage-based tool pruning filter.
///
/// Tracks which tools each agent has called across sessions.
/// After an agent has enough history, tools it never uses are
/// hidden from `tools/list` to reduce context window consumption.
pub struct UsagePruningFilter {
    tracker: Arc<ToolUsageTracker>,
}

impl UsagePruningFilter {
    pub fn new(tracker: Arc<ToolUsageTracker>) -> Self {
        Self { tracker }
    }
}

impl ToolFilter for UsagePruningFilter {
    fn filter(&self, tools: Vec<ToolDefinition>, ctx: &CallContext) -> Vec<ToolDefinition> {
        if !self.tracker.has_enough_history(&ctx.agent.name) {
            return tools;
        }
        let all_names: Vec<String> = tools.iter().map(|t| t.name.clone()).collect();
        let unused = self.tracker.unused_tools_from(&ctx.agent.name, &all_names);
        if unused.is_empty() {
            return tools;
        }
        tools
            .into_iter()
            .filter(|t| !unused.contains(&t.name))
            .collect()
    }
}

/// Tracks tool usage history per agent across sessions.
///
/// When a session ends, its tool set is pushed into a sliding window.
/// Tools not used in any of the last N sessions are considered unused.
pub struct ToolUsageTracker {
    history: std::sync::Mutex<std::collections::HashMap<String, AgentToolHistory>>,
    window_size: u32,
}

struct AgentToolHistory {
    sessions: std::collections::VecDeque<std::collections::HashSet<String>>,
}

impl ToolUsageTracker {
    pub fn new(window_size: u32) -> Self {
        Self {
            history: std::sync::Mutex::new(std::collections::HashMap::new()),
            window_size,
        }
    }

    pub fn record_session_end(
        &self,
        agent_name: &str,
        tools_used: std::collections::HashSet<String>,
    ) {
        let mut history = self.history.lock().unwrap();
        let entry = history
            .entry(agent_name.to_string())
            .or_insert_with(|| AgentToolHistory {
                sessions: std::collections::VecDeque::new(),
            });
        entry.sessions.push_back(tools_used);
        while entry.sessions.len() > self.window_size as usize {
            entry.sessions.pop_front();
        }
    }

    pub fn unused_tools(&self, agent_name: &str) -> std::collections::HashSet<String> {
        // Empty set = no pruning (new agent or not enough history)
        std::collections::HashSet::new()
    }

    pub fn unused_tools_from(
        &self,
        agent_name: &str,
        all_tool_names: &[String],
    ) -> std::collections::HashSet<String> {
        let history = self.history.lock().unwrap();
        let Some(entry) = history.get(agent_name) else {
            return std::collections::HashSet::new();
        };
        if (entry.sessions.len() as u32) < self.window_size {
            return std::collections::HashSet::new();
        }

        let mut ever_used: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for session in &entry.sessions {
            for tool in session {
                ever_used.insert(tool.as_str());
            }
        }

        all_tool_names
            .iter()
            .filter(|name| !ever_used.contains(name.as_str()))
            .cloned()
            .collect()
    }

    pub fn has_enough_history(&self, agent_name: &str) -> bool {
        let history = self.history.lock().unwrap();
        history
            .get(agent_name)
            .is_some_and(|e| e.sessions.len() as u32 >= self.window_size)
    }
}

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
                    subscribe: true,
                    list_changed: false,
                })
            },
            prompts: if self.prompts.is_empty() {
                None
            } else {
                Some(crate::protocol::PromptsCapability {
                    list_changed: false,
                })
            },
            permissions: Some(navra_protocol::permissions::PermissionsCapability {}),
        }
    }

    /// Handle an initialize request. Returns the result and the session ID.
    ///
    /// Validates parameters before creating a session to prevent resource
    /// exhaustion from malformed requests.
    pub fn handle_initialize(
        &self,
        params: InitializeParams,
        agent_identity: crate::auth::AgentIdentity,
    ) -> Result<(InitializeResult, String), String> {
        // Validate protocol version before allocating any resources
        if params.protocol_version.is_empty() {
            return Err("Missing protocol_version".to_string());
        }

        // Validate client info
        if params.client_info.name.is_empty() {
            return Err("Missing client_info.name".to_string());
        }

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
        self.metrics
            .sessions_created
            .fetch_add(1, Ordering::Relaxed);

        let result = InitializeResult {
            protocol_version: self.mcp_version.clone(),
            capabilities: self.capabilities(),
            server_info: self.server_info(),
            instructions: None,
        };
        Ok((result, session_id))
    }

    pub fn handle_list_tools(
        &self,
        agent: &crate::auth::AgentIdentity,
        pagination: &PaginatedRequest,
    ) -> ListToolsResult {
        let all_tools: Vec<_> = self.tools.values().map(|t| t.definition.clone()).collect();
        let visible = if let Some(disclosure) = self.tool_disclosure.get(&agent.permissions) {
            disclosure.filter(&all_tools)
        } else {
            all_tools
        };
        let offset = pagination.decode_offset().unwrap_or(0);
        let (tools, next_cursor) =
            crate::protocol::paginate(&visible, offset, crate::protocol::DEFAULT_PAGE_SIZE);
        ListToolsResult { tools, next_cursor }
    }

    /// List tools with dynamic filtering based on runtime context.
    ///
    /// Applies static disclosure rules first, then runs all registered
    /// `ToolFilter` implementations against the filtered list.
    pub fn handle_list_tools_dynamic(
        &self,
        agent: &crate::auth::AgentIdentity,
        pagination: &PaginatedRequest,
        ctx: &CallContext,
    ) -> ListToolsResult {
        let all_tools: Vec<_> = self.tools.values().map(|t| t.definition.clone()).collect();
        let mut visible = if let Some(disclosure) = self.tool_disclosure.get(&agent.permissions) {
            disclosure.filter(&all_tools)
        } else {
            all_tools
        };
        // Apply dynamic filters
        for filter in &self.dynamic_filters {
            visible = filter.filter(visible, ctx);
        }
        let offset = pagination.decode_offset().unwrap_or(0);
        let (tools, next_cursor) =
            crate::protocol::paginate(&visible, offset, crate::protocol::DEFAULT_PAGE_SIZE);
        ListToolsResult { tools, next_cursor }
    }

    pub async fn handle_call_tool(
        &self,
        params: CallToolParams,
        mut ctx: CallContext,
    ) -> CallToolResult {
        self.metrics
            .tool_calls_total
            .fetch_add(1, Ordering::Relaxed);

        // Wire sandbox profile from capability token into CallContext
        if ctx.sandbox.is_none() {
            if let Some(ref caps) = ctx.agent.capabilities {
                if let Some(ref sandbox) = caps.sandbox {
                    ctx.sandbox = Some(sandbox.clone());
                }
            }
        }

        // Reject all tool calls when paused
        if self.paused.load(Ordering::Relaxed) {
            return CallToolResult::error(
                "Server is paused. Resume from the system tray to continue.".to_string(),
            );
        }

        // Rate limit check (kernel-enforced)
        if self.quota_engine.has_limits()
            && !self
                .quota_engine
                .check(&ctx.agent.name, &ctx.agent.permissions)
        {
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
                    &ctx.agent.name,
                    &ctx.agent.permissions,
                    agent_did,
                    agent_ring,
                );
                self.metrics
                    .tool_calls_denied
                    .fetch_add(1, Ordering::Relaxed);
                return CallToolResult::error(format!(
                    "Permission denied: tool '{}' not in capability token grants",
                    params.name
                ));
            }
        } else if let Some(tp) = self.tool_permissions.get(&ctx.agent.permissions) {
            match tp.check(&params.name) {
                crate::permissions::tool_rules::ToolPolicy::Deny => {
                    // Check if a dynamic session grant overrides the denial
                    if !self
                        .session_permissions
                        .check_tool(&ctx.session_id, &params.name)
                    {
                        self.process_table.record_denied(
                            &ctx.agent.name,
                            &ctx.agent.permissions,
                            agent_did,
                            agent_ring,
                        );
                        return CallToolResult::error(format!(
                            "Permission denied: tool '{}' is blocked",
                            params.name,
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
                    if !self
                        .session_permissions
                        .check_tool(&ctx.session_id, &params.name)
                    {
                        self.process_table.record_denied(
                            &ctx.agent.name,
                            &ctx.agent.permissions,
                            agent_did,
                            agent_ring,
                        );
                        tracing::warn!(
                            tool = %params.name,
                            permission_set = %ctx.agent.permissions,
                            "Tool requires approval"
                        );
                        return CallToolResult::error(format!(
                            "Approval required: '{}'", params.name
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

        // Operations-based enforcement for upstream tools.
        // If a tool is classified as "write" and the agent's permission
        // set only allows "read", block it.
        if let Some(ops) = self.agent_operations.get(&ctx.agent.permissions) {
            if let Some(tool_op) = self.tool_operations.get(&params.name) {
                match tool_op {
                    navra_mcp::ToolOperation::Write if !ops.contains("write") => {
                        self.process_table.record_denied(
                            &ctx.agent.name,
                            &ctx.agent.permissions,
                            agent_did,
                            agent_ring,
                        );
                        tracing::warn!(
                            tool = %params.name,
                            permission_set = %ctx.agent.permissions,
                            "Write operation denied by permission set"
                        );
                        return CallToolResult::error(format!(
                            "Permission denied: '{}'", params.name
                        ));
                    }
                    navra_mcp::ToolOperation::Deny => {
                        return CallToolResult::error(format!(
                            "Permission denied: '{}'", params.name
                        ));
                    }
                    _ => {}
                }
            }
        }

        // Domain-based enforcement (semantic classification gate).
        // If domain_rules are configured for this permission set, check
        // the tool's classified domain:operation against allowed pairs.
        if let Some(rules) = self.domain_rules.get(&ctx.agent.permissions) {
            if let Some(class) = self.tool_classifications.get(&params.name) {
                if rules.check(class) == crate::permissions::DomainPolicy::Deny {
                    self.process_table.record_denied(
                        &ctx.agent.name,
                        &ctx.agent.permissions,
                        agent_did,
                        agent_ring,
                    );
                    self.metrics
                        .tool_calls_denied
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        tool = %params.name,
                        classification = %class,
                        permission_set = %ctx.agent.permissions,
                        "Domain classification denied"
                    );
                    return CallToolResult::error(format!(
                        "Permission denied: '{}'", params.name
                    ));
                }
            }
        }

        // Cedar policy check (second gate — can only further restrict)
        #[cfg(feature = "cedar")]
        if let Some(ref cedar) = self.cedar_engine {
            let context = std::collections::HashMap::from([
                ("permission_set".to_string(), ctx.agent.permissions.clone()),
                ("session_id".to_string(), ctx.session_id.clone()),
            ]);
            let resource = params
                .arguments
                .get("path")
                .or_else(|| params.arguments.get("repo"))
                .or_else(|| params.arguments.get("uri"))
                .and_then(|v| v.as_str())
                .unwrap_or("_default");
            match cedar.is_authorized(&ctx.agent.name, &params.name, resource, &context) {
                crate::permissions::CedarDecision::Allow => {}
                crate::permissions::CedarDecision::Deny(reason) => {
                    self.process_table.record_denied(
                        &ctx.agent.name,
                        &ctx.agent.permissions,
                        agent_did,
                        agent_ring,
                    );
                    self.metrics.cedar_denials.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        tool = %params.name,
                        cedar_reason = %reason,
                        "Cedar policy denied"
                    );
                    return CallToolResult::error(format!(
                        "Permission denied: '{}'", params.name
                    ));
                }
            }
        }

        // Gateway-level path ACL check: extract path from tool arguments
        // and validate against the agent's allow/deny patterns. This ensures
        // upstream MCP tools respect navra's path ACLs.
        if let Some(path_str) = params
            .arguments
            .get("path")
            .or_else(|| params.arguments.get("file_path"))
            .and_then(|v| v.as_str())
        {
            if let Some(acl) = self.path_acls.get(&ctx.agent.permissions) {
                let path = std::path::Path::new(path_str);
                let tool_op = if crate::ifc::is_write_tool(
                    &params.name,
                    self.tools
                        .get(&params.name)
                        .and_then(|t| t.definition.annotations.as_ref()),
                ) {
                    "write"
                } else {
                    "read"
                };
                match navra_auth::permissions::PermissionEngine::check_acl(acl, tool_op, path) {
                    navra_auth::permissions::PermissionResult::Allowed => {}
                    result => {
                        self.process_table.record_denied(
                            &ctx.agent.name,
                            &ctx.agent.permissions,
                            agent_did,
                            agent_ring,
                        );
                        self.metrics
                            .tool_calls_denied
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::info!(
                            tool = %params.name,
                            path = %path_str,
                            result = ?result,
                            "Path ACL denied at gateway"
                        );
                        return CallToolResult::error(format!(
                            "Access denied: path '{}' blocked by ACL policy",
                            path_str
                        ));
                    }
                }
            }
        }

        // IFC: resolve variable references in arguments
        let session_store = self.value_stores.get_or_create(&ctx.session_id);
        let resolved =
            match crate::ifc::value_store::resolve_variable_refs(&params.arguments, &session_store)
            {
                Ok(r) => r,
                Err(msg) => {
                    self.process_table.record_denied(
                        &ctx.agent.name,
                        &ctx.agent.permissions,
                        agent_did,
                        agent_ring,
                    );
                    self.metrics
                        .tool_calls_denied
                        .fetch_add(1, Ordering::Relaxed);
                    return CallToolResult::error(msg);
                }
            };

        // IFC pre-check: per-value write blocking (Bell-LaPadula no-write-down).
        let tool_annotations = self
            .tools
            .get(&params.name)
            .and_then(|t| t.definition.annotations.as_ref());
        if crate::ifc::is_write_tool(&params.name, tool_annotations) {
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
                            &ctx.agent.name,
                            &ctx.agent.permissions,
                            agent_did,
                            agent_ring,
                        );
                        tracing::info!(
                            agent = %ctx.agent.name,
                            tool = %params.name,
                            label = %check_label,
                            var_refs = ?resolved.referenced_vars,
                            "IFC: tainted write denied"
                        );
                        return CallToolResult::error(format!(
                            "Permission denied: '{}'", params.name
                        ));
                    }
                    Some(crate::ifc::TaintedWritePolicy::Approve) => {
                        self.process_table.record_denied(
                            &ctx.agent.name,
                            &ctx.agent.permissions,
                            agent_did,
                            agent_ring,
                        );
                        return CallToolResult::error(format!(
                            "Approval required: '{}'", params.name
                        ));
                    }
                    Some(crate::ifc::TaintedWritePolicy::Allow) => {} // Explicitly allowed
                    None => {
                        // Missing policy defaults to Deny (fail-closed)
                        self.process_table.record_denied(
                            &ctx.agent.name,
                            &ctx.agent.permissions,
                            agent_did,
                            agent_ring,
                        );
                        tracing::warn!(
                            agent = %ctx.agent.name,
                            permissions = %ctx.agent.permissions,
                            tool = %params.name,
                            "IFC: no policy configured, defaulting to deny"
                        );
                        return CallToolResult::error(format!(
                            "Permission denied: '{}'", params.name
                        ));
                    }
                }
            }
        }

        // Record tool call in process table
        self.process_table.record_call(
            &ctx.agent.name,
            &ctx.agent.permissions,
            agent_did,
            agent_ring,
            &params.name,
        );

        tracing::info!(
            tool.name = %params.name,
            agent.name = %ctx.agent.name,
            session.id = %ctx.session_id,
            "tool_call.start"
        );

        // Run pre-hooks (may modify arguments, simulate, or block execution)
        let arguments = if self.hooks.has_hooks() {
            match self
                .hooks
                .run_pre(&params.name, resolved.arguments, &ctx)
                .await
            {
                crate::hooks::PreHookOutcome::Proceed(args) => args,
                crate::hooks::PreHookOutcome::Simulated(result) => {
                    self.process_table
                        .complete_call(&ctx.agent.name, &params.name);
                    return result;
                }
                crate::hooks::PreHookOutcome::Blocked(reason) => {
                    self.process_table
                        .complete_call(&ctx.agent.name, &params.name);
                    tracing::warn!(
                        tool = %params.name,
                        reason = %reason,
                        "Tool blocked by pre-hook"
                    );
                    return CallToolResult::error(format!(
                        "Permission denied: '{}'", params.name
                    ));
                }
                crate::hooks::PreHookOutcome::Pending { request_id, reason } => {
                    tracing::info!(
                        tool = %params.name,
                        request_id = %request_id,
                        reason = %reason,
                        "Tool pending approval"
                    );
                    return CallToolResult::error(format!(
                        "Approval required: '{}' (request: {})", params.name, request_id
                    ));
                }
            }
        } else {
            resolved.arguments
        };

        let tool_start = std::time::Instant::now();
        let mut result = match self.tools.get(&params.name) {
            Some(tool) => (tool.handler)(arguments.clone(), ctx.clone()).await,
            None => {
                self.process_table
                    .complete_call(&ctx.agent.name, &params.name);
                if let Some(ref bb) = self.blackbox {
                    bb.record(
                        &ctx.agent.name,
                        &ctx.agent.permissions,
                        &ctx.session_id,
                        &params.name,
                        &arguments.to_string(),
                        "Unknown tool",
                        "error",
                        0,
                        "N/A",
                    );
                }
                return CallToolResult::error(format!("Unknown tool: {}", params.name));
            }
        };
        let tool_duration_us = tool_start.elapsed().as_micros() as u64;
        self.metrics
            .tool_duration_us_sum
            .fetch_add(tool_duration_us, Ordering::Relaxed);
        if result.is_error {
            self.metrics
                .tool_calls_errors
                .fetch_add(1, Ordering::Relaxed);
        }
        tracing::info!(
            tool.name = %params.name,
            agent.name = %ctx.agent.name,
            duration_us = tool_duration_us,
            is_error = result.is_error,
            "tool_call.complete"
        );

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
                self.metrics
                    .ifc_taint_elevations
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        // IFC: Simple Security Property (no-read-up).
        // If the result's confidentiality exceeds the agent's clearance,
        // block the result based on the read clearance policy.
        if crate::ifc::is_external_read_tool(&params.name) {
            if let Some(clearance) = self.ifc_read_clearances.get(&ctx.agent.permissions) {
                if !crate::ifc::DataLabel::can_read_from(
                    clearance.level,
                    result.label.confidentiality,
                ) {
                    match clearance.policy {
                        crate::ifc::TaintedWritePolicy::Deny => {
                            if let Some(bb) = &self.blackbox {
                                bb.record(
                                    &ctx.agent.name, &ctx.agent.permissions, &ctx.session_id,
                                    &params.name, &arguments.to_string(),
                                    &format!("[BLOCKED: no-read-up, classification {:?} > clearance {:?}]",
                                        result.label.confidentiality, clearance.level),
                                    "denied_ifc", tool_duration_us,
                                    &result.label.to_string(),
                                );
                            }
                            tracing::warn!(
                                tool = %params.name,
                                classification = ?result.label.confidentiality,
                                clearance = ?clearance.level,
                                "IFC: read blocked — classification exceeds clearance"
                            );
                            return CallToolResult::error(format!(
                                "Access denied: insufficient clearance for '{}'", params.name
                            ));
                        }
                        crate::ifc::TaintedWritePolicy::Approve => {
                            tracing::warn!(
                                tool = %params.name, agent = %ctx.agent.name,
                                classification = ?result.label.confidentiality,
                                clearance = ?clearance.level,
                                "IFC: read exceeds clearance, approval would be required"
                            );
                        }
                        crate::ifc::TaintedWritePolicy::Allow => {}
                    }
                }
            }
        }

        // IFC: absorb tool result label into session taint
        ctx.taint.absorb(result.label);
        // Persist taint to session for cross-request persistence
        self.sessions
            .update_context_label(&ctx.session_id, result.label);

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
        // Append variable ID (but not the IFC label — exposing
        // classification to agents leaks security metadata).
        result.content.push(crate::protocol::Content::text(format!(
            "\n---\n_var: {}_",
            var_id
        )));

        // Mark call complete in process table
        self.process_table
            .complete_call(&ctx.agent.name, &params.name);

        // Record in blackbox
        if let Some(ref bb) = self.blackbox {
            let result_text = result
                .content
                .iter()
                .filter_map(|c| match c {
                    crate::protocol::Content::Text(t) => Some(t.text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("");
            let result_trunc = crate::blackbox::truncate(&result_text, 4096);
            bb.record(
                &ctx.agent.name,
                &ctx.agent.permissions,
                &ctx.session_id,
                &params.name,
                &arguments.to_string(),
                result_trunc,
                if result.is_error { "error" } else { "allowed" },
                tool_duration_us,
                &format!("{:?}", result.label),
            );
        }

        // Run post-hooks (includes safety filtering if wired as a hook)
        if self.hooks.has_hooks() {
            return self
                .hooks
                .run_post(&params.name, &arguments, result, &ctx)
                .await;
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
                    if findings
                        .iter()
                        .any(|f| crate::safety::is_pii_category(&f.category))
                    {
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
                Content::Resource(ref res) => {
                    if res.resource.mime_type.as_deref().is_some_and(|m| m.starts_with("text/")) {
                        if let Some(ref text) = res.resource.text {
                            match pipeline.process(text, &filter_ctx) {
                                Ok(processed) => {
                                    filtered_content.push(Content::text(processed));
                                }
                                Err(reason) => {
                                    return CallToolResult::error(reason);
                                }
                            }
                        } else {
                            filtered_content.push(content);
                        }
                    } else {
                        tracing::warn!(
                            tool = tool_name,
                            agent = ctx.agent.name,
                            "Non-text resource blocked by safety pipeline"
                        );
                        return CallToolResult::error(
                            "Non-text resource content blocked by safety pipeline"
                        );
                    }
                }
                _binary => {
                    tracing::warn!(
                        tool = tool_name,
                        agent = ctx.agent.name,
                        "Non-text content (image/audio) blocked by safety pipeline"
                    );
                    return CallToolResult::error(
                        "Non-text content blocked by safety pipeline (no binary filter configured)"
                    );
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

    pub fn handle_list_prompts(
        &self,
        agent: &crate::auth::AgentIdentity,
        pagination: &PaginatedRequest,
    ) -> ListPromptsResult {
        let all_prompts: Vec<_> = self
            .prompts
            .values()
            .map(|p| p.definition.clone())
            .collect();

        // Filter prompts by domain rules (if configured).
        let visible = if let Some(rules) = self.domain_rules.get(&agent.permissions) {
            let class = crate::permissions::resource_class::classify_prompt();
            if rules.check(&class) == crate::permissions::DomainPolicy::Deny {
                Vec::new()
            } else {
                all_prompts
            }
        } else {
            all_prompts
        };

        let offset = pagination.decode_offset().unwrap_or(0);
        let (prompts, next_cursor) =
            crate::protocol::paginate(&visible, offset, crate::protocol::DEFAULT_PAGE_SIZE);
        ListPromptsResult {
            prompts,
            next_cursor,
        }
    }

    pub async fn handle_get_prompt(
        &self,
        params: GetPromptParams,
        agent: &crate::auth::AgentIdentity,
        session_id: &str,
    ) -> Result<GetPromptResult, String> {
        // Domain-based permission check for prompts.
        if let Some(rules) = self.domain_rules.get(&agent.permissions) {
            let class = crate::permissions::resource_class::classify_prompt();
            if rules.check(&class) == crate::permissions::DomainPolicy::Deny {
                return Err(format!(
                    "Permission denied: prompt '{}' blocked by domain rules for '{}'",
                    params.name, agent.permissions
                ));
            }
        }

        match self.prompts.get(&params.name) {
            Some(prompt) => {
                let ctx = CallContext::new(agent.clone(), session_id);
                Ok((prompt.handler)(params.arguments, ctx).await)
            }
            None => Err(format!("Unknown prompt: {}", params.name)),
        }
    }

    pub fn prompt_count(&self) -> usize {
        self.prompts.len()
    }

    pub fn handle_list_resources(
        &self,
        agent: &crate::auth::AgentIdentity,
        pagination: &PaginatedRequest,
    ) -> ListResourcesResult {
        let all_resources: Vec<_> = self
            .resources
            .values()
            .map(|r| r.definition.clone())
            .collect();
        let visible = self.filter_resources_for_agent(agent, all_resources);
        let offset = pagination.decode_offset().unwrap_or(0);
        let (resources, next_cursor) =
            crate::protocol::paginate(&visible, offset, crate::protocol::DEFAULT_PAGE_SIZE);
        ListResourcesResult {
            resources,
            next_cursor,
        }
    }

    pub async fn handle_read_resource(
        &self,
        params: ReadResourceParams,
        agent: &crate::auth::AgentIdentity,
        session_id: &str,
    ) -> Result<ReadResourceResult, String> {
        let ctx = CallContext::new(agent.clone(), session_id);
        if let Some(resource) = self.resources.get(&params.uri) {
            if !self.agent_can_see_resource(agent, &resource.definition.uri) {
                return Err("Permission denied".to_string());
            }
            return Ok((resource.handler)(params.uri, ctx).await);
        }
        for rt in &self.resource_templates {
            if matches_uri_template(&rt.template.uri_template, &params.uri) {
                if !self.agent_can_see_resource(agent, &rt.template.uri_template) {
                    return Err("Permission denied".to_string());
                }
                return Ok((rt.handler)(params.uri, ctx).await);
            }
        }
        Err(format!("Unknown resource: {}", params.uri))
    }

    pub fn handle_list_resource_templates(
        &self,
        agent: &crate::auth::AgentIdentity,
        pagination: &PaginatedRequest,
    ) -> crate::protocol::ListResourceTemplatesResult {
        let all_templates: Vec<_> = self
            .resource_templates
            .iter()
            .map(|rt| rt.template.clone())
            .collect();
        let visible = self.filter_resource_templates_for_agent(agent, all_templates);
        let offset = pagination.decode_offset().unwrap_or(0);
        let (resource_templates, next_cursor) =
            crate::protocol::paginate(&visible, offset, crate::protocol::DEFAULT_PAGE_SIZE);
        crate::protocol::ListResourceTemplatesResult {
            resource_templates,
            next_cursor,
        }
    }

    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    // --- Permission negotiation handlers ---

    /// Handle a permissions/request: register a pending permission request.
    pub fn handle_permission_request(
        &self,
        params: navra_protocol::permissions::PermissionRequestParams,
        session_id: &str,
        agent_name: &str,
    ) -> navra_protocol::permissions::PermissionRequestResult {
        let mut pending = self.pending_permission_requests.lock().unwrap_or_else(|e| {
            tracing::warn!("pending_permission_requests Mutex poisoned, recovering");
            e.into_inner()
        });
        pending.insert(
            params.id.clone(),
            super::PendingPermissionRequest {
                session_id: session_id.to_string(),
                agent_name: agent_name.to_string(),
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
        navra_protocol::permissions::PermissionRequestResult {
            id: params.id,
            status: "pending".to_string(),
        }
    }

    /// Handle a permissions/grant: resolve a pending request and add a dynamic grant.
    pub fn handle_permission_grant(
        &self,
        params: navra_protocol::permissions::PermissionGrantParams,
        agent_name: &str,
    ) -> Result<navra_protocol::permissions::PermissionGrantResult, String> {
        let pending_req = {
            let mut pending = self.pending_permission_requests.lock().unwrap_or_else(|e| {
                tracing::warn!("pending_permission_requests Mutex poisoned, recovering");
                e.into_inner()
            });
            pending
                .remove(&params.request_id)
                .ok_or_else(|| format!("No pending request with id '{}'", params.request_id))?
        };

        if pending_req.agent_name == agent_name {
            return Err("Permission denied: agents cannot approve their own requests".to_string());
        }

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

        Ok(navra_protocol::permissions::PermissionGrantResult {
            request_id: params.request_id,
            scope: pending_req.scope,
            expires_at,
            granted_by: agent_name.to_string(),
        })
    }

    /// Handle a permissions/deny: remove the pending request.
    pub fn handle_permission_deny(
        &self,
        params: navra_protocol::permissions::PermissionDenyParams,
    ) -> Result<navra_protocol::permissions::PermissionDenyResult, String> {
        let mut pending = self.pending_permission_requests.lock().unwrap_or_else(|e| {
            tracing::warn!("pending_permission_requests Mutex poisoned, recovering");
            e.into_inner()
        });
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

        Ok(navra_protocol::permissions::PermissionDenyResult {
            request_id: params.request_id,
        })
    }

    /// Handle a permissions/list: return active grants for the session.
    pub fn handle_permission_list(
        &self,
        session_id: &str,
    ) -> navra_protocol::permissions::PermissionListResult {
        let grants = self.session_permissions.list(session_id);
        navra_protocol::permissions::PermissionListResult { grants }
    }

    /// Handle completion/complete: suggest argument values for prompts or resources.
    pub fn handle_complete(
        &self,
        params: crate::protocol::CompleteParams,
    ) -> crate::protocol::CompleteResult {
        let values = match params.ref_type.as_str() {
            "ref/prompt" => {
                let matching: Vec<String> = self
                    .prompts
                    .values()
                    .filter_map(|p| {
                        p.definition
                            .arguments
                            .iter()
                            .find(|a| a.name == params.argument.name)
                            .map(|_| p.definition.name.clone())
                    })
                    .filter(|name| {
                        params.argument.value.is_empty() || name.starts_with(&params.argument.value)
                    })
                    .collect();
                if matching.is_empty() {
                    self.prompts
                        .values()
                        .flat_map(|p| p.definition.arguments.iter())
                        .filter(|a| a.name == params.argument.name)
                        .filter_map(|a| a.description.clone())
                        .collect()
                } else {
                    matching
                }
            }
            "ref/resource" => self
                .resources
                .keys()
                .filter(|uri| {
                    params.argument.value.is_empty() || uri.starts_with(&params.argument.value)
                })
                .cloned()
                .take(100)
                .collect(),
            _ => Vec::new(),
        };
        let total = values.len() as u32;
        let has_more = total > 100;
        let values: Vec<String> = values.into_iter().take(100).collect();
        crate::protocol::CompleteResult {
            values,
            total: Some(total),
            has_more: Some(has_more),
        }
    }

    /// Handle logging/setLevel: set the minimum log level for a session.
    pub fn handle_set_log_level(&self, params: crate::protocol::SetLevelParams, session_id: &str) {
        let mut levels = self.session_log_levels.write().unwrap_or_else(|e| {
            tracing::warn!("session_log_levels RwLock poisoned, recovering");
            e.into_inner()
        });
        tracing::info!(
            session_id = %session_id,
            level = ?params.level,
            "Client set log level"
        );
        levels.insert(session_id.to_string(), params.level);
    }

    /// Handle resources/subscribe: register a session's interest in a resource URI.
    pub fn handle_resource_subscribe(&self, uri: &str, session_id: &str) -> Result<(), String> {
        if !self.resources.contains_key(uri) {
            return Err(format!("Unknown resource: {}", uri));
        }
        let mut subs = self.resource_subscriptions.write().unwrap_or_else(|e| {
            tracing::warn!("resource_subscriptions RwLock poisoned, recovering");
            e.into_inner()
        });
        subs.entry(session_id.to_string())
            .or_default()
            .insert(uri.to_string());
        tracing::info!(session_id = %session_id, uri = %uri, "Resource subscription added");
        Ok(())
    }

    /// Handle resources/unsubscribe: remove a session's subscription to a resource URI.
    pub fn handle_resource_unsubscribe(&self, uri: &str, session_id: &str) -> Result<(), String> {
        let mut subs = self.resource_subscriptions.write().unwrap_or_else(|e| {
            tracing::warn!("resource_subscriptions RwLock poisoned, recovering");
            e.into_inner()
        });
        if let Some(uris) = subs.get_mut(session_id) {
            if !uris.remove(uri) {
                return Err(format!("Not subscribed to: {}", uri));
            }
            if uris.is_empty() {
                subs.remove(session_id);
            }
            tracing::info!(session_id = %session_id, uri = %uri, "Resource subscription removed");
            Ok(())
        } else {
            Err(format!("No subscriptions for session: {}", session_id))
        }
    }

    /// Notify all sessions subscribed to a resource that it has been updated.
    pub fn notify_resource_updated(&self, uri: &str) {
        let subs = self.resource_subscriptions.read().unwrap_or_else(|e| {
            tracing::warn!("resource_subscriptions RwLock poisoned, recovering");
            e.into_inner()
        });
        for (session_id, uris) in subs.iter() {
            if uris.contains(uri) {
                self.notify_session(
                    session_id,
                    crate::protocol::NOTIFY_RESOURCES_UPDATED,
                    Some(serde_json::json!({ "uri": uri })),
                );
            }
        }
    }

    /// Send a log message notification to sessions with appropriate log level.
    pub fn send_log_message(
        &self,
        level: crate::protocol::LoggingLevel,
        logger: Option<&str>,
        data: serde_json::Value,
    ) {
        let levels = self.session_log_levels.read().unwrap_or_else(|e| {
            tracing::warn!("session_log_levels RwLock poisoned, recovering");
            e.into_inner()
        });
        let params = serde_json::json!({
            "level": level,
            "logger": logger,
            "data": data,
        });
        if levels.is_empty() {
            self.notify("notifications/message", Some(params));
        } else {
            for (session_id, min_level) in levels.iter() {
                if level.severity() >= min_level.severity() {
                    self.notify_session(session_id, "notifications/message", Some(params.clone()));
                }
            }
        }
    }

    /// Get the session permission store (for checking dynamic grants in tool dispatch).
    pub fn session_permission_store(&self) -> &crate::permissions::SessionPermissionStore {
        &self.session_permissions
    }

    pub fn sessions(&self) -> &crate::session::SessionStore {
        &self.sessions
    }

    pub fn mcp_version(&self) -> &str {
        &self.mcp_version
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

    pub fn blackbox(&self) -> Option<&crate::blackbox::Blackbox> {
        self.blackbox.as_deref()
    }

    pub fn safety_pipeline(
        &self,
        permission_set: &str,
    ) -> Option<&navra_safety_hooks::safety::FilterPipeline> {
        self.safety_pipelines.get(permission_set)
    }

    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Returns sorted list of registered tool names.
    pub fn tool_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.tools.keys().cloned().collect();
        names.sort();
        names
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

    fn filter_resources_for_agent(
        &self,
        agent: &crate::auth::AgentIdentity,
        resources: Vec<crate::protocol::ResourceDefinition>,
    ) -> Vec<crate::protocol::ResourceDefinition> {
        resources
            .into_iter()
            .filter(|r| self.agent_can_see_resource(agent, &r.uri))
            .collect()
    }

    fn filter_resource_templates_for_agent(
        &self,
        agent: &crate::auth::AgentIdentity,
        templates: Vec<crate::protocol::ResourceTemplate>,
    ) -> Vec<crate::protocol::ResourceTemplate> {
        templates
            .into_iter()
            .filter(|t| self.agent_can_see_resource(agent, &t.uri_template))
            .collect()
    }

    fn agent_can_see_resource(&self, agent: &crate::auth::AgentIdentity, uri: &str) -> bool {
        // Capability token tool globs: if the agent has caps with tool
        // patterns, the resource URI must match at least one.
        if let Some(ref caps) = agent.capabilities {
            if !caps.tools.is_empty() {
                let uri_matches = caps.tools.iter().any(|pattern| {
                    glob::Pattern::new(pattern)
                        .map(|p| p.matches(uri))
                        .unwrap_or(false)
                });
                if !uri_matches {
                    return false;
                }
            }
        }

        // IFC read clearance (Simple Security Property): check agent's
        // read clearance against resource confidentiality.
        if let Some(clearance) = self.ifc_read_clearances.get(&agent.permissions) {
            let resource_level = resource_confidentiality(uri);
            if (resource_level as u8) > (clearance.level as u8) {
                return false;
            }
        }

        true
    }
}

/// Assign a confidentiality level to a resource URI for IFC filtering.
///
/// Kernel resources with sensitive data get higher levels so agents
/// with restricted read clearance don't see them.
fn resource_confidentiality(uri: &str) -> crate::ifc::Confidentiality {
    use crate::ifc::Confidentiality;
    if uri.starts_with("navra://audit") {
        Confidentiality::Sensitive
    } else if uri.starts_with("navra://proc")
        && (uri.contains("/taint") || uri.contains("/capabilities"))
    {
        Confidentiality::Sensitive
    } else {
        Confidentiality::Public
    }
}

/// Match a concrete URI against a URI template (RFC 6570 Level 1).
///
/// Supports simple `{name}` placeholders that match one or more non-`/` characters.
pub(super) fn matches_uri_template(template: &str, uri: &str) -> bool {
    let parts: Vec<&str> = template.split('{').collect();
    if parts.is_empty() {
        return template == uri;
    }
    let mut remaining = uri;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            if !remaining.starts_with(part) {
                return false;
            }
            remaining = &remaining[part.len()..];
        } else {
            let suffix = match part.find('}') {
                Some(end) => &part[end + 1..],
                None => return false,
            };
            if suffix.is_empty() {
                return !remaining.is_empty() && !remaining.contains('/');
            }
            match remaining.find(suffix) {
                Some(pos) => {
                    let value = &remaining[..pos];
                    if value.is_empty() || value.contains('/') {
                        return false;
                    }
                    remaining = &remaining[pos + suffix.len()..];
                }
                None => return false,
            }
        }
    }
    remaining.is_empty()
}
