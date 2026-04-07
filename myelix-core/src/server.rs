use crate::a2a::TaskStore;
use crate::auth::{Authenticator, CallContext};
use crate::hooks::HookPipeline;
use crate::process::ProcessTable;
use crate::quota::QuotaEngine;
use crate::module::{Module, PromptHandler, ResourceHandler};
use crate::permissions::tool_rules::{ToolPermissions, ToolPolicy};
use crate::protocol::a2a::{
    AgentCapabilities, AgentCard, AgentProvider, AgentSkill, A2A_PROTOCOL_VERSION,
};
use crate::protocol::{
    CallToolParams, CallToolResult, Content, GetPromptParams, GetPromptResult, InitializeParams,
    InitializeResult, ListPromptsResult, ListResourcesResult, ListToolsResult, PromptDefinition,
    PromptsCapability, ReadResourceParams, ReadResourceResult, ResourceDefinition,
    ResourcesCapability, ServerCapabilities, ServerInfo, ToolDefinition, ToolsCapability,
};
use crate::safety::{FilterContext, FilterPipeline};
use crate::session::{Session, SessionStore};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Async tool handler function type.
pub type ToolHandler = Arc<
    dyn Fn(serde_json::Value, CallContext) -> Pin<Box<dyn Future<Output = CallToolResult> + Send>>
        + Send
        + Sync,
>;

/// Registered tool: definition + handler.
struct RegisteredTool {
    definition: ToolDefinition,
    handler: ToolHandler,
}

/// Registered prompt: definition + handler.
struct RegisteredPrompt {
    definition: PromptDefinition,
    handler: PromptHandler,
}

/// Registered resource: definition + handler.
struct RegisteredResource {
    definition: ResourceDefinition,
    handler: ResourceHandler,
}

/// The MCP server, holding all state and tool/prompt/resource registrations.
pub struct McpServer {
    pub(crate) name: String,
    pub(crate) version: String,
    tools: HashMap<String, RegisteredTool>,
    prompts: HashMap<String, RegisteredPrompt>,
    resources: HashMap<String, RegisteredResource>,
    pub(crate) sessions: SessionStore,
    pub(crate) authenticator: Arc<dyn Authenticator>,
    /// Safety filter pipelines keyed by permission set name (legacy, used when no hooks).
    safety_pipelines: HashMap<String, FilterPipeline>,
    /// Per-tool permission rules keyed by permission set name.
    tool_permissions: HashMap<String, ToolPermissions>,
    /// Hook pipeline for pre/post tool-call interception.
    hooks: HookPipeline,
    /// Shared pause flag — when true, tool calls are rejected.
    paused: Arc<AtomicBool>,
    /// A2A task store for tracking agent-to-agent tasks.
    task_store: TaskStore,
    /// Process table tracking active agent sessions.
    process_table: ProcessTable,
    /// Quota engine for rate limiting.
    quota_engine: QuotaEngine,
    /// IFC policies per permission set (tainted write handling).
    ifc_policies: HashMap<String, crate::ifc::TaintedWritePolicy>,
    /// Per-value variable store for IFC tracking.
    value_stores: crate::ifc::value_store::ValueStoreMap,
}

impl McpServer {
    pub fn builder() -> McpServerBuilder {
        McpServerBuilder::new()
    }

    pub fn server_info(&self) -> ServerInfo {
        ServerInfo {
            name: self.name.clone(),
            version: Some(self.version.clone()),
        }
    }

    pub fn capabilities(&self) -> ServerCapabilities {
        ServerCapabilities {
            tools: if self.tools.is_empty() {
                None
            } else {
                Some(ToolsCapability { list_changed: true })
            },
            resources: if self.resources.is_empty() {
                None
            } else {
                Some(ResourcesCapability {
                    subscribe: false,
                    list_changed: false,
                })
            },
            prompts: if self.prompts.is_empty() {
                None
            } else {
                Some(PromptsCapability { list_changed: false })
            },
        }
    }

    /// Handle an initialize request. Returns the result and the session ID.
    pub fn handle_initialize(&self, params: InitializeParams, agent_identity: crate::auth::AgentIdentity) -> (InitializeResult, String) {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = Session {
            id: session_id.clone(),
            agent: agent_identity,
            client_info: params.client_info,
            initialized: true,
            context_label: crate::ifc::DataLabel::TRUSTED_PUBLIC,
        };
        self.sessions.create(session);

        let result = InitializeResult {
            protocol_version: crate::protocol::PROTOCOL_VERSION.to_string(),
            capabilities: self.capabilities(),
            server_info: self.server_info(),
        };
        (result, session_id)
    }

    pub fn handle_list_tools(&self) -> ListToolsResult {
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
        if self.quota_engine.has_limits() {
            if !self.quota_engine.check(&ctx.agent.name, &ctx.agent.permissions) {
                return CallToolResult::error(format!(
                    "Rate limit exceeded for agent '{}'",
                    ctx.agent.name
                ));
            }
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
                ToolPolicy::Deny => {
                    self.process_table.record_denied(
                        &ctx.agent.name, &ctx.agent.permissions, agent_did, agent_ring,
                    );
                    return CallToolResult::error(format!(
                        "Permission denied: tool '{}' is blocked for permission set '{}'",
                        params.name, ctx.agent.permissions
                    ));
                }
                ToolPolicy::Approve => {
                    self.process_table.record_denied(
                        &ctx.agent.name, &ctx.agent.permissions, agent_did, agent_ring,
                    );
                    return CallToolResult::error(format!(
                        "Approval required: tool '{}' requires approval for permission set '{}'",
                        params.name, ctx.agent.permissions
                    ));
                }
                ToolPolicy::Allow => {}
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

        let mut result = match self.tools.get(&params.name) {
            Some(tool) => (tool.handler)(arguments.clone(), ctx.clone()).await,
            None => {
                self.process_table.complete_call(&ctx.agent.name, &params.name);
                return CallToolResult::error(format!("Unknown tool: {}", params.name));
            }
        };

        // IFC: auto-label external read tool outputs as Untrusted.
        // Only escalates the integrity dimension — confidentiality is
        // preserved from whatever the tool handler set (Public by default,
        // Sensitive/Secret if the handler knows the content is confidential).
        if crate::ifc::is_external_read_tool(&params.name)
            && result.label.integrity == crate::ifc::Integrity::Trusted
        {
            result.label.integrity = crate::ifc::Integrity::Untrusted;
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
        for content in result.content.drain(..) {
            match content {
                Content::Text(text) => {
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
        result
    }

    pub fn handle_list_prompts(&self) -> ListPromptsResult {
        let prompts = self.prompts.values().map(|p| p.definition.clone()).collect();
        ListPromptsResult { prompts }
    }

    pub async fn handle_get_prompt(
        &self,
        params: GetPromptParams,
    ) -> Result<GetPromptResult, String> {
        match self.prompts.get(&params.name) {
            Some(prompt) => Ok((prompt.handler)(params.arguments).await),
            None => Err(format!("Unknown prompt: {}", params.name)),
        }
    }

    pub fn prompt_count(&self) -> usize {
        self.prompts.len()
    }

    pub fn handle_list_resources(&self) -> ListResourcesResult {
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
    ) -> Result<ReadResourceResult, String> {
        match self.resources.get(&params.uri) {
            Some(resource) => Ok((resource.handler)(params.uri).await),
            None => Err(format!("Unknown resource: {}", params.uri)),
        }
    }

    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    pub fn sessions(&self) -> &SessionStore {
        &self.sessions
    }

    pub fn authenticator(&self) -> &dyn Authenticator {
        self.authenticator.as_ref()
    }

    pub fn task_store(&self) -> &TaskStore {
        &self.task_store
    }

    pub fn process_table(&self) -> &ProcessTable {
        &self.process_table
    }

    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Generate a Server Card: static metadata about this server's
    /// capabilities, tools, prompts, and resources.
    ///
    /// Served at `/.well-known/mcp.json` to enable client
    /// autoconfiguration without a full initialize handshake.
    pub fn server_card(&self) -> serde_json::Value {
        let tools: Vec<_> = self
            .tools
            .values()
            .map(|t| {
                serde_json::json!({
                    "name": t.definition.name,
                    "description": t.definition.description,
                })
            })
            .collect();

        let prompts: Vec<_> = self
            .prompts
            .values()
            .map(|p| {
                serde_json::json!({
                    "name": p.definition.name,
                    "description": p.definition.description,
                    "arguments": p.definition.arguments,
                })
            })
            .collect();

        let resources: Vec<_> = self
            .resources
            .values()
            .map(|r| {
                serde_json::json!({
                    "uri": r.definition.uri,
                    "name": r.definition.name,
                    "description": r.definition.description,
                    "mimeType": r.definition.mime_type,
                })
            })
            .collect();

        serde_json::json!({
            "serverInfo": self.server_info(),
            "capabilities": self.capabilities(),
            "protocolVersion": crate::protocol::PROTOCOL_VERSION,
            "tools": tools,
            "prompts": prompts,
            "resources": resources,
        })
    }

    /// Generate an A2A Agent Card describing this server's capabilities
    /// as skills for agent-to-agent discovery.
    ///
    /// Served at `GET /.well-known/agent.json`. Each registered tool
    /// becomes a skill. Tools sharing a prefix (e.g., `docs_*`) are
    /// tagged by module name.
    pub fn agent_card(&self, endpoint_url: &str, root_did: Option<&str>) -> AgentCard {
        let skills: Vec<AgentSkill> = self
            .tools
            .values()
            .map(|t| {
                let name = &t.definition.name;
                let tag = name.split('_').next().unwrap_or(name).to_string();
                AgentSkill {
                    id: name.clone(),
                    name: name.clone(),
                    description: t.definition.description.clone().unwrap_or_default(),
                    tags: vec![tag],
                    examples: vec![],
                    input_modes: None,
                    output_modes: None,
                }
            })
            .collect();

        let has_voice = self.tools.keys().any(|k| k.starts_with("voice_"));
        let mut input_modes = vec!["text/plain".to_string()];
        let mut output_modes = vec!["text/plain".to_string()];
        if has_voice {
            input_modes.push("audio/wav".to_string());
            output_modes.push("audio/wav".to_string());
        }

        AgentCard {
            name: self.name.clone(),
            description: format!(
                "MCP gateway with {} tools across {} capabilities",
                self.tools.len(),
                self.tools
                    .keys()
                    .map(|k| k.split('_').next().unwrap_or(k))
                    .collect::<std::collections::HashSet<_>>()
                    .len()
            ),
            url: endpoint_url.to_string(),
            version: self.version.clone(),
            provider: Some(AgentProvider {
                organization: "mcpd".to_string(),
                url: endpoint_url.to_string(),
            }),
            did: root_did.map(String::from),
            capabilities: AgentCapabilities {
                streaming: Some(true),
                push_notifications: Some(false),
                state_transition_history: Some(false),
            },
            default_input_modes: input_modes,
            default_output_modes: output_modes,
            skills,
            documentation_url: None,
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        }
    }

    /// Returns the shared pause flag. Use this to wire pause/resume
    /// from external sources (e.g., system tray).
    pub fn pause_flag(&self) -> Arc<AtomicBool> {
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
}

/// Builder for constructing an McpServer.
pub struct McpServerBuilder {
    name: String,
    version: String,
    tools: HashMap<String, RegisteredTool>,
    prompts: HashMap<String, RegisteredPrompt>,
    resources: HashMap<String, RegisteredResource>,
    authenticator: Option<Arc<dyn Authenticator>>,
    safety_pipelines: HashMap<String, FilterPipeline>,
    tool_permissions: HashMap<String, ToolPermissions>,
    hooks: Vec<Box<dyn crate::hooks::Hook>>,
    hook_timeout: std::time::Duration,
    quota_engine: Option<QuotaEngine>,
    ifc_policies: Option<HashMap<String, crate::ifc::TaintedWritePolicy>>,
}

impl McpServerBuilder {
    fn new() -> Self {
        Self {
            name: "mcpd".to_string(),
            version: "0.1.0".to_string(),
            tools: HashMap::new(),
            prompts: HashMap::new(),
            resources: HashMap::new(),
            authenticator: None,
            safety_pipelines: HashMap::new(),
            tool_permissions: HashMap::new(),
            hooks: Vec::new(),
            hook_timeout: std::time::Duration::from_secs(10),
            quota_engine: None,
            ifc_policies: None,
        }
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Register an individual tool with its handler.
    pub fn tool(
        mut self,
        definition: ToolDefinition,
        handler: impl Fn(serde_json::Value, CallContext) -> Pin<Box<dyn Future<Output = CallToolResult> + Send>>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        let name = definition.name.clone();
        self.tools.insert(
            name,
            RegisteredTool {
                definition,
                handler: Arc::new(handler),
            },
        );
        self
    }

    /// Register all tools and prompts from a module.
    ///
    /// Panics if a tool or prompt name conflicts with an already-registered one.
    /// Tool names should be prefixed with the module name (e.g. `docs_read`,
    /// `git_status`) to avoid collisions.
    pub fn module(mut self, module: impl Module) -> Self {
        let mod_name = module.name().to_string();
        for (definition, handler) in module.tools() {
            let tool_name = definition.name.clone();
            if self.tools.contains_key(&tool_name) {
                panic!(
                    "Tool name conflict: '{}' from module '{}' already registered by another module",
                    tool_name, mod_name
                );
            }
            tracing::info!(
                module = %mod_name,
                tool = %tool_name,
                "Registered tool"
            );
            self.tools.insert(
                tool_name,
                RegisteredTool {
                    definition,
                    handler,
                },
            );
        }
        for (definition, handler) in module.prompts() {
            let prompt_name = definition.name.clone();
            if self.prompts.contains_key(&prompt_name) {
                panic!(
                    "Prompt name conflict: '{}' from module '{}' already registered by another module",
                    prompt_name, mod_name
                );
            }
            tracing::info!(
                module = %mod_name,
                prompt = %prompt_name,
                "Registered prompt"
            );
            self.prompts.insert(
                prompt_name,
                RegisteredPrompt {
                    definition,
                    handler,
                },
            );
        }
        for (definition, handler) in module.resources() {
            let resource_uri = definition.uri.clone();
            if self.resources.contains_key(&resource_uri) {
                panic!(
                    "Resource URI conflict: '{}' from module '{}' already registered by another module",
                    resource_uri, mod_name
                );
            }
            tracing::info!(
                module = %mod_name,
                resource = %resource_uri,
                "Registered resource"
            );
            self.resources.insert(
                resource_uri,
                RegisteredResource {
                    definition,
                    handler,
                },
            );
        }
        self
    }

    pub fn authenticator(mut self, auth: impl Authenticator) -> Self {
        self.authenticator = Some(Arc::new(auth));
        self
    }

    /// Set the safety filter pipeline for a permission set.
    pub fn safety_profile(
        mut self,
        permission_set: impl Into<String>,
        pipeline: FilterPipeline,
    ) -> Self {
        self.safety_pipelines.insert(permission_set.into(), pipeline);
        self
    }

    /// Add a hook to the pipeline.
    ///
    /// Hooks are executed in the order they are added for pre-hooks,
    /// and in reverse order for post-hooks.
    pub fn hook(mut self, hook: impl crate::hooks::Hook) -> Self {
        self.hooks.push(Box::new(hook));
        self
    }

    /// Set the per-hook timeout (default: 10s).
    pub fn hook_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.hook_timeout = timeout;
        self
    }

    /// Set per-tool permission rules for a permission set.
    pub fn tool_permissions(
        mut self,
        permission_set: impl Into<String>,
        permissions: ToolPermissions,
    ) -> Self {
        self.tool_permissions
            .insert(permission_set.into(), permissions);
        self
    }

    /// Set the quota engine for rate limiting.
    pub fn quota_engine(mut self, engine: QuotaEngine) -> Self {
        self.quota_engine = Some(engine);
        self
    }

    /// Set an IFC policy for a permission set.
    pub fn ifc_policy(
        mut self,
        permission_set: impl Into<String>,
        policy: crate::ifc::TaintedWritePolicy,
    ) -> Self {
        self.ifc_policies
            .get_or_insert_with(HashMap::new)
            .insert(permission_set.into(), policy);
        self
    }

    pub fn build(self) -> McpServer {
        let authenticator = self.authenticator.unwrap_or_else(|| {
            Arc::new(crate::auth::NoAuthenticator {
                default_identity: crate::auth::AgentIdentity::new("anonymous", "readonly"),
            })
        });

        let mut hooks = HookPipeline::new(self.hook_timeout);
        for hook in self.hooks {
            hooks.add_boxed(hook);
        }

        let value_stores = crate::ifc::value_store::ValueStoreMap::new();
        let sessions = SessionStore::new();
        let mut tools = self.tools;

        // Register gateway IFC tools
        {
            use crate::protocol::{ToolDefinition, ToolInputSchema};
            use crate::ifc::value_store;

            // myelix_var_list — list all variables in the session
            let vs = value_stores.clone();
            tools.insert(
                "myelix_var_list".to_string(),
                RegisteredTool {
                    definition: ToolDefinition {
                        name: "myelix_var_list".to_string(),
                        description: Some("List all IFC-tracked variables in the current session".to_string()),
                        input_schema: ToolInputSchema {
                            schema_type: "object".to_string(),
                            properties: None,
                            required: None,
                        },
                    },
                    handler: Arc::new(move |_args, ctx| {
                        let vs = vs.clone();
                        Box::pin(async move {
                            let store = vs.get_or_create(&ctx.session_id);
                            let summaries = store.list();
                            let json: Vec<serde_json::Value> = summaries
                                .iter()
                                .map(|s| {
                                    serde_json::json!({
                                        "id": s.id,
                                        "label": format!("{}", s.label),
                                        "source_tool": s.source_tool,
                                        "is_error": s.is_error,
                                    })
                                })
                                .collect();
                            CallToolResult::text(serde_json::to_string_pretty(&json).unwrap_or_default())
                        })
                    }),
                },
            );

            // myelix_var_inspect — read a variable's content (taints context)
            let vs = value_stores.clone();
            let sess = sessions.clone();
            tools.insert(
                "myelix_var_inspect".to_string(),
                RegisteredTool {
                    definition: ToolDefinition {
                        name: "myelix_var_inspect".to_string(),
                        description: Some("Read a variable's content into the LLM context (taints session)".to_string()),
                        input_schema: ToolInputSchema {
                            schema_type: "object".to_string(),
                            properties: Some(std::collections::HashMap::from([(
                                "id".to_string(),
                                serde_json::json!({"type": "string", "description": "Variable ID"}),
                            )])),
                            required: Some(vec!["id".to_string()]),
                        },
                    },
                    handler: Arc::new(move |args, ctx| {
                        let vs = vs.clone();
                        let sess = sess.clone();
                        Box::pin(async move {
                            let var_id = match args.get("id").and_then(|v| v.as_str()) {
                                Some(id) => id,
                                None => return CallToolResult::error("Missing 'id' argument"),
                            };
                            let store = vs.get_or_create(&ctx.session_id);
                            match store.get(var_id) {
                                Some(stored) => {
                                    // Taint the session context label
                                    sess.update_context_label(&ctx.session_id, stored.label);
                                    let mut result = CallToolResult::success(stored.content);
                                    result.label = stored.label;
                                    result
                                }
                                None => CallToolResult::error(format!("Variable not found: {var_id}")),
                            }
                        })
                    }),
                },
            );

            // myelix_var_drop — remove a variable from the store
            let vs = value_stores.clone();
            tools.insert(
                "myelix_var_drop".to_string(),
                RegisteredTool {
                    definition: ToolDefinition {
                        name: "myelix_var_drop".to_string(),
                        description: Some("Remove a variable from the session store".to_string()),
                        input_schema: ToolInputSchema {
                            schema_type: "object".to_string(),
                            properties: Some(std::collections::HashMap::from([(
                                "id".to_string(),
                                serde_json::json!({"type": "string", "description": "Variable ID"}),
                            )])),
                            required: Some(vec!["id".to_string()]),
                        },
                    },
                    handler: Arc::new(move |args, ctx| {
                        let vs = vs.clone();
                        Box::pin(async move {
                            let var_id = match args.get("id").and_then(|v| v.as_str()) {
                                Some(id) => id,
                                None => return CallToolResult::error("Missing 'id' argument"),
                            };
                            let store = vs.get_or_create(&ctx.session_id);
                            match store.remove(var_id) {
                                Some(_) => CallToolResult::text(format!("Variable {var_id} removed")),
                                None => CallToolResult::error(format!("Variable not found: {var_id}")),
                            }
                        })
                    }),
                },
            );
        }

        McpServer {
            name: self.name,
            version: self.version,
            tools,
            prompts: self.prompts,
            resources: self.resources,
            sessions,
            authenticator,
            safety_pipelines: self.safety_pipelines,
            tool_permissions: self.tool_permissions,
            hooks,
            paused: Arc::new(AtomicBool::new(false)),
            task_store: TaskStore::new(),
            process_table: ProcessTable::new(),
            quota_engine: self.quota_engine.unwrap_or_default(),
            ifc_policies: self.ifc_policies.unwrap_or_default(),
            value_stores,
        }
    }
}

impl McpServer {
    /// Get the per-session value store map (for IFC variable tracking).
    pub fn value_stores(&self) -> &crate::ifc::value_store::ValueStoreMap {
        &self.value_stores
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AgentIdentity;
    use crate::protocol::ToolInputSchema;

    fn echo_tool_def() -> ToolDefinition {
        ToolDefinition {
            name: "echo".to_string(),
            description: Some("Echoes input".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
        }
    }

    fn test_agent() -> AgentIdentity {
        AgentIdentity::new("tester", "dev")
    }

    fn test_ctx() -> CallContext {
        CallContext::new(test_agent(), "test-session")
    }

    // A test module providing one tool.
    struct TestModule;

    impl Module for TestModule {
        fn name(&self) -> &str {
            "test"
        }

        fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
            vec![(
                ToolDefinition {
                    name: "test_ping".to_string(),
                    description: Some("Returns pong".to_string()),
                    input_schema: ToolInputSchema {
                        schema_type: "object".to_string(),
                        properties: None,
                        required: None,
                    },
                },
                Arc::new(|_args, _ctx| Box::pin(async { CallToolResult::text("pong") })),
            )]
        }
    }

    /// Number of gateway tools always registered (myelix_var_*).
    const GATEWAY_TOOLS: usize = 3;

    #[test]
    fn builder_defaults() {
        let server = McpServer::builder().build();
        assert_eq!(server.name, "mcpd");
        // Only gateway tools (myelix_var_list, myelix_var_inspect, myelix_var_drop)
        assert_eq!(server.tool_count(), GATEWAY_TOOLS);
    }

    #[test]
    fn builder_with_name_and_version() {
        let server = McpServer::builder()
            .name("my-server")
            .version("2.0.0")
            .build();
        let info = server.server_info();
        assert_eq!(info.name, "my-server");
        assert_eq!(info.version.unwrap(), "2.0.0");
    }

    #[test]
    fn register_tool_and_list() {
        let server = McpServer::builder()
            .tool(echo_tool_def(), |args, _ctx| {
                Box::pin(async move {
                    CallToolResult::text(format!("echo: {args}"))
                })
            })
            .build();

        let result = server.handle_list_tools();
        assert_eq!(result.tools.len(), 1 + GATEWAY_TOOLS);
        assert!(result.tools.iter().any(|t| t.name == "echo"));
    }

    #[test]
    fn register_module() {
        let server = McpServer::builder()
            .module(TestModule)
            .build();

        let result = server.handle_list_tools();
        assert_eq!(result.tools.len(), 1 + GATEWAY_TOOLS);
        assert!(result.tools.iter().any(|t| t.name == "test_ping"));
    }

    #[test]
    fn register_multiple_modules() {
        struct AnotherModule;
        impl Module for AnotherModule {
            fn name(&self) -> &str { "another" }
            fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
                vec![(
                    ToolDefinition {
                        name: "another_hello".to_string(),
                        description: None,
                        input_schema: ToolInputSchema {
                            schema_type: "object".to_string(),
                            properties: None,
                            required: None,
                        },
                    },
                    Arc::new(|_args, _ctx| Box::pin(async { CallToolResult::text("hi") })),
                )]
            }
        }

        let server = McpServer::builder()
            .module(TestModule)
            .module(AnotherModule)
            .build();

        assert_eq!(server.tool_count(), 2 + GATEWAY_TOOLS);
    }

    #[test]
    #[should_panic(expected = "Tool name conflict")]
    fn duplicate_tool_name_panics() {
        // Two modules both registering "test_ping" should fail
        struct DuplicateModule;
        impl Module for DuplicateModule {
            fn name(&self) -> &str { "duplicate" }
            fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
                vec![(
                    ToolDefinition {
                        name: "test_ping".to_string(),
                        description: None,
                        input_schema: ToolInputSchema {
                            schema_type: "object".to_string(),
                            properties: None,
                            required: None,
                        },
                    },
                    Arc::new(|_args, _ctx| Box::pin(async { CallToolResult::text("dup") })),
                )]
            }
        }

        McpServer::builder()
            .module(TestModule)
            .module(DuplicateModule)
            .build();
    }

    #[tokio::test]
    async fn call_module_tool() {
        let server = McpServer::builder()
            .module(TestModule)
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "test_ping".to_string(),
                    arguments: serde_json::json!({}),
                },
                test_ctx(),
            )
            .await;

        assert!(!result.is_error);
        match &result.content[0] {
            crate::protocol::Content::Text(t) => assert_eq!(t.text, "pong"),
        }
    }

    #[test]
    fn capabilities_reflect_tools() {
        // Gateway tools are always registered, so tools capability is always present
        let server = McpServer::builder().build();
        assert!(server.capabilities().tools.is_some());

        let with_tool = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("ok") })
            })
            .build();
        assert!(with_tool.capabilities().tools.is_some());
    }

    #[tokio::test]
    async fn call_registered_tool() {
        let server = McpServer::builder()
            .tool(echo_tool_def(), |args, _ctx| {
                Box::pin(async move {
                    let msg = args.get("message").and_then(|v| v.as_str()).unwrap_or("nil");
                    CallToolResult::text(format!("echo: {msg}"))
                })
            })
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({"message": "hello"}),
                },
                test_ctx(),
            )
            .await;

        assert!(!result.is_error);
        match &result.content[0] {
            crate::protocol::Content::Text(t) => assert_eq!(t.text, "echo: hello"),
        }
    }

    #[tokio::test]
    async fn call_unknown_tool() {
        let server = McpServer::builder().build();
        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "nonexistent".to_string(),
                    arguments: serde_json::Value::Null,
                },
                test_ctx(),
            )
            .await;
        assert!(result.is_error);
    }

    #[test]
    fn handle_initialize_creates_session() {
        let server = McpServer::builder().name("test").build();
        let params = InitializeParams {
            protocol_version: "2025-03-26".to_string(),
            capabilities: Default::default(),
            client_info: crate::protocol::ClientInfo {
                name: "client".to_string(),
                version: None,
            },
        };

        let (result, session_id) = server.handle_initialize(params, test_agent());
        assert_eq!(result.protocol_version, "2025-03-26");
        assert_eq!(result.server_info.name, "test");
        assert_eq!(server.sessions().count(), 1);
        assert!(!session_id.is_empty());
        assert!(server.sessions().get(&session_id).is_some());
    }

    #[tokio::test]
    async fn safety_filter_redacts_secrets() {
        let server = McpServer::builder()
            .tool(echo_tool_def(), |args, _ctx| {
                Box::pin(async move {
                    let msg = args.get("message").and_then(|v| v.as_str()).unwrap_or("");
                    CallToolResult::text(msg.to_string())
                })
            })
            .safety_profile("dev", crate::safety::build_pipeline("standard"))
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({"message": "key = AKIAIOSFODNN7EXAMPLE"}),
                },
                test_ctx(),
            )
            .await;

        assert!(!result.is_error);
        match &result.content[0] {
            crate::protocol::Content::Text(t) => {
                assert!(t.text.contains("[REDACTED:aws-key]"));
                assert!(!t.text.contains("AKIAIOSFODNN7EXAMPLE"));
            }
        }
    }

    #[tokio::test]
    async fn safety_filter_blocks_when_configured() {
        let server = McpServer::builder()
            .tool(echo_tool_def(), |args, _ctx| {
                Box::pin(async move {
                    let msg = args.get("message").and_then(|v| v.as_str()).unwrap_or("");
                    CallToolResult::text(msg.to_string())
                })
            })
            .safety_profile("dev", crate::safety::build_pipeline("block"))
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({"message": "SSN: 123-45-6789"}),
                },
                test_ctx(),
            )
            .await;

        assert!(result.is_error);
    }

    #[tokio::test]
    async fn no_safety_profile_passes_through() {
        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("AKIAIOSFODNN7EXAMPLE") })
            })
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                test_ctx(),
            )
            .await;

        // No safety profile configured → content passes through unmodified
        match &result.content[0] {
            crate::protocol::Content::Text(t) => {
                assert!(t.text.contains("AKIAIOSFODNN7EXAMPLE"));
            }
        }
    }

    // --- Prompt tests ---

    fn greeting_prompt_def() -> crate::protocol::PromptDefinition {
        crate::protocol::PromptDefinition {
            name: "greeting".to_string(),
            description: Some("A greeting prompt".to_string()),
            arguments: vec![crate::protocol::PromptArgument {
                name: "name".to_string(),
                description: Some("Name to greet".to_string()),
                required: true,
            }],
        }
    }

    fn greeting_prompt_handler() -> PromptHandler {
        Arc::new(|args: HashMap<String, String>| {
            Box::pin(async move {
                let name = args.get("name").cloned().unwrap_or_else(|| "world".to_string());
                crate::protocol::GetPromptResult {
                    description: Some("A greeting".to_string()),
                    messages: vec![crate::protocol::PromptMessage {
                        role: crate::protocol::PromptRole::User,
                        content: crate::protocol::Content::text(format!("Hello, {name}!")),
                    }],
                }
            })
        })
    }

    // A test module providing both tools and prompts.
    struct PromptModule;

    impl Module for PromptModule {
        fn name(&self) -> &str {
            "prompt_test"
        }

        fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
            vec![]
        }

        fn prompts(&self) -> Vec<(crate::protocol::PromptDefinition, PromptHandler)> {
            vec![(greeting_prompt_def(), greeting_prompt_handler())]
        }
    }

    #[test]
    fn register_module_with_prompts() {
        let server = McpServer::builder()
            .module(PromptModule)
            .build();

        assert_eq!(server.prompt_count(), 1);
        let result = server.handle_list_prompts();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "greeting");
    }

    #[tokio::test]
    async fn call_registered_prompt() {
        let server = McpServer::builder()
            .module(PromptModule)
            .build();

        let result = server
            .handle_get_prompt(crate::protocol::GetPromptParams {
                name: "greeting".to_string(),
                arguments: HashMap::from([("name".to_string(), "Alice".to_string())]),
            })
            .await;

        let result = result.unwrap();
        assert_eq!(result.description, Some("A greeting".to_string()));
        match &result.messages[0].content {
            crate::protocol::Content::Text(t) => assert_eq!(t.text, "Hello, Alice!"),
        }
    }

    #[tokio::test]
    async fn call_unknown_prompt() {
        let server = McpServer::builder().build();
        let result = server
            .handle_get_prompt(crate::protocol::GetPromptParams {
                name: "nonexistent".to_string(),
                arguments: HashMap::new(),
            })
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown prompt"));
    }

    #[test]
    fn capabilities_reflect_prompts() {
        let empty = McpServer::builder().build();
        assert!(empty.capabilities().prompts.is_none());

        let with_prompt = McpServer::builder()
            .module(PromptModule)
            .build();
        assert!(with_prompt.capabilities().prompts.is_some());
    }

    #[test]
    #[should_panic(expected = "Prompt name conflict")]
    fn duplicate_prompt_name_panics() {
        struct DuplicatePromptModule;
        impl Module for DuplicatePromptModule {
            fn name(&self) -> &str { "duplicate" }
            fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> { vec![] }
            fn prompts(&self) -> Vec<(crate::protocol::PromptDefinition, PromptHandler)> {
                vec![(greeting_prompt_def(), greeting_prompt_handler())]
            }
        }

        McpServer::builder()
            .module(PromptModule)
            .module(DuplicatePromptModule)
            .build();
    }

    // --- Resource tests ---

    fn info_resource_def() -> crate::protocol::ResourceDefinition {
        crate::protocol::ResourceDefinition {
            uri: "info://server/status".to_string(),
            name: "Server Status".to_string(),
            description: Some("Current server status".to_string()),
            mime_type: Some("text/plain".to_string()),
        }
    }

    fn info_resource_handler() -> crate::module::ResourceHandler {
        Arc::new(|uri: String| {
            Box::pin(async move {
                crate::protocol::ReadResourceResult {
                    contents: vec![crate::protocol::ResourceContent {
                        uri,
                        mime_type: Some("text/plain".to_string()),
                        text: Some("running".to_string()),
                        blob: None,
                    }],
                }
            })
        })
    }

    struct ResourceModule;

    impl Module for ResourceModule {
        fn name(&self) -> &str { "resource_test" }
        fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> { vec![] }
        fn resources(&self) -> Vec<(crate::protocol::ResourceDefinition, crate::module::ResourceHandler)> {
            vec![(info_resource_def(), info_resource_handler())]
        }
    }

    #[test]
    fn register_module_with_resources() {
        let server = McpServer::builder()
            .module(ResourceModule)
            .build();

        assert_eq!(server.resource_count(), 1);
        let result = server.handle_list_resources();
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].uri, "info://server/status");
    }

    #[tokio::test]
    async fn read_registered_resource() {
        let server = McpServer::builder()
            .module(ResourceModule)
            .build();

        let result = server
            .handle_read_resource(crate::protocol::ReadResourceParams {
                uri: "info://server/status".to_string(),
            })
            .await;

        let result = result.unwrap();
        assert_eq!(result.contents[0].text, Some("running".to_string()));
    }

    #[tokio::test]
    async fn read_unknown_resource() {
        let server = McpServer::builder().build();
        let result = server
            .handle_read_resource(crate::protocol::ReadResourceParams {
                uri: "info://nonexistent".to_string(),
            })
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown resource"));
    }

    #[test]
    fn capabilities_reflect_resources() {
        let empty = McpServer::builder().build();
        assert!(empty.capabilities().resources.is_none());

        let with_resource = McpServer::builder()
            .module(ResourceModule)
            .build();
        assert!(with_resource.capabilities().resources.is_some());
    }

    #[test]
    #[should_panic(expected = "Resource URI conflict")]
    fn duplicate_resource_uri_panics() {
        struct DuplicateResourceModule;
        impl Module for DuplicateResourceModule {
            fn name(&self) -> &str { "duplicate" }
            fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> { vec![] }
            fn resources(&self) -> Vec<(crate::protocol::ResourceDefinition, crate::module::ResourceHandler)> {
                vec![(info_resource_def(), info_resource_handler())]
            }
        }

        McpServer::builder()
            .module(ResourceModule)
            .module(DuplicateResourceModule)
            .build();
    }

    // --- Per-tool permission tests ---

    #[tokio::test]
    async fn tool_permissions_deny_blocks_tool() {
        use crate::permissions::tool_rules::{ToolPermissions, ToolPolicy, ToolRule};

        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("should not reach") })
            })
            .tool_permissions(
                "dev",
                ToolPermissions::new(
                    vec![ToolRule {
                        tool: "echo".to_string(),
                        policy: ToolPolicy::Deny,
                    }],
                    ToolPolicy::Allow,
                ),
            )
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                test_ctx(),
            )
            .await;

        assert!(result.is_error);
        match &result.content[0] {
            crate::protocol::Content::Text(t) => {
                assert!(t.text.contains("Permission denied"));
            }
        }
    }

    #[tokio::test]
    async fn tool_permissions_allow_passes_through() {
        use crate::permissions::tool_rules::{ToolPermissions, ToolPolicy, ToolRule};

        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("reached") })
            })
            .tool_permissions(
                "dev",
                ToolPermissions::new(
                    vec![ToolRule {
                        tool: "echo".to_string(),
                        policy: ToolPolicy::Allow,
                    }],
                    ToolPolicy::Deny,
                ),
            )
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                test_ctx(),
            )
            .await;

        assert!(!result.is_error);
        match &result.content[0] {
            crate::protocol::Content::Text(t) => assert_eq!(t.text, "reached"),
        }
    }

    #[tokio::test]
    async fn tool_permissions_approve_returns_approval_required() {
        use crate::permissions::tool_rules::{ToolPermissions, ToolPolicy, ToolRule};

        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("should not reach") })
            })
            .tool_permissions(
                "dev",
                ToolPermissions::new(
                    vec![ToolRule {
                        tool: "echo".to_string(),
                        policy: ToolPolicy::Approve,
                    }],
                    ToolPolicy::Allow,
                ),
            )
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                test_ctx(),
            )
            .await;

        assert!(result.is_error);
        match &result.content[0] {
            crate::protocol::Content::Text(t) => {
                assert!(t.text.contains("Approval required"));
            }
        }
    }

    #[tokio::test]
    async fn no_tool_permissions_allows_all() {
        // No tool_permissions registered at all — everything should pass
        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("ok") })
            })
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                test_ctx(),
            )
            .await;

        assert!(!result.is_error);
    }

    // --- Capability token tool permission tests ---

    fn cap_ctx(tools: Vec<&str>) -> CallContext {
        use crate::auth::capability::ResolvedCapabilities;
        CallContext::new(
            AgentIdentity {
                name: "cap-agent".to_string(),
                permissions: "cap:ring1".to_string(),
                signing_key: None,
                did: Some("did:key:z6MkTest".to_string()),
                capabilities: Some(ResolvedCapabilities {
                    issuer_did: "did:key:z6MkRoot".to_string(),
                    subject_did: "did:key:z6MkTest".to_string(),
                    ring: 1,
                    paths: vec!["/home/user/**".to_string()],
                    operations: ["read", "write"].into_iter().map(String::from).collect(),
                    tools: tools.into_iter().map(String::from).collect(),
                    credentials: vec![],
                    expires_at: u64::MAX,
                }),
            },
            "cap-session",
        )
    }

    #[tokio::test]
    async fn cap_token_allows_matching_tool() {
        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("ok") })
            })
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                cap_ctx(vec!["echo", "docs_*"]),
            )
            .await;

        assert!(!result.is_error);
    }

    #[tokio::test]
    async fn cap_token_allows_glob_matching_tool() {
        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("ok") })
            })
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                cap_ctx(vec!["*"]),  // wildcard grants all
            )
            .await;

        assert!(!result.is_error);
    }

    #[tokio::test]
    async fn cap_token_denies_unmatched_tool() {
        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("should not reach") })
            })
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                cap_ctx(vec!["docs_*", "git_*"]),  // no match for "echo"
            )
            .await;

        assert!(result.is_error);
        match &result.content[0] {
            crate::protocol::Content::Text(t) => {
                assert!(t.text.contains("not in capability token"));
            }
        }
    }

    #[tokio::test]
    async fn cap_token_bypasses_tool_permissions() {
        // Even if tool_permissions deny "echo", cap token with matching
        // tool glob should allow it (cap path takes priority).
        use crate::permissions::tool_rules::{ToolPermissions, ToolPolicy, ToolRule};

        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("ok") })
            })
            .tool_permissions(
                "cap:ring1",
                ToolPermissions::new(
                    vec![ToolRule {
                        tool: "echo".to_string(),
                        policy: ToolPolicy::Deny,
                    }],
                    ToolPolicy::Allow,
                ),
            )
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                cap_ctx(vec!["echo"]),
            )
            .await;

        // Cap token allows — tool_permissions not consulted
        assert!(!result.is_error);
    }

    // --- IFC (Information Flow Control) tests ---

    fn read_tool_def() -> ToolDefinition {
        ToolDefinition {
            name: "docs_read".to_string(),
            description: Some("Reads a file".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
        }
    }

    fn write_tool_def() -> ToolDefinition {
        ToolDefinition {
            name: "docs_write".to_string(),
            description: Some("Writes a file".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
        }
    }

    #[tokio::test]
    async fn ifc_deny_write_after_untrusted_read() {
        // Build server with IFC deny policy and both read + write tools
        let server = McpServer::builder()
            .tool(read_tool_def(), |_args, _ctx| {
                Box::pin(async {
                    // Simulate reading external file — handler returns trusted,
                    // but is_external_read_tool("docs_read") auto-labels Untrusted
                    CallToolResult::text("file contents with injected instructions")
                })
            })
            .tool(write_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("should not reach") })
            })
            .ifc_policy("dev", crate::ifc::TaintedWritePolicy::Deny)
            .build();

        // First call: read — taints the session
        let mut ctx = test_ctx();
        let read_result = server
            .handle_call_tool(
                CallToolParams {
                    name: "docs_read".to_string(),
                    arguments: serde_json::json!({"path": "/tmp/file.md"}),
                },
                ctx.clone(),
            )
            .await;
        assert!(!read_result.is_error);

        // Simulate taint propagation (in real flow, ctx is mutable across calls)
        ctx.taint.absorb(crate::ifc::DataLabel::UNTRUSTED_SENSITIVE);

        // Second call: write — should be denied by IFC
        let write_result = server
            .handle_call_tool(
                CallToolParams {
                    name: "docs_write".to_string(),
                    arguments: serde_json::json!({"path": "/tmp/out.md", "content": "exfiltrated"}),
                },
                ctx,
            )
            .await;
        assert!(write_result.is_error);
        match &write_result.content[0] {
            crate::protocol::Content::Text(t) => {
                assert!(t.text.contains("IFC"));
                assert!(t.text.contains("tainted"));
            }
        }
    }

    #[tokio::test]
    async fn ifc_allow_write_without_taint() {
        // No prior read — session is clean, write should succeed
        let server = McpServer::builder()
            .tool(write_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("written") })
            })
            .ifc_policy("dev", crate::ifc::TaintedWritePolicy::Deny)
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "docs_write".to_string(),
                    arguments: serde_json::json!({}),
                },
                test_ctx(),
            )
            .await;
        assert!(!result.is_error);
    }

    #[tokio::test]
    async fn ifc_no_policy_allows_tainted_write() {
        // No IFC policy configured — tainted writes pass through
        let server = McpServer::builder()
            .tool(write_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("written") })
            })
            .build();

        let mut ctx = test_ctx();
        ctx.taint.absorb(crate::ifc::DataLabel::UNTRUSTED_SENSITIVE);

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "docs_write".to_string(),
                    arguments: serde_json::json!({}),
                },
                ctx,
            )
            .await;
        assert!(!result.is_error);
    }

    #[tokio::test]
    async fn ifc_read_tool_auto_labels_untrusted() {
        // docs_read output should be auto-labeled as Untrusted
        let server = McpServer::builder()
            .tool(read_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("file data") })
            })
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "docs_read".to_string(),
                    arguments: serde_json::json!({}),
                },
                test_ctx(),
            )
            .await;

        // The result should be labeled Untrusted (confidentiality stays Public)
        assert_eq!(result.label.integrity, crate::ifc::Integrity::Untrusted);
        assert_eq!(result.label.confidentiality, crate::ifc::Confidentiality::Public);
    }

    // --- Hook pipeline tests ---

    #[tokio::test]
    async fn hook_safety_filter_via_pipeline() {
        use crate::hooks::SafetyHook;

        let server = McpServer::builder()
            .tool(echo_tool_def(), |args, _ctx| {
                Box::pin(async move {
                    let msg = args.get("message").and_then(|v| v.as_str()).unwrap_or("");
                    CallToolResult::text(msg.to_string())
                })
            })
            .hook(SafetyHook::single("dev", crate::safety::build_pipeline("standard")))
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({"message": "key = AKIAIOSFODNN7EXAMPLE"}),
                },
                test_ctx(),
            )
            .await;

        assert!(!result.is_error);
        match &result.content[0] {
            crate::protocol::Content::Text(t) => {
                assert!(t.text.contains("[REDACTED:aws-key]"));
            }
        }
    }

    #[tokio::test]
    async fn hook_blocks_tool_call() {
        /// A pre-hook that blocks all tool calls.
        struct BlockAll;

        #[async_trait::async_trait]
        impl crate::hooks::Hook for BlockAll {
            fn name(&self) -> &str { "block-all" }
            async fn pre_tool_use(
                &self,
                _tool_name: &str,
                _arguments: &serde_json::Value,
                _ctx: &CallContext,
            ) -> crate::hooks::HookDecision {
                crate::hooks::HookDecision::Block("blocked by test hook".to_string())
            }
        }

        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("should not reach") })
            })
            .hook(BlockAll)
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                test_ctx(),
            )
            .await;

        assert!(result.is_error);
        match &result.content[0] {
            crate::protocol::Content::Text(t) => {
                assert!(t.text.contains("blocked by test hook"));
            }
        }
    }

    #[tokio::test]
    async fn legacy_safety_filter_still_works_without_hooks() {
        // When no hooks are registered, safety_profile() still works via legacy path
        let server = McpServer::builder()
            .tool(echo_tool_def(), |args, _ctx| {
                Box::pin(async move {
                    let msg = args.get("message").and_then(|v| v.as_str()).unwrap_or("");
                    CallToolResult::text(msg.to_string())
                })
            })
            .safety_profile("dev", crate::safety::build_pipeline("standard"))
            .build();

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({"message": "AKIAIOSFODNN7EXAMPLE"}),
                },
                test_ctx(),
            )
            .await;

        assert!(!result.is_error);
        match &result.content[0] {
            crate::protocol::Content::Text(t) => {
                assert!(t.text.contains("[REDACTED:aws-key]"));
            }
        }
    }

    // --- Pause/resume tests ---

    #[tokio::test]
    async fn paused_server_rejects_tool_calls() {
        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("should not reach") })
            })
            .build();

        server.pause();
        assert!(server.is_paused());

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                test_ctx(),
            )
            .await;

        assert!(result.is_error);
        match &result.content[0] {
            crate::protocol::Content::Text(t) => {
                assert!(t.text.contains("paused"));
            }
        }
    }

    #[tokio::test]
    async fn resumed_server_accepts_tool_calls() {
        let server = McpServer::builder()
            .tool(echo_tool_def(), |_args, _ctx| {
                Box::pin(async { CallToolResult::text("ok") })
            })
            .build();

        server.pause();
        server.resume();
        assert!(!server.is_paused());

        let result = server
            .handle_call_tool(
                CallToolParams {
                    name: "echo".to_string(),
                    arguments: serde_json::json!({}),
                },
                test_ctx(),
            )
            .await;

        assert!(!result.is_error);
    }

    #[test]
    fn pause_flag_is_shared() {
        let server = McpServer::builder().build();
        let flag = server.pause_flag();

        assert!(!flag.load(std::sync::atomic::Ordering::Relaxed));
        server.pause();
        assert!(flag.load(std::sync::atomic::Ordering::Relaxed));
        server.resume();
        assert!(!flag.load(std::sync::atomic::Ordering::Relaxed));
    }
}
