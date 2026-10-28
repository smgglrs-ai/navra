use crate::hooks::HookPipeline;
use crate::module::Module;
use crate::permissions::tool_rules::ToolPermissions;
use crate::protocol::CallToolResult;
use crate::quota::QuotaEngine;
use crate::safety::FilterPipeline;
use crate::session::SessionStore;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::AtomicBool;

use super::McpServer;
use super::types::{
    RegisteredPrompt, RegisteredResource, RegisteredResourceTemplate, RegisteredTool,
};

/// Builder for constructing an McpServer.
pub struct McpServerBuilder {
    name: String,
    version: String,
    tools: HashMap<String, RegisteredTool>,
    prompts: HashMap<String, RegisteredPrompt>,
    resources: HashMap<String, RegisteredResource>,
    resource_templates: Vec<RegisteredResourceTemplate>,
    authenticator: Option<Arc<dyn crate::auth::Authenticator>>,
    safety_pipelines: HashMap<String, FilterPipeline>,
    tool_permissions: HashMap<String, ToolPermissions>,
    agent_operations: HashMap<String, HashSet<String>>,
    tool_operations: HashMap<String, navra_mcp::ToolOperation>,
    tool_classifications: HashMap<String, navra_auth::permissions::ResourceClass>,
    domain_rules: HashMap<String, navra_auth::permissions::DomainRules>,
    hooks: Vec<Box<dyn crate::hooks::Hook>>,
    hook_timeout: std::time::Duration,
    quota_engine: Option<QuotaEngine>,
    ifc_policies: Option<HashMap<String, crate::ifc::TaintedWritePolicy>>,
    ifc_read_clearances: Option<HashMap<String, crate::ifc::ReadClearance>>,
    trusted_paths: Option<HashMap<String, Vec<String>>>,
    session_store: Option<SessionStore>,
    process_table: Option<crate::process::ProcessTable>,
    blackbox: Option<Arc<crate::blackbox::Blackbox>>,
    broadcaster: Option<crate::transport::sse::SseBroadcaster>,
    #[cfg(feature = "cedar")]
    cedar_engine: Option<navra_auth::permissions::CedarEngine>,
    #[cfg(feature = "cedar")]
    cedar_action_version: Option<super::CedarActionVersion>,
    #[cfg(feature = "opa")]
    opa_engine: Option<navra_auth::permissions::OpaEngine>,
    dmn_engine: Option<navra_auth::permissions::DmnEngine>,
    tool_disclosure: HashMap<String, navra_auth::permissions::ToolDisclosure>,
    hide_denied_tools: bool,
    declassification_authority: Option<Arc<navra_auth::ifc::DeclassificationAuthority>>,
    declassification_ledger: Option<Arc<crate::safety::DeclassificationLedger>>,
    upstream_watchers: Vec<crate::UpstreamWatcher>,
    /// Tool names registered per module (for upstream registry swaps).
    module_tool_index: HashMap<String, Vec<String>>,
    dynamic_filters: Vec<Box<dyn super::ToolFilter>>,
    path_acls: HashMap<String, navra_auth::permissions::PathAcl>,
    mcp_version: String,
    enterprise_auth: bool,
    tool_routing: super::routing::ToolRoutingConfig,
    metrics: Option<Arc<crate::metrics::Metrics>>,
    upstream_modules: HashSet<String>,
    max_sessions: Option<usize>,
    session_ttl_secs: Option<u64>,
}

impl McpServerBuilder {
    pub(super) fn new() -> Self {
        Self {
            name: "navra".to_string(),
            version: "0.1.0".to_string(),
            tools: HashMap::new(),
            prompts: HashMap::new(),
            resources: HashMap::new(),
            resource_templates: Vec::new(),
            authenticator: None,
            safety_pipelines: HashMap::new(),
            tool_permissions: HashMap::new(),
            agent_operations: HashMap::new(),
            tool_operations: HashMap::new(),
            tool_classifications: HashMap::new(),
            domain_rules: HashMap::new(),
            hooks: Vec::new(),
            hook_timeout: std::time::Duration::from_secs(10),
            quota_engine: None,
            ifc_policies: None,
            ifc_read_clearances: None,
            trusted_paths: None,
            session_store: None,
            process_table: None,
            blackbox: None,
            broadcaster: None,
            #[cfg(feature = "cedar")]
            cedar_engine: None,
            #[cfg(feature = "cedar")]
            cedar_action_version: None,
            #[cfg(feature = "opa")]
            opa_engine: None,
            dmn_engine: None,
            tool_disclosure: HashMap::new(),
            hide_denied_tools: true,
            declassification_authority: None,
            declassification_ledger: None,
            upstream_watchers: Vec::new(),
            module_tool_index: HashMap::new(),
            dynamic_filters: Vec::new(),
            path_acls: HashMap::new(),
            mcp_version: navra_protocol::PROTOCOL_VERSION_2026.to_string(),
            enterprise_auth: false,
            tool_routing: super::routing::ToolRoutingConfig::default(),
            metrics: None,
            upstream_modules: HashSet::new(),
            max_sessions: None,
            session_ttl_secs: None,
        }
    }

    pub fn max_sessions(mut self, n: usize) -> Self {
        self.max_sessions = Some(n);
        self
    }

    pub fn session_ttl_secs(mut self, secs: u64) -> Self {
        self.session_ttl_secs = Some(secs);
        self
    }

    pub fn upstream_module(mut self, name: impl Into<String>) -> Self {
        self.upstream_modules.insert(name.into());
        self
    }

    pub fn path_acl(
        mut self,
        permission_set: impl Into<String>,
        acl: navra_auth::permissions::PathAcl,
    ) -> Self {
        self.path_acls.insert(permission_set.into(), acl);
        self
    }

    pub fn mcp_version(mut self, version: &str) -> Self {
        self.mcp_version = version.to_string();
        self
    }

    pub fn enterprise_auth(mut self, enabled: bool) -> Self {
        self.enterprise_auth = enabled;
        self
    }

    pub fn tool_routing(mut self, config: super::routing::ToolRoutingConfig) -> Self {
        self.tool_routing = config;
        self
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
        definition: crate::protocol::ToolDefinition,
        handler: impl Fn(
            serde_json::Value,
            crate::auth::CallContext,
        ) -> Pin<Box<dyn Future<Output = CallToolResult> + Send>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        let name = definition.name.to_string();
        self.tools.insert(
            name,
            RegisteredTool {
                definition,
                handler: Arc::new(handler),
            },
        );
        self
    }

    /// Register an individual resource with its handler.
    pub fn resource(
        mut self,
        definition: crate::protocol::ResourceDefinition,
        handler: crate::module::ResourceHandler,
    ) -> Self {
        let uri = definition.uri.clone();
        self.resources.insert(
            uri,
            RegisteredResource {
                definition,
                handler,
            },
        );
        self
    }

    /// Register a resource template with a handler for parameterized URIs.
    pub fn resource_template(
        mut self,
        template: crate::protocol::ResourceTemplate,
        handler: crate::module::ResourceHandler,
    ) -> Self {
        self.resource_templates
            .push(RegisteredResourceTemplate { template, handler });
        self
    }

    /// Register all tools and prompts from a module.
    ///
    /// Panics if a tool or prompt name conflicts with an already-registered one.
    /// Tool names should be prefixed with the module name (e.g. `file_read`,
    /// `git_status`) to avoid collisions.
    pub fn module(mut self, module: impl Module) -> Self {
        let mod_name = module.name().to_string();
        let mut mod_tools = Vec::new();
        for (definition, handler) in module.tools() {
            let tool_name = definition.name.to_string();
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
            mod_tools.push(tool_name.clone());
            self.tools.insert(
                tool_name,
                RegisteredTool {
                    definition,
                    handler,
                },
            );
        }
        self.module_tool_index.insert(mod_name.clone(), mod_tools);
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

    pub fn authenticator(mut self, auth: impl crate::auth::Authenticator) -> Self {
        self.authenticator = Some(Arc::new(auth));
        self
    }

    /// Set the safety filter pipeline for a permission set.
    pub fn safety_profile(
        mut self,
        permission_set: impl Into<String>,
        pipeline: FilterPipeline,
    ) -> Self {
        self.safety_pipelines
            .insert(permission_set.into(), pipeline);
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

    /// Set allowed operations for a permission set (e.g., "read", "write").
    pub fn agent_operations(
        mut self,
        permission_set: impl Into<String>,
        operations: HashSet<String>,
    ) -> Self {
        self.agent_operations
            .insert(permission_set.into(), operations);
        self
    }

    /// Merge upstream tool operation classifications into the server.
    pub fn merge_tool_operations(mut self, ops: HashMap<String, navra_mcp::ToolOperation>) -> Self {
        self.tool_operations.extend(ops);
        self
    }

    /// Merge tool semantic classifications into the server.
    pub fn merge_tool_classifications(
        mut self,
        classes: HashMap<String, navra_auth::permissions::ResourceClass>,
    ) -> Self {
        self.tool_classifications.extend(classes);
        self
    }

    /// Set domain-based permission rules for a permission set.
    pub fn domain_rules(
        mut self,
        permission_set: impl Into<String>,
        rules: navra_auth::permissions::DomainRules,
    ) -> Self {
        self.domain_rules.insert(permission_set.into(), rules);
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

    /// Set IFC read clearance for a permission set (Simple Security Property).
    pub fn ifc_read_clearance(
        mut self,
        permission_set: impl Into<String>,
        clearance: crate::ifc::ReadClearance,
    ) -> Self {
        self.ifc_read_clearances
            .get_or_insert_with(HashMap::new)
            .insert(permission_set.into(), clearance);
        self
    }

    /// Set trusted path patterns for a permission set.
    ///
    /// Files matching these glob patterns keep their Trusted integrity
    /// label even when accessed via external read tools.
    pub fn trusted_paths(mut self, permission_set: impl Into<String>, paths: Vec<String>) -> Self {
        self.trusted_paths
            .get_or_insert_with(HashMap::new)
            .insert(permission_set.into(), paths);
        self
    }

    /// Enable the gateway-level blackbox (audit recorder).
    pub fn blackbox(mut self, bb: crate::blackbox::Blackbox) -> Self {
        self.blackbox = Some(Arc::new(bb));
        self
    }

    /// Set tool disclosure rules for a permission set (progressive tool disclosure).
    pub fn tool_disclosure(
        mut self,
        permission_set: impl Into<String>,
        disclosure: navra_auth::permissions::ToolDisclosure,
    ) -> Self {
        self.tool_disclosure
            .insert(permission_set.into(), disclosure);
        self
    }

    /// Set the trusted declassification authority (the gateway's
    /// CapSigner). Without an authority, full-redaction declassification
    /// recommendations cannot step labels down — results stay at the
    /// elevated label (fail-safe).
    pub fn declassification_authority(
        mut self,
        authority: Arc<navra_auth::ifc::DeclassificationAuthority>,
    ) -> Self {
        self.declassification_authority = Some(authority);
        self
    }

    /// Attach the shared declassification ledger. The same `Arc` must
    /// be given to the `SafetyHook` (when hooks are wired) so that
    /// recommendations recorded during post-call filtering reach the
    /// gateway's declassification path.
    pub fn declassification_ledger(
        mut self,
        ledger: Arc<crate::safety::DeclassificationLedger>,
    ) -> Self {
        self.declassification_ledger = Some(ledger);
        self
    }

    /// Register a refresh watcher for an upstream module that
    /// advertises `list_changed`. The embedding server must drain the
    /// watchers after `build()` and spawn `UpstreamWatcher::run`.
    pub fn upstream_watcher(mut self, watcher: crate::UpstreamWatcher) -> Self {
        self.upstream_watchers.push(watcher);
        self
    }

    /// Control whether tools with a static `Deny` in `tool_rules` are
    /// hidden from `tools/list`. Default: true (deny-wins philosophy —
    /// a denied tool's description is pure injection surface for a
    /// tool the agent cannot call). Setting false restores the
    /// historical behavior where denied tools remain listed.
    pub fn hide_denied_tools(mut self, hide: bool) -> Self {
        self.hide_denied_tools = hide;
        self
    }

    /// Add a dynamic tool filter.
    ///
    /// Dynamic filters run during `handle_list_tools_dynamic()` after
    /// static disclosure rules. They can hide tools based on runtime
    /// state such as session taint or quota.
    pub fn tool_filter(mut self, filter: impl super::ToolFilter + 'static) -> Self {
        self.dynamic_filters.push(Box::new(filter));
        self
    }

    pub fn metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Set the Cedar policy engine for conditional access control.
    #[cfg(feature = "cedar")]
    pub fn cedar_engine(mut self, engine: navra_auth::permissions::CedarEngine) -> Self {
        self.cedar_engine = Some(engine);
        self
    }

    /// Select the Cedar action dispatch version (default v1, bare
    /// tool names). See [`CedarActionVersion`] for the v2 upstream
    /// namespacing semantics.
    #[cfg(feature = "cedar")]
    pub fn cedar_action_version(mut self, version: super::CedarActionVersion) -> Self {
        self.cedar_action_version = Some(version);
        self
    }

    /// Evaluate a Cedar action against the configured engine.
    ///
    /// Used at wiring time for actions that are not tool calls —
    /// notably `upstream_discover`, dispatched when an upstream's
    /// discovery results are accepted for registration. Returns true
    /// (allow) when no Cedar engine is configured: the Cedar gate can
    /// only further restrict, never grant.
    #[cfg(feature = "cedar")]
    pub fn cedar_allows(
        &self,
        action: &str,
        resource: &str,
        context: &std::collections::HashMap<String, String>,
    ) -> bool {
        match &self.cedar_engine {
            None => true,
            Some(engine) => matches!(
                engine.is_authorized("navra-gateway", action, resource, context),
                crate::permissions::CedarDecision::Allow
            ),
        }
    }

    /// Set the OPA/Rego policy engine for conditional access control.
    #[cfg(feature = "opa")]
    pub fn opa_engine(mut self, engine: navra_auth::permissions::OpaEngine) -> Self {
        self.opa_engine = Some(engine);
        self
    }

    /// Set the DMN decision table engine for business-rule guardrails.
    pub fn dmn_engine(mut self, engine: navra_auth::permissions::DmnEngine) -> Self {
        self.dmn_engine = Some(engine);
        self
    }

    /// Set the SSE broadcaster for server-initiated notifications.
    pub fn broadcaster(mut self, b: crate::transport::sse::SseBroadcaster) -> Self {
        self.broadcaster = Some(b);
        self
    }

    /// Use a custom session store backend (e.g. SQLite for persistence).
    /// If not set, sessions are stored in memory (lost on restart).
    pub fn session_store(mut self, store: SessionStore) -> Self {
        self.session_store = Some(store);
        self
    }

    /// Use a pre-created process table (e.g. for sharing with resource handlers).
    /// If not set, a new empty table is created during build.
    pub fn process_table(mut self, table: crate::process::ProcessTable) -> Self {
        self.process_table = Some(table);
        self
    }

    /// Opt in to unauthenticated mode. Required when no authenticator
    /// is configured — prevents silent fallback to open access.
    pub fn allow_anonymous(mut self) -> Self {
        if self.authenticator.is_none() {
            self.authenticator = Some(Arc::new(crate::auth::NoAuthenticator {
                default_identity: crate::auth::AgentIdentity::new("anonymous", "readonly"),
            }));
        }
        self
    }

    pub fn build(mut self) -> McpServer {
        let authenticator = self.authenticator.unwrap_or_else(|| {
            panic!(
                "No authenticator configured. Call .allow_anonymous() for \
                 intentional open access, or add [[agents]] to config.toml."
            );
        });

        let mut hooks = HookPipeline::new(self.hook_timeout);
        for hook in self.hooks {
            hooks.add_boxed(hook);
        }

        let value_stores = crate::ifc::value_store::ValueStoreMap::new();
        let sessions = self.session_store.unwrap_or_default();
        let mut tools = self.tools;

        // Register gateway IFC tools
        {
            use crate::protocol::ToolDefinition;
            use navra_protocol::compat::CallToolResultExt;

            // navra_var_list — list all variables in the session
            let vs = value_stores.clone();
            tools.insert(
                "navra_var_list".to_string(),
                RegisteredTool {
                    definition: ToolDefinition::new(
                        "navra_var_list",
                        "List all IFC-tracked variables in the current session",
                        navra_protocol::compat::empty_input_schema(),
                    ),
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
                            CallToolResult::text(
                                serde_json::to_string_pretty(&json).unwrap_or_default(),
                            )
                        })
                    }),
                },
            );

            // navra_var_inspect — read a variable's content (taints context)
            let vs = value_stores.clone();
            let sess = sessions.clone();
            tools.insert(
                "navra_var_inspect".to_string(),
                RegisteredTool {
                    definition: ToolDefinition::new(
                        "navra_var_inspect",
                        "Read a variable's content into the LLM context (taints session)",
                        navra_protocol::compat::tool_input_schema(
                            Some(std::collections::HashMap::from([(
                                "id".to_string(),
                                serde_json::json!({"type": "string", "description": "Variable ID"}),
                            )])),
                            Some(vec!["id".to_string()]),
                        ),
                    ),
                    handler: Arc::new(move |args, ctx| {
                        let vs = vs.clone();
                        let sess = sess.clone();
                        Box::pin(async move {
                            let var_id = match args.get("id").and_then(|v| v.as_str()) {
                                Some(id) => id,
                                None => return CallToolResult::error_msg("Missing 'id' argument"),
                            };
                            let store = vs.get_or_create(&ctx.session_id);
                            match store.get(var_id) {
                                Some(stored) => {
                                    // Taint the session context label
                                    sess.update_context_label(&ctx.session_id, stored.label);
                                    // label tracking placeholder: stored.label not propagated via CallToolResult
                                    CallToolResult::success(stored.content)
                                }
                                None => CallToolResult::error_msg(format!(
                                    "Variable not found: {var_id}"
                                )),
                            }
                        })
                    }),
                },
            );

            // navra_var_drop — remove a variable from the store
            let vs = value_stores.clone();
            tools.insert(
                "navra_var_drop".to_string(),
                RegisteredTool {
                    definition: ToolDefinition::new(
                        "navra_var_drop",
                        "Remove a variable from the session store",
                        navra_protocol::compat::tool_input_schema(
                            Some(std::collections::HashMap::from([(
                                "id".to_string(),
                                serde_json::json!({"type": "string", "description": "Variable ID"}),
                            )])),
                            Some(vec!["id".to_string()]),
                        ),
                    ),
                    handler: Arc::new(move |args, ctx| {
                        let vs = vs.clone();
                        Box::pin(async move {
                            let var_id = match args.get("id").and_then(|v| v.as_str()) {
                                Some(id) => id,
                                None => return CallToolResult::error_msg("Missing 'id' argument"),
                            };
                            let store = vs.get_or_create(&ctx.session_id);
                            match store.remove(var_id) {
                                Some(_) => {
                                    CallToolResult::text(format!("Variable {var_id} removed"))
                                }
                                None => CallToolResult::error_msg(format!(
                                    "Variable not found: {var_id}"
                                )),
                            }
                        })
                    }),
                },
            );
        }

        let process_table = self.process_table.unwrap_or_default();
        let blackbox = self.blackbox;

        // Register kernel state resources (navra:// scheme)
        let mut resources = self.resources;
        let mut resource_templates = self.resource_templates;

        // navra://proc — process table snapshot
        {
            let pt = process_table.clone();
            resources.insert(
                "navra://proc".to_string(),
                RegisteredResource {
                    definition: crate::protocol::RawResource::new("navra://proc", "Process table")
                        .with_description("Connected agents, privilege rings, call counts")
                        .with_mime_type("application/json"),
                    handler: Arc::new(move |uri, _ctx| {
                        let pt = pt.clone();
                        Box::pin(async move {
                            let snapshot = pt.snapshot();
                            let json = serde_json::to_string_pretty(&snapshot).unwrap_or_default();
                            crate::protocol::ReadResourceResult::new(vec![
                                crate::protocol::ResourceContent::TextResourceContents {
                                    uri,
                                    mime_type: Some("application/json".to_string()),
                                    text: json,
                                    meta: None,
                                },
                            ])
                        })
                    }),
                },
            );
        }

        // navra://ifc/labels — all session taint labels
        {
            let sess = sessions.clone();
            resources.insert(
                "navra://ifc/labels".to_string(),
                RegisteredResource {
                    definition: crate::protocol::RawResource::new(
                        "navra://ifc/labels",
                        "IFC labels",
                    )
                    .with_description("Current IFC taint labels for all sessions")
                    .with_mime_type("application/json"),
                    handler: Arc::new(move |uri, _ctx| {
                        let sess = sess.clone();
                        Box::pin(async move {
                            let all = sess.list_all();
                            let labels: Vec<serde_json::Value> = all
                                .iter()
                                .map(|s| {
                                    serde_json::json!({
                                        "session_id": s.id,
                                        "agent": s.agent.name,
                                        "label": format!("{}", s.context_label),
                                    })
                                })
                                .collect();
                            let json = serde_json::to_string_pretty(&labels).unwrap_or_default();
                            crate::protocol::ReadResourceResult::new(vec![
                                crate::protocol::ResourceContent::TextResourceContents {
                                    uri,
                                    mime_type: Some("application/json".to_string()),
                                    text: json,
                                    meta: None,
                                },
                            ])
                        })
                    }),
                },
            );
        }

        // navra://audit/recent — last N blackbox entries
        {
            let bb = blackbox.clone();
            resources.insert(
                "navra://audit/recent".to_string(),
                RegisteredResource {
                    definition: crate::protocol::RawResource::new(
                        "navra://audit/recent",
                        "Recent audit entries",
                    )
                    .with_description("Last 50 blackbox audit entries")
                    .with_mime_type("application/json"),
                    handler: Arc::new(move |uri, _ctx| {
                        let bb = bb.clone();
                        Box::pin(async move {
                            let entries = bb
                                .as_ref()
                                .map(|b| {
                                    let recent = b.recent(50);
                                    serde_json::to_string_pretty(&recent).unwrap_or_default()
                                })
                                .unwrap_or_else(|| "[]".to_string());
                            crate::protocol::ReadResourceResult::new(vec![
                                crate::protocol::ResourceContent::TextResourceContents {
                                    uri,
                                    mime_type: Some("application/json".to_string()),
                                    text: entries,
                                    meta: None,
                                },
                            ])
                        })
                    }),
                },
            );
        }

        // navra://budget/gpu — GPU semaphore state (permits info)
        {
            resources.insert(
                "navra://budget/gpu".to_string(),
                RegisteredResource {
                    definition: crate::protocol::RawResource::new("navra://budget/gpu", "GPU budget")
                            .with_description("GPU semaphore: permits used/available")
                            .with_mime_type("application/json"),
                    handler: Arc::new(|uri, _ctx| {
                        Box::pin(async move {
                            let json = serde_json::json!({
                                "note": "GPU semaphore is managed per-flow; query flow executor for live permit state"
                            });
                            crate::protocol::ReadResourceResult::new(vec![
                                crate::protocol::ResourceContent::TextResourceContents {
                                    uri,
                                    mime_type: Some("application/json".to_string()),
                                    text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                                    meta: None,
                                },
                            ])
                        })
                    }),
                },
            );
        }

        // navra://proc/{agent}/taint — per-agent taint label (template)
        {
            let sess = sessions.clone();
            resource_templates.push(RegisteredResourceTemplate {
                template: crate::protocol::RawResourceTemplate::new(
                    "navra://proc/{agent}/taint",
                    "Agent taint label",
                )
                .with_description("Current IFC taint label for a specific agent session")
                .with_mime_type("application/json"),
                handler: Arc::new(move |uri, _ctx| {
                    let sess = sess.clone();
                    Box::pin(async move {
                        let agent_name = uri
                            .strip_prefix("navra://proc/")
                            .and_then(|rest| rest.strip_suffix("/taint"));
                        match agent_name {
                            Some(name) => {
                                let all = sess.list_all();
                                let matching: Vec<serde_json::Value> = all
                                    .iter()
                                    .filter(|s| s.agent.name == name)
                                    .map(|s| {
                                        serde_json::json!({
                                            "session_id": s.id,
                                            "agent": s.agent.name,
                                            "label": format!("{}", s.context_label),
                                        })
                                    })
                                    .collect();
                                let json =
                                    serde_json::to_string_pretty(&matching).unwrap_or_default();
                                crate::protocol::ReadResourceResult::new(vec![
                                    crate::protocol::ResourceContent::TextResourceContents {
                                        uri,
                                        mime_type: Some("application/json".to_string()),
                                        text: json,
                                        meta: None,
                                    },
                                ])
                            }
                            None => crate::protocol::ReadResourceResult::new(vec![
                                crate::protocol::ResourceContent::TextResourceContents {
                                    uri,
                                    mime_type: Some("application/json".to_string()),
                                    text: r#"{"error": "Invalid URI"}"#.to_string(),
                                    meta: None,
                                },
                            ]),
                        }
                    })
                }),
            });
        }

        // navra://proc/{agent}/capabilities — per-agent capability set (template)
        {
            let sess = sessions.clone();
            resource_templates.push(RegisteredResourceTemplate {
                template: crate::protocol::RawResourceTemplate::new(
                    "navra://proc/{agent}/capabilities",
                    "Agent capabilities",
                )
                .with_description("Active capability set for a specific agent")
                .with_mime_type("application/json"),
                handler: Arc::new(move |uri, _ctx| {
                    let sess = sess.clone();
                    Box::pin(async move {
                        let agent_name = uri
                            .strip_prefix("navra://proc/")
                            .and_then(|rest| rest.strip_suffix("/capabilities"));
                        match agent_name {
                            Some(name) => {
                                let all = sess.list_all();
                                let matching: Vec<serde_json::Value> = all
                                    .iter()
                                    .filter(|s| s.agent.name == name)
                                    .map(|s| {
                                        let caps = s.agent.capabilities.as_ref().map(|c| {
                                            serde_json::json!({
                                                "issuer_did": c.issuer_did,
                                                "subject_did": c.subject_did,
                                                "ring": c.ring,
                                                "paths": c.paths,
                                                "operations": c.operations,
                                                "tools": c.tools,
                                                "credentials": c.credentials,
                                                "expires_at": c.expires_at,
                                                "obo_sub": c.obo_sub,
                                            })
                                        });
                                        serde_json::json!({
                                            "session_id": s.id,
                                            "agent": s.agent.name,
                                            "permissions": s.agent.permissions,
                                            "capabilities": caps,
                                        })
                                    })
                                    .collect();
                                let json =
                                    serde_json::to_string_pretty(&matching).unwrap_or_default();
                                crate::protocol::ReadResourceResult::new(vec![
                                    crate::protocol::ResourceContent::TextResourceContents {
                                        uri,
                                        mime_type: Some("application/json".to_string()),
                                        text: json,
                                        meta: None,
                                    },
                                ])
                            }
                            None => crate::protocol::ReadResourceResult::new(vec![
                                crate::protocol::ResourceContent::TextResourceContents {
                                    uri,
                                    mime_type: Some("application/json".to_string()),
                                    text: r#"{"error": "Invalid URI"}"#.to_string(),
                                    meta: None,
                                },
                            ]),
                        }
                    })
                }),
            });
        }

        // Auto-classify any tools not already classified by upstream or overrides.
        for (name, tool) in &tools {
            if !self.tool_classifications.contains_key(name.as_str()) {
                let class = navra_auth::permissions::resource_class::classify_tool_heuristic(
                    name,
                    tool.definition.annotations.as_ref(),
                );
                self.tool_classifications.insert(name.clone(), class);
            }
        }

        McpServer {
            name: self.name,
            version: self.version,
            prompts: self.prompts,
            resources,
            resource_templates,
            sessions,
            authenticator,
            safety_pipelines: self.safety_pipelines,
            tool_permissions: self.tool_permissions,
            agent_operations: self.agent_operations,
            domain_rules: self.domain_rules,
            hooks,
            paused: Arc::new(AtomicBool::new(false)),
            max_sessions: self.max_sessions.unwrap_or(10_000),
            session_ttl_secs: self.session_ttl_secs.unwrap_or(3600),
            task_store: crate::a2a::TaskStore::new(),
            process_table,
            quota_engine: self.quota_engine.unwrap_or_default(),
            ifc_policies: self.ifc_policies.unwrap_or_default(),
            ifc_read_clearances: self.ifc_read_clearances.unwrap_or_default(),
            trusted_paths: self.trusted_paths.unwrap_or_default(),
            value_stores,
            blackbox,
            session_permissions: crate::permissions::SessionPermissionStore::new(),
            pending_permission_requests: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            broadcaster: self.broadcaster,
            #[cfg(feature = "cedar")]
            cedar_engine: self.cedar_engine,
            #[cfg(feature = "cedar")]
            cedar_action_version: self.cedar_action_version.unwrap_or_default(),
            #[cfg(feature = "opa")]
            opa_engine: self.opa_engine.map(std::sync::Mutex::new),
            dmn_engine: self.dmn_engine,
            tool_disclosure: self.tool_disclosure,
            hide_denied_tools: self.hide_denied_tools,
            declassification_authority: self.declassification_authority,
            declassification_ledger: self.declassification_ledger,
            declassification_witnesses: std::sync::Mutex::new(Vec::new()),
            tools: RwLock::new(tools),
            tool_operations: RwLock::new(self.tool_operations),
            tool_classifications: RwLock::new(self.tool_classifications),
            upstream_tool_index: RwLock::new(self.module_tool_index),
            upstream_watchers: RwLock::new(self.upstream_watchers),
            dynamic_filters: self.dynamic_filters,
            resource_subscriptions: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            session_log_levels: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            path_acls: self.path_acls,
            metrics: self
                .metrics
                .unwrap_or_else(|| std::sync::Arc::new(crate::metrics::Metrics::new())),
            mcp_version: self.mcp_version,
            enterprise_auth: self.enterprise_auth,
            tool_routing: self.tool_routing,
            upstream_modules: self.upstream_modules,
            concurrency_semaphores: dashmap::DashMap::new(),
        }
    }
}
