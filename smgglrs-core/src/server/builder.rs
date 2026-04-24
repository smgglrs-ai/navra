use crate::hooks::HookPipeline;
use crate::module::Module;
use crate::permissions::tool_rules::ToolPermissions;
use crate::protocol::CallToolResult;
use crate::quota::QuotaEngine;
use crate::safety::FilterPipeline;
use crate::session::SessionStore;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use super::types::{RegisteredPrompt, RegisteredResource, RegisteredTool};
use super::McpServer;

/// Builder for constructing an McpServer.
pub struct McpServerBuilder {
    name: String,
    version: String,
    tools: HashMap<String, RegisteredTool>,
    prompts: HashMap<String, RegisteredPrompt>,
    resources: HashMap<String, RegisteredResource>,
    authenticator: Option<Arc<dyn crate::auth::Authenticator>>,
    safety_pipelines: HashMap<String, FilterPipeline>,
    tool_permissions: HashMap<String, ToolPermissions>,
    hooks: Vec<Box<dyn crate::hooks::Hook>>,
    hook_timeout: std::time::Duration,
    quota_engine: Option<QuotaEngine>,
    ifc_policies: Option<HashMap<String, crate::ifc::TaintedWritePolicy>>,
    trusted_paths: Option<HashMap<String, Vec<String>>>,
    session_store: Option<SessionStore>,
    blackbox: Option<crate::blackbox::Blackbox>,
}

impl McpServerBuilder {
    pub(super) fn new() -> Self {
        Self {
            name: "smgglrs".to_string(),
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
            trusted_paths: None,
            session_store: None,
            blackbox: None,
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
        definition: crate::protocol::ToolDefinition,
        handler: impl Fn(serde_json::Value, crate::auth::CallContext) -> Pin<Box<dyn Future<Output = CallToolResult> + Send>>
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

    /// Set trusted path patterns for a permission set.
    ///
    /// Files matching these glob patterns keep their Trusted integrity
    /// label even when accessed via external read tools.
    pub fn trusted_paths(
        mut self,
        permission_set: impl Into<String>,
        paths: Vec<String>,
    ) -> Self {
        self.trusted_paths
            .get_or_insert_with(HashMap::new)
            .insert(permission_set.into(), paths);
        self
    }

    /// Enable the gateway-level blackbox (audit recorder).
    pub fn blackbox(mut self, bb: crate::blackbox::Blackbox) -> Self {
        self.blackbox = Some(bb);
        self
    }

    /// Use a custom session store backend (e.g. SQLite for persistence).
    /// If not set, sessions are stored in memory (lost on restart).
    pub fn session_store(mut self, store: SessionStore) -> Self {
        self.session_store = Some(store);
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

    pub fn build(self) -> McpServer {
        let authenticator = self.authenticator.unwrap_or_else(|| {
            tracing::error!(
                "No authenticator configured and allow_anonymous() not called. \
                 Falling back to NoAuthenticator — all connections will be \
                 accepted as anonymous. Add [[agents]] to config.toml or \
                 call .allow_anonymous() for intentional open access."
            );
            Arc::new(crate::auth::NoAuthenticator {
                default_identity: crate::auth::AgentIdentity::new("anonymous", "readonly"),
            })
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
            use crate::protocol::{ToolDefinition, ToolInputSchema};


            // smgglrs_var_list — list all variables in the session
            let vs = value_stores.clone();
            tools.insert(
                "smgglrs_var_list".to_string(),
                RegisteredTool {
                    definition: ToolDefinition {
                        name: "smgglrs_var_list".to_string(),
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

            // smgglrs_var_inspect — read a variable's content (taints context)
            let vs = value_stores.clone();
            let sess = sessions.clone();
            tools.insert(
                "smgglrs_var_inspect".to_string(),
                RegisteredTool {
                    definition: ToolDefinition {
                        name: "smgglrs_var_inspect".to_string(),
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

            // smgglrs_var_drop — remove a variable from the store
            let vs = value_stores.clone();
            tools.insert(
                "smgglrs_var_drop".to_string(),
                RegisteredTool {
                    definition: ToolDefinition {
                        name: "smgglrs_var_drop".to_string(),
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
            task_store: crate::a2a::TaskStore::new(),
            process_table: crate::process::ProcessTable::new(),
            quota_engine: self.quota_engine.unwrap_or_default(),
            ifc_policies: self.ifc_policies.unwrap_or_default(),
            trusted_paths: self.trusted_paths.unwrap_or_default(),
            value_stores,
            blackbox: self.blackbox,
        }
    }
}
