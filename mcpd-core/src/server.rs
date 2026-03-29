use crate::auth::{Authenticator, CallContext};
use crate::module::Module;
use crate::protocol::{
    CallToolParams, CallToolResult, InitializeParams, InitializeResult, ListToolsResult,
    ServerCapabilities, ServerInfo, ToolDefinition, ToolsCapability,
};
use crate::session::{Session, SessionStore};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
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

/// The MCP server, holding all state and tool registrations.
pub struct McpServer {
    pub(crate) name: String,
    pub(crate) version: String,
    tools: HashMap<String, RegisteredTool>,
    pub(crate) sessions: SessionStore,
    pub(crate) authenticator: Arc<dyn Authenticator>,
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
            resources: None,
        }
    }

    pub fn handle_initialize(&self, params: InitializeParams, agent_identity: crate::auth::AgentIdentity) -> InitializeResult {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = Session {
            id: session_id,
            agent: agent_identity,
            client_info: params.client_info,
            initialized: true,
        };
        self.sessions.create(session);

        InitializeResult {
            protocol_version: crate::protocol::PROTOCOL_VERSION.to_string(),
            capabilities: self.capabilities(),
            server_info: self.server_info(),
        }
    }

    pub fn handle_list_tools(&self) -> ListToolsResult {
        let tools = self.tools.values().map(|t| t.definition.clone()).collect();
        ListToolsResult { tools }
    }

    pub async fn handle_call_tool(
        &self,
        params: CallToolParams,
        ctx: CallContext,
    ) -> CallToolResult {
        match self.tools.get(&params.name) {
            Some(tool) => (tool.handler)(params.arguments, ctx).await,
            None => CallToolResult::error(format!("Unknown tool: {}", params.name)),
        }
    }

    pub fn sessions(&self) -> &SessionStore {
        &self.sessions
    }

    pub fn authenticator(&self) -> &dyn Authenticator {
        self.authenticator.as_ref()
    }

    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }
}

/// Builder for constructing an McpServer.
pub struct McpServerBuilder {
    name: String,
    version: String,
    tools: HashMap<String, RegisteredTool>,
    authenticator: Option<Arc<dyn Authenticator>>,
}

impl McpServerBuilder {
    fn new() -> Self {
        Self {
            name: "mcpd".to_string(),
            version: "0.1.0".to_string(),
            tools: HashMap::new(),
            authenticator: None,
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

    /// Register all tools from a module.
    ///
    /// Panics if a tool name conflicts with an already-registered tool.
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
        self
    }

    pub fn authenticator(mut self, auth: impl Authenticator) -> Self {
        self.authenticator = Some(Arc::new(auth));
        self
    }

    pub fn build(self) -> McpServer {
        let authenticator = self.authenticator.unwrap_or_else(|| {
            Arc::new(crate::auth::NoAuthenticator {
                default_identity: crate::auth::AgentIdentity {
                    name: "anonymous".to_string(),
                    permissions: "readonly".to_string(),
                },
            })
        });

        McpServer {
            name: self.name,
            version: self.version,
            tools: self.tools,
            sessions: SessionStore::new(),
            authenticator,
        }
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
        AgentIdentity {
            name: "tester".to_string(),
            permissions: "dev".to_string(),
        }
    }

    fn test_ctx() -> CallContext {
        CallContext {
            agent: test_agent(),
            session_id: "test-session".to_string(),
        }
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

    #[test]
    fn builder_defaults() {
        let server = McpServer::builder().build();
        assert_eq!(server.name, "mcpd");
        assert!(server.tools.is_empty());
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
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "echo");
    }

    #[test]
    fn register_module() {
        let server = McpServer::builder()
            .module(TestModule)
            .build();

        let result = server.handle_list_tools();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "test_ping");
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

        assert_eq!(server.tool_count(), 2);
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
        let empty = McpServer::builder().build();
        assert!(empty.capabilities().tools.is_none());

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

        let result = server.handle_initialize(params, test_agent());
        assert_eq!(result.protocol_version, "2025-03-26");
        assert_eq!(result.server_info.name, "test");
        assert_eq!(server.sessions().count(), 1);
    }
}
