use super::*;
use crate::auth::AgentIdentity;
use crate::auth::CallContext;
use crate::module::{Module, PromptHandler, ResourceHandler};
use crate::protocol::{CallToolParams, CallToolResult, ToolDefinition, ToolInputSchema};
use std::collections::HashMap;
use std::sync::Arc;

fn echo_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "echo".to_string(),
        description: Some("Echoes input".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: None,
            required: None,
        },
        annotations: None,
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
                annotations: None,
            },
            Arc::new(|_args, _ctx| Box::pin(async { CallToolResult::text("pong") })),
        )]
    }
}

/// Number of gateway tools always registered (smgglrs_var_*).
const GATEWAY_TOOLS: usize = 3;

#[test]
fn builder_defaults() {
    let server = McpServer::builder().build();
    assert_eq!(server.name, "smgglrs");
    // Only gateway tools (smgglrs_var_list, smgglrs_var_inspect, smgglrs_var_drop)
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
            Box::pin(async move { CallToolResult::text(format!("echo: {args}")) })
        })
        .build();

    let result = server.handle_list_tools(&test_agent(), &Default::default());
    assert_eq!(result.tools.len(), 1 + GATEWAY_TOOLS);
    assert!(result.tools.iter().any(|t| t.name == "echo"));
}

#[test]
fn register_module() {
    let server = McpServer::builder().module(TestModule).build();

    let result = server.handle_list_tools(&test_agent(), &Default::default());
    assert_eq!(result.tools.len(), 1 + GATEWAY_TOOLS);
    assert!(result.tools.iter().any(|t| t.name == "test_ping"));
}

#[test]
fn register_multiple_modules() {
    struct AnotherModule;
    impl Module for AnotherModule {
        fn name(&self) -> &str {
            "another"
        }
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
                    annotations: None,
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
        fn name(&self) -> &str {
            "duplicate"
        }
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
                    annotations: None,
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
    let server = McpServer::builder().module(TestModule).build();

    let result = server
        .handle_call_tool(
            CallToolParams {
                name: "test_ping".to_string(),
                arguments: serde_json::json!({}),
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert!(!result.is_error);
    match &result.content[0] {
        crate::protocol::Content::Text(t) => assert_eq!(t.text, "pong"),
        _ => panic!("expected text content"),
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
                let msg = args
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("nil");
                CallToolResult::text(format!("echo: {msg}"))
            })
        })
        .build();

    let result = server
        .handle_call_tool(
            CallToolParams {
                name: "echo".to_string(),
                arguments: serde_json::json!({"message": "hello"}),
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert!(!result.is_error);
    match &result.content[0] {
        crate::protocol::Content::Text(t) => assert_eq!(t.text, "echo: hello"),
        _ => panic!("expected text content"),
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
                meta: None,
            },
            test_ctx(),
        )
        .await;
    assert!(result.is_error);
}

#[test]
fn handle_initialize_creates_session() {
    let server = McpServer::builder().name("test").build();
    let params = crate::protocol::InitializeParams {
        protocol_version: "2025-03-26".to_string(),
        capabilities: Default::default(),
        client_info: crate::protocol::ClientInfo {
            name: "client".to_string(),
            version: None,
        },
    };

    let (result, session_id) = server.handle_initialize(params, test_agent()).unwrap();
    assert_eq!(result.protocol_version, "2025-03-26");
    assert_eq!(result.server_info.name, "test");
    assert_eq!(server.sessions().count(), 1);
    assert!(!session_id.is_empty());
    assert!(server.sessions().get(&session_id).is_some());
}

#[test]
fn handle_initialize_rejects_empty_protocol_version() {
    let server = McpServer::builder().name("test").build();
    let params = crate::protocol::InitializeParams {
        protocol_version: "".to_string(),
        capabilities: Default::default(),
        client_info: crate::protocol::ClientInfo {
            name: "client".to_string(),
            version: None,
        },
    };

    let err = server.handle_initialize(params, test_agent()).unwrap_err();
    assert!(err.contains("protocol_version"));
    assert_eq!(server.sessions().count(), 0);
}

#[test]
fn handle_initialize_rejects_empty_client_name() {
    let server = McpServer::builder().name("test").build();
    let params = crate::protocol::InitializeParams {
        protocol_version: "2025-03-26".to_string(),
        capabilities: Default::default(),
        client_info: crate::protocol::ClientInfo {
            name: "".to_string(),
            version: None,
        },
    };

    let err = server.handle_initialize(params, test_agent()).unwrap_err();
    assert!(err.contains("client_info"));
    assert_eq!(server.sessions().count(), 0);
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
                meta: None,
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
        _ => panic!("expected text content"),
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
                meta: None,
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
                meta: None,
            },
            test_ctx(),
        )
        .await;

    // No safety profile configured → content passes through unmodified
    match &result.content[0] {
        crate::protocol::Content::Text(t) => {
            assert!(t.text.contains("AKIAIOSFODNN7EXAMPLE"));
        }
        _ => panic!("expected text content"),
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
            let name = args
                .get("name")
                .cloned()
                .unwrap_or_else(|| "world".to_string());
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
    let server = McpServer::builder().module(PromptModule).build();

    assert_eq!(server.prompt_count(), 1);
    let result = server.handle_list_prompts(&test_agent(), &Default::default());
    assert_eq!(result.prompts.len(), 1);
    assert_eq!(result.prompts[0].name, "greeting");
}

#[tokio::test]
async fn call_registered_prompt() {
    let server = McpServer::builder().module(PromptModule).build();

    let result = server
        .handle_get_prompt(
            crate::protocol::GetPromptParams {
                name: "greeting".to_string(),
                arguments: HashMap::from([("name".to_string(), "Alice".to_string())]),
            },
            &test_agent(),
        )
        .await;

    let result = result.unwrap();
    assert_eq!(result.description, Some("A greeting".to_string()));
    match &result.messages[0].content {
        crate::protocol::Content::Text(t) => assert_eq!(t.text, "Hello, Alice!"),
        _ => panic!("expected text content"),
    }
}

#[tokio::test]
async fn call_unknown_prompt() {
    let server = McpServer::builder().build();
    let result = server
        .handle_get_prompt(
            crate::protocol::GetPromptParams {
                name: "nonexistent".to_string(),
                arguments: HashMap::new(),
            },
            &test_agent(),
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unknown prompt"));
}

#[test]
fn capabilities_reflect_prompts() {
    let empty = McpServer::builder().build();
    assert!(empty.capabilities().prompts.is_none());

    let with_prompt = McpServer::builder().module(PromptModule).build();
    assert!(with_prompt.capabilities().prompts.is_some());
}

#[test]
#[should_panic(expected = "Prompt name conflict")]
fn duplicate_prompt_name_panics() {
    struct DuplicatePromptModule;
    impl Module for DuplicatePromptModule {
        fn name(&self) -> &str {
            "duplicate"
        }
        fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
            vec![]
        }
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
        size: None,
    }
}

fn info_resource_handler() -> ResourceHandler {
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
    fn name(&self) -> &str {
        "resource_test"
    }
    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        vec![]
    }
    fn resources(&self) -> Vec<(crate::protocol::ResourceDefinition, ResourceHandler)> {
        vec![(info_resource_def(), info_resource_handler())]
    }
}

#[test]
fn register_module_with_resources() {
    let server = McpServer::builder().module(ResourceModule).build();

    let base_count = McpServer::builder().build().resource_count();
    assert_eq!(server.resource_count(), base_count + 1);
    let result = server.handle_list_resources(&test_agent(), &Default::default());
    assert!(result
        .resources
        .iter()
        .any(|r| r.uri == "info://server/status"));
}

#[tokio::test]
async fn read_registered_resource() {
    let server = McpServer::builder().module(ResourceModule).build();

    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams {
                uri: "info://server/status".to_string(),
            },
            &test_agent(),
        )
        .await;

    let result = result.unwrap();
    assert_eq!(result.contents[0].text, Some("running".to_string()));
}

#[tokio::test]
async fn read_unknown_resource() {
    let server = McpServer::builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams {
                uri: "info://nonexistent".to_string(),
            },
            &test_agent(),
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unknown resource"));
}

#[test]
fn capabilities_reflect_resources() {
    // Kernel resources are always registered, so resources capability is always present
    let empty = McpServer::builder().build();
    assert!(empty.capabilities().resources.is_some());

    let with_resource = McpServer::builder().module(ResourceModule).build();
    assert!(with_resource.capabilities().resources.is_some());
}

#[test]
#[should_panic(expected = "Resource URI conflict")]
fn duplicate_resource_uri_panics() {
    struct DuplicateResourceModule;
    impl Module for DuplicateResourceModule {
        fn name(&self) -> &str {
            "duplicate"
        }
        fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
            vec![]
        }
        fn resources(&self) -> Vec<(crate::protocol::ResourceDefinition, ResourceHandler)> {
            vec![(info_resource_def(), info_resource_handler())]
        }
    }

    McpServer::builder()
        .module(ResourceModule)
        .module(DuplicateResourceModule)
        .build();
}

// --- Kernel resource tests ---

#[test]
fn kernel_resources_always_registered() {
    let server = McpServer::builder().build();
    let result = server.handle_list_resources(&test_agent(), &Default::default());
    let uris: Vec<&str> = result.resources.iter().map(|r| r.uri.as_str()).collect();
    assert!(uris.contains(&"smgglrs://proc"));
    assert!(uris.contains(&"smgglrs://ifc/labels"));
    assert!(uris.contains(&"smgglrs://audit/recent"));
    assert!(uris.contains(&"smgglrs://budget/gpu"));
}

#[tokio::test]
async fn kernel_resource_proc_returns_json() {
    let server = McpServer::builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams {
                uri: "smgglrs://proc".to_string(),
            },
            &test_agent(),
        )
        .await
        .unwrap();
    assert_eq!(
        result.contents[0].mime_type,
        Some("application/json".to_string())
    );
    let text = result.contents[0].text.as_ref().unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
    assert!(parsed.is_empty());
}

#[tokio::test]
async fn kernel_resource_proc_shows_active_agents() {
    let server = McpServer::builder().build();
    server
        .process_table()
        .record_call("test-agent", "dev", None, Some(1), "file_read");

    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams {
                uri: "smgglrs://proc".to_string(),
            },
            &test_agent(),
        )
        .await
        .unwrap();
    let text = result.contents[0].text.as_ref().unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["name"], "test-agent");
    assert_eq!(parsed[0]["call_count"], 1);
}

#[tokio::test]
async fn kernel_resource_ifc_labels_returns_json() {
    let server = McpServer::builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams {
                uri: "smgglrs://ifc/labels".to_string(),
            },
            &test_agent(),
        )
        .await
        .unwrap();
    let text = result.contents[0].text.as_ref().unwrap();
    let _: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
}

#[tokio::test]
async fn kernel_resource_audit_recent_returns_json() {
    let server = McpServer::builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams {
                uri: "smgglrs://audit/recent".to_string(),
            },
            &test_agent(),
        )
        .await
        .unwrap();
    let text = result.contents[0].text.as_ref().unwrap();
    let _: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
}

#[test]
fn kernel_resource_templates_registered() {
    let server = McpServer::builder().build();
    let result = server.handle_list_resource_templates(&test_agent(), &Default::default());
    let templates: Vec<&str> = result
        .resource_templates
        .iter()
        .map(|t| t.uri_template.as_str())
        .collect();
    assert!(templates.contains(&"smgglrs://proc/{agent}/taint"));
    assert!(templates.contains(&"smgglrs://proc/{agent}/capabilities"));
}

#[tokio::test]
async fn kernel_resource_template_taint_matches() {
    let server = McpServer::builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams {
                uri: "smgglrs://proc/test-agent/taint".to_string(),
            },
            &test_agent(),
        )
        .await;
    assert!(result.is_ok());
    let text = result.unwrap().contents[0]
        .text
        .as_ref()
        .unwrap()
        .to_string();
    let _: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
}

#[tokio::test]
async fn kernel_resource_template_capabilities_matches() {
    let server = McpServer::builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams {
                uri: "smgglrs://proc/my-agent/capabilities".to_string(),
            },
            &test_agent(),
        )
        .await;
    assert!(result.is_ok());
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
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert!(result.is_error);
    match &result.content[0] {
        crate::protocol::Content::Text(t) => {
            assert!(t.text.contains("Permission denied"));
        }
        _ => panic!("expected text content"),
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
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert!(!result.is_error);
    match &result.content[0] {
        crate::protocol::Content::Text(t) => assert_eq!(t.text, "reached"),
        _ => panic!("expected text content"),
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
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert!(result.is_error);
    match &result.content[0] {
        crate::protocol::Content::Text(t) => {
            assert!(t.text.contains("Approval required"));
        }
        _ => panic!("expected text content"),
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
                meta: None,
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
                obo_sub: None,
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
                meta: None,
            },
            cap_ctx(vec!["echo", "file_*"]),
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
                meta: None,
            },
            cap_ctx(vec!["*"]), // wildcard grants all
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
                meta: None,
            },
            cap_ctx(vec!["file_*", "git_*"]), // no match for "echo"
        )
        .await;

    assert!(result.is_error);
    match &result.content[0] {
        crate::protocol::Content::Text(t) => {
            assert!(t.text.contains("not in capability token"));
        }
        _ => panic!("expected text content"),
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
                meta: None,
            },
            cap_ctx(vec!["echo"]),
        )
        .await;

    // Cap token allows — tool_permissions not consulted
    assert!(!result.is_error);
}

// ========================================================================
// MCP spec compliance: dispatch handler tests (Phase 9i)
// ========================================================================

/// Helper to run a JSON-RPC request through the dispatch function.
async fn dispatch_request(
    server: &std::sync::Arc<super::McpServer>,
    method: &str,
    params: Option<serde_json::Value>,
    session_id: Option<String>,
) -> crate::protocol::JsonRpcResponse {
    let request =
        crate::protocol::JsonRpcRequest::new(method, params, crate::protocol::RequestId::Number(1));
    let (response, _) =
        crate::dispatch_for_test(server.clone(), request, test_agent(), session_id).await;
    response
}

/// Helper to initialize a session and return (server, session_id).
fn init_test_session() -> (std::sync::Arc<super::McpServer>, String) {
    let server = std::sync::Arc::new(super::McpServer::builder().name("test").build());
    let params = crate::protocol::InitializeParams {
        protocol_version: "2025-03-26".to_string(),
        capabilities: Default::default(),
        client_info: crate::protocol::ClientInfo {
            name: "test-client".to_string(),
            version: None,
        },
    };
    let (_, session_id) = server.handle_initialize(params, test_agent()).unwrap();
    (server, session_id)
}

#[tokio::test]
async fn dispatch_ping_returns_empty_object() {
    let (server, session_id) = init_test_session();
    let resp = dispatch_request(&server, "ping", None, Some(session_id)).await;
    assert!(resp.error.is_none());
    assert_eq!(resp.result.unwrap(), serde_json::json!({}));
}

#[tokio::test]
async fn dispatch_completion_complete_returns_empty_values() {
    let (server, session_id) = init_test_session();
    let resp = dispatch_request(
        &server,
        "completion/complete",
        Some(serde_json::json!({
            "ref": {"type": "ref/prompt", "name": "test"},
            "argument": {"name": "lang", "value": "py"}
        })),
        Some(session_id),
    )
    .await;
    assert!(resp.error.is_none());
    let result = resp.result.unwrap();
    assert!(result["completion"]["values"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!result["completion"]["hasMore"].as_bool().unwrap());
}

#[tokio::test]
async fn dispatch_logging_set_level_returns_success() {
    let (server, session_id) = init_test_session();
    let resp = dispatch_request(
        &server,
        "logging/setLevel",
        Some(serde_json::json!({"level": "warning"})),
        Some(session_id),
    )
    .await;
    assert!(resp.error.is_none());
    assert_eq!(resp.result.unwrap(), serde_json::json!({}));
}

#[tokio::test]
async fn dispatch_resources_subscribe_unknown_resource_fails() {
    let (server, session_id) = init_test_session();
    let resp = dispatch_request(
        &server,
        "resources/subscribe",
        Some(serde_json::json!({"uri": "file:///watched.md"})),
        Some(session_id),
    )
    .await;
    assert!(resp.error.is_some());
}

#[tokio::test]
async fn dispatch_resources_unsubscribe_without_subscribe_fails() {
    let (server, session_id) = init_test_session();
    let resp = dispatch_request(
        &server,
        "resources/unsubscribe",
        Some(serde_json::json!({"uri": "file:///watched.md"})),
        Some(session_id),
    )
    .await;
    assert!(resp.error.is_some());
}

#[tokio::test]
async fn dispatch_unknown_method_returns_method_not_found() {
    let (server, session_id) = init_test_session();
    let resp = dispatch_request(&server, "nonexistent/method", None, Some(session_id)).await;
    let error = resp.error.unwrap();
    assert_eq!(error.code, -32601);
    assert!(error.message.contains("nonexistent/method"));
}

#[tokio::test]
async fn dispatch_without_session_returns_error() {
    let server = std::sync::Arc::new(super::McpServer::builder().name("test").build());
    // Any method except "initialize" should require a session
    let resp = dispatch_request(&server, "tools/list", None, None).await;
    let error = resp.error.unwrap();
    assert_eq!(error.code, -32002);
    assert!(error.message.contains("Session required"));
}

#[tokio::test]
async fn dispatch_initialize_does_not_require_session() {
    let server = std::sync::Arc::new(super::McpServer::builder().name("test").build());
    let resp = dispatch_request(
        &server,
        "initialize",
        Some(serde_json::json!({
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test"}
        })),
        None,
    )
    .await;
    assert!(resp.error.is_none());
    let result = resp.result.unwrap();
    assert_eq!(result["protocolVersion"], "2025-03-26");
}

// ========================================================================
// MCP spec compliance: dispatch method tests
// ========================================================================

fn init_test_session_with_modules() -> (std::sync::Arc<super::McpServer>, String) {
    let server = std::sync::Arc::new(
        super::McpServer::builder()
            .name("test")
            .module(TestModule)
            .module(PromptModule)
            .module(ResourceModule)
            .build(),
    );
    let params = crate::protocol::InitializeParams {
        protocol_version: "2025-03-26".to_string(),
        capabilities: Default::default(),
        client_info: crate::protocol::ClientInfo {
            name: "test-client".to_string(),
            version: None,
        },
    };
    let (_, session_id) = server.handle_initialize(params, test_agent()).unwrap();
    (server, session_id)
}

#[tokio::test]
async fn dispatch_tools_list_returns_tools() {
    let (server, session_id) = init_test_session_with_modules();
    let resp = dispatch_request(&server, "tools/list", None, Some(session_id)).await;
    assert!(resp.error.is_none());
    let result = resp.result.unwrap();
    let tools = result["tools"].as_array().unwrap();
    assert!(!tools.is_empty());
}

#[tokio::test]
async fn dispatch_tools_call_echo_returns_result() {
    let (server, session_id) = init_test_session_with_modules();
    let resp = dispatch_request(
        &server,
        "tools/call",
        Some(serde_json::json!({
            "name": "test_ping",
            "arguments": {}
        })),
        Some(session_id),
    )
    .await;
    assert!(resp.error.is_none());
}

#[tokio::test]
async fn dispatch_tools_call_unknown_returns_error() {
    let (server, session_id) = init_test_session_with_modules();
    let resp = dispatch_request(
        &server,
        "tools/call",
        Some(serde_json::json!({
            "name": "nonexistent_tool",
            "arguments": {}
        })),
        Some(session_id),
    )
    .await;
    let result = resp.result.unwrap();
    assert_eq!(result["isError"], true);
}

#[tokio::test]
async fn dispatch_prompts_list_returns_prompts() {
    let (server, session_id) = init_test_session_with_modules();
    let resp = dispatch_request(&server, "prompts/list", None, Some(session_id)).await;
    assert!(resp.error.is_none());
    let result = resp.result.unwrap();
    let prompts = result["prompts"].as_array().unwrap();
    assert!(!prompts.is_empty());
}

#[tokio::test]
async fn dispatch_prompts_get_returns_messages() {
    let (server, session_id) = init_test_session_with_modules();
    let resp = dispatch_request(
        &server,
        "prompts/get",
        Some(serde_json::json!({
            "name": "greeting",
            "arguments": {"name": "Alice"}
        })),
        Some(session_id),
    )
    .await;
    assert!(resp.error.is_none());
    let result = resp.result.unwrap();
    let messages = result["messages"].as_array().unwrap();
    assert!(!messages.is_empty());
}

#[tokio::test]
async fn dispatch_prompts_get_unknown_returns_error() {
    let (server, session_id) = init_test_session_with_modules();
    let resp = dispatch_request(
        &server,
        "prompts/get",
        Some(serde_json::json!({
            "name": "nonexistent_prompt",
            "arguments": {}
        })),
        Some(session_id),
    )
    .await;
    assert!(resp.error.is_some());
}

#[tokio::test]
async fn dispatch_resources_list_returns_resources() {
    let (server, session_id) = init_test_session_with_modules();
    let resp = dispatch_request(&server, "resources/list", None, Some(session_id)).await;
    assert!(resp.error.is_none());
    let result = resp.result.unwrap();
    let resources = result["resources"].as_array().unwrap();
    assert!(!resources.is_empty());
}

#[tokio::test]
async fn dispatch_resources_read_returns_content() {
    let (server, session_id) = init_test_session_with_modules();
    let resp = dispatch_request(
        &server,
        "resources/read",
        Some(serde_json::json!({
            "uri": "info://server/status"
        })),
        Some(session_id),
    )
    .await;
    assert!(resp.error.is_none());
    let result = resp.result.unwrap();
    let contents = result["contents"].as_array().unwrap();
    assert!(!contents.is_empty());
}

#[tokio::test]
async fn dispatch_resources_read_unknown_returns_error() {
    let (server, session_id) = init_test_session_with_modules();
    let resp = dispatch_request(
        &server,
        "resources/read",
        Some(serde_json::json!({
            "uri": "info://nonexistent/resource"
        })),
        Some(session_id),
    )
    .await;
    assert!(resp.error.is_some());
}

// ========================================================================
// MCP spec compliance: error code tests (Phase 9i)
// ========================================================================

#[test]
fn error_code_parse_error() {
    let err = crate::protocol::JsonRpcError::parse_error();
    assert_eq!(err.code, -32700);
}

#[test]
fn error_code_invalid_request() {
    let err = crate::protocol::JsonRpcError::invalid_request("bad");
    assert_eq!(err.code, -32600);
}

#[test]
fn error_code_method_not_found() {
    let err = crate::protocol::JsonRpcError::method_not_found("foo");
    assert_eq!(err.code, -32601);
}

#[test]
fn error_code_invalid_params() {
    let err = crate::protocol::JsonRpcError::invalid_params("missing field");
    assert_eq!(err.code, -32602);
}

#[test]
fn error_code_internal_error() {
    let err = crate::protocol::JsonRpcError::internal("oops");
    assert_eq!(err.code, -32603);
}

#[test]
fn error_code_request_cancelled() {
    assert_eq!(crate::protocol::REQUEST_CANCELLED, -32001);
}

#[test]
fn error_code_content_too_large() {
    assert_eq!(crate::protocol::CONTENT_TOO_LARGE, -32002);
}

#[test]
fn error_code_enum_roundtrip() {
    use crate::protocol::ErrorCode;
    assert_eq!(ErrorCode::ParseError.code(), -32700);
    assert_eq!(ErrorCode::InvalidRequest.code(), -32600);
    assert_eq!(ErrorCode::MethodNotFound.code(), -32601);
    assert_eq!(ErrorCode::InvalidParams.code(), -32602);
    assert_eq!(ErrorCode::InternalError.code(), -32603);
    assert_eq!(ErrorCode::from_code(-32700), ErrorCode::ParseError);
    assert_eq!(ErrorCode::from_code(-32600), ErrorCode::InvalidRequest);
    assert_eq!(ErrorCode::from_code(-32601), ErrorCode::MethodNotFound);
    assert_eq!(ErrorCode::from_code(-32602), ErrorCode::InvalidParams);
    assert_eq!(ErrorCode::from_code(-32603), ErrorCode::InternalError);
}

// --- IFC (Information Flow Control) tests ---

fn read_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "file_read".to_string(),
        description: Some("Reads a file".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: None,
            required: None,
        },
        annotations: None,
    }
}

fn write_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "file_write".to_string(),
        description: Some("Writes a file".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: None,
            required: None,
        },
        annotations: None,
    }
}

#[tokio::test]
async fn ifc_deny_write_after_untrusted_read() {
    // Build server with IFC deny policy and both read + write tools
    let server = McpServer::builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async {
                // Simulate reading external file — handler returns trusted,
                // but is_external_read_tool("file_read") auto-labels Untrusted
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
                name: "file_read".to_string(),
                arguments: serde_json::json!({"path": "/tmp/file.md"}),
                meta: None,
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
                name: "file_write".to_string(),
                arguments: serde_json::json!({"path": "/tmp/out.md", "content": "exfiltrated"}),
                meta: None,
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
        _ => panic!("expected text content"),
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
                name: "file_write".to_string(),
                arguments: serde_json::json!({}),
                meta: None,
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
                name: "file_write".to_string(),
                arguments: serde_json::json!({}),
                meta: None,
            },
            ctx,
        )
        .await;
    assert!(!result.is_error);
}

#[tokio::test]
async fn ifc_read_tool_auto_labels_untrusted() {
    // file_read output should be auto-labeled as Untrusted
    let server = McpServer::builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("file data") })
        })
        .build();

    let result = server
        .handle_call_tool(
            CallToolParams {
                name: "file_read".to_string(),
                arguments: serde_json::json!({}),
                meta: None,
            },
            test_ctx(),
        )
        .await;

    // The result should be labeled Untrusted (confidentiality stays Public)
    assert_eq!(result.label.integrity, crate::ifc::Integrity::Untrusted);
    assert_eq!(
        result.label.confidentiality,
        crate::ifc::Confidentiality::Public
    );
}

#[tokio::test]
async fn ifc_trusted_path_keeps_trusted_label() {
    // file_read of a trusted path should stay Trusted
    let server = McpServer::builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("my code") })
        })
        .trusted_paths("dev", vec!["/home/user/Code/**".to_string()])
        .build();

    let result = server
        .handle_call_tool(
            CallToolParams {
                name: "file_read".to_string(),
                arguments: serde_json::json!({"path": "/home/user/Code/project/main.rs"}),
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert_eq!(result.label.integrity, crate::ifc::Integrity::Trusted);
}

#[tokio::test]
async fn ifc_untrusted_path_still_labeled_untrusted() {
    // file_read of a non-trusted path should be Untrusted
    let server = McpServer::builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("external data") })
        })
        .trusted_paths("dev", vec!["/home/user/Code/**".to_string()])
        .build();

    let result = server
        .handle_call_tool(
            CallToolParams {
                name: "file_read".to_string(),
                arguments: serde_json::json!({"path": "/tmp/untrusted.txt"}),
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert_eq!(result.label.integrity, crate::ifc::Integrity::Untrusted);
}

#[tokio::test]
async fn ifc_trusted_path_no_path_arg_labels_untrusted() {
    // file_read without a path argument should default to Untrusted
    let server = McpServer::builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("data") })
        })
        .trusted_paths("dev", vec!["/home/user/Code/**".to_string()])
        .build();

    let result = server
        .handle_call_tool(
            CallToolParams {
                name: "file_read".to_string(),
                arguments: serde_json::json!({}),
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert_eq!(result.label.integrity, crate::ifc::Integrity::Untrusted);
}

#[tokio::test]
async fn ifc_trusted_path_prevents_taint_so_write_succeeds() {
    // Full flow: read trusted path → session stays clean → write succeeds
    let server = McpServer::builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("my code") })
        })
        .tool(write_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("written") })
        })
        .ifc_policy("dev", crate::ifc::TaintedWritePolicy::Deny)
        .trusted_paths("dev", vec!["/home/user/Code/**".to_string()])
        .build();

    // Read from trusted path — should not taint session
    let sid = "trusted-session";
    let ctx = CallContext::new(test_agent(), sid);
    let _read_result = server
        .handle_call_tool(
            CallToolParams {
                name: "file_read".to_string(),
                arguments: serde_json::json!({"path": "/home/user/Code/main.rs"}),
                meta: None,
            },
            ctx,
        )
        .await;

    // Write — should succeed because session is not tainted
    let mut write_ctx = CallContext::new(test_agent(), sid);
    let persisted = server.sessions().context_label(sid);
    write_ctx.taint.absorb(persisted);

    let write_result = server
        .handle_call_tool(
            CallToolParams {
                name: "file_write".to_string(),
                arguments: serde_json::json!({"path": "/home/user/Code/out.rs", "content": "fn main() {}"}),
                meta: None,
            },
            write_ctx,
        )
        .await;
    assert!(!write_result.is_error);
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
        .hook(SafetyHook::single(
            "dev",
            crate::safety::build_pipeline("standard"),
        ))
        .build();

    let result = server
        .handle_call_tool(
            CallToolParams {
                name: "echo".to_string(),
                arguments: serde_json::json!({"message": "key = AKIAIOSFODNN7EXAMPLE"}),
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert!(!result.is_error);
    match &result.content[0] {
        crate::protocol::Content::Text(t) => {
            assert!(t.text.contains("[REDACTED:aws-key]"));
        }
        _ => panic!("expected text content"),
    }
}

#[tokio::test]
async fn hook_blocks_tool_call() {
    /// A pre-hook that blocks all tool calls.
    struct BlockAll;

    #[async_trait::async_trait]
    impl crate::hooks::Hook for BlockAll {
        fn name(&self) -> &str {
            "block-all"
        }
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
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert!(result.is_error);
    match &result.content[0] {
        crate::protocol::Content::Text(t) => {
            assert!(t.text.contains("blocked by test hook"));
        }
        _ => panic!("expected text content"),
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
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert!(!result.is_error);
    match &result.content[0] {
        crate::protocol::Content::Text(t) => {
            assert!(t.text.contains("[REDACTED:aws-key]"));
        }
        _ => panic!("expected text content"),
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
                meta: None,
            },
            test_ctx(),
        )
        .await;

    assert!(result.is_error);
    match &result.content[0] {
        crate::protocol::Content::Text(t) => {
            assert!(t.text.contains("paused"));
        }
        _ => panic!("expected text content"),
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
                meta: None,
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

// --- Permission negotiation tests ---

#[test]
fn permission_request_registers_pending() {
    let server = McpServer::builder().build();
    let params = smgglrs_protocol::permissions::PermissionRequestParams {
        id: "req-1".to_string(),
        scope: smgglrs_protocol::permissions::PermissionScope::ToolAccess {
            tool_name: "git_push".to_string(),
        },
        reason: "Need to push changes".to_string(),
        duration_secs: Some(3600),
    };

    let result = server.handle_permission_request(params, "session-1");
    assert_eq!(result.id, "req-1");
    assert_eq!(result.status, "pending");
}

#[test]
fn permission_grant_creates_dynamic_grant() {
    let server = McpServer::builder().build();
    let req_params = smgglrs_protocol::permissions::PermissionRequestParams {
        id: "req-grant".to_string(),
        scope: smgglrs_protocol::permissions::PermissionScope::ToolAccess {
            tool_name: "git_push".to_string(),
        },
        reason: "Need push".to_string(),
        duration_secs: None,
    };
    server.handle_permission_request(req_params, "s1");

    let grant_params = smgglrs_protocol::permissions::PermissionGrantParams {
        request_id: "req-grant".to_string(),
    };
    let result = server.handle_permission_grant(grant_params, "operator");
    assert!(result.is_ok());
    let grant = result.unwrap();
    assert_eq!(grant.request_id, "req-grant");
    assert_eq!(grant.granted_by, "operator");
    assert!(grant.expires_at.is_none());

    // Verify the grant is active in the session permission store
    assert!(server
        .session_permission_store()
        .check_tool("s1", "git_push"));
}

#[test]
fn permission_grant_with_duration() {
    let server = McpServer::builder().build();
    let req_params = smgglrs_protocol::permissions::PermissionRequestParams {
        id: "req-timed".to_string(),
        scope: smgglrs_protocol::permissions::PermissionScope::PathAccess {
            path: "/tmp/output".to_string(),
            operations: vec!["write".to_string()],
        },
        reason: "Need temp write access".to_string(),
        duration_secs: Some(60),
    };
    server.handle_permission_request(req_params, "s2");

    let grant_params = smgglrs_protocol::permissions::PermissionGrantParams {
        request_id: "req-timed".to_string(),
    };
    let result = server
        .handle_permission_grant(grant_params, "user")
        .unwrap();
    assert!(result.expires_at.is_some());
    // expires_at should be in the future
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(result.expires_at.unwrap() > now);
}

#[test]
fn permission_deny_removes_pending() {
    let server = McpServer::builder().build();
    let req_params = smgglrs_protocol::permissions::PermissionRequestParams {
        id: "req-deny".to_string(),
        scope: smgglrs_protocol::permissions::PermissionScope::ToolAccess {
            tool_name: "shell_exec".to_string(),
        },
        reason: "Want shell".to_string(),
        duration_secs: None,
    };
    server.handle_permission_request(req_params, "s3");

    let deny_params = smgglrs_protocol::permissions::PermissionDenyParams {
        request_id: "req-deny".to_string(),
        reason: Some("Too dangerous".to_string()),
    };
    let result = server.handle_permission_deny(deny_params);
    assert!(result.is_ok());

    // Tool should not be granted
    assert!(!server
        .session_permission_store()
        .check_tool("s3", "shell_exec"));
}

#[test]
fn permission_grant_unknown_request_fails() {
    let server = McpServer::builder().build();
    let grant_params = smgglrs_protocol::permissions::PermissionGrantParams {
        request_id: "nonexistent".to_string(),
    };
    let result = server.handle_permission_grant(grant_params, "user");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No pending request"));
}

#[test]
fn permission_deny_unknown_request_fails() {
    let server = McpServer::builder().build();
    let deny_params = smgglrs_protocol::permissions::PermissionDenyParams {
        request_id: "nonexistent".to_string(),
        reason: None,
    };
    let result = server.handle_permission_deny(deny_params);
    assert!(result.is_err());
}

#[test]
fn permission_list_returns_grants() {
    let server = McpServer::builder().build();

    // Initially empty
    let list = server.handle_permission_list("s4");
    assert!(list.grants.is_empty());

    // Add a grant
    let req_params = smgglrs_protocol::permissions::PermissionRequestParams {
        id: "req-list".to_string(),
        scope: smgglrs_protocol::permissions::PermissionScope::ToolAccess {
            tool_name: "file_write".to_string(),
        },
        reason: "Need write".to_string(),
        duration_secs: None,
    };
    server.handle_permission_request(req_params, "s4");
    let grant_params = smgglrs_protocol::permissions::PermissionGrantParams {
        request_id: "req-list".to_string(),
    };
    server
        .handle_permission_grant(grant_params, "user")
        .unwrap();

    let list = server.handle_permission_list("s4");
    assert_eq!(list.grants.len(), 1);
    assert_eq!(list.grants[0].request_id, "req-list");
    assert_eq!(list.grants[0].granted_by, "user");
}

#[test]
fn capabilities_include_permissions() {
    let server = McpServer::builder().build();
    assert!(server.capabilities().permissions.is_some());
}

#[tokio::test]
async fn dynamic_grant_overrides_tool_deny() {
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
                    policy: ToolPolicy::Deny,
                }],
                ToolPolicy::Allow,
            ),
        )
        .build();

    // Without dynamic grant, tool is denied
    let result = server
        .handle_call_tool(
            CallToolParams {
                name: "echo".to_string(),
                arguments: serde_json::json!({}),
                meta: None,
            },
            test_ctx(),
        )
        .await;
    assert!(result.is_error);

    // Grant the tool dynamically for the session
    let req_params = smgglrs_protocol::permissions::PermissionRequestParams {
        id: "req-override".to_string(),
        scope: smgglrs_protocol::permissions::PermissionScope::ToolAccess {
            tool_name: "echo".to_string(),
        },
        reason: "Need echo".to_string(),
        duration_secs: None,
    };
    server.handle_permission_request(req_params, "test-session");
    server
        .handle_permission_grant(
            smgglrs_protocol::permissions::PermissionGrantParams {
                request_id: "req-override".to_string(),
            },
            "user",
        )
        .unwrap();

    // Now the tool should be allowed via dynamic grant
    let result = server
        .handle_call_tool(
            CallToolParams {
                name: "echo".to_string(),
                arguments: serde_json::json!({}),
                meta: None,
            },
            test_ctx(),
        )
        .await;
    assert!(!result.is_error);
    match &result.content[0] {
        crate::protocol::Content::Text(t) => assert_eq!(t.text, "reached"),
        _ => panic!("expected text content"),
    }
}

// --- URI template matching tests ---

#[test]
fn uri_template_matching() {
    use super::handlers::matches_uri_template;

    assert!(matches_uri_template(
        "smgglrs://proc/{agent}/taint",
        "smgglrs://proc/alice/taint"
    ));
    assert!(matches_uri_template(
        "smgglrs://proc/{agent}/taint",
        "smgglrs://proc/my-agent/taint"
    ));
    assert!(!matches_uri_template(
        "smgglrs://proc/{agent}/taint",
        "smgglrs://proc//taint"
    ));
    assert!(!matches_uri_template(
        "smgglrs://proc/{agent}/taint",
        "smgglrs://proc/a/b/taint"
    ));
    assert!(!matches_uri_template(
        "smgglrs://proc/{agent}/taint",
        "smgglrs://other/alice/taint"
    ));
    assert!(matches_uri_template(
        "smgglrs://proc/{agent}/capabilities",
        "smgglrs://proc/bob/capabilities"
    ));
    assert!(!matches_uri_template(
        "smgglrs://proc/{agent}/capabilities",
        "smgglrs://proc/bob/taint"
    ));
    assert!(matches_uri_template("no-template", "no-template"));
    assert!(!matches_uri_template("no-template", "other"));
}

// --- Resource filtering tests (14c) ---

#[test]
fn resource_list_filtered_by_capability_token_globs() {
    use smgglrs_security::auth::capability::ResolvedCapabilities;

    let mut agent = AgentIdentity::new("cap-agent", "dev");
    agent.capabilities = Some(ResolvedCapabilities {
        issuer_did: "did:key:z6MkIssuer".to_string(),
        subject_did: "did:key:z6MkSubject".to_string(),
        ring: 2,
        paths: vec![],
        operations: std::collections::HashSet::new(),
        tools: vec!["smgglrs://proc*".to_string()],
        credentials: vec![],
        expires_at: u64::MAX,
        obo_sub: None,
    });

    let server = McpServer::builder().build();
    let result = server.handle_list_resources(&agent, &Default::default());

    // Only smgglrs://proc should be visible (matches glob)
    assert!(result.resources.iter().any(|r| r.uri == "smgglrs://proc"));
    assert!(!result
        .resources
        .iter()
        .any(|r| r.uri == "smgglrs://ifc/labels"));
    assert!(!result
        .resources
        .iter()
        .any(|r| r.uri == "smgglrs://audit/recent"));
    assert!(!result
        .resources
        .iter()
        .any(|r| r.uri == "smgglrs://budget/gpu"));
}

#[test]
fn resource_list_filtered_by_read_clearance() {
    use crate::ifc::{Confidentiality, ReadClearance, TaintedWritePolicy};

    let server = McpServer::builder()
        .ifc_read_clearance(
            "readonly",
            ReadClearance::new(Confidentiality::Public, TaintedWritePolicy::Deny),
        )
        .build();

    let agent = AgentIdentity::new("restricted", "readonly");
    let result = server.handle_list_resources(&agent, &Default::default());

    // Public resources visible
    assert!(result.resources.iter().any(|r| r.uri == "smgglrs://proc"));
    assert!(result
        .resources
        .iter()
        .any(|r| r.uri == "smgglrs://budget/gpu"));
    // Sensitive resources hidden
    assert!(!result
        .resources
        .iter()
        .any(|r| r.uri == "smgglrs://audit/recent"));
}

#[test]
fn resource_templates_filtered_by_read_clearance() {
    use crate::ifc::{Confidentiality, ReadClearance, TaintedWritePolicy};

    let server = McpServer::builder()
        .ifc_read_clearance(
            "readonly",
            ReadClearance::new(Confidentiality::Public, TaintedWritePolicy::Deny),
        )
        .build();

    let agent = AgentIdentity::new("restricted", "readonly");
    let result = server.handle_list_resource_templates(&agent, &Default::default());

    // Taint and capabilities templates are Sensitive — hidden from Public clearance
    assert!(result.resource_templates.is_empty());
}

#[test]
fn resource_list_no_filtering_without_caps_or_clearance() {
    let server = McpServer::builder().build();
    let agent = AgentIdentity::new("normal", "dev");
    let result = server.handle_list_resources(&agent, &Default::default());

    // All kernel resources visible when no restrictions
    assert!(result.resources.len() >= 4);
}
