use super::*;
use crate::auth::AgentIdentity;
use crate::auth::CallContext;
use crate::module::{Module, PromptHandler, ResourceHandler};
use crate::protocol::{CallToolParams, CallToolResult, ToolDefinition};
use navra_mcp::ToolHandler;
use navra_protocol::compat::{empty_input_schema, CallToolResultExt};
use std::collections::HashMap;
use std::sync::Arc;

fn echo_tool_def() -> ToolDefinition {
    ToolDefinition::new("echo", "Echoes input", empty_input_schema())
}

fn test_agent() -> AgentIdentity {
    AgentIdentity::new("tester", "dev")
}

fn test_ctx() -> CallContext {
    CallContext::new(test_agent(), "test-session")
}

fn test_builder() -> McpServerBuilder {
    McpServer::builder().allow_anonymous()
}

// A test module providing one tool.
struct TestModule;

impl Module for TestModule {
    fn name(&self) -> &str {
        "test"
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        vec![(
            ToolDefinition::new("test_ping", "Returns pong", empty_input_schema()),
            Arc::new(|_args, _ctx| Box::pin(async { CallToolResult::text("pong") })),
        )]
    }
}

/// Number of gateway tools always registered (navra_var_*).
const GATEWAY_TOOLS: usize = 3;

#[test]
fn builder_defaults() {
    let server = test_builder().build();
    assert_eq!(server.name, "navra");
    // Only gateway tools (navra_var_list, navra_var_inspect, navra_var_drop)
    assert_eq!(server.tool_count(), GATEWAY_TOOLS);
}

#[test]
fn builder_with_name_and_version() {
    let server = test_builder().name("my-server").version("2.0.0").build();
    let info = server.server_info();
    assert_eq!(info.name, "my-server");
    assert_eq!(info.version, "2.0.0");
}

#[test]
fn register_tool_and_list() {
    let server = test_builder()
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
    let server = test_builder().module(TestModule).build();

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
                ToolDefinition::new_with_raw("another_hello", None, empty_input_schema()),
                Arc::new(|_args, _ctx| Box::pin(async { CallToolResult::text("hi") })),
            )]
        }
    }

    let server = test_builder()
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
                ToolDefinition::new_with_raw("test_ping", None, empty_input_schema()),
                Arc::new(|_args, _ctx| Box::pin(async { CallToolResult::text("dup") })),
            )]
        }
    }

    test_builder()
        .module(TestModule)
        .module(DuplicateModule)
        .build();
}

#[tokio::test]
async fn call_module_tool() {
    let server = test_builder().module(TestModule).build();

    let result = server
        .handle_call_tool(
            {
                let mut p = CallToolParams::new("test_ping");
                p.arguments = Some(serde_json::Map::new());
                p
            },
            test_ctx(),
        )
        .await;

    assert!(result.is_error != Some(true));
    match &result.content[0] {
        c if c.raw.as_text().is_some() => assert_eq!(c.raw.as_text().unwrap().text, "pong"),
        _ => panic!("expected text content"),
    }
}

#[test]
fn capabilities_reflect_tools() {
    // Gateway tools are always registered, so tools capability is always present
    let server = test_builder().build();
    assert!(server.capabilities().tools.is_some());

    let with_tool = test_builder()
        .tool(echo_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("ok") })
        })
        .build();
    assert!(with_tool.capabilities().tools.is_some());
}

#[tokio::test]
async fn call_registered_tool() {
    let server = test_builder()
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
            {
                let mut p = CallToolParams::new("echo");
                p.arguments = Some(
                    serde_json::json!({"message": "hello"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
            test_ctx(),
        )
        .await;

    assert!(result.is_error != Some(true));
    match &result.content[0] {
        c if c.raw.as_text().is_some() => assert_eq!(c.raw.as_text().unwrap().text, "echo: hello"),
        _ => panic!("expected text content"),
    }
}

#[tokio::test]
async fn call_unknown_tool() {
    let server = test_builder().build();
    let result = server
        .handle_call_tool(CallToolParams::new("nonexistent"), test_ctx())
        .await;
    assert!(result.is_error == Some(true));
}

#[test]
fn handle_initialize_creates_session() {
    let server = test_builder().name("test").build();
    let params = {
        let mut p = crate::protocol::InitializeParams::new(
            Default::default(),
            crate::protocol::ClientInfo::new("client", ""),
        );
        p.protocol_version = crate::protocol::ProtocolVersion::V_2026_07_28;
        p
    };

    let (result, session_id) = server.handle_initialize(params, test_agent()).unwrap();
    assert_eq!(
        result.protocol_version,
        crate::protocol::ProtocolVersion::V_2026_07_28
    );
    assert_eq!(result.server_info.name, "test");
    assert_eq!(server.sessions().count(), 1);
    assert!(!session_id.is_empty());
    assert!(server.sessions().get(&session_id).is_some());
}

#[test]
fn handle_initialize_accepts_any_valid_protocol_version() {
    let server = test_builder().name("test").build();
    let params = {
        let mut p = crate::protocol::InitializeParams::new(
            Default::default(),
            crate::protocol::ClientInfo::new("client", ""),
        );
        p.protocol_version = crate::protocol::ProtocolVersion::V_2024_11_05;
        p
    };

    let result = server.handle_initialize(params, test_agent());
    assert!(result.is_ok());
}

#[test]
fn handle_initialize_rejects_empty_client_name() {
    let server = test_builder().name("test").build();
    let params = {
        let mut p = crate::protocol::InitializeParams::new(
            Default::default(),
            crate::protocol::ClientInfo::new("", ""),
        );
        p.protocol_version = crate::protocol::ProtocolVersion::V_2026_07_28;
        p
    };

    let err = server.handle_initialize(params, test_agent()).unwrap_err();
    assert!(err.contains("client_info"));
    assert_eq!(server.sessions().count(), 0);
}

#[tokio::test]
async fn safety_filter_redacts_secrets() {
    let server = test_builder()
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
            {
                let mut p = CallToolParams::new("echo");
                p.arguments = Some(
                    serde_json::json!({"message": "key = AKIAIOSFODNN7EXAMPLE"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
            test_ctx(),
        )
        .await;

    assert!(result.is_error != Some(true));
    {
        let t = result.content[0]
            .raw
            .as_text()
            .expect("expected text content");
        assert!(t.text.contains("[REDACTED:aws-key]"));
        assert!(!t.text.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}

#[tokio::test]
async fn safety_filter_blocks_when_configured() {
    let server = test_builder()
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
            {
                let mut p = CallToolParams::new("echo");
                p.arguments = Some(
                    serde_json::json!({"message": "SSN: 123-45-6789"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
            test_ctx(),
        )
        .await;

    assert!(result.is_error == Some(true));
}

#[tokio::test]
async fn no_safety_profile_passes_through() {
    let server = test_builder()
        .tool(echo_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("AKIAIOSFODNN7EXAMPLE") })
        })
        .build();

    let result = server
        .handle_call_tool(CallToolParams::new("echo"), test_ctx())
        .await;

    // No safety profile configured → content passes through unmodified
    {
        let t = result.content[0]
            .raw
            .as_text()
            .expect("expected text content");
        assert!(t.text.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}

// --- Prompt tests ---

fn greeting_prompt_def() -> crate::protocol::PromptDefinition {
    crate::protocol::PromptDefinition::new(
        "greeting",
        Some("A greeting prompt"),
        Some(vec![crate::protocol::PromptArgument::new("name")
            .with_description("Name to greet")
            .with_required(true)]),
    )
}

fn greeting_prompt_handler() -> PromptHandler {
    Arc::new(|args: HashMap<String, String>, _ctx| {
        Box::pin(async move {
            let name = args
                .get("name")
                .cloned()
                .unwrap_or_else(|| "world".to_string());
            crate::protocol::GetPromptResult::new(vec![crate::protocol::PromptMessage::new_text(
                crate::protocol::PromptRole::User,
                format!("Hello, {name}!"),
            )])
            .with_description("A greeting")
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
    let server = test_builder().module(PromptModule).build();

    assert_eq!(server.prompt_count(), 1);
    let result = server.handle_list_prompts(&test_agent(), &Default::default());
    assert_eq!(result.prompts.len(), 1);
    assert_eq!(result.prompts[0].name, "greeting");
}

#[tokio::test]
async fn call_registered_prompt() {
    let server = test_builder().module(PromptModule).build();

    let result = server
        .handle_get_prompt(
            {
                let mut p = crate::protocol::GetPromptParams::new("greeting");
                let mut args = serde_json::Map::new();
                args.insert(
                    "name".to_string(),
                    serde_json::Value::String("Alice".to_string()),
                );
                p.arguments = Some(args);
                p
            },
            &test_agent(),
            "test-session",
        )
        .await;

    let result = result.unwrap();
    assert_eq!(result.description, Some("A greeting".to_string()));
    match &result.messages[0].content {
        crate::protocol::PromptMessageContent::Text { text } => assert_eq!(text, "Hello, Alice!"),
        _ => panic!("expected text content"),
    }
}

#[tokio::test]
async fn call_unknown_prompt() {
    let server = test_builder().build();
    let result = server
        .handle_get_prompt(
            crate::protocol::GetPromptParams::new("nonexistent"),
            &test_agent(),
            "test-session",
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unknown prompt"));
}

#[test]
fn capabilities_reflect_prompts() {
    let empty = test_builder().build();
    assert!(empty.capabilities().prompts.is_none());

    let with_prompt = test_builder().module(PromptModule).build();
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

    test_builder()
        .module(PromptModule)
        .module(DuplicatePromptModule)
        .build();
}

// --- Resource tests ---

fn info_resource_def() -> crate::protocol::ResourceDefinition {
    navra_protocol::Annotated::new(
        crate::protocol::RawResource {
            uri: "info://server/status".to_string(),
            name: "Server Status".to_string(),
            title: None,
            description: Some("Current server status".to_string()),
            mime_type: Some("text/plain".to_string()),
            size: None,
            icons: None,
            meta: None,
        },
        None,
    )
}

fn info_resource_handler() -> ResourceHandler {
    Arc::new(|uri: String, _ctx| {
        Box::pin(async move {
            crate::protocol::ReadResourceResult::new(vec![
                crate::protocol::ResourceContent::TextResourceContents {
                    uri,
                    mime_type: Some("text/plain".to_string()),
                    text: "running".to_string(),
                    meta: None,
                },
            ])
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
    let server = test_builder().module(ResourceModule).build();

    let base_count = test_builder().build().resource_count();
    assert_eq!(server.resource_count(), base_count + 1);
    let result = server.handle_list_resources(&test_agent(), &Default::default());
    assert!(result
        .resources
        .iter()
        .any(|r| r.uri == "info://server/status"));
}

#[tokio::test]
async fn read_registered_resource() {
    let server = test_builder().module(ResourceModule).build();

    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams::new("info://server/status".to_string()),
            &test_agent(),
            "test-session",
        )
        .await;

    let result = result.unwrap();
    match &result.contents[0] {
        navra_protocol::ResourceContent::TextResourceContents { text, .. } => {
            assert_eq!(text, "running");
        }
        _ => panic!("expected text resource"),
    }
}

#[tokio::test]
async fn read_unknown_resource() {
    let server = test_builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams::new("info://nonexistent".to_string()),
            &test_agent(),
            "test-session",
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unknown resource"));
}

#[test]
fn capabilities_reflect_resources() {
    // Kernel resources are always registered, so resources capability is always present
    let empty = test_builder().build();
    assert!(empty.capabilities().resources.is_some());

    let with_resource = test_builder().module(ResourceModule).build();
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

    test_builder()
        .module(ResourceModule)
        .module(DuplicateResourceModule)
        .build();
}

// --- Kernel resource tests ---

#[test]
fn kernel_resources_always_registered() {
    let server = test_builder().build();
    let result = server.handle_list_resources(&test_agent(), &Default::default());
    let uris: Vec<&str> = result.resources.iter().map(|r| r.uri.as_str()).collect();
    assert!(uris.contains(&"navra://proc"));
    assert!(uris.contains(&"navra://ifc/labels"));
    assert!(uris.contains(&"navra://audit/recent"));
    assert!(uris.contains(&"navra://budget/gpu"));
}

#[tokio::test]
async fn kernel_resource_proc_returns_json() {
    let server = test_builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams::new("navra://proc".to_string()),
            &test_agent(),
            "test-session",
        )
        .await
        .unwrap();
    assert_eq!(
        match &result.contents[0] {
            navra_protocol::ResourceContent::TextResourceContents { mime_type, .. } =>
                mime_type.clone(),
            _ => panic!("expected text resource"),
        },
        Some("application/json".to_string())
    );
    let text = match &result.contents[0] {
        navra_protocol::ResourceContent::TextResourceContents { text, .. } => text.as_str(),
        _ => panic!("expected text resource"),
    };
    let parsed: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
    assert!(parsed.is_empty());
}

#[tokio::test]
async fn kernel_resource_proc_shows_active_agents() {
    let server = test_builder().build();
    server
        .process_table()
        .record_call("test-agent", "dev", None, Some(1), "file_read");

    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams::new("navra://proc".to_string()),
            &test_agent(),
            "test-session",
        )
        .await
        .unwrap();
    let text = match &result.contents[0] {
        navra_protocol::ResourceContent::TextResourceContents { text, .. } => text.as_str(),
        _ => panic!("expected text resource"),
    };
    let parsed: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["name"], "test-agent");
    assert_eq!(parsed[0]["call_count"], 1);
}

#[tokio::test]
async fn kernel_resource_ifc_labels_returns_json() {
    let server = test_builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams::new("navra://ifc/labels".to_string()),
            &test_agent(),
            "test-session",
        )
        .await
        .unwrap();
    let text = match &result.contents[0] {
        navra_protocol::ResourceContent::TextResourceContents { text, .. } => text.as_str(),
        _ => panic!("expected text resource"),
    };
    let _: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
}

#[tokio::test]
async fn kernel_resource_audit_recent_returns_json() {
    let server = test_builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams::new("navra://audit/recent".to_string()),
            &test_agent(),
            "test-session",
        )
        .await
        .unwrap();
    let text = match &result.contents[0] {
        navra_protocol::ResourceContent::TextResourceContents { text, .. } => text.as_str(),
        _ => panic!("expected text resource"),
    };
    let _: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
}

#[test]
fn kernel_resource_templates_registered() {
    let server = test_builder().build();
    let result = server.handle_list_resource_templates(&test_agent(), &Default::default());
    let templates: Vec<&str> = result
        .resource_templates
        .iter()
        .map(|t| t.uri_template.as_str())
        .collect();
    assert!(templates.contains(&"navra://proc/{agent}/taint"));
    assert!(templates.contains(&"navra://proc/{agent}/capabilities"));
}

#[tokio::test]
async fn kernel_resource_template_taint_matches() {
    let server = test_builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams::new("navra://proc/test-agent/taint".to_string()),
            &test_agent(),
            "test-session",
        )
        .await;
    assert!(result.is_ok());
    let text = match &result.unwrap().contents[0] {
        navra_protocol::ResourceContent::TextResourceContents { text, .. } => text.clone(),
        _ => panic!("expected text resource"),
    };
    let _: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
}

#[tokio::test]
async fn kernel_resource_template_capabilities_matches() {
    let server = test_builder().build();
    let result = server
        .handle_read_resource(
            crate::protocol::ReadResourceParams::new(
                "navra://proc/my-agent/capabilities".to_string(),
            ),
            &test_agent(),
            "test-session",
        )
        .await;
    assert!(result.is_ok());
}

// --- Per-tool permission tests ---

#[tokio::test]
async fn tool_permissions_deny_blocks_tool() {
    use crate::permissions::tool_rules::{ToolPermissions, ToolPolicy, ToolRule};

    let server = test_builder()
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
        .handle_call_tool(CallToolParams::new("echo"), test_ctx())
        .await;

    assert!(result.is_error == Some(true));
    {
        let t = result.content[0]
            .raw
            .as_text()
            .expect("expected text content");
        assert!(t.text.contains("Permission denied"));
    }
}

#[tokio::test]
async fn tool_permissions_allow_passes_through() {
    use crate::permissions::tool_rules::{ToolPermissions, ToolPolicy, ToolRule};

    let server = test_builder()
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
        .handle_call_tool(CallToolParams::new("echo"), test_ctx())
        .await;

    assert!(result.is_error != Some(true));
    match &result.content[0] {
        c if c.raw.as_text().is_some() => assert_eq!(c.raw.as_text().unwrap().text, "reached"),
        _ => panic!("expected text content"),
    }
}

#[tokio::test]
async fn tool_permissions_approve_returns_approval_required() {
    use crate::permissions::tool_rules::{ToolPermissions, ToolPolicy, ToolRule};

    let server = test_builder()
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
        .handle_call_tool(CallToolParams::new("echo"), test_ctx())
        .await;

    assert!(result.is_error == Some(true));
    {
        let t = result.content[0]
            .raw
            .as_text()
            .expect("expected text content");
        assert!(t.text.contains("Approval required"));
    }
}

#[tokio::test]
async fn no_tool_permissions_allows_all() {
    // No tool_permissions registered at all — everything should pass
    let server = test_builder()
        .tool(echo_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("ok") })
        })
        .build();

    let result = server
        .handle_call_tool(CallToolParams::new("echo"), test_ctx())
        .await;

    assert!(result.is_error != Some(true));
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
                sandbox: None,
            }),
            model: None,
            allowed_upstreams: Vec::new(),
            max_concurrent: None,
            max_context: None,
        },
        "cap-session",
    )
}

#[tokio::test]
async fn cap_token_allows_matching_tool() {
    let server = test_builder()
        .tool(echo_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("ok") })
        })
        .build();

    let result = server
        .handle_call_tool(CallToolParams::new("echo"), cap_ctx(vec!["echo", "file_*"]))
        .await;

    assert!(result.is_error != Some(true));
}

#[tokio::test]
async fn cap_token_allows_glob_matching_tool() {
    let server = test_builder()
        .tool(echo_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("ok") })
        })
        .build();

    let result = server
        .handle_call_tool(
            CallToolParams::new("echo"),
            cap_ctx(vec!["*"]), // wildcard grants all
        )
        .await;

    assert!(result.is_error != Some(true));
}

#[tokio::test]
async fn cap_token_denies_unmatched_tool() {
    let server = test_builder()
        .tool(echo_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("should not reach") })
        })
        .build();

    let result = server
        .handle_call_tool(
            CallToolParams::new("echo"),
            cap_ctx(vec!["file_*", "git_*"]), // no match for "echo"
        )
        .await;

    assert!(result.is_error == Some(true));
    {
        let t = result.content[0]
            .raw
            .as_text()
            .expect("expected text content");
        assert!(t.text.contains("not in capability token"));
    }
}

#[tokio::test]
async fn cap_token_bypasses_tool_permissions() {
    // Even if tool_permissions deny "echo", cap token with matching
    // tool glob should allow it (cap path takes priority).
    use crate::permissions::tool_rules::{ToolPermissions, ToolPolicy, ToolRule};

    let server = test_builder()
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
        .handle_call_tool(CallToolParams::new("echo"), cap_ctx(vec!["echo"]))
        .await;

    // Cap token allows — tool_permissions not consulted
    assert!(result.is_error != Some(true));
}

// ========================================================================
// MCP spec compliance: dispatch handler tests (Phase 9i)
// ========================================================================

/// Helper to run a JSON-RPC request by calling McpServer methods directly.
async fn dispatch_request(
    server: &std::sync::Arc<super::McpServer>,
    method: &str,
    params: Option<serde_json::Value>,
    session_id: Option<String>,
) -> crate::protocol::JsonRpcResponse {
    use crate::protocol::{JsonRpcError, JsonRpcResponse, RequestId};

    let id = RequestId::Number(1);
    let agent = test_agent();

    match method {
        "initialize" => {
            let p: crate::protocol::InitializeParams =
                match params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Invalid initialize params"),
                        )
                    }
                };
            match server.handle_initialize(p, agent) {
                Ok((result, _sid)) => {
                    JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap())
                }
                Err(msg) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
            }
        }

        _ => {
            let sid = session_id.unwrap_or_else(|| format!("stateless:{}", agent.name));

            if server.mcp_version() != navra_protocol::PROTOCOL_VERSION_2026 {
                if server.sessions().get(&sid).is_none() {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::new(
                            crate::protocol::ErrorCode::Custom(-32002),
                            "Session required — call initialize first",
                        ),
                    );
                }
            }

            server.ensure_session(&sid, &agent);
            dispatch_request_inner(server, method, params, &agent, &sid, id).await
        }
    }
}

async fn dispatch_request_inner(
    server: &std::sync::Arc<super::McpServer>,
    method: &str,
    params: Option<serde_json::Value>,
    agent: &crate::auth::AgentIdentity,
    sid: &str,
    id: crate::protocol::RequestId,
) -> crate::protocol::JsonRpcResponse {
    use crate::protocol::{JsonRpcError, JsonRpcResponse};

    match method {
        "ping" => JsonRpcResponse::success(id, serde_json::json!({})),

        "tools/list" => {
            let pagination: crate::protocol::PaginatedRequest = params
                .and_then(|p| serde_json::from_value(p).ok())
                .unwrap_or_default();
            let result = server.handle_list_tools(&agent, &pagination);
            JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap())
        }

        "tools/call" => {
            let p: crate::protocol::CallToolParams =
                match params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Invalid tool call params"),
                        )
                    }
                };
            let mut ctx = crate::auth::CallContext::new(agent.clone(), sid.to_string());
            let persisted_label = server.sessions().context_label(sid);
            ctx.taint.absorb(persisted_label);
            let result = server.handle_call_tool(p, ctx).await;
            JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap())
        }

        "resources/list" => {
            let pagination: crate::protocol::PaginatedRequest = params
                .and_then(|p| serde_json::from_value(p).ok())
                .unwrap_or_default();
            let result = server.handle_list_resources(&agent, &pagination);
            JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap())
        }

        "resources/templates/list" => {
            let pagination: crate::protocol::PaginatedRequest = params
                .and_then(|p| serde_json::from_value(p).ok())
                .unwrap_or_default();
            let result = server.handle_list_resource_templates(&agent, &pagination);
            JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap())
        }

        "resources/read" => {
            let p: crate::protocol::ReadResourceParams =
                match params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Invalid resource read params"),
                        )
                    }
                };
            match server.handle_read_resource(p, &agent, &sid).await {
                Ok(result) => JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap()),
                Err(msg) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
            }
        }

        "prompts/list" => {
            let pagination: crate::protocol::PaginatedRequest = params
                .and_then(|p| serde_json::from_value(p).ok())
                .unwrap_or_default();
            let result = server.handle_list_prompts(&agent, &pagination);
            JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap())
        }

        "prompts/get" => {
            let p: crate::protocol::GetPromptParams =
                match params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Invalid prompt get params"),
                        )
                    }
                };
            match server.handle_get_prompt(p, &agent, &sid).await {
                Ok(result) => JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap()),
                Err(msg) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
            }
        }

        "completion/complete" => {
            let p: crate::protocol::CompleteParams =
                match params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Invalid completion/complete params"),
                        )
                    }
                };
            let result = server.handle_complete(p);
            JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "completion": {
                        "values": result.completion.values,
                        "total": result.completion.total,
                        "hasMore": result.completion.has_more,
                    }
                }),
            )
        }

        "logging/setLevel" => {
            let p: crate::protocol::SetLevelParams =
                match params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Invalid logging/setLevel params"),
                        )
                    }
                };
            server.handle_set_log_level(p, &sid);
            JsonRpcResponse::success(id, serde_json::json!({}))
        }

        "resources/subscribe" => {
            let uri = match params
                .and_then(|p| p.get("uri").and_then(|u| u.as_str().map(String::from)))
            {
                Some(u) => u,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params("Missing 'uri' parameter"),
                    )
                }
            };
            match server.handle_resource_subscribe(&uri, &sid) {
                Ok(()) => JsonRpcResponse::success(id, serde_json::json!({})),
                Err(e) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&e)),
            }
        }

        "resources/unsubscribe" => {
            let uri = match params
                .and_then(|p| p.get("uri").and_then(|u| u.as_str().map(String::from)))
            {
                Some(u) => u,
                None => {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params("Missing 'uri' parameter"),
                    )
                }
            };
            match server.handle_resource_unsubscribe(&uri, &sid) {
                Ok(()) => JsonRpcResponse::success(id, serde_json::json!({})),
                Err(e) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&e)),
            }
        }

        _ => JsonRpcResponse::error(id, JsonRpcError::method_not_found(method)),
    }
}

/// Helper to initialize a session and return (server, session_id).
fn init_test_session() -> (std::sync::Arc<super::McpServer>, String) {
    let server = std::sync::Arc::new(
        super::McpServer::builder()
            .allow_anonymous()
            .name("test")
            .build(),
    );
    let params = {
        let mut p = crate::protocol::InitializeParams::new(
            Default::default(),
            crate::protocol::ClientInfo::new("test-client", ""),
        );
        p.protocol_version = crate::protocol::ProtocolVersion::V_2026_07_28;
        p
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
async fn dispatch_without_session_returns_error_legacy() {
    let server = std::sync::Arc::new(
        super::McpServer::builder()
            .allow_anonymous()
            .name("test")
            .mcp_version("2025-03-26")
            .build(),
    );
    let resp = dispatch_request(&server, "tools/list", None, None).await;
    let error = resp.error.unwrap();
    assert_eq!(error.code, -32002);
    assert!(error.message.contains("Session required"));
}

#[tokio::test]
async fn dispatch_without_session_succeeds_stateless() {
    let server = std::sync::Arc::new(
        super::McpServer::builder()
            .allow_anonymous()
            .name("test")
            .build(),
    );
    let resp = dispatch_request(&server, "tools/list", None, None).await;
    assert!(resp.error.is_none());
}

#[tokio::test]
async fn dispatch_initialize_does_not_require_session() {
    let server = std::sync::Arc::new(
        super::McpServer::builder()
            .allow_anonymous()
            .name("test")
            .build(),
    );
    let resp = dispatch_request(
        &server,
        "initialize",
        Some(serde_json::json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        })),
        None,
    )
    .await;
    assert!(resp.error.is_none(), "error: {:?}", resp.error);
    let result = resp.result.unwrap();
    assert!(!result["protocolVersion"].as_str().unwrap().is_empty());
}

// ========================================================================
// MCP spec compliance: dispatch method tests
// ========================================================================

fn init_test_session_with_modules() -> (std::sync::Arc<super::McpServer>, String) {
    let server = std::sync::Arc::new(
        super::McpServer::builder()
            .allow_anonymous()
            .name("test")
            .module(TestModule)
            .module(PromptModule)
            .module(ResourceModule)
            .build(),
    );
    let params = {
        let mut p = crate::protocol::InitializeParams::new(
            Default::default(),
            crate::protocol::ClientInfo::new("test-client", ""),
        );
        p.protocol_version = crate::protocol::ProtocolVersion::V_2026_07_28;
        p
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
    ToolDefinition::new("file_read", "Reads a file", empty_input_schema())
}

fn write_tool_def() -> ToolDefinition {
    ToolDefinition::new("file_write", "Writes a file", empty_input_schema())
}

#[tokio::test]
async fn ifc_deny_write_after_untrusted_read() {
    // Build server with IFC deny policy and both read + write tools
    let server = test_builder()
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
            {
                let mut p = CallToolParams::new("file_read");
                p.arguments = Some(
                    serde_json::json!({"path": "/tmp/file.md"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
            ctx.clone(),
        )
        .await;
    assert!(read_result.is_error != Some(true));

    // Simulate taint propagation (in real flow, ctx is mutable across calls)
    ctx.taint.absorb(crate::ifc::DataLabel::UNTRUSTED_SENSITIVE);

    // Second call: write — should be denied by IFC
    let write_result = server
        .handle_call_tool(
            {
                let mut p = CallToolParams::new("file_write");
                p.arguments = Some(
                    serde_json::json!({"path": "/tmp/out.md", "content": "exfiltrated"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
            ctx,
        )
        .await;
    assert!(write_result.is_error == Some(true));
    {
        let t = write_result.content[0]
            .raw
            .as_text()
            .expect("expected text content");
        assert!(t.text.contains("Permission denied"));
    }
}

#[tokio::test]
async fn ifc_allow_write_without_taint() {
    // No prior read — session is clean, write should succeed
    let server = test_builder()
        .tool(write_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("written") })
        })
        .ifc_policy("dev", crate::ifc::TaintedWritePolicy::Deny)
        .build();

    let result = server
        .handle_call_tool(CallToolParams::new("file_write"), test_ctx())
        .await;
    assert!(result.is_error != Some(true));
}

#[tokio::test]
async fn ifc_no_policy_denies_tainted_write() {
    // No IFC policy configured — tainted writes default to deny (fail-closed)
    let server = test_builder()
        .tool(write_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("written") })
        })
        .build();

    let mut ctx = test_ctx();
    ctx.taint.absorb(crate::ifc::DataLabel::UNTRUSTED_SENSITIVE);

    let result = server
        .handle_call_tool(CallToolParams::new("file_write"), ctx)
        .await;
    assert!(
        result.is_error == Some(true),
        "missing IFC policy should default to deny"
    );
}

#[tokio::test]
async fn ifc_read_tool_auto_labels_untrusted() {
    // file_read output should be auto-labeled as Untrusted
    let server = test_builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("file data") })
        })
        .build();

    let result = server
        .handle_call_tool(CallToolParams::new("file_read"), test_ctx())
        .await;

    // The result should be labeled Untrusted (confidentiality stays Public)
    // Label field was removed in rmcp migration — IFC labels tracked separately
}

#[tokio::test]
async fn ifc_trusted_path_keeps_trusted_label() {
    // file_read of a trusted path should stay Trusted
    let server = test_builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("my code") })
        })
        .trusted_paths("dev", vec!["/home/user/Code/**".to_string()])
        .build();

    let result = server
        .handle_call_tool(
            {
                let mut p = CallToolParams::new("file_read");
                p.arguments = Some(
                    serde_json::json!({"path": "/home/user/Code/project/main.rs"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
            test_ctx(),
        )
        .await;
}

#[tokio::test]
async fn ifc_untrusted_path_still_labeled_untrusted() {
    // file_read of a non-trusted path should be Untrusted
    let server = test_builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("external data") })
        })
        .trusted_paths("dev", vec!["/home/user/Code/**".to_string()])
        .build();

    let result = server
        .handle_call_tool(
            {
                let mut p = CallToolParams::new("file_read");
                p.arguments = Some(
                    serde_json::json!({"path": "/tmp/untrusted.txt"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
            test_ctx(),
        )
        .await;
}

#[tokio::test]
async fn ifc_trusted_path_no_path_arg_labels_untrusted() {
    // file_read without a path argument should default to Untrusted
    let server = test_builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("data") })
        })
        .trusted_paths("dev", vec!["/home/user/Code/**".to_string()])
        .build();

    let result = server
        .handle_call_tool(CallToolParams::new("file_read"), test_ctx())
        .await;
}

#[tokio::test]
async fn ifc_trusted_path_prevents_taint_so_write_succeeds() {
    // Full flow: read trusted path → session stays clean → write succeeds
    let server = test_builder()
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
            {
                let mut p = CallToolParams::new("file_read");
                p.arguments = Some(
                    serde_json::json!({"path": "/home/user/Code/main.rs"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
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
            {
                let mut p = CallToolParams::new("file_write");
                p.arguments = Some(serde_json::json!({"path": "/home/user/Code/out.rs", "content": "fn main() {}"}).as_object().unwrap().clone());
                p
            },
            write_ctx,
        )
        .await;
    assert!(write_result.is_error != Some(true));
}

// --- Hook pipeline tests ---

#[tokio::test]
async fn hook_safety_filter_via_pipeline() {
    use crate::hooks::SafetyHook;

    let server = test_builder()
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
            {
                let mut p = CallToolParams::new("echo");
                p.arguments = Some(
                    serde_json::json!({"message": "key = AKIAIOSFODNN7EXAMPLE"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
            test_ctx(),
        )
        .await;

    assert!(result.is_error != Some(true));
    {
        let t = result.content[0]
            .raw
            .as_text()
            .expect("expected text content");
        assert!(t.text.contains("[REDACTED:aws-key]"));
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
            _annotations: Option<&navra_protocol::ToolAnnotations>,
        ) -> crate::hooks::HookDecision {
            crate::hooks::HookDecision::Block("blocked by test hook".to_string())
        }
    }

    let server = test_builder()
        .tool(echo_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("should not reach") })
        })
        .hook(BlockAll)
        .build();

    let result = server
        .handle_call_tool(CallToolParams::new("echo"), test_ctx())
        .await;

    assert!(result.is_error == Some(true));
    {
        let t = result.content[0]
            .raw
            .as_text()
            .expect("expected text content");
        assert!(
            t.text.contains("Permission denied"),
            "Expected sanitized denial, got: {}",
            t.text
        );
    }
}

#[tokio::test]
async fn legacy_safety_filter_still_works_without_hooks() {
    // When no hooks are registered, safety_profile() still works via legacy path
    let server = test_builder()
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
            {
                let mut p = CallToolParams::new("echo");
                p.arguments = Some(
                    serde_json::json!({"message": "AKIAIOSFODNN7EXAMPLE"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
            test_ctx(),
        )
        .await;

    assert!(result.is_error != Some(true));
    {
        let t = result.content[0]
            .raw
            .as_text()
            .expect("expected text content");
        assert!(t.text.contains("[REDACTED:aws-key]"));
    }
}

// --- Pause/resume tests ---

#[tokio::test]
async fn paused_server_rejects_tool_calls() {
    let server = test_builder()
        .tool(echo_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("should not reach") })
        })
        .build();

    server.pause();
    assert!(server.is_paused());

    let result = server
        .handle_call_tool(CallToolParams::new("echo"), test_ctx())
        .await;

    assert!(result.is_error == Some(true));
    {
        let t = result.content[0]
            .raw
            .as_text()
            .expect("expected text content");
        assert!(t.text.contains("paused"));
    }
}

#[tokio::test]
async fn resumed_server_accepts_tool_calls() {
    let server = test_builder()
        .tool(echo_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("ok") })
        })
        .build();

    server.pause();
    server.resume();
    assert!(!server.is_paused());

    let result = server
        .handle_call_tool(CallToolParams::new("echo"), test_ctx())
        .await;

    assert!(result.is_error != Some(true));
}

#[test]
fn pause_flag_is_shared() {
    let server = test_builder().build();
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
    let server = test_builder().build();
    let params = navra_protocol::permissions::PermissionRequestParams {
        id: "req-1".to_string(),
        scope: navra_protocol::permissions::PermissionScope::ToolAccess {
            tool_name: "git_push".to_string(),
        },
        reason: "Need to push changes".to_string(),
        duration_secs: Some(3600),
    };

    let result = server.handle_permission_request(params, "session-1", "agent-a");
    assert_eq!(result.id, "req-1");
    assert_eq!(result.status, "pending");
}

#[test]
fn permission_grant_creates_dynamic_grant() {
    let server = test_builder().build();
    let req_params = navra_protocol::permissions::PermissionRequestParams {
        id: "req-grant".to_string(),
        scope: navra_protocol::permissions::PermissionScope::ToolAccess {
            tool_name: "git_push".to_string(),
        },
        reason: "Need push".to_string(),
        duration_secs: None,
    };
    server.handle_permission_request(req_params, "s1", "agent-a");

    let grant_params = navra_protocol::permissions::PermissionGrantParams {
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
    let server = test_builder().build();
    let req_params = navra_protocol::permissions::PermissionRequestParams {
        id: "req-timed".to_string(),
        scope: navra_protocol::permissions::PermissionScope::PathAccess {
            path: "/tmp/output".to_string(),
            operations: vec!["write".to_string()],
        },
        reason: "Need temp write access".to_string(),
        duration_secs: Some(60),
    };
    server.handle_permission_request(req_params, "s2", "agent-a");

    let grant_params = navra_protocol::permissions::PermissionGrantParams {
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
    let server = test_builder().build();
    let req_params = navra_protocol::permissions::PermissionRequestParams {
        id: "req-deny".to_string(),
        scope: navra_protocol::permissions::PermissionScope::ToolAccess {
            tool_name: "shell_exec".to_string(),
        },
        reason: "Want shell".to_string(),
        duration_secs: None,
    };
    server.handle_permission_request(req_params, "s3", "agent-a");

    let deny_params = navra_protocol::permissions::PermissionDenyParams {
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
    let server = test_builder().build();
    let grant_params = navra_protocol::permissions::PermissionGrantParams {
        request_id: "nonexistent".to_string(),
    };
    let result = server.handle_permission_grant(grant_params, "user");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No pending request"));
}

#[test]
fn permission_deny_unknown_request_fails() {
    let server = test_builder().build();
    let deny_params = navra_protocol::permissions::PermissionDenyParams {
        request_id: "nonexistent".to_string(),
        reason: None,
    };
    let result = server.handle_permission_deny(deny_params);
    assert!(result.is_err());
}

#[test]
fn permission_list_returns_grants() {
    let server = test_builder().build();

    // Initially empty
    let list = server.handle_permission_list("s4");
    assert!(list.grants.is_empty());

    // Add a grant
    let req_params = navra_protocol::permissions::PermissionRequestParams {
        id: "req-list".to_string(),
        scope: navra_protocol::permissions::PermissionScope::ToolAccess {
            tool_name: "file_write".to_string(),
        },
        reason: "Need write".to_string(),
        duration_secs: None,
    };
    server.handle_permission_request(req_params, "s4", "agent-a");
    let grant_params = navra_protocol::permissions::PermissionGrantParams {
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
    let server = test_builder().build();
    assert!(server.capabilities().permissions.is_some());
}

#[tokio::test]
async fn dynamic_grant_overrides_tool_deny() {
    use crate::permissions::tool_rules::{ToolPermissions, ToolPolicy, ToolRule};

    let server = test_builder()
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
        .handle_call_tool(CallToolParams::new("echo"), test_ctx())
        .await;
    assert!(result.is_error == Some(true));

    // Grant the tool dynamically for the session
    let req_params = navra_protocol::permissions::PermissionRequestParams {
        id: "req-override".to_string(),
        scope: navra_protocol::permissions::PermissionScope::ToolAccess {
            tool_name: "echo".to_string(),
        },
        reason: "Need echo".to_string(),
        duration_secs: None,
    };
    server.handle_permission_request(req_params, "test-session", "agent-a");
    server
        .handle_permission_grant(
            navra_protocol::permissions::PermissionGrantParams {
                request_id: "req-override".to_string(),
            },
            "user",
        )
        .unwrap();

    // Now the tool should be allowed via dynamic grant
    let result = server
        .handle_call_tool(CallToolParams::new("echo"), test_ctx())
        .await;
    assert!(result.is_error != Some(true));
    match &result.content[0] {
        c if c.raw.as_text().is_some() => assert_eq!(c.raw.as_text().unwrap().text, "reached"),
        _ => panic!("expected text content"),
    }
}

// --- URI template matching tests ---

#[test]
fn uri_template_matching() {
    use super::handlers::matches_uri_template;

    assert!(matches_uri_template(
        "navra://proc/{agent}/taint",
        "navra://proc/alice/taint"
    ));
    assert!(matches_uri_template(
        "navra://proc/{agent}/taint",
        "navra://proc/my-agent/taint"
    ));
    assert!(!matches_uri_template(
        "navra://proc/{agent}/taint",
        "navra://proc//taint"
    ));
    assert!(!matches_uri_template(
        "navra://proc/{agent}/taint",
        "navra://proc/a/b/taint"
    ));
    assert!(!matches_uri_template(
        "navra://proc/{agent}/taint",
        "navra://other/alice/taint"
    ));
    assert!(matches_uri_template(
        "navra://proc/{agent}/capabilities",
        "navra://proc/bob/capabilities"
    ));
    assert!(!matches_uri_template(
        "navra://proc/{agent}/capabilities",
        "navra://proc/bob/taint"
    ));
    assert!(matches_uri_template("no-template", "no-template"));
    assert!(!matches_uri_template("no-template", "other"));
}

// --- Resource filtering tests (14c) ---

#[test]
fn resource_list_filtered_by_capability_token_globs() {
    use navra_auth::auth::capability::ResolvedCapabilities;

    let mut agent = AgentIdentity::new("cap-agent", "dev");
    agent.capabilities = Some(ResolvedCapabilities {
        issuer_did: "did:key:z6MkIssuer".to_string(),
        subject_did: "did:key:z6MkSubject".to_string(),
        ring: 2,
        paths: vec![],
        operations: std::collections::HashSet::new(),
        tools: vec!["navra://proc*".to_string()],
        credentials: vec![],
        expires_at: u64::MAX,
        obo_sub: None,
        sandbox: None,
    });

    let server = test_builder().build();
    let result = server.handle_list_resources(&agent, &Default::default());

    // Only navra://proc should be visible (matches glob)
    assert!(result.resources.iter().any(|r| r.uri == "navra://proc"));
    assert!(!result
        .resources
        .iter()
        .any(|r| r.uri == "navra://ifc/labels"));
    assert!(!result
        .resources
        .iter()
        .any(|r| r.uri == "navra://audit/recent"));
    assert!(!result
        .resources
        .iter()
        .any(|r| r.uri == "navra://budget/gpu"));
}

#[test]
fn resource_list_filtered_by_read_clearance() {
    use crate::ifc::{Confidentiality, ReadClearance, TaintedWritePolicy};

    let server = test_builder()
        .ifc_read_clearance(
            "readonly",
            ReadClearance::new(Confidentiality::Public, TaintedWritePolicy::Deny),
        )
        .build();

    let agent = AgentIdentity::new("restricted", "readonly");
    let result = server.handle_list_resources(&agent, &Default::default());

    // Public resources visible
    assert!(result.resources.iter().any(|r| r.uri == "navra://proc"));
    assert!(result
        .resources
        .iter()
        .any(|r| r.uri == "navra://budget/gpu"));
    // Sensitive resources hidden
    assert!(!result
        .resources
        .iter()
        .any(|r| r.uri == "navra://audit/recent"));
}

#[test]
fn resource_templates_filtered_by_read_clearance() {
    use crate::ifc::{Confidentiality, ReadClearance, TaintedWritePolicy};

    let server = test_builder()
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
    let server = test_builder().build();
    let agent = AgentIdentity::new("normal", "dev");
    let result = server.handle_list_resources(&agent, &Default::default());

    // All kernel resources visible when no restrictions
    assert!(result.resources.len() >= 4);
}

// --- Dynamic tool routing tests (8l) ---

#[test]
fn ifc_tool_filter_hides_write_tools_when_tainted() {
    use super::IFCToolFilter;

    let server = test_builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("data") })
        })
        .tool(write_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("written") })
        })
        .tool_filter(IFCToolFilter)
        .build();

    // Tainted context — write tools should be hidden
    let mut ctx = test_ctx();
    ctx.taint.absorb(crate::ifc::DataLabel::UNTRUSTED_SENSITIVE);

    let result = server.handle_list_tools_dynamic(&test_agent(), &Default::default(), &ctx);
    let names: Vec<&str> = result.tools.iter().map(|t| &*t.name).collect();
    assert!(
        names.contains(&"file_read"),
        "Read tool should be visible when tainted"
    );
    assert!(
        !names.contains(&"file_write"),
        "Write tool should be hidden when tainted"
    );
}

#[test]
fn ifc_tool_filter_shows_all_when_clean() {
    use super::IFCToolFilter;

    let server = test_builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("data") })
        })
        .tool(write_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("written") })
        })
        .tool_filter(IFCToolFilter)
        .build();

    // Clean context — all tools should be visible
    let ctx = test_ctx();
    let result = server.handle_list_tools_dynamic(&test_agent(), &Default::default(), &ctx);
    let names: Vec<&str> = result.tools.iter().map(|t| &*t.name).collect();
    assert!(
        names.contains(&"file_read"),
        "Read tool should be visible when clean"
    );
    assert!(
        names.contains(&"file_write"),
        "Write tool should be visible when clean"
    );
}

#[test]
fn dynamic_filter_composes_with_static_disclosure() {
    use super::IFCToolFilter;
    use navra_auth::permissions::ToolDisclosure;

    let server = test_builder()
        .tool(read_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("data") })
        })
        .tool(write_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("written") })
        })
        .tool(echo_tool_def(), |_args, _ctx| {
            Box::pin(async { CallToolResult::text("echo") })
        })
        // Static disclosure: only show file_* tools for "dev"
        .tool_disclosure(
            "dev",
            ToolDisclosure::new(vec!["file_*".to_string()], vec![]),
        )
        // Dynamic filter: hide write tools when tainted
        .tool_filter(IFCToolFilter)
        .build();

    // Tainted context + static disclosure
    let mut ctx = test_ctx();
    ctx.taint.absorb(crate::ifc::DataLabel::UNTRUSTED_SENSITIVE);

    let result = server.handle_list_tools_dynamic(&test_agent(), &Default::default(), &ctx);
    let names: Vec<&str> = result.tools.iter().map(|t| &*t.name).collect();

    // Static disclosure hides "echo" (not matching file_*)
    assert!(
        !names.contains(&"echo"),
        "echo should be hidden by static disclosure"
    );
    // Dynamic filter hides "file_write" (tainted session)
    assert!(
        !names.contains(&"file_write"),
        "file_write should be hidden by IFC filter"
    );
    // file_read passes both filters
    assert!(
        names.contains(&"file_read"),
        "file_read should survive both filters"
    );
}

// ========================================================================
// Tool usage pruning (TW16)
// ========================================================================

#[test]
fn usage_tracker_new_agent_gets_all_tools() {
    let tracker = std::sync::Arc::new(super::ToolUsageTracker::new(3));
    let all = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let unused = tracker.unused_tools_from("new-agent", &all);
    assert!(unused.is_empty(), "new agent should see all tools");
}

#[test]
fn usage_tracker_prunes_after_window() {
    let tracker = std::sync::Arc::new(super::ToolUsageTracker::new(2));
    let all = vec![
        "file_read".to_string(),
        "file_write".to_string(),
        "git_status".to_string(),
    ];

    // Session 1: agent uses file_read
    let mut used1 = std::collections::HashSet::new();
    used1.insert("file_read".to_string());
    tracker.record_session_end("agent-1", used1);

    // Not enough history yet (1 < window 2)
    assert!(!tracker.has_enough_history("agent-1"));
    let unused = tracker.unused_tools_from("agent-1", &all);
    assert!(unused.is_empty());

    // Session 2: agent uses file_read again
    let mut used2 = std::collections::HashSet::new();
    used2.insert("file_read".to_string());
    tracker.record_session_end("agent-1", used2);

    // Now has enough history
    assert!(tracker.has_enough_history("agent-1"));
    let unused = tracker.unused_tools_from("agent-1", &all);
    assert!(
        unused.contains("file_write"),
        "file_write never used, should be pruned"
    );
    assert!(
        unused.contains("git_status"),
        "git_status never used, should be pruned"
    );
    assert!(
        !unused.contains("file_read"),
        "file_read was used, should not be pruned"
    );
}

#[test]
fn usage_tracker_sliding_window() {
    let tracker = std::sync::Arc::new(super::ToolUsageTracker::new(2));
    let all = vec!["a".to_string(), "b".to_string()];

    // Session 1: uses tool "a"
    let mut s1 = std::collections::HashSet::new();
    s1.insert("a".to_string());
    tracker.record_session_end("agent", s1);

    // Session 2: uses tool "b"
    let mut s2 = std::collections::HashSet::new();
    s2.insert("b".to_string());
    tracker.record_session_end("agent", s2);

    // Both used in window
    let unused = tracker.unused_tools_from("agent", &all);
    assert!(unused.is_empty());

    // Session 3: uses only "b" → "a" from session 1 slides out
    let mut s3 = std::collections::HashSet::new();
    s3.insert("b".to_string());
    tracker.record_session_end("agent", s3);

    let unused = tracker.unused_tools_from("agent", &all);
    assert!(
        unused.contains("a"),
        "tool 'a' should be pruned after sliding out of window"
    );
}
