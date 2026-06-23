//! Integration tests for the upstream MCP proxy.
//!
//! Uses a Python test server (test_upstream.py) that speaks MCP over stdio.

use navra_core::permissions::{Domain, DomainRules, Operation, ResourceClass};
use navra_core::protocol::{CallToolParams, GetPromptParams};
use navra_core::UpstreamModule;
use std::path::PathBuf;

fn test_server_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_upstream.py")
}

async fn spawn_rmcp_peer(
) -> (rmcp::Peer<rmcp::RoleClient>, rmcp::service::RunningService<rmcp::RoleClient, ()>) {
    let mut cmd = tokio::process::Command::new("python3");
    cmd.arg(test_server_path().to_string_lossy().to_string());
    let transport = rmcp::transport::TokioChildProcess::new(cmd).expect("spawn transport");
    let client = rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport)
        .await
        .expect("rmcp init");
    let peer = client.peer().clone();
    (peer, client)
}

#[tokio::test]
async fn upstream_spawn_and_discover_tools() {
    let (peer, _client) = spawn_rmcp_peer().await;

    let module = UpstreamModule::discover("test", peer, None, &Default::default()).await;

    let tools: Vec<_> = navra_core::Module::tools(&module);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].0.name, "echo");
}

#[tokio::test]
async fn upstream_spawn_and_discover_prompts() {
    let (peer, _client) = spawn_rmcp_peer().await;

    let module = UpstreamModule::discover("test", peer, None, &Default::default()).await;

    let prompts: Vec<_> = navra_core::Module::prompts(&module);
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].0.name, "greeting");
}

#[tokio::test]
async fn upstream_call_tool_through_module() {
    let (peer, _client) = spawn_rmcp_peer().await;

    let module = UpstreamModule::discover("test", peer, None, &Default::default()).await;

    let tools = navra_core::Module::tools(&module);
    let (_def, handler) = &tools[0];

    let ctx = navra_core::auth::CallContext::new(
        navra_core::auth::AgentIdentity::new("tester", "dev"),
        "test",
    );

    let result = handler(serde_json::json!({"message": "hello"}), ctx).await;
    assert!(result.is_error != Some(true));
    match &result.content[0] {
        c if c.raw.as_text().is_some() => assert_eq!(c.raw.as_text().unwrap().text, "echo: hello"),
        _ => panic!("expected text content"),
    }
}

#[tokio::test]
async fn upstream_get_prompt_through_module() {
    let (peer, _client) = spawn_rmcp_peer().await;

    let module = UpstreamModule::discover("test", peer, None, &Default::default()).await;

    let prompts = navra_core::Module::prompts(&module);
    let (_def, handler) = &prompts[0];

    let ctx = navra_core::auth::CallContext::new(
        navra_core::auth::AgentIdentity::new("tester", "dev"),
        "test",
    );
    let result = handler(std::collections::HashMap::new(), ctx).await;
    assert_eq!(result.description, Some("Greeting".to_string()));
    assert_eq!(result.messages.len(), 1);
    match &result.messages[0].content {
        navra_protocol::PromptMessageContent::Text { text } => {
            assert_eq!(text, "Hello from upstream!");
        }
        _ => panic!("expected text content"),
    }
}

#[tokio::test]
async fn upstream_registers_in_server() {
    let (peer, _client) = spawn_rmcp_peer().await;

    let module = UpstreamModule::discover("test", peer, None, &Default::default()).await;

    let server = navra_core::McpServer::builder()
        .allow_anonymous()
        .module(module)
        .build();

    // 1 upstream tool + 3 gateway tools (navra_var_*)
    assert_eq!(server.tool_count(), 4);
    assert_eq!(server.prompt_count(), 1);

    let agent = navra_core::auth::AgentIdentity::new("test", "dev");
    let tools_result = server.handle_list_tools(&agent, &Default::default());
    assert!(tools_result.tools.iter().any(|t| t.name == "echo"));

    let prompts_result = server.handle_list_prompts(&agent, &Default::default());
    assert!(prompts_result.prompts.iter().any(|p| p.name == "greeting"));
}

// --- Domain-based permission enforcement tests ---

fn domain_rules_readonly() -> DomainRules {
    use std::collections::{HashMap, HashSet};
    let mut rules = HashMap::new();
    rules.insert(Domain::Unknown, HashSet::from([Operation::Read]));
    rules.insert(Domain::Shell, HashSet::new());
    DomainRules::new(rules)
}

fn domain_rules_deny_prompts() -> DomainRules {
    use std::collections::{HashMap, HashSet};
    let mut rules = HashMap::new();
    rules.insert(Domain::Unknown, HashSet::from([Operation::Read]));
    rules.insert(Domain::Prompt, HashSet::new());
    DomainRules::new(rules)
}

#[tokio::test]
async fn domain_rules_block_write_tool() {
    let (peer, _client) = spawn_rmcp_peer().await;

    let module = UpstreamModule::discover("test", peer, None, &Default::default()).await;

    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "echo".to_string(),
        ResourceClass::new(Domain::Shell, Operation::Execute),
    );

    let server = navra_core::McpServer::builder()
        .allow_anonymous()
        .domain_rules("readonly", domain_rules_readonly())
        .merge_tool_classifications(overrides)
        .module(module)
        .build();

    let agent = navra_core::auth::AgentIdentity::new("test", "readonly");
    let ctx = navra_core::auth::CallContext::new(agent, "test-session");

    let result = server
        .handle_call_tool(
            { let mut p = CallToolParams::new("echo"); p.arguments = Some(serde_json::json!({"message": "test"}).as_object().unwrap().clone()); p },
            ctx,
        )
        .await;

    assert!(
        result.is_error == Some(true),
        "shell:execute should be denied for readonly"
    );
    let text = &result.content[0].raw.as_text().expect("expected text").text;
    assert!(
        text.contains("Permission denied"),
        "error should mention permission denied, got: {text}"
    );
}

#[tokio::test]
async fn domain_rules_allow_read_tool() {
    let (peer, _client) = spawn_rmcp_peer().await;

    let module = UpstreamModule::discover("test", peer, None, &Default::default()).await;

    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "echo".to_string(),
        ResourceClass::new(Domain::Unknown, Operation::Read),
    );

    let server = navra_core::McpServer::builder()
        .allow_anonymous()
        .domain_rules("readonly", domain_rules_readonly())
        .merge_tool_classifications(overrides)
        .module(module)
        .build();

    let agent = navra_core::auth::AgentIdentity::new("test", "readonly");
    let ctx = navra_core::auth::CallContext::new(agent, "test-session");

    let result = server
        .handle_call_tool(
            { let mut p = CallToolParams::new("echo"); p.arguments = Some(serde_json::json!({"message": "test"}).as_object().unwrap().clone()); p },
            ctx,
        )
        .await;

    assert!(
        result.is_error != Some(true),
        "unknown:read should be allowed for readonly"
    );
}

#[tokio::test]
async fn domain_rules_block_prompts() {
    let (peer, _client) = spawn_rmcp_peer().await;

    let module = UpstreamModule::discover("test", peer, None, &Default::default()).await;

    let server = navra_core::McpServer::builder()
        .allow_anonymous()
        .domain_rules("restricted", domain_rules_deny_prompts())
        .module(module)
        .build();

    let agent = navra_core::auth::AgentIdentity::new("test", "restricted");

    let result = server.handle_list_prompts(&agent, &Default::default());
    assert!(
        result.prompts.is_empty(),
        "prompts should be hidden for restricted agent"
    );

    let result = server
        .handle_get_prompt(
            GetPromptParams::new("greeting"),
            &agent,
            "test-session",
        )
        .await;
    assert!(result.is_err(), "get_prompt should be denied");
    assert!(
        result.unwrap_err().contains("Permission denied"),
        "error should mention permission denied"
    );
}

#[tokio::test]
async fn no_domain_rules_allows_everything() {
    let (peer, _client) = spawn_rmcp_peer().await;

    let module = UpstreamModule::discover("test", peer, None, &Default::default()).await;

    let server = navra_core::McpServer::builder()
        .allow_anonymous()
        .module(module)
        .build();

    let agent = navra_core::auth::AgentIdentity::new("test", "dev");
    let ctx = navra_core::auth::CallContext::new(agent.clone(), "test-session");

    let result = server
        .handle_call_tool(
            { let mut p = CallToolParams::new("echo"); p.arguments = Some(serde_json::json!({"message": "test"}).as_object().unwrap().clone()); p },
            ctx,
        )
        .await;
    assert!(result.is_error != Some(true), "no domain_rules = no enforcement");

    let prompts = server.handle_list_prompts(&agent, &Default::default());
    assert!(!prompts.prompts.is_empty(), "prompts should be visible");
}

fn domain_rules_deny_resources() -> DomainRules {
    use std::collections::{HashMap, HashSet};
    let mut rules = HashMap::new();
    rules.insert(Domain::Unknown, HashSet::from([Operation::Read]));
    rules.insert(Domain::Resource, HashSet::new());
    DomainRules::new(rules)
}

#[tokio::test]
async fn domain_rules_block_resources() {
    let (peer, _client) = spawn_rmcp_peer().await;

    let module = UpstreamModule::discover("test", peer, None, &Default::default()).await;

    let server = navra_core::McpServer::builder()
        .allow_anonymous()
        .domain_rules("restricted", domain_rules_deny_resources())
        .module(module)
        .build();

    let agent = navra_core::auth::AgentIdentity::new("test", "restricted");

    let result = server.handle_list_resources(&agent, &Default::default());
    assert!(
        result.resources.is_empty(),
        "resources should be hidden for restricted agent"
    );

    let templates = server.handle_list_resource_templates(&agent, &Default::default());
    assert!(
        templates.resource_templates.is_empty(),
        "resource templates should be hidden for restricted agent"
    );

    let result = server
        .handle_read_resource(
            navra_core::protocol::ReadResourceParams::new("test://status"),
            &agent,
            "test-session",
        )
        .await;
    assert!(result.is_err(), "read_resource should be denied");
    assert!(
        result.unwrap_err().contains("Permission denied"),
        "error should mention permission denied"
    );
}
