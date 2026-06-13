//! Integration tests for the upstream MCP proxy.
//!
//! Uses a Python test server (test_upstream.py) that speaks MCP over stdio.

use navra_core::permissions::{Domain, DomainRules, Operation, ResourceClass};
use navra_core::protocol::{CallToolParams, GetPromptParams};
use navra_core::upstream::Upstream;
use navra_core::UpstreamModule;
use std::path::PathBuf;

fn test_server_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_upstream.py")
}

#[tokio::test]
async fn upstream_spawn_and_discover_tools() {
    let upstream = Upstream::spawn(
        "test",
        &[
            "python3".to_string(),
            test_server_path().to_string_lossy().to_string(),
        ],
        None,
    )
    .await
    .expect("Failed to spawn upstream");

    let module = UpstreamModule::discover(upstream, None, &Default::default())
        .await
        .expect("Failed to discover");

    let tools: Vec<_> = navra_core::Module::tools(&module);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].0.name, "echo");
}

#[tokio::test]
async fn upstream_spawn_and_discover_prompts() {
    let upstream = Upstream::spawn(
        "test",
        &[
            "python3".to_string(),
            test_server_path().to_string_lossy().to_string(),
        ],
        None,
    )
    .await
    .expect("Failed to spawn upstream");

    let module = UpstreamModule::discover(upstream, None, &Default::default())
        .await
        .expect("Failed to discover");

    let prompts: Vec<_> = navra_core::Module::prompts(&module);
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].0.name, "greeting");
}

#[tokio::test]
async fn upstream_call_tool_through_module() {
    let upstream = Upstream::spawn(
        "test",
        &[
            "python3".to_string(),
            test_server_path().to_string_lossy().to_string(),
        ],
        None,
    )
    .await
    .expect("Failed to spawn upstream");

    let module = UpstreamModule::discover(upstream, None, &Default::default())
        .await
        .expect("Failed to discover");

    // Get the tool handler and call it
    let tools = navra_core::Module::tools(&module);
    let (_def, handler) = &tools[0];

    let ctx = navra_core::auth::CallContext::new(
        navra_core::auth::AgentIdentity::new("tester", "dev"),
        "test",
    );

    let result = handler(serde_json::json!({"message": "hello"}), ctx).await;
    assert!(!result.is_error);
    match &result.content[0] {
        navra_core::protocol::Content::Text(t) => assert_eq!(t.text, "echo: hello"),
        _ => panic!("expected text content"),
    }
}

#[tokio::test]
async fn upstream_get_prompt_through_module() {
    let upstream = Upstream::spawn(
        "test",
        &[
            "python3".to_string(),
            test_server_path().to_string_lossy().to_string(),
        ],
        None,
    )
    .await
    .expect("Failed to spawn upstream");

    let module = UpstreamModule::discover(upstream, None, &Default::default())
        .await
        .expect("Failed to discover");

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
        navra_core::protocol::Content::Text(t) => {
            assert_eq!(t.text, "Hello from upstream!");
        }
        _ => panic!("expected text content"),
    }
}

#[tokio::test]
async fn upstream_registers_in_server() {
    let upstream = Upstream::spawn(
        "test",
        &[
            "python3".to_string(),
            test_server_path().to_string_lossy().to_string(),
        ],
        None,
    )
    .await
    .expect("Failed to spawn upstream");

    let module = UpstreamModule::discover(upstream, None, &Default::default())
        .await
        .expect("Failed to discover");

    let server = navra_core::McpServer::builder()
        .allow_anonymous()
        .module(module)
        .build();

    // 1 upstream tool + 3 gateway tools (navra_var_*)
    assert_eq!(server.tool_count(), 4);
    assert_eq!(server.prompt_count(), 1);

    // Verify tools/list includes the upstream tool
    let agent = navra_core::auth::AgentIdentity::new("test", "dev");
    let tools_result = server.handle_list_tools(&agent, &Default::default());
    assert!(tools_result.tools.iter().any(|t| t.name == "echo"));

    // Verify prompts/list includes the upstream prompt
    let prompts_result = server.handle_list_prompts(&agent, &Default::default());
    assert!(prompts_result.prompts.iter().any(|p| p.name == "greeting"));
}

// --- Domain-based permission enforcement tests ---

fn domain_rules_readonly() -> DomainRules {
    use std::collections::{HashMap, HashSet};
    let mut rules = HashMap::new();
    rules.insert(Domain::Unknown, HashSet::from([Operation::Read]));
    // Deny all shell
    rules.insert(Domain::Shell, HashSet::new());
    DomainRules::new(rules)
}

fn domain_rules_deny_prompts() -> DomainRules {
    use std::collections::{HashMap, HashSet};
    let mut rules = HashMap::new();
    rules.insert(Domain::Unknown, HashSet::from([Operation::Read]));
    // Deny prompts
    rules.insert(Domain::Prompt, HashSet::new());
    DomainRules::new(rules)
}

#[tokio::test]
async fn domain_rules_block_write_tool() {
    let upstream = Upstream::spawn(
        "test",
        &[
            "python3".to_string(),
            test_server_path().to_string_lossy().to_string(),
        ],
        None,
    )
    .await
    .expect("spawn");

    let module = UpstreamModule::discover(upstream, None, &Default::default())
        .await
        .expect("discover");

    // Override echo tool classification to Shell:Execute
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
            CallToolParams {
                name: "echo".to_string(),
                arguments: serde_json::json!({"message": "test"}),
                meta: None,
            },
            ctx,
        )
        .await;

    assert!(
        result.is_error,
        "shell:execute should be denied for readonly"
    );
    let text = match &result.content[0] {
        navra_core::protocol::Content::Text(t) => &t.text,
        _ => panic!("expected text"),
    };
    assert!(
        text.contains("Permission denied"),
        "error should mention permission denied, got: {text}"
    );
}

#[tokio::test]
async fn domain_rules_allow_read_tool() {
    let upstream = Upstream::spawn(
        "test",
        &[
            "python3".to_string(),
            test_server_path().to_string_lossy().to_string(),
        ],
        None,
    )
    .await
    .expect("spawn");

    let module = UpstreamModule::discover(upstream, None, &Default::default())
        .await
        .expect("discover");

    // Classify echo as Unknown:Read (wildcard allows read)
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
            CallToolParams {
                name: "echo".to_string(),
                arguments: serde_json::json!({"message": "test"}),
                meta: None,
            },
            ctx,
        )
        .await;

    assert!(
        !result.is_error,
        "unknown:read should be allowed for readonly"
    );
}

#[tokio::test]
async fn domain_rules_block_prompts() {
    let upstream = Upstream::spawn(
        "test",
        &[
            "python3".to_string(),
            test_server_path().to_string_lossy().to_string(),
        ],
        None,
    )
    .await
    .expect("spawn");

    let module = UpstreamModule::discover(upstream, None, &Default::default())
        .await
        .expect("discover");

    let server = navra_core::McpServer::builder()
        .allow_anonymous()
        .domain_rules("restricted", domain_rules_deny_prompts())
        .module(module)
        .build();

    let agent = navra_core::auth::AgentIdentity::new("test", "restricted");

    // list_prompts should return empty
    let result = server.handle_list_prompts(&agent, &Default::default());
    assert!(
        result.prompts.is_empty(),
        "prompts should be hidden for restricted agent"
    );

    // get_prompt should be denied
    let result = server
        .handle_get_prompt(
            GetPromptParams {
                name: "greeting".to_string(),
                arguments: Default::default(),
            },
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
    // Backward compat: no domain_rules configured → no domain enforcement
    let upstream = Upstream::spawn(
        "test",
        &[
            "python3".to_string(),
            test_server_path().to_string_lossy().to_string(),
        ],
        None,
    )
    .await
    .expect("spawn");

    let module = UpstreamModule::discover(upstream, None, &Default::default())
        .await
        .expect("discover");

    let server = navra_core::McpServer::builder()
        .allow_anonymous()
        .module(module)
        .build();

    let agent = navra_core::auth::AgentIdentity::new("test", "dev");
    let ctx = navra_core::auth::CallContext::new(agent.clone(), "test-session");

    // Tool call should work
    let result = server
        .handle_call_tool(
            CallToolParams {
                name: "echo".to_string(),
                arguments: serde_json::json!({"message": "test"}),
                meta: None,
            },
            ctx,
        )
        .await;
    assert!(!result.is_error, "no domain_rules = no enforcement");

    // Prompts should be visible
    let prompts = server.handle_list_prompts(&agent, &Default::default());
    assert!(!prompts.prompts.is_empty(), "prompts should be visible");
}
