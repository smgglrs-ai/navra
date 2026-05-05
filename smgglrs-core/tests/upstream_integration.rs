//! Integration tests for the upstream MCP proxy.
//!
//! Uses a Python test server (test_upstream.py) that speaks MCP over stdio.

use smgglrs_core::protocol::{CallToolParams, GetPromptParams};
use smgglrs_core::upstream::Upstream;
use smgglrs_core::UpstreamModule;
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
        &["python3".to_string(), test_server_path().to_string_lossy().to_string()],
        None,
    )
    .await
    .expect("Failed to spawn upstream");

    let module = UpstreamModule::discover(upstream)
        .await
        .expect("Failed to discover");

    let tools: Vec<_> = smgglrs_core::Module::tools(&module);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].0.name, "echo");
}

#[tokio::test]
async fn upstream_spawn_and_discover_prompts() {
    let upstream = Upstream::spawn(
        "test",
        &["python3".to_string(), test_server_path().to_string_lossy().to_string()],
        None,
    )
    .await
    .expect("Failed to spawn upstream");

    let module = UpstreamModule::discover(upstream)
        .await
        .expect("Failed to discover");

    let prompts: Vec<_> = smgglrs_core::Module::prompts(&module);
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].0.name, "greeting");
}

#[tokio::test]
async fn upstream_call_tool_through_module() {
    let upstream = Upstream::spawn(
        "test",
        &["python3".to_string(), test_server_path().to_string_lossy().to_string()],
        None,
    )
    .await
    .expect("Failed to spawn upstream");

    let module = UpstreamModule::discover(upstream)
        .await
        .expect("Failed to discover");

    // Get the tool handler and call it
    let tools = smgglrs_core::Module::tools(&module);
    let (_def, handler) = &tools[0];

    let ctx = smgglrs_core::auth::CallContext::new(
        smgglrs_core::auth::AgentIdentity::new("tester", "dev"),
        "test",
    );

    let result = handler(serde_json::json!({"message": "hello"}), ctx).await;
    assert!(!result.is_error);
    match &result.content[0] {
        smgglrs_core::protocol::Content::Text(t) => assert_eq!(t.text, "echo: hello"),
        _ => panic!("expected text content"),
    }
}

#[tokio::test]
async fn upstream_get_prompt_through_module() {
    let upstream = Upstream::spawn(
        "test",
        &["python3".to_string(), test_server_path().to_string_lossy().to_string()],
        None,
    )
    .await
    .expect("Failed to spawn upstream");

    let module = UpstreamModule::discover(upstream)
        .await
        .expect("Failed to discover");

    let prompts = smgglrs_core::Module::prompts(&module);
    let (_def, handler) = &prompts[0];

    let result = handler(std::collections::HashMap::new()).await;
    assert_eq!(result.description, Some("Greeting".to_string()));
    assert_eq!(result.messages.len(), 1);
    match &result.messages[0].content {
        smgglrs_core::protocol::Content::Text(t) => {
            assert_eq!(t.text, "Hello from upstream!");
        }
        _ => panic!("expected text content"),
    }
}

#[tokio::test]
async fn upstream_registers_in_server() {
    let upstream = Upstream::spawn(
        "test",
        &["python3".to_string(), test_server_path().to_string_lossy().to_string()],
        None,
    )
    .await
    .expect("Failed to spawn upstream");

    let module = UpstreamModule::discover(upstream)
        .await
        .expect("Failed to discover");

    let server = smgglrs_core::McpServer::builder()
        .module(module)
        .build();

    // 1 upstream tool + 3 gateway tools (smgglrs_var_*)
    assert_eq!(server.tool_count(), 4);
    assert_eq!(server.prompt_count(), 1);

    // Verify tools/list includes the upstream tool
    let agent = smgglrs_core::auth::AgentIdentity::new("test", "dev");
    let tools_result = server.handle_list_tools(&agent, &Default::default());
    assert!(tools_result.tools.iter().any(|t| t.name == "echo"));

    // Verify prompts/list includes the upstream prompt
    let prompts_result = server.handle_list_prompts(&agent, &Default::default());
    assert!(prompts_result.prompts.iter().any(|p| p.name == "greeting"));
}
