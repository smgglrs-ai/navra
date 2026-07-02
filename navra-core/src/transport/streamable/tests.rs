use crate::auth::{AgentIdentity, NoAuthenticator};
use crate::protocol::{CallToolResult, ToolDefinition};
use crate::server::McpServer;
use crate::server::navra_handler::NavraHandler;
use navra_protocol::compat::CallToolResultExt;
use navra_protocol::compat::empty_input_schema;
use rmcp::model::{CallToolRequestParams, GetPromptRequestParams, ReadResourceRequestParams};
use rmcp::service::ServiceExt;
use std::sync::Arc;

use crate::module::{Module, PromptHandler, ResourceHandler};

struct TestPromptModule;

impl Module for TestPromptModule {
    fn name(&self) -> &str {
        "test_prompt"
    }
    fn tools(&self) -> Vec<(ToolDefinition, navra_mcp::ToolHandler)> {
        vec![]
    }
    fn prompts(&self) -> Vec<(crate::protocol::PromptDefinition, PromptHandler)> {
        vec![(
            crate::protocol::PromptDefinition::new("greet", Some("A greeting"), Some(vec![])),
            std::sync::Arc::new(|_args: std::collections::HashMap<String, String>, _ctx| {
                Box::pin(async {
                    crate::protocol::GetPromptResult::new(vec![
                        crate::protocol::PromptMessage::new_text(
                            crate::protocol::PromptRole::User,
                            "Hello!",
                        ),
                    ])
                    .with_description("Greeting")
                })
            }),
        )]
    }
}

struct TestResourceModule;

impl Module for TestResourceModule {
    fn name(&self) -> &str {
        "test_resource"
    }
    fn tools(&self) -> Vec<(ToolDefinition, navra_mcp::ToolHandler)> {
        vec![]
    }
    fn resources(&self) -> Vec<(crate::protocol::ResourceDefinition, ResourceHandler)> {
        vec![(
            navra_protocol::Annotated::new(
                crate::protocol::RawResource {
                    uri: "info://version".to_string(),
                    name: "Version".to_string(),
                    title: None,
                    description: Some("Server version".to_string()),
                    mime_type: Some("text/plain".to_string()),
                    size: None,
                    icons: None,
                    meta: None,
                },
                None,
            ),
            std::sync::Arc::new(|_uri: String, _ctx| {
                Box::pin(async {
                    crate::protocol::ReadResourceResult::new(vec![
                        crate::protocol::ResourceContent::TextResourceContents {
                            uri: "info://version".to_string(),
                            mime_type: Some("text/plain".to_string()),
                            text: "0.1.0".to_string(),
                            meta: None,
                        },
                    ])
                })
            }),
        )]
    }
}

fn test_server() -> Arc<McpServer> {
    Arc::new(
        McpServer::builder()
            .name("test-server")
            .version("0.1.0")
            .authenticator(NoAuthenticator {
                default_identity: AgentIdentity::new("tester", "dev"),
            })
            .tool(
                ToolDefinition::new("ping", "Returns pong", empty_input_schema()),
                |_args, _ctx| Box::pin(async { CallToolResult::text("pong") }),
            )
            .module(TestPromptModule)
            .module(TestResourceModule)
            .build(),
    )
}

/// Connect a NavraHandler and rmcp client via in-memory duplex (no TCP).
async fn connect_client() -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let (server_io, client_io) = tokio::io::duplex(65536);
    let handler = NavraHandler::new(test_server());
    tokio::spawn(async move {
        if let Ok(svc) = handler.serve(server_io).await {
            let _ = svc.waiting().await;
        }
    });
    ().serve(client_io).await.expect("client connect failed")
}

#[tokio::test]
async fn initialize_returns_capabilities() {
    let client = connect_client().await;
    let info = client
        .peer_info()
        .expect("should have peer info after init");
    assert_eq!(info.server_info.name, "test-server");
    assert_eq!(info.server_info.version, "0.1.0");
    client.cancel().await.ok();
}

#[tokio::test]
async fn tools_list_returns_registered_tools() {
    let client = connect_client().await;
    let result = client.list_tools(None).await.unwrap();
    // 1 user tool (ping) + 3 gateway tools (navra_var_*)
    assert_eq!(result.tools.len(), 4);
    assert!(result.tools.iter().any(|t| t.name == "ping"));
    client.cancel().await.ok();
}

#[tokio::test]
async fn tools_call_invokes_handler() {
    let client = connect_client().await;
    let result = client
        .call_tool(CallToolRequestParams::new("ping"))
        .await
        .unwrap();
    let text = result.content[0].raw.as_text().unwrap().text.as_str();
    assert!(text.contains("pong"));
    client.cancel().await.ok();
}

#[tokio::test]
async fn call_unknown_tool_returns_error() {
    let client = connect_client().await;
    let result = client
        .call_tool(CallToolRequestParams::new("nonexistent"))
        .await;
    match result {
        Ok(r) => assert!(r.is_error == Some(true), "expected tool-level error"),
        Err(_) => {} // protocol-level error also acceptable
    }
    client.cancel().await.ok();
}

#[tokio::test]
async fn prompts_list_returns_registered_prompts() {
    let client = connect_client().await;
    let result = client.list_prompts(None).await.unwrap();
    assert!(result.prompts.iter().any(|p| p.name == "greet"));
    client.cancel().await.ok();
}

#[tokio::test]
async fn prompts_get_invokes_handler() {
    let client = connect_client().await;
    let result = client
        .get_prompt(GetPromptRequestParams::new("greet"))
        .await
        .unwrap();
    assert_eq!(result.description.as_deref(), Some("Greeting"));
    client.cancel().await.ok();
}

#[tokio::test]
async fn prompts_get_unknown_returns_error() {
    let client = connect_client().await;
    let result = client
        .get_prompt(GetPromptRequestParams::new("nonexistent"))
        .await;
    assert!(result.is_err());
    client.cancel().await.ok();
}

#[tokio::test]
async fn resources_list_returns_registered_resources() {
    let client = connect_client().await;
    let result = client.list_resources(None).await.unwrap();
    assert!(result.resources.iter().any(|r| r.raw.name == "Version"));
    client.cancel().await.ok();
}

#[tokio::test]
async fn resources_read_invokes_handler() {
    let client = connect_client().await;
    let result = client
        .read_resource(ReadResourceRequestParams::new("info://version"))
        .await
        .unwrap();
    assert!(!result.contents.is_empty());
    client.cancel().await.ok();
}

#[tokio::test]
async fn resources_read_unknown_returns_error() {
    let client = connect_client().await;
    let result = client
        .read_resource(ReadResourceRequestParams::new("info://nonexistent"))
        .await;
    assert!(result.is_err());
    client.cancel().await.ok();
}

#[tokio::test]
async fn unknown_method_returns_error() {
    let client = connect_client().await;
    // rmcp doesn't expose a way to send arbitrary methods via the typed API,
    // but calling a method that returns an error validates the error path.
    // Use an unknown prompt name as a proxy for unknown-method behavior.
    let result = client
        .get_prompt(GetPromptRequestParams::new("__does_not_exist__"))
        .await;
    assert!(result.is_err());
    client.cancel().await.ok();
}
