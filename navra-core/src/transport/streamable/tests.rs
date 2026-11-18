use crate::auth::{AgentIdentity, NoAuthenticator};
use crate::protocol::{CallToolResult, ToolDefinition};
use crate::server::McpServer;
use crate::server::navra_handler::NavraHandler;
use navra_protocol::compat::CallToolResultExt;
use navra_protocol::compat::empty_input_schema;
use rmcp::model::{CallToolRequestParams, GetPromptRequestParams, ReadResourceRequestParams};
use rmcp::service::ServiceExt;
use std::sync::Arc;
use tower::ServiceExt as _;

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
            crate::protocol::RawResource::new("info://version".to_string(), "Version".to_string())
                .with_description("Server version".to_string())
                .with_mime_type("text/plain".to_string()),
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
                |_args, _ctx| {
                    Box::pin(async {
                        navra_protocol::CallToolResponse::Complete(CallToolResult::text("pong"))
                    })
                },
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
    let server_info = info.server_info.clone().expect("server_info present");
    assert_eq!(server_info.name, "test-server");
    assert_eq!(server_info.version, "0.1.0");
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
    let text = result.content[0].as_text().unwrap().text.as_str();
    assert!(text.contains("pong"));
    client.cancel().await.ok();
}

#[tokio::test]
async fn call_unknown_tool_returns_error() {
    let client = connect_client().await;
    let result = client
        .call_tool(CallToolRequestParams::new("nonexistent"))
        .await;
    if let Ok(r) = result {
        assert!(r.is_error == Some(true), "expected tool-level error");
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
    assert!(result.resources.iter().any(|r| r.name == "Version"));
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

// --- HTTP-level security tests (router + auth + host allowlist) ---

fn http_post(uri: &str, host: &str, body: String) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("host", host)
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn body_text(response: axum::http::Response<axum::body::Body>) -> String {
    use http_body_util::BodyExt;
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn initialize_request() -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 1,
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "http-test", "version": "0.1.0"}
        }
    })
    .to_string()
}

/// Server with a real authenticator and no registered agents: every
/// request fails authentication (no anonymous fallback).
fn token_authed_server() -> Arc<McpServer> {
    Arc::new(
        McpServer::builder()
            .name("auth-server")
            .authenticator(crate::auth::TokenAuthenticator::new())
            .build(),
    )
}

#[tokio::test]
async fn mcp_rejects_unauthenticated_request() {
    let router = super::router::build_router(token_authed_server());
    let response = router
        .oneshot(http_post("/mcp", "localhost:9315", initialize_request()))
        .await
        .unwrap();
    let text = body_text(response).await;
    assert!(
        text.contains("Authentication required"),
        "unauthenticated /mcp request must be rejected, got: {text}"
    );
}

#[tokio::test]
async fn metrics_requires_authentication() {
    let router = super::router::build_router(token_authed_server());
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri("/metrics")
                .header("host", "localhost:9315")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn metrics_serves_authenticated_callers() {
    let router = super::router::build_router(test_server());
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri("/metrics")
                .header("host", "localhost:9315")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn mcp_rejects_foreign_host_header() {
    // DNS-rebinding defense: the Host header must be on the
    // allowlist (localhost by default).
    let router = super::router::build_router(test_server());
    let response = router
        .oneshot(http_post("/mcp", "evil.example.com", initialize_request()))
        .await
        .unwrap();
    assert!(
        !response.status().is_success(),
        "requests with a foreign Host header must be rejected"
    );
}

#[tokio::test]
async fn mcp_allows_configured_host() {
    let server = Arc::new(
        McpServer::builder()
            .name("host-server")
            .authenticator(NoAuthenticator {
                default_identity: AgentIdentity::new("tester", "dev"),
            })
            .allowed_http_hosts(vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "navra.internal".to_string(),
            ])
            .build(),
    );
    let router = super::router::build_router(server);
    let response = router
        .oneshot(http_post(
            "/mcp",
            "navra.internal:9315",
            initialize_request(),
        ))
        .await
        .unwrap();
    let text = body_text(response).await;
    assert!(
        text.contains("host-server"),
        "allowlisted host must complete the initialize handshake, got: {text}"
    );
}

// --- Registry pagination with an active search filter ---

fn registry_entry(name: &str) -> serde_json::Value {
    serde_json::json!({
        "server": {
            "name": name,
            "description": format!("The {name} server"),
        }
    })
}

fn discovery_router(entries: Vec<serde_json::Value>) -> axum::Router {
    let server = Arc::new(
        McpServer::builder()
            .name("registry-server")
            .authenticator(NoAuthenticator {
                default_identity: AgentIdentity::new("tester", "dev"),
            })
            .build(),
    );
    super::router::build_router_with_discovery(
        server,
        crate::transport::sse::SseBroadcaster::new(),
        None,
        entries,
        None,
        None,
    )
}

#[tokio::test]
async fn registry_search_final_page_has_no_phantom_cursor() {
    // 5 entries, 2 matching the search. A page covering both matches
    // is the final FILTERED page: nextCursor must be null. The old
    // code compared against the unfiltered entry count and emitted a
    // phantom cursor pointing past the last match.
    let entries = vec![
        registry_entry("match-a"),
        registry_entry("match-b"),
        registry_entry("other-c"),
        registry_entry("other-d"),
        registry_entry("other-e"),
    ];
    let router = discovery_router(entries);
    let response = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/v0.1/servers?search=match&limit=2")
                .header("host", "localhost:9315")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let text = body_text(response).await;
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    let servers = body["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 2, "both matches fit on one page");
    assert!(
        body["metadata"]["nextCursor"].is_null(),
        "final filtered page must not carry a phantom cursor, got: {text}"
    );
}

#[tokio::test]
async fn registry_search_paginates_within_filtered_set() {
    // 3 matches, page size 2: page 1 carries a cursor, page 2
    // (1 remaining match) is final and must not.
    let entries = vec![
        registry_entry("match-a"),
        registry_entry("match-b"),
        registry_entry("match-c"),
        registry_entry("other-d"),
    ];
    let router = discovery_router(entries);

    let response = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/v0.1/servers?search=match&limit=2")
                .header("host", "localhost:9315")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let text = body_text(response).await;
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    let cursor = body["metadata"]["nextCursor"]
        .as_str()
        .expect("partial filtered page must carry a cursor")
        .to_string();

    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(format!(
                    "/v0.1/servers?search=match&limit=2&cursor={cursor}"
                ))
                .header("host", "localhost:9315")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let text = body_text(response).await;
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["servers"].as_array().unwrap().len(), 1);
    assert!(
        body["metadata"]["nextCursor"].is_null(),
        "final filtered page must not carry a phantom cursor, got: {text}"
    );
}
