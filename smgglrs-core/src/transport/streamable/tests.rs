use super::*;
use super::handlers::SESSION_HEADER;
use crate::auth::{AgentIdentity, NoAuthenticator};
use crate::protocol::{RequestId, ToolDefinition, ToolInputSchema, CallToolResult};
use crate::server::McpServer;
use crate::transport::sse::SseBroadcaster;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::util::ServiceExt;
use std::sync::Arc;

use crate::module::{Module, PromptHandler, ResourceHandler};

struct TestPromptModule;

impl Module for TestPromptModule {
    fn name(&self) -> &str { "test_prompt" }
    fn tools(&self) -> Vec<(ToolDefinition, crate::server::ToolHandler)> { vec![] }
    fn prompts(&self) -> Vec<(crate::protocol::PromptDefinition, PromptHandler)> {
        vec![(
            crate::protocol::PromptDefinition {
                name: "greet".to_string(),
                description: Some("A greeting".to_string()),
                arguments: vec![],
            },
            std::sync::Arc::new(|_args: std::collections::HashMap<String, String>| {
                Box::pin(async {
                    crate::protocol::GetPromptResult {
                        description: Some("Greeting".to_string()),
                        messages: vec![crate::protocol::PromptMessage {
                            role: crate::protocol::PromptRole::User,
                            content: crate::protocol::Content::text("Hello!"),
                        }],
                    }
                })
            }),
        )]
    }
}

struct TestResourceModule;

impl Module for TestResourceModule {
    fn name(&self) -> &str { "test_resource" }
    fn tools(&self) -> Vec<(ToolDefinition, crate::server::ToolHandler)> { vec![] }
    fn resources(&self) -> Vec<(crate::protocol::ResourceDefinition, ResourceHandler)> {
        vec![(
            crate::protocol::ResourceDefinition {
                uri: "info://version".to_string(),
                name: "Version".to_string(),
                description: Some("Server version".to_string()),
                mime_type: Some("text/plain".to_string()),
                size: None,
            },
            std::sync::Arc::new(|uri: String| {
                Box::pin(async move {
                    crate::protocol::ReadResourceResult {
                        contents: vec![crate::protocol::ResourceContent {
                            uri,
                            mime_type: Some("text/plain".to_string()),
                            text: Some("0.1.0".to_string()),
                            blob: None,
                        }],
                    }
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
                ToolDefinition {
                    name: "ping".to_string(),
                    description: Some("Returns pong".to_string()),
                    input_schema: ToolInputSchema {
                        schema_type: "object".to_string(),
                        properties: None,
                        required: None,
                    },
                    annotations: None,
                },
                |_args, _ctx| Box::pin(async { CallToolResult::text("pong") }),
            )
            .module(TestPromptModule)
            .module(TestResourceModule)
            .build(),
    )
}

async fn post_json(
    router: &Router,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

#[tokio::test]
async fn initialize_returns_capabilities() {
    let router = build_router(test_server());
    let (status, json) = post_json(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test"}
            }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(json["result"]["serverInfo"]["name"], "test-server");
}

#[tokio::test]
async fn tools_list_returns_registered_tools() {
    let router = build_router(test_server());
    let sid = init_session(&router).await;
    let (status, _, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 2
        }),
        Some(&sid),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let tools = json["result"]["tools"].as_array().unwrap();
    // 1 user tool + 3 gateway tools (smgglrs_var_*)
    assert_eq!(tools.len(), 4);
    assert!(tools.iter().any(|t| t["name"] == "ping"));
}

#[tokio::test]
async fn tools_call_invokes_handler() {
    let router = build_router(test_server());
    let sid = init_session(&router).await;
    let (status, _, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 3,
            "params": {
                "name": "ping",
                "arguments": {}
            }
        }),
        Some(&sid),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["content"][0]["text"], "pong");
}

#[tokio::test]
async fn unknown_method_returns_error() {
    let router = build_router(test_server());
    let sid = init_session(&router).await;
    let (_, _, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "unknown/method",
            "id": 4
        }),
        Some(&sid),
    )
    .await;

    assert_eq!(json["error"]["code"], -32601);
}

#[tokio::test]
async fn call_unknown_tool_returns_tool_error() {
    let router = build_router(test_server());
    let sid = init_session(&router).await;
    let (_, _, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 5,
            "params": {"name": "nonexistent", "arguments": {}}
        }),
        Some(&sid),
    )
    .await;

    assert!(json["result"]["isError"].as_bool().unwrap());
}

#[tokio::test]
async fn prompts_list_returns_registered_prompts() {
    let router = build_router(test_server());
    let sid = init_session(&router).await;
    let (status, _, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "prompts/list",
            "id": 6
        }),
        Some(&sid),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let prompts = json["result"]["prompts"].as_array().unwrap();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0]["name"], "greet");
}

#[tokio::test]
async fn prompts_get_invokes_handler() {
    let router = build_router(test_server());
    let sid = init_session(&router).await;
    let (status, _, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "prompts/get",
            "id": 7,
            "params": {
                "name": "greet",
                "arguments": {}
            }
        }),
        Some(&sid),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["description"], "Greeting");
    assert_eq!(json["result"]["messages"][0]["role"], "user");
    assert_eq!(json["result"]["messages"][0]["content"]["text"], "Hello!");
}

#[tokio::test]
async fn prompts_get_unknown_returns_error() {
    let router = build_router(test_server());
    let sid = init_session(&router).await;
    let (_, _, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "prompts/get",
            "id": 8,
            "params": {"name": "nonexistent", "arguments": {}}
        }),
        Some(&sid),
    )
    .await;

    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Unknown prompt"));
}

#[tokio::test]
async fn resources_list_returns_registered_resources() {
    let router = build_router(test_server());
    let sid = init_session(&router).await;
    let (status, _, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "resources/list",
            "id": 9
        }),
        Some(&sid),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let resources = json["result"]["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["uri"], "info://version");
}

#[tokio::test]
async fn resources_read_invokes_handler() {
    let router = build_router(test_server());
    let sid = init_session(&router).await;
    let (status, _, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "resources/read",
            "id": 10,
            "params": {
                "uri": "info://version"
            }
        }),
        Some(&sid),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["contents"][0]["text"], "0.1.0");
    assert_eq!(json["result"]["contents"][0]["uri"], "info://version");
}

#[tokio::test]
async fn resources_read_unknown_returns_error() {
    let router = build_router(test_server());
    let sid = init_session(&router).await;
    let (_, _, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "resources/read",
            "id": 11,
            "params": {"uri": "info://nonexistent"}
        }),
        Some(&sid),
    )
    .await;

    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Unknown resource"));
}

/// Initialize a session and return the session ID.
async fn init_session(router: &Router) -> String {
    let (_, headers, _) = post_json_full(
        router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test"}
            }
        }),
        None,
    ).await;
    headers.get(SESSION_HEADER)
        .expect("missing session header")
        .to_str()
        .unwrap()
        .to_string()
}

/// Post JSON and return status, headers, and body.
async fn post_json_full(
    router: &Router,
    body: serde_json::Value,
    session_id: Option<&str>,
) -> (StatusCode, HeaderMap, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");

    if let Some(sid) = session_id {
        req = req.header(SESSION_HEADER, sid);
    }

    let req = req
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, headers, json)
}

#[tokio::test]
async fn initialize_returns_session_header() {
    let router = build_router(test_server());
    let (status, headers, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test"}
            }
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["protocolVersion"], "2025-03-26");

    // Session header must be present and non-empty
    let session_id = headers.get(SESSION_HEADER).expect("missing session header");
    let sid = session_id.to_str().unwrap();
    assert!(!sid.is_empty());
    // Should be a valid UUID
    assert!(uuid::Uuid::parse_str(sid).is_ok());
}

#[tokio::test]
async fn server_card_returns_metadata() {
    let router = build_router(test_server());
    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/mcp.json")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Server info
    assert_eq!(json["serverInfo"]["name"], "test-server");
    assert_eq!(json["serverInfo"]["version"], "0.1.0");

    // Protocol version
    assert_eq!(json["protocolVersion"], "2025-03-26");

    // Tools — internal tools (sys_*, smgglrs_var_*) are redacted from public card
    let tools = json["tools"].as_array().unwrap();
    // Only user-facing tools remain (ping); internal tools are filtered
    assert!(tools.iter().any(|t| t["name"] == "ping"), "user tool 'ping' should be in card");
    assert!(!tools.iter().any(|t| {
        let n = t["name"].as_str().unwrap_or("");
        n.starts_with("sys_") || n.starts_with("smgglrs_var_")
    }), "internal tools should be redacted from public card");

    // Prompts
    let prompts = json["prompts"].as_array().unwrap();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0]["name"], "greet");

    // Resources
    let resources = json["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["uri"], "info://version");

    // Capabilities
    assert!(json["capabilities"]["tools"].is_object());
    assert!(json["capabilities"]["prompts"].is_object());
    assert!(json["capabilities"]["resources"].is_object());
}

#[tokio::test]
async fn aid_record_served_when_configured() {
    let aid = serde_json::json!({
        "v": "aid1",
        "u": "https://tools.example.com/mcp",
        "p": "mcp",
        "a": "pat",
        "s": "Example MCP Tools",
    });
    let router = build_router_with_discovery(
        test_server(),
        SseBroadcaster::new(),
        Some(aid),
        Vec::new(),
        None,
        None,
    );

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/agent")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["v"], "aid1");
    assert_eq!(json["u"], "https://tools.example.com/mcp");
    assert_eq!(json["p"], "mcp");
    assert_eq!(json["a"], "pat");
    assert_eq!(json["s"], "Example MCP Tools");
}

#[tokio::test]
async fn aid_record_not_served_when_unconfigured() {
    let router = build_router(test_server());

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/agent")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    // Route doesn't exist when AID is not configured
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn registry_returns_entries() {
    let entries = vec![
        serde_json::json!({
            "server": {
                "name": "my-tools",
                "description": "My MCP tools",
                "remotes": [{"type": "streamable-http", "url": "https://tools.example.com/mcp"}],
            },
            "_meta": {"source": "self"},
        }),
        serde_json::json!({
            "server": {
                "name": "approved-server",
                "description": "Approved external server",
                "remotes": [{"type": "sse", "url": "https://external.example.com/sse"}],
            },
            "_meta": {"source": "whitelist"},
        }),
    ];
    let router = build_router_with_discovery(
        test_server(),
        SseBroadcaster::new(),
        None,
        entries,
        None,
        None,
    );

    let req = Request::builder()
        .method("GET")
        .uri("/v0.1/servers")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let servers = json["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0]["server"]["name"], "my-tools");
    assert_eq!(servers[1]["server"]["name"], "approved-server");
    assert!(json["metadata"]["nextCursor"].is_null());
}

#[tokio::test]
async fn registry_supports_search() {
    let entries = vec![
        serde_json::json!({"server": {"name": "docs-server", "description": "Document tools"}}),
        serde_json::json!({"server": {"name": "git-server", "description": "Git tools"}}),
        serde_json::json!({"server": {"name": "code-helper", "description": "Code review"}}),
    ];
    let router = build_router_with_discovery(
        test_server(),
        SseBroadcaster::new(),
        None,
        entries,
        None,
        None,
    );

    let req = Request::builder()
        .method("GET")
        .uri("/v0.1/servers?search=git")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let servers = json["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0]["server"]["name"], "git-server");
}

#[tokio::test]
async fn agent_card_returns_a2a_skills() {
    let router = build_router_with_discovery(
        test_server(),
        SseBroadcaster::new(),
        None,
        Vec::new(),
        Some("https://tools.example.com/mcp".to_string()),
        None,
    );

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/agent.json")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["name"], "test-server");
    assert_eq!(json["version"], "0.1.0");
    assert_eq!(json["url"], "https://tools.example.com/mcp");
    assert!(json["capabilities"]["streaming"].as_bool().unwrap());

    let skills = json["skills"].as_array().unwrap();
    assert!(!skills.is_empty());
    let ping = skills.iter().find(|s| s["id"] == "ping").unwrap();
    assert_eq!(ping["name"], "ping");
    assert_eq!(ping["description"], "Returns pong");
    assert!(ping["tags"].as_array().unwrap().contains(&serde_json::json!("ping")));
}

#[tokio::test]
async fn registry_supports_pagination() {
    let entries: Vec<serde_json::Value> = (0..5)
        .map(|i| serde_json::json!({"server": {"name": format!("server-{i}"), "description": ""}}))
        .collect();
    let router = build_router_with_discovery(
        test_server(),
        SseBroadcaster::new(),
        None,
        entries,
        None,
        None,
    );

    // First page
    let req = Request::builder()
        .method("GET")
        .uri("/v0.1/servers?limit=2")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let servers = json["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0]["server"]["name"], "server-0");
    assert_eq!(json["metadata"]["nextCursor"], "2");

    // Second page
    let req = Request::builder()
        .method("GET")
        .uri("/v0.1/servers?limit=2&cursor=2")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let servers = json["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0]["server"]["name"], "server-2");
}

#[tokio::test]
async fn session_header_not_in_initialize_body() {
    let router = build_router(test_server());
    let (_, _, json) = post_json_full(
        &router,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test"}
            }
        }),
        None,
    )
    .await;

    // The _sessionId internal field should NOT leak into the response body
    assert!(json["result"]["_sessionId"].is_null());
}
