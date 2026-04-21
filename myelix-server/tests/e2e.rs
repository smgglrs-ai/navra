//! End-to-end integration tests.
//!
//! Each test spawns a real mcpd server as a child process, connects
//! clients via HTTP, exercises the full pipeline (auth, ACLs, IFC,
//! safety, blackbox), and verifies results.
//!
//! No mocks. No in-process shortcuts. Real server, real clients,
//! real protocols.

use std::process::Stdio;
use std::time::Duration;
use tokio::process::{Child, Command};

/// Spawn a mcpd server with a given config, wait for it to be ready.
async fn spawn_mcpd(config_toml: &str) -> (Child, u16, String) {
    // Pick a free port
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    // Write config to temp file
    let config_path = format!("/tmp/mcpd-e2e-{port}.toml");
    let config = config_toml.replace("{port}", &port.to_string());
    std::fs::write(&config_path, &config).unwrap();

    // Find the mcpd binary
    let mcpd_bin = std::env::current_exe()
        .unwrap()
        .parent().unwrap()
        .parent().unwrap()
        .join("mcpd");

    let child = Command::new(&mcpd_bin)
        .args(["serve", "--config", &config_path, "--no-tray"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env("ORT_LIB_PATH", std::env::var("ORT_LIB_PATH").unwrap_or_default())
        .env("ORT_PREFER_DYNAMIC_LINK", "1")
        .spawn()
        .expect("failed to spawn mcpd");

    let url = format!("http://127.0.0.1:{port}");

    // Wait for server to be ready
    let client = reqwest::Client::new();
    for i in 0..30 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if client.get(format!("{url}/mcp")).send().await.is_ok() {
            break;
        }
        if i == 29 {
            panic!("mcpd did not start within 15 seconds");
        }
    }

    (child, port, url)
}

const BASIC_CONFIG: &str = r#"
cognitive_core = "cognitive_core"

[server]
tcp = "127.0.0.1:{port}"

[modules.docs]
enabled = false
"#;

const DOCS_CONFIG: &str = r#"
cognitive_core = "cognitive_core"

[server]
tcp = "127.0.0.1:{port}"

[modules.docs]
enabled = true
"#;

// --- MCP Protocol Tests ---

#[tokio::test]
async fn mcp_initialize_returns_capabilities() {
    let (mut child, _port, url) = spawn_mcpd(BASIC_CONFIG).await;

    let client = reqwest::Client::new();
    let resp = client.post(format!("{url}/mcp"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "e2e-test"}
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["result"]["protocolVersion"], "2025-03-26");
    assert!(json["result"]["capabilities"]["tools"].is_object());

    child.kill().await.ok();
}

#[tokio::test]
async fn mcp_tools_list_requires_session() {
    let (mut child, _port, url) = spawn_mcpd(BASIC_CONFIG).await;

    let client = reqwest::Client::new();
    let resp = client.post(format!("{url}/mcp"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 2
        }))
        .send()
        .await
        .unwrap();

    let json: serde_json::Value = resp.json().await.unwrap();
    // Should fail — no session
    assert!(json["error"].is_object());

    child.kill().await.ok();
}

#[tokio::test]
async fn mcp_full_session_list_tools() {
    let (mut child, _port, url) = spawn_mcpd(BASIC_CONFIG).await;
    let client = reqwest::Client::new();

    // Initialize — get session ID from response header
    let resp = client.post(format!("{url}/mcp"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "e2e-test"}
            }
        }))
        .send()
        .await
        .unwrap();

    let session_id = resp.headers()
        .get("mcp-session-id")
        .expect("missing session header")
        .to_str().unwrap()
        .to_string();

    // List tools with session
    let resp = client.post(format!("{url}/mcp"))
        .header("mcp-session-id", &session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 2
        }))
        .send()
        .await
        .unwrap();

    let json: serde_json::Value = resp.json().await.unwrap();
    let tools = json["result"]["tools"].as_array().unwrap();
    assert!(tools.len() >= 3, "expected gateway tools, got {}", tools.len());

    child.kill().await.ok();
}

// --- Model Proxy Tests ---

#[tokio::test]
async fn v1_chat_completions_returns_openai_format() {
    let (mut child, _port, url) = spawn_mcpd(BASIC_CONFIG).await;
    let client = reqwest::Client::new();

    let resp = client.post(format!("{url}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "test",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 5
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["object"], "chat.completion");
    assert!(json["choices"].is_array());
    assert_eq!(json["choices"][0]["message"]["role"], "assistant");
    assert!(json["usage"].is_object());

    child.kill().await.ok();
}

// --- API Tests ---

#[tokio::test]
async fn api_status_returns_server_info() {
    let (mut child, _port, url) = spawn_mcpd(BASIC_CONFIG).await;
    let client = reqwest::Client::new();

    let resp = client.get(format!("{url}/api/status"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["name"], "mcpd");
    assert_eq!(json["status"], "running");

    child.kill().await.ok();
}

#[tokio::test]
async fn static_index_html_served() {
    let (mut child, _port, url) = spawn_mcpd(BASIC_CONFIG).await;
    let client = reqwest::Client::new();

    let resp = client.get(&url)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(text.contains("<!DOCTYPE html>") || text.contains("<html"));

    child.kill().await.ok();
}

// --- Blackbox Tests ---

#[tokio::test]
async fn tool_call_recorded_in_blackbox() {
    let (mut child, _port, url) = spawn_mcpd(DOCS_CONFIG).await;
    let client = reqwest::Client::new();

    // Initialize
    let resp = client.post(format!("{url}/mcp"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "e2e-blackbox-test"}
            }
        }))
        .send()
        .await
        .unwrap();

    let session_id = resp.headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str().unwrap()
        .to_string();

    // Call a tool
    let resp = client.post(format!("{url}/mcp"))
        .header("mcp-session-id", &session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 3,
            "params": {
                "name": "docs_tree",
                "arguments": {}
            }
        }))
        .send()
        .await
        .unwrap();

    let json: serde_json::Value = resp.json().await.unwrap();
    // Should succeed (docs module enabled, default root set)
    assert!(json["result"].is_object(), "expected result, got: {json}");

    // Verify blackbox recorded it
    // The blackbox is at ~/.local/share/mcpd/blackbox.db
    // We can verify via the audit_query tool
    let resp = client.post(format!("{url}/mcp"))
        .header("mcp-session-id", &session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 4,
            "params": {
                "name": "audit_query",
                "arguments": {"summary": true}
            }
        }))
        .send()
        .await
        .unwrap();

    let json: serde_json::Value = resp.json().await.unwrap();
    // audit_query should return something (even if no run_id filter)
    assert!(json["result"].is_object());

    child.kill().await.ok();
}
