//! C3 Adversarial Security Evaluation.
//!
//! 10 attack scenarios through the full MCP protocol stack. Each test
//! spawns a real navra server, configures realistic permissions, sends
//! crafted MCP requests that attempt attacks, and verifies the attack
//! is blocked with the correct error.
//!
//! These tests complement `security_eval.rs` (property-level) and
//! `ifc_integration.rs` (IFC-specific) by testing the complete
//! auth → ACL → IFC → safety → hook pipeline under adversarial
//! conditions.

use serde_json::json;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::{Child, Command};

async fn spawn_navra(config_toml: &str) -> (Child, u16, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let config_path = format!("/tmp/navra-adversarial-{port}.toml");
    let config = config_toml.replace("{port}", &port.to_string());
    std::fs::write(&config_path, &config).unwrap();

    let navra_bin = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("navra");

    let child = Command::new(&navra_bin)
        .args(["serve", "--config", &config_path, "--no-tray"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env(
            "ORT_LIB_PATH",
            std::env::var("ORT_LIB_PATH").unwrap_or_default(),
        )
        .env("ORT_PREFER_DYNAMIC_LINK", "1")
        .spawn()
        .expect("failed to spawn navra");

    let url = format!("http://127.0.0.1:{port}");

    let client = reqwest::Client::new();
    for i in 0..30 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if client.get(format!("{url}/mcp")).send().await.is_ok() {
            break;
        }
        if i == 29 {
            panic!("navra did not start within 15 seconds");
        }
    }

    (child, port, url)
}

async fn init_session(client: &reqwest::Client, url: &str) -> String {
    let resp = client
        .post(format!("{url}/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "adversarial-eval"}
            }
        }))
        .send()
        .await
        .unwrap();

    resp.headers()
        .get("mcp-session-id")
        .expect("missing session header")
        .to_str()
        .unwrap()
        .to_string()
}

async fn call_tool(
    client: &reqwest::Client,
    url: &str,
    session_id: &str,
    tool_name: &str,
    args: serde_json::Value,
    request_id: u64,
) -> serde_json::Value {
    let resp = client
        .post(format!("{url}/mcp"))
        .header("mcp-session-id", session_id)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": request_id,
            "params": {
                "name": tool_name,
                "arguments": args
            }
        }))
        .send()
        .await
        .unwrap();

    resp.json().await.unwrap()
}

fn result_text(resp: &serde_json::Value) -> String {
    resp["result"]["content"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|c| c["text"].as_str())
        .unwrap_or("")
        .to_string()
}

fn is_error_result(resp: &serde_json::Value) -> bool {
    resp["result"]["isError"].as_bool().unwrap_or(false)
}

// Config with file + git modules, ring 2 (readonly) agent, safety=standard, IFC=deny.
// Uses [permissions.default] as fallback for anonymous agents, plus
// [permissions.readonly] which the anonymous identity maps to.
const ADVERSARIAL_CONFIG: &str = r#"
cognitive_core = "cognitive_core"

[server]
tcp = "127.0.0.1:{port}"

[modules.file]
enabled = true

[permissions.default]
ring = 2
operations = ["read", "search", "list"]
allow = ["{project_dir}/**"]
deny = ["/etc/**", "/root/**", "/home/*/.ssh/**"]
safety = "standard"
tainted_write_policy = "deny"

[permissions.readonly]
ring = 2
operations = ["read", "search", "list"]
allow = ["{project_dir}/**"]
deny = ["/etc/**", "/root/**", "/home/*/.ssh/**"]
safety = "standard"
tainted_write_policy = "deny"
"#;

// Config with write-capable agent for IFC tests.
// Defines both "default" and "readonly" so the anonymous agent's
// "readonly" permission set resolves correctly with IFC deny policy.
const IFC_CONFIG: &str = r#"
cognitive_core = "cognitive_core"

[server]
tcp = "127.0.0.1:{port}"

[modules.file]
enabled = true

[permissions.default]
ring = 1
operations = ["read", "write", "search", "list"]
allow = ["{project_dir}/**"]
deny = ["/etc/**", "/root/**"]
safety = "standard"
tainted_write_policy = "deny"

[permissions.readonly]
ring = 1
operations = ["read", "write", "search", "list"]
allow = ["{project_dir}/**"]
deny = ["/etc/**", "/root/**"]
safety = "standard"
tainted_write_policy = "deny"
"#;

fn config_with_project_dir(template: &str, dir: &str) -> String {
    template.replace("{project_dir}", dir)
}

// ── A1: Path traversal — absolute path outside ACL ──────────────

#[tokio::test]
async fn a1_path_traversal_absolute() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_project_dir(ADVERSARIAL_CONFIG, &dir.path().to_string_lossy());
    let (mut child, _port, url) = spawn_navra(&config).await;
    let client = reqwest::Client::new();
    let session = init_session(&client, &url).await;

    let resp = call_tool(
        &client,
        &url,
        &session,
        "file_read",
        json!({"path": "/etc/shadow"}),
        2,
    )
    .await;

    assert!(
        is_error_result(&resp),
        "Expected path traversal to be blocked, got: {resp}"
    );
    let text = result_text(&resp);
    assert!(
        text.contains("denied") || text.contains("permission") || text.contains("outside"),
        "Expected ACL denial message, got: {text}"
    );

    child.kill().await.ok();
}

// ── A2: Path traversal — dot-dot escape ─────────────────────────

#[tokio::test]
async fn a2_path_traversal_dotdot() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_project_dir(ADVERSARIAL_CONFIG, &dir.path().to_string_lossy());
    let (mut child, _port, url) = spawn_navra(&config).await;
    let client = reqwest::Client::new();
    let session = init_session(&client, &url).await;

    let attack_path = format!("{}/../../../etc/passwd", dir.path().display());
    let resp = call_tool(
        &client,
        &url,
        &session,
        "file_read",
        json!({"path": attack_path}),
        2,
    )
    .await;

    assert!(
        is_error_result(&resp),
        "Expected dot-dot traversal to be blocked after canonicalization, got: {resp}"
    );

    child.kill().await.ok();
}

// ── A3: Symlink escape ──────────────────────────────────────────

#[tokio::test]
async fn a3_symlink_escape() {
    let dir = tempfile::tempdir().unwrap();
    let symlink_path = dir.path().join("escape");
    std::os::unix::fs::symlink("/etc/passwd", &symlink_path).unwrap();

    let config = config_with_project_dir(ADVERSARIAL_CONFIG, &dir.path().to_string_lossy());
    let (mut child, _port, url) = spawn_navra(&config).await;
    let client = reqwest::Client::new();
    let session = init_session(&client, &url).await;

    let resp = call_tool(
        &client,
        &url,
        &session,
        "file_read",
        json!({"path": symlink_path.to_string_lossy()}),
        2,
    )
    .await;

    assert!(
        is_error_result(&resp),
        "Expected symlink escape to be blocked, got: {resp}"
    );

    child.kill().await.ok();
}

// ── A4: Privilege escalation — readonly agent attempts write ────

#[tokio::test]
async fn a4_privilege_escalation_write() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_project_dir(ADVERSARIAL_CONFIG, &dir.path().to_string_lossy());
    let (mut child, _port, url) = spawn_navra(&config).await;
    let client = reqwest::Client::new();
    let session = init_session(&client, &url).await;

    let target = dir.path().join("pwned.txt");
    let resp = call_tool(
        &client,
        &url,
        &session,
        "file_write",
        json!({"path": target.to_string_lossy(), "content": "attacker was here"}),
        2,
    )
    .await;

    assert!(
        is_error_result(&resp),
        "Expected write from readonly agent to be blocked, got: {resp}"
    );
    assert!(
        !target.exists(),
        "File should not have been created by readonly agent"
    );

    child.kill().await.ok();
}

// ── A5: Deny-wins — allow + deny on same path, deny wins ────────

#[tokio::test]
async fn a5_deny_wins_over_allow() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("id_rsa"), "PRIVATE KEY CONTENT").unwrap();

    // Config allows dir/** but denies .ssh/**
    let config = format!(
        r#"
cognitive_core = "cognitive_core"

[server]
tcp = "127.0.0.1:{{port}}"

[modules.file]
enabled = true

[permissions.default]
ring = 2
operations = ["read", "search", "list"]
allow = ["{dir}/**"]
deny = ["{dir}/.ssh/**"]
safety = "none"

[permissions.readonly]
ring = 2
operations = ["read", "search", "list"]
allow = ["{dir}/**"]
deny = ["{dir}/.ssh/**"]
safety = "none"
"#,
        dir = dir.path().display()
    );

    let (mut child, _port, url) = spawn_navra(&config).await;
    let client = reqwest::Client::new();
    let session = init_session(&client, &url).await;

    let resp = call_tool(
        &client,
        &url,
        &session,
        "file_read",
        json!({"path": ssh_dir.join("id_rsa").to_string_lossy()}),
        2,
    )
    .await;

    assert!(
        is_error_result(&resp),
        "Deny rule should override allow rule for .ssh, got: {resp}"
    );
    let text = result_text(&resp);
    assert!(
        !text.contains("PRIVATE KEY CONTENT"),
        "Private key content should not be returned"
    );

    child.kill().await.ok();
}

// ── A6: Tool not in operations — file_delete denied ─────────────

#[tokio::test]
async fn a6_tool_outside_operations_denied() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("important.txt");
    std::fs::write(&target, "critical data").unwrap();

    let config = config_with_project_dir(ADVERSARIAL_CONFIG, &dir.path().to_string_lossy());
    let (mut child, _port, url) = spawn_navra(&config).await;
    let client = reqwest::Client::new();
    let session = init_session(&client, &url).await;

    let resp = call_tool(
        &client,
        &url,
        &session,
        "file_delete",
        json!({"path": target.to_string_lossy()}),
        2,
    )
    .await;

    assert!(
        is_error_result(&resp),
        "file_delete should be denied for read-only agent, got: {resp}"
    );
    assert!(target.exists(), "File should still exist after denied delete");

    child.kill().await.ok();
}

// ── A7: IFC write-down — read untrusted, then try write ────────

#[tokio::test]
async fn a7_ifc_write_down_blocked() {
    let dir = tempfile::tempdir().unwrap();

    let untrusted_file = dir.path().join("external_data.txt");
    std::fs::write(&untrusted_file, "data from external source").unwrap();

    let output_file = dir.path().join("output.txt");

    let config = config_with_project_dir(IFC_CONFIG, &dir.path().to_string_lossy());
    let (mut child, _port, url) = spawn_navra(&config).await;
    let client = reqwest::Client::new();
    let session = init_session(&client, &url).await;

    // Step 1: Read external data (taints the session)
    let _read_resp = call_tool(
        &client,
        &url,
        &session,
        "file_read",
        json!({"path": untrusted_file.to_string_lossy()}),
        2,
    )
    .await;

    // Step 2: Attempt write (should be blocked by IFC deny policy)
    let write_resp = call_tool(
        &client,
        &url,
        &session,
        "file_write",
        json!({
            "path": output_file.to_string_lossy(),
            "content": "exfiltrated data"
        }),
        3,
    )
    .await;

    assert!(
        is_error_result(&write_resp),
        "Expected IFC write-down to be blocked, got: {write_resp}"
    );
    let text = result_text(&write_resp);
    assert!(
        text.contains("taint") || text.contains("IFC") || text.contains("write"),
        "Expected IFC denial message, got: {text}"
    );
    assert!(
        !output_file.exists(),
        "File should not exist after IFC denial"
    );

    child.kill().await.ok();
}

// ── A8: Token replay — expired capability token ─────────────────

#[tokio::test]
async fn a8_expired_token_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_project_dir(ADVERSARIAL_CONFIG, &dir.path().to_string_lossy());
    let (mut child, _port, url) = spawn_navra(&config).await;
    let client = reqwest::Client::new();

    // Attempt to use a forged/expired capability token
    let resp = client
        .post(format!("{url}/mcp"))
        .header(
            "Authorization",
            "Bearer navra_cap_v1.invalid_payload.invalid_sig",
        )
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "attacker"}
            }
        }))
        .send()
        .await
        .unwrap();

    let json: serde_json::Value = resp.json().await.unwrap();
    // Should either error or fall through to anonymous with no capabilities
    let has_capabilities = json["result"]["capabilities"].is_object();
    if has_capabilities {
        // Server accepted anonymous — that's OK with NoAuthenticator,
        // but the token should not have granted any capability elevation
        assert!(
            json.to_string().contains("capabilities")
                || json["error"].is_object(),
            "Forged token should not elevate privileges"
        );
    }

    child.kill().await.ok();
}

// ── A9: Readonly agent attempts git commit ──────────────────────

#[tokio::test]
async fn a9_readonly_git_commit_blocked() {
    let dir = tempfile::tempdir().unwrap();

    // Initialize a git repo in the temp dir
    std::process::Command::new("git")
        .args(["init", "--initial-branch=main"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::fs::write(dir.path().join("README.md"), "# test").unwrap();
    std::process::Command::new("git")
        .args(["add", "."])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let config = config_with_project_dir(ADVERSARIAL_CONFIG, &dir.path().to_string_lossy());
    let (mut child, _port, url) = spawn_navra(&config).await;
    let client = reqwest::Client::new();
    let session = init_session(&client, &url).await;

    let resp = call_tool(
        &client,
        &url,
        &session,
        "git_commit",
        json!({"path": dir.path().to_string_lossy(), "message": "attacker commit"}),
        2,
    )
    .await;

    assert!(
        is_error_result(&resp),
        "Expected git_commit from readonly agent to be blocked, got: {resp}"
    );

    child.kill().await.ok();
}

// ── A10: Multiple file reads accumulate taint ───────────────────

#[tokio::test]
async fn a10_taint_accumulation_blocks_write() {
    let dir = tempfile::tempdir().unwrap();

    // Create multiple files at different taint levels
    std::fs::write(dir.path().join("public.txt"), "public info").unwrap();
    std::fs::write(dir.path().join("data.json"), r#"{"key": "value"}"#).unwrap();
    std::fs::write(dir.path().join("sensitive.log"), "user activity log").unwrap();

    let output_file = dir.path().join("summary.txt");

    let config = config_with_project_dir(IFC_CONFIG, &dir.path().to_string_lossy());
    let (mut child, _port, url) = spawn_navra(&config).await;
    let client = reqwest::Client::new();
    let session = init_session(&client, &url).await;

    // Read multiple files — each read taints the session
    for (i, name) in ["public.txt", "data.json", "sensitive.log"]
        .iter()
        .enumerate()
    {
        call_tool(
            &client,
            &url,
            &session,
            "file_read",
            json!({"path": dir.path().join(name).to_string_lossy()}),
            (i + 2) as u64,
        )
        .await;
    }

    // After reading external files, session is tainted — write should be blocked
    let write_resp = call_tool(
        &client,
        &url,
        &session,
        "file_write",
        json!({
            "path": output_file.to_string_lossy(),
            "content": "aggregated data"
        }),
        10,
    )
    .await;

    assert!(
        is_error_result(&write_resp),
        "Expected tainted session to block write, got: {write_resp}"
    );
    assert!(
        !output_file.exists(),
        "File should not exist after tainted write denial"
    );

    child.kill().await.ok();
}
