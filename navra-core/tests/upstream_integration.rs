//! Integration tests for the upstream MCP proxy.
//!
//! Uses a Python test server (test_upstream.py) that speaks MCP over stdio.

use navra_core::UpstreamModule;
use navra_core::permissions::{Domain, DomainRules, Operation, ResourceClass};
use navra_core::protocol::{CallToolParams, GetPromptParams};
use std::path::PathBuf;

fn test_server_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_upstream.py")
}

async fn spawn_rmcp_peer() -> (
    rmcp::Peer<rmcp::RoleClient>,
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
) {
    spawn_rmcp_peer_with_env(&[]).await
}

/// Spawn the Python test server with extra environment variables.
async fn spawn_rmcp_peer_with_env(
    env: &[(&str, &str)],
) -> (
    rmcp::Peer<rmcp::RoleClient>,
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
) {
    let mut cmd = tokio::process::Command::new("python3");
    cmd.arg(test_server_path().to_string_lossy().to_string());
    for (key, val) in env {
        cmd.env(key, val);
    }
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
async fn upstream_discover_scanner_drops_malicious_keeps_clean() {
    // Verdict semantics through discover(): a Malicious (Critical
    // poisoning pattern) tool is dropped, the clean sibling registers.
    let (peer, _client) = spawn_rmcp_peer_with_env(&[("NAVRA_TEST_POISON", "1")]).await;

    let mut scanner = navra_auth::tool_scanner::ToolScanner::with_hash_path(
        navra_auth::tool_scanner::ToolScanConfig::default(),
        None,
    );
    let module =
        UpstreamModule::discover("scan-test", peer, Some(&mut scanner), &Default::default()).await;

    let tools: Vec<_> = navra_core::Module::tools(&module);
    let names: Vec<_> = tools.iter().map(|(def, _)| def.name.to_string()).collect();
    assert_eq!(names, vec!["echo".to_string()]);
}
