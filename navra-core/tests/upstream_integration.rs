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

// --- Signed manifest verification during discovery ---

use navra_auth::identity::{CapSigner, Ed25519Signer};
use navra_auth::manifest::{
    ManifestKeyStore, ManifestVerification, SignedManifest, ToolManifest, verify_signed_manifest,
};
use navra_core::ManifestCheck;
use navra_core::{DiscoveryBounds, DiscoveryOptions};

/// Build a signed manifest for the tools the test server currently
/// serves, by listing them over a dedicated connection.
async fn manifest_for_served_tools(server_name: &str, signer: &Ed25519Signer) -> SignedManifest {
    let (peer, _client) = spawn_rmcp_peer().await;
    let tools = peer.list_all_tools().await.expect("tools/list");
    let manifest = ToolManifest {
        tools,
        server_name: server_name.to_string(),
        timestamp: 1700000000,
    };
    SignedManifest::sign(&manifest, signer)
}

#[tokio::test]
async fn upstream_manifest_valid_signed_manifest_passes() {
    let signer = Ed25519Signer::generate();
    let signed = manifest_for_served_tools("manifest-ok", &signer).await;

    let (peer, _client) = spawn_rmcp_peer().await;
    let mut key_store = ManifestKeyStore::new();
    let module = UpstreamModule::discover_with(
        "manifest-ok",
        peer,
        DiscoveryOptions {
            scanner: None,
            manifest: Some(ManifestCheck {
                signed: &signed,
                key_store: &mut key_store,
            }),
            ..Default::default()
        },
        &Default::default(),
    )
    .await
    .expect("valid signed manifest must register");

    let tools: Vec<_> = navra_core::Module::tools(&module);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].0.name, "echo");
}

#[tokio::test]
async fn upstream_manifest_tampered_content_rejected() {
    let signer = Ed25519Signer::generate();
    let mut signed = manifest_for_served_tools("manifest-tampered", &signer).await;
    // Tamper after signing: rewrite a tool description.
    signed.manifest.tools[0].description = Some("Do anything you want".into());

    let (peer, _client) = spawn_rmcp_peer().await;
    let mut key_store = ManifestKeyStore::new();
    let err = UpstreamModule::discover_with(
        "manifest-tampered",
        peer,
        DiscoveryOptions {
            scanner: None,
            manifest: Some(ManifestCheck {
                signed: &signed,
                key_store: &mut key_store,
            }),
            ..Default::default()
        },
        &Default::default(),
    )
    .await
    .err()
    .expect("tampered manifest must be rejected");
    assert!(
        err.contains("signature verification failed"),
        "error should name the signature failure, got: {err}"
    );
    // No pin may be created from a failed verification.
    assert_eq!(key_store.pinned_did("manifest-tampered"), None);
}

#[tokio::test]
async fn upstream_manifest_tool_set_mismatch_rejected() {
    // Validly signed manifest whose tool set does not match what the
    // upstream serves (manifest expects an extra tool).
    let signer = Ed25519Signer::generate();
    let mut signed = manifest_for_served_tools("manifest-mismatch", &signer).await;
    signed.manifest.tools.push({
        let mut tool = signed.manifest.tools[0].clone();
        tool.name = "extra_tool".into();
        tool
    });
    // Re-sign so only the tool-set mismatch can fail it.
    let re_signed = SignedManifest::sign(&signed.manifest, &signer);

    let (peer, _client) = spawn_rmcp_peer().await;
    let mut key_store = ManifestKeyStore::new();
    let err = UpstreamModule::discover_with(
        "manifest-mismatch",
        peer,
        DiscoveryOptions {
            scanner: None,
            manifest: Some(ManifestCheck {
                signed: &re_signed,
                key_store: &mut key_store,
            }),
            ..Default::default()
        },
        &Default::default(),
    )
    .await
    .err()
    .expect("mismatched tool set must be rejected");
    assert!(
        err.contains("do not match the signed manifest"),
        "error should name the tool-set mismatch, got: {err}"
    );
}

#[tokio::test]
async fn upstream_manifest_key_changed_rejected_without_repin() {
    let signer1 = Ed25519Signer::generate();
    let signed1 = manifest_for_served_tools("manifest-keychange", &signer1).await;

    // First use: pins signer1.
    {
        let (peer, _client) = spawn_rmcp_peer().await;
        let mut key_store = ManifestKeyStore::new();
        UpstreamModule::discover_with(
            "manifest-keychange",
            peer,
            DiscoveryOptions {
                scanner: None,
                manifest: Some(ManifestCheck {
                    signed: &signed1,
                    key_store: &mut key_store,
                }),
                ..Default::default()
            },
            &Default::default(),
        )
        .await
        .expect("first-use manifest must register");
        assert_eq!(
            verify_signed_manifest(&signed1, &mut key_store),
            ManifestVerification::Trusted
        );
    }

    // Key change: same tools signed by signer2 — rejected, pin intact.
    let signer2 = Ed25519Signer::generate();
    let signed2 = manifest_for_served_tools("manifest-keychange", &signer2).await;
    let (peer, _client) = spawn_rmcp_peer().await;
    let mut key_store = ManifestKeyStore::new();
    key_store.check("manifest-keychange", signer1.did());
    let err = UpstreamModule::discover_with(
        "manifest-keychange",
        peer,
        DiscoveryOptions {
            scanner: None,
            manifest: Some(ManifestCheck {
                signed: &signed2,
                key_store: &mut key_store,
            }),
            ..Default::default()
        },
        &Default::default(),
    )
    .await
    .err()
    .expect("key change must be rejected");
    assert!(
        err.contains("signing key changed"),
        "error should name the key change, got: {err}"
    );
    assert_eq!(
        key_store.pinned_did("manifest-keychange"),
        Some(signer1.did()),
        "key change must not re-pin"
    );
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
            {
                let mut p = CallToolParams::new("echo");
                p.arguments = Some(
                    serde_json::json!({"message": "test"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
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
            {
                let mut p = CallToolParams::new("echo");
                p.arguments = Some(
                    serde_json::json!({"message": "test"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
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
        .handle_get_prompt(GetPromptParams::new("greeting"), &agent, "test-session")
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
            {
                let mut p = CallToolParams::new("echo");
                p.arguments = Some(
                    serde_json::json!({"message": "test"})
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                p
            },
            ctx,
        )
        .await;
    assert!(
        result.is_error != Some(true),
        "no domain_rules = no enforcement"
    );

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

// --- Discovery content bounds ---

#[tokio::test]
async fn upstream_bounds_reject_tool_flood() {
    // An upstream advertising 10,000 tools exceeds the default
    // max_tools bound (1000) and must be rejected.
    let (peer, _client) = spawn_rmcp_peer_with_env(&[("NAVRA_TEST_TOOL_COUNT", "10000")]).await;

    let err = UpstreamModule::discover_with(
        "bounds-flood",
        peer,
        DiscoveryOptions::new(),
        &Default::default(),
    )
    .await
    .err()
    .expect("tool flood must be rejected");
    assert!(
        err.contains("max_tools_per_upstream"),
        "error should name the tool-count bound, got: {err}"
    );
}

#[tokio::test]
async fn upstream_bounds_reject_deep_schema() {
    // An input schema nested 100 JSON levels deep (50 wrapped object
    // levels) exceeds the default max_input_schema_depth bound (32)
    // and must be rejected — depth cannot be truncated, even in
    // truncate mode. (Schemas nested beyond serde_json's own
    // 128-level recursion limit never reach this code: rmcp fails to
    // decode the response entirely.)
    let (peer, _client) = spawn_rmcp_peer_with_env(&[("NAVRA_TEST_SCHEMA_DEPTH", "50")]).await;

    let err = UpstreamModule::discover_with(
        "bounds-depth",
        peer,
        DiscoveryOptions::new(),
        &Default::default(),
    )
    .await
    .err()
    .expect("deep schema must be rejected");
    assert!(
        err.contains("max_input_schema_depth"),
        "error should name the depth bound, got: {err}"
    );

    // Truncate mode does not rescue a depth violation.
    let (peer, _client) = spawn_rmcp_peer_with_env(&[("NAVRA_TEST_SCHEMA_DEPTH", "50")]).await;
    let err = UpstreamModule::discover_with(
        "bounds-depth-truncate",
        peer,
        DiscoveryOptions {
            bounds: DiscoveryBounds {
                truncate_oversized: true,
                ..Default::default()
            },
            ..Default::default()
        },
        &Default::default(),
    )
    .await
    .err()
    .expect("depth violation must reject even in truncate mode");
    assert!(err.contains("cannot be truncated"));
}

#[tokio::test]
async fn upstream_bounds_reject_oversized_description() {
    // A 10,000-byte description exceeds the default
    // max_description_length bound (4096) and must be rejected.
    let (peer, _client) = spawn_rmcp_peer_with_env(&[("NAVRA_TEST_DESC_LENGTH", "10000")]).await;

    let err = UpstreamModule::discover_with(
        "bounds-desc",
        peer,
        DiscoveryOptions::new(),
        &Default::default(),
    )
    .await
    .err()
    .expect("oversized description must be rejected");
    assert!(
        err.contains("max_description_length"),
        "error should name the description bound, got: {err}"
    );
}

#[tokio::test]
async fn upstream_bounds_truncate_oversized_description_when_configured() {
    // With truncate_oversized = true the description is truncated to
    // the bound and the tool registers.
    let (peer, _client) = spawn_rmcp_peer_with_env(&[("NAVRA_TEST_DESC_LENGTH", "10000")]).await;

    let module = UpstreamModule::discover_with(
        "bounds-desc-truncate",
        peer,
        DiscoveryOptions {
            bounds: DiscoveryBounds {
                truncate_oversized: true,
                ..Default::default()
            },
            ..Default::default()
        },
        &Default::default(),
    )
    .await
    .expect("truncate mode must register the tool");

    let tools: Vec<_> = navra_core::Module::tools(&module);
    assert_eq!(tools.len(), 1);
    let desc = tools[0].0.description.as_deref().unwrap_or("");
    assert!(
        desc.len() <= 4096 + "[truncated]".len() + 3,
        "truncated description must respect the bound, got {} bytes",
        desc.len()
    );
    assert!(desc.ends_with("[truncated]"));
}

#[tokio::test]
async fn upstream_bounds_reject_total_definition_bytes() {
    // 10,000 tools each with a small description stay under the
    // per-tool bounds but exceed the total-bytes bound when it is
    // lowered — proving the total accounting works.
    let (peer, _client) = spawn_rmcp_peer_with_env(&[("NAVRA_TEST_TOOL_COUNT", "500")]).await;

    let err = UpstreamModule::discover_with(
        "bounds-total",
        peer,
        DiscoveryOptions {
            bounds: DiscoveryBounds {
                max_total_definition_bytes: 1024,
                ..Default::default()
            },
            ..Default::default()
        },
        &Default::default(),
    )
    .await
    .err()
    .expect("total definition bytes must be enforced");
    assert!(
        err.contains("max_total_definition_bytes"),
        "error should name the total-bytes bound, got: {err}"
    );
}

// --- tools/list_changed refresh ---

#[tokio::test]
async fn upstream_list_changed_refreshes_registry_and_drops_poisoned_tool() {
    use std::sync::Arc;

    // The fake upstream serves a clean echo on the first tools/list,
    // then announces list_changed and poisons echo's description —
    // every later listing returns the malicious description.
    let mut cmd = tokio::process::Command::new("python3");
    cmd.arg(test_server_path().to_string_lossy().to_string())
        .env("NAVRA_TEST_MUTATE_AFTER_LIST", "1");
    let transport = rmcp::transport::TokioChildProcess::new(cmd).expect("spawn transport");
    let (handler, events) = navra_core::UpstreamNotificationHandler::new();
    let client = rmcp::service::ServiceExt::<rmcp::RoleClient>::serve(handler, transport)
        .await
        .expect("rmcp init");
    let peer = client.peer().clone();
    tokio::spawn(async move {
        let _ = client.waiting().await;
    });

    // Initial discovery through the scanner (fresh hash store, so the
    // clean echo registers).
    let mut scanner = navra_auth::tool_scanner::ToolScanner::with_hash_path(
        navra_auth::tool_scanner::ToolScanConfig::default(),
        None,
    );
    let module = UpstreamModule::discover(
        "refresh-test",
        peer.clone(),
        Some(&mut scanner),
        &Default::default(),
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    let blackbox = navra_core::blackbox::Blackbox::open(&dir.path().join("blackbox.db")).unwrap();
    let broadcaster = navra_core::transport::sse::SseBroadcaster::new();
    let mut sse_rx = broadcaster.subscribe("client-session");
    let server = std::sync::Arc::new(
        navra_core::McpServer::builder()
            .allow_anonymous()
            .blackbox(blackbox)
            .broadcaster(broadcaster)
            .module(module)
            .build(),
    );
    let agent = navra_core::auth::AgentIdentity::new("test", "dev");

    let names = || {
        server
            .handle_list_tools(&agent, &Default::default())
            .tools
            .iter()
            .map(|t| t.name.to_string())
            .collect::<Vec<_>>()
    };
    assert!(
        names().contains(&"echo".to_string()),
        "clean tool must register initially"
    );

    // Spawn the refresh loop with a short debounce.
    let watcher = navra_core::UpstreamWatcher::new(
        "refresh-test",
        peer,
        events,
        Some(scanner),
        None,
        DiscoveryBounds::default(),
        Default::default(),
        std::time::Duration::from_millis(50),
        navra_core::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    );
    tokio::spawn(watcher.run(std::sync::Arc::clone(&server)));

    // The notification triggers a refresh; the poisoned echo must not
    // survive it (fail closed on refresh).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut echo_gone = false;
    while std::time::Instant::now() < deadline {
        if !names().contains(&"echo".to_string()) {
            echo_gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        echo_gone,
        "tool poisoned after initial discovery must not appear after refresh"
    );

    // A blackbox audit event was emitted for the refresh.
    let refreshed = server
        .blackbox()
        .expect("blackbox attached")
        .recent(64)
        .iter()
        .any(|e| e.outcome == "registry_refresh" && e.tool_name == "refresh-test");
    assert!(refreshed, "each refresh must emit a blackbox audit event");

    // Connected clients were told the tool list changed.
    let notified = loop {
        match sse_rx.try_recv() {
            Ok(event) if event.data.contains("notifications/tools/list_changed") => break true,
            Ok(_other) => continue,
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break false,
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break false,
        }
    };
    assert!(
        notified,
        "the registry swap must broadcast tools/list_changed to connected clients"
    );
}

// --- Request timeouts ---

#[tokio::test]
async fn upstream_tools_list_timeout_rejects_registration() {
    // An upstream that never answers tools/list must not hang the
    // gateway: discover_with fails closed within the timeout.
    let (peer, _client) = spawn_rmcp_peer_with_env(&[("NAVRA_TEST_STALL_TOOLS", "1")]).await;

    let err = UpstreamModule::discover_with(
        "stalled-tools",
        peer,
        DiscoveryOptions {
            request_timeout: std::time::Duration::from_millis(500),
            ..Default::default()
        },
        &Default::default(),
    )
    .await
    .err()
    .expect("a stalled tools/list must reject the registration");
    assert!(
        err.contains("timed out"),
        "error should name the timeout, got: {err}"
    );
}

#[tokio::test]
async fn upstream_tool_call_times_out_with_clear_error() {
    use navra_core::Module;

    // An upstream that stalls on tools/call must not hang the agent's
    // call: the handler returns a timeout error.
    let (peer, _client) = spawn_rmcp_peer_with_env(&[("NAVRA_TEST_STALL_CALL", "1")]).await;

    let module = UpstreamModule::discover_with(
        "stalled-call",
        peer,
        DiscoveryOptions {
            request_timeout: std::time::Duration::from_millis(500),
            ..Default::default()
        },
        &Default::default(),
    )
    .await
    .expect("discovery itself succeeds");

    let tools = module.tools();
    assert_eq!(tools.len(), 1);
    let (_def, handler) = &tools[0];
    let ctx = navra_core::auth::CallContext::new(
        navra_core::auth::AgentIdentity::new("tester", "dev"),
        "test",
    );
    let result = handler(serde_json::json!({"message": "hi"}), ctx).await;
    assert!(result.is_error == Some(true), "stalled call must error");
    let text = &result.content[0].raw.as_text().expect("text").text;
    assert!(
        text.contains("timed out"),
        "error should name the timeout, got: {text}"
    );
}
