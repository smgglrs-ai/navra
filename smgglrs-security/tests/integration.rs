//! Integration tests for smgglrs-security public API.
//!
//! Tests cross-module behavior: auth → permissions → IFC → hooks → safety.

use smgglrs_security::auth::capability::{
    build_delegated_payload, build_payload, decode_token, encode_token, resolve_capabilities,
    validate_delegation, CapabilitySet,
};
use smgglrs_security::auth::{
    AgentIdentity, AuthError, Authenticator, CallContext, TokenAuthenticator,
};
use smgglrs_security::auth::chain::{CapabilityAuthenticator, ChainAuthenticator};
use smgglrs_security::hooks::{Hook, HookDecision, HookPipeline};
use smgglrs_security::identity::{CapSigner, Ed25519Signer};
use smgglrs_security::ifc::{DataLabel, TaintTracker};
use smgglrs_security::ifc::value_store::{ValueStore, StoredValue, resolve_variable_refs};
use smgglrs_security::permissions::{PathAcl, PermissionEngine, PermissionResult};
use smgglrs_security::permissions::tool_rules::{ToolPermissions, ToolPolicy, ToolRule};
use smgglrs_security::quota::{QuotaEngine, RateLimit};
use smgglrs_security::process::ProcessTable;
use smgglrs_security::safety::{build_pipeline, FilterContext};
use axum::http::HeaderMap;
use smgglrs_protocol::Content;
use std::path::Path;
use std::time::Duration;

// =====================================================================
// 1. BLAKE3 token hashing and verification
// =====================================================================

#[test]
fn blake3_token_register_authenticate_roundtrip() {
    let mut auth = TokenAuthenticator::new();
    let identity = AgentIdentity::new("agent-alpha", "developer");
    auth.register("my-secret-token-42", identity);

    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer my-secret-token-42".parse().unwrap());

    let result = auth.authenticate(&headers).unwrap();
    assert_eq!(result.name, "agent-alpha");
    assert_eq!(result.permissions, "developer");
    assert!(result.capabilities.is_none());
}

#[test]
fn blake3_hash_register_and_authenticate() {
    let hash = TokenAuthenticator::hash_token("token-xyz");
    let mut auth = TokenAuthenticator::new();
    auth.register_hash(&hash, AgentIdentity::new("hashed-agent", "readonly"));

    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer token-xyz".parse().unwrap());

    let identity = auth.authenticate(&headers).unwrap();
    assert_eq!(identity.name, "hashed-agent");
}

#[test]
fn blake3_wrong_token_rejected() {
    let mut auth = TokenAuthenticator::new();
    auth.register("correct-token", AgentIdentity::new("agent", "dev"));

    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer wrong-token".parse().unwrap());

    assert!(matches!(auth.authenticate(&headers), Err(AuthError::InvalidToken)));
}

// =====================================================================
// 2. PermissionEngine with path ACLs (allow, deny, deny-wins)
// =====================================================================

fn build_permission_engine() -> PermissionEngine {
    let mut engine = PermissionEngine::new();
    engine.add_permission_set(
        "dev".to_string(),
        PathAcl {
            ring: None,
            allow: vec!["/home/user/projects/**".to_string()],
            deny: vec![
                "/home/user/projects/.secrets/**".to_string(),
                "**/.env".to_string(),
            ],
            operations: ["read", "write", "list", "git.status"]
                .into_iter()
                .map(String::from)
                .collect(),
            requires_approval: ["write"]
                .into_iter()
                .map(String::from)
                .collect(),
        },
    );
    engine
}

#[test]
fn permission_engine_allow_read() {
    let engine = build_permission_engine();
    let result = engine.check("dev", "read", Path::new("/home/user/projects/app/main.rs"));
    assert_eq!(result, PermissionResult::Allowed);
}

#[test]
fn permission_engine_deny_wins_over_allow() {
    let engine = build_permission_engine();
    // Path is inside allowed /home/user/projects/** but also matches deny
    let result = engine.check("dev", "read", Path::new("/home/user/projects/.secrets/key.pem"));
    assert_eq!(result, PermissionResult::DeniedPath);
}

#[test]
fn permission_engine_deny_dot_env_anywhere() {
    let engine = build_permission_engine();
    let result = engine.check("dev", "read", Path::new("/home/user/projects/app/.env"));
    assert_eq!(result, PermissionResult::DeniedPath);
}

#[test]
fn permission_engine_path_outside_allowed_denied() {
    let engine = build_permission_engine();
    let result = engine.check("dev", "read", Path::new("/etc/passwd"));
    assert_eq!(result, PermissionResult::DeniedPath);
}

#[test]
fn permission_engine_write_needs_approval() {
    let engine = build_permission_engine();
    let result = engine.check("dev", "write", Path::new("/home/user/projects/app/file.rs"));
    assert_eq!(result, PermissionResult::NeedsApproval);
}

#[test]
fn permission_engine_traversal_blocked() {
    let engine = build_permission_engine();
    let result = engine.check(
        "dev",
        "read",
        Path::new("/home/user/projects/../../etc/passwd"),
    );
    assert_eq!(result, PermissionResult::DeniedPath);
}

// =====================================================================
// 3. IFC taint tracker (label propagation, lattice join)
// =====================================================================

#[test]
fn taint_tracker_starts_trusted_public() {
    let tracker = TaintTracker::new();
    assert_eq!(tracker.level(), DataLabel::TRUSTED_PUBLIC);
    assert!(!tracker.is_untrusted());
    assert!(!tracker.is_sensitive());
}

#[test]
fn taint_tracker_absorb_untrusted_rises() {
    let mut tracker = TaintTracker::new();
    tracker.absorb(DataLabel::UNTRUSTED_PUBLIC);
    assert!(tracker.is_untrusted());
    assert!(!tracker.is_sensitive());
}

#[test]
fn taint_tracker_only_rises_never_drops() {
    let mut tracker = TaintTracker::new();
    tracker.absorb(DataLabel::UNTRUSTED_SENSITIVE);
    tracker.absorb(DataLabel::TRUSTED_PUBLIC);
    // Should remain at the highest level
    assert!(tracker.is_untrusted());
    assert!(tracker.is_sensitive());
}

#[test]
fn value_store_resolve_refs_propagates_labels() {
    let store = ValueStore::new();
    store.store(StoredValue {
        id: "v-trusted".to_string(),
        content: vec![Content::text("safe")],
        label: DataLabel::TRUSTED_PUBLIC,
        source_tool: "test".to_string(),
        created_at: std::time::Instant::now(),
        is_error: false,
    });
    store.store(StoredValue {
        id: "v-tainted".to_string(),
        content: vec![Content::text("danger")],
        label: DataLabel::UNTRUSTED_SENSITIVE,
        source_tool: "test".to_string(),
        created_at: std::time::Instant::now(),
        is_error: false,
    });

    let args = serde_json::json!({
        "a": "var://v-trusted",
        "b": "var://v-tainted"
    });
    let resolved = resolve_variable_refs(&args, &store).unwrap();
    // Join of TRUSTED_PUBLIC and UNTRUSTED_SENSITIVE = UNTRUSTED_SENSITIVE
    assert_eq!(resolved.effective_label, DataLabel::UNTRUSTED_SENSITIVE);
    assert_eq!(resolved.referenced_vars.len(), 2);
}

// =====================================================================
// 4. Hook pipeline execution
// =====================================================================

/// A hook that blocks any tool matching a name pattern.
struct TestBlockHook {
    blocked: String,
}

#[async_trait::async_trait]
impl Hook for TestBlockHook {
    fn name(&self) -> &str { "test-block" }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        _ctx: &CallContext,
    ) -> HookDecision {
        if tool_name == self.blocked {
            HookDecision::Block(format!("blocked: {tool_name}"))
        } else {
            HookDecision::Continue
        }
    }
}

/// A hook that modifies the result by appending a suffix.
struct TestResultHook {
    suffix: String,
}

#[async_trait::async_trait]
impl Hook for TestResultHook {
    fn name(&self) -> &str { "test-result" }

    async fn post_tool_use(
        &self,
        _tool_name: &str,
        _arguments: &serde_json::Value,
        result: &smgglrs_protocol::CallToolResult,
        _ctx: &CallContext,
    ) -> HookDecision {
        let text = match &result.content[0] {
            Content::Text(t) => &t.text,
        };
        HookDecision::ModifyResult(smgglrs_protocol::CallToolResult::text(
            format!("{}{}", text, self.suffix),
        ))
    }
}

fn test_ctx() -> CallContext {
    CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
}

#[tokio::test]
async fn hook_pipeline_pre_blocks_dangerous_tool() {
    let mut pipeline = HookPipeline::new(Duration::from_secs(5));
    pipeline.add(TestBlockHook { blocked: "shell_exec".to_string() });

    let result = pipeline
        .run_pre("shell_exec", serde_json::json!({}), &test_ctx())
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("blocked"));
}

#[tokio::test]
async fn hook_pipeline_pre_allows_safe_tool() {
    let mut pipeline = HookPipeline::new(Duration::from_secs(5));
    pipeline.add(TestBlockHook { blocked: "shell_exec".to_string() });

    let result = pipeline
        .run_pre("file_read", serde_json::json!({}), &test_ctx())
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn hook_pipeline_post_modifies_result() {
    let mut pipeline = HookPipeline::new(Duration::from_secs(5));
    pipeline.add(TestResultHook { suffix: " [audited]".to_string() });

    let original = smgglrs_protocol::CallToolResult::text("output");
    let result = pipeline
        .run_post("file_read", &serde_json::json!({}), original, &test_ctx())
        .await;

    match &result.content[0] {
        Content::Text(t) => assert_eq!(t.text, "output [audited]"),
    }
}

// =====================================================================
// 5. Capability token sign/verify
// =====================================================================

#[test]
fn capability_token_sign_verify_roundtrip() {
    let signer = Ed25519Signer::generate();
    let payload = build_payload(
        signer.did(),
        "did:key:z6MkAgent",
        CapabilitySet {
            paths: vec!["/home/**".to_string()],
            operations: vec!["read".to_string(), "write".to_string()],
            tools: vec!["file_*".to_string()],
            credentials: vec!["github.pat".to_string()],
        },
        1,
        3600,
    );

    let token = encode_token(&payload, &signer).unwrap();
    assert!(token.starts_with("smgglrs_cap_v1."));

    let decoded = decode_token(&token, &signer).unwrap();
    assert_eq!(decoded.iss, signer.did());
    assert_eq!(decoded.sub, "did:key:z6MkAgent");
    assert_eq!(decoded.ring, 1);
    assert_eq!(decoded.cap.operations, vec!["read", "write"]);
    assert_eq!(decoded.cap.credentials, vec!["github.pat"]);
}

#[test]
fn capability_token_wrong_key_rejected() {
    let signer1 = Ed25519Signer::generate();
    let signer2 = Ed25519Signer::generate();
    let payload = build_payload(
        signer1.did(),
        "did:key:z6MkAgent",
        CapabilitySet {
            paths: vec![], operations: vec![], tools: vec![], credentials: vec![],
        },
        1, 3600,
    );
    let token = encode_token(&payload, &signer1).unwrap();
    assert!(decode_token(&token, &signer2).is_err());
}

#[test]
fn delegation_ring_escalation_blocked() {
    let signer = Ed25519Signer::generate();
    let parent = build_payload(
        signer.did(),
        "did:key:z6MkParent",
        CapabilitySet {
            paths: vec!["/home/**".to_string()],
            operations: vec!["read".to_string()],
            tools: vec!["*".to_string()],
            credentials: vec![],
        },
        1, 3600,
    );

    let mut child = build_payload(
        "did:key:z6MkParent",
        "did:key:z6MkChild",
        parent.cap.clone(),
        0, // escalation: ring 0 < parent ring 1
        3600,
    );
    child.parent = Some(parent.nonce);

    let result = validate_delegation(&parent, &child, 3);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("ring escalation"));
}

#[test]
fn delegation_operation_escalation_blocked() {
    let signer = Ed25519Signer::generate();
    let parent = build_payload(
        signer.did(),
        "did:key:z6MkParent",
        CapabilitySet {
            paths: vec![], operations: vec!["read".to_string()],
            tools: vec![], credentials: vec![],
        },
        1, 3600,
    );

    let mut child = build_payload(
        "did:key:z6MkParent",
        "did:key:z6MkChild",
        CapabilitySet {
            paths: vec![],
            operations: vec!["read".to_string(), "shell.exec".to_string()],
            tools: vec![], credentials: vec![],
        },
        1, 3600,
    );
    child.parent = Some(parent.nonce);

    let result = validate_delegation(&parent, &child, 3);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("shell.exec"));
}

// =====================================================================
// 6. Cross-module: auth chain + tool rules + quota + process table
// =====================================================================

#[test]
fn auth_chain_cap_then_blake3_fallthrough() {
    let root = Ed25519Signer::generate();
    let mut blake3 = TokenAuthenticator::new();
    blake3.register("legacy-token", AgentIdentity::new("legacy", "dev"));

    let chain = ChainAuthenticator::new()
        .add(CapabilityAuthenticator::new(Box::new(root)))
        .add(blake3);

    // BLAKE3 token falls through cap authenticator
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer legacy-token".parse().unwrap());
    let identity = chain.authenticate(&headers).unwrap();
    assert_eq!(identity.name, "legacy");
    assert!(identity.capabilities.is_none());
}

#[test]
fn tool_rules_deny_wins() {
    let perms = ToolPermissions::new(
        vec![
            ToolRule { tool: "git_*".to_string(), policy: ToolPolicy::Allow },
            ToolRule { tool: "git_push".to_string(), policy: ToolPolicy::Deny },
        ],
        ToolPolicy::Allow,
    );
    assert_eq!(perms.check("git_status"), ToolPolicy::Allow);
    assert_eq!(perms.check("git_push"), ToolPolicy::Deny);
}

#[test]
fn quota_engine_rate_limits_per_agent() {
    let mut engine = QuotaEngine::new();
    engine.add_limit("dev".to_string(), RateLimit { max_calls: 3, window_secs: 60 });

    assert!(engine.check("alice", "dev"));
    assert!(engine.check("alice", "dev"));
    assert!(engine.check("alice", "dev"));
    assert!(!engine.check("alice", "dev"));
    // Bob has a separate bucket
    assert!(engine.check("bob", "dev"));
}

#[test]
fn process_table_tracks_agents() {
    let table = ProcessTable::new();
    table.record_call("agent-1", "dev", Some("did:key:z6Mk1"), Some(1), "file_read");
    table.record_call("agent-1", "dev", Some("did:key:z6Mk1"), Some(1), "git_status");
    table.record_denied("agent-1", "dev", Some("did:key:z6Mk1"), Some(1));

    let snap = table.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].call_count, 2);
    assert_eq!(snap[0].denied_count, 1);
    assert_eq!(snap[0].active_calls.len(), 2);

    table.complete_call("agent-1", "file_read");
    let snap = table.snapshot();
    assert_eq!(snap[0].active_calls, vec!["git_status"]);
}

// =====================================================================
// 7. Safety filter pipeline
// =====================================================================

#[test]
fn safety_pipeline_redacts_aws_key() {
    let pipeline = build_pipeline("standard");
    let ctx = FilterContext {
        agent_name: "test",
        operation: "read",
        path: Some("/test"),
    };
    let result = pipeline
        .process("Config: AKIAIOSFODNN7EXAMPLE", &ctx)
        .unwrap();
    assert!(result.contains("[REDACTED:aws-key]"));
    assert!(!result.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn safety_pipeline_blocks_when_configured() {
    let pipeline = build_pipeline("block");
    let ctx = FilterContext {
        agent_name: "test",
        operation: "read",
        path: Some("/test"),
    };
    let result = pipeline.process("SSN: 123-45-6789", &ctx);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("blocked"));
}

// =====================================================================
// 8. Delegated capability tokens for teammate scoping
// =====================================================================

fn root_payload(signer: &Ed25519Signer) -> smgglrs_security::auth::capability::CapabilityPayload {
    build_payload(
        signer.did(),
        signer.did(),
        CapabilitySet {
            paths: vec!["**".to_string()],
            operations: vec![
                "read".to_string(), "write".to_string(), "search".to_string(),
                "list".to_string(), "git.status".to_string(),
            ],
            tools: vec!["*".to_string()],
            credentials: vec![],
        },
        1,
        86400,
    )
}

#[test]
fn delegated_token_scopes_operations() {
    let signer = Ed25519Signer::generate();
    let root = root_payload(&signer);

    // Teammate gets only "read" and "search"
    let child = build_delegated_payload(
        &root,
        "did:teammate:team-1:reader",
        vec!["read".to_string(), "search".to_string()],
        vec!["file_read".to_string(), "file_grep".to_string()],
        2,
        600,
    )
    .unwrap();

    let token = encode_token(&child, &signer).unwrap();
    let decoded = decode_token(&token, &signer).unwrap();

    assert_eq!(decoded.cap.operations, vec!["read", "search"]);
    assert_eq!(decoded.cap.tools, vec!["file_read", "file_grep"]);
    assert!(decoded.parent.is_some());

    // Validate delegation chain
    assert!(validate_delegation(&root, &decoded, 3).is_ok());
}

#[test]
fn delegated_token_rejects_operation_not_in_parent() {
    let signer = Ed25519Signer::generate();
    let root = root_payload(&signer);

    // "shell.exec" is not in root's operations
    let err = build_delegated_payload(
        &root,
        "did:teammate:team-1:hacker",
        vec!["read".to_string(), "shell.exec".to_string()],
        vec!["file_read".to_string()],
        2,
        600,
    )
    .unwrap_err();

    assert!(err.to_string().contains("operation escalation"));
    assert!(err.to_string().contains("shell.exec"));
}

#[test]
fn delegated_token_rejects_tool_not_in_parent_globs() {
    let signer = Ed25519Signer::generate();
    // Parent with restricted tool globs (not wildcard)
    let root = build_payload(
        signer.did(),
        signer.did(),
        CapabilitySet {
            paths: vec!["**".to_string()],
            operations: vec!["read".to_string()],
            tools: vec!["file_*".to_string()],
            credentials: vec![],
        },
        1,
        3600,
    );

    // "git_status" is not covered by file_*
    let err = build_delegated_payload(
        &root,
        "did:teammate:team-1:hacker",
        vec!["read".to_string()],
        vec!["git_status".to_string()],
        2,
        600,
    )
    .unwrap_err();

    assert!(err.to_string().contains("tool escalation"));
    assert!(err.to_string().contains("git_status"));
}

#[test]
fn delegated_token_expiry_capped_by_parent() {
    let signer = Ed25519Signer::generate();
    let root = root_payload(&signer);

    let child = build_delegated_payload(
        &root,
        "did:teammate:team-1:worker",
        vec!["read".to_string()],
        vec!["file_read".to_string()],
        2,
        999999, // much longer than parent's 86400
    )
    .unwrap();

    assert!(child.exp <= root.exp);
}

#[test]
fn delegated_token_permission_engine_integration() {
    let signer = Ed25519Signer::generate();
    let root = root_payload(&signer);

    let child = build_delegated_payload(
        &root,
        "did:teammate:team-1:reader",
        vec!["read".to_string(), "search".to_string()],
        vec!["file_read".to_string()],
        2,
        600,
    )
    .unwrap();

    let token = encode_token(&child, &signer).unwrap();
    let decoded = decode_token(&token, &signer).unwrap();
    let caps = resolve_capabilities(&decoded);

    // PermissionEngine with no named set should fall back to capabilities
    let engine = PermissionEngine::new();

    // "read" is in the token — allowed
    let result = engine.check_with_capabilities(
        "cap:ring2", "read", Path::new("/home/user/project/file.rs"), Some(&caps),
    );
    assert_eq!(result, PermissionResult::Allowed);

    // "write" is NOT in the token — denied
    let result = engine.check_with_capabilities(
        "cap:ring2", "write", Path::new("/home/user/project/file.rs"), Some(&caps),
    );
    assert_eq!(result, PermissionResult::DeniedOperation);

    // "search" is in the token — allowed
    let result = engine.check_with_capabilities(
        "cap:ring2", "search", Path::new("/home/user/project/file.rs"), Some(&caps),
    );
    assert_eq!(result, PermissionResult::Allowed);
}
