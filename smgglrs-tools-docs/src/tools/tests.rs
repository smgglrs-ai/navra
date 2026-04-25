use super::*;
use super::handlers::*;
use super::path_security::resolve_path;
use crate::store::IndexStore;
use smgglrs_core::auth::{AgentIdentity, CallContext};
use smgglrs_core::notify::NoopNotifier;
use smgglrs_core::permissions::{ApprovalStore, PathAcl, PermissionEngine};
use smgglrs_core::protocol::CallToolResult;
use std::collections::HashSet;
use std::sync::Arc;
use tempfile::TempDir;

fn test_state(tmpdir: &TempDir) -> Arc<DocsState> {
    let mut engine = PermissionEngine::new();
    engine.add_permission_set(
        "dev".to_string(),
        PathAcl {
            ring: None,
            allow: vec![format!("{}/**", tmpdir.path().display())],
            deny: vec![format!("{}/.secret/**", tmpdir.path().display())],
            operations: ["read", "write", "search", "list"]
                .into_iter()
                .map(String::from)
                .collect(),
            requires_approval: HashSet::new(),
        },
    );
    engine.add_permission_set(
        "readonly".to_string(),
        PathAcl {
            ring: None,
            allow: vec![format!("{}/**", tmpdir.path().display())],
            deny: vec![],
            operations: ["read", "search", "list"]
                .into_iter()
                .map(String::from)
                .collect(),
            requires_approval: HashSet::new(),
        },
    );
    let index = IndexStore::open_memory().unwrap();
    Arc::new(DocsState {
        perm_engine: Arc::new(engine),
        index: Arc::new(index),
        approvals: Arc::new(ApprovalStore::new(300)),
        notifier: Arc::new(NoopNotifier),
        embedding_model: None,
        default_root: None,
    })
}

fn dev_ctx() -> CallContext {
    CallContext::new(AgentIdentity::new("test-agent", "dev"), "test")
}

fn readonly_ctx() -> CallContext {
    CallContext::new(AgentIdentity::new("reader", "readonly"), "test")
}

fn text_of(result: &CallToolResult) -> &str {
    match &result.content[0] {
        smgglrs_core::protocol::Content::Text(t) => &t.text,
    }
}

// --- resolve_path ---

#[test]
fn resolve_path_rejects_relative() {
    assert!(resolve_path("relative/path.txt", true).unwrap_err().contains("absolute"));
}

#[test]
fn resolve_path_rejects_nonexistent() {
    assert!(resolve_path("/nonexistent/path/file.txt", true).is_err());
}

#[test]
fn resolve_path_canonicalizes() {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("test.txt");
    std::fs::write(&file, "hello").unwrap();
    let resolved = resolve_path(file.to_str().unwrap(), true).unwrap();
    assert!(resolved.is_absolute());
}

// --- read ---

#[tokio::test]
async fn read_full_file() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("hello.txt");
    std::fs::write(&file, "Hello, world!").unwrap();

    let result = handle_read(
        serde_json::json!({"path": file.to_str().unwrap()}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(!result.is_error);
    assert!(text_of(&result).contains("Hello, world!"));
    assert!(text_of(&result).contains("1 lines"));
}

#[tokio::test]
async fn read_partial_with_offset_and_limit() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("multi.txt");
    std::fs::write(&file, "line1\nline2\nline3\nline4\nline5\n").unwrap();

    let result = handle_read(
        serde_json::json!({"path": file.to_str().unwrap(), "offset": 2, "limit": 2}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(!result.is_error);
    let text = text_of(&result);
    assert!(text.contains("lines 2-3 of"));
    assert!(text.contains("line2"));
    assert!(text.contains("line3"));
    assert!(!text.contains("line1"));
    assert!(!text.contains("line4"));
}

#[tokio::test]
async fn read_denied_path() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let secret_dir = tmp.path().join(".secret");
    std::fs::create_dir(&secret_dir).unwrap();
    let file = secret_dir.join("key.pem");
    std::fs::write(&file, "private key").unwrap();

    let result = handle_read(
        serde_json::json!({"path": file.to_str().unwrap()}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(result.is_error);
    assert!(text_of(&result).contains("denied"));
}

// --- write ---

#[tokio::test]
async fn write_new_file() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("new.md");

    let result = handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "# Hello\n\nWorld"}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(!result.is_error);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "# Hello\n\nWorld");
}

#[tokio::test]
async fn write_denied_for_readonly() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("nope.txt");

    let result = handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "fail"}),
        readonly_ctx(),
        state.clone(),
    ).await;
    assert!(result.is_error);
    assert!(!file.exists());
}

// --- edit ---

#[tokio::test]
async fn edit_replaces_unique_string() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("doc.md");
    std::fs::write(&file, "Hello world, this is a test.").unwrap();

    let result = handle_edit(
        serde_json::json!({
            "path": file.to_str().unwrap(),
            "old_string": "Hello world",
            "new_string": "Goodbye world"
        }),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(!result.is_error);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "Goodbye world, this is a test."
    );
}

#[tokio::test]
async fn edit_fails_if_not_found() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("doc.md");
    std::fs::write(&file, "Hello world").unwrap();

    let result = handle_edit(
        serde_json::json!({
            "path": file.to_str().unwrap(),
            "old_string": "nonexistent",
            "new_string": "replacement"
        }),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(result.is_error);
    assert!(text_of(&result).contains("not found"));
}

#[tokio::test]
async fn edit_fails_if_not_unique() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("doc.md");
    std::fs::write(&file, "foo bar foo baz").unwrap();

    let result = handle_edit(
        serde_json::json!({
            "path": file.to_str().unwrap(),
            "old_string": "foo",
            "new_string": "qux"
        }),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(result.is_error);
    assert!(text_of(&result).contains("2 times"));
    // File should be unchanged
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "foo bar foo baz");
}

#[tokio::test]
async fn edit_denied_for_readonly() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("doc.md");
    std::fs::write(&file, "content").unwrap();

    let result = handle_edit(
        serde_json::json!({
            "path": file.to_str().unwrap(),
            "old_string": "content",
            "new_string": "modified"
        }),
        readonly_ctx(),
        state.clone(),
    ).await;
    assert!(result.is_error);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "content");
}

// --- info ---

#[tokio::test]
async fn info_returns_metadata() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("info.md");
    std::fs::write(&file, "line1\nline2\nline3\n").unwrap();

    let result = handle_info(
        serde_json::json!({"path": file.to_str().unwrap()}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(!result.is_error);
    let text = text_of(&result);
    assert!(text.contains("type: file"));
    assert!(text.contains("lines: 3"));
    assert!(text.contains("mime: text/markdown"));
    assert!(text.contains("indexed: false"));
}

// --- delete ---

#[tokio::test]
async fn delete_removes_file() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("doomed.txt");
    std::fs::write(&file, "goodbye").unwrap();

    let result = handle_delete(
        serde_json::json!({"path": file.to_str().unwrap()}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(!result.is_error);
    assert!(!file.exists());
}

#[tokio::test]
async fn delete_denied_for_readonly() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("safe.txt");
    std::fs::write(&file, "safe").unwrap();

    let result = handle_delete(
        serde_json::json!({"path": file.to_str().unwrap()}),
        readonly_ctx(),
        state.clone(),
    ).await;
    assert!(result.is_error);
    assert!(file.exists());
}

// --- list ---

#[tokio::test]
async fn list_directory() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    std::fs::write(tmp.path().join("a.txt"), "aaa").unwrap();
    std::fs::create_dir(tmp.path().join("subdir")).unwrap();

    let result = handle_list(
        serde_json::json!({"path": tmp.path().to_str().unwrap()}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(!result.is_error);
    let text = text_of(&result);
    assert!(text.contains("a.txt"));
    assert!(text.contains("subdir/"));
}

// --- search ---

#[tokio::test]
async fn search_returns_results() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let path = tmp.path().join("notes.md");
    std::fs::write(&path, "").unwrap();
    state.index.upsert(
        path.to_str().unwrap(), "text/markdown", 100, "t", "h",
        "Notes", "rust programming guide",
    ).unwrap();

    let result = handle_search(
        serde_json::json!({"query": "rust programming"}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(!result.is_error);
    assert!(text_of(&result).contains("1 result"));
}

// --- module trait ---

#[test]
fn module_provides_all_tools() {
    let engine = Arc::new(PermissionEngine::new());
    let index = Arc::new(IndexStore::open_memory().unwrap());
    let approvals = Arc::new(ApprovalStore::new(300));
    let notifier: Arc<dyn smgglrs_core::notify::Notifier> = Arc::new(NoopNotifier);
    let module = DocsModule::new(engine, index, approvals, notifier);

    assert_eq!(module.name(), "file");
    let tools = module.tools();
    let names: Vec<_> = tools.iter().map(|(def, _)| def.name.as_str()).collect();
    assert!(names.contains(&"file_search"));
    assert!(names.contains(&"file_read"));
    assert!(names.contains(&"file_list"));
    assert!(names.contains(&"file_write"));
    assert!(names.contains(&"file_edit"));
    assert!(names.contains(&"file_info"));
    assert!(names.contains(&"file_delete"));
    assert!(names.contains(&"file_approve"));
    assert!(names.contains(&"file_deny"));
    assert!(names.contains(&"file_tree"));
    assert!(names.contains(&"file_grep"));
    assert_eq!(tools.len(), 11);
}

// --- roundtrips ---

#[tokio::test]
async fn write_then_read_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("rt.md");

    handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "# RT\n\nContent."}),
        dev_ctx(),
        state.clone(),
    ).await;

    let result = handle_read(
        serde_json::json!({"path": file.to_str().unwrap()}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(text_of(&result).contains("# RT\n\nContent."));
}

#[tokio::test]
async fn write_edit_read_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("edit_rt.md");

    handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "Hello world"}),
        dev_ctx(),
        state.clone(),
    ).await;

    handle_edit(
        serde_json::json!({
            "path": file.to_str().unwrap(),
            "old_string": "Hello world",
            "new_string": "Goodbye world"
        }),
        dev_ctx(),
        state.clone(),
    ).await;

    let result = handle_read(
        serde_json::json!({"path": file.to_str().unwrap()}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(text_of(&result).contains("Goodbye world"));
}

#[tokio::test]
async fn write_then_search_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("searchable.md");

    handle_write(
        serde_json::json!({
            "path": file.to_str().unwrap(),
            "content": "# K8s Guide\n\nDeploy pods with kubectl."
        }),
        dev_ctx(),
        state.clone(),
    ).await;

    let result = handle_search(
        serde_json::json!({"query": "kubectl deploy"}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(text_of(&result).contains("1 result"));
}

#[tokio::test]
async fn write_delete_read_fails() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);
    let file = tmp.path().join("temp.txt");

    handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "temporary"}),
        dev_ctx(),
        state.clone(),
    ).await;

    handle_delete(
        serde_json::json!({"path": file.to_str().unwrap()}),
        dev_ctx(),
        state.clone(),
    ).await;

    let result = handle_read(
        serde_json::json!({"path": file.to_str().unwrap()}),
        dev_ctx(),
        state.clone(),
    ).await;
    assert!(result.is_error);
}

// --- approval flow ---

fn test_state_with_approval(tmpdir: &TempDir) -> Arc<DocsState> {
    let mut engine = PermissionEngine::new();
    engine.add_permission_set(
        "needs_approval".to_string(),
        PathAcl {
            ring: None,
            allow: vec![format!("{}/**", tmpdir.path().display())],
            deny: vec![],
            operations: ["read", "write", "search", "list"]
                .into_iter()
                .map(String::from)
                .collect(),
            requires_approval: ["write"].into_iter().map(String::from).collect(),
        },
    );
    let index = IndexStore::open_memory().unwrap();
    Arc::new(DocsState {
        perm_engine: Arc::new(engine),
        index: Arc::new(index),
        approvals: Arc::new(ApprovalStore::new(5)),
        notifier: Arc::new(NoopNotifier),
        embedding_model: None,
        default_root: None,
    })
}

fn approval_ctx() -> CallContext {
    CallContext::new(AgentIdentity::new("approval-agent", "needs_approval"), "test")
}

fn admin_ctx() -> CallContext {
    CallContext::new(AgentIdentity::new("admin", "admin"), "test-admin")
}

#[tokio::test]
async fn write_needs_approval_returns_request_id() {
    let tmp = TempDir::new().unwrap();
    let state = test_state_with_approval(&tmp);
    let file = tmp.path().join("needs_approval.md");

    let result = handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "content"}),
        approval_ctx(),
        state.clone(),
    ).await;

    assert!(!result.is_error);
    let text = text_of(&result);
    assert!(text.contains("Approval required"));
    assert!(text.contains("Request ID:"));
    assert!(text.contains("file_approve"));
    assert!(!file.exists());
    assert_eq!(state.approvals.pending_count(), 1);
}

#[tokio::test]
async fn approve_then_retry_succeeds() {
    let tmp = TempDir::new().unwrap();
    let state = test_state_with_approval(&tmp);
    let file = tmp.path().join("approved.md");

    handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "approved content"}),
        approval_ctx(),
        state.clone(),
    ).await;

    let pending = state.approvals.pending_requests();
    let result = handle_approve(
        serde_json::json!({"request_id": pending[0].id}),
        admin_ctx(),
        state.clone(),
    ).await;
    assert!(!result.is_error);
    assert!(text_of(&result).contains("Approved"));

    let result = handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "approved content"}),
        approval_ctx(),
        state.clone(),
    ).await;
    assert!(!result.is_error);
    assert!(text_of(&result).contains("Written"));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "approved content");
}

#[tokio::test]
async fn deny_then_retry_still_needs_approval() {
    let tmp = TempDir::new().unwrap();
    let state = test_state_with_approval(&tmp);
    let file = tmp.path().join("denied.md");

    handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "content"}),
        approval_ctx(),
        state.clone(),
    ).await;

    let pending = state.approvals.pending_requests();
    let result = handle_deny(
        serde_json::json!({"request_id": pending[0].id}),
        admin_ctx(),
        state.clone(),
    ).await;
    assert!(!result.is_error);
    assert!(text_of(&result).contains("Denied"));

    let result = handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "content"}),
        approval_ctx(),
        state.clone(),
    ).await;
    assert!(text_of(&result).contains("Approval required"));
    assert!(!file.exists());
}

#[tokio::test]
async fn approve_unknown_request_fails() {
    let tmp = TempDir::new().unwrap();
    let state = test_state_with_approval(&tmp);

    let result = handle_approve(
        serde_json::json!({"request_id": "nonexistent"}),
        admin_ctx(),
        state,
    ).await;
    assert!(result.is_error);
    assert!(text_of(&result).contains("No pending"));
}

#[tokio::test]
async fn grant_is_single_use() {
    let tmp = TempDir::new().unwrap();
    let state = test_state_with_approval(&tmp);
    let file = tmp.path().join("single_use.md");

    handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "first"}),
        approval_ctx(),
        state.clone(),
    ).await;
    let pending = state.approvals.pending_requests();
    handle_approve(
        serde_json::json!({"request_id": pending[0].id}),
        admin_ctx(),
        state.clone(),
    ).await;

    let result = handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "first"}),
        approval_ctx(),
        state.clone(),
    ).await;
    assert!(text_of(&result).contains("Written"));

    let result = handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "second"}),
        approval_ctx(),
        state.clone(),
    ).await;
    assert!(text_of(&result).contains("Approval required"));
}

#[tokio::test]
async fn read_without_approval_still_works() {
    let tmp = TempDir::new().unwrap();
    let state = test_state_with_approval(&tmp);
    let file = tmp.path().join("readable.txt");
    std::fs::write(&file, "no approval needed").unwrap();

    let result = handle_read(
        serde_json::json!({"path": file.to_str().unwrap()}),
        approval_ctx(),
        state,
    ).await;
    assert!(!result.is_error);
    assert!(text_of(&result).contains("no approval needed"));
}

#[tokio::test]
async fn dbus_approval_also_creates_grant() {
    let tmp = TempDir::new().unwrap();
    let state = test_state_with_approval(&tmp);
    let file = tmp.path().join("dbus_approved.md");

    handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "content"}),
        approval_ctx(),
        state.clone(),
    ).await;

    let pending = state.approvals.pending_requests();
    state.approvals.approve(&pending[0].id);

    let result = handle_write(
        serde_json::json!({"path": file.to_str().unwrap(), "content": "content"}),
        approval_ctx(),
        state.clone(),
    ).await;
    assert!(text_of(&result).contains("Written"));
}
