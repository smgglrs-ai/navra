//! Integration tests for smgglrs-tools-docs public API.
//!
//! Tests DocsModule construction, tool definitions, and IndexStore behavior
//! through the public interface only.

use smgglrs_core::auth::{AgentIdentity, CallContext};
use smgglrs_core::notify::NoopNotifier;
use smgglrs_core::permissions::{ApprovalStore, PathAcl, PermissionEngine};
use smgglrs_core::protocol::Content;
use smgglrs_core::Module;
use smgglrs_tools_docs::{DocsModule, IndexStore};
use std::collections::HashSet;
use std::sync::Arc;

// =====================================================================
// Helpers
// =====================================================================

fn build_docs_module() -> DocsModule {
    let engine = Arc::new(PermissionEngine::new());
    let index = Arc::new(IndexStore::open_memory().unwrap());
    let approvals = Arc::new(ApprovalStore::new(300));
    let notifier: Arc<dyn smgglrs_core::notify::Notifier> = Arc::new(NoopNotifier);
    DocsModule::new(engine, index, approvals, notifier)
}

fn build_docs_module_with_perms(tmpdir: &tempfile::TempDir) -> DocsModule {
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
    let index = Arc::new(IndexStore::open_memory().unwrap());
    let approvals = Arc::new(ApprovalStore::new(300));
    let notifier: Arc<dyn smgglrs_core::notify::Notifier> = Arc::new(NoopNotifier);
    DocsModule::new(Arc::new(engine), index, approvals, notifier)
}

fn dev_ctx() -> CallContext {
    CallContext::new(AgentIdentity::new("test-agent", "dev"), "test-session")
}

fn text_of(result: &smgglrs_core::protocol::CallToolResult) -> &str {
    match &result.content[0] {
        Content::Text(t) => &t.text,
    }
}

// =====================================================================
// 1. Module construction and naming
// =====================================================================

#[test]
fn module_name_is_docs() {
    let module = build_docs_module();
    assert_eq!(module.name(), "docs");
}

// =====================================================================
// 2. Tool definitions: count and names
// =====================================================================

#[test]
fn module_registers_all_expected_tools() {
    let module = build_docs_module();
    let tools = module.tools();
    let names: Vec<&str> = tools.iter().map(|(def, _)| def.name.as_str()).collect();

    // Without embedding model, semantic_search is not registered
    assert_eq!(tools.len(), 11);

    let expected = [
        "docs_search",
        "docs_read",
        "docs_list",
        "docs_write",
        "docs_edit",
        "docs_info",
        "docs_delete",
        "docs_approve",
        "docs_deny",
        "docs_tree",
        "docs_grep",
    ];
    for name in &expected {
        assert!(names.contains(name), "Missing tool: {name}");
    }
}

#[test]
fn all_tool_names_prefixed_with_docs() {
    let module = build_docs_module();
    let tools = module.tools();
    for (def, _) in &tools {
        assert!(
            def.name.starts_with("docs_"),
            "Tool '{}' does not start with 'docs_'",
            def.name
        );
    }
}

// =====================================================================
// 3. Tool definition schemas
// =====================================================================

#[test]
fn tool_schemas_have_correct_types() {
    let module = build_docs_module();
    let tools = module.tools();
    for (def, _) in &tools {
        assert_eq!(
            def.input_schema.schema_type, "object",
            "Tool '{}' schema_type is not 'object'",
            def.name
        );
        // Every tool should have a description
        assert!(
            def.description.is_some(),
            "Tool '{}' has no description",
            def.name
        );
    }
}

#[test]
fn read_tool_requires_path() {
    let module = build_docs_module();
    let tools = module.tools();
    let read = tools.iter().find(|(d, _)| d.name == "docs_read").unwrap();
    let required = read.0.input_schema.required.as_ref().unwrap();
    assert!(required.contains(&"path".to_string()));
}

#[test]
fn write_tool_requires_path_and_content() {
    let module = build_docs_module();
    let tools = module.tools();
    let write = tools.iter().find(|(d, _)| d.name == "docs_write").unwrap();
    let required = write.0.input_schema.required.as_ref().unwrap();
    assert!(required.contains(&"path".to_string()));
    assert!(required.contains(&"content".to_string()));
}

#[test]
fn grep_tool_requires_path_and_pattern() {
    let module = build_docs_module();
    let tools = module.tools();
    let grep = tools.iter().find(|(d, _)| d.name == "docs_grep").unwrap();
    let required = grep.0.input_schema.required.as_ref().unwrap();
    assert!(required.contains(&"path".to_string()));
    assert!(required.contains(&"pattern".to_string()));
}

#[test]
fn tree_tool_has_no_required_params() {
    let module = build_docs_module();
    let tools = module.tools();
    let tree = tools.iter().find(|(d, _)| d.name == "docs_tree").unwrap();
    assert!(tree.0.input_schema.required.is_none());
}

// =====================================================================
// 4. IndexStore public API
// =====================================================================

#[test]
fn index_store_open_memory_succeeds() {
    let store = IndexStore::open_memory().unwrap();
    assert_eq!(store.count().unwrap(), 0);
}

#[test]
fn index_store_upsert_search_roundtrip() {
    let store = IndexStore::open_memory().unwrap();
    store
        .upsert(
            "/test/doc.md",
            "text/markdown",
            42,
            "123",
            "hash",
            "Test Doc",
            "rust async programming patterns",
        )
        .unwrap();

    assert_eq!(store.count().unwrap(), 1);

    let results = store.search("rust programming", 10).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].path, "/test/doc.md");
    assert_eq!(results[0].title, "Test Doc");
}

#[test]
fn index_store_delete_removes_from_search() {
    let store = IndexStore::open_memory().unwrap();
    store
        .upsert("/a.md", "text/markdown", 10, "t", "h", "A", "unique content here")
        .unwrap();

    assert!(store.delete("/a.md").unwrap());
    assert_eq!(store.count().unwrap(), 0);
    assert!(store.search("unique content", 10).unwrap().is_empty());
}

// =====================================================================
// 5. set_default_root
// =====================================================================

#[test]
fn set_default_root_changes_module_state() {
    let mut module = build_docs_module();
    // Should not panic
    module.set_default_root("/home/user/project".to_string());
    // Module should still work after replacing state
    assert_eq!(module.name(), "docs");
    assert_eq!(module.tools().len(), 11);
}
