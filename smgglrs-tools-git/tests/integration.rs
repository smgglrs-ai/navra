//! Integration tests for smgglrs-tools-git public API.
//!
//! Tests GitModule construction, tool definitions, naming, and schemas.

use smgglrs_core::notify::NoopNotifier;
use smgglrs_core::permissions::{ApprovalStore, PermissionEngine};
use smgglrs_core::Module;
use smgglrs_tools_git::GitModule;
use std::sync::Arc;

// =====================================================================
// Helpers
// =====================================================================

fn build_git_module() -> GitModule {
    GitModule::new(
        Arc::new(PermissionEngine::new()),
        Arc::new(ApprovalStore::new(300)),
        Arc::new(NoopNotifier),
    )
}

// =====================================================================
// 1. Module construction and naming
// =====================================================================

#[test]
fn module_name_is_git() {
    let module = build_git_module();
    assert_eq!(module.name(), "git");
}

// =====================================================================
// 2. Tool definitions: count and names
// =====================================================================

#[test]
fn module_registers_five_tools() {
    let module = build_git_module();
    let tools = module.tools();
    assert_eq!(tools.len(), 5);
}

#[test]
fn module_registers_expected_tool_names() {
    let module = build_git_module();
    let tools = module.tools();
    let names: Vec<&str> = tools.iter().map(|(def, _)| def.name.as_str()).collect();

    let expected = [
        "git_status",
        "git_diff",
        "git_log",
        "git_branch",
        "git_commit",
    ];
    for name in &expected {
        assert!(names.contains(name), "Missing tool: {name}");
    }
}

// =====================================================================
// 3. Tool name prefixing
// =====================================================================

#[test]
fn all_tool_names_prefixed_with_git() {
    let module = build_git_module();
    let tools = module.tools();
    for (def, _) in &tools {
        assert!(
            def.name.starts_with("git_"),
            "Tool '{}' does not start with 'git_'",
            def.name
        );
    }
}

// =====================================================================
// 4. Tool definition schemas
// =====================================================================

#[test]
fn all_tools_have_object_schemas() {
    let module = build_git_module();
    let tools = module.tools();
    for (def, _) in &tools {
        assert_eq!(
            def.input_schema.schema_type, "object",
            "Tool '{}' schema_type is not 'object'",
            def.name
        );
    }
}

#[test]
fn all_tools_have_descriptions() {
    let module = build_git_module();
    let tools = module.tools();
    for (def, _) in &tools {
        assert!(
            def.description.is_some(),
            "Tool '{}' has no description",
            def.name
        );
    }
}

#[test]
fn status_tool_requires_path() {
    let module = build_git_module();
    let tools = module.tools();
    let status = tools.iter().find(|(d, _)| d.name == "git_status").unwrap();
    let required = status.0.input_schema.required.as_ref().unwrap();
    assert!(required.contains(&"path".to_string()));
}

#[test]
fn commit_tool_requires_path_and_message() {
    let module = build_git_module();
    let tools = module.tools();
    let commit = tools.iter().find(|(d, _)| d.name == "git_commit").unwrap();
    let required = commit.0.input_schema.required.as_ref().unwrap();
    assert!(required.contains(&"path".to_string()));
    assert!(required.contains(&"message".to_string()));
}

#[test]
fn diff_tool_has_staged_and_ref_properties() {
    let module = build_git_module();
    let tools = module.tools();
    let diff = tools.iter().find(|(d, _)| d.name == "git_diff").unwrap();
    let props = diff.0.input_schema.properties.as_ref().unwrap();
    assert!(props.contains_key("staged"), "diff tool missing 'staged' property");
    assert!(props.contains_key("ref"), "diff tool missing 'ref' property");
}

#[test]
fn log_tool_has_limit_and_oneline_properties() {
    let module = build_git_module();
    let tools = module.tools();
    let log = tools.iter().find(|(d, _)| d.name == "git_log").unwrap();
    let props = log.0.input_schema.properties.as_ref().unwrap();
    assert!(props.contains_key("limit"), "log tool missing 'limit' property");
    assert!(props.contains_key("oneline"), "log tool missing 'oneline' property");
}
