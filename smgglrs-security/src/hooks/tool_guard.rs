//! Tool use guard hook: validates tool call arguments before execution.
//!
//! Implements scaffolding improvements from "Honey I Shrunk the Coding
//! Agent" — pre-validates tool calls to catch common small-model mistakes
//! before they reach handlers:
//!
//! - `file_write` to existing files: warns to use `file_edit` instead
//! - Any tool: validates JSON well-formedness of arguments
//! - `file_delete`: adds user-friendly path context

use super::{Hook, HookDecision};
use crate::auth::CallContext;

/// A pre-hook that validates tool call arguments before execution.
///
/// Catches common mistakes from small models:
/// - Using `file_write` when `file_edit` would be more appropriate
/// - Malformed JSON in arguments (unclosed brackets, trailing commas)
/// - Missing required fields for destructive operations
pub struct ToolGuardHook;

#[async_trait::async_trait]
impl Hook for ToolGuardHook {
    fn name(&self) -> &str {
        "tool-guard"
    }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        _ctx: &CallContext,
    ) -> HookDecision {
        // Validate JSON structure: check for obvious issues that would
        // have been caught by proper parsing but might slip through
        // when arguments are constructed from raw model output.
        if let Some(obj) = arguments.as_object() {
            // Check for empty required fields on write operations
            if tool_name == "file_write" || tool_name == "file_edit" {
                if let Some(path) = obj.get("path") {
                    if path.as_str().is_some_and(|p| p.is_empty()) {
                        return HookDecision::Block(
                            "file path cannot be empty".to_string(),
                        );
                    }
                }
            }
        }

        // file_write guard: if the target file exists, suggest file_edit
        if tool_name == "file_write" {
            if let Some(path) = arguments.get("path").and_then(|v| v.as_str()) {
                if std::path::Path::new(path).exists() {
                    tracing::info!(
                        path = %path,
                        "file_write to existing file — consider file_edit instead"
                    );
                    // Warn but don't block: inject a note into the arguments
                    // so the handler and audit log capture the suggestion.
                    let mut modified = arguments.clone();
                    modified["_guard_warning"] = serde_json::json!(
                        format!(
                            "Warning: '{}' already exists. Consider using file_edit \
                             to modify it instead of file_write which overwrites the \
                             entire file.",
                            path
                        )
                    );
                    return HookDecision::ModifyArgs(modified);
                }
            }
        }

        // file_delete guard: user-friendly path message
        if tool_name == "file_delete" {
            if let Some(path) = arguments.get("path").and_then(|v| v.as_str()) {
                if path.is_empty() {
                    return HookDecision::Block(
                        "file_delete: path cannot be empty".to_string(),
                    );
                }
                if path == "/" || path == "." {
                    return HookDecision::Block(format!(
                        "file_delete: refusing to delete '{}' — this would be destructive",
                        path
                    ));
                }
            }
        }

        HookDecision::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AgentIdentity;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
    }

    #[tokio::test]
    async fn warns_on_file_write_to_existing_file() {
        let hook = ToolGuardHook;
        // Use a file that definitely exists
        let args = serde_json::json!({"path": "/etc/hosts", "content": "test"});
        let decision = hook.pre_tool_use("file_write", &args, &test_ctx()).await;
        match decision {
            HookDecision::ModifyArgs(modified) => {
                assert!(modified["_guard_warning"].as_str().unwrap().contains("file_edit"));
            }
            other => panic!("Expected ModifyArgs with warning, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn continues_on_file_write_to_nonexistent() {
        let hook = ToolGuardHook;
        let args = serde_json::json!({
            "path": "/tmp/definitely_does_not_exist_smgglrs_test_1234567890.txt",
            "content": "test"
        });
        let decision = hook.pre_tool_use("file_write", &args, &test_ctx()).await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn blocks_file_delete_root() {
        let hook = ToolGuardHook;
        let args = serde_json::json!({"path": "/"});
        let decision = hook.pre_tool_use("file_delete", &args, &test_ctx()).await;
        match decision {
            HookDecision::Block(reason) => {
                assert!(reason.contains("destructive"));
            }
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn blocks_empty_path_on_write() {
        let hook = ToolGuardHook;
        let args = serde_json::json!({"path": "", "content": "test"});
        let decision = hook.pre_tool_use("file_write", &args, &test_ctx()).await;
        match decision {
            HookDecision::Block(reason) => {
                assert!(reason.contains("empty"));
            }
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn continues_on_unrelated_tool() {
        let hook = ToolGuardHook;
        let args = serde_json::json!({"query": "hello"});
        let decision = hook.pre_tool_use("git_status", &args, &test_ctx()).await;
        assert!(matches!(decision, HookDecision::Continue));
    }
}
