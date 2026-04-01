//! Safety filter as a post-tool-use hook.
//!
//! Migrates the safety filtering logic from `McpServer::apply_safety_filter()`
//! into a reusable `Hook` implementation, so it participates in the hook
//! pipeline alongside other hooks.

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use crate::protocol::{CallToolResult, Content};
use crate::safety::{FilterContext, FilterPipeline};
use std::collections::HashMap;

/// A hook that applies content safety filtering to tool results.
///
/// Looks up the appropriate `FilterPipeline` by the agent's permission
/// set name and applies it to all text content in the tool result.
pub struct SafetyHook {
    /// Safety pipelines keyed by permission set name.
    pipelines: HashMap<String, FilterPipeline>,
}

impl SafetyHook {
    /// Create a new safety hook with the given pipelines.
    pub fn new(pipelines: HashMap<String, FilterPipeline>) -> Self {
        Self { pipelines }
    }

    /// Create a safety hook from a single permission set and pipeline.
    pub fn single(permission_set: impl Into<String>, pipeline: FilterPipeline) -> Self {
        let mut pipelines = HashMap::new();
        pipelines.insert(permission_set.into(), pipeline);
        Self { pipelines }
    }

    /// Add a pipeline for a permission set.
    pub fn add_pipeline(&mut self, permission_set: impl Into<String>, pipeline: FilterPipeline) {
        self.pipelines.insert(permission_set.into(), pipeline);
    }
}

#[async_trait::async_trait]
impl Hook for SafetyHook {
    fn name(&self) -> &str {
        "safety-filter"
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        result: &CallToolResult,
        ctx: &CallContext,
    ) -> HookDecision {
        let pipeline = match self.pipelines.get(&ctx.agent.permissions) {
            Some(p) if p.has_filters() => p,
            _ => return HookDecision::Continue,
        };

        let filter_ctx = FilterContext {
            agent_name: &ctx.agent.name,
            operation: tool_name,
            path: None,
        };

        let mut filtered_content = Vec::new();
        for content in &result.content {
            match content {
                Content::Text(text) => match pipeline.process(&text.text, &filter_ctx) {
                    Ok(processed) => {
                        filtered_content.push(Content::text(processed));
                    }
                    Err(reason) => {
                        return HookDecision::ModifyResult(CallToolResult::error(reason));
                    }
                },
            }
        }

        let new_result = CallToolResult {
            content: filtered_content,
            is_error: result.is_error,
        };
        // Only return ModifyResult if content actually changed
        if new_result.content.len() != result.content.len() {
            return HookDecision::ModifyResult(new_result);
        }
        for (new, old) in new_result.content.iter().zip(result.content.iter()) {
            match (new, old) {
                (Content::Text(new_t), Content::Text(old_t)) => {
                    if new_t.text != old_t.text {
                        return HookDecision::ModifyResult(new_result);
                    }
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
        CallContext {
            agent: AgentIdentity {
                name: "tester".to_string(),
                permissions: "dev".to_string(),
            },
            session_id: "test-session".to_string(),
        }
    }

    #[tokio::test]
    async fn safety_hook_redacts_secrets() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("standard"));

        let result = CallToolResult::text("key = AKIAIOSFODNN7EXAMPLE".to_string());
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyResult(r) => {
                assert!(!r.is_error);
                match &r.content[0] {
                    Content::Text(t) => {
                        assert!(t.text.contains("[REDACTED:aws-key]"));
                        assert!(!t.text.contains("AKIAIOSFODNN7EXAMPLE"));
                    }
                }
            }
            other => panic!("Expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn safety_hook_blocks_when_configured() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("block"));

        let result = CallToolResult::text("SSN: 123-45-6789".to_string());
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyResult(r) => {
                assert!(r.is_error);
            }
            other => panic!("Expected ModifyResult (error), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn safety_hook_continues_on_clean_content() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("standard"));

        let result = CallToolResult::text("Hello, world!".to_string());
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn safety_hook_continues_on_unknown_permission_set() {
        let hook = SafetyHook::single("admin", crate::safety::build_pipeline("standard"));

        // ctx uses "dev" but hook only has "admin" pipeline
        let result = CallToolResult::text("AKIAIOSFODNN7EXAMPLE".to_string());
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;

        // No matching pipeline -> continue unchanged
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn safety_hook_continues_on_none_profile() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("none"));

        let result = CallToolResult::text("AKIAIOSFODNN7EXAMPLE".to_string());
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;

        // "none" profile has no filters -> continue
        assert!(matches!(decision, HookDecision::Continue));
    }
}
