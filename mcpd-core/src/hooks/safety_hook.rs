//! Safety filter as a pre- and post-tool-use hook.
//!
//! **Outbound** (post-hook): Filters tool responses before they reach
//! the agent. Applies regex + ML filters to redact secrets, PII, and
//! unsafe content.
//!
//! **Inbound** (pre-hook): Filters tool arguments on write-path
//! operations (write, edit, voice.speak). Applies ML filters only —
//! regex secret detection is irrelevant for content an agent is writing.

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use crate::protocol::{CallToolResult, Content};
use crate::safety::{FilterContext, FilterPipeline};
use std::collections::HashMap;

/// Operations that carry content from the agent into the system
/// (write-path). These get inbound filtering.
const WRITE_OPS: &[&str] = &[
    "docs_write",
    "docs_edit",
    "voice_speak",
];

/// A hook that applies content safety filtering to tool calls.
///
/// Looks up the appropriate `FilterPipeline` by the agent's permission
/// set name and applies it:
/// - **post_tool_use**: outbound filtering on all tool responses
/// - **pre_tool_use**: inbound filtering on write-path tool arguments
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

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        ctx: &CallContext,
    ) -> HookDecision {
        // Only filter write-path operations
        if !WRITE_OPS.iter().any(|op| *op == tool_name) {
            return HookDecision::Continue;
        }

        let pipeline = match self.pipelines.get(&ctx.agent.permissions) {
            Some(p) if p.has_filters() => p,
            _ => return HookDecision::Continue,
        };

        // Extract the content field from arguments
        let content_field = arguments
            .get("content")
            .or_else(|| arguments.get("new_string"))
            .or_else(|| arguments.get("text"))
            .and_then(|v| v.as_str());

        let content = match content_field {
            Some(c) => c,
            None => return HookDecision::Continue,
        };

        let filter_ctx = FilterContext {
            agent_name: &ctx.agent.name,
            operation: tool_name,
            path: arguments.get("path").and_then(|v| v.as_str()),
        };

        match pipeline.process_inbound(content, &filter_ctx).await {
            Ok(_) => HookDecision::Continue,
            Err(reason) => HookDecision::Block(reason),
        }
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
                Content::Text(text) => {
                    match pipeline.process_outbound(&text.text, &filter_ctx).await {
                        Ok(processed) => {
                            filtered_content.push(Content::text(processed));
                        }
                        Err(reason) => {
                            return HookDecision::ModifyResult(CallToolResult::error(reason));
                        }
                    }
                }
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

    #[tokio::test]
    async fn inbound_skips_non_write_tools() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("block"));

        let args = serde_json::json!({"path": "/tmp/test", "content": "SSN: 123-45-6789"});
        let decision = hook
            .pre_tool_use("docs_read", &args, &test_ctx())
            .await;

        // docs_read is not a write-path tool, so inbound filtering skips it
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn inbound_continues_on_clean_write() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("standard"));

        let args = serde_json::json!({"path": "/tmp/test", "content": "Hello, world!"});
        let decision = hook
            .pre_tool_use("docs_write", &args, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }
}
