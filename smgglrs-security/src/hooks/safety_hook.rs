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
use smgglrs_protocol::label::Confidentiality;
use smgglrs_protocol::{CallToolResult, Content};
use crate::safety::{is_pii_category, FilterContext, FilterPipeline};
use std::collections::HashMap;

/// Operations that carry content from the agent into the system
/// (write-path). These get inbound filtering.
const WRITE_OPS: &[&str] = &[
    "file_write",
    "file_edit",
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
        if !WRITE_OPS.contains(&tool_name) {
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
        let mut has_pii = false;
        for content in &result.content {
            match content {
                Content::Text(text) => {
                    let (processed, findings) = pipeline
                        .process_outbound_with_findings(&text.text, &filter_ctx)
                        .await;
                    // Track whether any finding is PII — even if redacted,
                    // the label persists so downstream consumers know.
                    if findings.iter().any(|f| is_pii_category(&f.category)) {
                        has_pii = true;
                    }
                    match processed {
                        Ok(text) => {
                            filtered_content.push(Content::text(text));
                        }
                        Err(reason) => {
                            return HookDecision::ModifyResult(CallToolResult::error(reason));
                        }
                    }
                }
            }
        }

        // Elevate IFC label to at least Pii if PII was detected
        let label = if has_pii && result.label.confidentiality < Confidentiality::Pii {
            smgglrs_protocol::label::DataLabel {
                integrity: result.label.integrity,
                confidentiality: Confidentiality::Pii,
            }
        } else {
            result.label
        };

        let new_result = CallToolResult {
            content: filtered_content,
            is_error: result.is_error,
            label,
        };
        // Return ModifyResult if content or label changed
        if label != result.label {
            return HookDecision::ModifyResult(new_result);
        }
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
    use smgglrs_protocol::label::Confidentiality;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
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
    async fn safety_hook_elevates_pii_label() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("standard"));

        // Content contains an SSN (PII category)
        let result = CallToolResult::text("SSN: 123-45-6789".to_string());
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyResult(r) => {
                // Content should be redacted
                match &r.content[0] {
                    Content::Text(t) => assert!(t.text.contains("[REDACTED:ssn]")),
                }
                // Label should be elevated to Pii
                assert_eq!(r.label.confidentiality, Confidentiality::Pii);
            }
            other => panic!("Expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn safety_hook_elevates_email_to_pii() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("standard"));

        let result = CallToolResult::text("Contact: john@example.com".to_string());
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyResult(r) => {
                assert_eq!(r.label.confidentiality, Confidentiality::Pii);
            }
            other => panic!("Expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn safety_hook_does_not_downgrade_secret_for_pii() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("standard"));

        // Result already labeled Secret — PII should not downgrade it
        let mut result = CallToolResult::text("SSN: 123-45-6789".to_string());
        result.label.confidentiality = Confidentiality::Secret;
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyResult(r) => {
                assert_eq!(r.label.confidentiality, Confidentiality::Secret);
            }
            other => panic!("Expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn safety_hook_secrets_only_no_pii_elevation() {
        // "secrets-only" profile doesn't include PII filter
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("secrets-only"));

        let result = CallToolResult::text("SSN: 123-45-6789".to_string());
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;

        // No PII filter in secrets-only, so no findings, no label change
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn inbound_skips_non_write_tools() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("block"));

        let args = serde_json::json!({"path": "/tmp/test", "content": "SSN: 123-45-6789"});
        let decision = hook
            .pre_tool_use("file_read", &args, &test_ctx())
            .await;

        // file_read is not a write-path tool, so inbound filtering skips it
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn inbound_continues_on_clean_write() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("standard"));

        let args = serde_json::json!({"path": "/tmp/test", "content": "Hello, world!"});
        let decision = hook
            .pre_tool_use("file_write", &args, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }
}
