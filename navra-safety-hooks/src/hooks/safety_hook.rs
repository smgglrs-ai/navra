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
use crate::safety::{FilterContext, FilterPipeline};
use navra_auth::auth::CallContext;
use navra_protocol::compat::CallToolResultExt;
use navra_protocol::{CallToolResult, Content, RawContent};
use std::collections::HashMap;

use navra_auth::ifc::is_write_tool;

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
        _annotations: Option<&navra_protocol::ToolAnnotations>,
    ) -> HookDecision {
        if !is_write_tool(tool_name, None) {
            return HookDecision::Continue;
        }

        let pipeline = match self.pipelines.get(&ctx.agent.permissions) {
            Some(p) if p.has_filters() => p,
            _ => return HookDecision::Continue,
        };

        let filter_ctx = FilterContext {
            agent_name: &ctx.agent.name,
            operation: tool_name,
            path: arguments.get("path").and_then(|v| v.as_str()),
        };

        // Scan ALL string-valued fields, not just hardcoded names.
        // Skip known-safe fields that contain paths/identifiers, not content.
        const SKIP_FIELDS: &[&str] = &[
            "path",
            "repo",
            "branch",
            "source_branch",
            "target_branch",
            "ref",
            "working_dir",
            "command",
            "id",
            "name",
            "key",
        ];

        if let Some(obj) = arguments.as_object() {
            for (field, value) in obj {
                if SKIP_FIELDS.contains(&field.as_str()) {
                    continue;
                }
                if let Some(text) = value.as_str() {
                    if text.is_empty() {
                        continue;
                    }
                    match pipeline.process_inbound(text, &filter_ctx).await {
                        Ok(_) => {}
                        Err(reason) => {
                            return HookDecision::Block(format!(
                                "blocked in field '{}': {}",
                                field, reason
                            ));
                        }
                    }
                }
            }
        }

        HookDecision::Continue
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
            match &content.raw {
                RawContent::Text(text) => {
                    let (processed, _findings) = pipeline
                        .process_outbound_with_findings(&text.text, &filter_ctx)
                        .await;
                    match processed {
                        Ok(text) => {
                            filtered_content.push(Content::text(text));
                        }
                        Err(reason) => {
                            return HookDecision::ModifyResult(CallToolResult::error_msg(reason));
                        }
                    }
                }
                RawContent::Resource(res) => {
                    use navra_protocol::ResourceContent;
                    match &res.resource {
                        ResourceContent::TextResourceContents {
                            mime_type, text, ..
                        } => {
                            if mime_type.as_deref().is_some_and(|m| m.starts_with("text/")) {
                                let (processed, _findings) = pipeline
                                    .process_outbound_with_findings(text, &filter_ctx)
                                    .await;
                                match processed {
                                    Ok(t) => filtered_content.push(Content::text(t)),
                                    Err(reason) => {
                                        return HookDecision::ModifyResult(
                                            CallToolResult::error_msg(reason),
                                        );
                                    }
                                }
                            } else {
                                filtered_content.push(content.clone());
                            }
                        }
                        ResourceContent::BlobResourceContents { .. } => {
                            return HookDecision::ModifyResult(CallToolResult::error_msg(
                                "Non-text resource content blocked by safety pipeline",
                            ));
                        }
                    }
                }
                _ => {
                    return HookDecision::ModifyResult(CallToolResult::error_msg(
                        "Non-text content blocked by safety pipeline (no binary filter configured)",
                    ));
                }
            }
        }

        let mut new_result = CallToolResult::success(filtered_content);
        new_result.is_error = result.is_error;

        // Return ModifyResult if content changed
        if new_result.content.len() != result.content.len() {
            return HookDecision::ModifyResult(new_result);
        }
        for (new_c, old_c) in new_result.content.iter().zip(result.content.iter()) {
            if let (RawContent::Text(new_t), RawContent::Text(old_t)) = (&new_c.raw, &old_c.raw)
                && new_t.text != old_t.text {
                    return HookDecision::ModifyResult(new_result);
                }
        }
        HookDecision::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_auth::auth::AgentIdentity;

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
                assert!(!r.is_err());
                match &r.content[0].raw {
                    RawContent::Text(t) => {
                        assert!(t.text.contains("[REDACTED:aws-key]"));
                        assert!(!t.text.contains("AKIAIOSFODNN7EXAMPLE"));
                    }
                    _ => panic!("expected text content"),
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
                assert!(r.is_err());
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
    async fn safety_hook_redacts_pii() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("standard"));

        // Content contains an SSN (PII category)
        let result = CallToolResult::text("SSN: 123-45-6789".to_string());
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyResult(r) => {
                // Content should be redacted
                match &r.content[0].raw {
                    RawContent::Text(t) => assert!(t.text.contains("[REDACTED:ssn]")),
                    _ => panic!("expected text content"),
                }
            }
            other => panic!("Expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn safety_hook_redacts_email() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("standard"));

        let result = CallToolResult::text("Contact: john@example.com".to_string());
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyResult(r) => match &r.content[0].raw {
                RawContent::Text(t) => assert!(t.text.contains("[REDACTED:")),
                _ => panic!("expected text content"),
            },
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
            .pre_tool_use("file_read", &args, &test_ctx(), None)
            .await;

        // file_read is not a write-path tool, so inbound filtering skips it
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn inbound_scans_non_standard_field_names() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("block"));

        // "body" and "payload" are non-standard field names that should now be scanned
        let args = serde_json::json!({"path": "/tmp/test", "body": "SSN: 123-45-6789"});
        let decision = hook
            .pre_tool_use("file_write", &args, &test_ctx(), None)
            .await;

        assert!(
            matches!(decision, HookDecision::Block(_)),
            "Expected Block for 'body' field with SSN, got {decision:?}"
        );
    }

    #[tokio::test]
    async fn inbound_skips_path_fields() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("block"));

        // "path" is in the skip list, so its content should not trigger blocking
        let args = serde_json::json!({"path": "AKIAIOSFODNN7EXAMPLE", "content": "clean"});
        let decision = hook
            .pre_tool_use("file_write", &args, &test_ctx(), None)
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn inbound_continues_on_clean_write() {
        let hook = SafetyHook::single("dev", crate::safety::build_pipeline("standard"));

        let args = serde_json::json!({"path": "/tmp/test", "content": "Hello, world!"});
        let decision = hook
            .pre_tool_use("file_write", &args, &test_ctx(), None)
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }
}
