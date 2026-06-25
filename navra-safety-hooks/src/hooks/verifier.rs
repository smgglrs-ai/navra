//! Post-tool-use verifier hook with false-pass-rate tracking.
//!
//! Checks tool results against configurable rubrics (empty output,
//! keyword matches, excessive length) and tracks per-tool verification
//! statistics including a false-pass-rate metric for safety-critical
//! domains.

use super::{Hook, HookDecision};
use navra_auth::auth::CallContext;
use navra_protocol::CallToolResult;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;

/// Per-tool verification counters.
#[derive(Debug, Clone, Default)]
pub struct VerifierStats {
    pub total: u64,
    pub passed: u64,
    pub failed: u64,
    /// Suspicious results that passed (false passes).
    pub flagged: u64,
}

impl VerifierStats {
    pub fn false_pass_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.flagged as f64 / self.total as f64
        }
    }
}

/// Configuration for the verifier hook.
#[derive(Debug, Clone, Default)]
pub struct VerifierConfig {
    /// Tool name patterns to verify (empty = all tools).
    pub tool_patterns: Vec<String>,
    /// Keywords in output that indicate suspicious results.
    pub rubric_keywords: Vec<String>,
    /// Maximum output length before flagging (0 = no limit).
    pub max_output_length: usize,
    /// Whether to block suspicious results or just track them.
    pub block_on_fail: bool,
}

/// Post-tool-use hook that verifies results against rubrics and
/// tracks false-pass-rate metrics per tool.
pub struct VerifierHook {
    config: VerifierConfig,
    stats: Mutex<HashMap<String, VerifierStats>>,
}

impl VerifierHook {
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            config,
            stats: Mutex::new(HashMap::new()),
        }
    }

    fn should_verify(&self, tool_name: &str) -> bool {
        if self.config.tool_patterns.is_empty() {
            return true;
        }
        self.config
            .tool_patterns
            .iter()
            .any(|p| tool_name.contains(p.as_str()))
    }

    fn extract_text(result: &CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|c| match c {
                navra_protocol::Content {
                    raw: navra_protocol::RawContent::Text(t),
                    ..
                } => Some(t.text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn check_rubrics(&self, text: &str) -> Option<String> {
        if text.trim().is_empty() {
            return Some("empty result".into());
        }

        let text_lower = text.to_lowercase();
        for keyword in &self.config.rubric_keywords {
            if text_lower.contains(&keyword.to_lowercase()) {
                return Some(format!("rubric keyword match: {keyword}"));
            }
        }

        if self.config.max_output_length > 0 && text.len() > self.config.max_output_length {
            return Some(format!(
                "output length {} exceeds limit {}",
                text.len(),
                self.config.max_output_length
            ));
        }

        None
    }

    /// Render Prometheus-format metrics for all tracked tools.
    pub fn render_metrics(&self) -> String {
        let stats = self.stats.lock().unwrap();
        let mut out = String::new();

        let _ = writeln!(
            out,
            "# HELP navra_verifier_total Total verifications per tool"
        );
        let _ = writeln!(out, "# TYPE navra_verifier_total counter");
        for (tool, s) in &*stats {
            let _ = writeln!(out, "navra_verifier_total{{tool=\"{tool}\"}} {}", s.total);
        }

        let _ = writeln!(
            out,
            "# HELP navra_verifier_passed Passed verifications per tool"
        );
        let _ = writeln!(out, "# TYPE navra_verifier_passed counter");
        for (tool, s) in &*stats {
            let _ = writeln!(out, "navra_verifier_passed{{tool=\"{tool}\"}} {}", s.passed);
        }

        let _ = writeln!(
            out,
            "# HELP navra_verifier_flagged Flagged (suspicious pass) verifications per tool"
        );
        let _ = writeln!(out, "# TYPE navra_verifier_flagged counter");
        for (tool, s) in &*stats {
            let _ = writeln!(
                out,
                "navra_verifier_flagged{{tool=\"{tool}\"}} {}",
                s.flagged
            );
        }

        let _ = writeln!(
            out,
            "# HELP navra_verifier_false_pass_rate Ratio of flagged to total verifications"
        );
        let _ = writeln!(out, "# TYPE navra_verifier_false_pass_rate gauge");
        for (tool, s) in &*stats {
            let _ = writeln!(
                out,
                "navra_verifier_false_pass_rate{{tool=\"{tool}\"}} {:.6}",
                s.false_pass_rate()
            );
        }

        out
    }

    /// Get a snapshot of stats for a specific tool.
    pub fn tool_stats(&self, tool_name: &str) -> Option<VerifierStats> {
        self.stats.lock().unwrap().get(tool_name).cloned()
    }
}

#[async_trait::async_trait]
impl Hook for VerifierHook {
    fn name(&self) -> &str {
        "verifier"
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        result: &CallToolResult,
        _ctx: &CallContext,
    ) -> HookDecision {
        if !self.should_verify(tool_name) {
            return HookDecision::Continue;
        }

        let text = Self::extract_text(result);
        let flag_reason = self.check_rubrics(&text);

        {
            let mut stats = self.stats.lock().unwrap();
            let entry = stats.entry(tool_name.to_string()).or_default();
            entry.total += 1;

            if result.is_error == Some(true) {
                entry.failed += 1;
            } else if let Some(ref _reason) = flag_reason {
                entry.flagged += 1;
            } else {
                entry.passed += 1;
            }
        }

        if let Some(reason) = flag_reason {
            tracing::warn!(
                tool = %tool_name,
                reason = %reason,
                "Verifier hook: suspicious tool result"
            );
            if self.config.block_on_fail {
                return HookDecision::Block(format!(
                    "verifier: tool {tool_name} result flagged — {reason}"
                ));
            }
        }

        HookDecision::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_auth::auth::AgentIdentity;
    use navra_protocol::compat::CallToolResultExt;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
    }

    #[tokio::test]
    async fn empty_result_is_flagged() {
        let hook = VerifierHook::new(VerifierConfig {
            block_on_fail: true,
            ..Default::default()
        });

        let result = CallToolResult::text("");
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::Block(reason) => {
                assert!(reason.contains("empty result"), "got: {reason}");
            }
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn keyword_match_is_flagged() {
        let hook = VerifierHook::new(VerifierConfig {
            rubric_keywords: vec!["ERROR".into(), "UNAUTHORIZED".into()],
            block_on_fail: true,
            ..Default::default()
        });

        let result = CallToolResult::text("Access UNAUTHORIZED for this resource");
        let decision = hook
            .post_tool_use("api_call", &serde_json::json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::Block(reason) => {
                assert!(reason.contains("UNAUTHORIZED"), "got: {reason}");
            }
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn normal_result_passes() {
        let hook = VerifierHook::new(VerifierConfig {
            rubric_keywords: vec!["ERROR".into()],
            block_on_fail: true,
            ..Default::default()
        });

        let result = CallToolResult::text("File contents: hello world");
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn max_length_exceeded_is_flagged() {
        let hook = VerifierHook::new(VerifierConfig {
            max_output_length: 10,
            block_on_fail: true,
            ..Default::default()
        });

        let result = CallToolResult::text("this is definitely longer than ten characters");
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::Block(reason) => {
                assert!(reason.contains("output length"), "got: {reason}");
            }
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn false_pass_rate_calculation() {
        let hook = VerifierHook::new(VerifierConfig {
            rubric_keywords: vec!["bad".into()],
            block_on_fail: false,
            ..Default::default()
        });
        let ctx = test_ctx();

        // 2 clean passes
        for _ in 0..2 {
            hook.post_tool_use(
                "tool_a",
                &serde_json::json!({}),
                &CallToolResult::text("good result"),
                &ctx,
            )
            .await;
        }

        // 1 flagged (keyword match, but not blocked)
        hook.post_tool_use(
            "tool_a",
            &serde_json::json!({}),
            &CallToolResult::text("bad result"),
            &ctx,
        )
        .await;

        let stats = hook.tool_stats("tool_a").unwrap();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.passed, 2);
        assert_eq!(stats.flagged, 1);
        assert!((stats.false_pass_rate() - 1.0 / 3.0).abs() < 1e-6);
    }

    #[tokio::test]
    async fn error_results_counted_as_failed() {
        let hook = VerifierHook::new(VerifierConfig::default());
        let ctx = test_ctx();

        let error_result = CallToolResult::error_msg("something went wrong");
        hook.post_tool_use("tool_a", &serde_json::json!({}), &error_result, &ctx)
            .await;

        let stats = hook.tool_stats("tool_a").unwrap();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.passed, 0);
        assert_eq!(stats.flagged, 0);
    }

    #[tokio::test]
    async fn tool_pattern_filtering() {
        let hook = VerifierHook::new(VerifierConfig {
            tool_patterns: vec!["file_".into()],
            block_on_fail: true,
            ..Default::default()
        });
        let ctx = test_ctx();

        // Non-matching tool should pass through
        let result = CallToolResult::text("");
        let decision = hook
            .post_tool_use("git_status", &serde_json::json!({}), &result, &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
        assert!(hook.tool_stats("git_status").is_none());

        // Matching tool should be checked (and blocked for empty)
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Block(_)));
    }

    #[tokio::test]
    async fn metrics_rendering() {
        let hook = VerifierHook::new(VerifierConfig {
            rubric_keywords: vec!["suspicious".into()],
            ..Default::default()
        });
        let ctx = test_ctx();

        hook.post_tool_use(
            "tool_a",
            &serde_json::json!({}),
            &CallToolResult::text("clean output"),
            &ctx,
        )
        .await;
        hook.post_tool_use(
            "tool_a",
            &serde_json::json!({}),
            &CallToolResult::text("suspicious output"),
            &ctx,
        )
        .await;

        let metrics = hook.render_metrics();
        assert!(metrics.contains("navra_verifier_total{tool=\"tool_a\"} 2"));
        assert!(metrics.contains("navra_verifier_passed{tool=\"tool_a\"} 1"));
        assert!(metrics.contains("navra_verifier_flagged{tool=\"tool_a\"} 1"));
        assert!(metrics.contains("navra_verifier_false_pass_rate{tool=\"tool_a\"}"));
    }

    #[tokio::test]
    async fn hook_name() {
        let hook = VerifierHook::new(VerifierConfig::default());
        assert_eq!(hook.name(), "verifier");
    }

    #[tokio::test]
    async fn flagged_but_not_blocked_when_block_off() {
        let hook = VerifierHook::new(VerifierConfig {
            rubric_keywords: vec!["warning".into()],
            block_on_fail: false,
            ..Default::default()
        });
        let ctx = test_ctx();

        let result = CallToolResult::text("this has a warning in it");
        let decision = hook
            .post_tool_use("tool_a", &serde_json::json!({}), &result, &ctx)
            .await;

        assert!(matches!(decision, HookDecision::Continue));
        let stats = hook.tool_stats("tool_a").unwrap();
        assert_eq!(stats.flagged, 1);
    }

    #[tokio::test]
    async fn keyword_match_is_case_insensitive() {
        let hook = VerifierHook::new(VerifierConfig {
            rubric_keywords: vec!["ERROR".into()],
            block_on_fail: true,
            ..Default::default()
        });

        let result = CallToolResult::text("something had an error");
        let decision = hook
            .post_tool_use("tool_a", &serde_json::json!({}), &result, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Block(_)));
    }
}
