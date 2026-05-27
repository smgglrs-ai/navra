//! Sandbox hook: enforces per-agent sandbox profiles in the hook pipeline.
//!
//! Reads the `SandboxProfile` from `ctx.sandbox` and applies the matching
//! rule for the tool being called:
//! - Simulate: return canned response without executing the tool
//! - Redact: execute the tool, then redact matching patterns from output
//! - RateLimit: enforce per-tool call rate limits
//! - PathRewrite: rewrite path arguments before execution

use crate::auth::sandbox_profile::{SandboxAction, SandboxProfile};
use crate::auth::CallContext;
use crate::hooks::{Hook, HookDecision};
use smgglrs_protocol::CallToolResult;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Hook that enforces sandbox profiles from capability tokens.
pub struct SandboxHook {
    /// Per-agent, per-tool rate limit state: (agent_name, tool_name) -> (count, window_start)
    rate_state: Mutex<HashMap<(String, String), (u32, Instant)>>,
}

impl SandboxHook {
    pub fn new() -> Self {
        Self {
            rate_state: Mutex::new(HashMap::new()),
        }
    }

    /// Check rate limit for a tool call. Returns true if allowed.
    fn check_rate_limit(
        &self,
        agent_name: &str,
        tool_name: &str,
        max_calls: u32,
        window_secs: u64,
    ) -> bool {
        let key = (agent_name.to_string(), tool_name.to_string());
        let mut state = self.rate_state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let window = std::time::Duration::from_secs(window_secs);

        let entry = state.entry(key).or_insert((0, now));
        if now.duration_since(entry.1) >= window {
            // Reset window
            *entry = (1, now);
            true
        } else if entry.0 < max_calls {
            entry.0 += 1;
            true
        } else {
            false
        }
    }

    /// Apply redaction patterns to text content.
    fn redact_text(text: &str, patterns: &[String], replacement: &str) -> String {
        let mut result = text.to_string();
        for pattern in patterns {
            if let Ok(re) = regex_lite::Regex::new(pattern) {
                result = re.replace_all(&result, replacement).to_string();
            }
        }
        result
    }

    /// Rewrite path arguments in a JSON value.
    fn rewrite_paths(
        args: &serde_json::Value,
        strip_prefix: &str,
        add_prefix: &str,
    ) -> serde_json::Value {
        let mut args = args.clone();
        if let Some(obj) = args.as_object_mut() {
            for key in ["path", "file", "directory", "repo"] {
                if let Some(val) = obj.get_mut(key) {
                    if let Some(s) = val.as_str() {
                        let rewritten = if let Some(rest) = s.strip_prefix(strip_prefix) {
                            format!("{}{}", add_prefix, rest)
                        } else {
                            s.to_string()
                        };
                        *val = serde_json::Value::String(rewritten);
                    }
                }
            }
        }
        args
    }
}

impl Default for SandboxHook {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Hook for SandboxHook {
    fn name(&self) -> &str {
        "sandbox"
    }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        ctx: &CallContext,
    ) -> HookDecision {
        let sandbox = match &ctx.sandbox {
            Some(s) => s,
            None => return HookDecision::Continue,
        };

        let rule = match sandbox.rule_for(tool_name) {
            Some(r) => r,
            None => return HookDecision::Continue,
        };

        match &rule.action {
            SandboxAction::Simulate { response } => {
                HookDecision::Simulate(CallToolResult::text(response.clone()))
            }
            SandboxAction::RateLimit {
                max_calls,
                window_secs,
            } => {
                if self.check_rate_limit(&ctx.agent.name, tool_name, *max_calls, *window_secs) {
                    HookDecision::Continue
                } else {
                    HookDecision::Block(format!(
                        "Sandbox rate limit exceeded: {} calls per {}s for tool '{}'",
                        max_calls, window_secs, tool_name
                    ))
                }
            }
            SandboxAction::PathRewrite {
                strip_prefix,
                add_prefix,
            } => {
                let rewritten = Self::rewrite_paths(arguments, strip_prefix, add_prefix);
                HookDecision::ModifyArgs(rewritten)
            }
            // Redact is a post-hook action (applied to output, not input)
            SandboxAction::Redact { .. } => HookDecision::Continue,
        }
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        result: &CallToolResult,
        ctx: &CallContext,
    ) -> HookDecision {
        let sandbox = match &ctx.sandbox {
            Some(s) => s,
            None => return HookDecision::Continue,
        };

        let rule = match sandbox.rule_for(tool_name) {
            Some(r) => r,
            None => return HookDecision::Continue,
        };

        match &rule.action {
            SandboxAction::Redact {
                patterns,
                replacement,
            } => {
                let mut new_content = Vec::new();
                for content in &result.content {
                    match content {
                        smgglrs_protocol::Content::Text(t) => {
                            let redacted = Self::redact_text(&t.text, patterns, replacement);
                            new_content.push(smgglrs_protocol::Content::text(redacted));
                        }
                        other => new_content.push(other.clone()),
                    }
                }
                let mut new_result = CallToolResult::text("");
                new_result.content = new_content;
                new_result.is_error = result.is_error;
                HookDecision::ModifyResult(new_result)
            }
            _ => HookDecision::Continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::sandbox_profile::ToolSandboxRule;
    use crate::auth::AgentIdentity;

    fn test_ctx_with_sandbox(profile: SandboxProfile) -> CallContext {
        let mut ctx = CallContext::new(AgentIdentity::new("test-agent", "dev"), "test-session");
        ctx.sandbox = Some(profile);
        ctx
    }

    #[tokio::test]
    async fn no_sandbox_continues() {
        let hook = SandboxHook::new();
        let ctx = CallContext::new(AgentIdentity::new("test", "dev"), "s1");
        let decision = hook
            .pre_tool_use("file_read", &serde_json::json!({}), &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn no_matching_rule_continues() {
        let profile = SandboxProfile::default();
        let ctx = test_ctx_with_sandbox(profile);
        let hook = SandboxHook::new();
        let decision = hook
            .pre_tool_use("file_read", &serde_json::json!({}), &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn simulate_returns_canned_response() {
        let mut profile = SandboxProfile::default();
        profile.rules.insert(
            "file_write".to_string(),
            ToolSandboxRule {
                action: SandboxAction::Simulate {
                    response: "write simulated OK".to_string(),
                },
            },
        );
        let ctx = test_ctx_with_sandbox(profile);
        let hook = SandboxHook::new();

        let decision = hook
            .pre_tool_use(
                "file_write",
                &serde_json::json!({"path": "/etc/passwd"}),
                &ctx,
            )
            .await;
        match decision {
            HookDecision::Simulate(result) => {
                match &result.content[0] {
                    smgglrs_protocol::Content::Text(t) => {
                        assert_eq!(t.text, "write simulated OK");
                    }
                    _ => panic!("expected text"),
                }
            }
            other => panic!("expected Simulate, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rate_limit_allows_within_limit() {
        let mut profile = SandboxProfile::default();
        profile.rules.insert(
            "file_read".to_string(),
            ToolSandboxRule {
                action: SandboxAction::RateLimit {
                    max_calls: 3,
                    window_secs: 60,
                },
            },
        );
        let ctx = test_ctx_with_sandbox(profile);
        let hook = SandboxHook::new();

        for _ in 0..3 {
            let decision = hook
                .pre_tool_use("file_read", &serde_json::json!({}), &ctx)
                .await;
            assert!(matches!(decision, HookDecision::Continue));
        }

        // 4th call should be blocked
        let decision = hook
            .pre_tool_use("file_read", &serde_json::json!({}), &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Block(_)));
    }

    #[tokio::test]
    async fn path_rewrite_modifies_args() {
        let mut profile = SandboxProfile::default();
        profile.rules.insert(
            "file_read".to_string(),
            ToolSandboxRule {
                action: SandboxAction::PathRewrite {
                    strip_prefix: "/home/user/".to_string(),
                    add_prefix: "/sandbox/user/".to_string(),
                },
            },
        );
        let ctx = test_ctx_with_sandbox(profile);
        let hook = SandboxHook::new();

        let args = serde_json::json!({"path": "/home/user/secret.txt"});
        let decision = hook.pre_tool_use("file_read", &args, &ctx).await;

        match decision {
            HookDecision::ModifyArgs(new_args) => {
                assert_eq!(
                    new_args["path"].as_str().unwrap(),
                    "/sandbox/user/secret.txt"
                );
            }
            other => panic!("expected ModifyArgs, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn path_rewrite_no_match_keeps_original() {
        let mut profile = SandboxProfile::default();
        profile.rules.insert(
            "file_read".to_string(),
            ToolSandboxRule {
                action: SandboxAction::PathRewrite {
                    strip_prefix: "/home/user/".to_string(),
                    add_prefix: "/sandbox/".to_string(),
                },
            },
        );
        let ctx = test_ctx_with_sandbox(profile);
        let hook = SandboxHook::new();

        let args = serde_json::json!({"path": "/tmp/file.txt"});
        let decision = hook.pre_tool_use("file_read", &args, &ctx).await;

        match decision {
            HookDecision::ModifyArgs(new_args) => {
                assert_eq!(new_args["path"].as_str().unwrap(), "/tmp/file.txt");
            }
            other => panic!("expected ModifyArgs, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn redact_applies_in_post_hook() {
        let mut profile = SandboxProfile::default();
        profile.rules.insert(
            "file_read".to_string(),
            ToolSandboxRule {
                action: SandboxAction::Redact {
                    patterns: vec![r"\d{3}-\d{2}-\d{4}".to_string()],
                    replacement: "[SSN]".to_string(),
                },
            },
        );
        let ctx = test_ctx_with_sandbox(profile);
        let hook = SandboxHook::new();

        let result = CallToolResult::text("SSN: 123-45-6789 is sensitive");
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &ctx)
            .await;

        match decision {
            HookDecision::ModifyResult(new_result) => {
                match &new_result.content[0] {
                    smgglrs_protocol::Content::Text(t) => {
                        assert_eq!(t.text, "SSN: [SSN] is sensitive");
                        assert!(!t.text.contains("123-45-6789"));
                    }
                    _ => panic!("expected text"),
                }
            }
            other => panic!("expected ModifyResult, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn redact_skips_in_pre_hook() {
        let mut profile = SandboxProfile::default();
        profile.rules.insert(
            "file_read".to_string(),
            ToolSandboxRule {
                action: SandboxAction::Redact {
                    patterns: vec!["secret".to_string()],
                    replacement: "[REDACTED]".to_string(),
                },
            },
        );
        let ctx = test_ctx_with_sandbox(profile);
        let hook = SandboxHook::new();

        // Redact should not trigger in pre-hook
        let decision = hook
            .pre_tool_use("file_read", &serde_json::json!({}), &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn simulate_with_glob_pattern() {
        let mut profile = SandboxProfile::default();
        profile.rules.insert(
            "git_*".to_string(),
            ToolSandboxRule {
                action: SandboxAction::Simulate {
                    response: "git operations disabled in sandbox".to_string(),
                },
            },
        );
        let ctx = test_ctx_with_sandbox(profile);
        let hook = SandboxHook::new();

        let decision = hook
            .pre_tool_use("git_commit", &serde_json::json!({}), &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Simulate(_)));

        let decision = hook
            .pre_tool_use("git_push", &serde_json::json!({}), &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Simulate(_)));

        // Non-git tool should not match
        let decision = hook
            .pre_tool_use("file_read", &serde_json::json!({}), &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[test]
    fn redact_text_replaces_patterns() {
        let result = SandboxHook::redact_text(
            "Call 555-1234 or email test@example.com",
            &[r"\d{3}-\d{4}".to_string(), r"[\w.]+@[\w.]+".to_string()],
            "[REDACTED]",
        );
        assert_eq!(result, "Call [REDACTED] or email [REDACTED]");
    }

    #[test]
    fn redact_text_invalid_regex_ignored() {
        // Invalid regex should be skipped (not crash)
        let result = SandboxHook::redact_text("hello world", &["[invalid".to_string()], "[X]");
        assert_eq!(result, "hello world");
    }

    #[test]
    fn rewrite_paths_replaces_matching_prefix() {
        let args = serde_json::json!({"path": "/home/user/docs/file.txt", "other": "unchanged"});
        let result = SandboxHook::rewrite_paths(&args, "/home/user/", "/sandbox/");
        assert_eq!(result["path"].as_str().unwrap(), "/sandbox/docs/file.txt");
        assert_eq!(result["other"].as_str().unwrap(), "unchanged");
    }
}
