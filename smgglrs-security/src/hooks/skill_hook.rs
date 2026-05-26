//! HASP-style Program Functions as executable guardrails.
//!
//! SkillHook transforms passive heuristics into active interventions.
//! Each skill rule has a deterministic activation predicate and an
//! intervention action (modify arguments, inject context, or no-op).

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A single skill rule: activation predicate + intervention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillRule {
    pub name: String,
    pub tool_pattern: String,
    pub path_pattern: Option<String>,
    pub intervention: Intervention,
}

/// What action to take when a skill rule activates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Intervention {
    InjectContext { message: String },
    ModifyArg { key: String, value: serde_json::Value },
    Block { reason: String },
    Noop,
}

/// Hook that applies skill rules as pre-tool-call guardrails.
pub struct SkillHook {
    rules: Vec<SkillRule>,
}

impl SkillHook {
    pub fn new(rules: Vec<SkillRule>) -> Self {
        Self { rules }
    }

    fn matches_tool(pattern: &str, tool_name: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if pattern.ends_with('*') {
            tool_name.starts_with(&pattern[..pattern.len() - 1])
        } else {
            tool_name == pattern
        }
    }

    fn matches_path(pattern: Option<&str>, args: &serde_json::Value) -> bool {
        let Some(pattern) = pattern else {
            return true;
        };
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if pattern.ends_with('*') {
            path.starts_with(&pattern[..pattern.len() - 1])
        } else {
            path == pattern
        }
    }
}

#[async_trait]
impl Hook for SkillHook {
    fn name(&self) -> &str {
        "skill"
    }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        _ctx: &CallContext,
    ) -> HookDecision {
        for rule in &self.rules {
            if !Self::matches_tool(&rule.tool_pattern, tool_name) {
                continue;
            }
            if !Self::matches_path(rule.path_pattern.as_deref(), arguments) {
                continue;
            }

            tracing::info!(
                rule = %rule.name,
                tool = tool_name,
                "SkillHook activated"
            );

            match &rule.intervention {
                Intervention::Block { reason } => {
                    return HookDecision::Block(format!(
                        "SkillHook '{}': {}",
                        rule.name, reason
                    ));
                }
                Intervention::ModifyArg { key, value } => {
                    let mut modified = arguments.clone();
                    if let Some(obj) = modified.as_object_mut() {
                        obj.insert(key.clone(), value.clone());
                    }
                    return HookDecision::ModifyArgs(modified);
                }
                Intervention::InjectContext { message } => {
                    let mut modified = arguments.clone();
                    if let Some(obj) = modified.as_object_mut() {
                        let existing = obj
                            .get("_skill_context")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let combined = if existing.is_empty() {
                            message.clone()
                        } else {
                            format!("{existing}\n{message}")
                        };
                        obj.insert(
                            "_skill_context".to_string(),
                            serde_json::Value::String(combined),
                        );
                    }
                    return HookDecision::ModifyArgs(modified);
                }
                Intervention::Noop => {}
            }
        }
        HookDecision::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_ctx() -> CallContext {
        CallContext {
            agent: crate::auth::AgentIdentity {
                name: "test".to_string(),
                permissions: "full".to_string(),
                signing_key: None,
                did: None,
                capabilities: None,
            },
            session_id: "sess-1".to_string(),
            taint: crate::ifc::TaintTracker::new(),
        }
    }

    #[tokio::test]
    async fn block_rule_prevents_execution() {
        let hook = SkillHook::new(vec![SkillRule {
            name: "block-etc-writes".into(),
            tool_pattern: "file_write".into(),
            path_pattern: Some("/etc/*".into()),
            intervention: Intervention::Block {
                reason: "writes to /etc/ require approval".into(),
            },
        }]);

        let decision = hook
            .pre_tool_use("file_write", &json!({"path": "/etc/passwd"}), &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Block(_)));
    }

    #[tokio::test]
    async fn block_rule_allows_other_paths() {
        let hook = SkillHook::new(vec![SkillRule {
            name: "block-etc-writes".into(),
            tool_pattern: "file_write".into(),
            path_pattern: Some("/etc/*".into()),
            intervention: Intervention::Block {
                reason: "no".into(),
            },
        }]);

        let decision = hook
            .pre_tool_use("file_write", &json!({"path": "/home/user/file.txt"}), &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn inject_context_adds_skill_context() {
        let hook = SkillHook::new(vec![SkillRule {
            name: "verify-permissions".into(),
            tool_pattern: "file_write".into(),
            path_pattern: None,
            intervention: Intervention::InjectContext {
                message: "Verify file permissions before writing".into(),
            },
        }]);

        let decision = hook
            .pre_tool_use("file_write", &json!({"path": "/tmp/test"}), &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyArgs(args) => {
                assert_eq!(
                    args["_skill_context"],
                    "Verify file permissions before writing"
                );
            }
            other => panic!("expected ModifyArgs, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn modify_arg_injects_value() {
        let hook = SkillHook::new(vec![SkillRule {
            name: "force-readonly".into(),
            tool_pattern: "file_*".into(),
            path_pattern: None,
            intervention: Intervention::ModifyArg {
                key: "readonly".into(),
                value: json!(true),
            },
        }]);

        let decision = hook
            .pre_tool_use("file_read", &json!({"path": "/src"}), &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyArgs(args) => {
                assert_eq!(args["readonly"], true);
                assert_eq!(args["path"], "/src");
            }
            other => panic!("expected ModifyArgs, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn noop_continues() {
        let hook = SkillHook::new(vec![SkillRule {
            name: "log-only".into(),
            tool_pattern: "*".into(),
            path_pattern: None,
            intervention: Intervention::Noop,
        }]);

        let decision = hook
            .pre_tool_use("anything", &json!({}), &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn wildcard_tool_pattern_matches_all() {
        let hook = SkillHook::new(vec![SkillRule {
            name: "universal".into(),
            tool_pattern: "*".into(),
            path_pattern: None,
            intervention: Intervention::Block {
                reason: "blocked".into(),
            },
        }]);

        let d1 = hook.pre_tool_use("file_read", &json!({}), &test_ctx()).await;
        let d2 = hook.pre_tool_use("git_commit", &json!({}), &test_ctx()).await;

        assert!(matches!(d1, HookDecision::Block(_)));
        assert!(matches!(d2, HookDecision::Block(_)));
    }

    #[tokio::test]
    async fn no_matching_rules_continues() {
        let hook = SkillHook::new(vec![SkillRule {
            name: "git-only".into(),
            tool_pattern: "git_*".into(),
            path_pattern: None,
            intervention: Intervention::Block {
                reason: "no git".into(),
            },
        }]);

        let decision = hook
            .pre_tool_use("file_read", &json!({}), &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[test]
    fn skill_rule_serialization_roundtrip() {
        let rule = SkillRule {
            name: "test".into(),
            tool_pattern: "file_*".into(),
            path_pattern: Some("/etc/*".into()),
            intervention: Intervention::Block {
                reason: "blocked".into(),
            },
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: SkillRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
    }
}
