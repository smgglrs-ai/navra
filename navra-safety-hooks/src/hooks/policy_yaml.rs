//! ACS-style YAML policy ingestion hook.
//!
//! Parses Microsoft ACS-compatible YAML policy files and maps
//! `pre_tool_call` / `post_tool_call` rules into navra's hook pipeline.
//! Each rule specifies conditions (tool name pattern, argument field
//! patterns, result content patterns) and an action (allow, block,
//! modify_result, escalate).

use super::{Hook, HookDecision};
use navra_auth::auth::CallContext;
use navra_protocol::CallToolResult;
use regex_lite::Regex;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// YAML schema types
// ---------------------------------------------------------------------------

/// Top-level policy file.
#[derive(Debug, Deserialize)]
pub struct PolicyFile {
    pub policies: Vec<Policy>,
}

/// A named policy containing one or more rules.
#[derive(Debug, Deserialize)]
pub struct Policy {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub rules: Vec<PolicyRule>,
}

/// A single rule within a policy.
#[derive(Debug, Deserialize)]
pub struct PolicyRule {
    pub event: RuleEvent,
    pub condition: Condition,
    pub action: Action,
    /// Human-readable block/escalation message.
    #[serde(default)]
    pub message: String,
    /// Replacement text for `modify_result` actions.
    #[serde(default)]
    pub replacement: String,
}

/// Which hook phase the rule applies to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEvent {
    PreToolCall,
    PostToolCall,
}

/// Conditions that must all match for the rule to fire.
#[derive(Debug, Deserialize)]
pub struct Condition {
    /// Regex pattern matched against the tool name.
    #[serde(default)]
    pub tool_name_matches: Option<String>,
    /// Match a specific argument field against a regex.
    #[serde(default)]
    pub arg_field_matches: Option<ArgFieldCondition>,
    /// Regex pattern matched against the serialised result text.
    #[serde(default)]
    pub result_contains: Option<String>,
}

/// Condition on a single argument field value.
#[derive(Debug, Deserialize)]
pub struct ArgFieldCondition {
    pub field: String,
    pub pattern: String,
}

/// What to do when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Block,
    Escalate,
    ModifyResult,
}

// ---------------------------------------------------------------------------
// Compiled rule (pre-compiled regexes)
// ---------------------------------------------------------------------------

struct CompiledRule {
    event: RuleEvent,
    tool_name_re: Option<Regex>,
    arg_field: Option<String>,
    arg_pattern_re: Option<Regex>,
    result_re: Option<Regex>,
    action: Action,
    message: String,
    replacement: String,
}

// ---------------------------------------------------------------------------
// PolicyYamlHook
// ---------------------------------------------------------------------------

/// Hook that evaluates ACS-style YAML policy rules against tool calls.
pub struct PolicyYamlHook {
    rules: Vec<CompiledRule>,
}

impl PolicyYamlHook {
    /// Parse an ACS-style YAML policy string and compile all regex patterns.
    pub fn from_yaml(yaml_str: &str) -> anyhow::Result<Self> {
        let file: PolicyFile = serde_yaml::from_str(yaml_str)?;
        let mut rules = Vec::new();
        for policy in file.policies {
            for rule in policy.rules {
                let tool_name_re = rule
                    .condition
                    .tool_name_matches
                    .as_deref()
                    .map(Regex::new)
                    .transpose()?;
                let (arg_field, arg_pattern_re) = match &rule.condition.arg_field_matches {
                    Some(af) => (Some(af.field.clone()), Some(Regex::new(&af.pattern)?)),
                    None => (None, None),
                };
                let result_re = rule
                    .condition
                    .result_contains
                    .as_deref()
                    .map(Regex::new)
                    .transpose()?;
                rules.push(CompiledRule {
                    event: rule.event,
                    tool_name_re,
                    arg_field,
                    arg_pattern_re,
                    result_re,
                    action: rule.action,
                    message: rule.message,
                    replacement: rule.replacement,
                });
            }
        }
        Ok(Self { rules })
    }
}

/// Check whether a compiled rule's conditions match for pre_tool_call.
fn matches_pre(rule: &CompiledRule, tool_name: &str, arguments: &serde_json::Value) -> bool {
    if let Some(re) = &rule.tool_name_re {
        if !re.is_match(tool_name) {
            return false;
        }
    }
    if let (Some(field), Some(re)) = (&rule.arg_field, &rule.arg_pattern_re) {
        let val = arguments
            .get(field.as_str())
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !re.is_match(val) {
            return false;
        }
    }
    true
}

/// Extract text content from a CallToolResult for pattern matching.
fn result_text(result: &CallToolResult) -> String {
    use navra_protocol::Content;
    result
        .content
        .iter()
        .filter_map(|c| match c {
            Content::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Check whether a compiled rule's conditions match for post_tool_call.
fn matches_post(
    rule: &CompiledRule,
    tool_name: &str,
    arguments: &serde_json::Value,
    result: &CallToolResult,
) -> bool {
    if let Some(re) = &rule.tool_name_re {
        if !re.is_match(tool_name) {
            return false;
        }
    }
    if let (Some(field), Some(re)) = (&rule.arg_field, &rule.arg_pattern_re) {
        let val = arguments
            .get(field.as_str())
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !re.is_match(val) {
            return false;
        }
    }
    if let Some(re) = &rule.result_re {
        let text = result_text(result);
        if !re.is_match(&text) {
            return false;
        }
    }
    true
}

#[async_trait::async_trait]
impl Hook for PolicyYamlHook {
    fn name(&self) -> &str {
        "policy-yaml"
    }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        _ctx: &CallContext,
    ) -> HookDecision {
        for rule in &self.rules {
            if rule.event != RuleEvent::PreToolCall {
                continue;
            }
            if !matches_pre(rule, tool_name, arguments) {
                continue;
            }
            match rule.action {
                Action::Block => return HookDecision::Block(rule.message.clone()),
                Action::Escalate => return HookDecision::Pending(rule.message.clone()),
                Action::Allow => return HookDecision::Continue,
                Action::ModifyResult => {
                    // modify_result doesn't make sense pre-call; treat as continue
                    continue;
                }
            }
        }
        HookDecision::Continue
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        result: &CallToolResult,
        _ctx: &CallContext,
    ) -> HookDecision {
        for rule in &self.rules {
            if rule.event != RuleEvent::PostToolCall {
                continue;
            }
            if !matches_post(rule, tool_name, arguments, result) {
                continue;
            }
            match rule.action {
                Action::Block => return HookDecision::Block(rule.message.clone()),
                Action::Escalate => return HookDecision::Pending(rule.message.clone()),
                Action::ModifyResult => {
                    let replacement = rule.replacement.clone();
                    let redacted = CallToolResult::text(replacement);
                    return HookDecision::ModifyResult(redacted);
                }
                Action::Allow => return HookDecision::Continue,
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

    const POLICY_YAML: &str = r#"
policies:
  - name: "test-policy"
    description: "Test policy for unit tests"
    rules:
      - event: pre_tool_call
        condition:
          tool_name_matches: "file_delete|exec_run"
        action: block
        message: "Tool blocked by policy"
      - event: post_tool_call
        condition:
          result_contains: "password"
        action: modify_result
        replacement: "[REDACTED]"
      - event: pre_tool_call
        condition:
          tool_name_matches: ".*"
          arg_field_matches:
            field: "path"
            pattern: "/etc/shadow"
        action: block
        message: "Access to sensitive files blocked"
      - event: pre_tool_call
        condition:
          tool_name_matches: "dangerous_tool"
        action: escalate
        message: "Requires human approval"
"#;

    fn hook() -> PolicyYamlHook {
        PolicyYamlHook::from_yaml(POLICY_YAML).expect("valid YAML")
    }

    #[tokio::test]
    async fn blocks_on_tool_name_match() {
        let h = hook();
        let args = serde_json::json!({});
        let decision = h.pre_tool_use("file_delete", &args, &test_ctx()).await;
        match decision {
            HookDecision::Block(msg) => assert_eq!(msg, "Tool blocked by policy"),
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn blocks_exec_run() {
        let h = hook();
        let args = serde_json::json!({});
        let decision = h.pre_tool_use("exec_run", &args, &test_ctx()).await;
        assert!(matches!(decision, HookDecision::Block(_)));
    }

    #[tokio::test]
    async fn blocks_on_arg_field_match() {
        let h = hook();
        let args = serde_json::json!({"path": "/etc/shadow"});
        let decision = h.pre_tool_use("file_read", &args, &test_ctx()).await;
        match decision {
            HookDecision::Block(msg) => {
                assert!(msg.contains("sensitive files"));
            }
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn continues_when_no_rules_match() {
        let h = hook();
        let args = serde_json::json!({"query": "hello"});
        let decision = h.pre_tool_use("git_status", &args, &test_ctx()).await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn modifies_result_on_content_match() {
        let h = hook();
        let args = serde_json::json!({});
        let result = CallToolResult::text("my password is secret123");
        let decision = h
            .post_tool_use("some_tool", &args, &result, &test_ctx())
            .await;
        match decision {
            HookDecision::ModifyResult(modified) => {
                let text = match &modified.content[0] {
                    navra_protocol::Content::Text(t) => t.text.as_str(),
                    _ => panic!("Expected text content"),
                };
                assert_eq!(text, "[REDACTED]");
            }
            other => panic!("Expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn continues_post_when_no_match() {
        let h = hook();
        let args = serde_json::json!({});
        let result = CallToolResult::text("all good, no secrets here");
        let decision = h
            .post_tool_use("some_tool", &args, &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn escalates_dangerous_tool() {
        let h = hook();
        let args = serde_json::json!({});
        let decision = h.pre_tool_use("dangerous_tool", &args, &test_ctx()).await;
        match decision {
            HookDecision::Pending(msg) => assert_eq!(msg, "Requires human approval"),
            other => panic!("Expected Pending, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_invalid_yaml() {
        let result = PolicyYamlHook::from_yaml("not: valid: yaml: [[[");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_regex() {
        let yaml = r#"
policies:
  - name: "bad-regex"
    rules:
      - event: pre_tool_call
        condition:
          tool_name_matches: "[invalid"
        action: block
        message: "nope"
"#;
        let result = PolicyYamlHook::from_yaml(yaml);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn multiple_policies() {
        let yaml = r#"
policies:
  - name: "policy-a"
    rules:
      - event: pre_tool_call
        condition:
          tool_name_matches: "tool_a"
        action: block
        message: "blocked by A"
  - name: "policy-b"
    rules:
      - event: pre_tool_call
        condition:
          tool_name_matches: "tool_b"
        action: block
        message: "blocked by B"
"#;
        let h = PolicyYamlHook::from_yaml(yaml).unwrap();
        let args = serde_json::json!({});
        let ctx = test_ctx();

        let d1 = h.pre_tool_use("tool_a", &args, &ctx).await;
        match d1 {
            HookDecision::Block(msg) => assert_eq!(msg, "blocked by A"),
            other => panic!("Expected Block A, got {other:?}"),
        }

        let d2 = h.pre_tool_use("tool_b", &args, &ctx).await;
        match d2 {
            HookDecision::Block(msg) => assert_eq!(msg, "blocked by B"),
            other => panic!("Expected Block B, got {other:?}"),
        }

        let d3 = h.pre_tool_use("tool_c", &args, &ctx).await;
        assert!(matches!(d3, HookDecision::Continue));
    }
}
