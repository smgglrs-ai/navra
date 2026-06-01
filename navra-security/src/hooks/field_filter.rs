//! Gateway-level field filtering for token optimization.
//!
//! Strips unnecessary fields from tool responses before forwarding
//! to agents, reducing token consumption.

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use async_trait::async_trait;
use navra_protocol::CallToolResult;
use std::collections::HashMap;

/// Per-tool field retention configuration.
#[derive(Debug, Clone)]
pub struct FieldFilterConfig {
    /// Tool name → set of field names to retain in JSON responses.
    pub tool_fields: HashMap<String, Vec<String>>,
}

/// Post-call hook that prunes tool response JSON to specified fields.
pub struct FieldFilterHook {
    config: FieldFilterConfig,
}

impl FieldFilterHook {
    pub fn new(config: FieldFilterConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Hook for FieldFilterHook {
    fn name(&self) -> &str {
        "field_filter"
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        result: &CallToolResult,
        _ctx: &CallContext,
    ) -> HookDecision {
        let Some(retain_fields) = self.config.tool_fields.get(tool_name) else {
            return HookDecision::Continue;
        };

        let mut filtered = result.clone();
        for content in &mut filtered.content {
            if let navra_protocol::Content::Text(ref mut text) = content {
                if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&text.text) {
                    filter_json(&mut json, retain_fields);
                    if let Ok(compact) = serde_json::to_string(&json) {
                        text.text = compact;
                    }
                }
            }
        }

        HookDecision::ModifyResult(filtered)
    }
}

fn filter_json(value: &mut serde_json::Value, retain: &[String]) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|k, _| retain.iter().any(|r| r == k));
            for v in map.values_mut() {
                filter_json(v, retain);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                filter_json(item, retain);
            }
        }
        _ => {}
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
            remaining_tokens: None,
            sandbox: None,
        }
    }

    fn make_result(json_text: &str) -> CallToolResult {
        CallToolResult {
            content: vec![navra_protocol::Content::text(json_text.to_string())],
            is_error: false,
            label: navra_protocol::label::DataLabel::TRUSTED_PUBLIC,
        }
    }

    #[tokio::test]
    async fn filters_configured_tool() {
        let config = FieldFilterConfig {
            tool_fields: HashMap::from([(
                "database_query".into(),
                vec!["id".into(), "name".into()],
            )]),
        };
        let hook = FieldFilterHook::new(config);

        let result = make_result(r#"{"id": 1, "name": "Alice", "email": "a@b.com", "age": 30}"#);
        let decision = hook
            .post_tool_use("database_query", &json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyResult(r) => {
                let text = match &r.content[0] {
                    navra_protocol::Content::Text(t) => &t.text,
                    _ => panic!("expected text"),
                };
                let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
                assert!(parsed.get("id").is_some());
                assert!(parsed.get("name").is_some());
                assert!(parsed.get("email").is_none());
                assert!(parsed.get("age").is_none());
            }
            other => panic!("expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unconfigured_tool_passes_through() {
        let config = FieldFilterConfig {
            tool_fields: HashMap::new(),
        };
        let hook = FieldFilterHook::new(config);

        let result = make_result(r#"{"foo": "bar"}"#);
        let decision = hook
            .post_tool_use("some_tool", &json!({}), &result, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn filters_array_responses() {
        let config = FieldFilterConfig {
            tool_fields: HashMap::from([(
                "list_users".into(),
                vec!["id".into(), "name".into()],
            )]),
        };
        let hook = FieldFilterHook::new(config);

        let result = make_result(
            r#"[{"id": 1, "name": "A", "secret": "x"}, {"id": 2, "name": "B", "secret": "y"}]"#,
        );
        let decision = hook
            .post_tool_use("list_users", &json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyResult(r) => {
                let text = match &r.content[0] {
                    navra_protocol::Content::Text(t) => &t.text,
                    _ => panic!("expected text"),
                };
                let parsed: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
                assert_eq!(parsed.len(), 2);
                assert!(parsed[0].get("secret").is_none());
            }
            other => panic!("expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_json_content_unchanged() {
        let config = FieldFilterConfig {
            tool_fields: HashMap::from([("tool".into(), vec!["id".into()])]),
        };
        let hook = FieldFilterHook::new(config);

        let result = make_result("This is plain text, not JSON");
        let decision = hook
            .post_tool_use("tool", &json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyResult(r) => {
                let text = match &r.content[0] {
                    navra_protocol::Content::Text(t) => &t.text,
                    _ => panic!("expected text"),
                };
                assert_eq!(text, "This is plain text, not JSON");
            }
            other => panic!("expected ModifyResult, got {other:?}"),
        }
    }
}
