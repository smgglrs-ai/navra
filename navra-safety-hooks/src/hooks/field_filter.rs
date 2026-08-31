//! Gateway-level field filtering for token optimization.
//!
//! Strips unnecessary fields from tool responses before forwarding
//! to agents, reducing token consumption.

use super::{Hook, HookDecision};
use async_trait::async_trait;
use navra_auth::auth::CallContext;
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
            if let navra_protocol::Content {
                raw: navra_protocol::RawContent::Text(text),
                ..
            } = content
                && let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&text.text)
            {
                filter_json(&mut json, retain_fields);
                if let Ok(compact) = serde_json::to_string(&json) {
                    text.text = compact;
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
    use crate::test_support::test_ctx;
    use serde_json::json;

    fn make_result(json_text: &str) -> CallToolResult {
        use navra_protocol::compat::CallToolResultExt;
        CallToolResult::text(json_text.to_string())
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
                    navra_protocol::Content {
                        raw: navra_protocol::RawContent::Text(t),
                        ..
                    } => &t.text,
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
            tool_fields: HashMap::from([("list_users".into(), vec!["id".into(), "name".into()])]),
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
                    navra_protocol::Content {
                        raw: navra_protocol::RawContent::Text(t),
                        ..
                    } => &t.text,
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
                    navra_protocol::Content {
                        raw: navra_protocol::RawContent::Text(t),
                        ..
                    } => &t.text,
                    _ => panic!("expected text"),
                };
                assert_eq!(text, "This is plain text, not JSON");
            }
            other => panic!("expected ModifyResult, got {other:?}"),
        }
    }

    // --- Edge-case tests ---

    fn extract_text(decision: &HookDecision) -> &str {
        match decision {
            HookDecision::ModifyResult(r) => match &r.content[0] {
                navra_protocol::Content {
                    raw: navra_protocol::RawContent::Text(t),
                    ..
                } => &t.text,
                _ => panic!("expected text content"),
            },
            other => panic!("expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn filter_deeply_nested_json() {
        let config = FieldFilterConfig {
            tool_fields: HashMap::from([("tool".into(), vec!["keep".into()])]),
        };
        let hook = FieldFilterHook::new(config);

        // 10-level nested object with "keep" and "remove" at the deepest level
        let result = make_result(
            r#"{"keep": {"keep": {"keep": {"keep": {"keep": {"keep": {"keep": {"keep": {"keep": {"keep": "deep", "remove": "gone"}}}}}}}}}}"#,
        );
        let decision = hook
            .post_tool_use("tool", &json!({}), &result, &test_ctx())
            .await;

        let text = extract_text(&decision);
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        // "remove" should be stripped at every level
        assert!(!text.contains("remove"));
        assert!(!text.contains("gone"));
        // "keep" should be preserved through the nesting
        assert!(parsed.get("keep").is_some());
    }

    #[tokio::test]
    async fn filter_array_of_objects() {
        let config = FieldFilterConfig {
            tool_fields: HashMap::from([("tool".into(), vec!["id".into()])]),
        };
        let hook = FieldFilterHook::new(config);

        let result = make_result(
            r#"[{"id": 1, "secret": "a"}, {"id": 2, "secret": "b"}, {"id": 3, "secret": "c"}]"#,
        );
        let decision = hook
            .post_tool_use("tool", &json!({}), &result, &test_ctx())
            .await;

        let text = extract_text(&decision);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
        assert_eq!(parsed.len(), 3);
        for obj in &parsed {
            assert!(obj.get("id").is_some());
            assert!(obj.get("secret").is_none());
        }
    }

    #[tokio::test]
    async fn filter_empty_object() {
        let config = FieldFilterConfig {
            tool_fields: HashMap::from([("tool".into(), vec!["id".into()])]),
        };
        let hook = FieldFilterHook::new(config);

        let result = make_result("{}");
        let decision = hook
            .post_tool_use("tool", &json!({}), &result, &test_ctx())
            .await;

        let text = extract_text(&decision);
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(parsed.as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn filter_null_values() {
        let config = FieldFilterConfig {
            tool_fields: HashMap::from([("tool".into(), vec!["id".into(), "name".into()])]),
        };
        let hook = FieldFilterHook::new(config);

        let result = make_result(r#"{"id": null, "name": "Alice", "secret": null}"#);
        let decision = hook
            .post_tool_use("tool", &json!({}), &result, &test_ctx())
            .await;

        let text = extract_text(&decision);
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(parsed.get("id").is_some());
        assert!(parsed.get("id").unwrap().is_null());
        assert!(parsed.get("name").is_some());
        assert!(parsed.get("secret").is_none());
    }

    #[tokio::test]
    async fn filter_mixed_types() {
        let config = FieldFilterConfig {
            tool_fields: HashMap::from([(
                "tool".into(),
                vec!["str".into(), "num".into(), "bool".into(), "null".into(), "arr".into(), "obj".into()],
            )]),
        };
        let hook = FieldFilterHook::new(config);

        let result = make_result(
            r#"{"str": "hello", "num": 42, "bool": true, "null": null, "arr": [1,2], "obj": {"str": "nested"}, "extra": "remove"}"#,
        );
        let decision = hook
            .post_tool_use("tool", &json!({}), &result, &test_ctx())
            .await;

        let text = extract_text(&decision);
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed.get("str").unwrap(), "hello");
        assert_eq!(parsed.get("num").unwrap(), 42);
        assert_eq!(parsed.get("bool").unwrap(), true);
        assert!(parsed.get("null").unwrap().is_null());
        assert!(parsed.get("arr").unwrap().is_array());
        assert!(parsed.get("obj").unwrap().is_object());
        assert!(parsed.get("extra").is_none());
    }

    #[tokio::test]
    async fn filter_unicode_field_names() {
        let config = FieldFilterConfig {
            tool_fields: HashMap::from([(
                "tool".into(),
                vec!["\u{540d}\u{524d}".into(), "\u{30e1}\u{30fc}\u{30eb}".into()],
            )]),
        };
        let hook = FieldFilterHook::new(config);

        let result = make_result(
            r#"{"名前": "Tanaka", "メール": "a@b.com", "secret": "hidden"}"#,
        );
        let decision = hook
            .post_tool_use("tool", &json!({}), &result, &test_ctx())
            .await;

        let text = extract_text(&decision);
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(parsed.get("\u{540d}\u{524d}").is_some());
        assert!(parsed.get("\u{30e1}\u{30fc}\u{30eb}").is_some());
        assert!(parsed.get("secret").is_none());
    }
}
