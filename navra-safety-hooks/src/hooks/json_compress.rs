//! JSON response compression hook.
//!
//! Reduces large JSON tool responses before they reach the agent's
//! context window. Operates on JSON structure (key stripping, array
//! truncation, depth flattening) rather than raw token counting.
//! Complements the BudgetHook which handles token-level truncation.

use super::{Hook, HookDecision};
use async_trait::async_trait;
use navra_auth::auth::CallContext;
use navra_protocol::{CallToolResult, Content};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct JsonCompressConfig {
    pub max_array_elements: usize,
    pub max_depth: usize,
    pub strip_keys: HashSet<String>,
}

impl Default for JsonCompressConfig {
    fn default() -> Self {
        Self {
            max_array_elements: 20,
            max_depth: 3,
            strip_keys: ["_links", "pagination", "metadata"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

pub struct JsonCompressHook {
    max_array_elements: usize,
    max_depth: usize,
    strip_keys: HashSet<String>,
}

impl JsonCompressHook {
    pub fn new(config: JsonCompressConfig) -> Self {
        Self {
            max_array_elements: config.max_array_elements,
            max_depth: config.max_depth,
            strip_keys: config.strip_keys,
        }
    }
}

#[async_trait]
impl Hook for JsonCompressHook {
    fn name(&self) -> &str {
        "json_compress"
    }

    async fn post_tool_use(
        &self,
        _tool_name: &str,
        _arguments: &serde_json::Value,
        result: &CallToolResult,
        _ctx: &CallContext,
    ) -> HookDecision {
        if result.is_error {
            return HookDecision::Continue;
        }

        let mut any_changed = false;
        let mut compressed_content = Vec::with_capacity(result.content.len());
        let mut annotations = Vec::new();

        for content in &result.content {
            match content {
                Content::Text(t) => {
                    let Ok(mut json) = serde_json::from_str::<Value>(&t.text) else {
                        compressed_content.push(content.clone());
                        continue;
                    };

                    let stripped = strip_keys(&mut json, &self.strip_keys);
                    let truncated = truncate_arrays(&mut json, self.max_array_elements);
                    let flattened = flatten_depth(&mut json, self.max_depth, 0);

                    if stripped > 0 || !truncated.is_empty() || flattened > 0 {
                        any_changed = true;
                        if stripped > 0 {
                            annotations.push(format!("{stripped} keys stripped"));
                        }
                        for (path, kept, total) in &truncated {
                            annotations
                                .push(format!("array {path}: {kept}/{total} elements kept"));
                        }
                        if flattened > 0 {
                            annotations.push(format!("{flattened} subtrees flattened at depth {}", self.max_depth));
                        }
                    }

                    match serde_json::to_string(&json) {
                        Ok(compact) => compressed_content.push(Content::text(compact)),
                        Err(_) => compressed_content.push(content.clone()),
                    }
                }
                _ => compressed_content.push(content.clone()),
            }
        }

        if !any_changed {
            return HookDecision::Continue;
        }

        compressed_content.push(Content::text(format!(
            "[json_compress: {}]",
            annotations.join("; ")
        )));

        HookDecision::ModifyResult(CallToolResult {
            content: compressed_content,
            is_error: result.is_error,
            label: result.label,
        })
    }
}

fn strip_keys(value: &mut Value, keys: &HashSet<String>) -> usize {
    let mut count = 0;
    match value {
        Value::Object(map) => {
            let before = map.len();
            map.retain(|k, _| !keys.contains(k));
            count += before - map.len();
            for v in map.values_mut() {
                count += strip_keys(v, keys);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                count += strip_keys(item, keys);
            }
        }
        _ => {}
    }
    count
}

/// Truncates arrays beyond `max_elements`, returning (path, kept, total) for each.
fn truncate_arrays(value: &mut Value, max_elements: usize) -> Vec<(String, usize, usize)> {
    let mut result = Vec::new();
    truncate_arrays_inner(value, max_elements, "$", &mut result);
    result
}

fn truncate_arrays_inner(
    value: &mut Value,
    max_elements: usize,
    path: &str,
    out: &mut Vec<(String, usize, usize)>,
) {
    match value {
        Value::Array(arr) => {
            if arr.len() > max_elements {
                let total = arr.len();
                arr.truncate(max_elements);
                out.push((path.to_string(), max_elements, total));
            }
            for (i, item) in arr.iter_mut().enumerate() {
                truncate_arrays_inner(item, max_elements, &format!("{path}[{i}]"), out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                truncate_arrays_inner(v, max_elements, &format!("{path}.{k}"), out);
            }
        }
        _ => {}
    }
}

/// Replaces subtrees beyond `max_depth` with a summary string.
fn flatten_depth(value: &mut Value, max_depth: usize, current: usize) -> usize {
    if current >= max_depth {
        return match value {
            Value::Object(map) if !map.is_empty() => {
                let keys: Vec<_> = map.keys().cloned().collect();
                let summary = format!("{{...{} keys: {}}}", keys.len(), keys.join(", "));
                *value = Value::String(summary);
                1
            }
            Value::Array(arr) if !arr.is_empty() => {
                let summary = format!("[...{} items]", arr.len());
                *value = Value::String(summary);
                1
            }
            _ => 0,
        };
    }

    let mut count = 0;
    match value {
        Value::Object(map) => {
            for v in map.values_mut() {
                count += flatten_depth(v, max_depth, current + 1);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                count += flatten_depth(item, max_depth, current + 1);
            }
        }
        _ => {}
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_ctx() -> CallContext {
        CallContext {
            agent: navra_auth::auth::AgentIdentity {
                name: "test".to_string(),
                permissions: "full".to_string(),
                signing_key: None,
                did: None,
                capabilities: None,
            },
            session_id: "sess-1".to_string(),
            taint: navra_auth::ifc::TaintTracker::new(),
            remaining_tokens: None,
            sandbox: None,
        }
    }

    fn make_result(text: &str) -> CallToolResult {
        CallToolResult {
            content: vec![Content::text(text.to_string())],
            is_error: false,
            label: navra_protocol::label::DataLabel::TRUSTED_PUBLIC,
        }
    }

    // --- Key stripping ---

    #[test]
    fn strip_keys_removes_configured_keys() {
        let mut val = json!({
            "id": 1,
            "name": "test",
            "_links": {"self": "/api/1"},
            "pagination": {"page": 1},
            "metadata": {"created": "2026-01-01"}
        });
        let keys: HashSet<_> = ["_links", "pagination", "metadata"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let count = strip_keys(&mut val, &keys);
        assert_eq!(count, 3);
        assert!(val.get("id").is_some());
        assert!(val.get("name").is_some());
        assert!(val.get("_links").is_none());
        assert!(val.get("pagination").is_none());
        assert!(val.get("metadata").is_none());
    }

    #[test]
    fn strip_keys_recurses_into_nested() {
        let mut val = json!({
            "items": [
                {"id": 1, "_links": {"next": "/2"}},
                {"id": 2, "_links": {"next": "/3"}}
            ]
        });
        let keys: HashSet<_> = ["_links"].iter().map(|s| s.to_string()).collect();
        let count = strip_keys(&mut val, &keys);
        assert_eq!(count, 2);
        let items = val["items"].as_array().unwrap();
        assert!(items[0].get("_links").is_none());
        assert!(items[1].get("_links").is_none());
    }

    #[test]
    fn strip_keys_no_match_returns_zero() {
        let mut val = json!({"id": 1, "name": "test"});
        let keys: HashSet<_> = ["_links"].iter().map(|s| s.to_string()).collect();
        assert_eq!(strip_keys(&mut val, &keys), 0);
    }

    // --- Array truncation ---

    #[test]
    fn truncate_small_array_unchanged() {
        let mut val = json!([1, 2, 3]);
        let result = truncate_arrays(&mut val, 20);
        assert!(result.is_empty());
        assert_eq!(val.as_array().unwrap().len(), 3);
    }

    #[test]
    fn truncate_large_array() {
        let items: Vec<Value> = (0..50).map(|i| json!({"id": i})).collect();
        let mut val = Value::Array(items);
        let result = truncate_arrays(&mut val, 10);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("$".to_string(), 10, 50));
        assert_eq!(val.as_array().unwrap().len(), 10);
    }

    #[test]
    fn truncate_nested_arrays() {
        let mut val = json!({
            "results": (0..30).map(|i| json!({"id": i})).collect::<Vec<_>>()
        });
        let result = truncate_arrays(&mut val, 5);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, 5); // kept
        assert_eq!(result[0].2, 30); // total
        assert_eq!(val["results"].as_array().unwrap().len(), 5);
    }

    // --- Depth flattening ---

    #[test]
    fn flatten_shallow_unchanged() {
        let mut val = json!({"a": 1, "b": "two"});
        let count = flatten_depth(&mut val, 3, 0);
        assert_eq!(count, 0);
        assert_eq!(val, json!({"a": 1, "b": "two"}));
    }

    #[test]
    fn flatten_deep_object() {
        let mut val = json!({
            "level1": {
                "level2": {
                    "level3": {
                        "deep_key": "deep_value",
                        "another": 42
                    }
                }
            }
        });
        let count = flatten_depth(&mut val, 3, 0);
        assert_eq!(count, 1);
        let flattened = val["level1"]["level2"]["level3"].as_str().unwrap();
        assert!(flattened.contains("2 keys"));
    }

    #[test]
    fn flatten_deep_array() {
        let mut val = json!({
            "a": {
                "b": {
                    "c": [1, 2, 3, 4, 5]
                }
            }
        });
        let count = flatten_depth(&mut val, 3, 0);
        assert_eq!(count, 1);
        let flattened = val["a"]["b"]["c"].as_str().unwrap();
        assert!(flattened.contains("5 items"));
    }

    // --- Hook integration ---

    #[tokio::test]
    async fn non_json_passes_through() {
        let hook = JsonCompressHook::new(JsonCompressConfig::default());
        let result = make_result("This is plain text, not JSON");
        let decision = hook
            .post_tool_use("echo", &json!({}), &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn small_json_passes_through() {
        let hook = JsonCompressHook::new(JsonCompressConfig::default());
        let result = make_result(r#"{"id": 1, "name": "test"}"#);
        let decision = hook
            .post_tool_use("api_call", &json!({}), &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn error_results_skipped() {
        let hook = JsonCompressHook::new(JsonCompressConfig::default());
        let mut result = make_result(r#"{"_links": {"self": "/x"}, "id": 1}"#);
        result.is_error = true;
        let decision = hook
            .post_tool_use("api_call", &json!({}), &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn strips_configured_keys() {
        let hook = JsonCompressHook::new(JsonCompressConfig::default());
        let result = make_result(
            r#"{"id": 1, "name": "test", "_links": {"self": "/1"}, "pagination": {"next": "/2"}}"#,
        );
        let decision = hook
            .post_tool_use("api_call", &json!({}), &result, &test_ctx())
            .await;
        match decision {
            HookDecision::ModifyResult(r) => {
                let text = match &r.content[0] {
                    Content::Text(t) => &t.text,
                    _ => panic!("expected text"),
                };
                let parsed: Value = serde_json::from_str(text).unwrap();
                assert!(parsed.get("id").is_some());
                assert!(parsed.get("_links").is_none());
                assert!(parsed.get("pagination").is_none());
                // Check annotation
                let annotation = match &r.content[1] {
                    Content::Text(t) => &t.text,
                    _ => panic!("expected text"),
                };
                assert!(annotation.contains("json_compress"));
                assert!(annotation.contains("keys stripped"));
            }
            other => panic!("expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn truncates_large_arrays() {
        let config = JsonCompressConfig {
            max_array_elements: 3,
            ..Default::default()
        };
        let hook = JsonCompressHook::new(config);

        let items: Vec<Value> = (0..25).map(|i| json!({"id": i, "val": format!("item-{i}")})).collect();
        let json_str = serde_json::to_string(&items).unwrap();
        let result = make_result(&json_str);

        let decision = hook
            .post_tool_use("list_items", &json!({}), &result, &test_ctx())
            .await;
        match decision {
            HookDecision::ModifyResult(r) => {
                let text = match &r.content[0] {
                    Content::Text(t) => &t.text,
                    _ => panic!("expected text"),
                };
                let parsed: Vec<Value> = serde_json::from_str(text).unwrap();
                assert_eq!(parsed.len(), 3);
                let annotation = match &r.content[1] {
                    Content::Text(t) => &t.text,
                    _ => panic!("expected text"),
                };
                assert!(annotation.contains("3/25 elements kept"));
            }
            other => panic!("expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn realistic_api_response() {
        let config = JsonCompressConfig {
            max_array_elements: 5,
            max_depth: 3,
            strip_keys: ["_links", "pagination", "metadata", "_embedded"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        let hook = JsonCompressHook::new(config);

        let response = json!({
            "total_count": 150,
            "pagination": {
                "page": 1,
                "per_page": 50,
                "total_pages": 3,
                "next_cursor": "abc123"
            },
            "_links": {
                "self": "/api/v1/items?page=1",
                "next": "/api/v1/items?page=2"
            },
            "items": (0..50).map(|i| json!({
                "id": i,
                "title": format!("Item {i}"),
                "status": "active",
                "metadata": {"created_at": "2026-01-01", "updated_at": "2026-06-01"},
                "details": {
                    "category": "test",
                    "tags": ["a", "b"],
                    "nested": {
                        "deep": {
                            "very_deep": {"key": "value"}
                        }
                    }
                }
            })).collect::<Vec<_>>()
        });
        let result = make_result(&serde_json::to_string(&response).unwrap());
        let decision = hook
            .post_tool_use("api_list", &json!({}), &result, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyResult(r) => {
                let text = match &r.content[0] {
                    Content::Text(t) => &t.text,
                    _ => panic!("expected text"),
                };
                let parsed: Value = serde_json::from_str(text).unwrap();
                // Top-level keys stripped
                assert!(parsed.get("_links").is_none());
                assert!(parsed.get("pagination").is_none());
                assert!(parsed.get("total_count").is_some());
                // Array truncated to 5
                let items = parsed["items"].as_array().unwrap();
                assert_eq!(items.len(), 5);
                // Metadata stripped from items
                assert!(items[0].get("metadata").is_none());

                let annotation = match r.content.last() {
                    Some(Content::Text(t)) => &t.text,
                    _ => panic!("expected text"),
                };
                assert!(annotation.contains("json_compress"));
            }
            other => panic!("expected ModifyResult, got {other:?}"),
        }
    }
}
