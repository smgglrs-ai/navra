//! Compatibility helpers for navra-specific patterns on top of rmcp types.

use rmcp::model::{CallToolResult, Content};
use std::collections::HashMap;
use std::sync::Arc;

/// Build a JSON Schema `object` from structured properties and required fields.
///
/// Replaces the old `ToolInputSchema { schema_type, properties, required }`
/// struct with a raw JSON object that rmcp's `Tool::input_schema` expects.
pub fn tool_input_schema(
    properties: Option<HashMap<String, serde_json::Value>>,
    required: Option<Vec<String>>,
) -> Arc<serde_json::Map<String, serde_json::Value>> {
    let mut map = serde_json::Map::new();
    map.insert(
        "type".to_owned(),
        serde_json::Value::String("object".to_owned()),
    );
    if let Some(props) = properties {
        let props_map: serde_json::Map<String, serde_json::Value> = props.into_iter().collect();
        map.insert(
            "properties".to_owned(),
            serde_json::Value::Object(props_map),
        );
    }
    if let Some(req) = required {
        map.insert(
            "required".to_owned(),
            serde_json::Value::Array(req.into_iter().map(serde_json::Value::String).collect()),
        );
    }
    Arc::new(map)
}

/// Build a minimal empty-object JSON Schema (no properties, no required).
pub fn empty_input_schema() -> Arc<serde_json::Map<String, serde_json::Value>> {
    let mut map = serde_json::Map::new();
    map.insert(
        "type".to_owned(),
        serde_json::Value::String("object".to_owned()),
    );
    Arc::new(map)
}

/// Extension trait adding navra convenience constructors to `CallToolResult`.
pub trait CallToolResultExt {
    fn text(msg: impl Into<String>) -> CallToolResult;
    fn error_msg(msg: impl Into<String>) -> CallToolResult;
    fn is_err(&self) -> bool;
}

impl CallToolResultExt for CallToolResult {
    fn text(msg: impl Into<String>) -> CallToolResult {
        CallToolResult::success(vec![Content::text(msg)])
    }

    fn error_msg(msg: impl Into<String>) -> CallToolResult {
        CallToolResult::error(vec![Content::text(msg)])
    }

    fn is_err(&self) -> bool {
        self.is_error == Some(true)
    }
}

/// Extract text from a `Content` value, if it is a text variant.
pub fn content_as_text(content: &Content) -> Option<&str> {
    content.raw.as_text().map(|tc| tc.text.as_str())
}

/// Compress tool output to fit within a token budget.
///
/// Truncates text content at sentence boundaries and appends a
/// truncation notice.
pub fn compress_result(result: &mut CallToolResult, max_tokens: u32) {
    let chars_budget = (max_tokens as usize) * 4;
    for content in &mut result.content {
        if let Some(tc) = content.raw.as_text()
            && tc.text.len() > chars_budget
        {
            let cut = chars_budget.saturating_sub(40).min(tc.text.len());
            let mut safe_cut = cut;
            while safe_cut > 0 && !tc.text.is_char_boundary(safe_cut) {
                safe_cut -= 1;
            }
            let slice = &tc.text[..safe_cut];
            let cut_point = slice
                .rfind(". ")
                .or_else(|| slice.rfind('\n'))
                .map(|p| p + 1)
                .unwrap_or(safe_cut);
            let remaining = tc.text.len() - cut_point;
            let new_text = format!(
                "{}\n[compressed — {remaining} chars omitted]",
                &tc.text[..cut_point]
            );
            *content = Content::text(new_text);
        }
    }
}
