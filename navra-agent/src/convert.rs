//! Conversion between MCP protocol types and Open Responses types.

use navra_model::ResponseTool;
use navra_protocol::ToolDefinition;

/// Convert an MCP `ToolDefinition` to an Open Responses `FunctionTool`.
pub fn tool_def_to_response(tool: &ToolDefinition) -> ResponseTool {
    let schema = serde_json::Value::Object(tool.input_schema.as_ref().clone());

    ResponseTool {
        kind: "function".to_string(),
        name: tool.name.to_string(),
        description: tool.description.as_deref().map(|s| s.to_string()),
        parameters: Some(schema),
        strict: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_tool(name: &str, description: Option<&str>, schema: serde_json::Value) -> ToolDefinition {
        let obj = match schema {
            serde_json::Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        ToolDefinition::new_with_raw(
            name.to_string(),
            description.map(|s| std::borrow::Cow::Owned(s.to_string())),
            Arc::new(obj),
        )
    }

    #[test]
    fn converts_full_tool_definition() {
        let tool = make_tool(
            "file_read",
            Some("Read a document"),
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"}
                },
                "required": ["path"]
            }),
        );

        let response_tool = tool_def_to_response(&tool);
        assert_eq!(response_tool.name, "file_read");
        assert_eq!(
            response_tool.description.as_deref(),
            Some("Read a document")
        );
        let params = response_tool.parameters.unwrap();
        assert_eq!(params["type"], "object");
        assert_eq!(params["properties"]["path"]["type"], "string");
        assert_eq!(params["required"][0], "path");
    }

    #[test]
    fn converts_minimal_tool_definition() {
        let tool = make_tool(
            "ping",
            None,
            serde_json::json!({"type": "object"}),
        );

        let response_tool = tool_def_to_response(&tool);
        assert_eq!(response_tool.name, "ping");
        assert!(response_tool.description.is_none());
        let params = response_tool.parameters.unwrap();
        assert_eq!(params["type"], "object");
    }
}
