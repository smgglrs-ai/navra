//! Conversion between MCP protocol types and Open Responses types.

use myelix_model::ResponseTool;
use myelix_protocol::ToolDefinition;

/// Convert an MCP `ToolDefinition` to an Open Responses `FunctionTool`.
pub fn tool_def_to_response(tool: &ToolDefinition) -> ResponseTool {
    let mut schema = serde_json::Map::new();
    schema.insert(
        "type".to_string(),
        serde_json::Value::String(tool.input_schema.schema_type.clone()),
    );
    if let Some(props) = &tool.input_schema.properties {
        schema.insert(
            "properties".to_string(),
            serde_json::to_value(props).unwrap_or_default(),
        );
    }
    if let Some(req) = &tool.input_schema.required {
        schema.insert(
            "required".to_string(),
            serde_json::to_value(req).unwrap_or_default(),
        );
    }

    ResponseTool {
        tool_type: "function".to_string(),
        name: tool.name.clone(),
        description: tool.description.clone(),
        parameters: Some(serde_json::Value::Object(schema)),
        strict: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myelix_protocol::ToolInputSchema;
    use std::collections::HashMap;

    #[test]
    fn converts_full_tool_definition() {
        let mut props = HashMap::new();
        props.insert(
            "path".to_string(),
            serde_json::json!({"type": "string", "description": "File path"}),
        );

        let tool = ToolDefinition {
            name: "docs_read".to_string(),
            description: Some("Read a document".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: Some(props),
                required: Some(vec!["path".to_string()]),
            },
        };

        let response_tool = tool_def_to_response(&tool);
        assert_eq!(response_tool.name, "docs_read");
        assert_eq!(response_tool.description.as_deref(), Some("Read a document"));
        let params = response_tool.parameters.unwrap();
        assert_eq!(params["type"], "object");
        assert_eq!(params["properties"]["path"]["type"], "string");
        assert_eq!(params["required"][0], "path");
    }

    #[test]
    fn converts_minimal_tool_definition() {
        let tool = ToolDefinition {
            name: "ping".to_string(),
            description: None,
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
        };

        let response_tool = tool_def_to_response(&tool);
        assert_eq!(response_tool.name, "ping");
        assert!(response_tool.description.is_none());
        let params = response_tool.parameters.unwrap();
        assert_eq!(params["type"], "object");
    }
}
