//! Conversion between MCP protocol types and model chat types.

use myelix_model::ChatToolDefinition;
use myelix_protocol::ToolDefinition;

/// Convert an MCP `ToolDefinition` to a model `ChatToolDefinition`.
///
/// The MCP schema has typed fields (`schema_type`, `properties`, `required`)
/// while the chat type expects a flat JSON Schema value.
pub fn tool_def_to_chat(tool: &ToolDefinition) -> ChatToolDefinition {
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

    ChatToolDefinition {
        name: tool.name.clone(),
        description: tool.description.clone().unwrap_or_default(),
        parameters: serde_json::Value::Object(schema),
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

        let chat = tool_def_to_chat(&tool);
        assert_eq!(chat.name, "docs_read");
        assert_eq!(chat.description, "Read a document");
        assert_eq!(chat.parameters["type"], "object");
        assert_eq!(
            chat.parameters["properties"]["path"]["type"],
            "string"
        );
        assert_eq!(chat.parameters["required"][0], "path");
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

        let chat = tool_def_to_chat(&tool);
        assert_eq!(chat.name, "ping");
        assert_eq!(chat.description, "");
        assert_eq!(chat.parameters["type"], "object");
        assert!(chat.parameters.get("properties").is_none());
        assert!(chat.parameters.get("required").is_none());
    }
}
