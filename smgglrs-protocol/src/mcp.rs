use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MCP protocol version supported by this implementation.
pub const PROTOCOL_VERSION: &str = "2025-03-26";

// --- Initialize ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: ClientInfo,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roots: Option<RootsCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootsCapability {
    #[serde(default)]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
    /// Permission negotiation extension (smgglrs extension to MCP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<crate::permissions::PermissionsCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    #[serde(default)]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    #[serde(default)]
    pub subscribe: bool,
    #[serde(default)]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

// --- Tools ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: ToolInputSchema,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInputSchema {
    #[serde(rename = "type")]
    pub schema_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListToolsResult {
    pub tools: Vec<ToolDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolParams {
    pub name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    pub content: Vec<Content>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
    /// IFC data label for this result (kernel-internal, not serialized).
    #[serde(skip)]
    pub label: crate::label::DataLabel,
}

// --- Content ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Content {
    Text(TextContent),
    // Future: Image, Resource
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextContent {
    pub text: String,
}

impl Content {
    pub fn text(text: impl Into<String>) -> Self {
        Content::Text(TextContent { text: text.into() })
    }
}

impl CallToolResult {
    pub fn success(content: Vec<Content>) -> Self {
        Self {
            content,
            is_error: false,
            label: crate::label::DataLabel::TRUSTED_PUBLIC,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![Content::text(message)],
            is_error: true,
            label: crate::label::DataLabel::TRUSTED_PUBLIC,
        }
    }

    pub fn text(text: impl Into<String>) -> Self {
        Self::success(vec![Content::text(text)])
    }

    /// Set the IFC data label on this result.
    pub fn with_label(mut self, label: crate::label::DataLabel) -> Self {
        self.label = label;
        self
    }
}

// --- Prompts ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptsCapability {
    #[serde(default)]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListPromptsResult {
    pub prompts: Vec<PromptDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPromptParams {
    pub name: String,
    #[serde(default)]
    pub arguments: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPromptResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub messages: Vec<PromptMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptMessage {
    pub role: PromptRole,
    pub content: Content,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PromptRole {
    User,
    Assistant,
}

// --- Resources ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResourcesResult {
    pub resources: Vec<ResourceDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResourceParams {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResourceResult {
    pub contents: Vec<ResourceContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContent {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

// --- Content Type helper ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Json,
    EventStream,
}

impl ContentType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::EventStream => "text/event-stream",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_initialize_params() {
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ClientCapabilities::default(),
            client_info: ClientInfo {
                name: "test-client".to_string(),
                version: Some("1.0".to_string()),
            },
        };
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["protocolVersion"], "2025-03-26");
        assert_eq!(json["clientInfo"]["name"], "test-client");
    }

    #[test]
    fn serialize_initialize_result() {
        let result = InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: true }),
                resources: Some(ResourcesCapability {
                    subscribe: true,
                    list_changed: true,
                }),
                prompts: None,
                permissions: None,
            },
            server_info: ServerInfo {
                name: "smgglrs-docs".to_string(),
                version: Some("0.1.0".to_string()),
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["capabilities"]["tools"]["listChanged"].as_bool().unwrap());
        assert!(json["capabilities"]["resources"]["subscribe"].as_bool().unwrap());
    }

    #[test]
    fn serialize_tool_definition() {
        let tool = ToolDefinition {
            name: "docs_search".to_string(),
            description: Some("Search documents".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: Some(HashMap::from([(
                    "query".to_string(),
                    serde_json::json!({"type": "string", "description": "Search query"}),
                )])),
                required: Some(vec!["query".to_string()]),
            },
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["name"], "docs_search");
        assert_eq!(json["inputSchema"]["type"], "object");
        assert!(json["inputSchema"]["required"].as_array().unwrap().contains(&serde_json::json!("query")));
    }

    #[test]
    fn tool_result_success() {
        let result = CallToolResult::text("hello");
        assert!(!result.is_error);
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["content"][0]["type"], "text");
        assert_eq!(json["content"][0]["text"], "hello");
        // is_error=false should be omitted
        assert!(json.get("isError").is_none());
    }

    #[test]
    fn tool_result_error() {
        let result = CallToolResult::error("something went wrong");
        assert!(result.is_error);
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["isError"].as_bool().unwrap());
    }

    #[test]
    fn deserialize_call_tool_params() {
        let json = r#"{"name":"docs_read","arguments":{"path":"/home/user/doc.md"}}"#;
        let params: CallToolParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "docs_read");
        assert_eq!(params.arguments["path"], "/home/user/doc.md");
    }

    #[test]
    fn content_type_strings() {
        assert_eq!(ContentType::Json.as_str(), "application/json");
        assert_eq!(ContentType::EventStream.as_str(), "text/event-stream");
    }

    #[test]
    fn serialize_prompt_definition() {
        let prompt = PromptDefinition {
            name: "persona:developer".to_string(),
            description: Some("Software Developer persona".to_string()),
            arguments: vec![PromptArgument {
                name: "mandate".to_string(),
                description: Some("The task to perform".to_string()),
                required: true,
            }],
        };
        let json = serde_json::to_value(&prompt).unwrap();
        assert_eq!(json["name"], "persona:developer");
        assert_eq!(json["arguments"][0]["name"], "mandate");
        assert!(json["arguments"][0]["required"].as_bool().unwrap());
    }

    #[test]
    fn serialize_prompt_definition_no_args() {
        let prompt = PromptDefinition {
            name: "greeting".to_string(),
            description: None,
            arguments: vec![],
        };
        let json = serde_json::to_value(&prompt).unwrap();
        assert_eq!(json["name"], "greeting");
        // Empty arguments should be omitted
        assert!(json.get("arguments").is_none());
    }

    #[test]
    fn serialize_get_prompt_result() {
        let result = GetPromptResult {
            description: Some("A test prompt".to_string()),
            messages: vec![PromptMessage {
                role: PromptRole::User,
                content: Content::text("Hello, world!"),
            }],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["description"], "A test prompt");
        assert_eq!(json["messages"][0]["role"], "user");
        assert_eq!(json["messages"][0]["content"]["text"], "Hello, world!");
    }

    #[test]
    fn deserialize_get_prompt_params() {
        let json = r#"{"name":"persona:dev","arguments":{"mandate":"Fix the bug"}}"#;
        let params: GetPromptParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "persona:dev");
        assert_eq!(params.arguments["mandate"], "Fix the bug");
    }

    #[test]
    fn deserialize_get_prompt_params_no_args() {
        let json = r#"{"name":"greeting"}"#;
        let params: GetPromptParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "greeting");
        assert!(params.arguments.is_empty());
    }

    #[test]
    fn serialize_resource_definition() {
        let resource = ResourceDefinition {
            uri: "file:///home/user/doc.md".to_string(),
            name: "doc.md".to_string(),
            description: Some("A document".to_string()),
            mime_type: Some("text/markdown".to_string()),
        };
        let json = serde_json::to_value(&resource).unwrap();
        assert_eq!(json["uri"], "file:///home/user/doc.md");
        assert_eq!(json["name"], "doc.md");
        assert_eq!(json["mimeType"], "text/markdown");
    }

    #[test]
    fn serialize_read_resource_result() {
        let result = ReadResourceResult {
            contents: vec![ResourceContent {
                uri: "file:///doc.md".to_string(),
                mime_type: Some("text/markdown".to_string()),
                text: Some("# Hello".to_string()),
                blob: None,
            }],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["contents"][0]["uri"], "file:///doc.md");
        assert_eq!(json["contents"][0]["text"], "# Hello");
        assert!(json["contents"][0].get("blob").is_none());
    }

    #[test]
    fn deserialize_read_resource_params() {
        let json = r#"{"uri":"file:///doc.md"}"#;
        let params: ReadResourceParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.uri, "file:///doc.md");
    }

    #[test]
    fn capabilities_with_prompts() {
        let caps = ServerCapabilities {
            tools: None,
            resources: None,
            prompts: Some(PromptsCapability { list_changed: true }),
            permissions: None,
        };
        let json = serde_json::to_value(&caps).unwrap();
        assert!(json["prompts"]["listChanged"].as_bool().unwrap());
        // tools and resources should be omitted
        assert!(json.get("tools").is_none());
    }
}
