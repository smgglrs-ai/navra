use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MCP protocol version supported by this implementation.
pub const PROTOCOL_VERSION: &str = "2025-03-26";

// --- Server-initiated notification methods ---

pub const NOTIFY_TOOLS_LIST_CHANGED: &str = "notifications/tools/list_changed";
pub const NOTIFY_RESOURCES_LIST_CHANGED: &str = "notifications/resources/list_changed";
pub const NOTIFY_RESOURCES_UPDATED: &str = "notifications/resources/updated";
pub const NOTIFY_PROMPTS_LIST_CHANGED: &str = "notifications/prompts/list_changed";
pub const NOTIFY_PROGRESS: &str = "notifications/progress";
pub const NOTIFY_INITIALIZED: &str = "notifications/initialized";

/// Default page size for paginated list operations.
pub const DEFAULT_PAGE_SIZE: usize = 100;

// --- Pagination ---

/// Optional cursor parameter for paginated list requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl PaginatedRequest {
    /// Decode the cursor into an offset. Returns 0 if no cursor is set.
    /// Returns `None` if the cursor is present but invalid.
    pub fn decode_offset(&self) -> Option<usize> {
        match &self.cursor {
            None => Some(0),
            Some(cursor) => {
                let bytes = URL_SAFE_NO_PAD.decode(cursor).ok()?;
                let s = std::str::from_utf8(&bytes).ok()?;
                s.parse::<usize>().ok()
            }
        }
    }
}

/// Encode an offset into a cursor string.
pub fn encode_cursor(offset: usize) -> String {
    URL_SAFE_NO_PAD.encode(offset.to_string().as_bytes())
}

/// Apply pagination to a collected list, returning (page, next_cursor).
pub fn paginate<T: Clone>(items: &[T], offset: usize, page_size: usize) -> (Vec<T>, Option<String>) {
    if offset >= items.len() {
        return (Vec::new(), None);
    }
    let end = (offset + page_size).min(items.len());
    let page = items[offset..end].to_vec();
    let next_cursor = if end < items.len() {
        Some(encode_cursor(end))
    } else {
        None
    };
    (page, next_cursor)
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
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
#[serde(rename_all = "camelCase")]
pub struct ListToolsResult {
    pub tools: Vec<ToolDefinition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolParams {
    pub name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "_meta")]
    pub meta: Option<RequestMeta>,
}

/// Request metadata carrying a progress token for long-running operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_token: Option<serde_json::Value>,
}

/// Parameters for `notifications/progress`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressParams {
    pub progress_token: serde_json::Value,
    pub progress: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Parameters for `notifications/resources/updated`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUpdatedParams {
    pub uri: String,
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
    Image(ImageContent),
    Audio(AudioContent),
    Resource(EmbeddedResourceContent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextContent {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageContent {
    pub data: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioContent {
    pub data: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedResourceContent {
    pub resource: ResourceContent,
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
#[serde(rename_all = "camelCase")]
pub struct ListPromptsResult {
    pub prompts: Vec<PromptDefinition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResourcesResult {
    pub resources: Vec<ResourceDefinition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
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

// --- Roots ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Root {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRootsResult {
    pub roots: Vec<Root>,
}

// --- Resource Templates ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTemplate {
    pub uri_template: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResourceTemplatesResult {
    pub resource_templates: Vec<ResourceTemplate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// --- Cancellation ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelledNotification {
    pub request_id: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// --- Progress ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressNotification {
    pub progress_token: serde_json::Value,
    pub progress: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// --- Logging ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingLevel {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetLevelParams {
    pub level: LoggingLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingMessageNotification {
    pub level: LoggingLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logger: Option<String>,
    pub data: serde_json::Value,
}

// --- Sampling ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateMessageParams {
    pub messages: Vec<SamplingMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_preferences: Option<ModelPreferences>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    pub max_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateMessageResult {
    pub role: String,
    pub content: serde_json::Value,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelPreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<ModelHint>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_priority: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed_priority: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_priority: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelHint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingMessage {
    pub role: String,
    pub content: serde_json::Value,
}

// --- Completions ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteParams {
    pub ref_type: String,
    pub ref_name: String,
    pub argument: CompletionArgument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionArgument {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteResult {
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_more: Option<bool>,
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
            instructions: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["capabilities"]["tools"]["listChanged"].as_bool().unwrap());
        assert!(json["capabilities"]["resources"]["subscribe"].as_bool().unwrap());
    }

    #[test]
    fn serialize_tool_definition() {
        let tool = ToolDefinition {
            name: "file_search".to_string(),
            description: Some("Search documents".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: Some(HashMap::from([(
                    "query".to_string(),
                    serde_json::json!({"type": "string", "description": "Search query"}),
                )])),
                required: Some(vec!["query".to_string()]),
            },
            annotations: None,
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["name"], "file_search");
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
        let json = r#"{"name":"file_read","arguments":{"path":"/home/user/doc.md"}}"#;
        let params: CallToolParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "file_read");
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
            size: None,
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

    #[test]
    fn serialize_initialize_result_with_instructions() {
        let result = InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities::default(),
            server_info: ServerInfo {
                name: "test".to_string(),
                version: None,
            },
            instructions: Some("You are a helpful assistant.".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["instructions"], "You are a helpful assistant.");
    }

    #[test]
    fn serialize_tool_annotations() {
        let tool = ToolDefinition {
            name: "file_read".to_string(),
            description: None,
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
                idempotent_hint: Some(true),
                open_world_hint: None,
                title: Some("Read File".to_string()),
            }),
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert!(json["annotations"]["readOnlyHint"].as_bool().unwrap());
        assert!(!json["annotations"]["destructiveHint"].as_bool().unwrap());
        assert_eq!(json["annotations"]["title"], "Read File");
        assert!(json["annotations"].get("openWorldHint").is_none());
    }

    #[test]
    fn serialize_image_content() {
        let content = Content::Image(ImageContent {
            data: "iVBORw0KGgo=".to_string(),
            mime_type: "image/png".to_string(),
        });
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "image");
        assert_eq!(json["mimeType"], "image/png");
    }

    #[test]
    fn serialize_audio_content() {
        let content = Content::Audio(AudioContent {
            data: "UklGR...".to_string(),
            mime_type: "audio/wav".to_string(),
        });
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "audio");
        assert_eq!(json["mimeType"], "audio/wav");
    }

    #[test]
    fn serialize_embedded_resource_content() {
        let content = Content::Resource(EmbeddedResourceContent {
            resource: ResourceContent {
                uri: "file:///doc.md".to_string(),
                mime_type: Some("text/markdown".to_string()),
                text: Some("# Title".to_string()),
                blob: None,
            },
        });
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "resource");
        assert_eq!(json["resource"]["uri"], "file:///doc.md");
    }

    #[test]
    fn serialize_resource_with_size() {
        let resource = ResourceDefinition {
            uri: "file:///data.bin".to_string(),
            name: "data.bin".to_string(),
            description: None,
            mime_type: None,
            size: Some(4096),
        };
        let json = serde_json::to_value(&resource).unwrap();
        assert_eq!(json["size"], 4096);
    }

    #[test]
    fn roundtrip_root() {
        let root = Root {
            uri: "file:///workspace".to_string(),
            name: Some("Workspace".to_string()),
        };
        let json = serde_json::to_string(&root).unwrap();
        let parsed: Root = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.uri, "file:///workspace");
        assert_eq!(parsed.name.as_deref(), Some("Workspace"));
    }

    #[test]
    fn roundtrip_cancelled_notification() {
        let notif = CancelledNotification {
            request_id: serde_json::json!(42),
            reason: Some("User cancelled".to_string()),
        };
        let json = serde_json::to_string(&notif).unwrap();
        let parsed: CancelledNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.request_id, serde_json::json!(42));
        assert_eq!(parsed.reason.as_deref(), Some("User cancelled"));
    }

    #[test]
    fn roundtrip_progress_notification() {
        let notif = ProgressNotification {
            progress_token: serde_json::json!("tok-1"),
            progress: 0.5,
            total: Some(1.0),
            message: Some("Halfway done".to_string()),
        };
        let json = serde_json::to_string(&notif).unwrap();
        let parsed: ProgressNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.progress, 0.5);
        assert_eq!(parsed.total, Some(1.0));
    }

    #[test]
    fn roundtrip_logging_level() {
        let params = SetLevelParams {
            level: LoggingLevel::Warning,
        };
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["level"], "warning");
        let parsed: SetLevelParams = serde_json::from_value(json).unwrap();
        assert!(matches!(parsed.level, LoggingLevel::Warning));
    }

    #[test]
    fn roundtrip_create_message_params() {
        let params = CreateMessageParams {
            messages: vec![SamplingMessage {
                role: "user".to_string(),
                content: serde_json::json!({"type": "text", "text": "Hello"}),
            }],
            model_preferences: Some(ModelPreferences {
                hints: Some(vec![ModelHint {
                    name: Some("claude-sonnet".to_string()),
                }]),
                cost_priority: None,
                speed_priority: Some(0.8),
                intelligence_priority: None,
            }),
            system_prompt: None,
            max_tokens: 1024,
        };
        let json = serde_json::to_string(&params).unwrap();
        let parsed: CreateMessageParams = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_tokens, 1024);
        assert_eq!(parsed.messages.len(), 1);
    }

    #[test]
    fn roundtrip_complete_params() {
        let params = CompleteParams {
            ref_type: "ref/prompt".to_string(),
            ref_name: "code_review".to_string(),
            argument: CompletionArgument {
                name: "language".to_string(),
                value: "py".to_string(),
            },
        };
        let json = serde_json::to_string(&params).unwrap();
        let parsed: CompleteParams = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ref_type, "ref/prompt");
        assert_eq!(parsed.argument.value, "py");
    }

    #[test]
    fn roundtrip_resource_template() {
        let tmpl = ResourceTemplate {
            uri_template: "file:///{path}".to_string(),
            name: "File".to_string(),
            description: Some("Read any file".to_string()),
            mime_type: None,
            annotations: None,
        };
        let json = serde_json::to_value(&tmpl).unwrap();
        assert_eq!(json["uriTemplate"], "file:///{path}");
        let parsed: ResourceTemplate = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.name, "File");
    }

    // --- Pagination tests ---

    #[test]
    fn paginated_request_no_cursor_decodes_to_zero() {
        let req = PaginatedRequest { cursor: None };
        assert_eq!(req.decode_offset(), Some(0));
    }

    #[test]
    fn cursor_roundtrip() {
        let offset = 42usize;
        let cursor = encode_cursor(offset);
        let req = PaginatedRequest { cursor: Some(cursor) };
        assert_eq!(req.decode_offset(), Some(42));
    }

    #[test]
    fn invalid_cursor_returns_none() {
        let req = PaginatedRequest { cursor: Some("!!!invalid!!!".to_string()) };
        assert_eq!(req.decode_offset(), None);
    }

    #[test]
    fn paginate_all_items_no_next_cursor() {
        let items: Vec<i32> = (0..5).collect();
        let (page, next) = paginate(&items, 0, 100);
        assert_eq!(page.len(), 5);
        assert!(next.is_none());
    }

    #[test]
    fn paginate_first_page_with_next_cursor() {
        let items: Vec<i32> = (0..10).collect();
        let (page, next) = paginate(&items, 0, 3);
        assert_eq!(page, vec![0, 1, 2]);
        assert!(next.is_some());

        // Decode the cursor and fetch the next page
        let req = PaginatedRequest { cursor: next };
        let offset = req.decode_offset().unwrap();
        assert_eq!(offset, 3);

        let (page2, next2) = paginate(&items, offset, 3);
        assert_eq!(page2, vec![3, 4, 5]);
        assert!(next2.is_some());
    }

    #[test]
    fn paginate_last_page_no_next_cursor() {
        let items: Vec<i32> = (0..10).collect();
        let (page, next) = paginate(&items, 9, 3);
        assert_eq!(page, vec![9]);
        assert!(next.is_none());
    }

    #[test]
    fn paginate_offset_past_end() {
        let items: Vec<i32> = (0..5).collect();
        let (page, next) = paginate(&items, 100, 3);
        assert!(page.is_empty());
        assert!(next.is_none());
    }

    #[test]
    fn paginate_empty_list() {
        let items: Vec<i32> = vec![];
        let (page, next) = paginate(&items, 0, 10);
        assert!(page.is_empty());
        assert!(next.is_none());
    }

    #[test]
    fn list_tools_result_serializes_next_cursor() {
        let result = ListToolsResult {
            tools: vec![],
            next_cursor: Some(encode_cursor(5)),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["nextCursor"].is_string());
    }

    #[test]
    fn list_tools_result_omits_null_next_cursor() {
        let result = ListToolsResult {
            tools: vec![],
            next_cursor: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json.get("nextCursor").is_none());
    }

    #[test]
    fn paginated_request_deserializes_from_empty() {
        let json = r#"{}"#;
        let req: PaginatedRequest = serde_json::from_str(json).unwrap();
        assert!(req.cursor.is_none());
        assert_eq!(req.decode_offset(), Some(0));
    }

    #[test]
    fn paginated_request_deserializes_with_cursor() {
        let cursor = encode_cursor(50);
        let json = format!(r#"{{"cursor":"{}"}}"#, cursor);
        let req: PaginatedRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.decode_offset(), Some(50));
    }
}
