//! Request types for creating responses.

use crate::item::InputItem;
use crate::tool::{FunctionTool, ToolChoice};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Request to create a response.
///
/// This is the primary input type — equivalent to `POST /v1/responses`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateResponseRequest {
    /// Model identifier.
    pub model: String,
    /// Input items (messages, tool results, references).
    pub input: Vec<InputItem>,
    /// Instructions (system prompt). Appended to default instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Available tools.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<FunctionTool>,
    /// Tool selection strategy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Maximum output tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    /// Maximum tool calls per response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tool_calls: Option<u32>,
    /// Sampling temperature (0.0–2.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Nucleus sampling threshold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Presence penalty (-2.0–2.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f32>,
    /// Frequency penalty (-2.0–2.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f32>,
    /// Text output configuration (format, verbosity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<TextConfig>,
    /// Reasoning configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<ReasoningConfig>,
    /// Whether to enable streaming.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Previous response ID for stateful follow-ups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    /// Context truncation strategy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncation: Option<Truncation>,
    /// Allow parallel tool calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    /// Whether to persist the response for later retrieval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    /// Run in background (return immediately, poll for result).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<bool>,
    /// Service tier hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_tier: Option<String>,
    /// Metadata key-value pairs (max 16).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
    /// Provider-specific extension fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl CreateResponseRequest {
    /// Create a minimal request.
    pub fn new(model: impl Into<String>, input: Vec<InputItem>) -> Self {
        Self {
            model: model.into(),
            input,
            instructions: None,
            tools: Vec::new(),
            tool_choice: None,
            max_output_tokens: None,
            max_tool_calls: None,
            temperature: None,
            top_p: None,
            presence_penalty: None,
            frequency_penalty: None,
            text: None,
            reasoning: None,
            stream: None,
            previous_response_id: None,
            truncation: None,
            parallel_tool_calls: None,
            store: None,
            background: None,
            service_tier: None,
            metadata: HashMap::new(),
            extra: HashMap::new(),
        }
    }

    /// Set instructions (system prompt).
    pub fn with_instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// Set tools.
    pub fn with_tools(mut self, tools: Vec<FunctionTool>) -> Self {
        self.tools = tools;
        self
    }

    /// Set response format to JSON schema.
    pub fn with_json_schema(mut self, name: impl Into<String>, schema: serde_json::Value) -> Self {
        self.text = Some(TextConfig {
            format: Some(ResponseFormat::JsonSchema {
                name: name.into(),
                description: None,
                schema,
                strict: Some(true),
            }),
            verbosity: None,
        });
        self
    }

    /// Enable streaming.
    pub fn streaming(mut self) -> Self {
        self.stream = Some(true);
        self
    }

    /// Set previous response for stateful follow-up.
    pub fn following(mut self, response_id: impl Into<String>) -> Self {
        self.previous_response_id = Some(response_id.into());
        self
    }
}

/// Text output configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextConfig {
    /// Output format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<ResponseFormat>,
    /// Output verbosity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verbosity: Option<Verbosity>,
}

/// Response output format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum ResponseFormat {
    /// Free-form text.
    #[serde(rename = "text")]
    Text,
    /// Valid JSON object.
    #[serde(rename = "json_object")]
    JsonObject,
    /// JSON conforming to a schema.
    #[serde(rename = "json_schema")]
    JsonSchema {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        schema: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        strict: Option<bool>,
    },
}

/// Reasoning configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effort: Option<ReasoningEffort>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<ReasoningSummary>,
}

/// Reasoning effort level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningEffort {
    None,
    Low,
    Medium,
    High,
    Xhigh,
}

/// Reasoning summary mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningSummary {
    Concise,
    Detailed,
    Auto,
}

/// Output verbosity level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verbosity {
    Low,
    Medium,
    High,
}

/// Context truncation strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Truncation {
    /// Gracefully drop oldest items when context overflows.
    Auto,
    /// Fail if context would overflow.
    Disabled,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::InputItem;

    #[test]
    fn minimal_request() {
        let req = CreateResponseRequest::new("granite3.3:8b", vec![InputItem::user("Hello")]);
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "granite3.3:8b");
        assert!(json["input"].is_array());
    }

    #[test]
    fn request_with_json_schema() {
        let req = CreateResponseRequest::new("gpt-4o", vec![InputItem::user("List findings")])
            .with_json_schema(
                "findings",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "items": { "type": "array" }
                    }
                }),
            );
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["text"]["format"]["type"], "json_schema");
        assert_eq!(json["text"]["format"]["name"], "findings");
        assert_eq!(json["text"]["format"]["strict"], true);
    }

    #[test]
    fn response_format_text_serde() {
        let fmt = ResponseFormat::Text;
        let json = serde_json::to_string(&fmt).unwrap();
        assert!(json.contains("\"type\":\"text\""));
    }

    #[test]
    fn response_format_json_schema_roundtrip() {
        let fmt = ResponseFormat::JsonSchema {
            name: "audit".to_string(),
            description: Some("Security audit findings".to_string()),
            schema: serde_json::json!({"type": "object"}),
            strict: Some(true),
        };
        let json = serde_json::to_string(&fmt).unwrap();
        let parsed: ResponseFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(fmt, parsed);
    }

    #[test]
    fn stateful_followup() {
        let req = CreateResponseRequest::new("model", vec![InputItem::user("Continue")])
            .following("resp_abc123");
        assert_eq!(req.previous_response_id.as_deref(), Some("resp_abc123"));
    }

    #[test]
    fn extra_fields_preserved() {
        let json = serde_json::json!({
            "model": "test",
            "input": [],
            "smgglrs:ifc_label": "confidential"
        });
        let req: CreateResponseRequest = serde_json::from_value(json).unwrap();
        assert_eq!(
            req.extra.get("smgglrs:ifc_label").and_then(|v| v.as_str()),
            Some("confidential")
        );
    }
}
