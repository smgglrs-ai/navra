//! Response types returned by the API.

use crate::item::OutputItem;
use crate::tool::{FunctionTool, ToolChoice};
use crate::request::{ReasoningConfig, TextConfig, Truncation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A completed (or in-progress) response from the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Unique response identifier.
    pub id: String,
    /// Always "response".
    #[serde(default = "default_object")]
    pub object: String,
    /// Unix timestamp of creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    /// Unix timestamp of completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<u64>,
    /// Response lifecycle status.
    pub status: ResponseStatus,
    /// Model used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Output items (messages, function calls, reasoning).
    pub output: Vec<OutputItem>,
    /// Token usage statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    /// Error details (if status is failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<crate::error::ResponseError>,
    /// Previous response ID (for stateful chains).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    /// Instructions used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Tools available during this response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<FunctionTool>,
    /// Tool choice used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Text configuration used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<TextConfig>,
    /// Reasoning configuration used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<ReasoningConfig>,
    /// Truncation strategy used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncation: Option<Truncation>,
    /// Temperature used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Max output tokens used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    /// Metadata.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
    /// Incomplete details (if status is incomplete).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete_details: Option<IncompleteDetails>,
    /// Provider-specific extension fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

fn default_object() -> String {
    "response".to_string()
}

/// Response lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    InProgress,
    Completed,
    Incomplete,
    Failed,
    Queued,
}

/// Details about why a response is incomplete.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncompleteDetails {
    pub reason: String,
}

/// Token usage statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens_details: Option<InputTokensDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens_details: Option<OutputTokensDetails>,
}

/// Breakdown of input token usage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputTokensDetails {
    pub cached_tokens: u32,
}

/// Breakdown of output token usage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutputTokensDetails {
    pub reasoning_tokens: u32,
}

// --- Helpers ---

impl Response {
    /// Extract the first text output from the response.
    pub fn text(&self) -> Option<String> {
        self.output.iter().find_map(|item| item.text())
    }

    /// Get all function calls from the response.
    pub fn function_calls(&self) -> Vec<&crate::item::FunctionCallItem> {
        self.output
            .iter()
            .filter_map(|item| match item {
                OutputItem::FunctionCall(fc) => Some(fc),
                _ => None,
            })
            .collect()
    }

    /// Get all reasoning items from the response.
    pub fn reasoning(&self) -> Vec<&crate::item::ReasoningItem> {
        self.output
            .iter()
            .filter_map(|item| match item {
                OutputItem::Reasoning(r) => Some(r),
                _ => None,
            })
            .collect()
    }

    /// Whether the response completed successfully.
    pub fn is_completed(&self) -> bool {
        self.status == ResponseStatus::Completed
    }

    /// Whether the response has function calls that need execution.
    pub fn has_function_calls(&self) -> bool {
        self.output
            .iter()
            .any(|item| matches!(item, OutputItem::FunctionCall(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::*;

    #[test]
    fn response_text_extraction() {
        let resp = Response {
            id: "resp_1".into(),
            object: "response".into(),
            created_at: None,
            completed_at: None,
            status: ResponseStatus::Completed,
            model: Some("test".into()),
            output: vec![OutputItem::Message(MessageItem::assistant("Hello!"))],
            usage: Some(Usage {
                input_tokens: 10,
                output_tokens: 5,
                total_tokens: 15,
                input_tokens_details: None,
                output_tokens_details: None,
            }),
            error: None,
            previous_response_id: None,
            instructions: None,
            tools: vec![],
            tool_choice: None,
            text: None,
            reasoning: None,
            truncation: None,
            temperature: None,
            max_output_tokens: None,
            metadata: HashMap::new(),
            incomplete_details: None,
            extra: HashMap::new(),
        };

        assert_eq!(resp.text().as_deref(), Some("Hello!"));
        assert!(resp.is_completed());
        assert!(!resp.has_function_calls());
    }

    #[test]
    fn response_function_calls() {
        let resp = Response {
            id: "resp_2".into(),
            object: "response".into(),
            created_at: None,
            completed_at: None,
            status: ResponseStatus::Completed,
            model: None,
            output: vec![
                OutputItem::FunctionCall(FunctionCallItem {
                    id: Some("fc_1".into()),
                    call_id: "call_1".into(),
                    name: "search".into(),
                    arguments: "{}".into(),
                    status: Some(ItemStatus::Completed),
                }),
                OutputItem::FunctionCall(FunctionCallItem {
                    id: Some("fc_2".into()),
                    call_id: "call_2".into(),
                    name: "read".into(),
                    arguments: "{}".into(),
                    status: Some(ItemStatus::Completed),
                }),
            ],
            usage: None,
            error: None,
            previous_response_id: None,
            instructions: None,
            tools: vec![],
            tool_choice: None,
            text: None,
            reasoning: None,
            truncation: None,
            temperature: None,
            max_output_tokens: None,
            metadata: HashMap::new(),
            incomplete_details: None,
            extra: HashMap::new(),
        };

        assert!(resp.has_function_calls());
        assert_eq!(resp.function_calls().len(), 2);
        assert_eq!(resp.function_calls()[0].name, "search");
    }

    #[test]
    fn response_status_serde() {
        let status = ResponseStatus::InProgress;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"in_progress\"");
    }
}
