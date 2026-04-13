//! Item types — the atomic unit of model I/O in Open Responses.
//!
//! Items are polymorphic, discriminated by the `type` field.
//! Input items are what you send; output items are what you get back.

use crate::content::{InputContent, OutputContent};
use serde::{Deserialize, Serialize};

// --- Status ---

/// Lifecycle status of an item or response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    InProgress,
    Completed,
    Incomplete,
}

/// Role of a message item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    User,
    Assistant,
    System,
    Developer,
}

// --- Input items (request) ---

/// An item in the request input array.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum InputItem {
    /// A message from user, system, developer, or assistant.
    #[serde(rename = "message")]
    Message(MessageItem),
    /// A function call (replaying a previous tool invocation).
    #[serde(rename = "function_call")]
    FunctionCall(FunctionCallItem),
    /// The output of a function call (tool result).
    #[serde(rename = "function_call_output")]
    FunctionCallOutput(FunctionCallOutputItem),
    /// A reasoning trace.
    #[serde(rename = "reasoning")]
    Reasoning(ReasoningItem),
    /// Reference to an item from a previous response.
    #[serde(rename = "item_reference")]
    ItemReference { id: String },
}

// --- Output items (response) ---

/// An item in the response output array.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum OutputItem {
    /// An assistant message.
    #[serde(rename = "message")]
    Message(MessageItem),
    /// A function call the model wants to make.
    #[serde(rename = "function_call")]
    FunctionCall(FunctionCallItem),
    /// A reasoning trace from the model.
    #[serde(rename = "reasoning")]
    Reasoning(ReasoningItem),
}

// --- Concrete item types ---

/// A message item (input or output).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub role: MessageRole,
    /// Input messages use InputContent; output messages use OutputContent.
    /// We use serde_json::Value here to handle both polymorphically.
    /// For typed access, use the helper methods.
    pub content: MessageContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ItemStatus>,
}

/// Message content — either input (user/system/developer) or output (assistant).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum MessageContent {
    /// Plain text shorthand (serializes as a string).
    Text(String),
    /// Structured input content parts.
    InputParts(Vec<InputContent>),
    /// Structured output content parts.
    OutputParts(Vec<OutputContent>),
}

/// A function call item (model requesting tool execution).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FunctionCallItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub call_id: String,
    pub name: String,
    pub arguments: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ItemStatus>,
}

/// A function call output item (tool execution result).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FunctionCallOutputItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub call_id: String,
    pub output: FunctionCallOutputContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ItemStatus>,
}

/// Content of a function call output — text or structured parts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum FunctionCallOutputContent {
    Text(String),
    Parts(Vec<InputContent>),
}

/// A reasoning item (chain-of-thought trace).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub summary: Vec<InputContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<InputContent>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ItemStatus>,
}

// --- Helpers ---

impl MessageItem {
    /// Create a user message with text content.
    pub fn user(text: impl Into<String>) -> Self {
        Self {
            id: None,
            role: MessageRole::User,
            content: MessageContent::Text(text.into()),
            status: None,
        }
    }

    /// Create a system message with text content.
    pub fn system(text: impl Into<String>) -> Self {
        Self {
            id: None,
            role: MessageRole::System,
            content: MessageContent::Text(text.into()),
            status: None,
        }
    }

    /// Create a developer message with text content.
    pub fn developer(text: impl Into<String>) -> Self {
        Self {
            id: None,
            role: MessageRole::Developer,
            content: MessageContent::Text(text.into()),
            status: None,
        }
    }

    /// Create an assistant message with text content.
    pub fn assistant(text: impl Into<String>) -> Self {
        Self {
            id: None,
            role: MessageRole::Assistant,
            content: MessageContent::OutputParts(vec![OutputContent::text(text)]),
            status: Some(ItemStatus::Completed),
        }
    }

    /// Extract all text from this message's content.
    pub fn text(&self) -> String {
        match &self.content {
            MessageContent::Text(s) => s.clone(),
            MessageContent::InputParts(parts) => parts
                .iter()
                .filter_map(|p| match p {
                    InputContent::Text(t) => Some(t.text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(""),
            MessageContent::OutputParts(parts) => parts
                .iter()
                .map(|p| p.as_text())
                .collect::<Vec<_>>()
                .join(""),
        }
    }
}

impl InputItem {
    /// Create a user message input item.
    pub fn user(text: impl Into<String>) -> Self {
        Self::Message(MessageItem::user(text))
    }

    /// Create a system message input item.
    pub fn system(text: impl Into<String>) -> Self {
        Self::Message(MessageItem::system(text))
    }

    /// Create a developer message input item.
    pub fn developer(text: impl Into<String>) -> Self {
        Self::Message(MessageItem::developer(text))
    }

    /// Create a function call output (tool result) input item.
    pub fn tool_result(call_id: impl Into<String>, output: impl Into<String>) -> Self {
        Self::FunctionCallOutput(FunctionCallOutputItem {
            id: None,
            call_id: call_id.into(),
            output: FunctionCallOutputContent::Text(output.into()),
            status: Some(ItemStatus::Completed),
        })
    }
}

impl OutputItem {
    /// Extract text from a message output item.
    pub fn text(&self) -> Option<String> {
        match self {
            Self::Message(m) => Some(m.text()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_message_roundtrip() {
        let item = InputItem::user("Hello");
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"type\":\"message\""));
        assert!(json.contains("\"role\":\"user\""));
        let parsed: InputItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, parsed);
    }

    #[test]
    fn function_call_roundtrip() {
        let item = OutputItem::FunctionCall(FunctionCallItem {
            id: Some("fc_1".into()),
            call_id: "call_abc".into(),
            name: "get_weather".into(),
            arguments: "{\"city\":\"Paris\"}".into(),
            status: Some(ItemStatus::Completed),
        });
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"type\":\"function_call\""));
        assert!(json.contains("\"call_id\":\"call_abc\""));
        let parsed: OutputItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, parsed);
    }

    #[test]
    fn tool_result_roundtrip() {
        let item = InputItem::tool_result("call_abc", "Sunny, 22°C");
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"type\":\"function_call_output\""));
        let parsed: InputItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, parsed);
    }

    #[test]
    fn reasoning_roundtrip() {
        let item = OutputItem::Reasoning(ReasoningItem {
            id: Some("r_1".into()),
            summary: vec![InputContent::text("I need to think about this")],
            content: None,
            encrypted_content: None,
            status: Some(ItemStatus::Completed),
        });
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"type\":\"reasoning\""));
        let parsed: OutputItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, parsed);
    }

    #[test]
    fn message_text_extraction() {
        let msg = MessageItem::user("hello world");
        assert_eq!(msg.text(), "hello world");

        let msg = MessageItem::assistant("response text");
        assert_eq!(msg.text(), "response text");
    }

    #[test]
    fn item_status_serde() {
        let status = ItemStatus::InProgress;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"in_progress\"");
    }
}
