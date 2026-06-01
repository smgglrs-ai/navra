//! Chat completion types with tool use support.
//!
//! Provides the types for multi-turn conversation with tool calling,
//! compatible with the OpenAI chat completions API. These types are
//! backend-agnostic — any OpenAI-compatible API (vLLM, ollama, etc.)
//! can be used.

use crate::{ImageInput, ModelError};
use serde::{Deserialize, Serialize};

// --- Message types ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: Option<String>,
    pub images: Vec<ImageInput>,
    pub tool_calls: Vec<ToolCall>,
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::System,
            content: Some(content.into()),
            images: Vec::new(),
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::User,
            content: Some(content.into()),
            images: Vec::new(),
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: Some(content.into()),
            images: Vec::new(),
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }

    pub fn assistant_tool_calls(tool_calls: Vec<ToolCall>) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: None,
            images: Vec::new(),
            tool_calls,
            tool_call_id: None,
        }
    }

    pub fn tool_result(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::Tool,
            content: Some(content.into()),
            images: Vec::new(),
            tool_calls: Vec::new(),
            tool_call_id: Some(tool_call_id.into()),
        }
    }
}

// --- Tool types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type", default = "default_function_type")]
    pub call_type: String,
    pub function: FunctionCall,
}

fn default_function_type() -> String {
    "function".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone)]
pub struct ChatToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone)]
pub enum ToolChoice {
    Auto,
    None,
    Required,
}

// --- Request ---

#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub messages: Vec<ChatMessage>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub tools: Vec<ChatToolDefinition>,
    pub tool_choice: Option<ToolChoice>,
    /// JSON schema for structured output (Ollama `format` field).
    pub response_format: Option<serde_json::Value>,
}

// --- Response (non-streaming) ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
}

impl FinishReason {
    pub fn from_str(s: &str) -> Self {
        match s {
            "stop" => Self::Stop,
            "length" => Self::Length,
            "tool_calls" => Self::ToolCalls,
            _ => Self::Stop,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChatResponse {
    pub message: ChatMessage,
    pub finish_reason: FinishReason,
    pub prompt_tokens: Option<u32>,
    pub completion_tokens: Option<u32>,
}

// --- Streaming ---

#[derive(Debug, Clone)]
pub struct ChatChunk {
    pub delta_content: Option<String>,
    pub delta_tool_calls: Vec<ToolCallDelta>,
    pub finish_reason: Option<FinishReason>,
    pub usage: Option<ChatUsage>,
}

#[derive(Debug, Clone)]
pub struct ToolCallDelta {
    pub index: usize,
    pub id: Option<String>,
    pub function_name: Option<String>,
    pub arguments_delta: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChatUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

/// Parse a single SSE data chunk from a streaming chat completion response.
pub fn parse_stream_chunk(json_str: &str) -> Result<ChatChunk, ModelError> {
    let json: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| ModelError::Api(format!("invalid stream chunk: {e}")))?;

    let choice = &json["choices"][0];

    let delta_content = choice["delta"]["content"].as_str().map(String::from);

    let delta_tool_calls = choice["delta"]["tool_calls"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|tc| ToolCallDelta {
                    index: tc["index"].as_u64().unwrap_or(0) as usize,
                    id: tc["id"].as_str().map(String::from),
                    function_name: tc["function"]["name"].as_str().map(String::from),
                    arguments_delta: tc["function"]["arguments"].as_str().map(String::from),
                })
                .collect()
        })
        .unwrap_or_default();

    let finish_reason = choice["finish_reason"].as_str().map(FinishReason::from_str);

    let usage = json.get("usage").and_then(|u| {
        let pt = u["prompt_tokens"].as_u64()?;
        let ct = u["completion_tokens"].as_u64()?;
        Some(ChatUsage {
            prompt_tokens: pt as u32,
            completion_tokens: ct as u32,
        })
    });

    Ok(ChatChunk {
        delta_content,
        delta_tool_calls,
        finish_reason,
        usage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_chunk_content() {
        let json = r#"{"choices":[{"delta":{"content":"Hello"},"index":0}]}"#;
        let chunk = parse_stream_chunk(json).unwrap();
        assert_eq!(chunk.delta_content, Some("Hello".to_string()));
        assert!(chunk.delta_tool_calls.is_empty());
        assert!(chunk.finish_reason.is_none());
    }

    #[test]
    fn parse_chunk_tool_call_start() {
        let json = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"get_weather","arguments":""}}]},"index":0}]}"#;
        let chunk = parse_stream_chunk(json).unwrap();
        assert!(chunk.delta_content.is_none());
        assert_eq!(chunk.delta_tool_calls.len(), 1);
        assert_eq!(chunk.delta_tool_calls[0].index, 0);
        assert_eq!(chunk.delta_tool_calls[0].id, Some("call_abc".to_string()));
        assert_eq!(
            chunk.delta_tool_calls[0].function_name,
            Some("get_weather".to_string())
        );
    }

    #[test]
    fn parse_chunk_tool_call_arguments() {
        let json = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"loc"}}]},"index":0}]}"#;
        let chunk = parse_stream_chunk(json).unwrap();
        assert_eq!(chunk.delta_tool_calls.len(), 1);
        assert_eq!(
            chunk.delta_tool_calls[0].arguments_delta,
            Some("{\"loc".to_string())
        );
        assert!(chunk.delta_tool_calls[0].id.is_none());
    }

    #[test]
    fn parse_chunk_finish_reason_stop() {
        let json = r#"{"choices":[{"delta":{},"finish_reason":"stop","index":0}]}"#;
        let chunk = parse_stream_chunk(json).unwrap();
        assert_eq!(chunk.finish_reason, Some(FinishReason::Stop));
    }

    #[test]
    fn parse_chunk_finish_reason_tool_calls() {
        let json = r#"{"choices":[{"delta":{},"finish_reason":"tool_calls","index":0}]}"#;
        let chunk = parse_stream_chunk(json).unwrap();
        assert_eq!(chunk.finish_reason, Some(FinishReason::ToolCalls));
    }

    #[test]
    fn parse_chunk_with_usage() {
        let json = r#"{"choices":[{"delta":{},"finish_reason":"stop","index":0}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
        let chunk = parse_stream_chunk(json).unwrap();
        let usage = chunk.usage.unwrap();
        assert_eq!(usage.prompt_tokens, 10);
        assert_eq!(usage.completion_tokens, 5);
    }

    #[test]
    fn parse_chunk_empty_delta() {
        let json = r#"{"choices":[{"delta":{"role":"assistant"},"index":0}]}"#;
        let chunk = parse_stream_chunk(json).unwrap();
        assert!(chunk.delta_content.is_none());
        assert!(chunk.delta_tool_calls.is_empty());
        assert!(chunk.finish_reason.is_none());
    }

    // --- ChatMessage constructors ---

    #[test]
    fn message_constructors() {
        let sys = ChatMessage::system("You are helpful");
        assert_eq!(sys.role, ChatRole::System);
        assert_eq!(sys.content, Some("You are helpful".to_string()));

        let user = ChatMessage::user("Hello");
        assert_eq!(user.role, ChatRole::User);

        let asst = ChatMessage::assistant("Hi there");
        assert_eq!(asst.role, ChatRole::Assistant);
        assert!(asst.tool_calls.is_empty());

        let tc = ChatMessage::assistant_tool_calls(vec![ToolCall {
            id: "call_1".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "get_weather".to_string(),
                arguments: "{}".to_string(),
            },
        }]);
        assert!(tc.content.is_none());
        assert_eq!(tc.tool_calls.len(), 1);

        let result = ChatMessage::tool_result("call_1", "sunny");
        assert_eq!(result.role, ChatRole::Tool);
        assert_eq!(result.tool_call_id, Some("call_1".to_string()));
    }
}
