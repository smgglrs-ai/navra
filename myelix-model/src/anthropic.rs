//! Anthropic Messages API backend for Claude models.
//!
//! Connects to the Anthropic API directly or via Vertex AI.
//! Supports chat completion with tool use and streaming.

use crate::chat::{
    ChatChunk, ChatMessage, ChatRequest, ChatResponse, ChatRole, ChatUsage, FinishReason,
    FunctionCall, ToolCall, ToolCallDelta, ToolChoice,
};
use crate::{GenerateRequest, GenerateResponse, Locality, ModelBackend, ModelError};
use futures_util::StreamExt;

/// Anthropic Messages API version.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Default max tokens if not specified in the request.
const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Anthropic backend using the Messages API.
pub struct AnthropicBackend {
    client: reqwest::Client,
    base_url: String,
    model: String,
    api_key: Option<String>,
    locality: Locality,
    is_vertex: bool,
}

impl AnthropicBackend {
    /// Create a new Anthropic backend.
    ///
    /// Auto-detects Vertex AI from the base URL (contains "googleapis.com").
    pub fn new(
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: Option<String>,
        locality: Locality,
    ) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let is_vertex = base_url.contains("googleapis.com");
        Self {
            client: reqwest::Client::new(),
            base_url,
            model: model.into(),
            api_key,
            locality,
            is_vertex,
        }
    }

    /// Returns the locality of this backend.
    pub fn locality(&self) -> &Locality {
        &self.locality
    }

    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let req = if self.is_vertex {
            // Vertex AI uses Bearer token
            if let Some(ref key) = self.api_key {
                req.header("Authorization", format!("Bearer {key}"))
            } else {
                req
            }
        } else {
            // Direct Anthropic API uses x-api-key
            if let Some(ref key) = self.api_key {
                req.header("x-api-key", key)
            } else {
                req
            }
        };
        req.header("anthropic-version", ANTHROPIC_VERSION)
    }

    fn messages_url(&self) -> String {
        if self.is_vertex {
            // Vertex AI: the base URL IS the full endpoint (rawPredict)
            self.base_url.clone()
        } else {
            format!("{}/v1/messages", self.base_url)
        }
    }

    /// Build the Messages API request body.
    fn build_body(&self, request: &ChatRequest, stream: bool) -> serde_json::Value {
        // Extract system prompt from messages (Anthropic uses top-level field)
        let mut system_text: Option<String> = None;
        let messages: Vec<serde_json::Value> = request
            .messages
            .iter()
            .filter_map(|msg| {
                if msg.role == ChatRole::System {
                    system_text = msg.content.clone();
                    None
                } else {
                    Some(serialize_message(msg))
                }
            })
            .collect();

        // Merge consecutive tool_result messages into the preceding user message
        let messages = merge_tool_results(messages);

        let max_tokens = request.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS);

        let mut body = serde_json::json!({
            "model": &self.model,
            "max_tokens": max_tokens,
            "messages": messages,
        });

        if self.is_vertex {
            // Vertex AI: model is in the URL, not the body; version is required in body
            body.as_object_mut().unwrap().remove("model");
            body["anthropic_version"] = serde_json::json!("vertex-2023-10-16");
        }

        if let Some(ref system) = system_text {
            body["system"] = serde_json::json!(system);
        }

        if let Some(temperature) = request.temperature {
            body["temperature"] = serde_json::json!(temperature);
        }

        if !request.tools.is_empty() {
            let tools: Vec<serde_json::Value> = request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.parameters,
                    })
                })
                .collect();
            body["tools"] = serde_json::json!(tools);

            if let Some(ref choice) = request.tool_choice {
                body["tool_choice"] = match choice {
                    ToolChoice::Auto => serde_json::json!({"type": "auto"}),
                    ToolChoice::None => serde_json::json!({"type": "none"}),
                    ToolChoice::Required => serde_json::json!({"type": "any"}),
                };
            }
        }

        if stream {
            body["stream"] = serde_json::json!(true);
        }

        body
    }

    /// Parse a non-streaming Messages API response.
    fn parse_response(json: &serde_json::Value) -> Result<ChatResponse, ModelError> {
        let content_blocks = json["content"]
            .as_array()
            .ok_or_else(|| ModelError::Api("missing content array".into()))?;

        let mut text_parts = Vec::new();
        let mut tool_calls = Vec::new();

        for block in content_blocks {
            match block["type"].as_str() {
                Some("text") => {
                    if let Some(text) = block["text"].as_str() {
                        text_parts.push(text.to_string());
                    }
                }
                Some("tool_use") => {
                    if let (Some(id), Some(name)) =
                        (block["id"].as_str(), block["name"].as_str())
                    {
                        let input = &block["input"];
                        tool_calls.push(ToolCall {
                            id: id.to_string(),
                            call_type: "function".to_string(),
                            function: FunctionCall {
                                name: name.to_string(),
                                arguments: serde_json::to_string(input)
                                    .unwrap_or_else(|_| "{}".to_string()),
                            },
                        });
                    }
                }
                _ => {}
            }
        }

        let content = if text_parts.is_empty() {
            None
        } else {
            Some(text_parts.join(""))
        };

        let stop_reason = json["stop_reason"]
            .as_str()
            .map(anthropic_stop_reason)
            .unwrap_or(FinishReason::Stop);

        let prompt_tokens = json["usage"]["input_tokens"].as_u64().map(|v| v as u32);
        let completion_tokens = json["usage"]["output_tokens"].as_u64().map(|v| v as u32);

        Ok(ChatResponse {
            message: ChatMessage {
                role: ChatRole::Assistant,
                content,
                images: Vec::new(),
                tool_calls,
                tool_call_id: None,
            },
            finish_reason: stop_reason,
            prompt_tokens,
            completion_tokens,
        })
    }
}

impl ModelBackend for AnthropicBackend {
    fn generate(
        &self,
        request: &GenerateRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<GenerateResponse, ModelError>> + Send + '_>,
    > {
        let chat_request = ChatRequest {
            messages: {
                let mut msgs = Vec::new();
                if let Some(ref system) = request.system {
                    msgs.push(ChatMessage::system(system));
                }
                msgs.push(ChatMessage::user(&request.prompt));
                msgs
            },
            max_tokens: request.max_tokens,
            temperature: request.temperature,
            tools: Vec::new(),
            tool_choice: None,
        };

        let url = self.messages_url();
        let body = self.build_body(&chat_request, false);
        let req = self.apply_auth(self.client.post(&url).json(&body));

        Box::pin(async move {
            let resp = req
                .send()
                .await
                .map_err(|e| ModelError::Api(format!("request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(ModelError::Api(format!("HTTP {status}: {text}")));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ModelError::Api(format!("invalid response: {e}")))?;

            let chat_resp = Self::parse_response(&json)?;

            Ok(GenerateResponse {
                text: chat_resp.message.content.unwrap_or_default(),
                prompt_tokens: chat_resp.prompt_tokens,
                completion_tokens: chat_resp.completion_tokens,
            })
        })
    }

    fn respond(
        &self,
        request: &crate::CreateResponseRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<crate::ModelResponse, ModelError>> + Send + '_>,
    > {
        let chat_req = crate::responses_to_chat(request);
        let url = self.messages_url();
        let body = self.build_body(&chat_req, false);
        let model_name = self.model.clone();

        Box::pin(async move {
            let resp = crate::http_common::send_with_retry(|| {
                self.apply_auth(self.client.post(&url).json(&body))
            })
            .await?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(ModelError::Api(format!("HTTP {status}: {text}")));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ModelError::Api(format!("invalid response: {e}")))?;

            let chat_resp = Self::parse_response(&json)?;
            Ok(crate::chat_to_responses(&model_name, &chat_resp))
        })
    }
}

// --- Anthropic message serialization ---

/// Serialize a ChatMessage into the Anthropic messages format.
///
/// System messages are filtered out by the caller (extracted as top-level field).
fn serialize_message(msg: &ChatMessage) -> serde_json::Value {
    match msg.role {
        ChatRole::System => {
            // Should not reach here — filtered by build_body
            serde_json::json!({"role": "user", "content": [{"type": "text", "text": msg.content.as_deref().unwrap_or("")}]})
        }
        ChatRole::User if msg.images.is_empty() => {
            serde_json::json!({
                "role": "user",
                "content": [{"type": "text", "text": msg.content.as_deref().unwrap_or("")}]
            })
        }
        ChatRole::User => {
            let mut parts = vec![
                serde_json::json!({"type": "text", "text": msg.content.as_deref().unwrap_or("")}),
            ];
            for image in &msg.images {
                parts.push(serde_json::json!({
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": image.mime_type,
                        "data": image.data,
                    }
                }));
            }
            serde_json::json!({"role": "user", "content": parts})
        }
        ChatRole::Assistant if msg.tool_calls.is_empty() => {
            serde_json::json!({
                "role": "assistant",
                "content": [{"type": "text", "text": msg.content.as_deref().unwrap_or("")}]
            })
        }
        ChatRole::Assistant => {
            let mut content: Vec<serde_json::Value> = Vec::new();
            if let Some(ref text) = msg.content {
                if !text.is_empty() {
                    content.push(serde_json::json!({"type": "text", "text": text}));
                }
            }
            for tc in &msg.tool_calls {
                let input: serde_json::Value =
                    serde_json::from_str(&tc.function.arguments).unwrap_or(serde_json::json!({}));
                content.push(serde_json::json!({
                    "type": "tool_use",
                    "id": tc.id,
                    "name": tc.function.name,
                    "input": input,
                }));
            }
            serde_json::json!({"role": "assistant", "content": content})
        }
        ChatRole::Tool => {
            // Anthropic: tool results are sent as user messages with tool_result blocks.
            // These get merged with adjacent tool results by merge_tool_results().
            serde_json::json!({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": msg.tool_call_id.as_deref().unwrap_or(""),
                    "content": msg.content.as_deref().unwrap_or(""),
                }]
            })
        }
    }
}

/// Merge consecutive user messages (tool results) into a single user message.
///
/// The Anthropic API requires alternating user/assistant roles. Multiple
/// tool results from a single assistant turn must be combined into one
/// user message with multiple tool_result content blocks.
fn merge_tool_results(messages: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    let mut merged: Vec<serde_json::Value> = Vec::new();
    for msg in messages {
        let role = msg["role"].as_str().unwrap_or("");
        if role == "user" {
            if let Some(last) = merged.last_mut() {
                let last_role = last["role"].as_str().unwrap_or("");
                if last_role == "user" {
                    // Merge content arrays
                    if let Some(new_content) = msg["content"].as_array() {
                        if let Some(last_content) = last["content"].as_array_mut() {
                            for item in new_content {
                                last_content.push(item.clone());
                            }
                            continue;
                        }
                    }
                }
            }
        }
        merged.push(msg);
    }
    merged
}

/// Map Anthropic stop_reason to FinishReason.
fn anthropic_stop_reason(reason: &str) -> FinishReason {
    match reason {
        "end_turn" => FinishReason::Stop,
        "max_tokens" => FinishReason::Length,
        "tool_use" => FinishReason::ToolCalls,
        _ => FinishReason::Stop,
    }
}

/// Parse an Anthropic SSE event into a ChatChunk.
///
/// Returns `Ok(None)` for events that don't produce a chunk.
fn parse_anthropic_stream_event(
    json_str: &str,
    prompt_tokens: &mut Option<u32>,
) -> Result<Option<ChatChunk>, ModelError> {
    let json: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| ModelError::Api(format!("invalid stream event: {e}")))?;

    match json["type"].as_str() {
        Some("message_start") => {
            *prompt_tokens = json["message"]["usage"]["input_tokens"]
                .as_u64()
                .map(|v| v as u32);
            Ok(None)
        }
        Some("content_block_start") => {
            let block = &json["content_block"];
            let index = json["index"].as_u64().unwrap_or(0) as usize;
            if block["type"].as_str() == Some("tool_use") {
                Ok(Some(ChatChunk {
                    delta_content: None,
                    delta_tool_calls: vec![ToolCallDelta {
                        index,
                        id: block["id"].as_str().map(String::from),
                        function_name: block["name"].as_str().map(String::from),
                        arguments_delta: None,
                    }],
                    finish_reason: None,
                    usage: None,
                }))
            } else {
                Ok(None)
            }
        }
        Some("content_block_delta") => {
            let delta = &json["delta"];
            let index = json["index"].as_u64().unwrap_or(0) as usize;
            match delta["type"].as_str() {
                Some("text_delta") => Ok(Some(ChatChunk {
                    delta_content: delta["text"].as_str().map(String::from),
                    delta_tool_calls: Vec::new(),
                    finish_reason: None,
                    usage: None,
                })),
                Some("input_json_delta") => Ok(Some(ChatChunk {
                    delta_content: None,
                    delta_tool_calls: vec![ToolCallDelta {
                        index,
                        id: None,
                        function_name: None,
                        arguments_delta: delta["partial_json"].as_str().map(String::from),
                    }],
                    finish_reason: None,
                    usage: None,
                })),
                _ => Ok(None),
            }
        }
        Some("message_delta") => {
            let stop_reason = json["delta"]["stop_reason"]
                .as_str()
                .map(anthropic_stop_reason);
            let output_tokens = json["usage"]["output_tokens"].as_u64().map(|v| v as u32);
            let usage = output_tokens.map(|completion| ChatUsage {
                prompt_tokens: prompt_tokens.unwrap_or(0),
                completion_tokens: completion,
            });
            Ok(Some(ChatChunk {
                delta_content: None,
                delta_tool_calls: Vec::new(),
                finish_reason: stop_reason,
                usage,
            }))
        }
        Some("message_stop") | Some("ping") => Ok(None),
        Some(other) => {
            tracing::debug!(event_type = %other, "Unknown Anthropic stream event");
            Ok(None)
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::ChatToolDefinition;

    #[test]
    fn serialize_user_message() {
        let msg = ChatMessage::user("Hello");
        let json = serialize_message(&msg);
        assert_eq!(json["role"], "user");
        assert_eq!(json["content"][0]["type"], "text");
        assert_eq!(json["content"][0]["text"], "Hello");
    }

    #[test]
    fn serialize_assistant_text() {
        let msg = ChatMessage::assistant("Hi there");
        let json = serialize_message(&msg);
        assert_eq!(json["role"], "assistant");
        assert_eq!(json["content"][0]["type"], "text");
        assert_eq!(json["content"][0]["text"], "Hi there");
    }

    #[test]
    fn serialize_assistant_tool_calls() {
        let msg = ChatMessage::assistant_tool_calls(vec![ToolCall {
            id: "toolu_123".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "get_weather".to_string(),
                arguments: r#"{"city":"Paris"}"#.to_string(),
            },
        }]);
        let json = serialize_message(&msg);
        assert_eq!(json["role"], "assistant");
        assert_eq!(json["content"][0]["type"], "tool_use");
        assert_eq!(json["content"][0]["id"], "toolu_123");
        assert_eq!(json["content"][0]["name"], "get_weather");
        assert_eq!(json["content"][0]["input"]["city"], "Paris");
    }

    #[test]
    fn serialize_tool_result() {
        let msg = ChatMessage::tool_result("toolu_123", "22°C sunny");
        let json = serialize_message(&msg);
        assert_eq!(json["role"], "user");
        assert_eq!(json["content"][0]["type"], "tool_result");
        assert_eq!(json["content"][0]["tool_use_id"], "toolu_123");
        assert_eq!(json["content"][0]["content"], "22°C sunny");
    }

    #[test]
    fn merge_consecutive_tool_results() {
        let messages = vec![
            serde_json::json!({
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "1", "name": "a", "input": {}}]
            }),
            serde_json::json!({
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "1", "content": "result1"}]
            }),
            serde_json::json!({
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "2", "content": "result2"}]
            }),
        ];
        let merged = merge_tool_results(messages);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[1]["content"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn build_body_with_system_prompt() {
        let backend = AnthropicBackend::new(
            "https://api.anthropic.com",
            "claude-sonnet-4-20250514",
            None,
            Locality::Remote,
        );
        let request = ChatRequest {
            messages: vec![
                ChatMessage::system("Be helpful."),
                ChatMessage::user("Hello"),
            ],
            max_tokens: Some(1024),
            temperature: None,
            tools: Vec::new(),
            tool_choice: None,
        };
        let body = backend.build_body(&request, false);
        assert_eq!(body["system"], "Be helpful.");
        assert_eq!(body["max_tokens"], 1024);
        // System message should not appear in messages array
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
    }

    #[test]
    fn build_body_with_tools() {
        let backend = AnthropicBackend::new(
            "https://api.anthropic.com",
            "claude-sonnet-4-20250514",
            None,
            Locality::Remote,
        );
        let request = ChatRequest {
            messages: vec![ChatMessage::user("What's the weather?")],
            max_tokens: Some(1024),
            temperature: None,
            tools: vec![ChatToolDefinition {
                name: "get_weather".to_string(),
                description: "Get weather info".to_string(),
                parameters: serde_json::json!({"type": "object", "properties": {"city": {"type": "string"}}}),
            }],
            tool_choice: Some(ToolChoice::Auto),
        };
        let body = backend.build_body(&request, false);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "get_weather");
        assert_eq!(tools[0]["input_schema"]["type"], "object");
        assert_eq!(body["tool_choice"]["type"], "auto");
    }

    #[test]
    fn parse_text_response() {
        let json = serde_json::json!({
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello!"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        });
        let resp = AnthropicBackend::parse_response(&json).unwrap();
        assert_eq!(resp.message.content.unwrap(), "Hello!");
        assert_eq!(resp.finish_reason, FinishReason::Stop);
        assert_eq!(resp.prompt_tokens, Some(10));
        assert_eq!(resp.completion_tokens, Some(5));
    }

    #[test]
    fn parse_tool_use_response() {
        let json = serde_json::json!({
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Let me check the weather."},
                {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Paris"}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 20, "output_tokens": 15}
        });
        let resp = AnthropicBackend::parse_response(&json).unwrap();
        assert_eq!(resp.message.content.unwrap(), "Let me check the weather.");
        assert_eq!(resp.finish_reason, FinishReason::ToolCalls);
        assert_eq!(resp.message.tool_calls.len(), 1);
        assert_eq!(resp.message.tool_calls[0].id, "toolu_1");
        assert_eq!(resp.message.tool_calls[0].function.name, "get_weather");
        assert_eq!(resp.message.tool_calls[0].function.arguments, r#"{"city":"Paris"}"#);
    }

    #[test]
    fn stop_reason_mapping() {
        assert_eq!(anthropic_stop_reason("end_turn"), FinishReason::Stop);
        assert_eq!(anthropic_stop_reason("max_tokens"), FinishReason::Length);
        assert_eq!(anthropic_stop_reason("tool_use"), FinishReason::ToolCalls);
        assert_eq!(anthropic_stop_reason("unknown"), FinishReason::Stop);
    }

    #[test]
    fn parse_stream_text_delta() {
        let mut prompt_tokens = None;
        let event = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#;
        let chunk = parse_anthropic_stream_event(event, &mut prompt_tokens)
            .unwrap()
            .unwrap();
        assert_eq!(chunk.delta_content.unwrap(), "Hello");
        assert!(chunk.delta_tool_calls.is_empty());
    }

    #[test]
    fn parse_stream_tool_start() {
        let mut prompt_tokens = None;
        let event = r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather"}}"#;
        let chunk = parse_anthropic_stream_event(event, &mut prompt_tokens)
            .unwrap()
            .unwrap();
        assert!(chunk.delta_content.is_none());
        assert_eq!(chunk.delta_tool_calls.len(), 1);
        assert_eq!(chunk.delta_tool_calls[0].id.as_deref(), Some("toolu_1"));
        assert_eq!(
            chunk.delta_tool_calls[0].function_name.as_deref(),
            Some("get_weather")
        );
    }

    #[test]
    fn parse_stream_input_json_delta() {
        let mut prompt_tokens = None;
        let event = r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"city\":"}}"#;
        let chunk = parse_anthropic_stream_event(event, &mut prompt_tokens)
            .unwrap()
            .unwrap();
        assert!(chunk.delta_content.is_none());
        assert_eq!(chunk.delta_tool_calls.len(), 1);
        assert_eq!(
            chunk.delta_tool_calls[0].arguments_delta.as_deref(),
            Some("{\"city\":")
        );
    }

    #[test]
    fn parse_stream_message_delta() {
        let mut prompt_tokens = Some(10);
        let event = r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":50}}"#;
        let chunk = parse_anthropic_stream_event(event, &mut prompt_tokens)
            .unwrap()
            .unwrap();
        assert_eq!(chunk.finish_reason, Some(FinishReason::Stop));
        let usage = chunk.usage.unwrap();
        assert_eq!(usage.prompt_tokens, 10);
        assert_eq!(usage.completion_tokens, 50);
    }

    #[test]
    fn parse_stream_message_start_captures_prompt_tokens() {
        let mut prompt_tokens = None;
        let event = r#"{"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":42}}}"#;
        let result = parse_anthropic_stream_event(event, &mut prompt_tokens).unwrap();
        assert!(result.is_none()); // No chunk emitted
        assert_eq!(prompt_tokens, Some(42));
    }

    #[test]
    fn auto_detect_vertex() {
        let vertex = AnthropicBackend::new(
            "https://us-central1-aiplatform.googleapis.com/v1/projects/my-proj/locations/us-central1/publishers/anthropic/models/claude-sonnet-4-20250514:rawPredict",
            "claude-sonnet-4-20250514",
            None,
            Locality::Remote,
        );
        assert!(vertex.is_vertex);

        let direct = AnthropicBackend::new(
            "https://api.anthropic.com",
            "claude-sonnet-4-20250514",
            None,
            Locality::Remote,
        );
        assert!(!direct.is_vertex);
    }

    #[test]
    fn default_max_tokens_applied() {
        let backend = AnthropicBackend::new(
            "https://api.anthropic.com",
            "claude-sonnet-4-20250514",
            None,
            Locality::Remote,
        );
        let request = ChatRequest {
            messages: vec![ChatMessage::user("Hi")],
            max_tokens: None,
            temperature: None,
            tools: Vec::new(),
            tool_choice: None,
        };
        let body = backend.build_body(&request, false);
        assert_eq!(body["max_tokens"], DEFAULT_MAX_TOKENS);
    }
}
