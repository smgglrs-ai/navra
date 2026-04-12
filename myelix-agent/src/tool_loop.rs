//! Agentic tool-use loop (ReAct pattern).
//!
//! Discover tools → call model → execute tool calls → feed results back
//! → repeat until the model stops or max iterations reached.

use crate::client::McpClient;
use crate::error::AgentError;
use myelix_model::{
    ChatMessage, ChatRequest, ChatResponse, FinishReason, ModelBackend, ToolChoice,
};
use myelix_protocol::label::DataLabel;
use myelix_protocol::{CallToolResult, Content};

/// Configuration for the tool-use loop.
pub struct ToolLoopConfig {
    /// Maximum number of model→tool round-trips (default: 10).
    pub max_iterations: usize,
    /// System prompt prepended to all conversations.
    pub system_prompt: Option<String>,
    /// Temperature for model chat calls.
    pub temperature: Option<f32>,
    /// Max tokens per model response.
    pub max_tokens: Option<u32>,
}

impl Default for ToolLoopConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10,
            system_prompt: None,
            temperature: None,
            max_tokens: None,
        }
    }
}

/// Result of a completed tool-use loop.
#[derive(Debug)]
pub struct ToolLoopResult {
    /// Final assistant message text.
    pub response: String,
    /// Number of tool-call iterations executed.
    pub iterations: usize,
    /// Total prompt tokens consumed.
    pub prompt_tokens: u32,
    /// Total completion tokens consumed.
    pub completion_tokens: u32,
    /// Final taint level of the session.
    pub taint: DataLabel,
}

/// Extract text content from a [`CallToolResult`].
pub fn extract_text(result: &CallToolResult) -> String {
    let mut parts = Vec::new();
    if result.is_error {
        parts.push("Error: ".to_string());
    }
    for content in &result.content {
        match content {
            Content::Text(tc) => parts.push(tc.text.clone()),
        }
    }
    parts.join("")
}

/// Execute the agentic tool-use loop.
///
/// 1. Discover tools from `client`, convert to [`ChatToolDefinition`]
/// 2. Build initial messages (system + user prompt)
/// 3. Loop: call `model.chat()` → if `FinishReason::ToolCalls`, execute
///    each tool via `client`, feed results back as tool result messages
/// 4. Stop on `FinishReason::Stop`, `FinishReason::Length`, or max iterations
pub async fn run_tool_loop(
    model: &dyn ModelBackend,
    client: &mut McpClient,
    user_prompt: &str,
    config: &ToolLoopConfig,
) -> Result<ToolLoopResult, AgentError> {
    let tools = client.chat_tools().await?;

    let mut messages = Vec::new();
    if let Some(system) = &config.system_prompt {
        messages.push(ChatMessage::system(system));
    }
    messages.push(ChatMessage::user(user_prompt));

    let mut total_prompt = 0u32;
    let mut total_completion = 0u32;

    for iteration in 0..config.max_iterations {
        let request = ChatRequest {
            messages: messages.clone(),
            max_tokens: config.max_tokens,
            temperature: config.temperature,
            tools: tools.clone(),
            tool_choice: Some(ToolChoice::Auto),
        };

        let response: ChatResponse = model.chat(&request).await?;

        total_prompt += response.prompt_tokens.unwrap_or(0);
        total_completion += response.completion_tokens.unwrap_or(0);

        match response.finish_reason {
            FinishReason::Stop | FinishReason::Length => {
                return Ok(ToolLoopResult {
                    response: response.message.content.unwrap_or_default(),
                    iterations: iteration,
                    prompt_tokens: total_prompt,
                    completion_tokens: total_completion,
                    taint: client.taint(),
                });
            }
            FinishReason::ToolCalls => {
                let tool_calls = response.message.tool_calls.clone();
                messages.push(ChatMessage::assistant_tool_calls(tool_calls.clone()));

                for tc in &tool_calls {
                    let args: serde_json::Value =
                        serde_json::from_str(&tc.function.arguments)
                            .unwrap_or(serde_json::json!({}));

                    tracing::debug!(
                        tool = %tc.function.name,
                        args = %args,
                        "executing tool call"
                    );

                    let result = client.call_tool(&tc.function.name, args).await?;
                    let text = extract_text(&result);
                    messages.push(ChatMessage::tool_result(&tc.id, text));
                }
            }
        }
    }

    Err(AgentError::MaxIterations(config.max_iterations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use myelix_model::{
        ChatRequest, ChatResponse, FinishReason, FunctionCall, ModelBackend, ModelError, ToolCall,
    };
    use myelix_protocol::upstream::{Transport, UpstreamError};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    /// Mock model that returns a sequence of scripted responses.
    struct MockModel {
        responses: Mutex<Vec<ChatResponse>>,
    }

    impl MockModel {
        fn new(responses: Vec<ChatResponse>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }
    }

    impl ModelBackend for MockModel {
        fn chat(
            &self,
            _req: &ChatRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ChatResponse, ModelError>> + Send + '_>> {
            let response = {
                let mut responses = self.responses.lock().unwrap();
                if responses.is_empty() {
                    return Box::pin(async {
                        Err(ModelError::Inference("no more responses".into()))
                    });
                }
                responses.remove(0)
            };
            Box::pin(async move { Ok(response) })
        }
    }

    /// Mock transport for tests.
    struct MockTransport {
        responses: Mutex<Vec<serde_json::Value>>,
    }

    impl MockTransport {
        fn new(responses: Vec<serde_json::Value>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn request(
            &mut self,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, UpstreamError> {
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Ok(serde_json::json!({"jsonrpc": "2.0", "result": {}, "id": 1}))
            } else {
                Ok(responses.remove(0))
            }
        }

        fn shutdown(&mut self) {}
    }

    async fn mock_client(tool_responses: Vec<serde_json::Value>) -> McpClient {
        let mut all = vec![
            // initialize
            serde_json::json!({
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "serverInfo": {"name": "test", "version": "0.1.0"}
                },
                "id": 1
            }),
            // notifications/initialized
            serde_json::json!({"jsonrpc": "2.0", "result": {}, "id": 2}),
            // list_tools response (empty)
            serde_json::json!({
                "jsonrpc": "2.0",
                "result": {"tools": []},
                "id": 3
            }),
        ];
        all.extend(tool_responses);
        let transport = MockTransport::new(all);
        let upstream = myelix_protocol::Upstream::connect("test", transport)
            .await
            .unwrap();
        McpClient::new(upstream)
    }

    fn stop_response(text: &str) -> ChatResponse {
        ChatResponse {
            message: ChatMessage::assistant(text),
            finish_reason: FinishReason::Stop,
            prompt_tokens: Some(10),
            completion_tokens: Some(5),
        }
    }

    fn tool_call_response(tool_name: &str, args: &str) -> ChatResponse {
        ChatResponse {
            message: ChatMessage::assistant_tool_calls(vec![ToolCall {
                id: "call_1".to_string(),
                call_type: "function".to_string(),
                function: FunctionCall {
                    name: tool_name.to_string(),
                    arguments: args.to_string(),
                },
            }]),
            finish_reason: FinishReason::ToolCalls,
            prompt_tokens: Some(10),
            completion_tokens: Some(5),
        }
    }

    #[tokio::test]
    async fn immediate_stop() {
        let model = MockModel::new(vec![stop_response("Hello!")]);
        let mut client = mock_client(vec![]).await;
        let config = ToolLoopConfig::default();

        let result = run_tool_loop(&model, &mut client, "Hi", &config)
            .await
            .unwrap();
        assert_eq!(result.response, "Hello!");
        assert_eq!(result.iterations, 0);
        assert_eq!(result.prompt_tokens, 10);
        assert_eq!(result.completion_tokens, 5);
    }

    #[tokio::test]
    async fn one_tool_call_then_stop() {
        let model = MockModel::new(vec![
            tool_call_response("git_status", "{}"),
            stop_response("Status is clean."),
        ]);
        let mut client = mock_client(vec![serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": "nothing to commit"}],
                "isError": false
            },
            "id": 4
        })])
        .await;
        let config = ToolLoopConfig::default();

        let result = run_tool_loop(&model, &mut client, "What's the git status?", &config)
            .await
            .unwrap();
        assert_eq!(result.response, "Status is clean.");
        assert_eq!(result.iterations, 1);
        assert_eq!(result.prompt_tokens, 20);
        assert_eq!(result.completion_tokens, 10);
    }

    #[tokio::test]
    async fn max_iterations_error() {
        // Model always returns tool calls, never stops
        let model = MockModel::new(vec![
            tool_call_response("git_status", "{}"),
            tool_call_response("git_status", "{}"),
            tool_call_response("git_status", "{}"),
        ]);

        let tool_result = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": "ok"}],
                "isError": false
            },
            "id": 4
        });
        let mut client =
            mock_client(vec![tool_result.clone(), tool_result.clone(), tool_result]).await;
        let config = ToolLoopConfig {
            max_iterations: 3,
            ..Default::default()
        };

        let err = run_tool_loop(&model, &mut client, "loop forever", &config)
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::MaxIterations(3)));
    }

    #[test]
    fn extract_text_from_result() {
        let result = CallToolResult::success(vec![
            myelix_protocol::Content::text("line 1"),
            myelix_protocol::Content::text("line 2"),
        ]);
        assert_eq!(extract_text(&result), "line 1line 2");
    }

    #[test]
    fn extract_text_from_error_result() {
        let result = CallToolResult::error("something failed");
        assert_eq!(extract_text(&result), "Error: something failed");
    }
}
