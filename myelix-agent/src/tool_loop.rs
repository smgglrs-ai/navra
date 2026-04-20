//! Agentic tool-use loop (ReAct pattern) using Open Responses.
//!
//! Discover tools → call model.respond() → execute function calls →
//! feed results back → repeat until completion or max iterations.

use crate::client::McpClient;
use crate::error::AgentError;
use myelix_model::{
    CreateResponseRequest, FunctionCallItem, FunctionCallOutputItem, FunctionCallOutputContent,
    InputItem, ItemStatus, ModelBackend, ModelResponse, OutputItem, ResponseTool,
};
use myelix_protocol::label::DataLabel;
use myelix_protocol::{CallToolResult, Content};
use std::sync::Arc;
use std::time::Instant;

/// Callback trait for recording audit entries during the tool loop.
///
/// Implement this to capture tool calls and model calls without
/// introducing a dependency on `myelix-memory` or any specific
/// audit storage backend.
pub trait AuditCallback: Send + Sync {
    /// Called after each tool invocation completes.
    fn on_tool_call(
        &self,
        iteration: u32,
        tool_name: &str,
        args: &str,
        result: &str,
        duration_ms: u64,
    );

    /// Called after each model response is received.
    fn on_model_call(
        &self,
        iteration: u32,
        input_tokens: u32,
        output_tokens: u32,
        response_type: &str,
        reasoning: Option<&str>,
    );
}

/// Truncate a string to at most `max_bytes` bytes on a char boundary.
fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Configuration for the tool-use loop.
pub struct ToolLoopConfig {
    /// Maximum number of model→tool round-trips (default: 10).
    pub max_iterations: usize,
    /// System prompt prepended to all conversations.
    pub system_prompt: Option<String>,
    /// Temperature for model calls.
    pub temperature: Option<f32>,
    /// Max tokens per model response.
    pub max_tokens: Option<u32>,
    /// If set, only these tools are visible to the model.
    /// Tools not in this list are filtered out after discovery.
    /// The model cannot call tools it doesn't see.
    pub allowed_tools: Option<Vec<String>>,
    /// JSON schema for structured model output.
    /// When set, the model is constrained to produce output matching
    /// this schema (via ResponseFormat::JsonSchema). Defined by the
    /// persona, not the framework.
    pub output_json_schema: Option<serde_json::Value>,
    /// Tools that don't count toward the iteration limit when they
    /// are the only tools called in a round. Used for status-polling
    /// tools (e.g. `team_status`, `team_result`) that observe state
    /// without making progress.
    pub non_progress_tools: Option<Vec<String>>,
    /// Optional audit callback for recording tool and model calls.
    /// When set, the loop calls `on_tool_call` and `on_model_call`
    /// at the appropriate points. Does not introduce any dependency
    /// on a specific audit backend.
    pub audit: Option<Arc<dyn AuditCallback>>,
}

impl Default for ToolLoopConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10,
            system_prompt: None,
            temperature: None,
            max_tokens: None,
            allowed_tools: None,
            output_json_schema: None,
            non_progress_tools: None,
            audit: None,
        }
    }
}

/// Result of a completed tool-use loop.
#[derive(Debug)]
pub struct ToolLoopResult {
    /// Unique identifier for this run.
    pub run_id: String,
    /// Final assistant message text.
    pub response: String,
    /// Number of tool-call iterations executed.
    pub iterations: usize,
    /// Total input tokens consumed.
    pub input_tokens: u32,
    /// Total output tokens consumed.
    pub output_tokens: u32,
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

/// Execute the agentic tool-use loop using Open Responses.
///
/// 1. Discover tools from `client`, convert to [`ResponseTool`]
/// 2. Build initial input items (system + user prompt)
/// 3. Loop: call `model.respond()` → if output has function calls,
///    execute each via `client`, add results as input items
/// 4. Stop on text response, max iterations, or error
pub async fn run_tool_loop(
    model: &dyn ModelBackend,
    client: &mut McpClient,
    user_prompt: &str,
    config: &ToolLoopConfig,
    run_id: String,
) -> Result<ToolLoopResult, AgentError> {
    // Discover tools from MCP server, filtered by allowed_tools if set
    let mcp_tools = client.list_tools().await?;
    let tools: Vec<ResponseTool> = mcp_tools
        .iter()
        .filter(|t| {
            match &config.allowed_tools {
                Some(allowed) => allowed.contains(&t.name),
                None => true,
            }
        })
        .map(|t| ResponseTool {
            tool_type: "function".to_string(),
            name: t.name.clone(),
            description: t.description.clone(),
            parameters: Some(serde_json::json!({
                "type": t.input_schema.schema_type,
                "properties": t.input_schema.properties,
                "required": t.input_schema.required,
            })),
            strict: None,
        })
        .collect();

    if config.allowed_tools.is_some() {
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        eprintln!(
            "  [tool-filter] {} server tools → {} allowed: {:?}",
            mcp_tools.len(), tools.len(), tool_names
        );
    }

    // Build initial input
    let mut input: Vec<InputItem> = Vec::new();
    if let Some(system) = &config.system_prompt {
        input.push(InputItem::system(system));
    }
    input.push(InputItem::user(user_prompt));

    let mut total_input = 0u32;
    let mut total_output = 0u32;
    let mut progress_iterations = 0usize;
    let mut empty_retries = 0u8;

    loop {
        if progress_iterations >= config.max_iterations {
            return Err(AgentError::MaxIterations(config.max_iterations));
        }
        let iteration = progress_iterations;
        // Set structured output format if persona defines a JSON schema
        let text_config = config.output_json_schema.as_ref().map(|schema| {
            myelix_model::responses::request::TextConfig {
                format: Some(myelix_model::ResponseFormat::JsonSchema {
                    name: "persona_output".to_string(),
                    description: None,
                    schema: schema.clone(),
                    strict: Some(true),
                }),
                verbosity: None,
            }
        });

        let request = CreateResponseRequest {
            model: String::new(),
            input: input.clone(),
            instructions: None,
            tools: tools.clone(),
            tool_choice: Some(myelix_model::ResponseToolChoice::auto()),
            max_output_tokens: config.max_tokens,
            temperature: config.temperature,
            text: text_config,
            ..CreateResponseRequest::new(String::new(), vec![])
        };

        let response: ModelResponse = model.respond(&request).await?;

        // Lightweight sensitive data check on model response
        if let Some(text) = response.text() {
            warn_if_sensitive(&text);
        }

        if let Some(ref usage) = response.usage {
            total_input += usage.input_tokens;
            total_output += usage.output_tokens;
        }

        // Audit: record model call
        if let Some(ref audit) = config.audit {
            let (in_tok, out_tok) = response
                .usage
                .as_ref()
                .map(|u| (u.input_tokens, u.output_tokens))
                .unwrap_or((0, 0));
            let has_tool_calls = response
                .output
                .iter()
                .any(|o| matches!(o, OutputItem::FunctionCall(_)));
            let response_type = if has_tool_calls {
                "function_call"
            } else {
                "message"
            };
            // Extract reasoning summary text from output items
            let reasoning_parts: Vec<String> = response
                .reasoning()
                .iter()
                .flat_map(|r| r.summary.iter())
                .filter_map(|c| match c {
                    myelix_model::InputContent::Text(t) => Some(t.text.clone()),
                    _ => None,
                })
                .collect();
            let reasoning_text = if reasoning_parts.is_empty() {
                None
            } else {
                Some(reasoning_parts.join("\n"))
            };
            audit.on_model_call(
                iteration as u32,
                in_tok,
                out_tok,
                response_type,
                reasoning_text.as_deref(),
            );
        }

        // Check for function calls in output
        let function_calls: Vec<&FunctionCallItem> = response
            .output
            .iter()
            .filter_map(|item| match item {
                OutputItem::FunctionCall(fc) => Some(fc),
                _ => None,
            })
            .collect();

        if function_calls.is_empty() {
            let text = response.text().unwrap_or_default();

            // If the model returns empty text after tool calls were made,
            // prompt it once more to produce a synthesis (max 1 retry).
            if text.trim().is_empty() && progress_iterations > 0 && empty_retries == 0 {
                empty_retries += 1;
                tracing::info!("Empty response after tool use — prompting for synthesis");
                input.push(InputItem::user(
                    "Synthesize your findings into a final report. \
                     Do not call any more tools."
                ));
                continue;
            }

            return Ok(ToolLoopResult {
                run_id,
                response: text,
                iterations: iteration,
                input_tokens: total_input,
                output_tokens: total_output,
                taint: client.taint(),
            });
        }

        // Check if this round is purely status-polling (non-progress)
        let all_non_progress = config.non_progress_tools.as_ref().is_some_and(|npt| {
            function_calls.iter().all(|fc| npt.contains(&fc.name))
        });

        if all_non_progress {
            tracing::debug!(
                tools = ?function_calls.iter().map(|fc| fc.name.as_str()).collect::<Vec<_>>(),
                "non-progress round, not counting toward iteration limit"
            );
        } else {
            progress_iterations += 1;
        }

        // Execute each function call
        for fc in &function_calls {
            // Add the function call to input (for context)
            input.push(InputItem::FunctionCall(FunctionCallItem {
                id: fc.id.clone(),
                call_id: fc.call_id.clone(),
                name: fc.name.clone(),
                arguments: fc.arguments.clone(),
                status: Some(ItemStatus::Completed),
            }));

            warn_if_sensitive(&fc.arguments);

            let args: serde_json::Value =
                serde_json::from_str(&fc.arguments).unwrap_or(serde_json::json!({}));

            tracing::debug!(
                tool = %fc.name,
                args = %args,
                "executing tool call"
            );

            let tool_start = Instant::now();
            let result = client.call_tool(&fc.name, args).await?;
            let tool_duration = tool_start.elapsed();
            let text = extract_text(&result);

            // Audit: record tool call
            if let Some(ref audit) = config.audit {
                let truncated_args = truncate_str(&fc.arguments, 4096);
                let truncated_result = truncate_str(&text, 4096);
                audit.on_tool_call(
                    iteration as u32,
                    &fc.name,
                    truncated_args,
                    truncated_result,
                    tool_duration.as_millis() as u64,
                );
            }

            // Add the tool result to input
            input.push(InputItem::FunctionCallOutput(FunctionCallOutputItem {
                id: None,
                call_id: fc.call_id.clone(),
                output: FunctionCallOutputContent::Text(text),
                status: Some(ItemStatus::Completed),
            }));
        }
    }
}

/// Check if text contains patterns that look like leaked secrets.
/// Logs a warning for each match but does not block execution.
fn warn_if_sensitive(text: &str) {
    let patterns = ["sk_live_", "sk_test_", "AKIA", "ghp_", "-----BEGIN"];
    for pattern in &patterns {
        if text.contains(pattern) {
            tracing::warn!(pattern = pattern, "Model response may contain sensitive data");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myelix_model::{ModelBackend, ModelError, ModelResponse, OutputItem, MessageItem, ResponseStatus};
    use myelix_protocol::upstream::{Transport, UpstreamError};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;
    use async_trait::async_trait;

    /// Mock model that returns a sequence of scripted Open Responses.
    struct MockModel {
        responses: Mutex<Vec<ModelResponse>>,
    }

    impl MockModel {
        fn new(responses: Vec<ModelResponse>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }
    }

    impl ModelBackend for MockModel {
        fn respond(
            &self,
            _req: &CreateResponseRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ModelResponse, ModelError>> + Send + '_>> {
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
            serde_json::json!({
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "serverInfo": {"name": "test", "version": "0.1.0"}
                },
                "id": 1
            }),
            serde_json::json!({"jsonrpc": "2.0", "result": {}, "id": 2}),
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

    fn stop_response(text: &str) -> ModelResponse {
        use myelix_responses::response::Usage;
        ModelResponse {
            id: "resp_test".into(),
            object: "response".into(),
            created_at: None,
            completed_at: None,
            status: ResponseStatus::Completed,
            model: Some("test".into()),
            output: vec![OutputItem::Message(MessageItem::assistant(text))],
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
            metadata: Default::default(),
            incomplete_details: None,
            extra: Default::default(),
        }
    }

    fn tool_call_response(tool_name: &str, args: &str) -> ModelResponse {
        use myelix_responses::response::Usage;
        ModelResponse {
            id: "resp_test".into(),
            object: "response".into(),
            created_at: None,
            completed_at: None,
            status: ResponseStatus::Completed,
            model: Some("test".into()),
            output: vec![OutputItem::FunctionCall(FunctionCallItem {
                id: Some("fc_1".into()),
                call_id: "call_1".into(),
                name: tool_name.to_string(),
                arguments: args.to_string(),
                status: Some(ItemStatus::Completed),
            })],
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
            metadata: Default::default(),
            incomplete_details: None,
            extra: Default::default(),
        }
    }

    #[tokio::test]
    async fn immediate_stop() {
        let model = MockModel::new(vec![stop_response("Hello!")]);
        let mut client = mock_client(vec![]).await;
        let config = ToolLoopConfig::default();

        let result = run_tool_loop(&model, &mut client, "Hi", &config, "test-run".into())
            .await
            .unwrap();
        assert_eq!(result.response, "Hello!");
        assert_eq!(result.iterations, 0);
        assert_eq!(result.input_tokens, 10);
        assert_eq!(result.output_tokens, 5);
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

        let result = run_tool_loop(&model, &mut client, "What's the git status?", &config, "test-run".into())
            .await
            .unwrap();
        assert_eq!(result.response, "Status is clean.");
        assert_eq!(result.iterations, 1);
        assert_eq!(result.input_tokens, 20);
        assert_eq!(result.output_tokens, 10);
    }

    #[tokio::test]
    async fn max_iterations_error() {
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

        let err = run_tool_loop(&model, &mut client, "loop forever", &config, "test-run".into())
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::MaxIterations(3)));
    }

    #[tokio::test]
    async fn non_progress_tools_dont_count() {
        // 3 polling rounds (team_status) + 1 progress round (git_status) + stop
        let model = MockModel::new(vec![
            tool_call_response("team_status", "{}"),
            tool_call_response("team_status", "{}"),
            tool_call_response("team_status", "{}"),
            tool_call_response("git_status", "{}"),
            stop_response("Done."),
        ]);

        let tool_result = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": "ok"}],
                "isError": false
            },
            "id": 4
        });
        let mut client = mock_client(vec![
            tool_result.clone(),
            tool_result.clone(),
            tool_result.clone(),
            tool_result.clone(),
        ])
        .await;

        let config = ToolLoopConfig {
            max_iterations: 2, // would fail without non_progress_tools
            non_progress_tools: Some(vec!["team_status".to_string()]),
            ..Default::default()
        };

        let result = run_tool_loop(&model, &mut client, "poll then act", &config, "test-run".into())
            .await
            .unwrap();
        assert_eq!(result.response, "Done.");
        // Only 1 progress iteration (git_status), the 3 team_status don't count
        assert_eq!(result.iterations, 1);
    }

    #[tokio::test]
    async fn non_progress_still_limits_progress_calls() {
        // 3 progress rounds hit max_iterations=2
        let model = MockModel::new(vec![
            tool_call_response("team_status", "{}"), // non-progress
            tool_call_response("git_status", "{}"),  // progress #1
            tool_call_response("git_status", "{}"),  // progress #2 → hits limit
        ]);

        let tool_result = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": "ok"}],
                "isError": false
            },
            "id": 4
        });
        let mut client = mock_client(vec![
            tool_result.clone(),
            tool_result.clone(),
            tool_result.clone(),
        ])
        .await;

        let config = ToolLoopConfig {
            max_iterations: 2,
            non_progress_tools: Some(vec!["team_status".to_string()]),
            ..Default::default()
        };

        let err = run_tool_loop(&model, &mut client, "overflow", &config, "test-run".into())
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::MaxIterations(2)));
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
