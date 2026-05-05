//! Agentic tool-use loop (ReAct pattern) using Open Responses.
//!
//! Discover tools → call model.respond() → execute function calls →
//! feed results back → repeat until completion or max iterations.

use crate::client::McpClient;
use crate::error::AgentError;
use smgglrs_model::{
    CreateResponseRequest, FunctionCallItem, FunctionCallOutputItem, FunctionCallOutputContent,
    InputItem, ItemStatus, ModelBackend, ModelResponse, OutputItem, ResponseTool,
};
use smgglrs_protocol::label::DataLabel;
use smgglrs_protocol::{CallToolResult, Content};
use smgglrs_security::safety::{FilterContext, FilterPipeline};
use std::sync::Arc;
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
    /// Force tool calls for the first N progress iterations.
    /// Uses tool_choice="required" instead of "auto" to prevent
    /// the model from producing text responses prematurely.
    /// After N iterations, switches to "auto" to allow synthesis.
    pub force_tool_iterations: Option<usize>,
    /// Optional PII filter applied to model-generated reasoning text.
    /// When set, the model's text output is filtered through this
    /// pipeline before being stored in conversation history or
    /// returned in the final response. This catches PII that the
    /// model echoes in its reasoning even after tool results were
    /// redacted.
    pub pii_filter: Option<Arc<FilterPipeline>>,
    /// Maximum tokens for model reasoning text between tool calls
    /// (default: 2048). Prevents small models from wasting context
    /// on verbose explanations. Approximate: chars/4.
    pub max_reasoning_tokens: Option<usize>,
    /// Attempt to repair malformed JSON in model tool call arguments
    /// (default: true). Fixes missing braces, trailing commas,
    /// unquoted keys, and markdown fences around JSON — common
    /// failures with small local models.
    pub repair_malformed_output: bool,
    /// Maximum total tokens (input + output) allowed in a single run
    /// (default: 500_000). When exceeded, the loop logs a warning and
    /// stops. This is a soft circuit breaker — the existing
    /// max_iterations handles hard iteration limits.
    pub max_tokens_per_run: u64,
    /// Maximum tool calls allowed per 30-second window (default: 20).
    /// When exceeded, a warning is logged. This detects runaway agents
    /// making rapid-fire tool calls without meaningful progress.
    pub max_calls_per_window: usize,
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
            force_tool_iterations: None,
            pii_filter: None,
            max_reasoning_tokens: Some(2048),
            repair_malformed_output: true,
            max_tokens_per_run: 500_000,
            max_calls_per_window: 20,
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

/// Filter text through the PII pipeline, if configured.
///
/// Returns the filtered text, or the original text if no filter is set
/// or the filter encounters an error (graceful degradation).
async fn filter_pii(text: &str, pipeline: &FilterPipeline) -> String {
    let ctx = FilterContext {
        agent_name: "agent",
        operation: "model_response",
        path: None,
    };
    match pipeline.process_outbound(text, &ctx).await {
        Ok(filtered) => filtered,
        Err(_) => {
            // Graceful degradation: if the filter blocks entirely,
            // log and return the original text (the filter is meant
            // to redact, not block model reasoning).
            tracing::warn!("PII filter blocked model response text — returning original");
            text.to_string()
        }
    }
}

/// Truncate reasoning text to stay within a token budget.
///
/// Approximates token count as chars/4. When text exceeds the limit,
/// truncates at a word boundary and appends a note directing the model
/// to continue with action rather than explanation.
fn truncate_reasoning(text: &str, max_tokens: usize) -> String {
    let max_chars = max_tokens * 4;
    if text.len() <= max_chars {
        return text.to_string();
    }
    // Find a word boundary near the limit
    let mut end = max_chars;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    // Back up to a space if possible
    if let Some(space) = text[..end].rfind(' ') {
        end = space;
    }
    format!(
        "{}\n\n[reasoning truncated at {} tokens — continue with action]",
        &text[..end],
        max_tokens
    )
}

/// Attempt to repair malformed JSON from small model output.
///
/// Handles common failures:
/// - Markdown code fences wrapping JSON
/// - Trailing commas before closing braces/brackets
/// - Missing closing braces/brackets
/// - Unquoted keys (bare identifiers followed by colon)
pub fn repair_json(input: &str) -> Result<serde_json::Value, String> {
    // First try parsing as-is
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(input) {
        return Ok(v);
    }

    let mut text = input.to_string();

    // Strip markdown code fences
    if text.contains("```") {
        let lines: Vec<&str> = text.lines().collect();
        let mut cleaned = Vec::new();
        let mut in_fence = false;
        for line in &lines {
            let trimmed = line.trim();
            if trimmed.starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if in_fence || !trimmed.is_empty() {
                cleaned.push(*line);
            }
        }
        text = cleaned.join("\n");
        // Try parsing after fence removal
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            return Ok(v);
        }
    }

    // Fix trailing commas: ",}" or ",]"
    let re_trailing = regex_lite::Regex::new(r",(\s*[}\]])").unwrap();
    text = re_trailing.replace_all(&text, "$1").to_string();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        return Ok(v);
    }

    // Fix unquoted keys: word: -> "word":
    let re_unquoted = regex_lite::Regex::new(r"(?m)([{\s,])(\w+)\s*:").unwrap();
    text = re_unquoted.replace_all(&text, r#"$1"$2":"#).to_string();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        return Ok(v);
    }

    // Fix missing closing braces/brackets
    let open_braces = text.chars().filter(|c| *c == '{').count();
    let close_braces = text.chars().filter(|c| *c == '}').count();
    let open_brackets = text.chars().filter(|c| *c == '[').count();
    let close_brackets = text.chars().filter(|c| *c == ']').count();
    for _ in 0..(open_brackets.saturating_sub(close_brackets)) {
        text.push(']');
    }
    for _ in 0..(open_braces.saturating_sub(close_braces)) {
        text.push('}');
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        return Ok(v);
    }

    Err(format!("Could not parse or repair JSON: {}", &input[..input.len().min(200)]))
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
        .map(|t| crate::convert::tool_def_to_response(t))
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

    // Collect tool names for hallucinated tool detection
    let tool_names: Vec<String> = tools.iter().map(|t| t.name.clone()).collect();

    let mut total_input = 0u32;
    let mut total_output = 0u32;
    let mut progress_iterations = 0usize;
    let mut empty_retries = 0u8;
    let mut prev_outputs: Vec<String> = Vec::new();

    let mut budget_exhausted = false;

    // Circuit breaker state: token burn monitor
    let mut total_tokens_consumed: u64 = 0;

    // Circuit breaker state: tool call rate monitor (sliding 30s window)
    let mut call_timestamps: Vec<std::time::Instant> = Vec::new();
    let rate_window = std::time::Duration::from_secs(30);

    loop {
        if progress_iterations >= config.max_iterations {
            if budget_exhausted {
                return Err(AgentError::MaxIterations(config.max_iterations));
            }
            budget_exhausted = true;
            tracing::info!(
                iterations = progress_iterations,
                "Iteration budget exhausted — requesting final synthesis"
            );
            input.push(InputItem::user(
                "You have used all available iterations. Summarize your findings \
                 so far based on the work you have already done. Do not call any \
                 more tools — produce your best answer with the information you have."
            ));
        }
        let iteration = progress_iterations;
        // Set structured output format if persona defines a JSON schema
        let text_config = config.output_json_schema.as_ref().map(|schema| {
            smgglrs_model::responses::request::TextConfig {
                format: Some(smgglrs_model::ResponseFormat::JsonSchema {
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
            tools: if budget_exhausted { vec![] } else { tools.clone() },
            tool_choice: Some(if budget_exhausted {
                smgglrs_model::ResponseToolChoice::none()
            } else if config.force_tool_iterations.is_some_and(|n| progress_iterations < n) {
                smgglrs_model::ResponseToolChoice::required()
            } else {
                smgglrs_model::ResponseToolChoice::auto()
            }),
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

            // Circuit breaker: token burn monitor
            total_tokens_consumed += (usage.input_tokens + usage.output_tokens) as u64;
            if total_tokens_consumed > config.max_tokens_per_run {
                tracing::warn!(
                    tokens = total_tokens_consumed,
                    limit = config.max_tokens_per_run,
                    iterations = progress_iterations,
                    "Token burn circuit breaker: agent exceeded max_tokens_per_run"
                );
                let text = response.text().unwrap_or_else(|| format!(
                    "Agent stopped: token budget exceeded ({} tokens consumed, limit {})",
                    total_tokens_consumed, config.max_tokens_per_run
                ));
                return Ok(ToolLoopResult {
                    run_id,
                    response: text,
                    iterations: progress_iterations,
                    input_tokens: total_input,
                    output_tokens: total_output,
                    taint: client.taint(),
                });
            }
        }

        // Bounded reasoning: truncate verbose model text between tool calls
        // to prevent small models from wasting context on explanation.
        if let Some(max_tokens) = config.max_reasoning_tokens {
            if let Some(text) = response.text() {
                if text.len() > max_tokens * 4 {
                    let truncated = truncate_reasoning(&text, max_tokens);
                    tracing::info!(
                        original_chars = text.len(),
                        max_tokens = max_tokens,
                        "Truncated verbose model reasoning"
                    );
                    // Replace text in input context so subsequent turns
                    // don't carry the full verbose reasoning
                    input.push(InputItem::user(&truncated));
                }
            }
        }

        // Repetition loop detection: if the model produces the same
        // output 5 times in a row, abort to avoid infinite loops.
        // Threshold is 5 (not 3) because legitimate agents may read
        // the same file multiple times during analysis — 3 was too
        // aggressive and caused 8/115 agents to abort prematurely.
        // Exclude status-polling tools (flow_status, team_status)
        // since those are expected to return identical results while
        // waiting for async work to complete.
        const REPETITION_THRESHOLD: usize = 5;
        let is_status_poll = response.output.iter().any(|item| {
            matches!(item, OutputItem::FunctionCall(fc)
                if fc.name == "flow_status" || fc.name == "team_status")
        });
        if !is_status_poll {
            let output_fingerprint = response
                .output
                .iter()
                .map(|item| match item {
                    OutputItem::FunctionCall(fc) => format!("fc:{}:{}", fc.name, fc.arguments),
                    OutputItem::Message(msg) => format!("msg:{:?}", msg),
                    _ => format!("other:{item:?}"),
                })
                .collect::<Vec<_>>()
                .join("|");
            prev_outputs.push(output_fingerprint);
            if prev_outputs.len() >= REPETITION_THRESHOLD {
                let len = prev_outputs.len();
                let tail = &prev_outputs[len - REPETITION_THRESHOLD..];
                if tail.iter().all(|o| *o == tail[0]) {
                    return Err(AgentError::Other(anyhow::anyhow!(
                        "Repetition loop detected: model produced identical output \
                         {REPETITION_THRESHOLD} times in a row"
                    )));
                }
            }
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
            let mut text = response.text().unwrap_or_default();

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

            // Filter PII from the final model response before returning
            if let Some(ref pipeline) = config.pii_filter {
                text = filter_pii(&text, pipeline).await;
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

        // Circuit breaker: tool call rate monitor
        let now = std::time::Instant::now();
        call_timestamps.retain(|ts| now.duration_since(*ts) < rate_window);
        let calls_in_window = call_timestamps.len() + function_calls.len();
        if calls_in_window > config.max_calls_per_window {
            tracing::warn!(
                calls_in_window = calls_in_window,
                limit = config.max_calls_per_window,
                window_secs = rate_window.as_secs(),
                "Tool call rate circuit breaker: agent making rapid-fire tool calls"
            );
        }

        // Execute each function call
        for fc in &function_calls {
            // Hallucinated tool name detection: if the model calls a
            // tool that doesn't exist, return a helpful error listing
            // available tools instead of failing opaquely.
            if !tool_names.contains(&fc.name) {
                let available = tool_names.join(", ");
                let error_msg = format!(
                    "Unknown tool '{}'. Available tools: {}",
                    fc.name, available
                );
                tracing::warn!(tool = %fc.name, "Model hallucinated tool name");
                input.push(InputItem::FunctionCall(FunctionCallItem {
                    id: fc.id.clone(),
                    call_id: fc.call_id.clone(),
                    name: fc.name.clone(),
                    arguments: fc.arguments.clone(),
                    status: Some(ItemStatus::Completed),
                }));
                input.push(InputItem::FunctionCallOutput(FunctionCallOutputItem {
                    id: None,
                    call_id: fc.call_id.clone(),
                    output: FunctionCallOutputContent::Text(error_msg),
                    status: Some(ItemStatus::Completed),
                }));
                continue;
            }

            // Add the function call to input (for context)
            input.push(InputItem::FunctionCall(FunctionCallItem {
                id: fc.id.clone(),
                call_id: fc.call_id.clone(),
                name: fc.name.clone(),
                arguments: fc.arguments.clone(),
                status: Some(ItemStatus::Completed),
            }));

            warn_if_sensitive(&fc.arguments);

            // Parse arguments, with optional repair for malformed JSON
            let args: serde_json::Value = if config.repair_malformed_output {
                match repair_json(&fc.arguments) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            tool = %fc.name,
                            error = %e,
                            "Failed to parse or repair tool call arguments"
                        );
                        input.push(InputItem::FunctionCallOutput(FunctionCallOutputItem {
                            id: None,
                            call_id: fc.call_id.clone(),
                            output: FunctionCallOutputContent::Text(format!(
                                "Error: malformed JSON arguments — {e}"
                            )),
                            status: Some(ItemStatus::Completed),
                        }));
                        continue;
                    }
                }
            } else {
                serde_json::from_str(&fc.arguments).unwrap_or(serde_json::json!({}))
            };

            tracing::debug!(
                tool = %fc.name,
                args = %args,
                "executing tool call"
            );

            let result = client.call_tool(&fc.name, args).await?;
            let text = extract_text(&result);

            // Add the tool result to input
            input.push(InputItem::FunctionCallOutput(FunctionCallOutputItem {
                id: None,
                call_id: fc.call_id.clone(),
                output: FunctionCallOutputContent::Text(text),
                status: Some(ItemStatus::Completed),
            }));

            // Record timestamp for rate monitoring
            call_timestamps.push(std::time::Instant::now());
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
    use smgglrs_model::{ModelBackend, ModelError, ModelResponse, OutputItem, MessageItem, ResponseStatus};
    use smgglrs_protocol::upstream::{Transport, UpstreamError};
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
        let upstream = smgglrs_protocol::Upstream::connect("test", transport)
            .await
            .unwrap();
        McpClient::new(upstream)
    }

    fn stop_response(text: &str) -> ModelResponse {
        use smgglrs_responses::response::Usage;
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
        use smgglrs_responses::response::Usage;
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
    async fn max_iterations_forces_synthesis() {
        let model = MockModel::new(vec![
            tool_call_response("git_status", r#"{"verbose": false}"#),
            tool_call_response("git_status", r#"{"verbose": true}"#),
            tool_call_response("git_status", r#"{"branch": "main"}"#),
            stop_response("Partial findings from 3 iterations."),
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

        let result = run_tool_loop(&model, &mut client, "loop forever", &config, "test-run".into())
            .await
            .unwrap();
        assert_eq!(result.response, "Partial findings from 3 iterations.");
        assert_eq!(result.iterations, 3);
    }

    #[tokio::test]
    async fn non_progress_tools_dont_count() {
        // 3 polling rounds (team_status) + 1 progress round (git_status) + stop
        let model = MockModel::new(vec![
            tool_call_response("team_status", r#"{"poll": 1}"#),
            tool_call_response("team_status", r#"{"poll": 2}"#),
            tool_call_response("team_status", r#"{"poll": 3}"#),
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
        // 2 progress rounds hit max_iterations=2, then synthesis
        let model = MockModel::new(vec![
            tool_call_response("team_status", r#"{"poll": 1}"#), // non-progress
            tool_call_response("git_status", r#"{"verbose": false}"#),  // progress #1
            tool_call_response("git_status", r#"{"verbose": true}"#),  // progress #2 → budget exhausted
            stop_response("Synthesized from partial work."), // forced synthesis
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

        let result = run_tool_loop(&model, &mut client, "overflow", &config, "test-run".into())
            .await
            .unwrap();
        assert_eq!(result.response, "Synthesized from partial work.");
    }

    #[test]
    fn extract_text_from_result() {
        let result = CallToolResult::success(vec![
            smgglrs_protocol::Content::text("line 1"),
            smgglrs_protocol::Content::text("line 2"),
        ]);
        assert_eq!(extract_text(&result), "line 1line 2");
    }

    #[test]
    fn extract_text_from_error_result() {
        let result = CallToolResult::error("something failed");
        assert_eq!(extract_text(&result), "Error: something failed");
    }

    #[tokio::test]
    async fn pii_filter_redacts_model_response() {
        let pipeline = Arc::new(smgglrs_security::safety::build_pipeline("standard"));
        let model = MockModel::new(vec![stop_response(
            "The patient's SSN is 123-45-6789 and email is john@example.com",
        )]);
        let mut client = mock_client(vec![]).await;
        let config = ToolLoopConfig {
            pii_filter: Some(pipeline),
            ..Default::default()
        };

        let result = run_tool_loop(&model, &mut client, "Hi", &config, "test-run".into())
            .await
            .unwrap();
        assert!(
            result.response.contains("[REDACTED:ssn]"),
            "Expected SSN to be redacted: {}",
            result.response
        );
        assert!(
            result.response.contains("[REDACTED:email]"),
            "Expected email to be redacted: {}",
            result.response
        );
        assert!(
            !result.response.contains("123-45-6789"),
            "SSN should not appear in response"
        );
        assert!(
            !result.response.contains("john@example.com"),
            "Email should not appear in response"
        );
    }

    #[tokio::test]
    async fn pii_filter_none_passes_through() {
        let model = MockModel::new(vec![stop_response(
            "The patient's SSN is 123-45-6789",
        )]);
        let mut client = mock_client(vec![]).await;
        let config = ToolLoopConfig {
            pii_filter: None,
            ..Default::default()
        };

        let result = run_tool_loop(&model, &mut client, "Hi", &config, "test-run".into())
            .await
            .unwrap();
        assert!(
            result.response.contains("123-45-6789"),
            "SSN should pass through when no filter: {}",
            result.response
        );
    }

    #[tokio::test]
    async fn pii_filter_does_not_affect_tool_calls() {
        // PII filter only filters model text, not tool call arguments
        let pipeline = Arc::new(smgglrs_security::safety::build_pipeline("standard"));
        let model = MockModel::new(vec![
            tool_call_response("git_status", r#"{"ssn": "123-45-6789"}"#),
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
        let config = ToolLoopConfig {
            pii_filter: Some(pipeline),
            ..Default::default()
        };

        let result = run_tool_loop(
            &model, &mut client, "What's the git status?", &config, "test-run".into(),
        )
        .await
        .unwrap();
        // The final response text "Status is clean." should pass through fine
        assert_eq!(result.response, "Status is clean.");
        assert_eq!(result.iterations, 1);
    }

    // --- Bounded reasoning tests ---

    #[test]
    fn truncate_reasoning_short_text_unchanged() {
        let text = "Short reasoning.";
        assert_eq!(truncate_reasoning(text, 2048), text);
    }

    #[test]
    fn truncate_reasoning_at_2048_tokens() {
        // 2048 tokens ~ 8192 chars. Create text longer than that.
        let text = "word ".repeat(2500); // 12500 chars > 8192
        let truncated = truncate_reasoning(&text, 2048);
        assert!(truncated.len() < text.len());
        assert!(truncated.contains("[reasoning truncated at 2048 tokens"));
        // Truncated output should be roughly 8192 chars + the note
        assert!(truncated.len() < 8400);
    }

    // --- Malformed JSON repair tests ---

    #[test]
    fn repair_json_valid_passthrough() {
        let input = r#"{"key": "value"}"#;
        let result = repair_json(input).unwrap();
        assert_eq!(result["key"], "value");
    }

    #[test]
    fn repair_json_missing_brace() {
        let input = r#"{"key": "value""#;
        let result = repair_json(input).unwrap();
        assert_eq!(result["key"], "value");
    }

    #[test]
    fn repair_json_trailing_comma() {
        let input = r#"{"key": "value",}"#;
        let result = repair_json(input).unwrap();
        assert_eq!(result["key"], "value");
    }

    #[test]
    fn repair_json_markdown_fences() {
        let input = "```json\n{\"key\": \"value\"}\n```";
        let result = repair_json(input).unwrap();
        assert_eq!(result["key"], "value");
    }

    #[test]
    fn repair_json_markdown_fences_no_lang() {
        let input = "```\n{\"key\": \"value\"}\n```";
        let result = repair_json(input).unwrap();
        assert_eq!(result["key"], "value");
    }

    #[test]
    fn repair_json_trailing_comma_in_array() {
        let input = r#"{"items": [1, 2, 3,]}"#;
        let result = repair_json(input).unwrap();
        assert_eq!(result["items"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn repair_json_irreparable() {
        let input = "this is not json at all";
        assert!(repair_json(input).is_err());
    }

    // --- Repetition loop detection test ---

    #[tokio::test]
    async fn repetition_loop_aborts() {
        // Model produces the exact same tool call 5 times (threshold)
        let model = MockModel::new(vec![
            tool_call_response("git_status", "{}"),
            tool_call_response("git_status", "{}"),
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
            mock_client(vec![
                tool_result.clone(), tool_result.clone(), tool_result.clone(),
                tool_result.clone(), tool_result,
            ]).await;
        let config = ToolLoopConfig {
            max_iterations: 10,
            ..Default::default()
        };

        let result = run_tool_loop(&model, &mut client, "loop", &config, "test-run".into()).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Repetition loop"),
            "Expected repetition loop error, got: {err}"
        );
    }

    #[tokio::test]
    async fn three_identical_calls_no_longer_aborts() {
        // 3 identical calls followed by a different response should succeed
        // (old threshold was 3, now it's 5)
        let model = MockModel::new(vec![
            tool_call_response("git_status", "{}"),
            tool_call_response("git_status", "{}"),
            tool_call_response("git_status", "{}"),
            stop_response("Done after re-reading."),
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
            max_iterations: 10,
            ..Default::default()
        };

        let result = run_tool_loop(&model, &mut client, "read file", &config, "test-run".into()).await;
        assert!(result.is_ok(), "3 identical calls should not abort (threshold is 5)");
        assert_eq!(result.unwrap().response, "Done after re-reading.");
    }

    // --- Hallucinated tool name detection test ---

    #[tokio::test]
    async fn hallucinated_tool_returns_error_in_context() {
        // Model calls a tool that doesn't exist, then produces a final answer
        let model = MockModel::new(vec![
            tool_call_response("nonexistent_tool", "{}"),
            stop_response("I used the available tools."),
        ]);
        let mut client = mock_client(vec![]).await;
        let config = ToolLoopConfig::default();

        let result = run_tool_loop(
            &model, &mut client, "Do something", &config, "test-run".into(),
        )
        .await
        .unwrap();
        // The model should have received the error about the unknown tool
        // and produced a final response
        assert_eq!(result.response, "I used the available tools.");
    }
}
