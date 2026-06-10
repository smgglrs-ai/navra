//! Agentic tool-use loop (ReAct pattern) using Open Responses.
//!
//! Discover tools → call model.respond() → execute function calls →
//! feed results back → repeat until completion or max iterations.

use crate::action::{ActionRecord, AgentAction};
use crate::client::McpClient;
use crate::error::AgentError;
use crate::signal::{AgentSignal, SignalReceiver};
use navra_model::{
    CreateResponseRequest, EmbedRequest, FunctionCallItem, FunctionCallOutputContent,
    FunctionCallOutputItem, InputItem, ItemStatus, ModelBackend, ModelResponse, OutputItem,
    ResponseTool,
};
use navra_protocol::label::DataLabel;
use navra_protocol::{CallToolResult, Content};
use navra_safety::safety::{FilterContext, FilterPipeline};
use std::sync::Arc;
/// Transparent context retriever injected before each model call.
///
/// Implementations search a knowledge base and return relevant chunks
/// that are prepended to the conversation. The retriever is responsible
/// for score gating (don't return low-confidence results) and budget
/// gating (don't return more than the available context can hold).
pub trait ContextRetriever: Send + Sync {
    /// Retrieve context relevant to the query, limited to `max_tokens`.
    /// Returns empty string if nothing relevant or confidence too low.
    fn retrieve(
        &self,
        query: &str,
        max_tokens: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send + '_>>;
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
    /// Total context window size in tokens (default: 128_000).
    /// Used to compute fill ratio for progressive tool output compression.
    pub context_window_tokens: u32,
    /// Maximum tokens for a single tool result (default: 4096).
    /// Dynamically reduced as context fills up.
    pub max_tool_output_tokens: u32,
    /// Optional embedding model for query-aware extractive compression.
    /// When set, tool outputs are compressed by selecting the most
    /// relevant paragraphs instead of truncating from the tail.
    pub embedding_model: Option<Arc<dyn ModelBackend>>,
    /// Optional audit sink for recording tool and model calls.
    pub audit_sink: Option<crate::audit::SharedAuditSink>,
    /// Optional signal receiver for cooperative interruption.
    /// When set, the tool loop checks for signals between iterations.
    pub signal_rx: Option<SignalReceiver>,
    /// Loop detection: after N calls to the same tool+target, inject
    /// a "reconsider your approach" context message. 0 = disabled.
    pub loop_detection_threshold: usize,
    /// Reasoning phases: map iteration ranges to temperature overrides.
    /// Format: `[(start, end, temperature)]`. Example:
    /// `[(0, 2, 0.1), (2, 8, 0.0), (8, 10, 0.1)]` for planning→
    /// execution→verification sandwich.
    pub reasoning_phases: Vec<(usize, usize, f32)>,
    /// Transparent RAG context retriever. When set, relevant context
    /// is retrieved before each model call and injected as a system
    /// message. The retriever handles score gating and budget gating.
    pub context_retriever: Option<Arc<dyn ContextRetriever>>,
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
            context_window_tokens: 128_000,
            max_tool_output_tokens: 4096,
            embedding_model: None,
            audit_sink: None,
            signal_rx: None,
            loop_detection_threshold: 3,
            reasoning_phases: Vec::new(),
            context_retriever: None,
        }
    }
}

/// Get the temperature override for a given iteration based on
/// reasoning phases. Returns None if no phase matches.
fn phase_temperature(phases: &[(usize, usize, f32)], iteration: usize) -> Option<f32> {
    phases
        .iter()
        .find(|(start, end, _)| iteration >= *start && iteration < *end)
        .map(|(_, _, temp)| *temp)
}

/// Loop detection: track (tool_name, primary_arg) call counts.
struct LoopDetector {
    counts: std::collections::HashMap<String, usize>,
    threshold: usize,
}

impl LoopDetector {
    fn new(threshold: usize) -> Self {
        Self {
            counts: std::collections::HashMap::new(),
            threshold,
        }
    }

    fn record(&mut self, tool_name: &str, args: &serde_json::Value) -> Option<String> {
        if self.threshold == 0 {
            return None;
        }
        let primary_arg = args
            .as_object()
            .and_then(|o| o.values().next())
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let key = format!("{tool_name}:{primary_arg}");
        let count = self.counts.entry(key.clone()).or_insert(0);
        *count += 1;

        if *count == self.threshold {
            Some(format!(
                "You have called {tool_name} on the same target {count} times. \
                 Reconsider your approach — try a different tool or strategy."
            ))
        } else if *count == self.threshold + 2 {
            Some(format!(
                "WARNING: {tool_name} called {} times on same target. \
                 You must use a different approach.",
                count
            ))
        } else {
            None
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
    /// Classified action records for every tool call in this run.
    pub actions: Vec<ActionRecord>,
    /// Total characters saved by tool output compression.
    pub compressed_chars_saved: usize,
    /// Whether the run was stopped by a signal (Interrupt or Terminate).
    pub interrupted: bool,
}

/// Extract text content from a [`CallToolResult`].
pub fn extract_text(result: &CallToolResult) -> String {
    let mut parts = Vec::new();
    if result.is_error {
        parts.push("Error: ".to_string());
    }
    for content in &result.content {
        if let Content::Text(tc) = content {
            parts.push(tc.text.clone());
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

/// Compute effective token limit based on context fill ratio.
///
/// Progressive scaling: as context fills, the limit shrinks.
fn effective_token_limit(max_tool_output_tokens: u32, context_fill_ratio: f32) -> u32 {
    let limit = if context_fill_ratio < 0.5 {
        max_tool_output_tokens
    } else if context_fill_ratio < 0.7 {
        (max_tool_output_tokens as f32 * 0.75) as u32
    } else if context_fill_ratio < 0.8 {
        (max_tool_output_tokens as f32 * 0.50) as u32
    } else {
        (max_tool_output_tokens as f32 * 0.25) as u32
    };
    limit.max(256)
}

/// Compress tool output, using extractive compression when an embedding
/// model is available, falling back to truncation otherwise.
async fn compress_tool_output(
    text: &str,
    max_tool_output_tokens: u32,
    context_fill_ratio: f32,
    embedding_model: Option<&dyn ModelBackend>,
    query: Option<&str>,
) -> String {
    let effective_limit = effective_token_limit(max_tool_output_tokens, context_fill_ratio);
    if navra_cognitive::estimate_tokens(text) <= effective_limit {
        return text.to_string();
    }
    if let (Some(model), Some(q)) = (embedding_model, query) {
        match compress_extractive(text, q, model, effective_limit).await {
            Ok(compressed) => return compressed,
            Err(e) => {
                tracing::debug!(error = %e, "Extractive compression failed, falling back to truncation");
            }
        }
    }
    navra_cognitive::truncate_to_budget(text, effective_limit)
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    let denom = na.sqrt() * nb.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

/// Split text into paragraphs. Uses double newline for prose,
/// falls back to groups of lines for code-like content.
fn split_paragraphs(text: &str) -> Vec<&str> {
    let paragraphs: Vec<&str> = text
        .split("\n\n")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();
    if paragraphs.len() >= 3 {
        return paragraphs;
    }
    // Few or no double-newline splits — likely code. Group by 10 lines.
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= 10 {
        return vec![text];
    }
    let mut groups = Vec::new();
    let mut start = 0;
    for (i, line) in lines.iter().enumerate() {
        if (i + 1) % 10 == 0 || i == lines.len() - 1 {
            let end = line.as_ptr() as usize + line.len() - text.as_ptr() as usize;
            let start_ptr = lines[start].as_ptr() as usize - text.as_ptr() as usize;
            groups.push(&text[start_ptr..end]);
            start = i + 1;
        }
    }
    groups
}

/// Extract the most relevant paragraphs from text using embedding similarity.
async fn compress_extractive(
    text: &str,
    query: &str,
    model: &dyn ModelBackend,
    max_tokens: u32,
) -> Result<String, AgentError> {
    let paragraphs = split_paragraphs(text);
    if paragraphs.len() <= 1 {
        return Ok(navra_cognitive::truncate_to_budget(text, max_tokens));
    }

    // Embed the query (use first 512 chars of mandate)
    let query_text = if query.len() > 512 {
        &query[..512]
    } else {
        query
    };
    let query_embedding = model
        .embed(&EmbedRequest {
            text: query_text.to_string(),
        })
        .await?;

    // Embed each paragraph and score
    let mut scored: Vec<(usize, f32, &str)> = Vec::with_capacity(paragraphs.len());
    for (i, para) in paragraphs.iter().enumerate() {
        let para_text = if para.len() > 1024 {
            &para[..1024]
        } else {
            para
        };
        match model
            .embed(&EmbedRequest {
                text: para_text.to_string(),
            })
            .await
        {
            Ok(resp) => {
                let score = cosine_similarity(&query_embedding.embedding, &resp.embedding);
                scored.push((i, score, para));
            }
            Err(_) => {
                scored.push((i, 0.0, para));
            }
        }
    }

    // Sort by score descending, select top-K that fit budget
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut selected: Vec<(usize, &str)> = Vec::new();
    let mut tokens_used: u32 = 0;
    let notice_reserve: u32 = 20;
    for (idx, _score, para) in &scored {
        let para_tokens = navra_cognitive::estimate_tokens(para);
        if tokens_used + para_tokens + notice_reserve > max_tokens {
            continue;
        }
        selected.push((*idx, para));
        tokens_used += para_tokens;
    }

    if selected.is_empty() {
        // All paragraphs too large — take the highest-scored one, truncated
        if let Some((_, _, best)) = scored.first() {
            return Ok(navra_cognitive::truncate_to_budget(best, max_tokens));
        }
    }

    // Re-sort by document position to preserve reading order
    selected.sort_by_key(|(idx, _)| *idx);

    let mut result: String = selected
        .iter()
        .map(|(_, para)| *para)
        .collect::<Vec<_>>()
        .join("\n\n");
    result.push_str(&format!(
        "\n\n[extracted {}/{} paragraphs by relevance]",
        selected.len(),
        paragraphs.len()
    ));
    Ok(result)
}

/// Estimate total tokens in the input vector without serialization.
fn estimate_input_tokens(input: &[InputItem]) -> u32 {
    let mut total = 0u32;
    for item in input {
        total += match item {
            InputItem::FunctionCallOutput(fco) => match &fco.output {
                FunctionCallOutputContent::Text(t) => navra_cognitive::estimate_tokens(t),
                _ => 50,
            },
            InputItem::FunctionCall(fc) => navra_cognitive::estimate_tokens(&fc.arguments) + 20,
            InputItem::Message(m) => match &m.content {
                navra_model::MessageContent::Text(t) => navra_cognitive::estimate_tokens(t),
                _ => 50,
            },
            _ => 50,
        };
    }
    total
}

/// Compact old conversation history to bound memory usage.
///
/// Reasoning-first strategy: if the model produced reasoning about a
/// tool result (next item is a Message), replace the tool output with
/// a stub — the model's analysis is already in the conversation.
/// Extractive fallback: if no reasoning follows, compress the output
/// using the embedding model or truncate.
async fn compact_conversation(
    input: &mut Vec<InputItem>,
    keep_recent: usize,
    embedding_model: Option<&dyn ModelBackend>,
    query: Option<&str>,
) {
    if input.len() <= keep_recent + 2 {
        return;
    }

    let compact_end = input.len() - keep_recent;
    let mut compacted = 0usize;

    for i in 1..compact_end {
        let is_tool_output = matches!(&input[i], InputItem::FunctionCallOutput(_));
        if !is_tool_output {
            continue;
        }

        let has_reasoning = i + 1 < compact_end && matches!(&input[i + 1], InputItem::Message(_));

        let (call_id, text) = match &input[i] {
            InputItem::FunctionCallOutput(fco) => {
                let t = match &fco.output {
                    FunctionCallOutputContent::Text(t) if t.len() > 200 => t.clone(),
                    _ => continue,
                };
                (fco.call_id.clone(), t)
            }
            _ => continue,
        };

        let compressed = if has_reasoning {
            "[compacted — model analysis follows]".to_string()
        } else if let (Some(model), Some(q)) = (embedding_model, query) {
            match compress_extractive(&text, q, model, 256).await {
                Ok(c) => c,
                Err(_) => navra_cognitive::truncate_to_budget(&text, 256),
            }
        } else {
            navra_cognitive::truncate_to_budget(&text, 256)
        };

        input[i] = InputItem::FunctionCallOutput(FunctionCallOutputItem {
            id: None,
            call_id,
            output: FunctionCallOutputContent::Text(compressed),
            status: Some(ItemStatus::Completed),
        });
        compacted += 1;
    }

    if compacted > 0 {
        tracing::info!(
            compacted_items = compacted,
            remaining_items = input.len(),
            "Compacted old conversation history"
        );
    }
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

    Err(format!(
        "Could not parse or repair JSON: {}",
        &input[..input.len().min(200)]
    ))
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
    config: &mut ToolLoopConfig,
    run_id: String,
) -> Result<ToolLoopResult, AgentError> {
    // Take the signal receiver out of config so we can mutably borrow it
    // across await points without holding a mutable borrow on config.
    let mut signal_rx = config.signal_rx.take();
    // Discover tools from MCP server, filtered by allowed_tools if set
    let mcp_tools = client.list_tools().await?;
    let tools: Vec<ResponseTool> = mcp_tools
        .iter()
        .filter(|t| {
            config
                .allowed_tools
                .as_ref()
                .map_or(true, |allowed| allowed.contains(&t.name))
        })
        .map(crate::convert::tool_def_to_response)
        .collect();

    if config.allowed_tools.is_some() {
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        eprintln!(
            "  [tool-filter] {} server tools → {} allowed: {:?}",
            mcp_tools.len(),
            tools.len(),
            tool_names
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

    let mut actions: Vec<ActionRecord> = Vec::new();
    let mut loop_detector = LoopDetector::new(config.loop_detection_threshold);
    let mut compressed_chars_saved: usize = 0;
    let mut budget_exhausted = false;

    // Circuit breaker state: token burn monitor
    let mut total_tokens_consumed: u64 = 0;

    // Circuit breaker state: tool call rate monitor (sliding 30s window)
    let mut call_timestamps: Vec<std::time::Instant> = Vec::new();
    let rate_window = std::time::Duration::from_secs(30);

    loop {
        // Check for cooperative signals between iterations
        if let Some(ref mut rx) = signal_rx {
            match rx.check() {
                AgentSignal::Interrupt => {
                    tracing::info!(run_id = %run_id, "Agent interrupted, returning partial result");
                    let text = if progress_iterations > 0 {
                        format!("[interrupted after {} iterations]", progress_iterations)
                    } else {
                        "[interrupted before first iteration]".to_string()
                    };
                    return Ok(ToolLoopResult {
                        run_id,
                        response: text,
                        iterations: progress_iterations,
                        input_tokens: total_input,
                        output_tokens: total_output,
                        taint: client.taint(),
                        actions,
                        compressed_chars_saved,
                        interrupted: true,
                    });
                }
                AgentSignal::Terminate => {
                    tracing::info!(run_id = %run_id, "Agent terminated");
                    let text = if progress_iterations > 0 {
                        format!("[terminated after {} iterations]", progress_iterations)
                    } else {
                        "[terminated before first iteration]".to_string()
                    };
                    return Ok(ToolLoopResult {
                        run_id,
                        response: text,
                        iterations: progress_iterations,
                        input_tokens: total_input,
                        output_tokens: total_output,
                        taint: client.taint(),
                        actions,
                        compressed_chars_saved,
                        interrupted: true,
                    });
                }
                AgentSignal::Pause => {
                    tracing::info!(run_id = %run_id, "Agent paused, waiting for resume");
                    rx.wait_for_resume().await;
                    tracing::info!(run_id = %run_id, "Agent resumed");
                }
                AgentSignal::None | AgentSignal::Resume => {}
            }
        }

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
                 more tools — produce your best answer with the information you have.",
            ));
        }
        let iteration = progress_iterations;
        // Set structured output format if persona defines a JSON schema
        let text_config = config.output_json_schema.as_ref().map(|schema| {
            navra_model::responses::request::TextConfig {
                format: Some(navra_model::ResponseFormat::JsonSchema {
                    name: "persona_output".to_string(),
                    description: None,
                    schema: schema.clone(),
                    strict: Some(true),
                }),
                verbosity: None,
            }
        });

        // Transparent RAG: retrieve context before each model call
        if let Some(ref retriever) = config.context_retriever {
            let estimated_input_tokens = (total_input as usize).max(user_prompt.len() / 4);
            let available = (config.context_window_tokens as usize)
                .saturating_sub(estimated_input_tokens)
                / 3;
            if available > 100 {
                let context = retriever.retrieve(user_prompt, available).await;
                if !context.is_empty() {
                    input.push(InputItem::system(&format!(
                        "[Retrieved context]\n{context}"
                    )));
                }
            }
        }

        // Move input into request instead of cloning — avoids doubling
        // memory. We take it back from the request after the model call.
        let mut request = CreateResponseRequest {
            model: String::new(),
            input: std::mem::take(&mut input),
            instructions: None,
            tools: if budget_exhausted {
                vec![]
            } else {
                tools.clone()
            },
            tool_choice: Some(if budget_exhausted {
                navra_model::ResponseToolChoice::none()
            } else if config
                .force_tool_iterations
                .is_some_and(|n| progress_iterations < n)
            {
                navra_model::ResponseToolChoice::required()
            } else {
                navra_model::ResponseToolChoice::auto()
            }),
            max_output_tokens: config.max_tokens,
            temperature: phase_temperature(&config.reasoning_phases, progress_iterations)
                .or(config.temperature),
            text: text_config,
            ..CreateResponseRequest::new(String::new(), vec![])
        };

        let response: ModelResponse = model.respond(&request).await?;

        // Take input back from the request (avoids reallocation)
        input = std::mem::take(&mut request.input);

        // Lightweight sensitive data check on model response
        if let Some(text) = response.text() {
            warn_if_sensitive(&text);
        }

        if let Some(ref usage) = response.usage {
            total_input += usage.input_tokens;
            total_output += usage.output_tokens;

            if let Some(ref sink) = config.audit_sink {
                let has_tool_calls = response
                    .output
                    .iter()
                    .any(|o| matches!(o, OutputItem::FunctionCall(_)));
                let resp_type = if has_tool_calls {
                    "tool_calls"
                } else if response.text().is_some() {
                    "text"
                } else {
                    "empty"
                };
                sink.log_model_call(
                    &run_id,
                    &run_id,
                    iteration as u32,
                    "",
                    usage.input_tokens,
                    usage.output_tokens,
                    resp_type,
                );
            }

            // Circuit breaker: token burn monitor
            total_tokens_consumed += (usage.input_tokens + usage.output_tokens) as u64;
            if total_tokens_consumed > config.max_tokens_per_run {
                tracing::warn!(
                    tokens = total_tokens_consumed,
                    limit = config.max_tokens_per_run,
                    iterations = progress_iterations,
                    "Token burn circuit breaker: agent exceeded max_tokens_per_run"
                );
                let text = response.text().unwrap_or_else(|| {
                    format!(
                        "Agent stopped: token budget exceeded ({} tokens consumed, limit {})",
                        total_tokens_consumed, config.max_tokens_per_run
                    )
                });
                return Ok(ToolLoopResult {
                    run_id,
                    response: text,
                    iterations: progress_iterations,
                    input_tokens: total_input,
                    output_tokens: total_output,
                    taint: client.taint(),
                    actions,
                    compressed_chars_saved,
                    interrupted: false,
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
                     Do not call any more tools.",
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
                actions,
                compressed_chars_saved,
                interrupted: false,
            });
        }

        // Check if this round is purely status-polling (non-progress)
        let all_non_progress = config
            .non_progress_tools
            .as_ref()
            .is_some_and(|npt| function_calls.iter().all(|fc| npt.contains(&fc.name)));

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
                let error_msg =
                    format!("Unknown tool '{}'. Available tools: {}", fc.name, available);
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

            let action = AgentAction::classify(&fc.name, &args);
            let loop_warning = loop_detector.record(&fc.name, &args);
            let call_start = std::time::Instant::now();
            let result = client.call_tool(&fc.name, args).await?;
            let duration_ms = call_start.elapsed().as_millis() as u64;
            let raw_text = extract_text(&result);

            if let Some(ref sink) = config.audit_sink {
                let truncated_result = if raw_text.len() > 4096 {
                    format!("{}…", &raw_text[..4096])
                } else {
                    raw_text.clone()
                };
                sink.log_tool_call(
                    &run_id,
                    &run_id,
                    iteration as u32,
                    &fc.name,
                    &fc.arguments,
                    &truncated_result,
                    duration_ms,
                );
            }

            let context_fill_ratio = if config.context_window_tokens > 0 {
                total_input as f32 / config.context_window_tokens as f32
            } else {
                0.0
            };
            let query = config.system_prompt.as_deref();
            let embed_model: Option<&dyn ModelBackend> =
                config.embedding_model.as_ref().map(|m| m.as_ref());
            let text = compress_tool_output(
                &raw_text,
                config.max_tool_output_tokens,
                context_fill_ratio,
                embed_model,
                query,
            )
            .await;
            if text.len() < raw_text.len() {
                tracing::info!(
                    tool = %fc.name,
                    original_chars = raw_text.len(),
                    compressed_chars = text.len(),
                    fill_ratio = %format!("{:.1}%", context_fill_ratio * 100.0),
                    "Compressed tool output to fit context budget"
                );
                compressed_chars_saved += raw_text.len() - text.len();
            }

            actions.push(ActionRecord {
                action,
                success: !result.is_error,
                duration_ms,
                output_preview: text.chars().take(200).collect(),
            });

            // Add the tool result to input
            input.push(InputItem::FunctionCallOutput(FunctionCallOutputItem {
                id: None,
                call_id: fc.call_id.clone(),
                output: FunctionCallOutputContent::Text(text),
                status: Some(ItemStatus::Completed),
            }));

            if let Some(warning) = loop_warning {
                tracing::warn!(
                    tool = %fc.name,
                    iteration,
                    "Loop detection triggered"
                );
                input.push(InputItem::Message(navra_model::MessageItem {
                    role: navra_model::MessageRole::System,
                    content: navra_model::MessageContent::Text(warning),
                    id: None,
                    status: None,
                }));
            }

            // Record timestamp for rate monitoring
            call_timestamps.push(std::time::Instant::now());
        }

        // Compact old conversation history to bound memory
        let est_tokens = estimate_input_tokens(&input);
        if est_tokens > config.context_window_tokens / 2 {
            let embed_ref: Option<&dyn ModelBackend> =
                config.embedding_model.as_ref().map(|m| m.as_ref());
            let query_ref = config.system_prompt.as_deref();
            compact_conversation(&mut input, 6, embed_ref, query_ref).await;
        }
    }
}

/// Check if text contains patterns that look like leaked secrets.
/// Logs a warning for each match but does not block execution.
fn warn_if_sensitive(text: &str) {
    let patterns = ["sk_live_", "sk_test_", "AKIA", "ghp_", "-----BEGIN"];
    for pattern in &patterns {
        if text.contains(pattern) {
            tracing::warn!(
                pattern = pattern,
                "Model response may contain sensitive data"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use navra_model::{
        MessageItem, ModelBackend, ModelError, ModelResponse, OutputItem, ResponseStatus,
    };
    use navra_protocol::upstream::{Transport, UpstreamError};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

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
        let upstream = navra_protocol::Upstream::connect("test", transport)
            .await
            .unwrap();
        McpClient::new(upstream)
    }

    fn stop_response(text: &str) -> ModelResponse {
        use navra_responses::response::Usage;
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
        use navra_responses::response::Usage;
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
        let mut config = ToolLoopConfig::default();

        let result = run_tool_loop(&model, &mut client, "Hi", &mut config, "test-run".into())
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
        let mut config = ToolLoopConfig::default();

        let result = run_tool_loop(
            &model,
            &mut client,
            "What's the git status?",
            &mut config,
            "test-run".into(),
        )
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
        let mut config = ToolLoopConfig {
            max_iterations: 3,
            ..Default::default()
        };

        let result = run_tool_loop(
            &model,
            &mut client,
            "loop forever",
            &mut config,
            "test-run".into(),
        )
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

        let mut config = ToolLoopConfig {
            max_iterations: 2, // would fail without non_progress_tools
            non_progress_tools: Some(vec!["team_status".to_string()]),
            ..Default::default()
        };

        let result = run_tool_loop(
            &model,
            &mut client,
            "poll then act",
            &mut config,
            "test-run".into(),
        )
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
            tool_call_response("git_status", r#"{"verbose": false}"#), // progress #1
            tool_call_response("git_status", r#"{"verbose": true}"#), // progress #2 → budget exhausted
            stop_response("Synthesized from partial work."),          // forced synthesis
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

        let mut config = ToolLoopConfig {
            max_iterations: 2,
            non_progress_tools: Some(vec!["team_status".to_string()]),
            ..Default::default()
        };

        let result = run_tool_loop(
            &model,
            &mut client,
            "overflow",
            &mut config,
            "test-run".into(),
        )
        .await
        .unwrap();
        assert_eq!(result.response, "Synthesized from partial work.");
    }

    #[test]
    fn extract_text_from_result() {
        let result = CallToolResult::success(vec![
            navra_protocol::Content::text("line 1"),
            navra_protocol::Content::text("line 2"),
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
        let pipeline = Arc::new(navra_safety::safety::build_pipeline("standard"));
        let model = MockModel::new(vec![stop_response(
            "The patient's SSN is 123-45-6789 and email is john@example.com",
        )]);
        let mut client = mock_client(vec![]).await;
        let mut config = ToolLoopConfig {
            pii_filter: Some(pipeline),
            ..Default::default()
        };

        let result = run_tool_loop(&model, &mut client, "Hi", &mut config, "test-run".into())
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
        let model = MockModel::new(vec![stop_response("The patient's SSN is 123-45-6789")]);
        let mut client = mock_client(vec![]).await;
        let mut config = ToolLoopConfig {
            pii_filter: None,
            ..Default::default()
        };

        let result = run_tool_loop(&model, &mut client, "Hi", &mut config, "test-run".into())
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
        let pipeline = Arc::new(navra_safety::safety::build_pipeline("standard"));
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
        let mut config = ToolLoopConfig {
            pii_filter: Some(pipeline),
            ..Default::default()
        };

        let result = run_tool_loop(
            &model,
            &mut client,
            "What's the git status?",
            &mut config,
            "test-run".into(),
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
        let mut client = mock_client(vec![
            tool_result.clone(),
            tool_result.clone(),
            tool_result.clone(),
            tool_result.clone(),
            tool_result,
        ])
        .await;
        let mut config = ToolLoopConfig {
            max_iterations: 10,
            ..Default::default()
        };

        let result =
            run_tool_loop(&model, &mut client, "loop", &mut config, "test-run".into()).await;
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
        let mut config = ToolLoopConfig {
            max_iterations: 10,
            ..Default::default()
        };

        let result = run_tool_loop(
            &model,
            &mut client,
            "read file",
            &mut config,
            "test-run".into(),
        )
        .await;
        assert!(
            result.is_ok(),
            "3 identical calls should not abort (threshold is 5)"
        );
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
        let mut config = ToolLoopConfig::default();

        let result = run_tool_loop(
            &model,
            &mut client,
            "Do something",
            &mut config,
            "test-run".into(),
        )
        .await
        .unwrap();
        // The model should have received the error about the unknown tool
        // and produced a final response
        assert_eq!(result.response, "I used the available tools.");
    }

    #[tokio::test]
    async fn compress_no_op_under_50_pct() {
        let text = "Short tool output.";
        let result = compress_tool_output(text, 4096, 0.3, None, None).await;
        assert_eq!(result, text);
    }

    #[tokio::test]
    async fn compress_progressive_scaling() {
        let text = "x".repeat(50_000);
        let at_40 = compress_tool_output(&text, 4096, 0.4, None, None).await;
        let at_60 = compress_tool_output(&text, 4096, 0.6, None, None).await;
        let at_75 = compress_tool_output(&text, 4096, 0.75, None, None).await;
        let at_85 = compress_tool_output(&text, 4096, 0.85, None, None).await;
        assert!(
            at_40.len() > at_60.len(),
            "60% fill should compress more than 40%"
        );
        assert!(
            at_60.len() > at_75.len(),
            "75% fill should compress more than 60%"
        );
        assert!(
            at_75.len() > at_85.len(),
            "85% fill should compress more than 75%"
        );
    }

    #[tokio::test]
    async fn compress_floor_prevents_empty() {
        let text = "x".repeat(50_000);
        let result = compress_tool_output(&text, 4096, 0.99, None, None).await;
        // Floor is 256 tokens ≈ 896 chars, plus truncation notice
        assert!(
            result.len() >= 800,
            "floor should prevent near-empty output: got {}",
            result.len()
        );
    }

    #[tokio::test]
    async fn compress_short_text_untouched() {
        let text = "Small result";
        // Even at high fill, text under the floor stays unchanged
        let result = compress_tool_output(text, 4096, 0.95, None, None).await;
        assert_eq!(result, text);
    }

    #[test]
    fn cosine_similarity_identical() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!(cosine_similarity(&a, &b).abs() < 1e-6);
    }

    #[test]
    fn split_paragraphs_prose() {
        let text = "First paragraph.\n\nSecond paragraph.\n\nThird paragraph.";
        let paras = split_paragraphs(text);
        assert_eq!(paras.len(), 3);
        assert_eq!(paras[0], "First paragraph.");
    }

    #[test]
    fn split_paragraphs_code_groups_by_10_lines() {
        let lines: Vec<String> = (0..25).map(|i| format!("line {i}")).collect();
        let text = lines.join("\n");
        let paras = split_paragraphs(&text);
        assert!(paras.len() >= 2, "25 lines should split into 2+ groups");
    }

    /// Simulate a realistic 10-tool-call review flow and measure savings.
    ///
    /// Models a code review agent reading files of varying sizes across
    /// a session that progressively fills the context window.
    #[tokio::test]
    async fn compression_impact_simulation() {
        let tool_outputs: Vec<(&str, usize)> = vec![
            ("file_read (small config)", 800),
            ("file_read (medium module)", 8_000),
            ("file_read (large module)", 25_000),
            ("git_diff", 15_000),
            ("file_read (test file)", 20_000),
            ("file_search (FTS5)", 12_000),
            ("file_read (lib.rs)", 35_000),
            ("git_log", 5_000),
            ("file_read (handlers.rs)", 45_000),
            ("file_read (main.rs)", 30_000),
        ];

        let context_window: u32 = 128_000;
        let max_tool_output: u32 = 4096;
        let mut total_raw: usize = 0;
        let mut total_compressed: usize = 0;
        let mut context_used: u32 = 5_000; // system prompt

        println!("\n--- Compression Impact Simulation (128K context, 4096 cap) ---");
        println!(
            "{:<30} {:>8} {:>8} {:>6} {:>6}",
            "Tool", "Raw", "Comp", "Saved", "Fill%"
        );
        println!("{}", "-".repeat(66));

        for (name, size) in &tool_outputs {
            let text = "x".repeat(*size);
            let fill = context_used as f32 / context_window as f32;
            let compressed = compress_tool_output(&text, max_tool_output, fill, None, None).await;

            let saved = size - compressed.len();
            total_raw += size;
            total_compressed += compressed.len();

            println!(
                "{:<30} {:>8} {:>8} {:>6} {:>5.1}%",
                name,
                size,
                compressed.len(),
                saved,
                fill * 100.0
            );

            // Simulate context growth (compressed output + model reasoning)
            context_used += navra_cognitive::estimate_tokens(&compressed) + 500;
        }

        let total_saved = total_raw - total_compressed;
        let saving_pct = total_saved as f64 / total_raw as f64 * 100.0;
        println!("{}", "-".repeat(66));
        println!(
            "{:<30} {:>8} {:>8} {:>6} ({:.1}% saved)",
            "TOTAL", total_raw, total_compressed, total_saved, saving_pct
        );

        // The feature should save at least 30% across a typical session
        assert!(
            saving_pct > 30.0,
            "Expected >30% savings, got {:.1}%",
            saving_pct
        );
    }

    /// Test extractive compression with the Granite embedding model.
    /// Skipped if the model files are not present.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compress_extractive_keeps_relevant_content() {
        let home = std::env::var("HOME").unwrap_or_default();
        let model_path = std::path::PathBuf::from(&home)
            .join(".local/share/navra/models/granite-embedding-r2-onnx/model.onnx");
        if !model_path.exists() {
            eprintln!(
                "Skipping: Granite embedding model not found at {}",
                model_path.display()
            );
            return;
        }

        let tokenizer_path = model_path.parent().unwrap().join("tokenizer.json");
        let model = navra_model::OnnxBackend::load(
            "test-embed",
            &model_path,
            Some(&tokenizer_path),
            navra_model::ModelTask::Embedding { dimensions: 384 },
            navra_model::Device::Cpu,
        )
        .expect("Failed to load embedding model");

        // Simulate a file with mixed-relevance content.
        // Query is about security; paragraphs 2 and 4 are security-related.
        let text = "\
Configuration module for the application server.\n\
Loads settings from TOML files with environment variable overrides.\n\
\n\
Authentication uses BLAKE3 tokens with configurable expiry.\n\
Capability tokens support privilege attenuation and delegation chains.\n\
All token validation runs through the security middleware.\n\
\n\
The logging subsystem writes structured JSON to stderr.\n\
Log levels are configurable per module via RUST_LOG.\n\
Rotation is handled by the systemd journal.\n\
\n\
Access control uses deny-wins ACL evaluation.\n\
Path traversal attempts are blocked after canonicalization.\n\
IFC labels propagate through the tool call chain.\n\
\n\
The metrics endpoint exposes Prometheus counters.\n\
Request latency is tracked per tool and per session.\n\
Memory usage is sampled every 30 seconds.";

        let query = "Review the security model and access control mechanisms.";

        let result = compress_extractive(text, query, &model, 120)
            .await
            .expect("Extractive compression should succeed");

        println!("\n--- Extractive Compression Test ---");
        println!("Query: {query}");
        println!(
            "Input: {} chars, {} paragraphs",
            text.len(),
            split_paragraphs(text).len()
        );
        println!("Output: {} chars", result.len());
        println!("Result:\n{result}");

        // Security-related paragraphs should be kept
        assert!(
            result.contains("BLAKE3") || result.contains("deny-wins") || result.contains("IFC"),
            "Extractive compression should keep security-related content"
        );
        assert!(
            result.contains("[extracted"),
            "Should include extraction notice"
        );
    }

    /// Compare truncation vs extractive compression on realistic content.
    /// Measures: output size, relevance (keyword hits), and latency.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compression_ab_comparison() {
        let home = std::env::var("HOME").unwrap_or_default();
        let model_path = std::path::PathBuf::from(&home)
            .join(".local/share/navra/models/granite-embedding-r2-onnx/model.onnx");
        if !model_path.exists() {
            eprintln!("Skipping: Granite embedding model not found");
            return;
        }
        let tokenizer_path = model_path.parent().unwrap().join("tokenizer.json");
        let model = navra_model::OnnxBackend::load(
            "test-embed",
            &model_path,
            Some(&tokenizer_path),
            navra_model::ModelTask::Embedding { dimensions: 384 },
            navra_model::Device::Cpu,
        )
        .expect("Failed to load embedding model");

        // Realistic file content: a Rust module with security and non-security code.
        // Security-relevant keywords: auth, token, ACL, deny, taint, IFC, permission
        let file_content = "\
use std::collections::HashMap;\n\
use serde::{Deserialize, Serialize};\n\
\n\
/// Server configuration loaded from TOML.\n\
#[derive(Debug, Clone, Deserialize)]\n\
pub struct Config {\n\
    pub listen_addr: String,\n\
    pub port: u16,\n\
    pub log_level: String,\n\
    pub max_connections: usize,\n\
}\n\
\n\
/// Authentication token with BLAKE3 hashing and expiry.\n\
/// Tokens are capability-scoped: each token carries a set of\n\
/// allowed operations and tool patterns. The deny-wins ACL\n\
/// engine evaluates these against the request path.\n\
pub struct AuthToken {\n\
    pub hash: [u8; 32],\n\
    pub capabilities: CapabilitySet,\n\
    pub expires_at: u64,\n\
    pub nonce: u64,\n\
}\n\
\n\
impl AuthToken {\n\
    pub fn validate(&self, signer: &dyn Signer) -> bool {\n\
        let now = current_timestamp();\n\
        self.expires_at > now && signer.verify(&self.hash)\n\
    }\n\
}\n\
\n\
/// Database connection pool with health checks.\n\
pub struct DbPool {\n\
    connections: Vec<Connection>,\n\
    max_size: usize,\n\
    timeout_ms: u64,\n\
}\n\
\n\
impl DbPool {\n\
    pub fn acquire(&self) -> Option<&Connection> {\n\
        self.connections.iter().find(|c| c.is_idle())\n\
    }\n\
    pub fn health_check(&self) -> bool {\n\
        self.connections.iter().all(|c| c.ping().is_ok())\n\
    }\n\
}\n\
\n\
/// IFC taint tracker implementing Bell-LaPadula.\n\
/// Taint only rises: once a session reads sensitive data,\n\
/// it cannot write to lower-classified destinations.\n\
/// The no-write-down property prevents data exfiltration\n\
/// through tool call chains.\n\
pub struct TaintTracker {\n\
    current_label: DataLabel,\n\
}\n\
\n\
impl TaintTracker {\n\
    pub fn absorb(&mut self, label: DataLabel) {\n\
        self.current_label = self.current_label.join(label);\n\
    }\n\
    pub fn can_write_to(&self, target: &DataLabel) -> bool {\n\
        self.current_label <= *target\n\
    }\n\
}\n\
\n\
/// Prometheus metrics endpoint.\n\
pub fn metrics_handler() -> String {\n\
    let mut output = String::new();\n\
    output.push_str(\"# HELP request_count Total requests\\n\");\n\
    output.push_str(\"# TYPE request_count counter\\n\");\n\
    output\n\
}\n\
\n\
/// Permission engine with deny-wins ACL evaluation.\n\
/// Deny rules always beat allow rules. Path canonicalization\n\
/// runs before ACL check to prevent traversal attacks.\n\
pub fn check_permission(path: &str, agent: &str, acls: &[AclRule]) -> bool {\n\
    let canonical = canonicalize(path);\n\
    let dominated_by_deny = acls.iter()\n\
        .filter(|r| r.matches(&canonical, agent))\n\
        .any(|r| r.effect == Effect::Deny);\n\
    if dominated_by_deny { return false; }\n\
    acls.iter()\n\
        .filter(|r| r.matches(&canonical, agent))\n\
        .any(|r| r.effect == Effect::Allow)\n\
}\n\
\n\
/// Template engine for rendering HTML responses.\n\
pub fn render_template(name: &str, vars: &HashMap<String, String>) -> String {\n\
    let template = load_template(name);\n\
    vars.iter().fold(template, |acc, (k, v)| acc.replace(&format!(\"{{{{ {k} }}}}\"), v))\n\
}";

        let query =
            "Review the security model: authentication, authorization, and data flow controls.";
        let budget: u32 = 350;

        // --- Truncation ---
        let trunc_start = std::time::Instant::now();
        let truncated = navra_cognitive::truncate_to_budget(file_content, budget);
        let trunc_ms = trunc_start.elapsed().as_micros();

        // --- Extractive ---
        let extract_start = std::time::Instant::now();
        let extracted = compress_extractive(file_content, query, &model, budget)
            .await
            .expect("Extractive compression should succeed");
        let extract_ms = extract_start.elapsed().as_millis();

        // --- Relevance scoring ---
        let security_keywords = [
            "auth",
            "token",
            "BLAKE3",
            "capability",
            "deny",
            "ACL",
            "taint",
            "IFC",
            "Bell-LaPadula",
            "permission",
            "traversal",
            "no-write-down",
            "exfiltration",
            "canonicalize",
        ];

        let trunc_hits: usize = security_keywords
            .iter()
            .filter(|kw| truncated.contains(*kw))
            .count();
        let extract_hits: usize = security_keywords
            .iter()
            .filter(|kw| extracted.contains(*kw))
            .count();

        let trunc_tokens = navra_cognitive::estimate_tokens(&truncated);
        let extract_tokens = navra_cognitive::estimate_tokens(&extracted);

        println!("\n=== Compression A/B Comparison ===");
        println!(
            "Input: {} chars, {} tokens (est.), {} paragraphs",
            file_content.len(),
            navra_cognitive::estimate_tokens(file_content),
            split_paragraphs(file_content).len()
        );
        println!("Budget: {} tokens", budget);
        println!("Query: {query}");
        println!();
        println!("{:<20} {:>12} {:>12}", "", "Truncation", "Extractive");
        println!("{}", "-".repeat(46));
        println!(
            "{:<20} {:>12} {:>12}",
            "Output chars",
            truncated.len(),
            extracted.len()
        );
        println!(
            "{:<20} {:>12} {:>12}",
            "Output tokens (est.)", trunc_tokens, extract_tokens
        );
        println!(
            "{:<20} {:>10}/{:<2} {:>10}/{:<2}",
            "Security keywords",
            trunc_hits,
            security_keywords.len(),
            extract_hits,
            security_keywords.len()
        );
        println!("{:<20} {:>11}µs {:>11}ms", "Latency", trunc_ms, extract_ms);
        println!();

        // Extractive should find MORE security keywords in same token budget
        println!("Truncation kept:");
        for kw in &security_keywords {
            if truncated.contains(*kw) {
                print!("  ✓ {kw}");
            }
        }
        println!();
        println!("Extractive kept:");
        for kw in &security_keywords {
            if extracted.contains(*kw) {
                print!("  ✓ {kw}");
            }
        }
        println!();

        assert!(extract_hits >= trunc_hits,
            "Extractive ({} hits) should keep at least as many security keywords as truncation ({} hits)",
            extract_hits, trunc_hits);
    }

    #[tokio::test]
    async fn compact_replaces_old_output_when_reasoning_exists() {
        let mut input = vec![
            InputItem::system("You are a reviewer."),
            // Iteration 1: tool call + big result + model reasoning
            InputItem::FunctionCall(FunctionCallItem {
                id: None,
                call_id: "c1".into(),
                name: "file_read".into(),
                arguments: "{}".into(),
                status: None,
            }),
            InputItem::FunctionCallOutput(FunctionCallOutputItem {
                id: None,
                call_id: "c1".into(),
                output: FunctionCallOutputContent::Text("x".repeat(5000)),
                status: Some(ItemStatus::Completed),
            }),
            InputItem::user("The file contains important security patterns."),
            // Iteration 2: recent items (should be kept)
            InputItem::FunctionCall(FunctionCallItem {
                id: None,
                call_id: "c2".into(),
                name: "file_read".into(),
                arguments: "{}".into(),
                status: None,
            }),
            InputItem::FunctionCallOutput(FunctionCallOutputItem {
                id: None,
                call_id: "c2".into(),
                output: FunctionCallOutputContent::Text("y".repeat(5000)),
                status: Some(ItemStatus::Completed),
            }),
        ];

        assert_eq!(input.len(), 6);

        // keep_recent=2 means keep last 2 items (c2 call + result)
        compact_conversation(&mut input, 2, None, None).await;

        assert_eq!(input.len(), 6, "item count stays the same (in-place)");

        // Old tool output (item 2) should be compacted
        if let InputItem::FunctionCallOutput(fco) = &input[2] {
            let text = match &fco.output {
                FunctionCallOutputContent::Text(t) => t.clone(),
                _ => panic!("expected text"),
            };
            assert!(
                text.len() < 100,
                "old output should be compacted, got {} chars",
                text.len()
            );
            assert!(
                text.contains("compacted"),
                "should contain compaction marker"
            );
        } else {
            panic!("item 2 should still be FunctionCallOutput");
        }

        // Recent tool output (item 5) should be untouched
        if let InputItem::FunctionCallOutput(fco) = &input[5] {
            let text = match &fco.output {
                FunctionCallOutputContent::Text(t) => t.clone(),
                _ => panic!("expected text"),
            };
            assert_eq!(text.len(), 5000, "recent output should be untouched");
        }
    }

    #[tokio::test]
    async fn compact_noop_when_short() {
        let mut input = vec![InputItem::system("prompt"), InputItem::user("hello")];
        compact_conversation(&mut input, 6, None, None).await;
        assert_eq!(input.len(), 2);
    }

    #[test]
    fn estimate_tokens_basic() {
        let input = vec![
            InputItem::system("You are helpful."),
            InputItem::FunctionCallOutput(FunctionCallOutputItem {
                id: None,
                call_id: "c1".into(),
                output: FunctionCallOutputContent::Text("x".repeat(3500)),
                status: None,
            }),
        ];
        let est = estimate_input_tokens(&input);
        // "You are helpful." ≈ 5 tokens, 3500 chars ≈ 1000 tokens
        assert!(
            est > 900 && est < 1200,
            "estimate should be ~1005, got {}",
            est
        );
    }

    // --- Signal delivery tests ---

    #[tokio::test]
    async fn signal_interrupt_breaks_loop() {
        use crate::signal::SignalHandle;

        let model = MockModel::new(vec![
            tool_call_response("git_status", "{}"),
            tool_call_response("git_status", r#"{"verbose": true}"#),
            stop_response("Should not reach here."),
        ]);
        let tool_result = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": "ok"}],
                "isError": false
            },
            "id": 4
        });
        let mut client = mock_client(vec![tool_result.clone(), tool_result]).await;

        let (handle, rx) = SignalHandle::new();
        // Send interrupt before the loop starts — it will be caught
        // at the top of the second iteration
        handle.send(AgentSignal::Interrupt);

        let mut config = ToolLoopConfig {
            signal_rx: Some(rx),
            ..Default::default()
        };

        let result = run_tool_loop(
            &model,
            &mut client,
            "Do work",
            &mut config,
            "test-run".into(),
        )
        .await
        .unwrap();
        assert!(result.interrupted, "Result should be marked as interrupted");
        assert!(
            result.response.contains("interrupted"),
            "Response should mention interruption: {}",
            result.response
        );
    }

    #[tokio::test]
    async fn signal_terminate_breaks_loop() {
        use crate::signal::SignalHandle;

        let model = MockModel::new(vec![
            tool_call_response("git_status", "{}"),
            stop_response("Should not reach here."),
        ]);
        let tool_result = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": "ok"}],
                "isError": false
            },
            "id": 4
        });
        let mut client = mock_client(vec![tool_result]).await;

        let (handle, rx) = SignalHandle::new();
        handle.send(AgentSignal::Terminate);

        let mut config = ToolLoopConfig {
            signal_rx: Some(rx),
            ..Default::default()
        };

        let result = run_tool_loop(
            &model,
            &mut client,
            "Do work",
            &mut config,
            "test-run".into(),
        )
        .await
        .unwrap();
        assert!(result.interrupted);
        assert!(result.response.contains("terminated"));
    }

    #[tokio::test]
    async fn signal_pause_resume_continues() {
        use crate::signal::SignalHandle;

        let model = MockModel::new(vec![stop_response("Hello after resume!")]);
        let mut client = mock_client(vec![]).await;

        let (handle, rx) = SignalHandle::new();
        handle.send(AgentSignal::Pause);

        // Resume after a short delay
        let handle2 = handle.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            handle2.send(AgentSignal::Resume);
        });

        let mut config = ToolLoopConfig {
            signal_rx: Some(rx),
            ..Default::default()
        };

        let result = run_tool_loop(&model, &mut client, "Hi", &mut config, "test-run".into())
            .await
            .unwrap();
        assert_eq!(result.response, "Hello after resume!");
        assert!(!result.interrupted);
    }

    #[tokio::test]
    async fn no_signal_continues_normally() {
        use crate::signal::SignalHandle;

        let model = MockModel::new(vec![stop_response("Hello!")]);
        let mut client = mock_client(vec![]).await;

        let (_handle, rx) = SignalHandle::new();
        let mut config = ToolLoopConfig {
            signal_rx: Some(rx),
            ..Default::default()
        };

        let result = run_tool_loop(&model, &mut client, "Hi", &mut config, "test-run".into())
            .await
            .unwrap();
        assert_eq!(result.response, "Hello!");
        assert!(!result.interrupted);
    }

    #[tokio::test]
    async fn no_signal_rx_continues_normally() {
        // Default config (no signal_rx) should work as before
        let model = MockModel::new(vec![stop_response("Hello!")]);
        let mut client = mock_client(vec![]).await;
        let mut config = ToolLoopConfig::default();

        let result = run_tool_loop(&model, &mut client, "Hi", &mut config, "test-run".into())
            .await
            .unwrap();
        assert_eq!(result.response, "Hello!");
        assert!(!result.interrupted);
    }

    #[test]
    fn loop_detector_triggers_at_threshold() {
        let mut detector = LoopDetector::new(3);
        let args = serde_json::json!({"path": "/src/main.rs"});
        assert!(detector.record("file_edit", &args).is_none());
        assert!(detector.record("file_edit", &args).is_none());
        let warning = detector.record("file_edit", &args);
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("Reconsider"));
    }

    #[test]
    fn loop_detector_disabled_when_zero() {
        let mut detector = LoopDetector::new(0);
        let args = serde_json::json!({"path": "/x"});
        for _ in 0..10 {
            assert!(detector.record("file_edit", &args).is_none());
        }
    }

    #[test]
    fn loop_detector_different_targets_independent() {
        let mut detector = LoopDetector::new(2);
        let a = serde_json::json!({"path": "/a.rs"});
        let b = serde_json::json!({"path": "/b.rs"});
        assert!(detector.record("file_edit", &a).is_none());
        assert!(detector.record("file_edit", &b).is_none());
        // Second call to each — hits threshold
        let wa = detector.record("file_edit", &a);
        assert!(wa.is_some());
        let wb = detector.record("file_edit", &b);
        assert!(wb.is_some());
    }

    #[test]
    fn phase_temperature_selects_correct_phase() {
        let phases = vec![(0, 2, 0.1), (2, 8, 0.0), (8, 10, 0.1)];
        assert_eq!(phase_temperature(&phases, 0), Some(0.1));
        assert_eq!(phase_temperature(&phases, 1), Some(0.1));
        assert_eq!(phase_temperature(&phases, 2), Some(0.0));
        assert_eq!(phase_temperature(&phases, 7), Some(0.0));
        assert_eq!(phase_temperature(&phases, 8), Some(0.1));
        assert_eq!(phase_temperature(&phases, 10), None);
    }

    #[test]
    fn phase_temperature_empty_returns_none() {
        assert_eq!(phase_temperature(&[], 5), None);
    }
}
