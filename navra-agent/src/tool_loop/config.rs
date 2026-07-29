use crate::action::ActionRecord;
use crate::block::ToolBlock;
use crate::error::AgentError;
use crate::signal::SignalReceiver;
use navra_model::{EmbedRequest, InputItem, ModelBackend, ModelResponse};
use navra_protocol::CallToolResult;
use navra_protocol::label::DataLabel;
use navra_protocol::truncate_str;
use navra_safety_hooks::hooks::HookPipeline;
use navra_safety_hooks::safety::{FilterContext, FilterPipeline};
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
    /// Used to compute fill ratio for compression and compaction.
    pub context_window_tokens: u32,
    /// Maximum tokens for a single tool result when compression is enabled.
    /// When `None`, derived as `(context_window_tokens / 20).clamp(512, 16384)`.
    pub max_tool_output_tokens: Option<u32>,
    /// Context fill ratio at which tool output compression activates.
    /// `None` = compression disabled (default). `Some(0.9)` = compress at 90% fill.
    pub compression_start_ratio: Option<f32>,
    /// Number of recent input items kept verbatim during compaction.
    /// When `None`, derived as `(context_window_tokens / 16000).clamp(4, 20)`.
    pub compaction_keep_recent: Option<usize>,
    /// Context fill ratio at which conversation compaction triggers.
    /// When `None`, defaults to 0.6.
    pub compaction_trigger_ratio: Option<f32>,
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
    /// Optional hook pipeline for intercepting model calls.
    /// When set, pre_model_call/post_model_call hooks run around
    /// each model.respond() invocation.
    pub hook_pipeline: Option<Arc<HookPipeline>>,
    /// Optional fallback model for refusal recovery.
    /// When the primary model refuses a request, the gateway
    /// retries with this model before propagating the refusal.
    pub fallback_model: Option<Arc<dyn ModelBackend>>,
    /// Directory for writing Hermes-format JSONL trace files.
    /// When set, a `TraceRecord` is written to
    /// `{trace_export_dir}/{run_id}.jsonl` after each run.
    pub trace_export_dir: Option<std::path::PathBuf>,
    /// Optional PII sanitizer applied to trace messages before export.
    pub content_sanitizer: Option<crate::trace::ContentSanitizer>,
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
            max_tokens_per_run: u64::MAX,
            max_calls_per_window: 20,
            context_window_tokens: 128_000,
            max_tool_output_tokens: None,
            compression_start_ratio: None,
            compaction_keep_recent: None,
            compaction_trigger_ratio: None,
            embedding_model: None,
            audit_sink: None,
            signal_rx: None,
            loop_detection_threshold: 3,
            reasoning_phases: Vec::new(),
            context_retriever: None,
            hook_pipeline: None,
            fallback_model: None,
            trace_export_dir: None,
            content_sanitizer: None,
        }
    }
}

impl ToolLoopConfig {
    pub(super) fn effective_max_tool_output_tokens(&self) -> u32 {
        self.max_tool_output_tokens
            .unwrap_or_else(|| (self.context_window_tokens / 20).clamp(512, 16384))
    }

    pub(super) fn effective_keep_recent(&self) -> usize {
        self.compaction_keep_recent
            .unwrap_or_else(|| (self.context_window_tokens as usize / 16000).clamp(4, 20))
    }

    pub(super) fn effective_compaction_trigger(&self) -> f32 {
        self.compaction_trigger_ratio.unwrap_or(0.6)
    }
}

/// Get the temperature override for a given iteration based on
/// reasoning phases. Returns None if no phase matches.
pub(super) fn phase_temperature(phases: &[(usize, usize, f32)], iteration: usize) -> Option<f32> {
    phases
        .iter()
        .find(|(start, end, _)| iteration >= *start && iteration < *end)
        .map(|(_, _, temp)| *temp)
}

/// Loop detection: track (tool_name, primary_arg) call counts.
pub(super) struct LoopDetector {
    counts: std::collections::HashMap<String, usize>,
    threshold: usize,
}

impl LoopDetector {
    pub(super) fn new(threshold: usize) -> Self {
        Self {
            counts: std::collections::HashMap::new(),
            threshold,
        }
    }

    pub(super) fn record(&mut self, tool_name: &str, args: &serde_json::Value) -> Option<String> {
        if self.threshold == 0 {
            return None;
        }
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let canonical = args.to_string();
        canonical.hash(&mut hasher);
        let key = format!("{tool_name}:{:016x}", hasher.finish());
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
    /// Structured tool execution blocks for every tool call in this run.
    pub blocks: Vec<ToolBlock>,
    /// Total characters saved by tool output compression.
    pub compressed_chars_saved: usize,
    /// Whether the run was stopped by a signal (Interrupt or Terminate).
    pub interrupted: bool,
}

/// Extract text content from a [`CallToolResult`].
pub fn extract_text(result: &CallToolResult) -> String {
    use navra_protocol::compat::content_as_text;
    let mut parts = Vec::new();
    if result.is_error == Some(true) {
        parts.push("Error: ".to_string());
    }
    for content in &result.content {
        if let Some(text) = content_as_text(content) {
            parts.push(text.to_string());
        }
    }
    parts.join("")
}

/// Filter text through the PII pipeline, if configured.
///
/// Returns the filtered text, or the original text if no filter is set
/// or the filter encounters an error (graceful degradation).
pub(super) async fn filter_pii(text: &str, pipeline: &FilterPipeline) -> String {
    let ctx = FilterContext {
        agent_name: "agent",
        operation: "model_response",
        path: None,
    };
    match pipeline.process_outbound(text, &ctx).await {
        Ok(filtered) => filtered,
        Err(_) => {
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
pub(super) fn truncate_reasoning(text: &str, max_tokens: usize) -> String {
    let max_chars = max_tokens * 4;
    if text.len() <= max_chars {
        return text.to_string();
    }
    let truncated = truncate_str(text, max_chars);
    let end = if let Some(space) = truncated.rfind(' ') {
        space
    } else {
        truncated.len()
    };
    format!(
        "{}\n\n[reasoning truncated at {} tokens — continue with action]",
        &text[..end],
        max_tokens
    )
}

/// Compute effective token limit based on context fill ratio.
///
/// Linear scaling: no compression below `start`, scales down to 25%
/// of the budget as context approaches 100% fill.
pub(super) fn effective_token_limit(
    max_tool_output_tokens: u32,
    context_fill_ratio: f32,
    start: f32,
) -> u32 {
    if context_fill_ratio < start {
        return max_tool_output_tokens;
    }
    let pressure = (context_fill_ratio - start) / (1.0 - start);
    let scale = 1.0 - (pressure * 0.75); // 1.0 at start, 0.25 at 100%
    (max_tool_output_tokens as f32 * scale).max(256.0) as u32
}

/// Compress tool output, using extractive compression when an embedding
/// model is available, falling back to truncation otherwise.
pub(super) async fn compress_tool_output(
    text: &str,
    max_tool_output_tokens: u32,
    context_fill_ratio: f32,
    compression_start: f32,
    embedding_model: Option<&dyn ModelBackend>,
    query: Option<&str>,
) -> String {
    let effective_limit = effective_token_limit(
        max_tool_output_tokens,
        context_fill_ratio,
        compression_start,
    );
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

pub(crate) fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    let denom = na.sqrt() * nb.sqrt();
    if denom == 0.0 { 0.0 } else { dot / denom }
}

/// Split text into paragraphs. Uses double newline for prose,
/// falls back to groups of lines for code-like content.
pub(crate) fn split_paragraphs(text: &str) -> Vec<&str> {
    let paragraphs: Vec<&str> = text
        .split("\n\n")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();
    if paragraphs.len() >= 3 {
        return paragraphs;
    }
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
pub(crate) async fn compress_extractive(
    text: &str,
    query: &str,
    model: &dyn ModelBackend,
    max_tokens: u32,
) -> Result<String, AgentError> {
    let paragraphs = split_paragraphs(text);
    if paragraphs.len() <= 1 {
        return Ok(navra_cognitive::truncate_to_budget(text, max_tokens));
    }

    let query_text = truncate_str(query, 512);
    let query_embedding = model
        .embed(&EmbedRequest {
            text: query_text.to_string(),
        })
        .await?;

    let mut scored: Vec<(usize, f32, &str)> = Vec::with_capacity(paragraphs.len());
    for (i, para) in paragraphs.iter().enumerate() {
        let para_text = truncate_str(para, 1024);
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

    if selected.is_empty()
        && let Some((_, _, best)) = scored.first()
    {
        return Ok(navra_cognitive::truncate_to_budget(best, max_tokens));
    }

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
pub(super) fn estimate_input_tokens(input: &[InputItem]) -> u32 {
    let mut total = 0u32;
    for item in input {
        total += match item {
            InputItem::FunctionCallOutput(fco) => match &fco.output {
                navra_model::FunctionCallOutputContent::Text(t) => {
                    navra_cognitive::estimate_tokens(t)
                }
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
pub(super) fn compact_conversation(input: &mut Vec<InputItem>, keep_recent: usize) {
    if input.len() <= keep_recent + 2 {
        return;
    }

    let compact_end = input.len() - keep_recent;

    let mut drop_call_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for item in input[1..compact_end].iter() {
        if let InputItem::FunctionCallOutput(fco) = item {
            drop_call_ids.insert(fco.call_id.clone());
        }
    }

    if drop_call_ids.is_empty() {
        return;
    }

    let before = input.len();
    let mut idx = 0;
    input.retain(|item| {
        idx += 1;
        if idx > compact_end {
            return true;
        }
        match item {
            InputItem::FunctionCall(fc) => !drop_call_ids.contains(&fc.call_id),
            InputItem::FunctionCallOutput(fco) => !drop_call_ids.contains(&fco.call_id),
            _ => true,
        }
    });

    let dropped = before - input.len();
    if dropped > 0 {
        tracing::info!(
            dropped_items = dropped,
            remaining_items = input.len(),
            "Dropped old tool call pairs from conversation history"
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
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(input) {
        return Ok(v);
    }

    let mut text = input.to_string();

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
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            return Ok(v);
        }
    }

    let re_trailing = regex_lite::Regex::new(r",(\s*[}\]])").unwrap();
    text = re_trailing.replace_all(&text, "$1").to_string();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        return Ok(v);
    }

    let re_unquoted = regex_lite::Regex::new(r"(?m)([{\s,])(\w+)\s*:").unwrap();
    text = re_unquoted.replace_all(&text, r#"$1"$2":"#).to_string();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        return Ok(v);
    }

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

/// Write a trace record for a completed tool loop run.
pub(super) fn export_trace(
    result: &ToolLoopResult,
    config: &ToolLoopConfig,
    system_prompt: Option<&str>,
    user_prompt: &str,
) {
    let dir = match &config.trace_export_dir {
        Some(d) => d,
        None => return,
    };
    let success = !result.interrupted && !result.response.contains("Agent stopped:");
    let mut record = crate::trace::TraceExporter::build_record(
        system_prompt,
        user_prompt,
        &result.blocks,
        &result.response,
        &result.run_id,
        result.iterations,
        result.input_tokens,
        result.output_tokens,
        success,
    );
    if let Some(ref sanitizer) = config.content_sanitizer {
        record.sanitize(sanitizer);
    }
    if let Err(e) = record.write_to_dir(dir) {
        tracing::warn!(error = %e, dir = %dir.display(), "Failed to write trace record");
    }
}

pub(super) const REFUSAL_PATTERNS: &[&str] = &[
    "i cannot",
    "i can't",
    "i'm unable to",
    "i am unable to",
    "i'm not able to",
    "as an ai",
    "i must decline",
    "i cannot assist with",
];

pub(super) fn detect_model_refusal(response: &ModelResponse) -> bool {
    if let Some(text) = response.text() {
        if text.is_empty() {
            return false;
        }
        let lower = text.to_lowercase();
        return text.len() < 500 && REFUSAL_PATTERNS.iter().any(|p| lower.contains(p));
    }
    false
}

/// Check if text contains patterns that look like leaked secrets.
/// Logs a warning for each match but does not block execution.
pub(super) fn warn_if_sensitive(text: &str) {
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
