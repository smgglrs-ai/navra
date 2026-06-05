//! navra-model: Model inference backends.
//!
//! Provides a unified [`ModelBackend`] trait using the
//! [Open Responses](https://openresponses.org) specification as the
//! canonical model I/O interface. Backends translate to their native
//! wire format internally:
//!
//! - [`OpenAiBackend`] — Chat Completions API (Ollama, vLLM)
//! - [`AnthropicBackend`] — Messages API (Claude)
//! - [`OnnxBackend`] — In-process ONNX Runtime (embeddings, safety)
//!
//! `ModelBackend` methods:
//! - `respond()` / `respond_stream()` — multi-turn completion with tools
//! - `embed()` — text embeddings, `classify()` — content safety
//! - `generate()` — simple single-turn, `transcribe()` / `synthesize()` — audio

mod anthropic;
/// Chat Completions types used for backend translation and streaming.
pub mod chat;
pub mod cli;
pub(crate) mod http_common;
mod ogx;
mod onnx;
mod openai;
pub mod safe_backend;

pub use anthropic::AnthropicBackend;
pub use cli::CliBackend;
pub use ogx::{OgxBackend, DEFAULT_OGX_URL};
pub use onnx::{Device, ModelTask, OnnxBackend, OpenVinoDevice};
pub use openai::OpenAiBackend;
pub use safe_backend::{ModelSafetyFilter, SafeModelBackend};

// Re-export Open Responses types as the public model I/O interface.
pub use navra_responses::{
    self as responses, CreateResponseRequest, FunctionCallItem, FunctionCallOutputContent,
    FunctionCallOutputItem, FunctionTool as ResponseTool, InputContent, InputItem, ItemStatus,
    MessageContent, MessageItem, MessageRole, OutputContent, OutputItem, ReasoningItem,
    Response as ModelResponse, ResponseFormat, ResponseStatus, StreamEvent,
    ToolChoice as ResponseToolChoice,
};

use futures_util::stream::Stream;
use std::future::Future;
use std::pin::Pin;

/// Error type for model operations.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("model not loaded: {0}")]
    NotLoaded(String),
    #[error("inference failed: {0}")]
    Inference(String),
    #[error("tokenization failed: {0}")]
    Tokenization(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("API error: {0}")]
    Api(String),
}

// --- Embedding ---

/// Embedding request.
#[derive(Debug, Clone)]
pub struct EmbedRequest {
    /// Text to embed.
    pub text: String,
}

/// Embedding response.
#[derive(Debug, Clone)]
pub struct EmbedResponse {
    /// The embedding vector.
    pub embedding: Vec<f32>,
    /// Dimensionality of the embedding.
    pub dimensions: usize,
}

// --- Classification ---

/// Classification request for safety/moderation.
#[derive(Debug, Clone)]
pub struct ClassifyRequest {
    /// Text to classify.
    pub text: String,
}

/// A single classification label with score.
#[derive(Debug, Clone)]
pub struct ClassifyLabel {
    /// Label name (e.g., "hap", "safe", "violence").
    pub label: String,
    /// Confidence score (0.0 to 1.0).
    pub score: f32,
}

/// Classification response.
#[derive(Debug, Clone)]
pub struct ClassifyResponse {
    /// Labels sorted by score descending.
    pub labels: Vec<ClassifyLabel>,
}

impl ClassifyResponse {
    /// Returns the top label (highest confidence).
    pub fn top_label(&self) -> Option<&ClassifyLabel> {
        self.labels.first()
    }

    /// Returns true if the top label indicates unsafe content,
    /// with confidence above the given threshold.
    pub fn is_unsafe(&self, threshold: f32) -> bool {
        self.labels
            .iter()
            .any(|l| l.label != "safe" && l.score >= threshold)
    }

    /// Check labels against per-category thresholds.
    ///
    /// Returns the labels that exceed their category threshold,
    /// sorted by score descending. Categories not in the threshold
    /// map are ignored.
    pub fn exceeds_thresholds(
        &self,
        thresholds: &std::collections::HashMap<String, f32>,
    ) -> Vec<&ClassifyLabel> {
        let mut triggered: Vec<&ClassifyLabel> = self
            .labels
            .iter()
            .filter(|l| {
                if let Some(&thresh) = thresholds.get(&l.label) {
                    l.score >= thresh
                } else {
                    false
                }
            })
            .collect();
        triggered.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        triggered
    }
}

// --- Text generation ---

/// An image to include in a generation request.
#[derive(Debug, Clone)]
pub struct ImageInput {
    /// Base64-encoded image data.
    pub data: String,
    /// MIME type (e.g. "image/png", "image/jpeg").
    pub mime_type: String,
}

/// Text generation request (supports multimodal input).
#[derive(Debug, Clone)]
pub struct GenerateRequest {
    /// The prompt or messages to generate from.
    pub prompt: String,
    /// Maximum tokens to generate.
    pub max_tokens: Option<u32>,
    /// Sampling temperature (0.0 = deterministic).
    pub temperature: Option<f32>,
    /// System prompt (for chat-style APIs).
    pub system: Option<String>,
    /// Images to include with the prompt (for vision models).
    pub images: Vec<ImageInput>,
}

/// Text generation response.
#[derive(Debug, Clone)]
pub struct GenerateResponse {
    /// Generated text.
    pub text: String,
    /// Number of prompt tokens consumed.
    pub prompt_tokens: Option<u32>,
    /// Number of tokens generated.
    pub completion_tokens: Option<u32>,
}

// --- Transcription (ASR) ---

/// Audio transcription request.
#[derive(Debug, Clone)]
pub struct TranscribeRequest {
    /// Audio samples as 16kHz mono f32 PCM.
    pub audio: Vec<f32>,
    /// Language hint (ISO 639-1, e.g. "en", "fr"). None for auto-detect.
    pub language: Option<String>,
}

/// Audio transcription response.
#[derive(Debug, Clone)]
pub struct TranscribeResponse {
    /// Transcribed text.
    pub text: String,
    /// Detected language (ISO 639-1).
    pub language: Option<String>,
}

// --- Speech synthesis (TTS) ---

/// Text-to-speech request.
#[derive(Debug, Clone)]
pub struct SynthesizeRequest {
    /// Text to synthesize.
    pub text: String,
    /// Voice identifier (backend-specific).
    pub voice: Option<String>,
}

/// Text-to-speech response.
#[derive(Debug, Clone)]
pub struct SynthesizeResponse {
    /// Audio samples as f32 PCM.
    pub audio: Vec<f32>,
    /// Sample rate in Hz (e.g. 24000).
    pub sample_rate: u32,
}

// --- Locality ---

/// Where a model backend runs, relative to the trust perimeter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locality {
    /// Model runs on localhost or in-process — content flows directly.
    Local,
    /// Model runs on a remote API — content must be filtered before sending.
    Remote,
}

/// Trait for model inference backends.
///
/// The primary interface for LLM interaction is `respond()`, which
/// uses the [Open Responses](https://openresponses.org) specification.
/// This gives structured output, reasoning traces, tool governance,
/// and stateful follow-ups for free.
///
/// Backends translate to their native wire format internally:
/// - `OpenAiBackend` → Chat Completions API (Ollama, vLLM)
/// - `AnthropicBackend` → Messages API (Claude)
/// - Future `ResponsesBackend` → Open Responses API (native)
pub trait ModelBackend: Send + Sync + 'static {
    /// Create a response (Open Responses format).
    ///
    /// This is the primary LLM interface. Supports structured output,
    /// reasoning traces, `previous_response_id`, and `allowed_tools`.
    fn respond(
        &self,
        _request: &CreateResponseRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ModelResponse, ModelError>> + Send + '_>> {
        Box::pin(async { Err(ModelError::NotLoaded("respond not supported".into())) })
    }

    /// Streaming response (Open Responses format).
    fn respond_stream(
        &self,
        _request: &CreateResponseRequest,
    ) -> Pin<Box<dyn Stream<Item = Result<StreamEvent, ModelError>> + Send + '_>> {
        Box::pin(futures_util::stream::once(async {
            Err(ModelError::NotLoaded("respond_stream not supported".into()))
        }))
    }

    /// Generate embeddings for input text.
    fn embed(
        &self,
        _request: &EmbedRequest,
    ) -> Pin<Box<dyn Future<Output = Result<EmbedResponse, ModelError>> + Send + '_>> {
        Box::pin(async { Err(ModelError::NotLoaded("embed not supported".into())) })
    }

    /// Classify content (safety, moderation).
    fn classify(
        &self,
        _request: &ClassifyRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ClassifyResponse, ModelError>> + Send + '_>> {
        Box::pin(async { Err(ModelError::NotLoaded("classify not supported".into())) })
    }

    /// Generate text from a prompt (simple, single-turn).
    fn generate(
        &self,
        _request: &GenerateRequest,
    ) -> Pin<Box<dyn Future<Output = Result<GenerateResponse, ModelError>> + Send + '_>> {
        Box::pin(async { Err(ModelError::NotLoaded("generate not supported".into())) })
    }

    /// Transcribe audio to text.
    fn transcribe(
        &self,
        _request: &TranscribeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TranscribeResponse, ModelError>> + Send + '_>> {
        Box::pin(async { Err(ModelError::NotLoaded("transcribe not supported".into())) })
    }

    /// Synthesize text to audio.
    fn synthesize(
        &self,
        _request: &SynthesizeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<SynthesizeResponse, ModelError>> + Send + '_>> {
        Box::pin(async { Err(ModelError::NotLoaded("synthesize not supported".into())) })
    }

    /// Cancel an in-flight inference request.
    ///
    /// Used by the preemptive scheduler to yield GPU to a higher-priority
    /// agent. Default implementation is a no-op (backends that don't
    /// support cancellation simply let the request complete).
    fn cancel(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

// --- Internal translation helpers ---

/// Convert Open Responses request to Chat Completions (used by OpenAiBackend).
pub(crate) fn responses_to_chat(req: &CreateResponseRequest) -> chat::ChatRequest {
    use chat::*;

    let mut messages = Vec::new();

    if let Some(ref instructions) = req.instructions {
        messages.push(ChatMessage::system(instructions));
    }

    for item in &req.input {
        match item {
            InputItem::Message(msg) => {
                let text = msg.text();
                match msg.role {
                    MessageRole::System | MessageRole::Developer => {
                        messages.push(ChatMessage::system(text));
                    }
                    MessageRole::User => messages.push(ChatMessage::user(text)),
                    MessageRole::Assistant => messages.push(ChatMessage::assistant(&text)),
                }
            }
            InputItem::FunctionCall(fc) => {
                messages.push(ChatMessage::assistant_tool_calls(vec![ToolCall {
                    id: fc.call_id.clone(),
                    call_type: "function".to_string(),
                    function: FunctionCall {
                        name: fc.name.clone(),
                        arguments: fc.arguments.clone(),
                    },
                }]));
            }
            InputItem::FunctionCallOutput(fco) => {
                let text = match &fco.output {
                    FunctionCallOutputContent::Text(t) => t.clone(),
                    FunctionCallOutputContent::Parts(parts) => parts
                        .iter()
                        .filter_map(|p| match p {
                            InputContent::Text(t) => Some(t.text.as_str()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(""),
                };
                messages.push(ChatMessage::tool_result(&fco.call_id, text));
            }
            InputItem::Reasoning(_) | InputItem::ItemReference { .. } => {}
        }
    }

    let tools: Vec<ChatToolDefinition> = req
        .tools
        .iter()
        .map(|t| ChatToolDefinition {
            name: t.name.clone(),
            description: t.description.clone().unwrap_or_default(),
            parameters: t.parameters.clone().unwrap_or(serde_json::json!({})),
        })
        .collect();

    let tool_choice = req.tool_choice.as_ref().map(|tc| match tc {
        navra_responses::ToolChoice::Mode(mode) => match mode {
            navra_responses::ToolChoiceMode::Auto => ToolChoice::Auto,
            navra_responses::ToolChoiceMode::None => ToolChoice::None,
            navra_responses::ToolChoiceMode::Required => ToolChoice::Required,
        },
        _ => ToolChoice::Auto,
    });

    let response_format = req
        .text
        .as_ref()
        .and_then(|t| {
            t.format.as_ref().map(|f| match f {
                navra_responses::ResponseFormat::JsonObject => serde_json::json!("json"),
                navra_responses::ResponseFormat::JsonSchema { schema, .. } => schema.clone(),
                navra_responses::ResponseFormat::Text => serde_json::Value::Null,
            })
        })
        .filter(|v| !v.is_null());

    ChatRequest {
        messages,
        max_tokens: req.max_output_tokens,
        temperature: req.temperature,
        tools,
        tool_choice,
        response_format,
    }
}

/// Convert Chat Completions response to Open Responses format.
pub(crate) fn chat_to_responses(model: &str, resp: &chat::ChatResponse) -> ModelResponse {
    use chat::FinishReason;
    use navra_responses::response::Usage;
    use std::collections::HashMap;

    let mut output = Vec::new();

    if resp.finish_reason == FinishReason::ToolCalls {
        for tc in &resp.message.tool_calls {
            output.push(OutputItem::FunctionCall(FunctionCallItem {
                id: Some(tc.id.clone()),
                call_id: tc.id.clone(),
                name: tc.function.name.clone(),
                arguments: tc.function.arguments.clone(),
                status: Some(ItemStatus::Completed),
            }));
        }
    } else if let Some(ref text) = resp.message.content {
        output.push(OutputItem::Message(MessageItem::assistant(text)));
    }

    let status = match resp.finish_reason {
        FinishReason::Stop | FinishReason::ToolCalls => ResponseStatus::Completed,
        FinishReason::Length => ResponseStatus::Incomplete,
    };

    ModelResponse {
        id: format!("resp_{:016x}", rand_id()),
        object: "response".to_string(),
        created_at: None,
        completed_at: None,
        status,
        model: Some(model.to_string()),
        output,
        usage: Some(Usage {
            input_tokens: resp.prompt_tokens.unwrap_or(0),
            output_tokens: resp.completion_tokens.unwrap_or(0),
            total_tokens: resp.prompt_tokens.unwrap_or(0) + resp.completion_tokens.unwrap_or(0),
            input_tokens_details: None,
            output_tokens_details: None,
        }),
        error: None,
        previous_response_id: None,
        instructions: None,
        tools: Vec::new(),
        tool_choice: None,
        text: None,
        reasoning: None,
        truncation: None,
        temperature: None,
        max_output_tokens: None,
        metadata: HashMap::new(),
        incomplete_details: None,
        extra: HashMap::new(),
    }
}

fn rand_id() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    // RandomState uses OS entropy (SipHash with random keys),
    // producing unpredictable IDs without external crate deps.
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u8(0);
    hasher.finish()
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Pure threshold check for Kani: does score exceed threshold?
    fn score_exceeds(score: f32, threshold: f32) -> bool {
        score >= threshold
    }

    #[kani::proof]
    fn threshold_check_reflexive() {
        let score: f32 = kani::any();
        kani::assume(score.is_finite());
        assert!(score_exceeds(score, score));
    }

    #[kani::proof]
    fn threshold_check_monotonic() {
        let score: f32 = kani::any();
        let t1: f32 = kani::any();
        let t2: f32 = kani::any();
        kani::assume(score.is_finite() && t1.is_finite() && t2.is_finite());
        kani::assume(t2 >= t1);
        if score_exceeds(score, t2) {
            assert!(score_exceeds(score, t1));
        }
    }

    /// Exponential backoff calculation from send_with_retry.
    #[kani::proof]
    fn backoff_bounded() {
        let attempt: u32 = kani::any();
        kani::assume(attempt < 3); // MAX_RETRIES = 3
        let delay = 1u64 << attempt;
        assert!(delay <= 4); // 1, 2, 4
        assert!(delay >= 1);
    }
}
