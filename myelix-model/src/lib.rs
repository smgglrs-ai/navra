//! Model inference backends for myelix.
//!
//! Provides a unified `ModelBackend` trait for both in-process ONNX
//! models and external API-based models.
//!
//! Capabilities:
//! - `embed()` — generate text embeddings (for vector search)
//! - `classify()` — classify content (for safety filtering)
//! - `generate()` — generate text from a prompt (simple, single-turn)
//! - `chat()` — multi-turn chat completion with tool use
//! - `chat_stream()` — streaming chat completion with tool use
//! - `transcribe()` — transcribe audio to text
//! - `synthesize()` — synthesize text to audio

pub mod chat;
mod onnx;
mod openai;

pub use chat::*;
pub use onnx::{ModelTask, OnnxBackend};
pub use openai::OpenAiBackend;

use std::future::Future;
use std::pin::Pin;
use futures_util::stream::Stream;

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
        self.labels.iter().any(|l| l.label != "safe" && l.score >= threshold)
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
/// Implementations can be in-process (ONNX) or external (API).
/// Methods return `Err(ModelError::NotLoaded)` by default if the
/// operation is not supported by this backend.
pub trait ModelBackend: Send + Sync + 'static {
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

    /// Generate text from a prompt.
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

    /// Multi-turn chat completion with tool use.
    fn chat(
        &self,
        _request: &ChatRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChatResponse, ModelError>> + Send + '_>> {
        Box::pin(async { Err(ModelError::NotLoaded("chat not supported".into())) })
    }

    /// Streaming chat completion with tool use.
    fn chat_stream(
        &self,
        _request: &ChatRequest,
    ) -> Pin<Box<dyn Stream<Item = Result<ChatChunk, ModelError>> + Send + '_>> {
        Box::pin(futures_util::stream::once(async {
            Err(ModelError::NotLoaded("chat_stream not supported".into()))
        }))
    }
}
