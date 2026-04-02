//! Model inference backends for mcpd.
//!
//! Provides a unified `ModelBackend` trait for both in-process ONNX
//! models and external API-based models. Available behind the `onnx`
//! feature flag for the ONNX implementation.
//!
//! Current capabilities:
//! - `embed()` — generate text embeddings (for vector search)
//! - `classify()` — classify content (for safety filtering)

mod onnx;

pub use onnx::OnnxModel;

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
}

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

/// Trait for model inference backends.
///
/// Implementations can be in-process (ONNX) or external (API).
/// Methods return `Err(ModelError::NotLoaded)` if the operation
/// is not supported by this backend.
pub trait ModelBackend: Send + Sync + 'static {
    /// Generate embeddings for input text.
    fn embed(
        &self,
        request: &EmbedRequest,
    ) -> Pin<Box<dyn Future<Output = Result<EmbedResponse, ModelError>> + Send + '_>>;

    /// Classify content (safety, moderation).
    fn classify(
        &self,
        request: &ClassifyRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ClassifyResponse, ModelError>> + Send + '_>>;
}
