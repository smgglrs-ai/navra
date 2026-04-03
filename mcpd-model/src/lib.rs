//! Model backend implementations for mcpd.
//!
//! This crate provides concrete `ModelBackend` implementations:
//! - `OnnxBackend` — in-process ONNX Runtime inference (CPU tier)
//! - `OpenAiBackend` — external OpenAI-compatible API (GPU tier)

mod onnx;
mod openai;

pub use onnx::{ModelTask, OnnxBackend};
pub use openai::OpenAiBackend;

// Re-export trait and types from mcpd-core for convenience.
pub use mcpd_core::models::{
    ClassifyLabel, ClassifyRequest, ClassifyResponse, EmbedRequest, EmbedResponse,
    GenerateRequest, GenerateResponse, Locality, ModelBackend, ModelError, SynthesizeRequest,
    SynthesizeResponse, TranscribeRequest, TranscribeResponse,
};
