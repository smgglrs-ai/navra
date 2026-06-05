//! Voice modality for navra.
//!
//! Speech input (ASR) and output (TTS) via ONNX models. Includes
//! voice activity detection, silence-based auto-stop, and audio
//! format conversion.

pub mod audio;
mod tools;

pub use tools::VoiceModule;
