//! Vision modality for navra.
//!
//! Image and screen understanding via ONNX models (GPU tier).
//! Includes screenshot capture and visual analysis tools.

pub mod actor;
mod screenshot;
mod tools;

pub use tools::VisionModule;
