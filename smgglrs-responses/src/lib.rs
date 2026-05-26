//! Open Responses API types for Rust.
//!
//! Spec-compliant types for the [Open Responses](https://openresponses.org)
//! specification — the open standard for multi-provider LLM interfaces.
//!
//! This crate provides **types only** — no HTTP client, no async runtime,
//! no opinions about transport. Use it as the foundation for building
//! clients, servers, or middleware that speak the Open Responses protocol.
//!
//! All types implement `Serialize`, `Deserialize`, `Clone`, and `Debug`.
//!
//! # Core concepts
//!
//! - **Items** are the atomic unit of model output: messages, function
//!   calls, function call outputs, and reasoning traces.
//! - **Responses** contain a list of output items plus metadata.
//! - **Streaming events** carry incremental updates (deltas) and
//!   state machine transitions.
//! - **Provider extensions** are supported via `#[serde(flatten)]`
//!   on extra fields.

pub mod content;
pub mod error;
pub mod item;
pub mod request;
pub mod response;
pub mod streaming;
pub mod tool;

// Re-export key types at crate root for ergonomics.
pub use content::{
    Annotation, ImageDetail, InputContent, InputFileContent, InputImageContent, InputTextContent,
    InputVideoContent, OutputContent, OutputTextContent, RefusalContent,
};
pub use error::ResponseError;
pub use item::{
    FunctionCallItem, FunctionCallOutputContent, FunctionCallOutputItem, InputItem, ItemStatus,
    MessageContent, MessageItem, MessageRole, OutputItem, ReasoningItem,
};
pub use request::{
    CreateResponseRequest, ReasoningConfig, ReasoningEffort, ReasoningSummary, ResponseFormat,
    TextConfig, Truncation, Verbosity,
};
pub use response::{Response, ResponseStatus, Usage};
pub use streaming::StreamEvent;
pub use tool::{AllowedTools, FunctionTool, ToolChoice, ToolChoiceMode};
