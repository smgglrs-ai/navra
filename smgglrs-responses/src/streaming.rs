//! Streaming event types for Server-Sent Events (SSE).

use crate::item::OutputItem;
use crate::response::Response;
use serde::{Deserialize, Serialize};

/// A streaming event from the Responses API.
///
/// Events follow a state machine:
/// 1. `ResponseInProgress` — response started
/// 2. `OutputItemAdded` — new item begins
/// 3. `ContentPartAdded` — content part begins (if streamable)
/// 4. `OutputTextDelta` / `FunctionCallArgumentsDelta` — incremental content
/// 5. `OutputTextDone` / `ContentPartDone` — content part completed
/// 6. `OutputItemDone` — item completed
/// 7. `ResponseCompleted` / `ResponseFailed` — response finished
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StreamEvent {
    // --- State machine events ---
    /// Response has started processing.
    #[serde(rename = "response.in_progress")]
    ResponseInProgress {
        response: Response,
    },

    /// Response completed successfully.
    #[serde(rename = "response.completed")]
    ResponseCompleted {
        response: Response,
    },

    /// Response failed with an error.
    #[serde(rename = "response.failed")]
    ResponseFailed {
        response: Response,
    },

    // --- Item events ---
    /// A new output item was added.
    #[serde(rename = "response.output_item.added")]
    OutputItemAdded {
        output_index: usize,
        item: OutputItem,
    },

    /// An output item is fully resolved.
    #[serde(rename = "response.output_item.done")]
    OutputItemDone {
        output_index: usize,
        item: OutputItem,
    },

    // --- Content part events ---
    /// A new content part started within an item.
    #[serde(rename = "response.content_part.added")]
    ContentPartAdded {
        output_index: usize,
        content_index: usize,
        part: serde_json::Value,
    },

    /// A content part is fully resolved.
    #[serde(rename = "response.content_part.done")]
    ContentPartDone {
        output_index: usize,
        content_index: usize,
        part: serde_json::Value,
    },

    // --- Delta events ---
    /// Incremental text output.
    #[serde(rename = "response.output_text.delta")]
    OutputTextDelta {
        output_index: usize,
        content_index: usize,
        delta: String,
    },

    /// Text output completed.
    #[serde(rename = "response.output_text.done")]
    OutputTextDone {
        output_index: usize,
        content_index: usize,
        text: String,
    },

    /// Incremental function call arguments.
    #[serde(rename = "response.function_call_arguments.delta")]
    FunctionCallArgumentsDelta {
        output_index: usize,
        delta: String,
    },

    /// Function call arguments completed.
    #[serde(rename = "response.function_call_arguments.done")]
    FunctionCallArgumentsDone {
        output_index: usize,
        arguments: String,
    },
}

impl StreamEvent {
    /// Whether this event signals the end of the stream.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::ResponseCompleted { .. } | Self::ResponseFailed { .. }
        )
    }

    /// Whether this is a text delta event.
    pub fn is_text_delta(&self) -> bool {
        matches!(self, Self::OutputTextDelta { .. })
    }

    /// Extract text delta content, if this is a text delta event.
    pub fn text_delta(&self) -> Option<&str> {
        match self {
            Self::OutputTextDelta { delta, .. } => Some(delta),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_delta_roundtrip() {
        let event = StreamEvent::OutputTextDelta {
            output_index: 0,
            content_index: 0,
            delta: "Hello".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"response.output_text.delta\""));
        assert!(json.contains("\"delta\":\"Hello\""));
        let parsed: StreamEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.text_delta(), Some("Hello"));
    }

    #[test]
    fn terminal_events() {
        let completed = StreamEvent::ResponseCompleted {
            response: test_response(),
        };
        assert!(completed.is_terminal());

        let delta = StreamEvent::OutputTextDelta {
            output_index: 0,
            content_index: 0,
            delta: "x".into(),
        };
        assert!(!delta.is_terminal());
    }

    fn test_response() -> Response {
        Response {
            id: "test".into(),
            object: "response".into(),
            created_at: None,
            completed_at: None,
            status: crate::response::ResponseStatus::Completed,
            model: None,
            output: vec![],
            usage: None,
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
}
