//! Refusal detection for model responses.

use crate::chat::{ChatResponse, FinishReason};

const REFUSAL_PATTERNS: &[&str] = &[
    "i cannot",
    "i can't",
    "i'm unable to",
    "i am unable to",
    "i'm not able to",
    "as an ai",
    "i must decline",
    "i cannot assist with",
];

const MAX_REFUSAL_TEXT_LEN: usize = 500;

pub fn detect_refusal(response: &ChatResponse) -> bool {
    if response.finish_reason == FinishReason::Refusal {
        return true;
    }
    let text = response.message.content.as_deref().unwrap_or("");
    if text.is_empty() {
        return false;
    }
    let lower = text.to_lowercase();
    text.len() < MAX_REFUSAL_TEXT_LEN && REFUSAL_PATTERNS.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::{ChatMessage, ChatResponse, ChatRole, FinishReason};

    fn make_response(text: &str, finish_reason: FinishReason) -> ChatResponse {
        ChatResponse {
            message: ChatMessage {
                role: ChatRole::Assistant,
                content: if text.is_empty() {
                    None
                } else {
                    Some(text.to_string())
                },
                images: Vec::new(),
                tool_calls: Vec::new(),
                tool_call_id: None,
            },
            finish_reason,
            prompt_tokens: None,
            completion_tokens: None,
        }
    }

    #[test]
    fn test_refusal_detection_explicit() {
        let resp = make_response("content", FinishReason::Refusal);
        assert!(detect_refusal(&resp));
    }

    #[test]
    fn test_refusal_detection_heuristic_i_cannot() {
        let resp = make_response("I cannot help with that request.", FinishReason::Stop);
        assert!(detect_refusal(&resp));
    }

    #[test]
    fn test_refusal_detection_heuristic_as_an_ai() {
        let resp = make_response("As an AI, I'm not able to do that.", FinishReason::Stop);
        assert!(detect_refusal(&resp));
    }

    #[test]
    fn test_non_refusal_normal_response() {
        let resp = make_response(
            "Here is the information you requested about the project.",
            FinishReason::Stop,
        );
        assert!(!detect_refusal(&resp));
    }

    #[test]
    fn test_non_refusal_empty_content() {
        let resp = make_response("", FinishReason::Stop);
        assert!(!detect_refusal(&resp));
    }

    #[test]
    fn test_non_refusal_long_text_with_pattern() {
        let long_text = format!(
            "{}I cannot do this part, but here is the rest.",
            "x".repeat(500)
        );
        let resp = make_response(&long_text, FinishReason::Stop);
        assert!(!detect_refusal(&resp));
    }

    #[test]
    fn test_anthropic_refusal_stop_reason() {
        let resp = make_response("I cannot help.", FinishReason::Refusal);
        assert!(detect_refusal(&resp));
    }

    #[test]
    fn test_refusal_finish_reason_is_refusal() {
        assert!(FinishReason::Refusal.is_refusal());
        assert!(!FinishReason::Stop.is_refusal());
        assert!(!FinishReason::Length.is_refusal());
        assert!(!FinishReason::ToolCalls.is_refusal());
    }

    #[test]
    fn test_finish_reason_from_str_refusal() {
        assert_eq!(FinishReason::from_str("refusal"), FinishReason::Refusal);
    }
}
