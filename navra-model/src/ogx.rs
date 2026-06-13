//! OGX (ex-Llama Stack) backend for model inference and Llama Guard safety.
//!
//! OGX exposes OpenAI-compatible endpoints, so inference delegates to
//! [`OpenAiBackend`]. The added value is Llama Guard classification:
//! `classify()` sends text to a Llama Guard model via `generate()` and
//! parses the structured response (`"safe"` or `"unsafe\nS1\nS6"`) into
//! [`ClassifyResponse`] labels.

use crate::{
    ClassifyLabel, ClassifyRequest, ClassifyResponse, EmbedRequest, EmbedResponse, GenerateRequest,
    GenerateResponse, Locality, ModelBackend, ModelError, ModelResponse, StreamEvent,
    SynthesizeRequest, SynthesizeResponse, TranscribeRequest, TranscribeResponse,
};
use futures_util::stream::Stream;
use navra_responses::CreateResponseRequest;
use std::future::Future;
use std::pin::Pin;

/// Default OGX server URL.
pub const DEFAULT_OGX_URL: &str = "http://localhost:8321/v1";

/// Llama Guard safety categories (S1-S14).
const LLAMA_GUARD_CATEGORIES: &[(&str, &str)] = &[
    ("S1", "violent_crimes"),
    ("S2", "non_violent_crimes"),
    ("S3", "sex_crimes"),
    ("S4", "child_exploitation"),
    ("S5", "defamation"),
    ("S6", "specialized_advice"),
    ("S7", "privacy"),
    ("S8", "intellectual_property"),
    ("S9", "indiscriminate_weapons"),
    ("S10", "hate"),
    ("S11", "self_harm"),
    ("S12", "sexual_content"),
    ("S13", "elections"),
    ("S14", "code_interpreter_abuse"),
];

/// OGX backend wrapping an OpenAI-compatible connection.
///
/// When used with a Llama Guard model, `classify()` sends text and
/// parses the structured safety response. For inference (`respond()`,
/// `generate()`, `embed()`), delegates directly to the inner backend.
pub struct OgxBackend {
    inner: crate::OpenAiBackend,
}

impl OgxBackend {
    pub fn new(
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: Option<String>,
        locality: Locality,
    ) -> Self {
        Self {
            inner: crate::OpenAiBackend::new(base_url, model, api_key, locality),
        }
    }

    pub fn locality(&self) -> &Locality {
        self.inner.locality()
    }
}

/// Parse Llama Guard's text output into classification labels.
///
/// Format: `"safe"` → single safe label at 1.0
/// Format: `"unsafe\nS1\nS6"` → unsafe categories at 1.0, rest at 0.0
fn parse_llama_guard_response(text: &str) -> ClassifyResponse {
    let text = text.trim();
    let mut lines = text.lines();

    let verdict = lines.next().unwrap_or("safe").trim().to_lowercase();

    if verdict == "safe" {
        return ClassifyResponse {
            labels: vec![ClassifyLabel {
                label: "safe".to_string(),
                score: 1.0,
            }],
        };
    }

    // "unsafe" followed by category codes
    let violated: Vec<&str> = lines.map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

    let mut labels = Vec::new();

    for &(code, name) in LLAMA_GUARD_CATEGORIES {
        let score = if violated.iter().any(|v| v.eq_ignore_ascii_case(code)) {
            1.0
        } else {
            0.0
        };
        if score > 0.0 {
            labels.push(ClassifyLabel {
                label: name.to_string(),
                score,
            });
        }
    }

    // If no specific categories were parsed but verdict was unsafe,
    // return a generic unsafe label
    if labels.is_empty() {
        labels.push(ClassifyLabel {
            label: "unsafe".to_string(),
            score: 1.0,
        });
    }

    labels.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    ClassifyResponse { labels }
}

impl ModelBackend for OgxBackend {
    fn respond(
        &self,
        request: &CreateResponseRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ModelResponse, ModelError>> + Send + '_>> {
        self.inner.respond(request)
    }

    fn respond_stream(
        &self,
        request: &CreateResponseRequest,
    ) -> Pin<Box<dyn Stream<Item = Result<StreamEvent, ModelError>> + Send + '_>> {
        self.inner.respond_stream(request)
    }

    fn embed(
        &self,
        request: &EmbedRequest,
    ) -> Pin<Box<dyn Future<Output = Result<EmbedResponse, ModelError>> + Send + '_>> {
        self.inner.embed(request)
    }

    fn classify(
        &self,
        request: &ClassifyRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ClassifyResponse, ModelError>> + Send + '_>> {
        let gen_request = GenerateRequest {
            prompt: request.text.clone(),
            max_tokens: Some(100),
            temperature: Some(0.0),
            system: None,
            images: Vec::new(),
        };

        Box::pin(async move {
            let response = self.inner.generate(&gen_request).await?;
            Ok(parse_llama_guard_response(&response.text))
        })
    }

    fn generate(
        &self,
        request: &GenerateRequest,
    ) -> Pin<Box<dyn Future<Output = Result<GenerateResponse, ModelError>> + Send + '_>> {
        self.inner.generate(request)
    }

    fn transcribe(
        &self,
        request: &TranscribeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TranscribeResponse, ModelError>> + Send + '_>> {
        self.inner.transcribe(request)
    }

    fn synthesize(
        &self,
        request: &SynthesizeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<SynthesizeResponse, ModelError>> + Send + '_>> {
        self.inner.synthesize(request)
    }

    fn cancel(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.inner.cancel()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_safe() {
        let resp = parse_llama_guard_response("safe");
        assert_eq!(resp.labels.len(), 1);
        assert_eq!(resp.labels[0].label, "safe");
        assert_eq!(resp.labels[0].score, 1.0);
    }

    #[test]
    fn test_parse_safe_with_whitespace() {
        let resp = parse_llama_guard_response("  safe  \n");
        assert_eq!(resp.labels.len(), 1);
        assert_eq!(resp.labels[0].label, "safe");
    }

    #[test]
    fn test_parse_unsafe_single_category() {
        let resp = parse_llama_guard_response("unsafe\nS1");
        assert_eq!(resp.labels.len(), 1);
        assert_eq!(resp.labels[0].label, "violent_crimes");
        assert_eq!(resp.labels[0].score, 1.0);
    }

    #[test]
    fn test_parse_unsafe_multiple_categories() {
        let resp = parse_llama_guard_response("unsafe\nS1\nS6\nS10");
        assert_eq!(resp.labels.len(), 3);
        let names: Vec<&str> = resp.labels.iter().map(|l| l.label.as_str()).collect();
        assert!(names.contains(&"violent_crimes"));
        assert!(names.contains(&"specialized_advice"));
        assert!(names.contains(&"hate"));
    }

    #[test]
    fn test_parse_unsafe_no_categories() {
        let resp = parse_llama_guard_response("unsafe");
        assert_eq!(resp.labels.len(), 1);
        assert_eq!(resp.labels[0].label, "unsafe");
        assert_eq!(resp.labels[0].score, 1.0);
    }

    #[test]
    fn test_parse_unsafe_with_whitespace() {
        let resp = parse_llama_guard_response("  unsafe \n  S3  \n  S7  \n");
        assert_eq!(resp.labels.len(), 2);
        let names: Vec<&str> = resp.labels.iter().map(|l| l.label.as_str()).collect();
        assert!(names.contains(&"sex_crimes"));
        assert!(names.contains(&"privacy"));
    }

    #[test]
    fn test_parse_case_insensitive_verdict() {
        let resp = parse_llama_guard_response("Safe");
        assert_eq!(resp.labels[0].label, "safe");
    }

    #[test]
    fn test_parse_all_categories() {
        let resp = parse_llama_guard_response(
            "unsafe\nS1\nS2\nS3\nS4\nS5\nS6\nS7\nS8\nS9\nS10\nS11\nS12\nS13\nS14",
        );
        assert_eq!(resp.labels.len(), 14);
    }

    #[test]
    fn test_is_unsafe_integration() {
        let resp = parse_llama_guard_response("unsafe\nS1");
        assert!(resp.is_unsafe(0.5));

        let resp = parse_llama_guard_response("safe");
        assert!(!resp.is_unsafe(0.5));
    }

    #[test]
    fn test_empty_input() {
        let resp = parse_llama_guard_response("");
        assert_eq!(resp.labels[0].label, "safe");
    }
}
