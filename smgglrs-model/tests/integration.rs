//! Integration tests for smgglrs-model public API.
//!
//! Tests the public types, constructors, and classification response
//! helpers without requiring running model backends.

use smgglrs_model::{
    ClassifyLabel, ClassifyResponse, EmbedRequest,
    GenerateRequest, Locality, ModelBackend, ModelError,
    OpenAiBackend, AnthropicBackend,
    CreateResponseRequest, InputItem, OutputItem, MessageItem,
    ResponseStatus, ModelResponse,
    ClassifyRequest,
    safe_backend::{ModelSafetyFilter, SafeModelBackend},
};
use smgglrs_model::responses::response::Usage;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

// =====================================================================
// 1. ClassifyResponse helpers
// =====================================================================

#[test]
fn classify_response_top_label() {
    let resp = ClassifyResponse {
        labels: vec![
            ClassifyLabel { label: "safe".into(), score: 0.9 },
            ClassifyLabel { label: "hap".into(), score: 0.1 },
        ],
    };
    assert_eq!(resp.top_label().unwrap().label, "safe");
    assert_eq!(resp.top_label().unwrap().score, 0.9);
}

#[test]
fn classify_response_is_unsafe_above_threshold() {
    let resp = ClassifyResponse {
        labels: vec![
            ClassifyLabel { label: "hap".into(), score: 0.8 },
            ClassifyLabel { label: "safe".into(), score: 0.2 },
        ],
    };
    assert!(resp.is_unsafe(0.5));
    assert!(resp.is_unsafe(0.8));
    assert!(!resp.is_unsafe(0.9));
}

#[test]
fn classify_response_safe_not_unsafe() {
    let resp = ClassifyResponse {
        labels: vec![
            ClassifyLabel { label: "safe".into(), score: 0.99 },
        ],
    };
    assert!(!resp.is_unsafe(0.5));
}

// =====================================================================
// 2. ModelError display
// =====================================================================

#[test]
fn model_error_display() {
    let e = ModelError::NotLoaded("whisper".into());
    assert_eq!(format!("{e}"), "model not loaded: whisper");

    let e = ModelError::Api("HTTP 429".into());
    assert_eq!(format!("{e}"), "API error: HTTP 429");

    let e = ModelError::Inference("OOM".into());
    assert_eq!(format!("{e}"), "inference failed: OOM");

    let e = ModelError::InvalidInput("empty prompt".into());
    assert_eq!(format!("{e}"), "invalid input: empty prompt");
}

// =====================================================================
// 3. Locality enum
// =====================================================================

#[test]
fn locality_equality() {
    assert_eq!(Locality::Local, Locality::Local);
    assert_eq!(Locality::Remote, Locality::Remote);
    assert_ne!(Locality::Local, Locality::Remote);
}

// =====================================================================
// 4. OpenAiBackend constructor
// =====================================================================

#[test]
fn openai_backend_constructor() {
    let backend = OpenAiBackend::new(
        "http://localhost:11434/v1",
        "granite3.3:8b",
        None,
        Locality::Local,
    );
    assert_eq!(backend.locality(), &Locality::Local);
}

#[test]
fn openai_backend_with_api_key() {
    let backend = OpenAiBackend::new(
        "https://api.openai.com/v1",
        "gpt-4o",
        Some("sk-test-key".into()),
        Locality::Remote,
    );
    assert_eq!(backend.locality(), &Locality::Remote);
}

// =====================================================================
// 5. AnthropicBackend constructor
// =====================================================================

#[test]
fn anthropic_backend_constructor() {
    let backend = AnthropicBackend::new(
        "https://api.anthropic.com",
        "claude-sonnet-4-20250514",
        None,
        Locality::Remote,
    );
    assert_eq!(backend.locality(), &Locality::Remote);
}

// =====================================================================
// 6. SafeModelBackend with mock
// =====================================================================

struct FakeBackend;

impl ModelBackend for FakeBackend {
    fn respond(
        &self,
        _req: &CreateResponseRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ModelResponse, ModelError>> + Send + '_>> {
        Box::pin(async {
            Ok(ModelResponse {
                id: "resp_test".into(),
                object: "response".into(),
                created_at: None,
                completed_at: None,
                status: ResponseStatus::Completed,
                model: Some("fake".into()),
                output: vec![OutputItem::Message(MessageItem::assistant("hello world"))],
                usage: Some(Usage {
                    input_tokens: 10,
                    output_tokens: 5,
                    total_tokens: 15,
                    input_tokens_details: None,
                    output_tokens_details: None,
                }),
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
            })
        })
    }
}

struct CountingFilter {
    calls: AtomicU32,
}

impl ModelSafetyFilter for CountingFilter {
    fn filter_prompt(&self, _req: &CreateResponseRequest) -> Result<(), String> {
        Ok(())
    }
    fn filter_response(&self, _resp: &ModelResponse) -> Result<(), String> {
        Ok(())
    }
    fn record_call(&self, _model: &str, _in_tok: u32, _out_tok: u32, _blocked: bool) {
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}

struct BlockingFilter;

impl ModelSafetyFilter for BlockingFilter {
    fn filter_prompt(&self, _req: &CreateResponseRequest) -> Result<(), String> {
        Err("blocked: sensitive content".into())
    }
    fn filter_response(&self, _resp: &ModelResponse) -> Result<(), String> {
        Ok(())
    }
    fn record_call(&self, _model: &str, _in_tok: u32, _out_tok: u32, _blocked: bool) {}
}

#[tokio::test]
async fn safe_backend_passthrough() {
    let filter = Arc::new(CountingFilter { calls: AtomicU32::new(0) });
    let backend = SafeModelBackend::new(FakeBackend, filter.clone(), "test-model");

    let req = CreateResponseRequest::new(String::from("test"), vec![InputItem::user("hi")]);
    let resp = backend.respond(&req).await.unwrap();
    assert_eq!(resp.text().unwrap(), "hello world");
    assert_eq!(filter.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn safe_backend_blocks_sensitive_prompt() {
    let filter = Arc::new(BlockingFilter);
    let backend = SafeModelBackend::new(FakeBackend, filter, "test-model");

    let req = CreateResponseRequest::new(String::from("test"), vec![InputItem::user("secret data")]);
    let err = backend.respond(&req).await.unwrap_err();
    assert!(format!("{err}").contains("sensitive content"));
}

// =====================================================================
// 7. Default ModelBackend trait methods return NotLoaded
// =====================================================================

struct EmptyBackend;

impl ModelBackend for EmptyBackend {}

#[tokio::test]
async fn default_backend_methods_return_not_loaded() {
    let backend = EmptyBackend;

    let embed_err = backend.embed(&EmbedRequest { text: "hello".into() }).await;
    assert!(matches!(embed_err, Err(ModelError::NotLoaded(_))));

    let classify_err = backend.classify(&ClassifyRequest { text: "hello".into() }).await;
    assert!(matches!(classify_err, Err(ModelError::NotLoaded(_))));

    let gen_err = backend.generate(&GenerateRequest {
        prompt: "hello".into(),
        max_tokens: None,
        temperature: None,
        system: None,
        images: vec![],
    }).await;
    assert!(matches!(gen_err, Err(ModelError::NotLoaded(_))));

    let resp_err = backend.respond(
        &CreateResponseRequest::new(String::from("m"), vec![])
    ).await;
    assert!(matches!(resp_err, Err(ModelError::NotLoaded(_))));
}
