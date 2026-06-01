//! Safety-filtering model backend wrapper.
//!
//! Wraps any ModelBackend to filter prompts (outbound) and responses
//! (inbound) through a safety pipeline. The agent doesn't know it's
//! being filtered — the proxy is injected at construction time.
//!
//! This ensures sensitive data from tool results (API keys, PII,
//! secrets) is caught before leaving the device via model API calls,
//! and adversarial model responses are caught before reaching the agent.

use crate::{CreateResponseRequest, ModelBackend, ModelError, ModelResponse};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Callback trait for filtering model prompts and responses.
///
/// Implement this to connect to navra-security's safety pipeline
/// without creating a direct dependency from navra-model to
/// navra-security.
pub trait ModelSafetyFilter: Send + Sync {
    /// Filter the outbound prompt before it reaches the model.
    /// Returns Ok(()) to allow, Err(reason) to block.
    fn filter_prompt(&self, request: &CreateResponseRequest) -> Result<(), String>;

    /// Filter the inbound response before it reaches the agent.
    /// Returns Ok(()) to allow, Err(reason) to block.
    fn filter_response(&self, response: &ModelResponse) -> Result<(), String>;

    /// Record the model call for audit purposes.
    fn record_call(&self, model_name: &str, input_tokens: u32, output_tokens: u32, blocked: bool);
}

/// A model backend that filters all calls through a safety layer.
pub struct SafeModelBackend {
    inner: Box<dyn ModelBackend>,
    filter: Arc<dyn ModelSafetyFilter>,
    model_name: String,
}

impl SafeModelBackend {
    /// Wrap a model backend with safety filtering.
    pub fn new(
        inner: impl ModelBackend + 'static,
        filter: Arc<dyn ModelSafetyFilter>,
        model_name: impl Into<String>,
    ) -> Self {
        Self {
            inner: Box::new(inner),
            filter,
            model_name: model_name.into(),
        }
    }
}

impl ModelBackend for SafeModelBackend {
    fn respond(
        &self,
        request: &CreateResponseRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ModelResponse, ModelError>> + Send + '_>> {
        // Filter outbound prompt synchronously before async
        if let Err(reason) = self.filter.filter_prompt(request) {
            self.filter.record_call(&self.model_name, 0, 0, true);
            return Box::pin(async move {
                Err(ModelError::Inference(format!(
                    "Safety filter blocked prompt: {reason}"
                )))
            });
        }

        let fut = self.inner.respond(request);
        let filter = Arc::clone(&self.filter);
        let model_name = self.model_name.clone();

        Box::pin(async move {
            let response = fut.await?;

            let (in_tok, out_tok) = response
                .usage
                .as_ref()
                .map(|u| (u.input_tokens, u.output_tokens))
                .unwrap_or((0, 0));

            if let Err(reason) = filter.filter_response(&response) {
                filter.record_call(&model_name, in_tok, out_tok, true);
                return Err(ModelError::Inference(format!(
                    "Safety filter blocked response: {reason}"
                )));
            }

            filter.record_call(&model_name, in_tok, out_tok, false);
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::responses::response::Usage;
    use crate::{InputItem, MessageItem, ModelResponse, OutputItem, ResponseStatus};
    use std::sync::atomic::{AtomicU32, Ordering};

    struct PassthroughFilter {
        calls: AtomicU32,
    }

    impl ModelSafetyFilter for PassthroughFilter {
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
            Err("contains sensitive data".into())
        }
        fn filter_response(&self, _resp: &ModelResponse) -> Result<(), String> {
            Ok(())
        }
        fn record_call(&self, _model: &str, _in_tok: u32, _out_tok: u32, _blocked: bool) {}
    }

    struct FakeBackend;

    impl ModelBackend for FakeBackend {
        fn respond(
            &self,
            _req: &CreateResponseRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ModelResponse, ModelError>> + Send + '_>> {
            Box::pin(async {
                Ok(ModelResponse {
                    id: "test".into(),
                    object: "response".into(),
                    created_at: None,
                    completed_at: None,
                    status: ResponseStatus::Completed,
                    model: Some("fake".into()),
                    output: vec![OutputItem::Message(MessageItem::assistant("hello"))],
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

    #[tokio::test]
    async fn passthrough_allows_call() {
        let filter = Arc::new(PassthroughFilter {
            calls: AtomicU32::new(0),
        });
        let backend = SafeModelBackend::new(FakeBackend, filter.clone(), "test-model");
        let req = CreateResponseRequest::new(String::from("test"), vec![InputItem::user("hi")]);
        let resp = backend.respond(&req).await.unwrap();
        assert_eq!(resp.text().unwrap(), "hello");
        assert_eq!(filter.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn blocking_filter_rejects_prompt() {
        let filter = Arc::new(BlockingFilter);
        let backend = SafeModelBackend::new(FakeBackend, filter, "test-model");
        let req = CreateResponseRequest::new(String::from("test"), vec![InputItem::user("hi")]);
        let err = backend.respond(&req).await.unwrap_err();
        assert!(format!("{err}").contains("sensitive data"));
    }
}
