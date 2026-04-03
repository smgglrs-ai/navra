//! ML-based content safety filter using model inference.
//!
//! Complements the regex-based filters with contextual detection
//! that regex can't catch (e.g., "medical records", "salary info").
//! Uses any `ModelBackend` that supports classification.
//!
//! Implements the async `ModelFilter` trait — runs after sync regex
//! filters in the pipeline.

use crate::models::{ClassifyRequest, ModelBackend};
use super::{FilterContext, Finding, ModelFilter};
use std::sync::Arc;

/// ML-based content filter using a classification model.
///
/// Runs the entire text through a classifier and reports a finding
/// if the model detects unsafe content above the confidence threshold.
pub struct MlFilter {
    model: Arc<dyn ModelBackend>,
    /// Minimum confidence to trigger a finding.
    threshold: f32,
    /// Category to report (e.g., "ml-unsafe", "sensitive-content").
    category: String,
}

impl MlFilter {
    /// Create a new ML filter.
    pub fn new(
        model: Arc<dyn ModelBackend>,
        threshold: f32,
        category: impl Into<String>,
    ) -> Self {
        Self {
            model,
            threshold,
            category: category.into(),
        }
    }
}

impl ModelFilter for MlFilter {
    fn name(&self) -> &str {
        "ml-safety"
    }

    fn scan<'a>(
        &'a self,
        content: &'a str,
        _ctx: &'a FilterContext<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Finding>> + Send + 'a>> {
        Box::pin(async move {
            let request = ClassifyRequest {
                text: content.to_string(),
            };

            match self.model.classify(&request).await {
                Ok(response) => {
                    if response.is_unsafe(self.threshold) {
                        vec![Finding {
                            start: 0,
                            end: content.len(),
                            category: self.category.clone(),
                            confidence: response
                                .labels
                                .iter()
                                .find(|l| l.label != "safe")
                                .map(|l| l.score)
                                .unwrap_or(0.0),
                        }]
                    } else {
                        Vec::new()
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "ML safety filter inference failed, skipping");
                    Vec::new()
                }
            }
        })
    }
}
