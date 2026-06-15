//! ML-based content safety filter using model inference.
//!
//! Complements the regex-based filters with contextual detection
//! that regex can't catch (e.g., "medical records", "salary info").
//! Uses any [`Classifier`](crate::Classifier) implementation.
//!
//! Implements the async `ModelFilter` trait — runs after sync regex
//! filters in the pipeline.

use super::{FilterAction, FilterContext, Finding, ModelFilter};
use crate::classifier::Classifier;
use std::collections::HashMap;
use std::sync::Arc;

/// ML-based content filter using a classification model.
///
/// Runs the entire text through a classifier and reports a finding
/// if the model detects unsafe content above the confidence threshold.
///
/// For single-label (binary) models: uses the global `threshold` to
/// check for any non-"safe" label. For multi-label models that emit
/// per-category scores, use [`MultiLabelFilter`] instead.
pub struct MlFilter {
    model: Arc<dyn Classifier>,
    /// Minimum confidence to trigger a finding.
    threshold: f32,
    /// Category to report (e.g., "ml-unsafe", "sensitive-content").
    category: String,
}

impl MlFilter {
    /// Create a new ML filter.
    pub fn new(model: Arc<dyn Classifier>, threshold: f32, category: impl Into<String>) -> Self {
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
            match self.model.classify(content).await {
                Ok(output) => {
                    if output.is_unsafe(self.threshold) {
                        vec![Finding {
                            start: 0,
                            end: content.len(),
                            category: self.category.clone(),
                            confidence: output
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

/// Action to take when a multi-label category exceeds its threshold.
#[derive(Debug, Clone)]
pub struct CategoryPolicy {
    /// Confidence threshold for this category (0.0-1.0).
    pub threshold: f32,
    /// Action to take when the threshold is exceeded.
    pub action: FilterAction,
}

/// Multi-label content safety filter for models like GLiGuard.
///
/// Unlike [`MlFilter`] which treats classification as binary safe/unsafe,
/// this filter checks each category label from the model response against
/// its own threshold and maps it to a specific [`FilterAction`].
///
/// Categories are checked in severity order: Block > Redact > Pass.
/// The highest-severity triggered action wins. If multiple categories
/// trigger Block, the highest-confidence one is reported.
///
/// # Example
///
/// ```text
/// let mut policies = HashMap::new();
/// policies.insert("harm".into(), CategoryPolicy { threshold: 0.7, action: FilterAction::Block });
/// policies.insert("pii".into(), CategoryPolicy { threshold: 0.5, action: FilterAction::Redact });
/// policies.insert("jailbreak".into(), CategoryPolicy { threshold: 0.9, action: FilterAction::Block });
/// let filter = MultiLabelFilter::new(model, policies);
/// ```
pub struct MultiLabelFilter {
    model: Arc<dyn Classifier>,
    /// Per-category threshold and action.
    policies: HashMap<String, CategoryPolicy>,
    /// Fallback threshold for categories not in the policy map.
    /// If None, unlisted categories are ignored.
    fallback_threshold: Option<f32>,
}

impl MultiLabelFilter {
    /// Create a new multi-label filter with per-category policies.
    pub fn new(model: Arc<dyn Classifier>, policies: HashMap<String, CategoryPolicy>) -> Self {
        Self {
            model,
            policies,
            fallback_threshold: None,
        }
    }

    /// Create from simple threshold map (all categories map to Block).
    ///
    /// Convenience constructor for the common case where all categories
    /// should block content when they exceed their threshold.
    pub fn from_thresholds(model: Arc<dyn Classifier>, thresholds: HashMap<String, f32>) -> Self {
        let policies = thresholds
            .into_iter()
            .map(|(cat, thresh)| {
                (
                    cat,
                    CategoryPolicy {
                        threshold: thresh,
                        action: FilterAction::Block,
                    },
                )
            })
            .collect();
        Self {
            model,
            policies,
            fallback_threshold: None,
        }
    }

    /// Set a fallback threshold for categories not in the policy map.
    ///
    /// When set, any category label from the model that exceeds this
    /// threshold will produce a finding with FilterAction::Block.
    pub fn with_fallback_threshold(mut self, threshold: f32) -> Self {
        self.fallback_threshold = Some(threshold);
        self
    }

    /// Severity rank for ordering: Block > Redact > Pseudonymize > Pass.
    fn action_severity(action: &FilterAction) -> u8 {
        match action {
            FilterAction::Block => 3,
            FilterAction::Redact => 2,
            FilterAction::Pseudonymize => 1,
            FilterAction::Pass => 0,
        }
    }
}

impl ModelFilter for MultiLabelFilter {
    fn name(&self) -> &str {
        "ml-multi-label"
    }

    fn scan<'a>(
        &'a self,
        content: &'a str,
        _ctx: &'a FilterContext<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Finding>> + Send + 'a>> {
        Box::pin(async move {
            match self.model.classify(content).await {
                Ok(output) => {
                    let mut findings = Vec::new();

                    for label in &output.labels {
                        if label.label == "safe" {
                            continue;
                        }

                        let triggered = if let Some(policy) = self.policies.get(&label.label) {
                            label.score >= policy.threshold
                        } else if let Some(fallback) = self.fallback_threshold {
                            label.score >= fallback
                        } else {
                            false
                        };

                        if triggered {
                            findings.push(Finding {
                                start: 0,
                                end: content.len(),
                                category: label.label.clone(),
                                confidence: label.score,
                            });
                        }
                    }

                    // Sort by severity (action) descending, then confidence descending.
                    // Return only the highest-severity finding so the pipeline
                    // applies a single coherent action.
                    if findings.len() > 1 {
                        findings.sort_by(|a, b| {
                            let sev_a = self
                                .policies
                                .get(&a.category)
                                .map(|p| Self::action_severity(&p.action))
                                .unwrap_or(3); // fallback = Block
                            let sev_b = self
                                .policies
                                .get(&b.category)
                                .map(|p| Self::action_severity(&p.action))
                                .unwrap_or(3);
                            sev_b.cmp(&sev_a).then(
                                b.confidence
                                    .partial_cmp(&a.confidence)
                                    .unwrap_or(std::cmp::Ordering::Equal),
                            )
                        });
                    }

                    findings
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Multi-label safety filter inference failed, skipping");
                    Vec::new()
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::{ClassifyError, ClassifyLabel, ClassifyOutput};

    struct MockClassifier {
        labels: Vec<ClassifyLabel>,
    }

    impl MockClassifier {
        fn new(labels: Vec<ClassifyLabel>) -> Self {
            Self { labels }
        }
    }

    impl Classifier for MockClassifier {
        fn classify<'a>(
            &'a self,
            _text: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ClassifyOutput, ClassifyError>> + Send + 'a>,
        > {
            let labels = self.labels.clone();
            Box::pin(async move { Ok(ClassifyOutput { labels }) })
        }
    }

    struct FailingClassifier;

    impl Classifier for FailingClassifier {
        fn classify<'a>(
            &'a self,
            _text: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ClassifyOutput, ClassifyError>> + Send + 'a>,
        > {
            Box::pin(async { Err(ClassifyError::Inference("test failure".into())) })
        }
    }

    fn test_ctx() -> FilterContext<'static> {
        FilterContext {
            agent_name: "test",
            operation: "read",
            path: Some("/test"),
        }
    }

    // --- MlFilter tests ---

    #[tokio::test]
    async fn ml_filter_detects_unsafe() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "hap".into(),
                score: 0.85,
            },
            ClassifyLabel {
                label: "safe".into(),
                score: 0.15,
            },
        ]));
        let filter = MlFilter::new(model, 0.5, "ml-unsafe");
        let findings = filter.scan("some harmful content", &test_ctx()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ml-unsafe");
        assert!((findings[0].confidence - 0.85).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn ml_filter_passes_safe() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "safe".into(),
                score: 0.95,
            },
            ClassifyLabel {
                label: "hap".into(),
                score: 0.05,
            },
        ]));
        let filter = MlFilter::new(model, 0.5, "ml-unsafe");
        let findings = filter.scan("hello world", &test_ctx()).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn ml_filter_below_threshold_passes() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "hap".into(),
                score: 0.3,
            },
            ClassifyLabel {
                label: "safe".into(),
                score: 0.7,
            },
        ]));
        let filter = MlFilter::new(model, 0.5, "ml-unsafe");
        let findings = filter.scan("borderline content", &test_ctx()).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn ml_filter_inference_failure_skips() {
        let model = Arc::new(FailingClassifier);
        let filter = MlFilter::new(model, 0.5, "ml-unsafe");
        let findings = filter.scan("test", &test_ctx()).await;
        assert!(findings.is_empty());
    }

    // --- ClassifyOutput tests ---

    #[test]
    fn classify_output_empty_labels() {
        let out = ClassifyOutput { labels: vec![] };
        assert!(out.top_label().is_none());
        assert!(!out.is_unsafe(0.5));
        let thresholds = HashMap::new();
        assert!(out.exceeds_thresholds(&thresholds).is_empty());
    }

    #[test]
    fn classify_output_single_label() {
        let out = ClassifyOutput {
            labels: vec![ClassifyLabel {
                label: "safe".into(),
                score: 0.99,
            }],
        };
        assert!(!out.is_unsafe(0.5));
        assert_eq!(out.top_label().unwrap().label, "safe");
    }

    #[test]
    fn classify_output_exceeds_thresholds() {
        let out = ClassifyOutput {
            labels: vec![
                ClassifyLabel {
                    label: "harm".into(),
                    score: 0.8,
                },
                ClassifyLabel {
                    label: "pii".into(),
                    score: 0.6,
                },
                ClassifyLabel {
                    label: "jailbreak".into(),
                    score: 0.3,
                },
            ],
        };
        let mut thresholds = HashMap::new();
        thresholds.insert("harm".into(), 0.7);
        thresholds.insert("pii".into(), 0.5);
        thresholds.insert("jailbreak".into(), 0.9);

        let triggered = out.exceeds_thresholds(&thresholds);
        assert_eq!(triggered.len(), 2);
        assert_eq!(triggered[0].label, "harm");
        assert_eq!(triggered[1].label, "pii");
    }

    // --- MultiLabelFilter tests ---

    #[tokio::test]
    async fn multi_label_detects_multiple_categories() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "harm".into(),
                score: 0.85,
            },
            ClassifyLabel {
                label: "pii".into(),
                score: 0.6,
            },
            ClassifyLabel {
                label: "jailbreak".into(),
                score: 0.3,
            },
        ]));

        let mut policies = HashMap::new();
        policies.insert(
            "harm".into(),
            CategoryPolicy {
                threshold: 0.7,
                action: FilterAction::Block,
            },
        );
        policies.insert(
            "pii".into(),
            CategoryPolicy {
                threshold: 0.5,
                action: FilterAction::Redact,
            },
        );
        policies.insert(
            "jailbreak".into(),
            CategoryPolicy {
                threshold: 0.9,
                action: FilterAction::Block,
            },
        );

        let filter = MultiLabelFilter::new(model, policies);
        let findings = filter.scan("sensitive content", &test_ctx()).await;

        // harm (0.85 >= 0.7) and pii (0.6 >= 0.5) triggered
        // jailbreak (0.3 < 0.9) did not
        assert_eq!(findings.len(), 2);
        // Sorted by severity then confidence: harm (Block, 0.85) first
        assert_eq!(findings[0].category, "harm");
        assert_eq!(findings[1].category, "pii");
    }

    #[tokio::test]
    async fn multi_label_highest_severity_wins() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "pii".into(),
                score: 0.95,
            },
            ClassifyLabel {
                label: "harm".into(),
                score: 0.75,
            },
        ]));

        let mut policies = HashMap::new();
        policies.insert(
            "harm".into(),
            CategoryPolicy {
                threshold: 0.7,
                action: FilterAction::Block,
            },
        );
        policies.insert(
            "pii".into(),
            CategoryPolicy {
                threshold: 0.5,
                action: FilterAction::Redact,
            },
        );

        let filter = MultiLabelFilter::new(model, policies);
        let findings = filter.scan("content", &test_ctx()).await;

        assert_eq!(findings.len(), 2);
        // Block (harm) comes before Redact (pii) regardless of score
        assert_eq!(findings[0].category, "harm");
        assert_eq!(findings[1].category, "pii");
    }

    #[tokio::test]
    async fn multi_label_no_triggers() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "safe".into(),
                score: 0.95,
            },
            ClassifyLabel {
                label: "harm".into(),
                score: 0.1,
            },
        ]));

        let mut policies = HashMap::new();
        policies.insert(
            "harm".into(),
            CategoryPolicy {
                threshold: 0.7,
                action: FilterAction::Block,
            },
        );

        let filter = MultiLabelFilter::new(model, policies);
        let findings = filter.scan("safe content", &test_ctx()).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn multi_label_ignores_unlisted_categories() {
        let model = Arc::new(MockClassifier::new(vec![ClassifyLabel {
            label: "unknown-cat".into(),
            score: 0.99,
        }]));

        let policies = HashMap::new(); // no policies
        let filter = MultiLabelFilter::new(model, policies);
        let findings = filter.scan("content", &test_ctx()).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn multi_label_fallback_threshold() {
        let model = Arc::new(MockClassifier::new(vec![ClassifyLabel {
            label: "unknown-cat".into(),
            score: 0.8,
        }]));

        let filter = MultiLabelFilter::new(model, HashMap::new()).with_fallback_threshold(0.7);
        let findings = filter.scan("content", &test_ctx()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "unknown-cat");
    }

    #[tokio::test]
    async fn multi_label_from_thresholds_convenience() {
        let model = Arc::new(MockClassifier::new(vec![ClassifyLabel {
            label: "harm".into(),
            score: 0.8,
        }]));

        let mut thresholds = HashMap::new();
        thresholds.insert("harm".into(), 0.7);

        let filter = MultiLabelFilter::from_thresholds(model, thresholds);
        let findings = filter.scan("harmful content", &test_ctx()).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "harm");
    }

    #[tokio::test]
    async fn multi_label_inference_failure_skips() {
        let model = Arc::new(FailingClassifier);
        let filter = MultiLabelFilter::new(model, HashMap::new());
        let findings = filter.scan("test", &test_ctx()).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn multi_label_safe_label_ignored() {
        // Even if "safe" has a policy, the filter skips it
        let model = Arc::new(MockClassifier::new(vec![ClassifyLabel {
            label: "safe".into(),
            score: 0.99,
        }]));

        let mut policies = HashMap::new();
        policies.insert(
            "safe".into(),
            CategoryPolicy {
                threshold: 0.1,
                action: FilterAction::Block,
            },
        );

        let filter = MultiLabelFilter::new(model, policies);
        let findings = filter.scan("content", &test_ctx()).await;
        assert!(findings.is_empty());
    }
}
