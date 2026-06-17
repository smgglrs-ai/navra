use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

/// Trait for ML-based content classifiers (safety, moderation models).
///
/// Implement this to plug in your own classification backend
/// (ONNX Runtime, HTTP API, etc.).
///
/// # Example
///
/// ```text
/// struct MyClassifier;
///
/// impl navra_safety::Classifier for MyClassifier {
///     fn classify<'a>(&'a self, text: &'a str)
///         -> Pin<Box<dyn Future<Output = Result<ClassifyOutput, ClassifyError>> + Send + 'a>>
///     {
///         Box::pin(async move {
///             Ok(ClassifyOutput { labels: vec![] })
///         })
///     }
/// }
/// ```
pub trait Classifier: Send + Sync + 'static {
    fn classify<'a>(
        &'a self,
        text: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<ClassifyOutput, ClassifyError>> + Send + 'a>>;
}

/// Classification output containing scored labels.
#[derive(Debug, Clone)]
pub struct ClassifyOutput {
    /// Labels sorted by score descending.
    pub labels: Vec<ClassifyLabel>,
}

impl ClassifyOutput {
    /// Returns the top label (highest confidence).
    pub fn top_label(&self) -> Option<&ClassifyLabel> {
        self.labels.first()
    }

    /// Returns true if any non-"safe" label exceeds the threshold.
    /// NaN scores are treated as unsafe (fail-closed).
    pub fn is_unsafe(&self, threshold: f32) -> bool {
        self.labels
            .iter()
            .any(|l| l.label != "safe" && (l.score.is_nan() || l.score >= threshold))
    }

    /// Check labels against per-category thresholds.
    ///
    /// Returns labels that exceed their category threshold,
    /// sorted by score descending. Categories not in the threshold
    /// map are ignored.
    pub fn exceeds_thresholds(&self, thresholds: &HashMap<String, f32>) -> Vec<&ClassifyLabel> {
        let mut triggered: Vec<&ClassifyLabel> = self
            .labels
            .iter()
            .filter(|l| {
                if let Some(&thresh) = thresholds.get(&l.label) {
                    l.score.is_nan() || l.score >= thresh
                } else {
                    false
                }
            })
            .collect();
        triggered.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        triggered
    }
}

/// A single classification label with confidence score.
#[derive(Debug, Clone)]
pub struct ClassifyLabel {
    /// Label name (e.g., "hap", "safe", "violence").
    pub label: String,
    /// Confidence score (0.0 to 1.0).
    pub score: f32,
}

/// Error from a classification operation.
#[derive(Debug, thiserror::Error)]
pub enum ClassifyError {
    #[error("inference failed: {0}")]
    Inference(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nan_score_is_unsafe() {
        let output = ClassifyOutput {
            labels: vec![ClassifyLabel {
                label: "harm".into(),
                score: f32::NAN,
            }],
        };
        assert!(output.is_unsafe(0.5));
    }

    #[test]
    fn nan_score_exceeds_threshold() {
        let output = ClassifyOutput {
            labels: vec![ClassifyLabel {
                label: "harm".into(),
                score: f32::NAN,
            }],
        };
        let mut thresholds = HashMap::new();
        thresholds.insert("harm".into(), 0.5);
        let triggered = output.exceeds_thresholds(&thresholds);
        assert_eq!(triggered.len(), 1);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn nan_score_always_unsafe() {
        let output = ClassifyOutput {
            labels: vec![ClassifyLabel {
                label: "harm".to_string(),
                score: f32::NAN,
            }],
        };
        let threshold: f32 = kani::any();
        kani::assume(!threshold.is_nan() && threshold >= 0.0 && threshold <= 1.0);
        assert!(output.is_unsafe(threshold));
    }
}
