//! PII sequence classifier: fast ONNX pre-filter for the safety pipeline.
//!
//! Runs a sequence classification model (e.g., PII/no-PII binary or
//! multi-category) as a cheap first pass. When the classifier scores
//! text below the PII threshold, expensive NER can be skipped.
//!
//! Implements [`ContentFilter`] so it slots into the existing
//! `FilterPipeline` before `NerFilter`.

use super::{ContentFilter, FilterContext, Finding};
use std::path::Path;
use std::sync::Mutex;

/// Fast PII pre-filter using ONNX sequence classification.
///
/// Classifies entire text segments as containing PII or not.
/// When PII is detected, returns a single `Finding` spanning the
/// full text with the detected category and confidence.
pub struct PiiClassifier {
    session: Mutex<ort::session::Session>,
    tokenizer: tokenizers::Tokenizer,
    labels: Vec<String>,
    threshold: f32,
}

impl PiiClassifier {
    /// Load a PII classifier from a directory containing model.onnx and tokenizer.json.
    pub fn load(model_dir: &Path, threshold: f32) -> Option<Self> {
        let model_path = model_dir.join("model.onnx");
        let tokenizer_path = model_dir.join("tokenizer.json");

        if !model_path.exists() {
            tracing::debug!(
                path = %model_path.display(),
                "PII classifier model not found, skipping"
            );
            return None;
        }

        let session =
            navra_model::onnx::build_onnx_session(&model_path, &navra_model::Device::Cpu).ok()?;

        let tokenizer = tokenizers::Tokenizer::from_file(&tokenizer_path).ok()?;

        let label_path = model_dir.join("label_map.json");
        let labels = if label_path.exists() {
            let content = std::fs::read_to_string(&label_path).ok()?;
            serde_json::from_str::<Vec<String>>(&content).ok()?
        } else {
            vec!["no_pii".to_string(), "has_pii".to_string()]
        };

        tracing::info!(
            model = %model_path.display(),
            labels = ?labels,
            threshold,
            "Loaded PII classifier"
        );

        Some(Self {
            session: Mutex::new(session),
            tokenizer,
            labels,
            threshold,
        })
    }

    fn classify(&self, content: &str) -> Option<(String, f32)> {
        let encoding = self.tokenizer.encode(content, true).ok()?;
        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&m| m as i64)
            .collect();

        let seq_len = input_ids.len();
        let input_ids_array = ndarray::Array2::from_shape_vec((1, seq_len), input_ids).ok()?;
        let mask_array = ndarray::Array2::from_shape_vec((1, seq_len), attention_mask).ok()?;

        let input_ids_tensor = ort::value::TensorRef::from_array_view(&input_ids_array).ok()?;
        let mask_tensor = ort::value::TensorRef::from_array_view(&mask_array).ok()?;

        let mut session = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let outputs = session
            .run(ort::inputs![input_ids_tensor, mask_tensor])
            .ok()?;

        let (_name, output) = outputs.iter().next()?;
        let (_shape, logits) = output.try_extract_tensor::<f32>().ok()?;

        // Softmax over logits
        let max_logit = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let exp_sum: f32 = logits.iter().map(|x| (x - max_logit).exp()).sum();
        let probs: Vec<f32> = logits
            .iter()
            .map(|x| (x - max_logit).exp() / exp_sum)
            .collect();

        // Find the top label
        let (top_idx, top_prob) = probs
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))?;

        let label = self.labels.get(top_idx)?.clone();
        Some((label, *top_prob))
    }
}

impl ContentFilter for PiiClassifier {
    fn name(&self) -> &str {
        "pii_classifier"
    }

    fn scan(&self, content: &str, _ctx: &FilterContext) -> Vec<Finding> {
        if content.is_empty() {
            return Vec::new();
        }

        let Some((label, confidence)) = self.classify(content) else {
            return Vec::new();
        };

        // Only report PII findings for non-"safe"/"no_pii" labels above threshold
        if label == "no_pii" || label == "safe" || label == "0" {
            return Vec::new();
        }

        if confidence < self.threshold {
            return Vec::new();
        }

        let category = match label.as_str() {
            "has_pii" | "1" | "pii" => "pii-detected",
            other => other,
        };

        vec![Finding {
            start: 0,
            end: content.len(),
            category: category.to_string(),
            confidence,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pii_classifier_load_missing_model() {
        let result = PiiClassifier::load(std::path::Path::new("/nonexistent"), 0.5);
        assert!(result.is_none());
    }

    #[test]
    fn pii_classifier_default_labels() {
        let labels = vec!["no_pii".to_string(), "has_pii".to_string()];
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0], "no_pii");
        assert_eq!(labels[1], "has_pii");
    }

    #[test]
    fn softmax_computation() {
        let logits = vec![2.0f32, 1.0, 0.1];
        let max_logit = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let exp_sum: f32 = logits.iter().map(|x| (x - max_logit).exp()).sum();
        let probs: Vec<f32> = logits
            .iter()
            .map(|x| (x - max_logit).exp() / exp_sum)
            .collect();

        assert!(probs[0] > probs[1]);
        assert!(probs[1] > probs[2]);
        let sum: f32 = probs.iter().sum();
        assert!((sum - 1.0).abs() < 1e-5);
    }

    #[test]
    fn category_mapping() {
        for (label, expected) in [
            ("has_pii", "pii-detected"),
            ("1", "pii-detected"),
            ("pii", "pii-detected"),
            ("person", "person"),
            ("email", "email"),
        ] {
            let category = match label {
                "has_pii" | "1" | "pii" => "pii-detected",
                other => other,
            };
            assert_eq!(category, expected);
        }
    }
}
