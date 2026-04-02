//! ONNX Runtime backend for in-process model inference.
//!
//! Wraps `ort::session::Session` for text-based models (embeddings,
//! classification). Thread-safe via `std::sync::Mutex`. Uses
//! `spawn_blocking` to avoid blocking the Tokio executor.

use super::{
    ClassifyLabel, ClassifyResponse, ClassifyRequest, EmbedRequest, EmbedResponse, ModelBackend,
    ModelError,
};
use std::path::Path;
use std::sync::Mutex;

/// An ONNX model loaded into the runtime.
pub struct OnnxModel {
    session: Mutex<ort::session::Session>,
    task: ModelTask,
    name: String,
}

/// What this model is used for — determines how outputs are interpreted.
#[derive(Debug, Clone)]
pub enum ModelTask {
    /// Embedding model: output is mean-pooled hidden states.
    Embedding {
        /// Expected embedding dimensionality.
        dimensions: usize,
    },
    /// Classification model: output is logits over labels.
    Classification {
        /// Label names in order (matching model output indices).
        labels: Vec<String>,
    },
}

impl OnnxModel {
    /// Load an ONNX model from a file.
    pub fn load(name: &str, model_path: &Path, task: ModelTask) -> Result<Self, ModelError> {
        let mut builder = ort::session::Session::builder()
            .map_err(|e| ModelError::Inference(format!("session builder error: {e}")))?
            .with_execution_providers([
                ort::execution_providers::CPUExecutionProvider::default().build(),
            ])
            .map_err(|e| ModelError::Inference(format!("execution provider error: {e}")))?;

        let session = builder
            .commit_from_file(model_path)
            .map_err(|e| {
                ModelError::Inference(format!(
                    "failed to load '{}' from {}: {e}",
                    name,
                    model_path.display()
                ))
            })?;

        tracing::info!(
            model = name,
            path = %model_path.display(),
            inputs = session.inputs().len(),
            outputs = session.outputs().len(),
            "Loaded ONNX model"
        );

        Ok(Self {
            session: Mutex::new(session),
            task,
            name: name.to_string(),
        })
    }

    /// Run inference and return raw output values as flattened f32 vectors.
    fn run_inference(
        &self,
        input_ids: &[i64],
        attention_mask: &[i64],
    ) -> Result<Vec<Vec<f32>>, ModelError> {
        let mut session = self.session.lock().unwrap();
        let seq_len = input_ids.len();

        let input_ids_array = ndarray::Array2::from_shape_vec((1, seq_len), input_ids.to_vec())
            .map_err(|e| ModelError::Inference(format!("input_ids shape error: {e}")))?;
        let mask_array = ndarray::Array2::from_shape_vec((1, seq_len), attention_mask.to_vec())
            .map_err(|e| ModelError::Inference(format!("attention_mask shape error: {e}")))?;

        let input_ids_tensor = ort::value::TensorRef::from_array_view(&input_ids_array)
            .map_err(|e| ModelError::Inference(format!("input_ids tensor error: {e}")))?;
        let mask_tensor = ort::value::TensorRef::from_array_view(&mask_array)
            .map_err(|e| ModelError::Inference(format!("attention_mask tensor error: {e}")))?;

        let outputs = session
            .run(ort::inputs![input_ids_tensor, mask_tensor])
            .map_err(|e| ModelError::Inference(format!("inference error for '{}': {e}", self.name)))?;

        let mut result = Vec::new();
        for (_name, value) in outputs.iter() {
            let (_shape, data) = value.try_extract_tensor::<f32>().map_err(|e| {
                ModelError::Inference(format!("output extraction error: {e}"))
            })?;
            result.push(data.to_vec());
        }

        Ok(result)
    }

    /// Mean-pool hidden states to produce an embedding vector.
    fn compute_embedding(
        &self,
        input_ids: &[i64],
        attention_mask: &[i64],
        dimensions: usize,
    ) -> Result<EmbedResponse, ModelError> {
        let seq_len = input_ids.len();
        let outputs = self.run_inference(input_ids, attention_mask)?;

        if outputs.is_empty() {
            return Err(ModelError::Inference("no output from model".to_string()));
        }

        let hidden_states = &outputs[0];
        let mut embedding = vec![0.0f32; dimensions];
        let mut mask_sum = 0.0f32;

        for pos in 0..seq_len {
            let m = attention_mask[pos] as f32;
            mask_sum += m;
            for dim in 0..dimensions {
                let idx = pos * dimensions + dim;
                if idx < hidden_states.len() {
                    embedding[dim] += hidden_states[idx] * m;
                }
            }
        }

        if mask_sum > 0.0 {
            for v in &mut embedding {
                *v /= mask_sum;
            }
        }

        // L2 normalize
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for v in &mut embedding {
                *v /= norm;
            }
        }

        Ok(EmbedResponse {
            embedding,
            dimensions,
        })
    }

    /// Apply softmax and return classification labels.
    fn compute_classification(
        &self,
        input_ids: &[i64],
        attention_mask: &[i64],
        labels: &[String],
    ) -> Result<ClassifyResponse, ModelError> {
        let outputs = self.run_inference(input_ids, attention_mask)?;

        if outputs.is_empty() {
            return Err(ModelError::Inference("no output from model".to_string()));
        }

        let logits = &outputs[0];
        let max_logit = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let exp_sum: f32 = logits.iter().map(|x| (x - max_logit).exp()).sum();
        let probs: Vec<f32> = logits.iter().map(|x| (x - max_logit).exp() / exp_sum).collect();

        let mut label_results: Vec<ClassifyLabel> = labels
            .iter()
            .enumerate()
            .map(|(i, label)| ClassifyLabel {
                label: label.clone(),
                score: probs.get(i).copied().unwrap_or(0.0),
            })
            .collect();

        label_results
            .sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

        Ok(ClassifyResponse {
            labels: label_results,
        })
    }

    /// Returns the model name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl ModelBackend for OnnxModel {
    fn embed(
        &self,
        request: &EmbedRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<EmbedResponse, ModelError>> + Send + '_>,
    > {
        let dimensions = match &self.task {
            ModelTask::Embedding { dimensions } => *dimensions,
            _ => {
                return Box::pin(async {
                    Err(ModelError::NotLoaded(
                        "model not configured for embeddings".to_string(),
                    ))
                });
            }
        };

        let input_ids = simple_tokenize(&request.text);
        let attention_mask = vec![1i64; input_ids.len()];

        // Run inference synchronously via block_in_place since we hold &self.
        Box::pin(async move {
            let result = tokio::task::block_in_place(|| {
                self.compute_embedding(&input_ids, &attention_mask, dimensions)
            });
            result
        })
    }

    fn classify(
        &self,
        request: &ClassifyRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ClassifyResponse, ModelError>> + Send + '_>,
    > {
        let labels = match &self.task {
            ModelTask::Classification { labels } => labels.clone(),
            _ => {
                return Box::pin(async {
                    Err(ModelError::NotLoaded(
                        "model not configured for classification".to_string(),
                    ))
                });
            }
        };

        let input_ids = simple_tokenize(&request.text);
        let attention_mask = vec![1i64; input_ids.len()];

        Box::pin(async move {
            let result = tokio::task::block_in_place(|| {
                self.compute_classification(&input_ids, &attention_mask, &labels)
            });
            result
        })
    }
}

/// Simple character-level tokenization as a fallback.
///
/// Real models need proper tokenization (BPE, WordPiece) via the
/// `tokenizers` crate with a model-specific vocabulary. This fallback
/// is suitable for testing and models with character-level input.
fn simple_tokenize(text: &str) -> Vec<i64> {
    let mut ids = vec![101i64]; // [CLS]
    for ch in text.chars().take(512) {
        ids.push(ch as i64);
    }
    ids.push(102); // [SEP]
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_tokenize_basic() {
        let ids = simple_tokenize("hello");
        assert_eq!(ids[0], 101);
        assert_eq!(*ids.last().unwrap(), 102);
        assert_eq!(ids.len(), 7);
    }

    #[test]
    fn simple_tokenize_truncates() {
        let long_text = "a".repeat(1000);
        let ids = simple_tokenize(&long_text);
        assert_eq!(ids.len(), 514); // CLS + 512 + SEP
    }

    #[test]
    fn classify_response_top_label() {
        let response = ClassifyResponse {
            labels: vec![
                ClassifyLabel { label: "safe".to_string(), score: 0.9 },
                ClassifyLabel { label: "hap".to_string(), score: 0.1 },
            ],
        };
        assert_eq!(response.top_label().unwrap().label, "safe");
    }

    #[test]
    fn classify_response_is_unsafe() {
        let safe = ClassifyResponse {
            labels: vec![
                ClassifyLabel { label: "safe".to_string(), score: 0.95 },
                ClassifyLabel { label: "hap".to_string(), score: 0.05 },
            ],
        };
        assert!(!safe.is_unsafe(0.5));

        let unsafe_resp = ClassifyResponse {
            labels: vec![
                ClassifyLabel { label: "hap".to_string(), score: 0.8 },
                ClassifyLabel { label: "safe".to_string(), score: 0.2 },
            ],
        };
        assert!(unsafe_resp.is_unsafe(0.5));
    }
}
