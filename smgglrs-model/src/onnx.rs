//! ONNX Runtime backend for in-process model inference.
//!
//! Wraps `ort::session::Session` with an optional HuggingFace tokenizer
//! for text-based models (embeddings, classification). Thread-safe via
//! `std::sync::Mutex`. Uses `block_in_place` to avoid blocking the
//! Tokio executor.

use crate::{
    ClassifyLabel, ClassifyRequest, ClassifyResponse, EmbedRequest, EmbedResponse, ModelBackend,
    ModelError,
};
use std::path::Path;
use std::sync::Mutex;

/// Execution device for ONNX models.
#[derive(Debug, Clone, Default)]
pub enum Device {
    /// CPU execution provider (default, always available).
    #[default]
    Cpu,
    /// OpenVINO execution provider with a specific device target.
    /// Falls back to CPU if OpenVINO is not available.
    OpenVino(OpenVinoDevice),
    /// CUDA execution provider for NVIDIA GPUs.
    /// Falls back to CPU if CUDA is not available.
    Cuda,
}

/// OpenVINO device target.
#[derive(Debug, Clone)]
pub enum OpenVinoDevice {
    /// Automatic device selection (NPU > iGPU > CPU).
    Auto,
    /// Intel NPU (AI Boost).
    Npu,
    /// Intel iGPU (Arc).
    Gpu,
    /// Heterogeneous: split across multiple devices.
    Hetero(String),
}

impl Device {
    /// Parse a device string from config.
    ///
    /// Supported values: `"cpu"`, `"cuda"`, `"openvino"`, `"openvino:AUTO"`,
    /// `"openvino:NPU"`, `"openvino:GPU"`, `"openvino:HETERO:NPU,GPU"`.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "cpu" => Device::Cpu,
            "cuda" => Device::Cuda,
            "openvino" | "openvino:auto" => Device::OpenVino(OpenVinoDevice::Auto),
            "openvino:npu" => Device::OpenVino(OpenVinoDevice::Npu),
            "openvino:gpu" => Device::OpenVino(OpenVinoDevice::Gpu),
            other if other.starts_with("openvino:hetero:") => {
                let spec = &s["openvino:hetero:".len()..];
                Device::OpenVino(OpenVinoDevice::Hetero(spec.to_uppercase()))
            }
            _ => {
                tracing::warn!(device = s, "Unknown device, falling back to CPU");
                Device::Cpu
            }
        }
    }
}

/// An ONNX model loaded into the runtime.
pub struct OnnxBackend {
    session: Mutex<ort::session::Session>,
    tokenizer: Option<tokenizers::Tokenizer>,
    task: ModelTask,
    name: String,
    device: Device,
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

impl OnnxBackend {
    /// Load an ONNX model with an optional HuggingFace tokenizer.
    ///
    /// If `tokenizer_path` points to a valid `tokenizer.json`, it will be
    /// used for proper BPE/WordPiece tokenization. Otherwise, a simple
    /// character-level fallback is used.
    pub fn load(
        name: &str,
        model_path: &Path,
        tokenizer_path: Option<&Path>,
        task: ModelTask,
        device: Device,
    ) -> Result<Self, ModelError> {
        let eps = build_execution_providers(&device);
        let ep_desc = describe_device(&device);

        let mut builder = ort::session::Session::builder()
            .map_err(|e| ModelError::Inference(format!("session builder error: {e}")))?
            .with_execution_providers(eps)
            .map_err(|e| ModelError::Inference(format!("execution provider error: {e}")))?;

        let session = builder.commit_from_file(model_path).map_err(|e| {
            ModelError::Inference(format!(
                "failed to load '{}' from {}: {e}",
                name,
                model_path.display()
            ))
        })?;

        // Load tokenizer if provided
        let tokenizer = match tokenizer_path {
            Some(path) if path.exists() => {
                match tokenizers::Tokenizer::from_file(path) {
                    Ok(tok) => {
                        tracing::info!(
                            model = name,
                            tokenizer = %path.display(),
                            "Loaded HuggingFace tokenizer"
                        );
                        Some(tok)
                    }
                    Err(e) => {
                        tracing::warn!(
                            model = name,
                            tokenizer = %path.display(),
                            error = %e,
                            "Failed to load tokenizer, using fallback"
                        );
                        None
                    }
                }
            }
            Some(path) => {
                tracing::warn!(
                    model = name,
                    tokenizer = %path.display(),
                    "Tokenizer file not found, using fallback"
                );
                None
            }
            None => None,
        };

        tracing::info!(
            model = name,
            path = %model_path.display(),
            device = %ep_desc,
            inputs = session.inputs().len(),
            outputs = session.outputs().len(),
            has_tokenizer = tokenizer.is_some(),
            "Loaded ONNX model"
        );

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            task,
            name: name.to_string(),
            device,
        })
    }

    /// Tokenize text into input_ids and attention_mask.
    ///
    /// Uses the HuggingFace tokenizer if loaded, otherwise falls back
    /// to simple character-level tokenization.
    fn tokenize(&self, text: &str) -> Result<(Vec<i64>, Vec<i64>), ModelError> {
        match &self.tokenizer {
            Some(tok) => {
                let encoding = tok.encode(text, true).map_err(|e| {
                    ModelError::Tokenization(format!("tokenization failed: {e}"))
                })?;
                let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
                let attention_mask: Vec<i64> = encoding
                    .get_attention_mask()
                    .iter()
                    .map(|&m| m as i64)
                    .collect();
                Ok((input_ids, attention_mask))
            }
            None => {
                let input_ids = simple_tokenize(text);
                let attention_mask = vec![1i64; input_ids.len()];
                Ok((input_ids, attention_mask))
            }
        }
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
            .map_err(|e| {
                ModelError::Inference(format!("inference error for '{}': {e}", self.name))
            })?;

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
        let probs: Vec<f32> = logits
            .iter()
            .map(|x| (x - max_logit).exp() / exp_sum)
            .collect();

        let mut label_results: Vec<ClassifyLabel> = labels
            .iter()
            .enumerate()
            .map(|(i, label)| ClassifyLabel {
                label: label.clone(),
                score: probs.get(i).copied().unwrap_or(0.0),
            })
            .collect();

        label_results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(ClassifyResponse {
            labels: label_results,
        })
    }

    /// Returns the model name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether this model has a proper tokenizer loaded.
    pub fn has_tokenizer(&self) -> bool {
        self.tokenizer.is_some()
    }

    /// Returns the execution device this model was loaded with.
    pub fn device(&self) -> &Device {
        &self.device
    }
}

fn build_execution_providers(device: &Device) -> Vec<ort::ep::ExecutionProviderDispatch> {
    match device {
        Device::Cpu => vec![ort::ep::CPU::default().build()],
        Device::OpenVino(ov_device) => {
            let cache_dir =
                std::env::var("XDG_CACHE_HOME").unwrap_or_else(|_| {
                    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                    format!("{home}/.cache")
                });
            let ov_cache = format!("{cache_dir}/smgglrs/openvino");

            let device_type = match ov_device {
                OpenVinoDevice::Auto => "AUTO",
                OpenVinoDevice::Npu => "NPU",
                OpenVinoDevice::Gpu => "GPU",
                OpenVinoDevice::Hetero(spec) => {
                    // Leak is fine: these are created once at startup.
                    Box::leak(format!("HETERO:{spec}").into_boxed_str())
                }
            };

            vec![
                ort::ep::OpenVINO::default()
                    .with_device_type(device_type)
                    .with_cache_dir(&ov_cache)
                    .build(),
                ort::ep::CPU::default().build(),
            ]
        }
        Device::Cuda => {
            vec![
                ort::ep::CUDA::default().build(),
                ort::ep::CPU::default().build(),
            ]
        }
    }
}

fn describe_device(device: &Device) -> &'static str {
    match device {
        Device::Cpu => "CPU",
        Device::OpenVino(OpenVinoDevice::Auto) => "OpenVINO:AUTO",
        Device::OpenVino(OpenVinoDevice::Npu) => "OpenVINO:NPU",
        Device::OpenVino(OpenVinoDevice::Gpu) => "OpenVINO:GPU",
        Device::OpenVino(OpenVinoDevice::Hetero(_)) => "OpenVINO:HETERO",
        Device::Cuda => "CUDA",
    }
}

impl ModelBackend for OnnxBackend {
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

        let tokens = self.tokenize(&request.text);

        Box::pin(async move {
            let (input_ids, attention_mask) = tokens?;
            tokio::task::block_in_place(|| {
                self.compute_embedding(&input_ids, &attention_mask, dimensions)
            })
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

        let tokens = self.tokenize(&request.text);

        Box::pin(async move {
            let (input_ids, attention_mask) = tokens?;
            let labels = labels;
            tokio::task::block_in_place(|| {
                self.compute_classification(&input_ids, &attention_mask, &labels)
            })
        })
    }
}

/// Simple character-level tokenization fallback.
///
/// Used when no HuggingFace tokenizer is loaded. Produces CLS + char
/// codes + SEP, truncated to 512 tokens.
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
                ClassifyLabel {
                    label: "safe".to_string(),
                    score: 0.9,
                },
                ClassifyLabel {
                    label: "hap".to_string(),
                    score: 0.1,
                },
            ],
        };
        assert_eq!(response.top_label().unwrap().label, "safe");
    }

    #[test]
    fn classify_response_is_unsafe() {
        let safe = ClassifyResponse {
            labels: vec![
                ClassifyLabel {
                    label: "safe".to_string(),
                    score: 0.95,
                },
                ClassifyLabel {
                    label: "hap".to_string(),
                    score: 0.05,
                },
            ],
        };
        assert!(!safe.is_unsafe(0.5));

        let unsafe_resp = ClassifyResponse {
            labels: vec![
                ClassifyLabel {
                    label: "hap".to_string(),
                    score: 0.8,
                },
                ClassifyLabel {
                    label: "safe".to_string(),
                    score: 0.2,
                },
            ],
        };
        assert!(unsafe_resp.is_unsafe(0.5));
    }
}
