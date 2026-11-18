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

/// Maximum sequence length (in tokens) fed to ONNX models.
///
/// Bounds the O(n²) attention memory and matches the BERT-family
/// context window these models were trained with. The
/// character-level fallback (`simple_tokenize`) truncates to the
/// same cap, and the HuggingFace tokenizer gets a `TruncationParams`
/// with this max length at load time.
pub const MAX_SEQ_TOKENS: usize = 512;

/// Maximum input size (in chars) accepted at the embed/classify
/// entry points.
///
/// Pre-truncates before tokenization so the cost of tokenizing an
/// adversarial multi-megabyte input is bounded even though the
/// tokenizer itself scans the whole input.
const MAX_INPUT_CHARS: usize = MAX_SEQ_TOKENS * 8;

/// Apply sequence-length truncation to a tokenizer.
///
/// Encodes longer than `MAX_SEQ_TOKENS` are truncated by the
/// tokenizer itself, closing the gap with the character-level
/// fallback (which always capped at 512). If the tokenizer rejects
/// the truncation parameters, the hard cap in [`OnnxBackend::tokenize`]
/// still bounds the sequence.
fn apply_truncation(mut tok: tokenizers::Tokenizer) -> tokenizers::Tokenizer {
    if let Err(e) = tok.with_truncation(Some(tokenizers::TruncationParams {
        max_length: MAX_SEQ_TOKENS,
        ..Default::default()
    })) {
        tracing::warn!(error = %e, "failed to configure tokenizer truncation; relying on hard cap");
    }
    tok
}

/// Pre-truncate input text at the inference entry points.
fn cap_input(text: &str) -> String {
    text.chars().take(MAX_INPUT_CHARS).collect()
}

/// Probe the tokenizer's chars-per-token ratio on dense CJK text.
///
/// CJK scripts are the worst case for subword tokenizers (many emit
/// ~1 token per char, vs ~3-4 chars/token for English BPE), so this
/// ratio is the safe bound for sizing character windows against a
/// token budget. Returns 1.0 (most conservative) if the probe fails.
fn cjk_chars_per_token(tok: &tokenizers::Tokenizer) -> f64 {
    const SAMPLE_CHARS: usize = 64;
    let sample = "字".repeat(SAMPLE_CHARS);
    match tok.encode(sample.as_str(), false) {
        Ok(encoding) => {
            let tokens = encoding.get_ids().len().max(1);
            SAMPLE_CHARS as f64 / tokens as f64
        }
        Err(_) => 1.0,
    }
}

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
        let ep_desc = describe_device(&device);
        let session = build_onnx_session(model_path, &device)?;

        // Load tokenizer if provided
        let tokenizer = match tokenizer_path {
            Some(path) if path.exists() => match tokenizers::Tokenizer::from_file(path) {
                Ok(tok) => {
                    let tok = apply_truncation(tok);
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
            },
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
                let encoding = tok
                    .encode(text, true)
                    .map_err(|e| ModelError::Tokenization(format!("tokenization failed: {e}")))?;
                let mut input_ids: Vec<i64> =
                    encoding.get_ids().iter().map(|&id| id as i64).collect();
                let mut attention_mask: Vec<i64> = encoding
                    .get_attention_mask()
                    .iter()
                    .map(|&m| m as i64)
                    .collect();
                // Hard cap: guarantee the sequence bound even if the
                // tokenizer's truncation could not be configured.
                input_ids.truncate(MAX_SEQ_TOKENS);
                attention_mask.truncate(MAX_SEQ_TOKENS);
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
        let mut session = self.session.lock().unwrap_or_else(|e| e.into_inner());
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
            let (_shape, data) = value
                .try_extract_tensor::<f32>()
                .map_err(|e| ModelError::Inference(format!("output extraction error: {e}")))?;
            result.push(data.to_vec());
        }

        Ok(result)
    }

    /// Mean-pool hidden states to produce an embedding vector.
    ///
    /// Supports Matryoshka dimension truncation: if `target_dimensions` is
    /// smaller than the model's native hidden size, mean-pools at native
    /// dimensions first, then truncates and re-normalizes. This produces
    /// valid lower-dimensional embeddings from Matryoshka-trained models.
    fn compute_embedding(
        &self,
        input_ids: &[i64],
        attention_mask: &[i64],
        target_dimensions: usize,
    ) -> Result<EmbedResponse, ModelError> {
        let seq_len = input_ids.len();
        let outputs = self.run_inference(input_ids, attention_mask)?;

        if outputs.is_empty() {
            return Err(ModelError::Inference("no output from model".to_string()));
        }

        let hidden_states = &outputs[0];
        let hidden_dim = hidden_states
            .len()
            .checked_div(seq_len)
            .unwrap_or(target_dimensions);

        let pool_dim = hidden_dim.max(target_dimensions);
        let mut embedding = vec![0.0f32; pool_dim];
        let mut mask_sum = 0.0f32;

        for (pos, &mask_val) in attention_mask.iter().enumerate().take(seq_len) {
            let m = mask_val as f32;
            mask_sum += m;
            for (dim, emb_val) in embedding.iter_mut().enumerate().take(pool_dim) {
                let idx = pos * hidden_dim + dim;
                if idx < hidden_states.len() {
                    *emb_val += hidden_states[idx] * m;
                }
            }
        }

        if mask_sum > 0.0 {
            for v in &mut embedding {
                *v /= mask_sum;
            }
        }

        // Matryoshka truncation: take first target_dimensions elements
        embedding.truncate(target_dimensions);

        // L2 normalize (re-normalize after truncation for Matryoshka)
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for v in &mut embedding {
                *v /= norm;
            }
        }

        Ok(EmbedResponse {
            embedding,
            dimensions: target_dimensions,
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

    /// Maximum input length (in tokens) fed to the model per
    /// inference call.
    ///
    /// Inputs longer than this are truncated (by the tokenizer or
    /// the hard cap in [`OnnxBackend::tokenize`]) before inference,
    /// so windowing callers must slice inputs into sub-windows
    /// aligned to this budget. Exposed so safety-filter windowing
    /// (navra-safety's ML filters) can size its sub-windows without
    /// guessing.
    pub fn max_input_tokens(&self) -> usize {
        MAX_SEQ_TOKENS
    }

    /// Maximum input length (in chars) fed to the model per inference
    /// call, measured from the actual tokenizer.
    ///
    /// - No tokenizer (character-level fallback): exactly one char per
    ///   token, so the budget is [`MAX_SEQ_TOKENS`] chars.
    /// - HuggingFace tokenizer: probed with a dense CJK sample
    ///   (`字` × 64). CJK is the worst case for subword tokenizers
    ///   (~1 token per char), so the measured chars-per-token ratio,
    ///   clamped to `[1, 3]` (3 being the conservative ASCII BPE
    ///   default), yields a budget that never over-reports what the
    ///   tokenizer actually accepts.
    pub fn max_input_chars(&self) -> usize {
        max_input_chars_for(self.tokenizer.as_ref())
    }

    /// Returns the execution device this model was loaded with.
    pub fn device(&self) -> &Device {
        &self.device
    }
}

/// Compute the per-call character budget for a tokenizer option.
///
/// Split from [`OnnxBackend::max_input_chars`] so both paths (with
/// and without a tokenizer) are testable without a model file.
fn max_input_chars_for(tokenizer: Option<&tokenizers::Tokenizer>) -> usize {
    match tokenizer {
        // Character-level fallback: 1 char per token.
        None => MAX_SEQ_TOKENS,
        Some(tok) => {
            let chars_per_token = cjk_chars_per_token(tok).clamp(1.0, 3.0);
            (MAX_SEQ_TOKENS as f64 * chars_per_token) as usize
        }
    }
}

/// Build an ONNX Runtime session from a model file with the specified device.
///
/// Shared entry point for all crates that load ONNX models. Handles EP
/// construction, fallback, and error mapping.
pub fn build_onnx_session(
    model_path: &Path,
    device: &Device,
) -> Result<ort::session::Session, ModelError> {
    let eps = build_execution_providers(device);
    let mut builder = ort::session::Session::builder()
        .map_err(|e| ModelError::Inference(format!("session builder error: {e}")))?
        .with_execution_providers(eps)
        .map_err(|e| ModelError::Inference(format!("execution provider error: {e}")))?;

    builder.commit_from_file(model_path).map_err(|e| {
        ModelError::Inference(format!(
            "failed to load model from {}: {e}",
            model_path.display()
        ))
    })
}

/// Build execution providers for the given device target.
pub fn build_execution_providers(device: &Device) -> Vec<ort::ep::ExecutionProviderDispatch> {
    match device {
        Device::Cpu => vec![ort::ep::CPU::default().build()],
        Device::OpenVino(_ov_device) => {
            #[cfg(feature = "openvino")]
            {
                let cache_dir = std::env::var("XDG_CACHE_HOME").unwrap_or_else(|_| {
                    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                    format!("{home}/.cache")
                });
                let ov_cache = format!("{cache_dir}/navra/openvino");

                let device_type = match _ov_device {
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
            #[cfg(not(feature = "openvino"))]
            {
                tracing::warn!(
                    "OpenVINO device requested but navra-model was built without the 'openvino' feature — falling back to CPU"
                );
                vec![ort::ep::CPU::default().build()]
            }
        }
        Device::Cuda => {
            #[cfg(feature = "cuda")]
            {
                vec![
                    ort::ep::CUDA::default().build(),
                    ort::ep::CPU::default().build(),
                ]
            }
            #[cfg(not(feature = "cuda"))]
            {
                tracing::warn!(
                    "CUDA device requested but navra-model was built without the 'cuda' feature — falling back to CPU"
                );
                vec![ort::ep::CPU::default().build()]
            }
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

        let tokens = self.tokenize(&cap_input(&request.text));

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

        let tokens = self.tokenize(&cap_input(&request.text));

        Box::pin(async move {
            let (input_ids, attention_mask) = tokens?;
            let labels = labels;
            tokio::task::block_in_place(|| {
                self.compute_classification(&input_ids, &attention_mask, &labels)
            })
        })
    }

    fn max_input_chars(&self) -> Option<usize> {
        // Disambiguate from the inherent method of the same name.
        Some(OnnxBackend::max_input_chars(self))
    }
}

/// Simple character-level tokenization fallback.
///
/// Used when no HuggingFace tokenizer is loaded. Produces CLS + char
/// codes + SEP, truncated to [`MAX_SEQ_TOKENS`] characters.
fn simple_tokenize(text: &str) -> Vec<i64> {
    let mut ids = vec![101i64]; // [CLS]
    for ch in text.chars().take(MAX_SEQ_TOKENS) {
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
        assert_eq!(ids.len(), MAX_SEQ_TOKENS + 2); // CLS + MAX_SEQ_TOKENS + SEP
    }

    #[test]
    fn cap_input_bounds_entry_point() {
        let long_text = "a".repeat(MAX_INPUT_CHARS * 4);
        let capped = cap_input(&long_text);
        assert_eq!(capped.chars().count(), MAX_INPUT_CHARS);
        // Normal input passes through unchanged.
        assert_eq!(cap_input("hello world"), "hello world");
    }

    /// Build a minimal WordPiece tokenizer via its serde form so the
    /// truncation behavior can be tested without a model file.
    fn test_tokenizer() -> tokenizers::Tokenizer {
        let json = r###"{
            "version": "1.0",
            "truncation": null,
            "padding": null,
            "added_tokens": [],
            "normalizer": null,
            "pre_tokenizer": { "type": "Whitespace" },
            "post_processor": null,
            "decoder": null,
            "model": {
                "type": "WordPiece",
                "vocab": { "[UNK]": 0, "a": 1, "b": 2 },
                "unk_token": "[UNK]",
                "continuing_subword_prefix": "##",
                "max_input_chars_per_word": 100
            }
        }"###;
        serde_json::from_str(json).expect("valid tokenizer json")
    }

    #[test]
    fn hf_tokenizer_truncation_caps_token_count() {
        let tok = apply_truncation(test_tokenizer());
        let encoding = tok
            .encode("a".repeat(10_000), true)
            .expect("encode succeeds");
        assert!(
            encoding.get_ids().len() <= MAX_SEQ_TOKENS,
            "token count {} must be capped at {}",
            encoding.get_ids().len(),
            MAX_SEQ_TOKENS
        );
    }

    #[test]
    fn hf_tokenizer_normal_input_unaffected() {
        let tok = apply_truncation(test_tokenizer());
        let encoding = tok.encode("a b a", true).expect("encode succeeds");
        assert_eq!(encoding.get_ids().len(), 3);
    }

    #[test]
    fn cjk_probe_measures_chars_per_token() {
        // The test tokenizer's vocab has no CJK, so the dense sample
        // collapses to a single [UNK] token — ratio 64 chars/token,
        // i.e. the tokenizer accepts far more chars than tokens.
        let ratio = cjk_chars_per_token(&test_tokenizer());
        assert!(
            ratio > 3.0,
            "UNK-collapsing tokenizer must report a high ratio"
        );
    }

    #[test]
    fn cjk_probe_one_char_per_token() {
        // A tokenizer whose vocab covers the sample char emits one
        // token per char: ratio 1.0.
        let json = r###"{
            "version": "1.0",
            "truncation": null,
            "padding": null,
            "added_tokens": [],
            "normalizer": null,
            "pre_tokenizer": { "type": "Whitespace" },
            "post_processor": null,
            "decoder": null,
            "model": {
                "type": "WordPiece",
                "vocab": { "[UNK]": 0, "字": 1 },
                "unk_token": "[UNK]",
                "continuing_subword_prefix": "##",
                "max_input_chars_per_word": 100
            }
        }"###;
        let tok: tokenizers::Tokenizer = serde_json::from_str(json).expect("valid tokenizer json");
        // Whitespace pre-tokenization leaves the unspaced sample as
        // one word; WordPiece with the char in vocab splits it into
        // one token per char.
        let ratio = cjk_chars_per_token(&tok);
        assert!(
            (ratio - 1.0).abs() < 1e-9,
            "1-char-per-token expected, got {ratio}"
        );
    }

    #[test]
    fn max_input_chars_fallback_is_one_char_per_token() {
        // No tokenizer: the character-level fallback tokenizes
        // exactly 1 char per token, so the char budget equals the
        // token budget.
        assert_eq!(max_input_chars_for(None), MAX_SEQ_TOKENS);
    }

    #[test]
    fn max_input_chars_from_tokenizer_clamped() {
        // UNK-collapsing tokenizer: ratio 64 clamps to 3 chars/token
        // (the conservative ASCII default).
        assert_eq!(
            max_input_chars_for(Some(&test_tokenizer())),
            MAX_SEQ_TOKENS * 3
        );
        // 1-char-per-token CJK tokenizer: budget equals the token
        // budget — a 3-chars/token heuristic would have over-reported
        // by 3x and left two thirds of each window unclassified.
        let json = r###"{
            "version": "1.0",
            "truncation": null,
            "padding": null,
            "added_tokens": [],
            "normalizer": null,
            "pre_tokenizer": { "type": "Whitespace" },
            "post_processor": null,
            "decoder": null,
            "model": {
                "type": "WordPiece",
                "vocab": { "[UNK]": 0, "字": 1 },
                "unk_token": "[UNK]",
                "continuing_subword_prefix": "##",
                "max_input_chars_per_word": 100
            }
        }"###;
        let tok: tokenizers::Tokenizer = serde_json::from_str(json).expect("valid tokenizer json");
        assert_eq!(max_input_chars_for(Some(&tok)), MAX_SEQ_TOKENS);
    }

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn matryoshka_truncation_logic() {
        // Simulate hidden_states for 2 tokens, 4 dims each
        // Token 0: [1.0, 2.0, 3.0, 4.0], Token 1: [2.0, 4.0, 6.0, 8.0]
        let hidden_states: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0, 2.0, 4.0, 6.0, 8.0];
        let attention_mask: Vec<i64> = vec![1, 1];
        let seq_len = 2;
        let hidden_dim = 4;
        let target_dimensions = 2; // Matryoshka: truncate 4d -> 2d

        let pool_dim = hidden_dim.max(target_dimensions);
        let mut embedding = vec![0.0f32; pool_dim];
        let mut mask_sum = 0.0f32;

        for pos in 0..seq_len {
            let m = attention_mask[pos] as f32;
            mask_sum += m;
            for dim in 0..pool_dim {
                let idx = pos * hidden_dim + dim;
                if idx < hidden_states.len() {
                    embedding[dim] += hidden_states[idx] * m;
                }
            }
        }

        for v in &mut embedding {
            *v /= mask_sum;
        }

        // Mean-pooled full: [(1+2)/2, (2+4)/2, (3+6)/2, (4+8)/2] = [1.5, 3.0, 4.5, 6.0]
        assert!((embedding[0] - 1.5).abs() < 1e-6);
        assert!((embedding[1] - 3.0).abs() < 1e-6);
        assert!((embedding[2] - 4.5).abs() < 1e-6);
        assert!((embedding[3] - 6.0).abs() < 1e-6);

        // Truncate to target_dimensions
        embedding.truncate(target_dimensions);
        assert_eq!(embedding.len(), 2);
        assert!((embedding[0] - 1.5).abs() < 1e-6);
        assert!((embedding[1] - 3.0).abs() < 1e-6);

        // Re-normalize
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        for v in &mut embedding {
            *v /= norm;
        }
        let norm_check: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm_check - 1.0).abs() < 1e-5);
    }

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn matryoshka_full_dimensions_passthrough() {
        // When target_dimensions == hidden_dim, truncation is a no-op
        let hidden_states: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0];
        let _seq_len = 1;
        let hidden_dim = 4;
        let target_dimensions = 4;

        let pool_dim = hidden_dim.max(target_dimensions);
        let mut embedding = vec![0.0f32; pool_dim];

        for dim in 0..pool_dim {
            let idx = dim;
            if idx < hidden_states.len() {
                embedding[dim] += hidden_states[idx];
            }
        }

        embedding.truncate(target_dimensions);
        assert_eq!(embedding.len(), 4);
        assert!((embedding[0] - 1.0).abs() < 1e-6);
        assert!((embedding[3] - 4.0).abs() < 1e-6);
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
