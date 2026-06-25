//! Two-stage retrieval: cross-encoder reranking after vector search.
//!
//! After sqlite-vec returns approximate nearest neighbors, a cross-encoder
//! scores each (query, candidate) pair for fine-grained relevance. This
//! dramatically improves precision without sacrificing recall.
//!
//! The [`Reranker`] trait allows pluggable implementations:
//! - [`CrossEncoderReranker`] — ONNX cross-encoder (e.g. MiniLM-L6-v2)
//! - [`NoopReranker`] — passthrough for graceful degradation

use crate::store::ChunkResult;
use std::path::Path;
use std::sync::Mutex;

/// Trait for reranking search results after initial vector retrieval.
pub trait Reranker: Send + Sync {
    /// Rerank candidates by relevance to the query.
    ///
    /// Returns candidates sorted by descending relevance score.
    /// The `distance` field on each result is replaced with the
    /// cross-encoder score (higher = more relevant, negated for
    /// compatibility with the distance convention: lower = better).
    fn rerank(&self, query: &str, candidates: Vec<ChunkResult>) -> Vec<ChunkResult>;

    /// Whether this reranker actually rescores candidates.
    ///
    /// Returns `false` for `NoopReranker`. When `false`, the search
    /// pipeline skips over-fetching from the vector index.
    fn is_active(&self) -> bool {
        true
    }
}

/// Passthrough reranker that returns candidates unchanged.
///
/// Used when no cross-encoder model is available. Ensures the
/// pipeline always works, with graceful degradation.
pub struct NoopReranker;

impl Reranker for NoopReranker {
    fn rerank(&self, _query: &str, candidates: Vec<ChunkResult>) -> Vec<ChunkResult> {
        candidates
    }

    fn is_active(&self) -> bool {
        false
    }
}

#[cfg(feature = "onnx")]
mod onnx_reranker {
    use super::*;

    /// Cross-encoder reranker using an ONNX model.
    ///
    /// Scores each (query, candidate) pair independently. The model
    /// takes two text segments as input and produces a relevance score.
    /// Typical model: `cross-encoder/ms-marco-MiniLM-L-6-v2`.
    ///
    /// The ONNX model must accept `input_ids`, `attention_mask`, and
    /// `token_type_ids` tensors and output a single logit per pair.
    pub struct CrossEncoderReranker {
        session: Mutex<ort::session::Session>,
        tokenizer: tokenizers::Tokenizer,
        name: String,
    }

    impl CrossEncoderReranker {
        /// Load a cross-encoder ONNX model.
        ///
        /// `model_path` — path to the `.onnx` file.
        /// `tokenizer_path` — path to the HuggingFace `tokenizer.json`.
        pub fn load(
            name: &str,
            model_path: &Path,
            tokenizer_path: &Path,
        ) -> Result<Self, CrossEncoderError> {
            let session =
                navra_model::onnx::build_onnx_session(model_path, &navra_model::onnx::Device::Cpu)
                    .map_err(|e| CrossEncoderError::Load(format!("{e}")))?;

            let tokenizer = tokenizers::Tokenizer::from_file(tokenizer_path).map_err(|e| {
                CrossEncoderError::Load(format!(
                    "failed to load tokenizer from {}: {e}",
                    tokenizer_path.display()
                ))
            })?;

            tracing::info!(
                model = name,
                path = %model_path.display(),
                tokenizer = %tokenizer_path.display(),
                "Loaded cross-encoder reranker"
            );

            Ok(Self {
                session: Mutex::new(session),
                tokenizer,
                name: name.to_string(),
            })
        }

        /// Score all (query, candidate) pairs in a single batched ONNX call.
        ///
        /// Tokenizes all pairs, pads to uniform length, concatenates into
        /// batch tensors, and runs one inference. Returns one score per pair.
        fn score_batch(
            &self,
            query: &str,
            documents: &[&str],
        ) -> Result<Vec<f32>, CrossEncoderError> {
            if documents.is_empty() {
                return Ok(Vec::new());
            }

            let encodings: Vec<_> = documents
                .iter()
                .map(|doc| {
                    self.tokenizer
                        .encode((query, *doc), true)
                        .map_err(|e| CrossEncoderError::Inference(format!("tokenization: {e}")))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let max_len = encodings
                .iter()
                .map(|e| e.get_ids().len())
                .max()
                .unwrap_or(0);
            let batch_size = encodings.len();

            let mut all_ids = vec![0i64; batch_size * max_len];
            let mut all_mask = vec![0i64; batch_size * max_len];
            let mut all_types = vec![0i64; batch_size * max_len];

            for (i, enc) in encodings.iter().enumerate() {
                let ids = enc.get_ids();
                let mask = enc.get_attention_mask();
                let types = enc.get_type_ids();
                let offset = i * max_len;
                for (j, (&id, (&m, &t))) in
                    ids.iter().zip(mask.iter().zip(types.iter())).enumerate()
                {
                    all_ids[offset + j] = id as i64;
                    all_mask[offset + j] = m as i64;
                    all_types[offset + j] = t as i64;
                }
            }

            let ids_array = ndarray::Array2::from_shape_vec((batch_size, max_len), all_ids)
                .map_err(|e| CrossEncoderError::Inference(format!("batch input_ids shape: {e}")))?;
            let mask_array = ndarray::Array2::from_shape_vec((batch_size, max_len), all_mask)
                .map_err(|e| {
                    CrossEncoderError::Inference(format!("batch attention_mask shape: {e}"))
                })?;
            let type_array = ndarray::Array2::from_shape_vec((batch_size, max_len), all_types)
                .map_err(|e| {
                    CrossEncoderError::Inference(format!("batch token_type_ids shape: {e}"))
                })?;

            let ids_tensor = ort::value::TensorRef::from_array_view(&ids_array)
                .map_err(|e| CrossEncoderError::Inference(format!("batch ids tensor: {e}")))?;
            let mask_tensor = ort::value::TensorRef::from_array_view(&mask_array)
                .map_err(|e| CrossEncoderError::Inference(format!("batch mask tensor: {e}")))?;
            let type_tensor = ort::value::TensorRef::from_array_view(&type_array)
                .map_err(|e| CrossEncoderError::Inference(format!("batch type tensor: {e}")))?;

            let mut session = self.session.lock().unwrap();
            let outputs = session
                .run(ort::inputs![ids_tensor, mask_tensor, type_tensor])
                .map_err(|e| {
                    CrossEncoderError::Inference(format!(
                        "batch inference error for '{}': {e}",
                        self.name
                    ))
                })?;

            let (_name, output) = outputs.iter().next().ok_or_else(|| {
                CrossEncoderError::Inference("no output from cross-encoder".to_string())
            })?;

            let (_shape, data) = output.try_extract_tensor::<f32>().map_err(|e| {
                CrossEncoderError::Inference(format!("batch output extraction: {e}"))
            })?;

            let output_cols = data.len() / batch_size;
            let mut scores = Vec::with_capacity(batch_size);
            for i in 0..batch_size {
                let offset = i * output_cols;
                let score = if output_cols == 1 {
                    data[offset]
                } else if output_cols >= 2 {
                    let max = data[offset].max(data[offset + 1]);
                    let exp0 = (data[offset] - max).exp();
                    let exp1 = (data[offset + 1] - max).exp();
                    exp1 / (exp0 + exp1)
                } else {
                    0.0
                };
                scores.push(score);
            }

            Ok(scores)
        }

        /// Score a single (query, document) pair.
        ///
        /// Returns a relevance score (higher = more relevant).
        fn score_pair(&self, query: &str, document: &str) -> Result<f32, CrossEncoderError> {
            // Encode the pair — the tokenizer handles [CLS] query [SEP] doc [SEP]
            let encoding = self
                .tokenizer
                .encode((query, document), true)
                .map_err(|e| CrossEncoderError::Inference(format!("tokenization: {e}")))?;

            let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
            let attention_mask: Vec<i64> = encoding
                .get_attention_mask()
                .iter()
                .map(|&m| m as i64)
                .collect();
            let token_type_ids: Vec<i64> =
                encoding.get_type_ids().iter().map(|&t| t as i64).collect();

            let seq_len = input_ids.len();

            let ids_array = ndarray::Array2::from_shape_vec((1, seq_len), input_ids)
                .map_err(|e| CrossEncoderError::Inference(format!("input_ids shape: {e}")))?;
            let mask_array = ndarray::Array2::from_shape_vec((1, seq_len), attention_mask)
                .map_err(|e| CrossEncoderError::Inference(format!("attention_mask shape: {e}")))?;
            let type_array = ndarray::Array2::from_shape_vec((1, seq_len), token_type_ids)
                .map_err(|e| CrossEncoderError::Inference(format!("token_type_ids shape: {e}")))?;

            let ids_tensor = ort::value::TensorRef::from_array_view(&ids_array)
                .map_err(|e| CrossEncoderError::Inference(format!("input_ids tensor: {e}")))?;
            let mask_tensor = ort::value::TensorRef::from_array_view(&mask_array)
                .map_err(|e| CrossEncoderError::Inference(format!("attention_mask tensor: {e}")))?;
            let type_tensor = ort::value::TensorRef::from_array_view(&type_array)
                .map_err(|e| CrossEncoderError::Inference(format!("token_type_ids tensor: {e}")))?;

            let mut session = self.session.lock().unwrap();
            let outputs = session
                .run(ort::inputs![ids_tensor, mask_tensor, type_tensor])
                .map_err(|e| {
                    CrossEncoderError::Inference(format!(
                        "inference error for '{}': {e}",
                        self.name
                    ))
                })?;

            // Cross-encoder outputs a single logit per pair
            let (_name, output) = outputs.iter().next().ok_or_else(|| {
                CrossEncoderError::Inference("no output from cross-encoder".to_string())
            })?;

            let (_shape, data) = output
                .try_extract_tensor::<f32>()
                .map_err(|e| CrossEncoderError::Inference(format!("output extraction: {e}")))?;

            // The model may output a single value or a pair [not-relevant, relevant].
            // For ms-marco models, it's a single logit.
            let score = if data.len() == 1 {
                data[0]
            } else if data.len() >= 2 {
                // Softmax and take "relevant" class
                let max = data[0].max(data[1]);
                let exp0 = (data[0] - max).exp();
                let exp1 = (data[1] - max).exp();
                exp1 / (exp0 + exp1)
            } else {
                0.0
            };

            Ok(score)
        }
    }

    impl Reranker for CrossEncoderReranker {
        fn rerank(&self, query: &str, candidates: Vec<ChunkResult>) -> Vec<ChunkResult> {
            if candidates.is_empty() {
                return candidates;
            }

            // Try batched scoring first (one ONNX call for all pairs)
            let docs: Vec<&str> = candidates.iter().map(|c| c.content.as_str()).collect();
            let scores = match self.score_batch(query, &docs) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        candidates = candidates.len(),
                        "Batch scoring failed, falling back to sequential"
                    );
                    candidates
                        .iter()
                        .map(|c| {
                            self.score_pair(query, &c.content)
                                .unwrap_or(-(c.distance as f32))
                        })
                        .collect()
                }
            };

            let mut scored: Vec<(ChunkResult, f32)> = candidates.into_iter().zip(scores).collect();

            scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            scored
                .into_iter()
                .map(|(mut c, score)| {
                    c.distance = -(score as f64);
                    c
                })
                .collect()
        }
    }

    /// Error type for cross-encoder operations.
    #[derive(Debug, thiserror::Error)]
    pub enum CrossEncoderError {
        #[error("failed to load cross-encoder: {0}")]
        Load(String),
        #[error("cross-encoder inference failed: {0}")]
        Inference(String),
    }
}

#[cfg(feature = "onnx")]
pub use onnx_reranker::{CrossEncoderError, CrossEncoderReranker};

/// Try to load a cross-encoder reranker, falling back to noop.
///
/// This is the recommended way to create a reranker — it provides
/// graceful degradation when the model files are not available.
#[cfg(feature = "onnx")]
pub fn load_reranker(
    model_path: Option<&Path>,
    tokenizer_path: Option<&Path>,
) -> Box<dyn Reranker> {
    match (model_path, tokenizer_path) {
        (Some(model), Some(tokenizer)) if model.exists() && tokenizer.exists() => {
            match CrossEncoderReranker::load("cross-encoder", model, tokenizer) {
                Ok(reranker) => {
                    tracing::info!("Cross-encoder reranker loaded");
                    Box::new(reranker)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to load cross-encoder, using noop reranker");
                    Box::new(NoopReranker)
                }
            }
        }
        _ => {
            tracing::debug!("No cross-encoder model configured, using noop reranker");
            Box::new(NoopReranker)
        }
    }
}

#[cfg(not(feature = "onnx"))]
pub fn load_reranker(
    _model_path: Option<&Path>,
    _tokenizer_path: Option<&Path>,
) -> Box<dyn Reranker> {
    tracing::debug!("ONNX disabled, using noop reranker");
    Box::new(NoopReranker)
}

/// Configuration for confidence-based abstention.
#[derive(Debug, Clone)]
pub struct ConfidenceGate {
    pub threshold: f32,
    pub abstain_message: String,
}

impl Default for ConfidenceGate {
    fn default() -> Self {
        Self {
            threshold: 0.4,
            abstain_message: "Insufficient information to answer this query.".to_string(),
        }
    }
}

/// Reranker wrapper that filters results below a confidence threshold.
///
/// After the inner reranker scores candidates, computes the mean score
/// of the top-k results. If below the gate threshold, returns an empty
/// Vec (abstention). The caller checks for empty results and surfaces
/// the abstain message.
pub struct GatedReranker {
    inner: Box<dyn Reranker>,
    gate: ConfidenceGate,
}

impl GatedReranker {
    pub fn new(inner: Box<dyn Reranker>, gate: ConfidenceGate) -> Self {
        Self { inner, gate }
    }

    pub fn gate(&self) -> &ConfidenceGate {
        &self.gate
    }
}

impl Reranker for GatedReranker {
    fn rerank(&self, query: &str, candidates: Vec<ChunkResult>) -> Vec<ChunkResult> {
        let reranked = self.inner.rerank(query, candidates);
        if reranked.is_empty() {
            return reranked;
        }

        // Cross-encoder reranker negates scores (lower = better).
        // Compute mean of the absolute scores for gating.
        let mean_score: f32 = reranked
            .iter()
            .map(|c| c.distance.abs() as f32)
            .sum::<f32>()
            / reranked.len() as f32;

        if mean_score < self.gate.threshold {
            tracing::info!(
                mean_score,
                threshold = self.gate.threshold,
                candidates = reranked.len(),
                "Confidence gate: abstaining (mean score below threshold)"
            );
            return Vec::new();
        }

        reranked
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_results() -> Vec<ChunkResult> {
        vec![
            ChunkResult {
                path: "/a.md".to_string(),
                content: "Rust is a systems programming language".to_string(),
                chunk_index: 0,
                distance: 0.3,
            },
            ChunkResult {
                path: "/b.md".to_string(),
                content: "Python is a dynamic scripting language".to_string(),
                chunk_index: 0,
                distance: 0.1,
            },
            ChunkResult {
                path: "/c.md".to_string(),
                content: "Go is a compiled language by Google".to_string(),
                chunk_index: 0,
                distance: 0.2,
            },
        ]
    }

    #[test]
    fn noop_reranker_preserves_order() {
        let reranker = NoopReranker;
        let candidates = sample_results();
        let original_paths: Vec<_> = candidates.iter().map(|c| c.path.clone()).collect();
        let reranked = reranker.rerank("what is rust?", candidates);
        let reranked_paths: Vec<_> = reranked.iter().map(|c| c.path.clone()).collect();
        assert_eq!(original_paths, reranked_paths);
    }

    #[test]
    fn noop_reranker_preserves_distances() {
        let reranker = NoopReranker;
        let candidates = sample_results();
        let original_distances: Vec<_> = candidates.iter().map(|c| c.distance).collect();
        let reranked = reranker.rerank("query", candidates);
        let reranked_distances: Vec<_> = reranked.iter().map(|c| c.distance).collect();
        assert_eq!(original_distances, reranked_distances);
    }

    #[test]
    fn noop_reranker_empty_candidates() {
        let reranker = NoopReranker;
        let reranked = reranker.rerank("query", Vec::new());
        assert!(reranked.is_empty());
    }

    #[test]
    fn load_reranker_no_paths_returns_noop() {
        let reranker = load_reranker(None, None);
        // Verify it works as a noop (preserves order)
        let candidates = sample_results();
        let paths_before: Vec<_> = candidates.iter().map(|c| c.path.clone()).collect();
        let reranked = reranker.rerank("query", candidates);
        let paths_after: Vec<_> = reranked.iter().map(|c| c.path.clone()).collect();
        assert_eq!(paths_before, paths_after);
    }

    #[test]
    fn load_reranker_missing_files_returns_noop() {
        let reranker = load_reranker(
            Some(Path::new("/nonexistent/model.onnx")),
            Some(Path::new("/nonexistent/tokenizer.json")),
        );
        let candidates = sample_results();
        let paths_before: Vec<_> = candidates.iter().map(|c| c.path.clone()).collect();
        let reranked = reranker.rerank("query", candidates);
        let paths_after: Vec<_> = reranked.iter().map(|c| c.path.clone()).collect();
        assert_eq!(paths_before, paths_after);
    }

    /// Test that the reranking trait object can be stored in an Arc.
    #[test]
    fn reranker_is_arc_compatible() {
        use std::sync::Arc;
        let reranker: Arc<dyn Reranker> = Arc::new(NoopReranker);
        let candidates = sample_results();
        let reranked = reranker.rerank("query", candidates);
        assert_eq!(reranked.len(), 3);
    }

    /// A test reranker that assigns known scores for confidence gating tests.
    struct FixedScoreReranker(f64);

    impl Reranker for FixedScoreReranker {
        fn rerank(&self, _query: &str, candidates: Vec<ChunkResult>) -> Vec<ChunkResult> {
            candidates
                .into_iter()
                .map(|mut c| {
                    c.distance = -self.0; // negated score convention
                    c
                })
                .collect()
        }
    }

    #[test]
    fn gated_reranker_passes_high_confidence() {
        let gate = ConfidenceGate {
            threshold: 0.3,
            abstain_message: "abstain".to_string(),
        };
        let reranker = GatedReranker::new(Box::new(FixedScoreReranker(0.8)), gate);
        let results = reranker.rerank("query", sample_results());
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn gated_reranker_abstains_low_confidence() {
        let gate = ConfidenceGate {
            threshold: 0.5,
            abstain_message: "not enough info".to_string(),
        };
        let reranker = GatedReranker::new(Box::new(FixedScoreReranker(0.2)), gate);
        let results = reranker.rerank("query", sample_results());
        assert!(results.is_empty());
    }

    #[test]
    fn gated_reranker_empty_input_returns_empty() {
        let gate = ConfidenceGate::default();
        let reranker = GatedReranker::new(Box::new(NoopReranker), gate);
        let results = reranker.rerank("query", Vec::new());
        assert!(results.is_empty());
    }

    #[test]
    fn gated_reranker_at_threshold_passes() {
        let gate = ConfidenceGate {
            threshold: 0.5,
            abstain_message: "abstain".to_string(),
        };
        let reranker = GatedReranker::new(Box::new(FixedScoreReranker(0.5)), gate);
        let results = reranker.rerank("query", sample_results());
        assert_eq!(results.len(), 3);
    }
}
