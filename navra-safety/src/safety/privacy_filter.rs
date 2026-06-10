//! OpenAI privacy-filter: sparse MoE token classifier for PII detection.
//!
//! Complements regex and NER filters with 8 PII categories including
//! address, date, and secret detection that regex/NER cannot cover.
//! Uses BIOES tagging (Begin/Inside/Outside/End/Single) for span decoding.

use super::{ContentFilter, FilterContext, Finding};
use std::path::Path;
use std::sync::Mutex;

fn privacy_category(label: &str) -> Option<&'static str> {
    match label {
        "account_number" => Some("account-number"),
        "private_address" => Some("address"),
        "private_date" => Some("date"),
        "private_email" => Some("email"),
        "private_person" => Some("person"),
        "private_phone" => Some("phone"),
        "private_url" => Some("url"),
        "secret" => Some("secret"),
        _ => None,
    }
}

fn bioes_tag_type(label: &str) -> Option<(&str, &str)> {
    if label == "O" {
        return None;
    }
    if label.len() > 2
        && (label.starts_with("B-")
            || label.starts_with("I-")
            || label.starts_with("E-")
            || label.starts_with("S-"))
    {
        Some((&label[..1], &label[2..]))
    } else {
        None
    }
}

struct Span {
    start: usize,
    end: usize,
    category: String,
    confidence: f32,
}

fn group_bioes_tags(tokens: &[(String, f32, Option<(usize, usize)>)]) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut current_cat: Option<String> = None;
    let mut current_start = 0usize;
    let mut current_end = 0usize;
    let mut current_conf = 0.0f32;

    for (label, confidence, offsets) in tokens {
        let parsed = bioes_tag_type(label);

        match parsed {
            None => {
                if let Some(cat) = current_cat.take() {
                    if current_end > current_start {
                        spans.push(Span {
                            start: current_start,
                            end: current_end,
                            category: cat,
                            confidence: current_conf,
                        });
                    }
                }
            }
            Some(("S", entity)) => {
                if let Some(cat) = current_cat.take() {
                    if current_end > current_start {
                        spans.push(Span {
                            start: current_start,
                            end: current_end,
                            category: cat,
                            confidence: current_conf,
                        });
                    }
                }
                if let Some((s, e)) = offsets {
                    spans.push(Span {
                        start: *s,
                        end: *e,
                        category: entity.to_string(),
                        confidence: *confidence,
                    });
                }
            }
            Some(("B", entity)) => {
                if let Some(cat) = current_cat.take() {
                    if current_end > current_start {
                        spans.push(Span {
                            start: current_start,
                            end: current_end,
                            category: cat,
                            confidence: current_conf,
                        });
                    }
                }
                if let Some((s, e)) = offsets {
                    current_cat = Some(entity.to_string());
                    current_start = *s;
                    current_end = *e;
                    current_conf = *confidence;
                }
            }
            Some(("I", entity)) => {
                if current_cat.as_deref() == Some(entity) {
                    if let Some((_, e)) = offsets {
                        current_end = *e;
                    }
                    if *confidence > current_conf {
                        current_conf = *confidence;
                    }
                } else {
                    if let Some(cat) = current_cat.take() {
                        if current_end > current_start {
                            spans.push(Span {
                                start: current_start,
                                end: current_end,
                                category: cat,
                                confidence: current_conf,
                            });
                        }
                    }
                    if let Some((s, e)) = offsets {
                        current_cat = Some(entity.to_string());
                        current_start = *s;
                        current_end = *e;
                        current_conf = *confidence;
                    }
                }
            }
            Some(("E", entity)) => {
                if current_cat.as_deref() == Some(entity) {
                    if let Some((_, e)) = offsets {
                        current_end = *e;
                    }
                    let cat = current_cat.take().unwrap();
                    spans.push(Span {
                        start: current_start,
                        end: current_end,
                        category: cat,
                        confidence: current_conf.max(*confidence),
                    });
                } else {
                    if let Some(cat) = current_cat.take() {
                        if current_end > current_start {
                            spans.push(Span {
                                start: current_start,
                                end: current_end,
                                category: cat,
                                confidence: current_conf,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if let Some(cat) = current_cat {
        if current_end > current_start {
            spans.push(Span {
                start: current_start,
                end: current_end,
                category: cat,
                confidence: current_conf,
            });
        }
    }

    spans
}

fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|x| (x - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    exps.into_iter().map(|e| e / sum).collect()
}

pub struct PrivacyFilterModel {
    session: Mutex<ort::session::Session>,
    tokenizer: tokenizers::Tokenizer,
    id2label: Vec<String>,
    confidence_threshold: f32,
}

impl PrivacyFilterModel {
    pub fn load_from_dir(model_dir: &Path) -> Result<Self, PrivacyFilterError> {
        // FP16 uses standard ops (works with any ORT). Quantized variants
        // (model_q4, model_quantized) use GatherBlockQuantized which
        // requires ORT >= 1.26.
        let model_path = if model_dir.join("onnx/model_fp16.onnx").exists() {
            model_dir.join("onnx/model_fp16.onnx")
        } else if model_dir.join("onnx/model_quantized.onnx").exists() {
            model_dir.join("onnx/model_quantized.onnx")
        } else if model_dir.join("onnx/model_q4.onnx").exists() {
            model_dir.join("onnx/model_q4.onnx")
        } else if model_dir.join("onnx/model.onnx").exists() {
            model_dir.join("onnx/model.onnx")
        } else if model_dir.join("model.onnx").exists() {
            model_dir.join("model.onnx")
        } else {
            return Err(PrivacyFilterError::Load(format!(
                "no ONNX model found in {}",
                model_dir.display()
            )));
        };

        let tokenizer_path = model_dir.join("tokenizer.json");
        if !tokenizer_path.exists() {
            return Err(PrivacyFilterError::Load(format!(
                "no tokenizer.json in {}",
                model_dir.display()
            )));
        }

        let config_path = model_dir.join("config.json");
        let id2label = load_id2label(&config_path)?;

        let session = ort::session::Session::builder()
            .map_err(|e| PrivacyFilterError::Load(format!("session builder: {e}")))?
            .with_execution_providers([
                ort::execution_providers::CPUExecutionProvider::default().build(),
            ])
            .map_err(|e| PrivacyFilterError::Load(format!("execution provider: {e}")))?
            .commit_from_file(&model_path)
            .map_err(|e| {
                PrivacyFilterError::Load(format!(
                    "failed to load model from {}: {e}",
                    model_path.display()
                ))
            })?;

        let tokenizer =
            tokenizers::Tokenizer::from_file(&tokenizer_path).map_err(|e| {
                PrivacyFilterError::Load(format!(
                    "failed to load tokenizer from {}: {e}",
                    tokenizer_path.display()
                ))
            })?;

        tracing::info!(
            path = %model_path.display(),
            labels = id2label.len(),
            "Loaded OpenAI privacy-filter model"
        );

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            id2label,
            confidence_threshold: 0.5,
        })
    }

    fn detect_spans(&self, text: &str) -> Result<Vec<Span>, PrivacyFilterError> {
        const MAX_TOKENS: usize = 512;
        const OVERLAP: usize = 64;

        let full_encoding = self
            .tokenizer
            .encode(text, false)
            .map_err(|e| PrivacyFilterError::Inference(format!("tokenization: {e}")))?;

        let full_ids = full_encoding.get_ids();
        if full_ids.len() <= MAX_TOKENS {
            return self.detect_spans_window(text);
        }

        let full_offsets = full_encoding.get_offsets();
        let mut all_spans = Vec::new();
        let mut pos = 0;

        while pos < full_ids.len() {
            let end = (pos + MAX_TOKENS).min(full_ids.len());
            let char_start = full_offsets.get(pos).map(|o| o.0).unwrap_or(0);
            let char_end = full_offsets
                .get(end.saturating_sub(1))
                .map(|o| o.1)
                .unwrap_or(text.len());

            let window_start = char_start.min(text.len());
            let window_end = char_end.min(text.len());
            if window_start < window_end {
                if let Ok(mut spans) = self.detect_spans_window(&text[window_start..window_end]) {
                    for span in &mut spans {
                        span.start += window_start;
                        span.end += window_start;
                    }
                    all_spans.extend(spans);
                }
            }

            if end >= full_ids.len() {
                break;
            }
            pos = end - OVERLAP;
        }

        all_spans.sort_by_key(|s| (s.start, s.end));
        all_spans.dedup_by(|b, a| {
            a.start == b.start && a.end == b.end && a.category == b.category
        });

        Ok(all_spans)
    }

    fn detect_spans_window(&self, text: &str) -> Result<Vec<Span>, PrivacyFilterError> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| PrivacyFilterError::Inference(format!("tokenization: {e}")))?;

        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&m| m as i64)
            .collect();
        let seq_len = input_ids.len();

        let ids_array = ndarray::Array2::from_shape_vec((1, seq_len), input_ids)
            .map_err(|e| PrivacyFilterError::Inference(format!("input_ids shape: {e}")))?;
        let mask_array = ndarray::Array2::from_shape_vec((1, seq_len), attention_mask)
            .map_err(|e| PrivacyFilterError::Inference(format!("attention_mask shape: {e}")))?;

        let ids_tensor = ort::value::TensorRef::from_array_view(&ids_array)
            .map_err(|e| PrivacyFilterError::Inference(format!("input_ids tensor: {e}")))?;
        let mask_tensor = ort::value::TensorRef::from_array_view(&mask_array)
            .map_err(|e| PrivacyFilterError::Inference(format!("attention_mask tensor: {e}")))?;

        let mut session = self.session.lock().unwrap();

        let outputs = session
            .run(ort::inputs![ids_tensor, mask_tensor])
            .map_err(|e| PrivacyFilterError::Inference(format!("inference: {e}")))?;

        let (_name, output) = outputs
            .iter()
            .next()
            .ok_or_else(|| PrivacyFilterError::Inference("no output".to_string()))?;

        let (_shape, data) = output
            .try_extract_tensor::<f32>()
            .map_err(|e| PrivacyFilterError::Inference(format!("output extraction: {e}")))?;

        let num_labels = self.id2label.len();
        let offsets = encoding.get_offsets();

        let mut tokens: Vec<(String, f32, Option<(usize, usize)>)> = Vec::new();

        for pos in 0..seq_len {
            let start_idx = pos * num_labels;
            let end_idx = start_idx + num_labels;

            if end_idx > data.len() {
                break;
            }

            let logits = &data[start_idx..end_idx];
            let probs = softmax(logits);

            let (best_idx, best_prob) = probs
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap_or((0, &0.0));

            let label = self
                .id2label
                .get(best_idx)
                .cloned()
                .unwrap_or_else(|| "O".to_string());

            let char_offsets = if pos < offsets.len() {
                let (start, end) = offsets[pos];
                if start == 0 && end == 0 && (pos == 0 || pos == seq_len - 1) {
                    None
                } else {
                    Some((start, end))
                }
            } else {
                None
            };

            tokens.push((label, *best_prob, char_offsets));
        }

        let spans = group_bioes_tags(&tokens);

        Ok(spans
            .into_iter()
            .filter(|s| s.confidence >= self.confidence_threshold)
            .collect())
    }
}

impl ContentFilter for PrivacyFilterModel {
    fn name(&self) -> &str {
        "privacy-filter"
    }

    fn scan(&self, content: &str, _ctx: &FilterContext) -> Vec<Finding> {
        match self.detect_spans(content) {
            Ok(spans) => spans
                .into_iter()
                .filter_map(|span| {
                    let category = privacy_category(&span.category)?;
                    Some(Finding {
                        start: span.start,
                        end: span.end,
                        category: category.to_string(),
                        confidence: span.confidence,
                    })
                })
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "Privacy-filter inference failed, skipping");
                Vec::new()
            }
        }
    }
}

fn load_id2label(config_path: &Path) -> Result<Vec<String>, PrivacyFilterError> {
    let content = std::fs::read_to_string(config_path).map_err(|e| {
        PrivacyFilterError::Load(format!(
            "failed to read config from {}: {e}",
            config_path.display()
        ))
    })?;

    let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        PrivacyFilterError::Load(format!("failed to parse config: {e}"))
    })?;

    let id2label = json
        .get("id2label")
        .and_then(|v| v.as_object())
        .ok_or_else(|| PrivacyFilterError::Load("no id2label in config.json".to_string()))?;

    let max_idx = id2label
        .keys()
        .filter_map(|k| k.parse::<usize>().ok())
        .max()
        .ok_or_else(|| PrivacyFilterError::Load("empty id2label".to_string()))?;

    let mut labels = vec!["O".to_string(); max_idx + 1];
    for (key, value) in id2label {
        if let Ok(idx) = key.parse::<usize>() {
            labels[idx] = value.as_str().unwrap_or("O").to_string();
        }
    }

    Ok(labels)
}

pub fn load_privacy_filter(model_dir: &Path) -> Option<PrivacyFilterModel> {
    let has_model = model_dir.join("onnx/model_fp16.onnx").exists()
        || model_dir.join("onnx/model_quantized.onnx").exists()
        || model_dir.join("onnx/model_q4.onnx").exists()
        || model_dir.join("onnx/model.onnx").exists()
        || model_dir.join("model.onnx").exists();

    if !has_model {
        tracing::debug!(
            dir = %model_dir.display(),
            "Privacy-filter ONNX model not found, skipping"
        );
        return None;
    }

    match PrivacyFilterModel::load_from_dir(model_dir) {
        Ok(filter) => {
            tracing::info!(dir = %model_dir.display(), "Privacy-filter loaded");
            Some(filter)
        }
        Err(e) => {
            tracing::warn!(dir = %model_dir.display(), error = %e, "Failed to load privacy-filter, skipping");
            None
        }
    }
}

pub fn default_privacy_filter_model_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("~/.local/share"))
        .join("navra/models/openai-privacy-filter")
}

#[derive(Debug, thiserror::Error)]
pub enum PrivacyFilterError {
    #[error("failed to load privacy-filter model: {0}")]
    Load(String),
    #[error("privacy-filter inference failed: {0}")]
    Inference(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bioes_single_entity() {
        let tokens = vec![
            ("S-private_person".to_string(), 0.99, Some((10, 14))),
        ];
        let spans = group_bioes_tags(&tokens);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].category, "private_person");
        assert_eq!(spans[0].start, 10);
        assert_eq!(spans[0].end, 14);
    }

    #[test]
    fn bioes_begin_inside_end() {
        let tokens = vec![
            ("B-private_person".to_string(), 0.95, Some((0, 4))),
            ("I-private_person".to_string(), 0.90, Some((5, 10))),
            ("E-private_person".to_string(), 0.92, Some((11, 16))),
        ];
        let spans = group_bioes_tags(&tokens);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[0].end, 16);
        assert!((spans[0].confidence - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn bioes_multiple_entities() {
        let tokens = vec![
            ("S-private_email".to_string(), 0.99, Some((0, 15))),
            ("O".to_string(), 0.99, Some((16, 20))),
            ("B-private_person".to_string(), 0.95, Some((21, 25))),
            ("E-private_person".to_string(), 0.93, Some((26, 30))),
        ];
        let spans = group_bioes_tags(&tokens);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].category, "private_email");
        assert_eq!(spans[1].category, "private_person");
    }

    #[test]
    fn bioes_no_entities() {
        let tokens = vec![
            ("O".to_string(), 0.99, Some((0, 5))),
            ("O".to_string(), 0.99, Some((6, 10))),
        ];
        let spans = group_bioes_tags(&tokens);
        assert!(spans.is_empty());
    }

    #[test]
    fn bioes_unclosed_entity() {
        let tokens = vec![
            ("B-secret".to_string(), 0.88, Some((0, 5))),
            ("I-secret".to_string(), 0.85, Some((6, 10))),
        ];
        let spans = group_bioes_tags(&tokens);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].category, "secret");
        assert_eq!(spans[0].end, 10);
    }

    #[test]
    fn bioes_consecutive_singles() {
        let tokens = vec![
            ("S-private_email".to_string(), 0.99, Some((0, 10))),
            ("S-private_phone".to_string(), 0.98, Some((11, 20))),
        ];
        let spans = group_bioes_tags(&tokens);
        assert_eq!(spans.len(), 2);
    }

    #[test]
    fn bioes_different_type_inside_closes_current() {
        let tokens = vec![
            ("B-private_person".to_string(), 0.95, Some((0, 4))),
            ("I-private_email".to_string(), 0.90, Some((5, 10))),
        ];
        let spans = group_bioes_tags(&tokens);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].category, "private_person");
        assert_eq!(spans[1].category, "private_email");
    }

    #[test]
    fn privacy_category_mapping() {
        assert_eq!(privacy_category("account_number"), Some("account-number"));
        assert_eq!(privacy_category("private_address"), Some("address"));
        assert_eq!(privacy_category("private_date"), Some("date"));
        assert_eq!(privacy_category("private_email"), Some("email"));
        assert_eq!(privacy_category("private_person"), Some("person"));
        assert_eq!(privacy_category("private_phone"), Some("phone"));
        assert_eq!(privacy_category("private_url"), Some("url"));
        assert_eq!(privacy_category("secret"), Some("secret"));
        assert_eq!(privacy_category("O"), None);
        assert_eq!(privacy_category("unknown"), None);
    }

    #[test]
    fn bioes_tag_parsing() {
        assert_eq!(bioes_tag_type("O"), None);
        assert_eq!(bioes_tag_type("B-private_person"), Some(("B", "private_person")));
        assert_eq!(bioes_tag_type("I-secret"), Some(("I", "secret")));
        assert_eq!(bioes_tag_type("E-private_email"), Some(("E", "private_email")));
        assert_eq!(bioes_tag_type("S-private_phone"), Some(("S", "private_phone")));
    }

    #[test]
    fn load_privacy_filter_missing_dir() {
        assert!(load_privacy_filter(Path::new("/nonexistent")).is_none());
    }

    #[test]
    fn default_model_dir_path() {
        let dir = default_privacy_filter_model_dir();
        assert!(dir.to_string_lossy().contains("openai-privacy-filter"));
    }

    #[test]
    fn load_id2label_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        std::fs::write(
            &config_path,
            r#"{"id2label": {"0": "O", "1": "B-account_number", "2": "S-secret"}}"#,
        )
        .unwrap();

        let labels = load_id2label(&config_path).unwrap();
        assert_eq!(labels.len(), 3);
        assert_eq!(labels[0], "O");
        assert_eq!(labels[1], "B-account_number");
        assert_eq!(labels[2], "S-secret");
    }
}
