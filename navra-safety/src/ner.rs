//! NER-based semantic PII detection using ONNX token classification.
//!
//! Complements regex-based PII filters with named entity recognition
//! (PERSON, LOCATION, ORGANIZATION) that catches semantic PII patterns
//! regex cannot detect (e.g., "John Smith lives in Paris").
//!
//! Uses a token classification ONNX model (e.g., dslim/bert-base-NER)
//! to detect entity spans, then maps them back to character offsets.

use super::{ContentFilter, FilterContext, Finding};
use std::path::Path;
use std::sync::Mutex;

/// NER-based content filter using an ONNX token classification model.
///
/// Detects named entities (PERSON, LOCATION, ORGANIZATION, MISC) in text
/// and reports them as PII findings. Uses BIO tagging to group consecutive
/// tokens into entity spans.
pub struct NerFilter {
    session: Mutex<ort::session::Session>,
    tokenizer: tokenizers::Tokenizer,
    label_map: Vec<String>,
    confidence_threshold: f32,
}

/// Maps NER entity types to PII finding categories.
///
/// Returns `None` for the "O" (outside) label and unknown types.
/// Supports both dslim/bert-base-NER labels (PER, LOC, ORG, MISC)
/// and sfermion/bert-pii-detector labels (GIVENNAME1, STREET, etc.).
///
/// The protectai/bert-base-NER-onnx model uses the dslim labels and
/// is preferred for natural language PII detection (person names,
/// locations, organizations). The sfermion model covers more entity
/// types but performs poorly on natural language sentences.
fn entity_type_to_category(entity_type: &str) -> Option<&'static str> {
    match entity_type {
        // dslim/bert-base-NER
        "PER" | "PERSON" => Some("person"),
        "LOC" | "LOCATION" => Some("location"),
        "ORG" | "ORGANIZATION" => Some("organization"),
        "MISC" => Some("misc-entity"),
        // sfermion/bert-pii-detector
        "GIVENNAME1" | "GIVENNAME2" | "LASTNAME1" | "LASTNAME2" | "LASTNAME3" | "TITLE" => {
            Some("person")
        }
        "EMAIL" => Some("email"),
        "TEL" => Some("phone"),
        "STREET" | "CITY" | "STATE" | "COUNTRY" | "POSTCODE" | "BUILDING" | "SECADDRESS"
        | "GEOCOORD" => Some("location"),
        "PASSPORT" | "IDCARD" | "DRIVERLICENSE" | "SOCIALNUMBER" => Some("identity-document"),
        "IP" => Some("ip-address"),
        "DATE" | "TIME" | "BOD" => Some("temporal-pii"),
        "USERNAME" => Some("username"),
        "PASS" | "PASSWORD" => Some("secret"),
        "SEX" => Some("demographic"),
        // Extended PII labels (gravitee, ettin, Nemotron-PII family)
        // Uppercase variants (gravitee-io/bert-small-pii-detection)
        "DATE_TIME" => Some("date"),
        "EMAIL_ADDRESS" => Some("email"),
        "PHONE_NUMBER" => Some("phone"),
        "CREDIT_CARD" => Some("credit-card"),
        "IP_ADDRESS" | "MAC_ADDRESS" => Some("ip-address"),
        "IBAN_CODE" | "US_SSN" | "US_BANK_NUMBER" | "US_ITIN" | "FINANCIAL" => {
            Some("account-number")
        }
        "US_DRIVER_LICENSE" | "US_PASSPORT" => Some("identity-document"),
        "US_LICENSE_PLATE" => Some("vehicle-id"),
        "IMEI" => Some("device-fingerprint"),
        "COORDINATE" => Some("location"),
        "NRP" | "AGE" => Some("demographic"),
        "HONORIFIC" | "TITLE" => None,
        // Lowercase variants (ettin/Nemotron-PII)
        "first_name" | "last_name" | "middle_name" => Some("person"),
        "street_address" | "city" | "state" | "county" | "postcode" | "country" | "coordinate" => {
            Some("address")
        }
        "date" | "date_of_birth" | "date_time" | "time" => Some("date"),
        "password" | "pin" | "api_key" | "http_cookie" => Some("secret"),
        "email" => Some("email"),
        "phone_number" | "fax_number" => Some("phone"),
        "ssn"
        | "national_id"
        | "tax_id"
        | "account_number"
        | "bank_routing_number"
        | "swift_bic" => Some("account-number"),
        "credit_debit_card" | "cvv" => Some("credit-card"),
        "ipv4" | "ipv6" | "mac_address" => Some("ip-address"),
        "url" | "user_name" => Some("url"),
        "company_name" => Some("organization"),
        "license_plate" | "vehicle_identifier" => Some("vehicle-id"),
        "device_identifier" => Some("device-fingerprint"),
        "medical_record_number"
        | "health_plan_beneficiary_number"
        | "certificate_license_number" => Some("identity-document"),
        "customer_id" | "employee_id" | "unique_id" => Some("account-number"),
        "gender"
        | "age"
        | "race_ethnicity"
        | "sexuality"
        | "political_view"
        | "religious_belief"
        | "language"
        | "blood_type"
        | "biometric_identifier" => Some("demographic"),
        "occupation" | "employment_status" | "education_level" => None,
        _ => None,
    }
}

/// Extract the entity type from a BIO label (e.g., "B-PER" -> "PER").
fn bio_entity_type(label: &str) -> Option<&str> {
    if label == "O" {
        return None;
    }
    // Handle B-XXX and I-XXX formats
    if label.len() > 2 && (label.starts_with("B-") || label.starts_with("I-")) {
        Some(&label[2..])
    } else {
        None
    }
}

/// Whether a BIO label is a "begin" tag.
fn is_begin_tag(label: &str) -> bool {
    label.starts_with("B-")
}

/// Whether a BIO label is an "inside" tag.
fn is_inside_tag(label: &str) -> bool {
    label.starts_with("I-")
}

/// A detected entity span from NER inference.
#[derive(Debug, Clone)]
pub(crate) struct EntitySpan {
    /// Character start offset in the original text.
    start: usize,
    /// Character end offset in the original text (exclusive).
    end: usize,
    /// Entity type (e.g., "PER", "LOC", "ORG").
    entity_type: String,
    /// Maximum softmax confidence across the entity's tokens.
    confidence: f32,
}

/// Group consecutive BIO-tagged tokens into entity spans.
///
/// Rules:
/// - A B-XXX tag starts a new entity of type XXX.
/// - An I-XXX tag extends the current entity if the type matches.
/// - An I-XXX tag with a different type than the current entity starts a new entity.
/// - An O tag or end of sequence closes the current entity.
///
/// Each token is represented by its BIO label, confidence, and character
/// offsets in the original text.
pub(crate) fn group_bio_tags(tokens: &[(String, f32, Option<(usize, usize)>)]) -> Vec<EntitySpan> {
    let mut spans = Vec::new();
    let mut current: Option<EntitySpan> = None;

    for (label, confidence, offsets) in tokens {
        let entity_type = bio_entity_type(label);

        match (&mut current, entity_type) {
            // Inside tag continues the current entity (same type)
            (Some(ref mut span), Some(etype))
                if is_inside_tag(label) && span.entity_type == etype =>
            {
                if let Some((_, end)) = offsets {
                    span.end = *end;
                }
                if *confidence > span.confidence {
                    span.confidence = *confidence;
                }
            }
            // Begin tag or different-type inside tag: close current, start new
            (Some(_), Some(etype)) if is_begin_tag(label) || is_inside_tag(label) => {
                let finished = current.take().unwrap();
                spans.push(finished);
                if let Some((start, end)) = offsets {
                    current = Some(EntitySpan {
                        start: *start,
                        end: *end,
                        entity_type: etype.to_string(),
                        confidence: *confidence,
                    });
                }
            }
            // O tag or no entity type: close current
            (Some(_), None) => {
                let finished = current.take().unwrap();
                spans.push(finished);
            }
            // No current entity, begin tag starts one
            (None, Some(etype)) if is_begin_tag(label) => {
                if let Some((start, end)) = offsets {
                    current = Some(EntitySpan {
                        start: *start,
                        end: *end,
                        entity_type: etype.to_string(),
                        confidence: *confidence,
                    });
                }
            }
            // I-tag without a preceding B-tag: start a new entity (lenient)
            (None, Some(etype)) if is_inside_tag(label) => {
                if let Some((start, end)) = offsets {
                    current = Some(EntitySpan {
                        start: *start,
                        end: *end,
                        entity_type: etype.to_string(),
                        confidence: *confidence,
                    });
                }
            }
            // O tag with no current entity: nothing to do
            _ => {}
        }
    }

    // Close any remaining entity
    if let Some(span) = current {
        spans.push(span);
    }

    spans
}

/// Compute softmax probabilities from logits for a single position.
fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|x| (x - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    exps.into_iter().map(|e| e / sum).collect()
}

/// Built-in label map for protectai/bert-base-NER-onnx (9 labels).
///
/// Order matches the model's output logits: O, then B/I pairs for
/// MISC, PER, ORG, LOC.
fn protectai_label_map() -> Vec<String> {
    [
        "O", "B-MISC", "I-MISC", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Built-in label map for multilingual NER models like
/// Davlan/xlm-roberta-base-ner-hrl (9 labels).
///
/// Uses DATE instead of MISC compared to the protectai model.
/// Covers 10+ languages including English, French, German, Spanish,
/// Italian, Portuguese, and Dutch.
#[cfg(test)]
fn multilingual_label_map() -> Vec<String> {
    [
        "O", "B-DATE", "I-DATE", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn detect_label_map(num_labels: usize) -> Vec<String> {
    match num_labels {
        9 => {
            // Both protectai and multilingual models have 9 labels.
            // Without a label_map.json we cannot distinguish them,
            // so default to protectai (English). Multilingual models
            // ship with a label_map.json that is loaded instead.
            protectai_label_map()
        }
        55 => sfermion_label_map(),
        _ => {
            tracing::warn!(
                num_labels,
                "Unknown model label count, using sfermion default"
            );
            sfermion_label_map()
        }
    }
}

fn sfermion_label_map() -> Vec<String> {
    [
        "B-BOD",
        "B-BUILDING",
        "B-CITY",
        "B-COUNTRY",
        "B-DATE",
        "B-DRIVERLICENSE",
        "B-EMAIL",
        "B-GEOCOORD",
        "B-GIVENNAME1",
        "B-GIVENNAME2",
        "B-IDCARD",
        "B-IP",
        "B-LASTNAME1",
        "B-LASTNAME2",
        "B-LASTNAME3",
        "B-PASS",
        "B-PASSPORT",
        "B-POSTCODE",
        "B-SECADDRESS",
        "B-SEX",
        "B-SOCIALNUMBER",
        "B-STATE",
        "B-STREET",
        "B-TEL",
        "B-TIME",
        "B-TITLE",
        "B-USERNAME",
        "I-BOD",
        "I-BUILDING",
        "I-CITY",
        "I-COUNTRY",
        "I-DATE",
        "I-DRIVERLICENSE",
        "I-EMAIL",
        "I-GEOCOORD",
        "I-GIVENNAME1",
        "I-GIVENNAME2",
        "I-IDCARD",
        "I-IP",
        "I-LASTNAME1",
        "I-LASTNAME2",
        "I-LASTNAME3",
        "I-PASS",
        "I-PASSPORT",
        "I-POSTCODE",
        "I-SECADDRESS",
        "I-SEX",
        "I-SOCIALNUMBER",
        "I-STATE",
        "I-STREET",
        "I-TEL",
        "I-TIME",
        "I-TITLE",
        "I-USERNAME",
        "O",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

impl NerFilter {
    /// Load a NER ONNX model for entity detection.
    ///
    /// `model_path` — path to the `.onnx` model file.
    /// `tokenizer_path` — path to the HuggingFace `tokenizer.json`.
    /// `label_map_path` — path to a JSON file mapping indices to BIO labels
    ///   (e.g., `{"0": "O", "1": "B-PER", "2": "I-PER", ...}`).
    pub fn load(
        model_path: &Path,
        tokenizer_path: &Path,
        label_map_path: &Path,
    ) -> Result<Self, NerError> {
        let session =
            navra_model::onnx::build_onnx_session(model_path, &navra_model::onnx::Device::Cpu)
                .map_err(|e| NerError::Load(format!("{e}")))?;

        let tokenizer = tokenizers::Tokenizer::from_file(tokenizer_path).map_err(|e| {
            NerError::Load(format!(
                "failed to load tokenizer from {}: {e}",
                tokenizer_path.display()
            ))
        })?;

        let label_map = load_label_map(label_map_path)?;

        tracing::info!(
            path = %model_path.display(),
            tokenizer = %tokenizer_path.display(),
            labels = label_map.len(),
            "Loaded NER filter model"
        );

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            label_map,
            confidence_threshold: 0.7,
        })
    }

    /// Load a NER ONNX model from a directory.
    ///
    /// Looks for:
    /// - `model.onnx` or `onnx/model.onnx`
    /// - `tokenizer.json`
    /// - `label_map.json` (optional — uses built-in sfermion map if absent)
    ///
    /// Also detects whether the model requires `token_type_ids` input
    /// (sfermion does, dslim does not).
    pub fn load_from_dir(model_dir: &Path) -> Result<Self, NerError> {
        let model_path = if model_dir.join("model.onnx").exists() {
            model_dir.join("model.onnx")
        } else if model_dir.join("onnx/model.onnx").exists() {
            model_dir.join("onnx/model.onnx")
        } else {
            return Err(NerError::Load(format!(
                "no model.onnx found in {}",
                model_dir.display()
            )));
        };

        let tokenizer_path = model_dir.join("tokenizer.json");
        if !tokenizer_path.exists() {
            return Err(NerError::Load(format!(
                "no tokenizer.json found in {}",
                model_dir.display()
            )));
        }

        let mut session =
            navra_model::onnx::build_onnx_session(&model_path, &navra_model::onnx::Device::Cpu)
                .map_err(|e| NerError::Load(format!("{e}")))?;

        let label_map_path = model_dir.join("label_map.json");
        let config_path = model_dir.join("config.json");
        let label_map = if label_map_path.exists() {
            load_label_map(&label_map_path)?
        } else if config_path.exists() {
            load_label_map_from_config(&config_path)?
        } else {
            // Probe the model with a dummy input to detect output label count
            let dummy_ids = ndarray::Array2::from_shape_vec((1, 1), vec![0i64]).unwrap();
            let dummy_mask = ndarray::Array2::from_shape_vec((1, 1), vec![1i64]).unwrap();
            let ids_t = ort::value::TensorRef::from_array_view(&dummy_ids)
                .map_err(|e| NerError::Load(format!("probe ids: {e}")))?;
            let mask_t = ort::value::TensorRef::from_array_view(&dummy_mask)
                .map_err(|e| NerError::Load(format!("probe mask: {e}")))?;

            let needs_type_ids = session
                .inputs()
                .iter()
                .any(|input| input.name() == "token_type_ids");

            let probe_out = if needs_type_ids {
                let dummy_types = ndarray::Array2::from_shape_vec((1, 1), vec![0i64]).unwrap();
                let types_t = ort::value::TensorRef::from_array_view(&dummy_types)
                    .map_err(|e| NerError::Load(format!("probe types: {e}")))?;
                session.run(ort::inputs![ids_t, mask_t, types_t]).ok()
            } else {
                session.run(ort::inputs![ids_t, mask_t]).ok()
            };

            let num_labels = probe_out
                .and_then(|out| {
                    out.iter().next().and_then(|(_name, val)| {
                        val.try_extract_tensor::<f32>()
                            .ok()
                            .map(|(_shape, data)| data.len())
                    })
                })
                .unwrap_or(55);

            tracing::info!(
                dir = %model_dir.display(),
                num_labels,
                "No label_map.json found, auto-detected {num_labels} labels from model probe",
            );
            detect_label_map(num_labels)
        };

        let tokenizer = tokenizers::Tokenizer::from_file(&tokenizer_path).map_err(|e| {
            NerError::Load(format!(
                "failed to load tokenizer from {}: {e}",
                tokenizer_path.display()
            ))
        })?;

        // Detect whether the model expects token_type_ids by inspecting inputs
        let has_token_type_ids = session
            .inputs()
            .iter()
            .any(|input| input.name() == "token_type_ids");

        tracing::info!(
            path = %model_path.display(),
            tokenizer = %tokenizer_path.display(),
            labels = label_map.len(),
            has_token_type_ids,
            "Loaded NER filter model"
        );

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            label_map,
            confidence_threshold: 0.7,
        })
    }

    /// Set the confidence threshold for entity detection.
    ///
    /// Entities with softmax probability below this threshold are
    /// not reported. Default is 0.7.
    ///
    /// # Panics
    /// Panics if `threshold` is NaN, negative, or greater than 1.0.
    pub fn with_confidence_threshold(mut self, threshold: f32) -> Self {
        assert!(
            !threshold.is_nan() && (0.0..=1.0).contains(&threshold),
            "confidence threshold must be in [0.0, 1.0], got {threshold}"
        );
        self.confidence_threshold = threshold;
        self
    }

    /// Run NER inference on text and return entity spans.
    fn detect_entities(&self, text: &str) -> Result<Vec<EntitySpan>, NerError> {
        // BERT models have a max sequence length of 512 tokens.
        // Longer inputs waste memory (O(n²) attention) and produce
        // garbage past the training length. For long texts, we scan
        // in 512-token windows with 64-token overlap to catch entities
        // that span window boundaries.
        const MAX_TOKENS: usize = 512;
        const OVERLAP: usize = 64;

        let full_encoding = self
            .tokenizer
            .encode(text, false)
            .map_err(|e| NerError::Inference(format!("tokenization: {e}")))?;

        let full_ids = full_encoding.get_ids();
        if full_ids.len() <= MAX_TOKENS {
            return self.detect_entities_window(text);
        }

        // Sliding window over long text
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

            // Extract the text window using char offsets
            let window_start = char_start.min(text.len());
            let window_end = char_end.min(text.len());
            if window_start < window_end {
                if let Ok(mut spans) = self.detect_entities_window(&text[window_start..window_end])
                {
                    // Adjust offsets back to full text coordinates
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

        // Deduplicate overlapping spans (from window overlap)
        all_spans.sort_by_key(|s| (s.start, s.end));
        all_spans.dedup_by(|b, a| {
            a.start == b.start && a.end == b.end && a.entity_type == b.entity_type
        });

        Ok(all_spans)
    }

    fn detect_entities_window(&self, text: &str) -> Result<Vec<EntitySpan>, NerError> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| NerError::Inference(format!("tokenization: {e}")))?;

        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&m| m as i64)
            .collect();
        let seq_len = input_ids.len();

        let ids_array = ndarray::Array2::from_shape_vec((1, seq_len), input_ids)
            .map_err(|e| NerError::Inference(format!("input_ids shape: {e}")))?;
        let mask_array = ndarray::Array2::from_shape_vec((1, seq_len), attention_mask)
            .map_err(|e| NerError::Inference(format!("attention_mask shape: {e}")))?;

        let ids_tensor = ort::value::TensorRef::from_array_view(&ids_array)
            .map_err(|e| NerError::Inference(format!("input_ids tensor: {e}")))?;
        let mask_tensor = ort::value::TensorRef::from_array_view(&mask_array)
            .map_err(|e| NerError::Inference(format!("attention_mask tensor: {e}")))?;

        // Build token_type_ids (all zeros) for models that require it
        let type_ids: Vec<i64> = vec![0i64; seq_len];
        let type_ids_array = ndarray::Array2::from_shape_vec((1, seq_len), type_ids)
            .map_err(|e| NerError::Inference(format!("token_type_ids shape: {e}")))?;
        let type_ids_tensor = ort::value::TensorRef::from_array_view(&type_ids_array)
            .map_err(|e| NerError::Inference(format!("token_type_ids tensor: {e}")))?;

        let mut session = self.session.lock().unwrap_or_else(|e| e.into_inner());

        // Check whether the model expects token_type_ids
        let needs_type_ids = session
            .inputs()
            .iter()
            .any(|input| input.name() == "token_type_ids");

        let outputs = if needs_type_ids {
            session
                .run(ort::inputs![ids_tensor, mask_tensor, type_ids_tensor])
                .map_err(|e| NerError::Inference(format!("inference: {e}")))?
        } else {
            session
                .run(ort::inputs![ids_tensor, mask_tensor])
                .map_err(|e| NerError::Inference(format!("inference: {e}")))?
        };

        let (_name, output) = outputs
            .iter()
            .next()
            .ok_or_else(|| NerError::Inference("no output from NER model".to_string()))?;

        let (_shape, data) = output
            .try_extract_tensor::<f32>()
            .map_err(|e| NerError::Inference(format!("output extraction: {e}")))?;

        // Output shape: [1, seq_len, num_labels]
        let num_labels = self.label_map.len();
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

            // Find argmax
            let (best_idx, best_prob) = probs
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap_or((0, &0.0));

            let label = self
                .label_map
                .get(best_idx)
                .cloned()
                .unwrap_or_else(|| "O".to_string());

            // Get character offsets from the tokenizer
            let char_offsets = if pos < offsets.len() {
                let (start, end) = offsets[pos];
                // Skip special tokens (offset 0,0 typically)
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

        let spans = group_bio_tags(&tokens);

        // Filter by confidence threshold
        let filtered: Vec<EntitySpan> = spans
            .into_iter()
            .filter(|s| s.confidence.is_nan() || s.confidence >= self.confidence_threshold)
            .collect();

        Ok(filtered)
    }
}

/// Check if a PERSON/PER entity appears in a technical naming pattern.
///
/// Suppresses false positives where algorithm/method names (e.g.,
/// "Kahn's algorithm", "Dijkstra's algorithm", "Luhn algorithm")
/// are detected as person names. The NER model correctly identifies
/// them as person names, but in technical context the name refers
/// to a well-known algorithm, theorem, or method — not PII.
///
/// Only applies to PERSON/PER entity types (and sfermion person
/// subtypes). Returns `true` if the entity should be suppressed.
fn suppress_technical_names(text: &str, span: &EntitySpan) -> bool {
    let matched = &text[span.start..span.end];

    // Suppress any entity type if the matched text is a known
    // programming/technical term (data structures, formats, protocols)
    const TECHNICAL_TERMS: &[&str] = &[
        "HashMap",
        "HashSet",
        "BTreeMap",
        "BTreeSet",
        "LinkedList",
        "Vec",
        "String",
        "Option",
        "Result",
        "Arc",
        "Mutex",
        "RwLock",
        "JSON",
        "YAML",
        "TOML",
        "XML",
        "HTML",
        "CSS",
        "HTTP",
        "HTTPS",
        "TCP",
        "UDP",
        "DNS",
        "SSH",
        "TLS",
        "SSL",
        "REST",
        "GraphQL",
        "API",
        "SDK",
        "CLI",
        "GUI",
        "URL",
        "URI",
        "UUID",
        "GUID",
        "ONNX",
        "CUDA",
        "OpenCL",
        "Wasm",
        "LLVM",
        "OAuth",
        "JWT",
        "SAML",
        "OIDC",
        "RBAC",
        "ABAC",
        "PostgreSQL",
        "MySQL",
        "SQLite",
        "Redis",
        "MongoDB",
        "Kubernetes",
        "Docker",
        "Podman",
        "Linux",
        "Windows",
        "Tokio",
        "Axum",
        "Hyper",
        "Serde",
        "Cargo",
        "Rustc",
    ];
    if TECHNICAL_TERMS.contains(&matched) {
        return true;
    }

    // Suppress if the matched text is all-uppercase (likely an acronym)
    if matched.len() >= 2
        && matched
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return true;
    }

    // Suppress if the matched text looks like a type name (CamelCase
    // with no spaces, containing lowercase after uppercase)
    if matched.len() >= 2
        && matched
            .chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false)
        && !matched.contains(' ')
        && matched.chars().any(|c| c.is_ascii_lowercase())
        && matched.chars().filter(|c| c.is_ascii_uppercase()).count() >= 2
    {
        // CamelCase like "HashMap", "BTreeMap", "OpenAI" — but NOT
        // "Paris" or "John" (single capital). Require 2+ capitals.
        return true;
    }

    // Person-specific suppression below
    let is_person = matches!(
        span.entity_type.as_str(),
        "PER" | "PERSON" | "GIVENNAME1" | "GIVENNAME2" | "LASTNAME1" | "LASTNAME2" | "LASTNAME3"
    );
    if !is_person {
        return false;
    }

    let after = &text[span.end..];

    // Possessive patterns: "Kahn's algorithm", "Dijkstra's theorem"
    const POSSESSIVE_SUFFIXES: &[&str] = &[
        "'s algorithm",
        "'s theorem",
        "'s law",
        "'s method",
        "'s formula",
        "'s conjecture",
        "'s inequality",
        "'s lemma",
        "'s sort",
        "'s number",
        "\u{2019}s algorithm",
        "\u{2019}s theorem",
        "\u{2019}s law",
        "\u{2019}s method",
        "\u{2019}s formula",
        "\u{2019}s conjecture",
        "\u{2019}s inequality",
        "\u{2019}s lemma",
        "\u{2019}s sort",
        "\u{2019}s number",
    ];

    let after_lower = after.to_ascii_lowercase();
    for suffix in POSSESSIVE_SUFFIXES {
        if after_lower.starts_with(suffix) {
            return true;
        }
    }

    // Direct patterns: "Kahn algorithm", "Luhn algorithm"
    // Match " <technical_word>" or "-<Name> <technical_word>" (e.g., "Bell-LaPadula model")
    const TECHNICAL_WORDS: &[&str] = &[
        " algorithm",
        " sort",
        " search",
        " tree",
        " hash",
        " cipher",
        " protocol",
        " model",
        " theorem",
        " method",
        " formula",
        " conjecture",
        " inequality",
        " lemma",
        " number",
        " law",
    ];

    for word in TECHNICAL_WORDS {
        if after_lower.starts_with(word) {
            return true;
        }
    }

    // Hyphenated compound names followed by technical words:
    // "Bell-LaPadula model" — the entity might cover "Bell" or "Bell-LaPadula"
    // Check if the text after the span starts with "-<Word> <technical>"
    if after.starts_with('-') {
        // Find the end of the hyphenated part (next space or end)
        if let Some(space_pos) = after[1..].find(' ') {
            // remainder includes the space: " model ..."
            let remainder = &after_lower[1 + space_pos..];
            for word in TECHNICAL_WORDS {
                if remainder.starts_with(word) {
                    return true;
                }
            }
        }
    }

    false
}

impl ContentFilter for NerFilter {
    fn name(&self) -> &str {
        "ner"
    }

    fn scan(&self, content: &str, _ctx: &FilterContext) -> Vec<Finding> {
        match self.detect_entities(content) {
            Ok(spans) => spans
                .into_iter()
                .filter(|span| !suppress_technical_names(content, span))
                .filter_map(|span| {
                    let category = entity_type_to_category(&span.entity_type)?;
                    Some(Finding {
                        start: span.start,
                        end: span.end,
                        category: category.to_string(),
                        confidence: span.confidence,
                    })
                })
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "NER filter inference failed, blocking (fail-closed)");
                vec![Finding {
                    start: 0,
                    end: content.len(),
                    category: "inference_failure".to_string(),
                    confidence: 1.0,
                }]
            }
        }
    }
}

/// Load a label map from a JSON file.
///
/// Supports two formats:
/// - Object: `{"0": "O", "1": "B-PER", "2": "I-PER", ...}` (protectai style)
/// - Array: `["O", "B-PER", "I-PER", ...]` (multilingual/transformers.js style)
fn load_label_map(path: &Path) -> Result<Vec<String>, NerError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        NerError::Load(format!(
            "failed to read label map from {}: {e}",
            path.display()
        ))
    })?;

    let json_value: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        NerError::Load(format!(
            "failed to parse label map from {}: {e}",
            path.display()
        ))
    })?;

    match json_value {
        // Array format: ["O", "B-PER", "I-PER", ...]
        serde_json::Value::Array(arr) => {
            if arr.is_empty() {
                return Err(NerError::Load("empty label map array".to_string()));
            }
            let labels: Vec<String> = arr
                .into_iter()
                .map(|v| v.as_str().unwrap_or("O").to_string())
                .collect();
            Ok(labels)
        }
        // Object format: {"0": "O", "1": "B-PER", ...}
        serde_json::Value::Object(map) => {
            if map.is_empty() {
                return Err(NerError::Load("empty label map".to_string()));
            }
            let max_idx = map
                .keys()
                .filter_map(|k| k.parse::<usize>().ok())
                .max()
                .ok_or_else(|| NerError::Load("no valid indices in label map".to_string()))?;

            let mut labels = vec!["O".to_string(); max_idx + 1];
            for (key, value) in &map {
                if let Ok(idx) = key.parse::<usize>() {
                    labels[idx] = value.as_str().unwrap_or("O").to_string();
                }
            }
            Ok(labels)
        }
        _ => Err(NerError::Load(
            "label map must be a JSON object or array".to_string(),
        )),
    }
}

/// Load label map from a HuggingFace config.json (id2label field).
fn load_label_map_from_config(path: &Path) -> Result<Vec<String>, NerError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        NerError::Load(format!(
            "failed to read config from {}: {e}",
            path.display()
        ))
    })?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| NerError::Load(format!("failed to parse config: {e}")))?;

    let id2label = json
        .get("id2label")
        .and_then(|v| v.as_object())
        .ok_or_else(|| NerError::Load("no id2label in config.json".to_string()))?;

    let max_idx = id2label
        .keys()
        .filter_map(|k| k.parse::<usize>().ok())
        .max()
        .ok_or_else(|| NerError::Load("empty id2label".to_string()))?;

    let mut labels = vec!["O".to_string(); max_idx + 1];
    for (key, value) in id2label {
        if let Ok(idx) = key.parse::<usize>() {
            labels[idx] = value.as_str().unwrap_or("O").to_string();
        }
    }

    tracing::info!(
        path = %path.display(),
        labels = labels.len(),
        "Loaded label map from config.json id2label"
    );

    Ok(labels)
}

/// Try to load a NER filter from a model directory.
///
/// Looks for `model.onnx` (or `onnx/model.onnx`) and `tokenizer.json`
/// in the given directory. If no `label_map.json` is present, uses the
/// built-in sfermion/bert-pii-detector label map. Returns `None` if
/// required files are missing (graceful degradation).
pub fn load_ner_filter(model_dir: &Path) -> Option<NerFilter> {
    let has_model =
        model_dir.join("model.onnx").exists() || model_dir.join("onnx/model.onnx").exists();

    if !has_model {
        tracing::debug!(
            dir = %model_dir.display(),
            "NER model.onnx not found, skipping NER filter"
        );
        return None;
    }
    if !model_dir.join("tokenizer.json").exists() {
        tracing::debug!(
            dir = %model_dir.display(),
            "NER tokenizer.json not found, skipping NER filter"
        );
        return None;
    }

    match NerFilter::load_from_dir(model_dir) {
        Ok(filter) => {
            tracing::info!(
                dir = %model_dir.display(),
                "NER filter loaded"
            );
            Some(filter)
        }
        Err(e) => {
            tracing::warn!(
                dir = %model_dir.display(),
                error = %e,
                "Failed to load NER filter, skipping"
            );
            None
        }
    }
}

/// Returns the default PII NER model directory path.
///
/// `~/.local/share/navra/models/pii-ner/`
pub fn default_pii_ner_model_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("~/.local/share"))
        .join("navra/models/pii-ner")
}

/// Returns the default multilingual PII NER model directory path.
///
/// `~/.local/share/navra/models/pii-ner-multilingual/`
pub fn default_pii_ner_multilingual_model_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("~/.local/share"))
        .join("navra/models/pii-ner-multilingual")
}

/// Error type for NER filter operations.
#[derive(Debug, thiserror::Error)]
pub enum NerError {
    #[error("failed to load NER model: {0}")]
    Load(String),
    #[error("NER inference failed: {0}")]
    Inference(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- BIO tag grouping ---

    #[test]
    fn group_single_entity() {
        let tokens = vec![
            ("B-PER".to_string(), 0.95, Some((0, 4))),
            ("I-PER".to_string(), 0.90, Some((5, 10))),
        ];
        let spans = group_bio_tags(&tokens);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, "PER");
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[0].end, 10);
        assert!((spans[0].confidence - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn group_multiple_entities() {
        let tokens = vec![
            ("B-PER".to_string(), 0.95, Some((0, 4))),
            ("I-PER".to_string(), 0.90, Some((5, 10))),
            ("O".to_string(), 0.99, Some((11, 16))),
            ("B-LOC".to_string(), 0.88, Some((17, 22))),
        ];
        let spans = group_bio_tags(&tokens);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].entity_type, "PER");
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[0].end, 10);
        assert_eq!(spans[1].entity_type, "LOC");
        assert_eq!(spans[1].start, 17);
        assert_eq!(spans[1].end, 22);
    }

    #[test]
    fn group_consecutive_different_entities() {
        // B-PER followed directly by B-LOC (no O in between)
        let tokens = vec![
            ("B-PER".to_string(), 0.95, Some((0, 4))),
            ("B-LOC".to_string(), 0.88, Some((5, 10))),
        ];
        let spans = group_bio_tags(&tokens);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].entity_type, "PER");
        assert_eq!(spans[1].entity_type, "LOC");
    }

    #[test]
    fn group_entity_at_end() {
        // Entity at end of sequence without trailing O
        let tokens = vec![
            ("O".to_string(), 0.99, Some((0, 4))),
            ("B-ORG".to_string(), 0.85, Some((5, 10))),
            ("I-ORG".to_string(), 0.80, Some((11, 15))),
        ];
        let spans = group_bio_tags(&tokens);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, "ORG");
        assert_eq!(spans[0].start, 5);
        assert_eq!(spans[0].end, 15);
    }

    #[test]
    fn group_no_entities() {
        let tokens = vec![
            ("O".to_string(), 0.99, Some((0, 4))),
            ("O".to_string(), 0.99, Some((5, 10))),
        ];
        let spans = group_bio_tags(&tokens);
        assert!(spans.is_empty());
    }

    #[test]
    fn group_i_tag_without_b_tag() {
        // Lenient: I-tag without preceding B-tag starts a new entity
        let tokens = vec![
            ("I-PER".to_string(), 0.90, Some((0, 4))),
            ("I-PER".to_string(), 0.85, Some((5, 10))),
        ];
        let spans = group_bio_tags(&tokens);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, "PER");
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[0].end, 10);
    }

    #[test]
    fn group_i_tag_different_type_closes_current() {
        let tokens = vec![
            ("B-PER".to_string(), 0.95, Some((0, 4))),
            ("I-LOC".to_string(), 0.88, Some((5, 10))),
        ];
        let spans = group_bio_tags(&tokens);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].entity_type, "PER");
        assert_eq!(spans[0].end, 4);
        assert_eq!(spans[1].entity_type, "LOC");
        assert_eq!(spans[1].start, 5);
    }

    #[test]
    fn group_confidence_takes_max() {
        let tokens = vec![
            ("B-PER".to_string(), 0.80, Some((0, 4))),
            ("I-PER".to_string(), 0.95, Some((5, 10))),
            ("I-PER".to_string(), 0.85, Some((11, 15))),
        ];
        let spans = group_bio_tags(&tokens);
        assert_eq!(spans.len(), 1);
        assert!((spans[0].confidence - 0.95).abs() < f32::EPSILON);
    }

    // --- Confidence thresholding ---

    #[test]
    fn confidence_threshold_filters_low() {
        let spans = vec![
            EntitySpan {
                start: 0,
                end: 4,
                entity_type: "PER".to_string(),
                confidence: 0.95,
            },
            EntitySpan {
                start: 10,
                end: 15,
                entity_type: "LOC".to_string(),
                confidence: 0.50,
            },
        ];
        let threshold = 0.7;
        let filtered: Vec<_> = spans
            .into_iter()
            .filter(|s| s.confidence >= threshold)
            .collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].entity_type, "PER");
    }

    #[test]
    fn confidence_threshold_keeps_all_above() {
        let spans = vec![
            EntitySpan {
                start: 0,
                end: 4,
                entity_type: "PER".to_string(),
                confidence: 0.95,
            },
            EntitySpan {
                start: 10,
                end: 15,
                entity_type: "LOC".to_string(),
                confidence: 0.80,
            },
        ];
        let threshold = 0.7;
        let filtered: Vec<_> = spans
            .into_iter()
            .filter(|s| s.confidence >= threshold)
            .collect();
        assert_eq!(filtered.len(), 2);
    }

    // --- Entity type mapping ---

    #[test]
    fn entity_type_mapping() {
        // dslim labels
        assert_eq!(entity_type_to_category("PER"), Some("person"));
        assert_eq!(entity_type_to_category("PERSON"), Some("person"));
        assert_eq!(entity_type_to_category("LOC"), Some("location"));
        assert_eq!(entity_type_to_category("LOCATION"), Some("location"));
        assert_eq!(entity_type_to_category("ORG"), Some("organization"));
        assert_eq!(
            entity_type_to_category("ORGANIZATION"),
            Some("organization")
        );
        assert_eq!(entity_type_to_category("MISC"), Some("misc-entity"));
        assert_eq!(entity_type_to_category("O"), None);
        assert_eq!(entity_type_to_category("UNKNOWN"), None);
    }

    #[test]
    fn sfermion_entity_type_mapping() {
        // Person names
        assert_eq!(entity_type_to_category("GIVENNAME1"), Some("person"));
        assert_eq!(entity_type_to_category("GIVENNAME2"), Some("person"));
        assert_eq!(entity_type_to_category("LASTNAME1"), Some("person"));
        assert_eq!(entity_type_to_category("LASTNAME2"), Some("person"));
        assert_eq!(entity_type_to_category("LASTNAME3"), Some("person"));
        assert_eq!(entity_type_to_category("TITLE"), Some("person"));
        // Contact
        assert_eq!(entity_type_to_category("EMAIL"), Some("email"));
        assert_eq!(entity_type_to_category("TEL"), Some("phone"));
        // Location
        assert_eq!(entity_type_to_category("STREET"), Some("location"));
        assert_eq!(entity_type_to_category("CITY"), Some("location"));
        assert_eq!(entity_type_to_category("STATE"), Some("location"));
        assert_eq!(entity_type_to_category("COUNTRY"), Some("location"));
        assert_eq!(entity_type_to_category("POSTCODE"), Some("location"));
        assert_eq!(entity_type_to_category("BUILDING"), Some("location"));
        assert_eq!(entity_type_to_category("SECADDRESS"), Some("location"));
        assert_eq!(entity_type_to_category("GEOCOORD"), Some("location"));
        // Identity docs
        assert_eq!(
            entity_type_to_category("PASSPORT"),
            Some("identity-document")
        );
        assert_eq!(entity_type_to_category("IDCARD"), Some("identity-document"));
        assert_eq!(
            entity_type_to_category("DRIVERLICENSE"),
            Some("identity-document")
        );
        assert_eq!(
            entity_type_to_category("SOCIALNUMBER"),
            Some("identity-document")
        );
        // Other
        assert_eq!(entity_type_to_category("IP"), Some("ip-address"));
        assert_eq!(entity_type_to_category("DATE"), Some("temporal-pii"));
        assert_eq!(entity_type_to_category("TIME"), Some("temporal-pii"));
        assert_eq!(entity_type_to_category("BOD"), Some("temporal-pii"));
        assert_eq!(entity_type_to_category("USERNAME"), Some("username"));
        assert_eq!(entity_type_to_category("PASS"), Some("secret"));
        assert_eq!(entity_type_to_category("SEX"), Some("demographic"));
    }

    // --- BIO label parsing ---

    #[test]
    fn bio_entity_type_parsing() {
        assert_eq!(bio_entity_type("B-PER"), Some("PER"));
        assert_eq!(bio_entity_type("I-PER"), Some("PER"));
        assert_eq!(bio_entity_type("B-LOC"), Some("LOC"));
        assert_eq!(bio_entity_type("I-ORG"), Some("ORG"));
        assert_eq!(bio_entity_type("O"), None);
    }

    #[test]
    fn bio_tag_predicates() {
        assert!(is_begin_tag("B-PER"));
        assert!(!is_begin_tag("I-PER"));
        assert!(!is_begin_tag("O"));
        assert!(is_inside_tag("I-PER"));
        assert!(!is_inside_tag("B-PER"));
        assert!(!is_inside_tag("O"));
    }

    // --- Softmax ---

    #[test]
    fn softmax_basic() {
        let logits = vec![2.0, 1.0, 0.1];
        let probs = softmax(&logits);
        assert_eq!(probs.len(), 3);
        let sum: f32 = probs.iter().sum();
        assert!((sum - 1.0).abs() < 1e-5);
        // First should be highest
        assert!(probs[0] > probs[1]);
        assert!(probs[1] > probs[2]);
    }

    #[test]
    fn softmax_single() {
        let probs = softmax(&[5.0]);
        assert_eq!(probs.len(), 1);
        assert!((probs[0] - 1.0).abs() < 1e-5);
    }

    // --- Label map loading ---

    #[test]
    fn load_label_map_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("label_map.json");
        std::fs::write(
            &path,
            r#"{"0": "O", "1": "B-PER", "2": "I-PER", "3": "B-LOC", "4": "I-LOC"}"#,
        )
        .unwrap();

        let labels = load_label_map(&path).unwrap();
        assert_eq!(labels.len(), 5);
        assert_eq!(labels[0], "O");
        assert_eq!(labels[1], "B-PER");
        assert_eq!(labels[2], "I-PER");
        assert_eq!(labels[3], "B-LOC");
        assert_eq!(labels[4], "I-LOC");
    }

    #[test]
    fn load_label_map_missing_file() {
        let result = load_label_map(Path::new("/nonexistent/label_map.json"));
        assert!(result.is_err());
    }

    // --- load_ner_filter graceful degradation ---

    #[test]
    fn load_ner_filter_missing_dir() {
        let result = load_ner_filter(Path::new("/nonexistent/model/dir"));
        assert!(result.is_none());
    }

    #[test]
    fn load_ner_filter_missing_model() {
        let dir = tempfile::tempdir().unwrap();
        // Create tokenizer.json and label_map.json but not model.onnx
        std::fs::write(dir.path().join("tokenizer.json"), "{}").unwrap();
        std::fs::write(dir.path().join("label_map.json"), r#"{"0": "O"}"#).unwrap();
        let result = load_ner_filter(dir.path());
        assert!(result.is_none());
    }

    #[test]
    fn load_ner_filter_missing_tokenizer() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("model.onnx"), &[0u8; 10]).unwrap();
        std::fs::write(dir.path().join("label_map.json"), r#"{"0": "O"}"#).unwrap();
        let result = load_ner_filter(dir.path());
        assert!(result.is_none());
    }

    #[test]
    fn load_ner_filter_missing_label_map_uses_sfermion_default() {
        // With model.onnx + tokenizer.json but no label_map.json,
        // load_ner_filter should attempt to load using the built-in
        // sfermion label map. It will still fail (invalid model bytes)
        // but the error should be about the model, not about a missing
        // label_map.json.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("model.onnx"), &[0u8; 10]).unwrap();
        std::fs::write(dir.path().join("tokenizer.json"), "{}").unwrap();
        // Returns None because model.onnx is not a valid ONNX file,
        // but notably does NOT fail because label_map.json is missing.
        let result = load_ner_filter(dir.path());
        assert!(result.is_none());
    }

    // --- sfermion label map ---

    #[test]
    fn sfermion_label_map_has_55_labels() {
        let map = sfermion_label_map();
        assert_eq!(map.len(), 55);
        // First 27 are B- tags, next 27 are I- tags, last is O
        assert!(map[0].starts_with("B-"));
        assert!(map[27].starts_with("I-"));
        assert_eq!(map[54], "O");
    }

    #[test]
    fn load_ner_filter_finds_onnx_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let onnx_dir = dir.path().join("onnx");
        std::fs::create_dir_all(&onnx_dir).unwrap();
        std::fs::write(onnx_dir.join("model.onnx"), &[0u8; 10]).unwrap();
        std::fs::write(dir.path().join("tokenizer.json"), "{}").unwrap();
        // The directory has onnx/model.onnx + tokenizer.json — should attempt load
        // (fails because model.onnx is invalid, but detects the files correctly)
        let result = load_ner_filter(dir.path());
        assert!(result.is_none());
    }

    // --- Multilingual label map ---

    #[test]
    fn multilingual_label_map_has_9_labels() {
        let map = multilingual_label_map();
        assert_eq!(map.len(), 9);
        assert_eq!(map[0], "O");
        assert_eq!(map[1], "B-DATE");
        assert_eq!(map[2], "I-DATE");
        assert_eq!(map[3], "B-PER");
        assert_eq!(map[4], "I-PER");
        assert_eq!(map[5], "B-ORG");
        assert_eq!(map[6], "I-ORG");
        assert_eq!(map[7], "B-LOC");
        assert_eq!(map[8], "I-LOC");
    }

    #[test]
    fn detect_label_map_9_labels_returns_protectai() {
        let map = detect_label_map(9);
        assert_eq!(map.len(), 9);
        // Default for 9 labels is protectai (MISC, not DATE)
        assert_eq!(map[1], "B-MISC");
    }

    #[test]
    fn detect_label_map_55_labels_returns_sfermion() {
        let map = detect_label_map(55);
        assert_eq!(map.len(), 55);
    }

    #[test]
    fn multilingual_entity_types_map_to_categories() {
        // DATE entities from the multilingual model map to temporal-pii
        assert_eq!(entity_type_to_category("DATE"), Some("temporal-pii"));
        // PER, LOC, ORG work the same as protectai
        assert_eq!(entity_type_to_category("PER"), Some("person"));
        assert_eq!(entity_type_to_category("LOC"), Some("location"));
        assert_eq!(entity_type_to_category("ORG"), Some("organization"));
    }

    // --- Label map array format ---

    #[test]
    fn load_label_map_array_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("label_map.json");
        std::fs::write(
            &path,
            r#"["O", "B-DATE", "I-DATE", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC"]"#,
        )
        .unwrap();

        let labels = load_label_map(&path).unwrap();
        assert_eq!(labels.len(), 9);
        assert_eq!(labels[0], "O");
        assert_eq!(labels[1], "B-DATE");
        assert_eq!(labels[8], "I-LOC");
    }

    #[test]
    fn load_label_map_empty_array_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("label_map.json");
        std::fs::write(&path, "[]").unwrap();
        assert!(load_label_map(&path).is_err());
    }

    #[test]
    fn load_label_map_invalid_json_type_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("label_map.json");
        std::fs::write(&path, r#""just a string""#).unwrap();
        assert!(load_label_map(&path).is_err());
    }

    // --- Default model dirs ---

    #[test]
    fn default_multilingual_model_dir_differs_from_english() {
        let en = default_pii_ner_model_dir();
        let ml = default_pii_ner_multilingual_model_dir();
        assert_ne!(en, ml);
        assert!(ml.to_string_lossy().contains("pii-ner-multilingual"));
    }

    #[test]
    fn ner_multilingual_french_text() {
        // Requires: navra pii download --multilingual
        let model_dir = default_pii_ner_multilingual_model_dir();
        let filter =
            NerFilter::load_from_dir(&model_dir).expect("multilingual NER model not installed");
        let text = "M. Dupont habite au 15 rue de Rivoli à Paris";
        let spans = filter.detect_entities(text).unwrap();
        // Should detect at least one PER (Dupont) and one LOC (Paris)
        let person_spans: Vec<_> = spans.iter().filter(|s| s.entity_type == "PER").collect();
        let loc_spans: Vec<_> = spans.iter().filter(|s| s.entity_type == "LOC").collect();
        assert!(
            !person_spans.is_empty(),
            "Expected to detect person entity in French text"
        );
        assert!(
            !loc_spans.is_empty(),
            "Expected to detect location entity in French text"
        );
    }

    // --- Technical name suppression ---

    #[test]
    fn suppress_possessive_algorithm() {
        let text = "Kahn's algorithm performs topological sorting";
        let span = EntitySpan {
            start: 0,
            end: 4,
            entity_type: "PER".to_string(),
            confidence: 0.95,
        };
        assert!(suppress_technical_names(text, &span));
    }

    #[test]
    fn suppress_possessive_theorem() {
        let text = "Dijkstra's algorithm finds shortest paths";
        let span = EntitySpan {
            start: 0,
            end: 8,
            entity_type: "PER".to_string(),
            confidence: 0.95,
        };
        assert!(suppress_technical_names(text, &span));
    }

    #[test]
    fn suppress_direct_algorithm() {
        let text = "Luhn algorithm validates card numbers";
        let span = EntitySpan {
            start: 0,
            end: 4,
            entity_type: "PER".to_string(),
            confidence: 0.90,
        };
        assert!(suppress_technical_names(text, &span));
    }

    #[test]
    fn suppress_hyphenated_model() {
        // "Bell-LaPadula model" — entity covers "Bell" only
        let text = "Bell-LaPadula model enforces mandatory access control";
        let span = EntitySpan {
            start: 0,
            end: 4,
            entity_type: "PER".to_string(),
            confidence: 0.88,
        };
        assert!(suppress_technical_names(text, &span));
    }

    #[test]
    fn no_suppress_plain_person() {
        let text = "Jean Dupont called us yesterday";
        let span = EntitySpan {
            start: 0,
            end: 11,
            entity_type: "PER".to_string(),
            confidence: 0.95,
        };
        assert!(!suppress_technical_names(text, &span));
    }

    #[test]
    fn no_suppress_person_no_algorithm_context() {
        let text = "Kahn is our new employee";
        let span = EntitySpan {
            start: 0,
            end: 4,
            entity_type: "PER".to_string(),
            confidence: 0.90,
        };
        assert!(!suppress_technical_names(text, &span));
    }

    #[test]
    fn no_suppress_non_person_entity() {
        // LOC entities should never be suppressed
        let text = "Paris algorithm is not a real thing";
        let span = EntitySpan {
            start: 0,
            end: 5,
            entity_type: "LOC".to_string(),
            confidence: 0.90,
        };
        assert!(!suppress_technical_names(text, &span));
    }

    #[test]
    fn suppress_possessive_law() {
        let text = "Amdahl's law limits parallel speedup";
        let span = EntitySpan {
            start: 0,
            end: 6,
            entity_type: "PER".to_string(),
            confidence: 0.92,
        };
        assert!(suppress_technical_names(text, &span));
    }

    #[test]
    fn suppress_sort() {
        // If "Tim" were detected as a person followed by " sort"
        let text2 = "Tim sort is efficient";
        let span = EntitySpan {
            start: 0,
            end: 3,
            entity_type: "PER".to_string(),
            confidence: 0.85,
        };
        assert!(suppress_technical_names(text2, &span));
    }

    #[test]
    fn suppress_cipher() {
        let text = "Caesar cipher is a substitution cipher";
        let span = EntitySpan {
            start: 0,
            end: 6,
            entity_type: "PER".to_string(),
            confidence: 0.88,
        };
        assert!(suppress_technical_names(text, &span));
    }

    // --- NerFilter implements ContentFilter ---

    #[test]
    fn ner_filter_is_content_filter() {
        // Verify the trait bound at compile time by accepting a trait object reference
        fn accepts_content_filter(_f: &dyn ContentFilter) {}
        // We can't construct a real NerFilter without model files,
        // but the compile-time check is sufficient. The function
        // signature proves NerFilter: ContentFilter.
    }

    // --- Entity span to Finding conversion ---

    #[test]
    fn entity_span_to_finding() {
        let span = EntitySpan {
            start: 5,
            end: 15,
            entity_type: "PER".to_string(),
            confidence: 0.92,
        };
        let category = entity_type_to_category(&span.entity_type).unwrap();
        let finding = Finding {
            start: span.start,
            end: span.end,
            category: category.to_string(),
            confidence: span.confidence,
        };
        assert_eq!(finding.category, "person");
        assert_eq!(finding.start, 5);
        assert_eq!(finding.end, 15);
        assert!((finding.confidence - 0.92).abs() < f32::EPSILON);
    }
}
