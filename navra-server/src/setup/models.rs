//! Model registry and safety filter loading.
//!
//! Loads the model registry, PII NER filters, privacy filters, and
//! custom PII patterns. Produces a `SafetyFilterState` for downstream
//! safety pipeline construction.

use crate::config;
use crate::setup::safety::SafetyFilterState;
use crate::util;
use anyhow::Context as _;
use std::collections::HashMap;
use std::sync::Arc;

/// Output of [`load_models_and_filters`] — everything needed by
/// downstream module/tool registration.
pub(crate) struct ModelsAndFilters {
    pub(crate) models: HashMap<String, Arc<dyn navra_model::ModelBackend>>,
    pub(crate) safety_state: SafetyFilterState,
    pub(crate) running_endpoints: Vec<(
        Box<dyn navra_model_runtime::ModelRuntime>,
        navra_model_runtime::Endpoint,
    )>,
}

/// Load the model registry, PII/NER/privacy filters, and custom PII
/// patterns from config.
pub(crate) async fn load_models_and_filters(
    cfg: &config::Config,
) -> anyhow::Result<ModelsAndFilters> {
    // --- Load models into registry ---
    let model_entries = util::convert_model_configs(&cfg.models);
    let model_registry = navra_model_server::ModelRegistry::from_config(&model_entries)
        .await
        .context("failed to build model registry")?;
    let models = model_registry.models().clone();

    // Keep the registry alive for runtime process management.
    let _model_registry = model_registry;

    // Legacy endpoint tracking for shutdown
    let running_endpoints: Vec<(
        Box<dyn navra_model_runtime::ModelRuntime>,
        navra_model_runtime::Endpoint,
    )> = Vec::new();

    #[cfg(feature = "onnx")]
    let pii_ner_filter: Option<Arc<navra_core::safety::NerFilter>> = {
        let pii_ml_dir = cfg.pii_multilingual_model_dir();
        let pii_en_dir = cfg.pii_model_dir();
        match navra_core::safety::load_ner_filter(&pii_ml_dir) {
            Some(filter) => {
                tracing::info!(
                    dir = %pii_ml_dir.display(),
                    "Multilingual PII NER model loaded (EN, FR, DE, ES, IT, PT, NL)"
                );
                Some(Arc::new(filter))
            }
            None => match navra_core::safety::load_ner_filter(&pii_en_dir) {
                Some(filter) => {
                    tracing::info!(
                        dir = %pii_en_dir.display(),
                        "English PII NER model loaded for semantic entity detection"
                    );
                    Some(Arc::new(filter))
                }
                None => {
                    tracing::info!(
                        "PII NER model not installed. Run 'navra pii download' for semantic PII detection."
                    );
                    None
                }
            },
        }
    };

    #[cfg(feature = "onnx")]
    let privacy_filter: Option<Arc<navra_core::safety::PrivacyFilterModel>> = {
        let privacy_filter_dir = navra_core::safety::default_privacy_filter_model_dir();
        match navra_core::safety::load_privacy_filter(&privacy_filter_dir) {
            Some(filter) => {
                tracing::info!(
                    dir = %privacy_filter_dir.display(),
                    "OpenAI privacy-filter loaded (address, date, secret detection)"
                );
                Some(Arc::new(filter))
            }
            None => {
                tracing::info!(
                    "OpenAI privacy-filter not installed. Download from HuggingFace for address/date/secret PII detection."
                );
                None
            }
        }
    };

    // Build custom PII filter from global pii_patterns config
    let custom_pii_filter: Option<Arc<navra_core::safety::CustomPiiFilter>> =
        if !cfg.pii_patterns.is_empty() {
            let patterns: Vec<(String, String, String)> = cfg
                .pii_patterns
                .iter()
                .map(|p| (p.name.clone(), p.regex.clone(), p.category.clone()))
                .collect();
            match navra_core::safety::CustomPiiFilter::new(patterns) {
                Ok(filter) => {
                    if filter.has_patterns() {
                        navra_core::safety::register_pii_categories(&filter.categories());
                        tracing::info!(
                            patterns = cfg.pii_patterns.len(),
                            categories = ?filter.categories(),
                            "Custom PII patterns loaded"
                        );
                        Some(Arc::new(filter))
                    } else {
                        None
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to compile custom PII patterns");
                    None
                }
            }
        } else {
            None
        };

    let safety_state = SafetyFilterState {
        custom_pii_filter: custom_pii_filter.clone(),
        #[cfg(feature = "onnx")]
        pii_ner_filter: pii_ner_filter.clone(),
        #[cfg(feature = "onnx")]
        privacy_filter: privacy_filter.clone(),
        models: models.clone(),
    };

    Ok(ModelsAndFilters {
        models,
        safety_state,
        running_endpoints,
    })
}

/// Build a PII filter pipeline for model reasoning text. Uses
/// "standard" safety profile (regex PII + NER) to redact PII that
/// the model echoes in reasoning.
pub(crate) fn build_reasoning_pii_filter(
    cfg: &config::Config,
    safety_state: &SafetyFilterState,
) -> Option<Arc<navra_core::safety::FilterPipeline>> {
    let has_pii_profile = cfg.permissions.values().any(|p| {
        matches!(
            p.safety.as_str(),
            "standard" | "guardian" | "guardian-deep" | "block"
        )
    });
    if has_pii_profile {
        #[cfg(feature = "onnx")]
        let mut pipeline = navra_core::safety::build_pipeline("standard");
        #[cfg(not(feature = "onnx"))]
        let pipeline = navra_core::safety::build_pipeline("standard");
        #[cfg(feature = "onnx")]
        if let Some(ref ner) = safety_state.pii_ner_filter {
            pipeline.add_ner_filter_shared(Arc::clone(ner));
        }
        #[cfg(feature = "onnx")]
        if let Some(ref pf) = safety_state.privacy_filter {
            pipeline.add_privacy_filter_shared(Arc::clone(pf));
        }
        tracing::info!("PII filter enabled for model reasoning text");
        Some(Arc::new(pipeline))
    } else {
        None
    }
}

