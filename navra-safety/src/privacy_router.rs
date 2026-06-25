//! Unified privacy detection coordinator.
//!
//! `PrivacyRouter` holds all privacy detector components and implements
//! `ContentFilter`, routing content to appropriate detectors based on
//! text characteristics and prior findings. Short-circuits expensive
//! ML-based detectors when regex filters already found enough PII.

use crate::{ContentFilter, CustomPiiFilter, FilterContext, Finding, PathPiiFilter, PiiFilter};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "onnx")]
use std::sync::Arc;

#[cfg(feature = "onnx")]
use crate::{NerFilter, PrivacyFilterModel};

#[cfg(feature = "onnx")]
const MIN_NER_LENGTH: usize = 10;

fn default_true() -> bool {
    true
}

fn default_short_circuit() -> usize {
    5
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PrivacyRouterConfig {
    #[serde(default = "default_true")]
    pub regex_pii: bool,
    #[serde(default = "default_true")]
    pub path_pii: bool,
    #[serde(default = "default_true")]
    pub ner: bool,
    #[serde(default = "default_true")]
    pub privacy_model: bool,
    #[serde(default = "default_true")]
    pub custom_pii: bool,
    #[serde(default = "default_short_circuit")]
    pub short_circuit_threshold: usize,
}

impl Default for PrivacyRouterConfig {
    fn default() -> Self {
        Self {
            regex_pii: true,
            path_pii: true,
            ner: true,
            privacy_model: true,
            custom_pii: true,
            short_circuit_threshold: default_short_circuit(),
        }
    }
}

pub struct PrivacyRouter {
    pii_filter: Option<PiiFilter>,
    path_pii_filter: Option<PathPiiFilter>,
    #[cfg(feature = "onnx")]
    ner_filter: Option<Arc<NerFilter>>,
    #[cfg(feature = "onnx")]
    privacy_model: Option<Arc<PrivacyFilterModel>>,
    custom_pii_filter: Option<CustomPiiFilter>,
    #[cfg_attr(not(feature = "onnx"), allow(dead_code))]
    short_circuit_threshold: usize,
    skipped_total: AtomicU64,
}

impl PrivacyRouter {
    pub fn builder() -> PrivacyRouterBuilder {
        PrivacyRouterBuilder::default()
    }

    pub fn skipped_total(&self) -> u64 {
        self.skipped_total.load(Ordering::Relaxed)
    }
}

impl ContentFilter for PrivacyRouter {
    fn name(&self) -> &str {
        "privacy-router"
    }

    fn scan(&self, content: &str, ctx: &FilterContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: cheap regex detectors (always run if configured)
        if let Some(ref f) = self.pii_filter {
            findings.extend(f.scan(content, ctx));
        }
        if let Some(ref f) = self.path_pii_filter {
            findings.extend(f.scan(content, ctx));
        }
        if let Some(ref f) = self.custom_pii_filter {
            findings.extend(f.scan(content, ctx));
        }

        // Phase 2: expensive ML detectors — skip when short-circuit fires
        #[cfg(feature = "onnx")]
        {
            let skip_expensive =
                findings.len() >= self.short_circuit_threshold || content.len() < MIN_NER_LENGTH;

            if skip_expensive {
                let has_expensive = self.ner_filter.is_some() || self.privacy_model.is_some();
                if has_expensive && !findings.is_empty() {
                    self.skipped_total.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        regex_findings = findings.len(),
                        threshold = self.short_circuit_threshold,
                        content_len = content.len(),
                        "Privacy router short-circuited expensive detectors"
                    );
                }
            } else {
                if let Some(ref f) = self.ner_filter {
                    findings.extend(f.scan(content, ctx));
                }
                if let Some(ref f) = self.privacy_model {
                    findings.extend(f.scan(content, ctx));
                }
            }
        }

        findings
    }
}

#[derive(Default)]
pub struct PrivacyRouterBuilder {
    pii_filter: Option<PiiFilter>,
    path_pii_filter: Option<PathPiiFilter>,
    #[cfg(feature = "onnx")]
    ner_filter: Option<Arc<NerFilter>>,
    #[cfg(feature = "onnx")]
    privacy_model: Option<Arc<PrivacyFilterModel>>,
    custom_pii_filter: Option<CustomPiiFilter>,
    short_circuit_threshold: Option<usize>,
}

impl PrivacyRouterBuilder {
    pub fn with_pii_filter(mut self, filter: PiiFilter) -> Self {
        self.pii_filter = Some(filter);
        self
    }

    pub fn with_path_pii_filter(mut self, filter: PathPiiFilter) -> Self {
        self.path_pii_filter = Some(filter);
        self
    }

    #[cfg(feature = "onnx")]
    pub fn with_ner_filter(mut self, filter: Arc<NerFilter>) -> Self {
        self.ner_filter = Some(filter);
        self
    }

    #[cfg(feature = "onnx")]
    pub fn with_privacy_model(mut self, filter: Arc<PrivacyFilterModel>) -> Self {
        self.privacy_model = Some(filter);
        self
    }

    pub fn with_custom_pii_filter(mut self, filter: CustomPiiFilter) -> Self {
        self.custom_pii_filter = Some(filter);
        self
    }

    pub fn with_short_circuit_threshold(mut self, threshold: usize) -> Self {
        self.short_circuit_threshold = Some(threshold);
        self
    }

    pub fn build(self) -> PrivacyRouter {
        PrivacyRouter {
            pii_filter: self.pii_filter,
            path_pii_filter: self.path_pii_filter,
            #[cfg(feature = "onnx")]
            ner_filter: self.ner_filter,
            #[cfg(feature = "onnx")]
            privacy_model: self.privacy_model,
            custom_pii_filter: self.custom_pii_filter,
            short_circuit_threshold: self
                .short_circuit_threshold
                .unwrap_or_else(default_short_circuit),
            skipped_total: AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> FilterContext<'static> {
        FilterContext {
            agent_name: "test",
            operation: "read",
            path: Some("/test"),
        }
    }

    #[test]
    fn empty_router_returns_no_findings() {
        let router = PrivacyRouter::builder().build();
        let findings = router.scan("some content with SSN 123-45-6789", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn router_with_pii_filter_detects_pii() {
        let router = PrivacyRouter::builder()
            .with_pii_filter(PiiFilter::new())
            .build();
        let findings = router.scan("SSN: 123-45-6789", &ctx());
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "ssn"));
    }

    #[test]
    fn router_with_path_filter_detects_path_pii() {
        let router = PrivacyRouter::builder()
            .with_path_pii_filter(PathPiiFilter::new())
            .build();
        let findings = router.scan("/home/jean.dupont/docs/report.txt", &ctx());
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "path-username"));
    }

    #[test]
    fn router_with_all_regex_filters() {
        let custom = CustomPiiFilter::new(vec![(
            "badge".to_string(),
            r"\bBDG[A-Z]\d{4}\b".to_string(),
            "badge".to_string(),
        )])
        .unwrap();

        let router = PrivacyRouter::builder()
            .with_pii_filter(PiiFilter::new())
            .with_path_pii_filter(PathPiiFilter::new())
            .with_custom_pii_filter(custom)
            .build();

        let content = "SSN 123-45-6789, path /home/jean.dupont/x, badge BDGA1234";
        let findings = router.scan(content, &ctx());
        let categories: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
        assert!(categories.contains(&"ssn"));
        assert!(categories.contains(&"path-username"));
        assert!(categories.contains(&"badge"));
    }

    #[test]
    fn short_circuit_skips_when_threshold_reached() {
        // With threshold=1, any regex finding should trigger short-circuit.
        // Without ONNX models loaded, we can only verify the counter stays 0
        // (no expensive detectors to skip).
        let router = PrivacyRouter::builder()
            .with_pii_filter(PiiFilter::new())
            .with_short_circuit_threshold(1)
            .build();

        let content = "SSN: 123-45-6789 and email user@example.com";
        let findings = router.scan(content, &ctx());
        assert!(!findings.is_empty());
        // No ONNX detectors configured, so skipped_total stays 0
        assert_eq!(router.skipped_total(), 0);
    }

    #[test]
    fn short_text_still_runs_regex() {
        let router = PrivacyRouter::builder()
            .with_pii_filter(PiiFilter::new())
            .build();
        // Short text with an email — regex should still catch it
        let findings = router.scan("a@b.com", &ctx());
        assert!(findings.iter().any(|f| f.category == "email"));
    }

    #[test]
    fn builder_short_circuit_default() {
        let router = PrivacyRouter::builder().build();
        assert_eq!(router.short_circuit_threshold, 5);
    }

    #[test]
    fn builder_custom_threshold() {
        let router = PrivacyRouter::builder()
            .with_short_circuit_threshold(10)
            .build();
        assert_eq!(router.short_circuit_threshold, 10);
    }

    #[test]
    fn config_default_values() {
        let config = PrivacyRouterConfig::default();
        assert!(config.regex_pii);
        assert!(config.path_pii);
        assert!(config.ner);
        assert!(config.privacy_model);
        assert!(config.custom_pii);
        assert_eq!(config.short_circuit_threshold, 5);
    }

    #[test]
    fn config_deserialize_empty() {
        let config: PrivacyRouterConfig = serde_json::from_str("{}").unwrap();
        assert!(config.regex_pii);
        assert!(config.path_pii);
        assert!(config.ner);
        assert!(config.privacy_model);
        assert!(config.custom_pii);
        assert_eq!(config.short_circuit_threshold, 5);
    }

    #[test]
    fn config_deserialize_partial() {
        let config: PrivacyRouterConfig =
            serde_json::from_str(r#"{"ner": false, "short_circuit_threshold": 10}"#).unwrap();
        assert!(config.regex_pii);
        assert!(!config.ner);
        assert_eq!(config.short_circuit_threshold, 10);
    }

    #[test]
    fn config_serialize_roundtrip() {
        let config = PrivacyRouterConfig {
            regex_pii: true,
            path_pii: false,
            ner: true,
            privacy_model: false,
            custom_pii: true,
            short_circuit_threshold: 3,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: PrivacyRouterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.path_pii, false);
        assert_eq!(parsed.privacy_model, false);
        assert_eq!(parsed.short_circuit_threshold, 3);
    }

    #[test]
    fn router_name() {
        let router = PrivacyRouter::builder().build();
        assert_eq!(router.name(), "privacy-router");
    }

    #[test]
    fn router_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PrivacyRouter>();
    }

    #[test]
    fn no_findings_on_clean_text() {
        let router = PrivacyRouter::builder()
            .with_pii_filter(PiiFilter::new())
            .with_path_pii_filter(PathPiiFilter::new())
            .build();
        let findings = router.scan("This is perfectly normal text about programming.", &ctx());
        assert!(findings.is_empty());
    }
}
