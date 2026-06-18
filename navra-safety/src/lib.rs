//! PII detection, content safety filters, and pseudonymization for Rust.
//!
//! `navra-safety` provides a pipeline of content filters that detect
//! sensitive data (secrets, PII, prompt injection) in text. It supports
//! both regex-based filters (zero dependencies beyond `regex-lite`) and
//! optional ML-based classifiers via ONNX Runtime.
//!
//! # Quick start
//!
//! ```rust
//! use navra_safety::{FilterPipeline, FilterAction, FilterContext, SecretFilter, PiiFilter};
//!
//! let mut pipeline = FilterPipeline::new(FilterAction::Redact);
//! pipeline.add_filter(SecretFilter::new());
//! pipeline.add_filter(PiiFilter::new());
//!
//! let ctx = FilterContext {
//!     agent_name: "my-app",
//!     operation: "read",
//!     path: None,
//! };
//!
//! let result = pipeline.process("AWS key AKIAIOSFODNN7EXAMPLE, SSN 123-45-6789", &ctx);
//! assert!(result.unwrap().contains("[REDACTED:"));
//! ```
//!
//! # Feature flags
//!
//! - **default**: regex-only filters, zero native dependencies
//! - **onnx**: enables NER and privacy-filter models via ONNX Runtime

pub mod classifier;
pub mod confidentiality;
pub mod ml;
pub mod projection;
#[cfg(feature = "onnx")]
pub mod ner;
#[cfg(feature = "onnx")]
pub mod privacy_filter;
pub mod pseudonym;
mod regex;

pub use self::classifier::{ClassifyError, ClassifyLabel, ClassifyOutput, Classifier};
pub use self::projection::{ProjectionError, SparseProjectionMatrix};
pub use self::confidentiality::Confidentiality;
pub use self::ml::{CategoryPolicy, MlFilter, MultiLabelFilter};
#[cfg(feature = "onnx")]
pub use self::ner::{
    default_pii_ner_model_dir, default_pii_ner_multilingual_model_dir, load_ner_filter, NerFilter,
};
#[cfg(feature = "onnx")]
pub use self::privacy_filter::{
    default_privacy_filter_model_dir, load_privacy_filter, PrivacyFilterModel,
};
pub use self::pseudonym::{PseudonymMap, PseudonymReverser};
pub use self::regex::{
    CustomFilter, CustomPiiFilter, PathPiiFilter, PiiFilter, PromptInjectionFilter, SecretFilter,
};

use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// PII finding categories produced by the PII filter.
const PII_CATEGORIES: &[&str] = &[
    "ssn",
    "credit-card",
    "phone",
    "email",
    "person",
    "location",
    "organization",
    "misc-entity",
    // sfermion NER categories
    "identity-document",
    "ip-address",
    "temporal-pii",
    "username",
    "password",
    "demographic",
    "path-username",
    // Extended NER / privacy-filter categories
    "address",
    "date",
    "secret",
    "url",
    "account-number",
    "credit-card",
    "vehicle-id",
    "device-fingerprint",
];

/// Custom PII categories registered at runtime via `register_pii_categories`.
static CUSTOM_PII_CATEGORIES: std::sync::LazyLock<Mutex<Vec<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

/// Returns true if a finding category represents PII.
///
/// Checks both built-in categories and any custom categories
/// registered via `register_pii_categories`.
pub fn is_pii_category(category: &str) -> bool {
    if PII_CATEGORIES.contains(&category) {
        return true;
    }
    if let Ok(custom) = CUSTOM_PII_CATEGORIES.lock() {
        custom.iter().any(|c| c == category)
    } else {
        false
    }
}

/// Register additional PII categories from custom PII patterns.
///
/// Categories added here will be recognized by `is_pii_category`,
/// causing findings with these categories to trigger IFC taint
/// elevation and PII retention policies.
pub fn register_pii_categories(categories: &[String]) {
    if let Ok(mut custom) = CUSTOM_PII_CATEGORIES.lock() {
        for cat in categories {
            if !PII_CATEGORIES.contains(&cat.as_str()) && !custom.contains(cat) {
                custom.push(cat.clone());
            }
        }
    }
}

/// A detected sensitive content span.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// Byte offset of the start of the finding.
    pub start: usize,
    /// Byte offset of the end of the finding (exclusive).
    pub end: usize,
    /// Category of the finding (e.g. "aws-key", "ssn", "credit-card").
    pub category: String,
    /// Confidence score: 1.0 for regex matches, model confidence for ML.
    pub confidence: f32,
}

/// What to do with content that has findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterAction {
    /// Return content as-is.
    Pass,
    /// Return content with sensitive spans replaced by `[REDACTED:category]`.
    Redact,
    /// Replace sensitive spans with consistent pseudonyms (Person_A, Location_A, etc.).
    Pseudonymize,
    /// Block the entire response.
    Block,
}

/// Result of a declassification decision after PII filtering.
///
/// When the filter pipeline redacts all PII findings, it can recommend
/// stepping down the confidentiality label. This is an explicit,
/// audited declassification — the only exception to IFC monotonicity.
#[derive(Debug, Clone)]
pub struct Declassification {
    /// Recommended new confidentiality level (None = no change).
    pub new_confidentiality: Option<Confidentiality>,
    /// Filter action that was applied.
    pub action: FilterAction,
    /// Number of PII findings detected.
    pub findings_count: usize,
    /// Whether ALL findings were successfully redacted/handled.
    pub all_handled: bool,
    /// Human-readable reason for the declassification decision.
    pub reason: String,
}

impl Declassification {
    /// Determine declassification after PII filtering.
    ///
    /// | Action       | Step-down to     | Reason                                        |
    /// |-------------|-----------------|-----------------------------------------------|
    /// | Redact      | Sensitive        | Markers reveal PII existed, actual data gone   |
    /// | Pseudonymize| Pii (no change)  | Still personal data under GDPR Art. 4(5)       |
    /// | Block       | N/A              | No result returned                            |
    /// | Pass        | Pii (no change)  | Raw PII still present                         |
    pub fn from_filter_result(
        action: &FilterAction,
        findings_count: usize,
        all_handled: bool,
    ) -> Self {
        let (new_conf, reason) = match action {
            FilterAction::Redact if findings_count > 0 && all_handled => (
                Some(Confidentiality::Sensitive),
                format!("Full redaction: {findings_count} PII findings replaced with [REDACTED] markers. \
                         Structural metadata retained (markers reveal PII existed). \
                         Declassified Pii → Sensitive."),
            ),
            FilterAction::Redact if findings_count > 0 && !all_handled => (
                None,
                format!("Partial redaction: not all {findings_count} findings were handled. \
                         Declassification denied — raw PII may remain."),
            ),
            FilterAction::Pseudonymize => (
                None,
                format!("Pseudonymization: {findings_count} findings replaced with pseudonyms. \
                         No declassification — pseudonymized data is still personal data \
                         under GDPR Article 4(5) (reversible with key)."),
            ),
            FilterAction::Pass => (
                None,
                "No filtering applied. Label unchanged.".to_string(),
            ),
            FilterAction::Block => (
                None,
                "Content blocked. No declassification needed.".to_string(),
            ),
            _ => (None, "No PII findings detected.".to_string()),
        };

        Self {
            new_confidentiality: new_conf,
            action: action.clone(),
            findings_count,
            all_handled,
            reason,
        }
    }
}

/// Context passed to filters.
pub struct FilterContext<'a> {
    pub agent_name: &'a str,
    pub operation: &'a str,
    pub path: Option<&'a str>,
}

/// Trait for synchronous content safety filters (regex-based).
///
/// Filters scan text content and return findings (spans of sensitive
/// content with categories and confidence scores).
pub trait ContentFilter: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn scan(&self, content: &str, ctx: &FilterContext) -> Vec<Finding>;
}

/// Trait for asynchronous model-based content filters.
///
/// Runs after sync filters. Only invoked if sync filters did not
/// already block the content.
pub trait ModelFilter: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn scan<'a>(
        &'a self,
        content: &'a str,
        ctx: &'a FilterContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Vec<Finding>> + Send + 'a>>;
}

/// Point-in-time snapshot of PII metrics, safe to serialize.
#[derive(Debug, Clone, Serialize)]
pub struct PiiMetricsSnapshot {
    pub total_scans: u64,
    pub pii_detected: u64,
    pub pii_redacted: u64,
    pub pii_blocked: u64,
    pub by_category: HashMap<String, u64>,
}

/// Thread-safe PII detection metrics.
///
/// Tracks scan counts and per-category PII detections across all
/// filter pipeline invocations. Intended for GDPR DPIA reporting
/// (Article 35).
pub struct PiiMetrics {
    total_scans: AtomicU64,
    pii_detected: AtomicU64,
    pii_redacted: AtomicU64,
    pii_blocked: AtomicU64,
    by_category: Mutex<HashMap<String, u64>>,
}

impl PiiMetrics {
    pub fn new() -> Self {
        Self {
            total_scans: AtomicU64::new(0),
            pii_detected: AtomicU64::new(0),
            pii_redacted: AtomicU64::new(0),
            pii_blocked: AtomicU64::new(0),
            by_category: Mutex::new(HashMap::new()),
        }
    }

    /// Record findings from a scan.
    pub fn record(&self, findings: &[Finding], action: &FilterAction) {
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        let pii_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| is_pii_category(&f.category))
            .collect();
        if pii_findings.is_empty() {
            return;
        }
        self.pii_detected
            .fetch_add(pii_findings.len() as u64, Ordering::Relaxed);
        match action {
            FilterAction::Redact | FilterAction::Pseudonymize => {
                self.pii_redacted
                    .fetch_add(pii_findings.len() as u64, Ordering::Relaxed);
            }
            FilterAction::Block => {
                self.pii_blocked
                    .fetch_add(pii_findings.len() as u64, Ordering::Relaxed);
            }
            FilterAction::Pass => {}
        }
        let mut cats = self.by_category.lock().unwrap_or_else(|e| e.into_inner());
        for f in &pii_findings {
            *cats.entry(f.category.clone()).or_insert(0) += 1;
        }
    }

    /// Return a point-in-time snapshot of all counters.
    pub fn snapshot(&self) -> PiiMetricsSnapshot {
        let cats = self.by_category.lock().unwrap_or_else(|e| e.into_inner());
        PiiMetricsSnapshot {
            total_scans: self.total_scans.load(Ordering::Relaxed),
            pii_detected: self.pii_detected.load(Ordering::Relaxed),
            pii_redacted: self.pii_redacted.load(Ordering::Relaxed),
            pii_blocked: self.pii_blocked.load(Ordering::Relaxed),
            by_category: cats.clone(),
        }
    }

    /// Zero all counters.
    pub fn reset(&self) {
        self.total_scans.store(0, Ordering::Relaxed);
        self.pii_detected.store(0, Ordering::Relaxed);
        self.pii_redacted.store(0, Ordering::Relaxed);
        self.pii_blocked.store(0, Ordering::Relaxed);
        let mut cats = self.by_category.lock().unwrap_or_else(|e| e.into_inner());
        cats.clear();
    }
}

impl Default for PiiMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Pipeline that runs multiple filters and applies a configured action.
///
/// Sync filters (regex) run first. If they don't block, async model
/// filters run next. Supports both outbound (tool responses) and
/// inbound (tool arguments on write-path operations) filtering.
pub struct FilterPipeline {
    filters: Vec<Box<dyn ContentFilter>>,
    model_filters: Vec<Box<dyn ModelFilter>>,
    action: FilterAction,
    pseudonym_map: PseudonymMap,
    metrics: Option<std::sync::Arc<PiiMetrics>>,
}

impl FilterPipeline {
    pub fn new(action: FilterAction) -> Self {
        Self {
            filters: Vec::new(),
            model_filters: Vec::new(),
            action,
            pseudonym_map: PseudonymMap::new(),
            metrics: None,
        }
    }

    /// Create a pipeline with a shared pseudonym map.
    pub fn with_pseudonym_map(action: FilterAction, pseudonym_map: PseudonymMap) -> Self {
        Self {
            filters: Vec::new(),
            model_filters: Vec::new(),
            action,
            pseudonym_map,
            metrics: None,
        }
    }

    /// Returns a reference to the pipeline's pseudonym map.
    pub fn pseudonym_map(&self) -> &PseudonymMap {
        &self.pseudonym_map
    }

    /// Attach shared PII metrics to this pipeline.
    pub fn set_metrics(&mut self, metrics: std::sync::Arc<PiiMetrics>) {
        self.metrics = Some(metrics);
    }

    pub fn add_filter(&mut self, filter: impl ContentFilter) {
        self.filters.push(Box::new(filter));
    }

    pub fn add_model_filter(&mut self, filter: impl ModelFilter) {
        self.model_filters.push(Box::new(filter));
    }

    #[cfg(feature = "onnx")]
    pub fn add_ner_filter(&mut self, filter: NerFilter) {
        self.filters.push(Box::new(filter));
    }

    #[cfg(feature = "onnx")]
    pub fn add_ner_filter_shared(&mut self, filter: std::sync::Arc<NerFilter>) {
        self.filters.push(Box::new(SharedNerFilter(filter)));
    }

    #[cfg(feature = "onnx")]
    pub fn add_privacy_filter_shared(&mut self, filter: std::sync::Arc<PrivacyFilterModel>) {
        self.filters.push(Box::new(SharedPrivacyFilter(filter)));
    }

    /// Filter outbound content (tool responses → agent).
    pub async fn process_outbound(
        &self,
        content: &str,
        ctx: &FilterContext<'_>,
    ) -> Result<String, String> {
        self.run_pipeline(content, ctx, true).await
    }

    /// Filter inbound content (agent → tool write operations).
    pub async fn process_inbound(
        &self,
        content: &str,
        ctx: &FilterContext<'_>,
    ) -> Result<String, String> {
        self.run_pipeline(content, ctx, true).await
    }

    /// Filter outbound content and return findings alongside the result.
    pub async fn process_outbound_with_findings(
        &self,
        content: &str,
        ctx: &FilterContext<'_>,
    ) -> (Result<String, String>, Vec<Finding>) {
        self.run_pipeline_with_findings(content, ctx, true).await
    }

    /// Filter content and return a declassification recommendation.
    pub async fn process_with_declassification(
        &self,
        content: &str,
        ctx: &FilterContext<'_>,
    ) -> (Result<String, String>, Declassification) {
        let (result, findings) = self.run_pipeline_with_findings(content, ctx, true).await;
        let all_handled = result.is_ok();
        let declass =
            Declassification::from_filter_result(&self.action, findings.len(), all_handled);
        (result, declass)
    }

    /// Backward-compatible sync process (runs only sync filters).
    pub fn process(&self, content: &str, ctx: &FilterContext) -> Result<String, String> {
        if self.action == FilterAction::Pass || self.no_filters() {
            return Ok(content.to_string());
        }

        let mut findings: Vec<Finding> = Vec::new();
        for filter in &self.filters {
            findings.extend(filter.scan(content, ctx));
        }

        if let Some(ref m) = self.metrics {
            m.record(&findings, &self.action);
        }

        if findings.is_empty() {
            return Ok(content.to_string());
        }

        apply_action(&self.action, content, &mut findings, &self.pseudonym_map)
    }

    async fn run_pipeline(
        &self,
        content: &str,
        ctx: &FilterContext<'_>,
        include_sync: bool,
    ) -> Result<String, String> {
        if self.action == FilterAction::Pass || self.no_filters() {
            return Ok(content.to_string());
        }

        let mut findings: Vec<Finding> = Vec::new();

        if include_sync {
            for filter in &self.filters {
                findings.extend(filter.scan(content, ctx));
            }

            if !findings.is_empty() && self.action == FilterAction::Block {
                if let Some(ref m) = self.metrics {
                    m.record(&findings, &self.action);
                }
                return apply_action(&self.action, content, &mut findings, &self.pseudonym_map);
            }
        }

        for model_filter in &self.model_filters {
            findings.extend(model_filter.scan(content, ctx).await);
        }

        if let Some(ref m) = self.metrics {
            m.record(&findings, &self.action);
        }

        if findings.is_empty() {
            return Ok(content.to_string());
        }

        apply_action(&self.action, content, &mut findings, &self.pseudonym_map)
    }

    async fn run_pipeline_with_findings(
        &self,
        content: &str,
        ctx: &FilterContext<'_>,
        include_sync: bool,
    ) -> (Result<String, String>, Vec<Finding>) {
        if self.action == FilterAction::Pass || self.no_filters() {
            return (Ok(content.to_string()), Vec::new());
        }

        let mut findings: Vec<Finding> = Vec::new();

        if include_sync {
            for filter in &self.filters {
                findings.extend(filter.scan(content, ctx));
            }

            if !findings.is_empty() && self.action == FilterAction::Block {
                if let Some(ref m) = self.metrics {
                    m.record(&findings, &self.action);
                }
                let result =
                    apply_action(&self.action, content, &mut findings, &self.pseudonym_map);
                return (result, findings);
            }
        }

        for model_filter in &self.model_filters {
            findings.extend(model_filter.scan(content, ctx).await);
        }

        if let Some(ref m) = self.metrics {
            m.record(&findings, &self.action);
        }

        if findings.is_empty() {
            return (Ok(content.to_string()), Vec::new());
        }

        let result = apply_action(&self.action, content, &mut findings, &self.pseudonym_map);
        (result, findings)
    }

    /// Run sync filters only and return findings (no action applied).
    pub fn scan_sync(&self, content: &str, ctx: &FilterContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for filter in &self.filters {
            findings.extend(filter.scan(content, ctx));
        }
        findings
    }

    pub fn has_filters(&self) -> bool {
        !self.filters.is_empty() || !self.model_filters.is_empty()
    }

    fn no_filters(&self) -> bool {
        self.filters.is_empty() && self.model_filters.is_empty()
    }
}

fn apply_action(
    action: &FilterAction,
    content: &str,
    findings: &mut Vec<Finding>,
    pseudonym_map: &PseudonymMap,
) -> Result<String, String> {
    match action {
        FilterAction::Pass => Ok(content.to_string()),
        FilterAction::Block => {
            let categories: Vec<&str> = findings
                .iter()
                .map(|f| f.category.as_str())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            tracing::info!(
                count = findings.len(),
                categories = %categories.join(", "),
                "Content blocked by safety filter"
            );
            Err("Content blocked by security policy".to_string())
        }
        FilterAction::Redact => Ok(redact(content, findings)),
        FilterAction::Pseudonymize => Ok(pseudonymize(content, findings, pseudonym_map)),
    }
}

/// Snap a byte offset to the nearest valid UTF-8 char boundary (rounding down).
fn snap_to_char_boundary(s: &str, pos: usize) -> usize {
    let mut p = pos.min(s.len());
    while p > 0 && !s.is_char_boundary(p) {
        p -= 1;
    }
    p
}

fn redact(content: &str, findings: &mut [Finding]) -> String {
    if findings.is_empty() {
        return content.to_string();
    }
    findings.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut result = String::with_capacity(content.len());
    let mut pos = 0;
    for finding in findings.iter() {
        let start = snap_to_char_boundary(content, finding.start);
        let end = snap_to_char_boundary(content, finding.end);
        if start < pos {
            continue;
        }
        if start > pos {
            result.push_str(&content[pos..start]);
        }
        result.push_str(&format!("[REDACTED:{}]", finding.category));
        pos = end;
    }
    if pos < content.len() {
        result.push_str(&content[pos..]);
    }
    result
}

fn pseudonymize(content: &str, findings: &mut [Finding], map: &PseudonymMap) -> String {
    if findings.is_empty() {
        return content.to_string();
    }
    findings.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut result = String::with_capacity(content.len());
    let mut pos = 0;
    for finding in findings.iter() {
        let start = snap_to_char_boundary(content, finding.start);
        let end = snap_to_char_boundary(content, finding.end);
        if start < pos {
            continue;
        }
        if start > pos {
            result.push_str(&content[pos..start]);
        }
        let original = &content[start..end];
        let pseudonym = map.get_or_create(original, &finding.category);
        result.push_str(&pseudonym);
        pos = end;
    }
    if pos < content.len() {
        result.push_str(&content[pos..]);
    }
    result
}

#[cfg(feature = "onnx")]
mod onnx_wrappers {
    use super::*;

    pub(super) struct SharedNerFilter(pub std::sync::Arc<NerFilter>);

    impl ContentFilter for SharedNerFilter {
        fn name(&self) -> &str {
            self.0.name()
        }
        fn scan(&self, content: &str, ctx: &FilterContext) -> Vec<Finding> {
            self.0.scan(content, ctx)
        }
    }

    pub(super) struct SharedPrivacyFilter(pub std::sync::Arc<PrivacyFilterModel>);

    impl ContentFilter for SharedPrivacyFilter {
        fn name(&self) -> &str {
            self.0.name()
        }
        fn scan(&self, content: &str, ctx: &FilterContext) -> Vec<Finding> {
            self.0.scan(content, ctx)
        }
    }
}
#[cfg(feature = "onnx")]
use onnx_wrappers::{SharedNerFilter, SharedPrivacyFilter};

/// Build a filter pipeline from a safety profile name.
///
/// Profiles:
/// - `"standard"` — all regex filters, redact action
/// - `"pseudonymize"` — all regex filters, pseudonymize action
/// - `"secrets-only"` — secret filter only, redact action
/// - `"block"` — all regex filters, block action
/// - `"guardian"` / `"guardian-deep"` — regex pipeline (ML filters added separately)
/// - `"multi-label"` — regex pipeline (multi-label ML filters added separately)
/// - `"none"` — no filters
pub fn build_pipeline(profile: &str) -> FilterPipeline {
    match profile {
        "standard" => {
            let mut pipeline = FilterPipeline::new(FilterAction::Redact);
            pipeline.add_filter(SecretFilter::new());
            pipeline.add_filter(PiiFilter::new());
            pipeline.add_filter(PathPiiFilter::new());
            pipeline
        }
        "pseudonymize" => {
            let mut pipeline = FilterPipeline::new(FilterAction::Pseudonymize);
            pipeline.add_filter(SecretFilter::new());
            pipeline.add_filter(PiiFilter::new());
            pipeline.add_filter(PathPiiFilter::new());
            pipeline
        }
        "secrets-only" => {
            let mut pipeline = FilterPipeline::new(FilterAction::Redact);
            pipeline.add_filter(SecretFilter::new());
            pipeline
        }
        "block" => {
            let mut pipeline = FilterPipeline::new(FilterAction::Block);
            pipeline.add_filter(SecretFilter::new());
            pipeline.add_filter(PiiFilter::new());
            pipeline.add_filter(PathPiiFilter::new());
            pipeline
        }
        "guardian" | "guardian-deep" => {
            let mut pipeline = FilterPipeline::new(FilterAction::Redact);
            pipeline.add_filter(SecretFilter::new());
            pipeline.add_filter(PiiFilter::new());
            pipeline.add_filter(PathPiiFilter::new());
            pipeline
        }
        "multi-label" => {
            let mut pipeline = FilterPipeline::new(FilterAction::Block);
            pipeline.add_filter(SecretFilter::new());
            pipeline.add_filter(PiiFilter::new());
            pipeline.add_filter(PathPiiFilter::new());
            pipeline
        }
        "none" | "" => FilterPipeline::new(FilterAction::Pass),
        _ => {
            tracing::warn!(profile, "Unknown safety profile, defaulting to 'standard'");
            build_pipeline("standard")
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
    fn empty_pipeline_passes_through() {
        let pipeline = FilterPipeline::new(FilterAction::Redact);
        let result = pipeline.process("hello world", &ctx()).unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn pass_action_never_modifies() {
        let mut pipeline = FilterPipeline::new(FilterAction::Pass);
        pipeline.add_filter(SecretFilter::new());
        let content = "key = AKIAIOSFODNN7EXAMPLE";
        let result = pipeline.process(content, &ctx()).unwrap();
        assert_eq!(result, content);
    }

    #[test]
    fn redact_replaces_findings() {
        let mut findings = vec![Finding {
            start: 6,
            end: 26,
            category: "aws-key".to_string(),
            confidence: 1.0,
        }];
        let result = redact("key = AKIAIOSFODNN7EXAMPLE rest", &mut findings);
        assert_eq!(result, "key = [REDACTED:aws-key] rest");
    }

    #[test]
    fn redact_handles_adjacent_findings() {
        let mut findings = vec![
            Finding { start: 0, end: 3, category: "a".to_string(), confidence: 1.0 },
            Finding { start: 4, end: 7, category: "b".to_string(), confidence: 1.0 },
        ];
        let result = redact("AAA BBB CCC", &mut findings);
        assert_eq!(result, "[REDACTED:a] [REDACTED:b] CCC");
    }

    #[test]
    fn redact_handles_overlapping_findings() {
        let mut findings = vec![
            Finding { start: 0, end: 5, category: "wide".to_string(), confidence: 1.0 },
            Finding { start: 2, end: 4, category: "narrow".to_string(), confidence: 1.0 },
        ];
        let result = redact("ABCDEFGH", &mut findings);
        assert_eq!(result, "[REDACTED:wide]FGH");
    }

    #[test]
    fn redact_handles_multibyte_utf8() {
        // CJK characters are 3 bytes each: 你好世界 = 12 bytes
        let content = "AB你好CD";
        // Simulate a finding that starts mid-character (byte 3 = middle of 你)
        let mut findings = vec![Finding {
            start: 3,
            end: 8,
            category: "pii".to_string(),
            confidence: 1.0,
        }];
        // Should not panic — snaps to nearest char boundary
        let result = redact(content, &mut findings);
        assert!(!result.is_empty());
    }

    #[test]
    fn redact_handles_emoji() {
        let content = "Hello 🎉 world";
        let mut findings = vec![Finding {
            start: 6,
            end: 10,
            category: "emoji".to_string(),
            confidence: 1.0,
        }];
        let result = redact(content, &mut findings);
        assert!(result.contains("[REDACTED:emoji]"));
    }

    #[test]
    fn pseudonymize_handles_multibyte_utf8() {
        let content = "名前は田中です";
        let mut findings = vec![Finding {
            start: 9,
            end: 15,
            category: "name".to_string(),
            confidence: 1.0,
        }];
        let map = PseudonymMap::new();
        let result = pseudonymize(content, &mut findings, &map);
        assert!(!result.is_empty());
    }

    #[test]
    fn block_action_returns_error() {
        let mut pipeline = FilterPipeline::new(FilterAction::Block);
        pipeline.add_filter(SecretFilter::new());
        let result = pipeline.process("key = AKIAIOSFODNN7EXAMPLE", &ctx());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("blocked"));
    }

    #[test]
    fn build_pipeline_standard() {
        let pipeline = build_pipeline("standard");
        assert!(pipeline.has_filters());
        assert_eq!(pipeline.action, FilterAction::Redact);
    }

    #[test]
    fn build_pipeline_none() {
        let pipeline = build_pipeline("none");
        assert!(!pipeline.has_filters());
    }

    #[test]
    fn build_pipeline_guardian() {
        let pipeline = build_pipeline("guardian");
        assert!(pipeline.has_filters());
        assert_eq!(pipeline.action, FilterAction::Redact);
    }

    #[test]
    fn pii_category_detection() {
        assert!(is_pii_category("ssn"));
        assert!(is_pii_category("credit-card"));
        assert!(is_pii_category("phone"));
        assert!(is_pii_category("email"));
        assert!(!is_pii_category("aws-key"));
        assert!(!is_pii_category("private-key"));
    }

    #[test]
    fn pii_category_includes_ner_types() {
        assert!(is_pii_category("person"));
        assert!(is_pii_category("location"));
        assert!(is_pii_category("organization"));
        assert!(is_pii_category("misc-entity"));
    }

    #[test]
    fn pii_category_includes_sfermion_types() {
        assert!(is_pii_category("identity-document"));
        assert!(is_pii_category("ip-address"));
        assert!(is_pii_category("temporal-pii"));
        assert!(is_pii_category("username"));
        assert!(is_pii_category("password"));
        assert!(is_pii_category("demographic"));
        assert!(is_pii_category("path-username"));
    }

    #[tokio::test]
    async fn process_outbound_with_findings_returns_pii() {
        let mut pipeline = FilterPipeline::new(FilterAction::Redact);
        pipeline.add_filter(PiiFilter::new());
        let (result, findings) = pipeline
            .process_outbound_with_findings("SSN: 123-45-6789", &ctx())
            .await;
        assert!(result.unwrap().contains("[REDACTED:ssn]"));
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| is_pii_category(&f.category)));
    }

    #[tokio::test]
    async fn process_outbound_with_findings_no_pii() {
        let mut pipeline = FilterPipeline::new(FilterAction::Redact);
        pipeline.add_filter(SecretFilter::new());
        let (result, findings) = pipeline
            .process_outbound_with_findings("key = AKIAIOSFODNN7EXAMPLE", &ctx())
            .await;
        assert!(result.unwrap().contains("[REDACTED:aws-key]"));
        assert!(!findings.is_empty());
        assert!(!findings.iter().any(|f| is_pii_category(&f.category)));
    }

    #[test]
    fn build_pipeline_multi_label() {
        let pipeline = build_pipeline("multi-label");
        assert!(pipeline.has_filters());
        assert_eq!(pipeline.action, FilterAction::Block);
    }

    #[test]
    fn build_pipeline_guardian_deep() {
        let pipeline = build_pipeline("guardian-deep");
        assert!(pipeline.has_filters());
        assert_eq!(pipeline.action, FilterAction::Redact);
    }

    #[tokio::test]
    async fn process_outbound_redacts() {
        let mut pipeline = FilterPipeline::new(FilterAction::Redact);
        pipeline.add_filter(SecretFilter::new());
        let result = pipeline
            .process_outbound("key = AKIAIOSFODNN7EXAMPLE", &ctx())
            .await
            .unwrap();
        assert!(result.contains("[REDACTED:aws-key]"));
    }

    #[tokio::test]
    async fn process_inbound_catches_secrets() {
        let mut pipeline = FilterPipeline::new(FilterAction::Block);
        pipeline.add_filter(SecretFilter::new());
        let result = pipeline
            .process_inbound("key = AKIAIOSFODNN7EXAMPLE", &ctx())
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn pseudonymize_replaces_findings() {
        let map = PseudonymMap::new();
        let mut findings = vec![Finding {
            start: 4, end: 15, category: "email".to_string(), confidence: 1.0,
        }];
        let result = pseudonymize("Hi, a@b.example here", &mut findings, &map);
        assert_eq!(result, "Hi, Email_A here");
    }

    #[test]
    fn pseudonymize_consistent_across_calls() {
        let map = PseudonymMap::new();
        let mut findings1 = vec![Finding {
            start: 0, end: 11, category: "person".to_string(), confidence: 1.0,
        }];
        let result1 = pseudonymize("Jean Dupont said hello", &mut findings1, &map);
        let mut findings2 = vec![Finding {
            start: 9, end: 20, category: "person".to_string(), confidence: 1.0,
        }];
        let result2 = pseudonymize("Reply to Jean Dupont please", &mut findings2, &map);
        assert_eq!(result1, "Person_A said hello");
        assert_eq!(result2, "Reply to Person_A please");
    }

    #[test]
    fn build_pipeline_pseudonymize() {
        let pipeline = build_pipeline("pseudonymize");
        assert!(pipeline.has_filters());
        assert_eq!(pipeline.action, FilterAction::Pseudonymize);
    }

    #[tokio::test]
    async fn pseudonymize_pipeline_process_outbound() {
        let mut pipeline = FilterPipeline::new(FilterAction::Pseudonymize);
        pipeline.add_filter(PiiFilter::new());
        let result = pipeline.process_outbound("SSN: 123-45-6789", &ctx()).await.unwrap();
        assert!(!result.contains("123-45-6789"));
        assert!(result.contains("ID_A"));
    }

    #[test]
    fn custom_pii_categories_recognized() {
        register_pii_categories(&["employee-id".to_string(), "badge".to_string()]);
        assert!(is_pii_category("employee-id"));
        assert!(is_pii_category("badge"));
        assert!(is_pii_category("ssn"));
        assert!(!is_pii_category("aws-key"));
    }

    #[test]
    fn pii_metrics_counting() {
        let metrics = PiiMetrics::new();
        let findings = vec![
            Finding { start: 0, end: 5, category: "email".to_string(), confidence: 1.0 },
            Finding { start: 10, end: 15, category: "phone".to_string(), confidence: 1.0 },
            Finding { start: 20, end: 30, category: "aws-key".to_string(), confidence: 1.0 },
        ];
        metrics.record(&findings, &FilterAction::Redact);
        let snap = metrics.snapshot();
        assert_eq!(snap.total_scans, 1);
        assert_eq!(snap.pii_detected, 2);
        assert_eq!(snap.pii_redacted, 2);
        assert_eq!(snap.pii_blocked, 0);
        assert_eq!(snap.by_category.get("email"), Some(&1));
        assert_eq!(snap.by_category.get("phone"), Some(&1));
        assert_eq!(snap.by_category.get("aws-key"), None);
    }

    #[test]
    fn pii_metrics_reset() {
        let metrics = PiiMetrics::new();
        let findings = vec![Finding {
            start: 0, end: 5, category: "email".to_string(), confidence: 1.0,
        }];
        metrics.record(&findings, &FilterAction::Redact);
        assert_eq!(metrics.snapshot().total_scans, 1);
        metrics.reset();
        let snap = metrics.snapshot();
        assert_eq!(snap.total_scans, 0);
        assert!(snap.by_category.is_empty());
    }

    #[test]
    fn pipeline_records_metrics() {
        let metrics = std::sync::Arc::new(PiiMetrics::new());
        let mut pipeline = FilterPipeline::new(FilterAction::Redact);
        pipeline.add_filter(PiiFilter::new());
        pipeline.set_metrics(std::sync::Arc::clone(&metrics));
        let _ = pipeline.process("SSN: 123-45-6789", &ctx());
        let snap = metrics.snapshot();
        assert_eq!(snap.total_scans, 1);
        assert!(snap.pii_detected > 0);
    }
}
