pub mod ml;
pub mod ner;
pub mod pseudonym;
mod regex;

pub use self::ml::{CategoryPolicy, MlFilter, MultiLabelFilter};
pub use self::ner::{
    default_pii_ner_model_dir, default_pii_ner_multilingual_model_dir, load_ner_filter, NerFilter,
};
pub use self::pseudonym::{PseudonymMap, PseudonymReverser};
pub use self::regex::{CustomFilter, CustomPiiFilter, PathPiiFilter, PiiFilter, SecretFilter};

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
    pub new_confidentiality: Option<smgglrs_protocol::label::Confidentiality>,
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
    pub fn from_filter_result(action: &FilterAction, findings_count: usize, all_handled: bool) -> Self {
        use smgglrs_protocol::label::Confidentiality;

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
    /// Per-session pseudonym map, used when action is `Pseudonymize`.
    pseudonym_map: PseudonymMap,
    /// Optional PII metrics collector.
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
    ///
    /// Use this when multiple pipelines should share the same pseudonym
    /// assignments (e.g., across a session).
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

    /// Add a NER-based entity detection filter.
    ///
    /// The NER filter runs as a sync `ContentFilter` after regex filters.
    /// It detects named entities (PERSON, LOCATION, ORGANIZATION) that
    /// regex patterns cannot catch.
    pub fn add_ner_filter(&mut self, filter: NerFilter) {
        self.filters.push(Box::new(filter));
    }

    /// Add a shared NER filter from an `Arc`.
    ///
    /// Allows reusing the same loaded model across multiple safety
    /// pipelines without loading it multiple times.
    pub fn add_ner_filter_shared(&mut self, filter: std::sync::Arc<NerFilter>) {
        self.filters.push(Box::new(SharedNerFilter(filter)));
    }

    /// Filter outbound content (tool responses → agent).
    ///
    /// Runs all sync filters, then all model filters.
    /// Returns `Ok(content)` (possibly redacted) or `Err(reason)` if blocked.
    pub async fn process_outbound(
        &self,
        content: &str,
        ctx: &FilterContext<'_>,
    ) -> Result<String, String> {
        self.run_pipeline(content, ctx, true).await
    }

    /// Filter inbound content (agent → tool write operations).
    ///
    /// Runs the full pipeline (regex + model filters). Regex filters
    /// catch injection patterns and prompt injection in agent-written
    /// content. Used for write, edit, and voice.speak operations.
    /// Returns `Ok(content)` or `Err(reason)` if blocked.
    pub async fn process_inbound(
        &self,
        content: &str,
        ctx: &FilterContext<'_>,
    ) -> Result<String, String> {
        self.run_pipeline(content, ctx, true).await
    }

    /// Filter outbound content and return findings alongside the result.
    ///
    /// Like `process_outbound`, but also returns the list of findings
    /// so callers can inspect categories (e.g., to detect PII and
    /// elevate IFC labels).
    pub async fn process_outbound_with_findings(
        &self,
        content: &str,
        ctx: &FilterContext<'_>,
    ) -> (Result<String, String>, Vec<Finding>) {
        self.run_pipeline_with_findings(content, ctx, true).await
    }

    /// Filter content and return a declassification recommendation.
    ///
    /// Runs the full pipeline, then determines whether the
    /// confidentiality label can be stepped down based on what
    /// was filtered:
    /// - Redact (all handled) → Sensitive (markers reveal PII existed)
    /// - Pseudonymize → no change (GDPR Art. 4(5): still personal data)
    /// - Pass/Block → no change
    pub async fn process_with_declassification(
        &self,
        content: &str,
        ctx: &FilterContext<'_>,
    ) -> (Result<String, String>, Declassification) {
        let (result, findings) = self.run_pipeline_with_findings(content, ctx, true).await;
        let all_handled = result.is_ok();
        let declass = Declassification::from_filter_result(
            &self.action, findings.len(), all_handled,
        );
        (result, declass)
    }

    /// Backward-compatible sync process (for callers that don't have
    /// model filters). Runs only sync filters.
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
                let result = apply_action(&self.action, content, &mut findings, &self.pseudonym_map);
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
    ///
    /// Used by the legacy sync path to inspect findings for PII
    /// category detection before applying the action.
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

/// Apply the filter action (block, redact, or pseudonymize) to content with findings.
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
            Err(format!(
                "Content blocked: detected {} sensitive item(s) ({})",
                findings.len(),
                categories.join(", "),
            ))
        }
        FilterAction::Redact => Ok(redact(content, findings)),
        FilterAction::Pseudonymize => Ok(pseudonymize(content, findings, pseudonym_map)),
    }
}

/// Replace finding spans with `[REDACTED:category]` markers.
///
/// Handles overlapping spans by merging them (largest category wins).
fn redact(content: &str, findings: &mut [Finding]) -> String {
    if findings.is_empty() {
        return content.to_string();
    }

    // Sort by start position, then by length descending (longer match first)
    findings.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

    let mut result = String::with_capacity(content.len());
    let mut pos = 0;

    for finding in findings.iter() {
        // Skip findings that overlap with already-processed regions
        if finding.start < pos {
            continue;
        }
        // Append content before the finding
        if finding.start > pos {
            result.push_str(&content[pos..finding.start]);
        }
        // Replace with redaction marker
        result.push_str(&format!("[REDACTED:{}]", finding.category));
        pos = finding.end;
    }

    // Append remaining content
    if pos < content.len() {
        result.push_str(&content[pos..]);
    }

    result
}

/// Replace finding spans with consistent pseudonyms.
///
/// Uses the `PseudonymMap` to assign stable pseudonyms: the same
/// original value always maps to the same pseudonym within a session.
/// Handles overlapping spans identically to `redact`.
fn pseudonymize(content: &str, findings: &mut [Finding], map: &PseudonymMap) -> String {
    if findings.is_empty() {
        return content.to_string();
    }

    // Sort by start position, then by length descending (longer match first)
    findings.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

    let mut result = String::with_capacity(content.len());
    let mut pos = 0;

    for finding in findings.iter() {
        // Skip findings that overlap with already-processed regions
        if finding.start < pos {
            continue;
        }
        // Append content before the finding
        if finding.start > pos {
            result.push_str(&content[pos..finding.start]);
        }
        // Look up the original value and replace with pseudonym
        let original = &content[finding.start..finding.end];
        let pseudonym = map.get_or_create(original, &finding.category);
        result.push_str(&pseudonym);
        pos = finding.end;
    }

    // Append remaining content
    if pos < content.len() {
        result.push_str(&content[pos..]);
    }

    result
}

/// Wrapper around `Arc<NerFilter>` that implements `ContentFilter`.
///
/// Allows sharing a single loaded NER model across multiple pipelines.
struct SharedNerFilter(std::sync::Arc<NerFilter>);

impl ContentFilter for SharedNerFilter {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn scan(&self, content: &str, ctx: &FilterContext) -> Vec<Finding> {
        self.0.scan(content, ctx)
    }
}

/// Build a filter pipeline from a safety profile name.
///
/// Profiles:
/// - `"standard"` — all regex filters, redact action
/// - `"pseudonymize"` — all regex filters, pseudonymize action
/// - `"secrets-only"` — secret filter only, redact action
/// - `"block"` — all regex filters, block action
/// - `"guardian"` — regex + ML safety (Guardian HAP 38M, in-process)
/// - `"guardian-deep"` — regex + ML safety (HAP 38M + Guardian 3.3 8B)
/// - `"none"` — no filters
///
/// The `"guardian"` and `"guardian-deep"` profiles create the regex
/// pipeline here. ML model filters are added by the server at startup
/// when models are loaded (via `pipeline.add_model_filter()`). NER
/// filters are also added by the server via `pipeline.add_ner_filter()`
/// when a NER model directory is configured.
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
            // Regex tier (same as standard). ML model filters are added
            // by the server when models are loaded.
            let mut pipeline = FilterPipeline::new(FilterAction::Redact);
            pipeline.add_filter(SecretFilter::new());
            pipeline.add_filter(PiiFilter::new());
            pipeline.add_filter(PathPiiFilter::new());
            pipeline
        }
        "multi-label" => {
            // Regex tier (same as standard). Multi-label ML model
            // filters are added by the server when models are loaded,
            // using per-category thresholds from config.
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
        let mut findings = vec![
            Finding {
                start: 6,
                end: 26,
                category: "aws-key".to_string(),
                confidence: 1.0,
            },
        ];
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
        // Wide finding covers the narrow one
        assert_eq!(result, "[REDACTED:wide]FGH");
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
        // Only secret findings, no PII
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
        // Inbound filtering now runs the full pipeline (regex + model filters)
        let mut pipeline = FilterPipeline::new(FilterAction::Block);
        pipeline.add_filter(SecretFilter::new());
        let result = pipeline
            .process_inbound("key = AKIAIOSFODNN7EXAMPLE", &ctx())
            .await;
        // Secret should be caught and blocked
        assert!(result.is_err());
    }

    // --- Pseudonymization tests ---

    #[test]
    fn pseudonymize_replaces_findings() {
        let map = PseudonymMap::new();
        let mut findings = vec![
            Finding {
                start: 4,
                end: 15,
                category: "email".to_string(),
                confidence: 1.0,
            },
        ];
        let result = pseudonymize("Hi, a@b.example here", &mut findings, &map);
        assert_eq!(result, "Hi, Email_A here");
        assert!(!result.contains("a@b.example"));
    }

    #[test]
    fn pseudonymize_consistent_across_calls() {
        let map = PseudonymMap::new();
        // First call
        let mut findings1 = vec![
            Finding { start: 0, end: 11, category: "person".to_string(), confidence: 1.0 },
        ];
        let result1 = pseudonymize("Jean Dupont said hello", &mut findings1, &map);

        // Second call with same value at different position
        let mut findings2 = vec![
            Finding { start: 9, end: 20, category: "person".to_string(), confidence: 1.0 },
        ];
        let result2 = pseudonymize("Reply to Jean Dupont please", &mut findings2, &map);

        assert_eq!(result1, "Person_A said hello");
        assert_eq!(result2, "Reply to Person_A please");
    }

    #[test]
    fn pseudonymize_different_values_different_pseudonyms() {
        let map = PseudonymMap::new();
        let mut findings = vec![
            Finding { start: 0, end: 11, category: "person".to_string(), confidence: 1.0 },
            Finding { start: 16, end: 28, category: "person".to_string(), confidence: 1.0 },
        ];
        let result = pseudonymize("Jean Dupont and Marie Dupont", &mut findings, &map);
        assert_eq!(result, "Person_A and Person_B");
    }

    #[test]
    fn pseudonymize_different_categories() {
        let map = PseudonymMap::new();
        let mut findings = vec![
            Finding { start: 0, end: 4, category: "person".to_string(), confidence: 1.0 },
            Finding { start: 11, end: 16, category: "location".to_string(), confidence: 1.0 },
        ];
        let result = pseudonymize("Jean lives Paris way", &mut findings, &map);
        assert_eq!(result, "Person_A lives Location_A way");
    }

    #[test]
    fn pseudonymize_no_original_in_output() {
        let map = PseudonymMap::new();
        let mut findings = vec![
            Finding { start: 5, end: 19, category: "email".to_string(), confidence: 1.0 },
        ];
        let content = "mail jean@test.com ok";
        let result = pseudonymize(content, &mut findings, &map);
        assert!(!result.contains("jean@test.com"));
        assert!(result.contains("Email_A"));
    }

    #[test]
    fn pseudonymize_extract_reverser() {
        let map = PseudonymMap::new();
        let mut findings = vec![
            Finding { start: 0, end: 4, category: "person".to_string(), confidence: 1.0 },
        ];
        pseudonymize("Jean lives here", &mut findings, &map);
        let reverser = map.extract_reverser();
        assert_eq!(reverser.resolve("Person_A"), Some("Jean"));
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
        let content = "SSN: 123-45-6789";
        let result = pipeline.process_outbound(content, &ctx()).await.unwrap();
        assert!(!result.contains("123-45-6789"));
        assert!(result.contains("ID_A"));
    }

    #[tokio::test]
    async fn pseudonymize_pipeline_consistent_across_outbound_calls() {
        let mut pipeline = FilterPipeline::new(FilterAction::Pseudonymize);
        pipeline.add_filter(PiiFilter::new());
        let r1 = pipeline
            .process_outbound("Contact: test@example.com", &ctx())
            .await
            .unwrap();
        let r2 = pipeline
            .process_outbound("Again: test@example.com", &ctx())
            .await
            .unwrap();
        // Same email should produce the same pseudonym
        assert!(r1.contains("Email_A"));
        assert!(r2.contains("Email_A"));
    }

    #[test]
    fn custom_pii_categories_recognized() {
        register_pii_categories(&[
            "employee-id".to_string(),
            "badge".to_string(),
        ]);
        assert!(is_pii_category("employee-id"));
        assert!(is_pii_category("badge"));
        // Built-in categories still work
        assert!(is_pii_category("ssn"));
        assert!(is_pii_category("email"));
        // Non-PII categories still rejected
        assert!(!is_pii_category("aws-key"));
    }

    #[test]
    fn register_pii_categories_deduplicates() {
        register_pii_categories(&["test-dedup".to_string()]);
        register_pii_categories(&["test-dedup".to_string()]);
        let custom = CUSTOM_PII_CATEGORIES.lock().unwrap();
        let count = custom.iter().filter(|c| c.as_str() == "test-dedup").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn register_pii_categories_skips_builtin() {
        let before = CUSTOM_PII_CATEGORIES.lock().unwrap().len();
        register_pii_categories(&["ssn".to_string()]);
        let after = CUSTOM_PII_CATEGORIES.lock().unwrap().len();
        // "ssn" is already built-in, should not be added to custom
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn custom_pii_filter_in_pipeline_produces_findings() {
        let mut pipeline = FilterPipeline::new(FilterAction::Redact);
        let filter = CustomPiiFilter::new(vec![
            ("employee-id".to_string(), r"\bEMP-\d{6}\b".to_string(), "employee-id".to_string()),
        ]).unwrap();
        pipeline.add_filter(filter);
        let (result, findings) = pipeline
            .process_outbound_with_findings("Employee EMP-123456 is here", &ctx())
            .await;
        assert!(result.unwrap().contains("[REDACTED:employee-id]"));
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, "employee-id");
    }

    // --- PII metrics tests ---

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
    fn pii_metrics_block_counting() {
        let metrics = PiiMetrics::new();
        let findings = vec![
            Finding { start: 0, end: 5, category: "ssn".to_string(), confidence: 1.0 },
        ];
        metrics.record(&findings, &FilterAction::Block);
        let snap = metrics.snapshot();
        assert_eq!(snap.pii_blocked, 1);
        assert_eq!(snap.pii_redacted, 0);
    }

    #[test]
    fn pii_metrics_reset() {
        let metrics = PiiMetrics::new();
        let findings = vec![
            Finding { start: 0, end: 5, category: "email".to_string(), confidence: 1.0 },
        ];
        metrics.record(&findings, &FilterAction::Redact);
        assert_eq!(metrics.snapshot().total_scans, 1);
        metrics.reset();
        let snap = metrics.snapshot();
        assert_eq!(snap.total_scans, 0);
        assert_eq!(snap.pii_detected, 0);
        assert!(snap.by_category.is_empty());
    }

    #[test]
    fn pii_metrics_no_pii_findings() {
        let metrics = PiiMetrics::new();
        let findings = vec![
            Finding { start: 0, end: 5, category: "aws-key".to_string(), confidence: 1.0 },
        ];
        metrics.record(&findings, &FilterAction::Redact);
        let snap = metrics.snapshot();
        assert_eq!(snap.total_scans, 1);
        assert_eq!(snap.pii_detected, 0);
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
