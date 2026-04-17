pub mod ml;
mod regex;

pub use self::ml::MlFilter;
pub use self::regex::{CustomFilter, PiiFilter, SecretFilter};

use std::future::Future;
use std::pin::Pin;

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
    /// Block the entire response.
    Block,
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

/// Pipeline that runs multiple filters and applies a configured action.
///
/// Sync filters (regex) run first. If they don't block, async model
/// filters run next. Supports both outbound (tool responses) and
/// inbound (tool arguments on write-path operations) filtering.
pub struct FilterPipeline {
    filters: Vec<Box<dyn ContentFilter>>,
    model_filters: Vec<Box<dyn ModelFilter>>,
    action: FilterAction,
}

impl FilterPipeline {
    pub fn new(action: FilterAction) -> Self {
        Self {
            filters: Vec::new(),
            model_filters: Vec::new(),
            action,
        }
    }

    pub fn add_filter(&mut self, filter: impl ContentFilter) {
        self.filters.push(Box::new(filter));
    }

    pub fn add_model_filter(&mut self, filter: impl ModelFilter) {
        self.model_filters.push(Box::new(filter));
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

        if findings.is_empty() {
            return Ok(content.to_string());
        }

        apply_action(&self.action, content, &mut findings)
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

        // Phase 1: sync filters (regex) — sub-microsecond
        if include_sync {
            for filter in &self.filters {
                findings.extend(filter.scan(content, ctx));
            }

            // Short-circuit: if sync filters already blocked, skip model filters
            if !findings.is_empty() && self.action == FilterAction::Block {
                return apply_action(&self.action, content, &mut findings);
            }
        }

        // Phase 2: async model filters
        for model_filter in &self.model_filters {
            findings.extend(model_filter.scan(content, ctx).await);
        }

        if findings.is_empty() {
            return Ok(content.to_string());
        }

        apply_action(&self.action, content, &mut findings)
    }

    pub fn has_filters(&self) -> bool {
        !self.filters.is_empty() || !self.model_filters.is_empty()
    }

    fn no_filters(&self) -> bool {
        self.filters.is_empty() && self.model_filters.is_empty()
    }
}

/// Apply the filter action (block or redact) to content with findings.
fn apply_action(
    action: &FilterAction,
    content: &str,
    findings: &mut Vec<Finding>,
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

/// Build a filter pipeline from a safety profile name.
///
/// Profiles:
/// - `"standard"` — all regex filters, redact action
/// - `"secrets-only"` — secret filter only, redact action
/// - `"block"` — all regex filters, block action
/// - `"guardian"` — regex + ML safety (Guardian HAP 38M, in-process)
/// - `"guardian-deep"` — regex + ML safety (HAP 38M + Guardian 3.3 8B)
/// - `"none"` — no filters
///
/// The `"guardian"` and `"guardian-deep"` profiles create the regex
/// pipeline here. ML model filters are added by the server at startup
/// when models are loaded (via `pipeline.add_model_filter()`).
pub fn build_pipeline(profile: &str) -> FilterPipeline {
    match profile {
        "standard" => {
            let mut pipeline = FilterPipeline::new(FilterAction::Redact);
            pipeline.add_filter(SecretFilter::new());
            pipeline.add_filter(PiiFilter::new());
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
            pipeline
        }
        "guardian" | "guardian-deep" => {
            // Regex tier (same as standard). ML model filters are added
            // by the server when models are loaded.
            let mut pipeline = FilterPipeline::new(FilterAction::Redact);
            pipeline.add_filter(SecretFilter::new());
            pipeline.add_filter(PiiFilter::new());
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
}
