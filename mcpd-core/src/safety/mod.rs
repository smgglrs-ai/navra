mod regex;

pub use self::regex::{CustomFilter, PiiFilter, SecretFilter};

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

/// Trait for content safety filters.
///
/// Filters scan text content and return findings (spans of sensitive
/// content with categories and confidence scores).
pub trait ContentFilter: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn scan(&self, content: &str, ctx: &FilterContext) -> Vec<Finding>;
}

/// Pipeline that runs multiple filters and applies a configured action.
pub struct FilterPipeline {
    filters: Vec<Box<dyn ContentFilter>>,
    action: FilterAction,
}

impl FilterPipeline {
    pub fn new(action: FilterAction) -> Self {
        Self {
            filters: Vec::new(),
            action,
        }
    }

    pub fn add_filter(&mut self, filter: impl ContentFilter) {
        self.filters.push(Box::new(filter));
    }

    /// Scan content through all filters and apply the configured action.
    ///
    /// Returns `Ok(content)` (possibly redacted) or `Err(reason)` if blocked.
    pub fn process(&self, content: &str, ctx: &FilterContext) -> Result<String, String> {
        if self.action == FilterAction::Pass || self.filters.is_empty() {
            return Ok(content.to_string());
        }

        // Collect all findings from all filters
        let mut findings: Vec<Finding> = Vec::new();
        for filter in &self.filters {
            findings.extend(filter.scan(content, ctx));
        }

        if findings.is_empty() {
            return Ok(content.to_string());
        }

        match &self.action {
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
            FilterAction::Redact => Ok(redact(content, &mut findings)),
        }
    }

    pub fn has_filters(&self) -> bool {
        !self.filters.is_empty()
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
/// - `"none"` — no filters
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
}
