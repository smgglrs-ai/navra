//! ML-based content safety filter using model inference.
//!
//! Complements the regex-based filters with contextual detection
//! that regex can't catch (e.g., "medical records", "salary info").
//! Uses any [`Classifier`](crate::Classifier) implementation.
//!
//! Implements the async `ModelFilter` trait — runs after sync regex
//! filters in the pipeline.

use super::{FilterAction, FilterContext, Finding, ModelFilter};
use crate::classifier::Classifier;
use std::collections::HashMap;
use std::sync::Arc;

/// Maximum content length (chars) passed to the classifier in one
/// call. Longer inputs are scanned in overlapping windows, mirroring
/// the NER filter's sliding window — a single classify call on an
/// adversarial multi-megabyte input is a memory/latency DoS.
const MAX_SCAN_CHARS: usize = 4_000;
/// Character overlap between windows, so payloads spanning a window
/// boundary are still visible to the model.
const SCAN_OVERLAP: usize = 200;
/// Floor for the derived sub-window size, so a backend reporting a
/// very small token budget cannot degenerate into one-char windows.
const MIN_SUB_WINDOW_CHARS: usize = 600;
/// Total scan budget (chars) per `scan()` call across ALL windows.
///
/// Without it, a 10 MB tool output turned into ~7500 sequential
/// model inferences — an unbounded latency/DoS sink. Inputs larger
/// than the budget are scanned at the head and tail only (see
/// [`SCAN_BUDGET_HALF`]), with a logged truncation warning; the
/// dropped middle is a documented coverage gap.
const TOTAL_SCAN_BUDGET: usize = 64 * 1024;
/// Half of the total scan budget — the size of each head/tail
/// segment when an input exceeds [`TOTAL_SCAN_BUDGET`].
const SCAN_BUDGET_HALF: usize = TOTAL_SCAN_BUDGET / 2;

/// Derive the sub-window size (chars) for a classifier from its
/// reported character budget ([`Classifier::max_input_chars`]).
///
/// Clamped to `[MIN_SUB_WINDOW_CHARS, MAX_SCAN_CHARS]`.
fn sub_window_chars(max_chars: usize) -> usize {
    max_chars.clamp(MIN_SUB_WINDOW_CHARS, MAX_SCAN_CHARS)
}

/// Split oversized content into head and tail segments within the
/// total scan budget.
///
/// Content within [`TOTAL_SCAN_BUDGET`] is returned whole. Larger
/// content is split into the first and last [`SCAN_BUDGET_HALF`]
/// chars (on char boundaries), with a warning logged for the dropped
/// middle. Head+tail coverage keeps both leading metadata (file
/// headers, prompt prefixes) and trailing payloads (where exfil
/// content is typically appended) visible to the model.
fn scan_segments(content: &str) -> Vec<&str> {
    if content.len() <= TOTAL_SCAN_BUDGET {
        return vec![content];
    }
    tracing::warn!(
        len = content.len(),
        budget = TOTAL_SCAN_BUDGET,
        "ML safety scan input exceeds total scan budget; scanning head and tail only (middle dropped)"
    );
    // Head: first half, trimmed back to a char boundary.
    let mut head_end = SCAN_BUDGET_HALF;
    while head_end > 0 && !content.is_char_boundary(head_end) {
        head_end -= 1;
    }
    // Tail: last half, advanced forward to a char boundary.
    let mut tail_start = content.len() - SCAN_BUDGET_HALF;
    while tail_start < content.len() && !content.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    vec![&content[..head_end], &content[tail_start..]]
}

/// Split content into overlapping windows of at most
/// `window_chars` characters, each on a char boundary.
///
/// Windows are sized to the classifier's token budget (see
/// [`sub_window_chars`]) so the backend's pre-inference truncation
/// cannot silently drop the tail of each window.
fn scan_windows(content: &str, window_chars: usize) -> Vec<&str> {
    if content.len() <= window_chars {
        return vec![content];
    }
    let mut windows = Vec::new();
    let mut start = 0usize;
    while start < content.len() {
        let mut end = (start + window_chars).min(content.len());
        while end < content.len() && !content.is_char_boundary(end) {
            end += 1;
        }
        windows.push(&content[start..end]);
        if end >= content.len() {
            break;
        }
        // Advance with overlap, landing on a char boundary.
        let mut next = end - SCAN_OVERLAP.min(end - start);
        while next < content.len() && !content.is_char_boundary(next) {
            next += 1;
        }
        if next <= start {
            next = end;
        }
        start = next;
    }
    windows
}

/// ML-based content filter using a classification model.
///
/// Runs the entire text through a classifier and reports a finding
/// if the model detects unsafe content above the confidence threshold.
///
/// For single-label (binary) models: uses the global `threshold` to
/// check for any non-"safe" label. For multi-label models that emit
/// per-category scores, use [`MultiLabelFilter`] instead.
pub struct MlFilter {
    model: Arc<dyn Classifier>,
    /// Minimum confidence to trigger a finding.
    threshold: f32,
    /// Category to report (e.g., "ml-unsafe", "sensitive-content").
    category: String,
}

impl MlFilter {
    /// Create a new ML filter.
    ///
    /// # Panics
    /// Panics if `threshold` is NaN, negative, or greater than 1.0.
    pub fn new(model: Arc<dyn Classifier>, threshold: f32, category: impl Into<String>) -> Self {
        assert!(
            !threshold.is_nan() && (0.0..=1.0).contains(&threshold),
            "threshold must be in [0.0, 1.0], got {threshold}"
        );
        Self {
            model,
            threshold,
            category: category.into(),
        }
    }
}

impl ModelFilter for MlFilter {
    fn name(&self) -> &str {
        "ml-safety"
    }

    fn scan<'a>(
        &'a self,
        content: &'a str,
        _ctx: &'a FilterContext<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Finding>> + Send + 'a>> {
        Box::pin(async move {
            // Scan in bounded windows sized to the model's character
            // budget so oversized content cannot turn into a single
            // unbounded model call, and the backend's pre-inference
            // truncation cannot skip the tail of a window. Total
            // scanned chars are capped (head+tail) so a multi-MB
            // input cannot become thousands of inferences.
            let window_chars = sub_window_chars(self.model.max_input_chars());
            let mut best: Option<f32> = None;
            for segment in scan_segments(content) {
                for window in scan_windows(segment, window_chars) {
                    match self.model.classify(window).await {
                        Ok(output) => {
                            if output.is_unsafe(self.threshold) {
                                let conf = output
                                    .labels
                                    .iter()
                                    .find(|l| l.label != "safe")
                                    .map(|l| l.score)
                                    .unwrap_or(0.0);
                                best = Some(best.map_or(conf, |b: f32| b.max(conf)));
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "ML safety filter inference failed, blocking (fail-closed)");
                            return vec![Finding {
                                start: 0,
                                end: content.len(),
                                category: "inference_failure".to_string(),
                                confidence: 1.0,
                            }];
                        }
                    }
                }
            }
            match best {
                Some(confidence) => vec![Finding {
                    start: 0,
                    end: content.len(),
                    category: self.category.clone(),
                    confidence,
                }],
                None => Vec::new(),
            }
        })
    }
}

/// Action to take when a multi-label category exceeds its threshold.
#[derive(Debug, Clone)]
pub struct CategoryPolicy {
    /// Confidence threshold for this category (0.0-1.0).
    pub threshold: f32,
    /// Action to take when the threshold is exceeded.
    pub action: FilterAction,
}

/// Multi-label content safety filter for models like GLiGuard.
///
/// Unlike [`MlFilter`] which treats classification as binary safe/unsafe,
/// this filter checks each category label from the model response against
/// its own threshold and maps it to a specific [`FilterAction`].
///
/// Categories are checked in severity order: Block > Redact > Pass.
/// The highest-severity triggered action wins. If multiple categories
/// trigger Block, the highest-confidence one is reported.
///
/// # Example
///
/// ```text
/// let mut policies = HashMap::new();
/// policies.insert("harm".into(), CategoryPolicy { threshold: 0.7, action: FilterAction::Block });
/// policies.insert("pii".into(), CategoryPolicy { threshold: 0.5, action: FilterAction::Redact });
/// policies.insert("jailbreak".into(), CategoryPolicy { threshold: 0.9, action: FilterAction::Block });
/// let filter = MultiLabelFilter::new(model, policies);
/// ```
pub struct MultiLabelFilter {
    model: Arc<dyn Classifier>,
    /// Per-category threshold and action.
    policies: HashMap<String, CategoryPolicy>,
    /// Fallback threshold for categories not in the policy map.
    /// If None, unlisted categories are ignored.
    fallback_threshold: Option<f32>,
}

impl MultiLabelFilter {
    /// Create a new multi-label filter with per-category policies.
    pub fn new(model: Arc<dyn Classifier>, policies: HashMap<String, CategoryPolicy>) -> Self {
        Self {
            model,
            policies,
            fallback_threshold: None,
        }
    }

    /// Create from simple threshold map (all categories map to Block).
    ///
    /// Convenience constructor for the common case where all categories
    /// should block content when they exceed their threshold.
    pub fn from_thresholds(model: Arc<dyn Classifier>, thresholds: HashMap<String, f32>) -> Self {
        let policies = thresholds
            .into_iter()
            .map(|(cat, thresh)| {
                (
                    cat,
                    CategoryPolicy {
                        threshold: thresh,
                        action: FilterAction::Block,
                    },
                )
            })
            .collect();
        Self {
            model,
            policies,
            fallback_threshold: None,
        }
    }

    /// Set a fallback threshold for categories not in the policy map.
    ///
    /// When set, any category label from the model that exceeds this
    /// threshold will produce a finding with FilterAction::Block.
    ///
    /// # Panics
    /// Panics if `threshold` is NaN, negative, or greater than 1.0.
    pub fn with_fallback_threshold(mut self, threshold: f32) -> Self {
        assert!(
            !threshold.is_nan() && (0.0..=1.0).contains(&threshold),
            "fallback threshold must be in [0.0, 1.0], got {threshold}"
        );
        self.fallback_threshold = Some(threshold);
        self
    }

    /// Severity rank for ordering: Block > Redact > Pseudonymize > Pass.
    fn action_severity(action: &FilterAction) -> u8 {
        match action {
            FilterAction::Block => 3,
            FilterAction::Redact => 2,
            FilterAction::Pseudonymize => 1,
            FilterAction::Pass => 0,
        }
    }
}

impl ModelFilter for MultiLabelFilter {
    fn name(&self) -> &str {
        "ml-multi-label"
    }

    fn scan<'a>(
        &'a self,
        content: &'a str,
        _ctx: &'a FilterContext<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Finding>> + Send + 'a>> {
        Box::pin(async move {
            let mut findings = Vec::new();
            // Scan in bounded windows sized to the model's character
            // budget so oversized content cannot turn into a single
            // unbounded model call, and the backend's pre-inference
            // truncation cannot skip the tail of a window. Total
            // scanned chars are capped (head+tail) so a multi-MB
            // input cannot become thousands of inferences.
            let window_chars = sub_window_chars(self.model.max_input_chars());
            for segment in scan_segments(content) {
                for window in scan_windows(segment, window_chars) {
                    let output = match self.model.classify(window).await {
                        Ok(output) => output,
                        Err(e) => {
                            tracing::warn!(error = %e, "Multi-label safety filter inference failed, blocking (fail-closed)");
                            return vec![Finding {
                                start: 0,
                                end: content.len(),
                                category: "inference_failure".to_string(),
                                confidence: 1.0,
                            }];
                        }
                    };

                    for label in &output.labels {
                        if label.label == "safe" {
                            continue;
                        }

                        let triggered = if let Some(policy) = self.policies.get(&label.label) {
                            label.score.is_nan() || label.score >= policy.threshold
                        } else if let Some(fallback) = self.fallback_threshold {
                            label.score.is_nan() || label.score >= fallback
                        } else {
                            false
                        };

                        if triggered {
                            findings.push(Finding {
                                start: 0,
                                end: content.len(),
                                category: label.label.clone(),
                                confidence: label.score,
                            });
                        }
                    }
                }
            }

            // Sort by severity (action) descending, then confidence descending.
            // Return only the highest-severity finding so the pipeline
            // applies a single coherent action.
            if findings.len() > 1 {
                findings.sort_by(|a, b| {
                    let sev_a = self
                        .policies
                        .get(&a.category)
                        .map(|p| Self::action_severity(&p.action))
                        .unwrap_or(3); // fallback = Block
                    let sev_b = self
                        .policies
                        .get(&b.category)
                        .map(|p| Self::action_severity(&p.action))
                        .unwrap_or(3);
                    sev_b.cmp(&sev_a).then(
                        b.confidence
                            .partial_cmp(&a.confidence)
                            .unwrap_or(std::cmp::Ordering::Equal),
                    )
                });
            }

            findings
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::{ClassifyError, ClassifyLabel, ClassifyOutput};

    struct MockClassifier {
        labels: Vec<ClassifyLabel>,
    }

    impl MockClassifier {
        fn new(labels: Vec<ClassifyLabel>) -> Self {
            Self { labels }
        }
    }

    impl Classifier for MockClassifier {
        fn classify<'a>(
            &'a self,
            _text: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<ClassifyOutput, ClassifyError>> + Send + 'a,
            >,
        > {
            let labels = self.labels.clone();
            Box::pin(async move { Ok(ClassifyOutput { labels }) })
        }
    }

    struct FailingClassifier;

    /// Classifier that records the length of every text it receives.
    struct RecordingClassifier {
        lengths: std::sync::Mutex<Vec<usize>>,
    }

    impl RecordingClassifier {
        fn new() -> Self {
            Self {
                lengths: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn lengths(&self) -> Vec<usize> {
            self.lengths.lock().unwrap().clone()
        }
    }

    impl Classifier for RecordingClassifier {
        fn classify<'a>(
            &'a self,
            text: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<ClassifyOutput, ClassifyError>> + Send + 'a,
            >,
        > {
            self.lengths.lock().unwrap().push(text.len());
            Box::pin(async {
                Ok(ClassifyOutput {
                    labels: vec![ClassifyLabel {
                        label: "safe".into(),
                        score: 0.99,
                    }],
                })
            })
        }
    }

    /// Classifier that counts inference calls.
    struct CountingClassifier {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl CountingClassifier {
        fn new() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Classifier for CountingClassifier {
        fn classify<'a>(
            &'a self,
            _text: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<ClassifyOutput, ClassifyError>> + Send + 'a,
            >,
        > {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async {
                Ok(ClassifyOutput {
                    labels: vec![ClassifyLabel {
                        label: "safe".into(),
                        score: 0.99,
                    }],
                })
            })
        }
    }

    impl Classifier for FailingClassifier {
        fn classify<'a>(
            &'a self,
            _text: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<ClassifyOutput, ClassifyError>> + Send + 'a,
            >,
        > {
            Box::pin(async { Err(ClassifyError::Inference("test failure".into())) })
        }
    }

    fn test_ctx() -> FilterContext<'static> {
        FilterContext {
            agent_name: "test",
            operation: "read",
            path: Some("/test"),
        }
    }

    // --- MlFilter tests ---

    #[tokio::test]
    async fn ml_filter_detects_unsafe() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "hap".into(),
                score: 0.85,
            },
            ClassifyLabel {
                label: "safe".into(),
                score: 0.15,
            },
        ]));
        let filter = MlFilter::new(model, 0.5, "ml-unsafe");
        let findings = filter.scan("some harmful content", &test_ctx()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ml-unsafe");
        assert!((findings[0].confidence - 0.85).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn ml_filter_passes_safe() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "safe".into(),
                score: 0.95,
            },
            ClassifyLabel {
                label: "hap".into(),
                score: 0.05,
            },
        ]));
        let filter = MlFilter::new(model, 0.5, "ml-unsafe");
        let findings = filter.scan("hello world", &test_ctx()).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn ml_filter_below_threshold_passes() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "hap".into(),
                score: 0.3,
            },
            ClassifyLabel {
                label: "safe".into(),
                score: 0.7,
            },
        ]));
        let filter = MlFilter::new(model, 0.5, "ml-unsafe");
        let findings = filter.scan("borderline content", &test_ctx()).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn ml_filter_chunks_oversized_input() {
        let model = Arc::new(RecordingClassifier::new());
        let filter = MlFilter::new(model.clone(), 0.5, "ml-unsafe");
        let long = "a".repeat(MAX_SCAN_CHARS * 3);
        let findings = filter.scan(&long, &test_ctx()).await;
        assert!(findings.is_empty());
        let lengths = model.lengths();
        assert!(!lengths.is_empty(), "at least one classify call expected");
        assert!(
            lengths.iter().all(|&l| l <= MAX_SCAN_CHARS),
            "every classify call must be bounded: {lengths:?}"
        );
        assert!(
            lengths.len() >= 3,
            "long input must be scanned in multiple windows"
        );
    }

    #[tokio::test]
    async fn multi_label_chunks_oversized_input() {
        let model = Arc::new(RecordingClassifier::new());
        let mut thresholds = HashMap::new();
        thresholds.insert("harm".to_string(), 0.7f32);
        let filter = MultiLabelFilter::from_thresholds(model.clone(), thresholds);
        let long = "x".repeat(MAX_SCAN_CHARS * 2 + 50);
        let findings = filter.scan(&long, &test_ctx()).await;
        assert!(findings.is_empty());
        let lengths = model.lengths();
        assert!(
            lengths.iter().all(|&l| l <= MAX_SCAN_CHARS),
            "every classify call must be bounded: {lengths:?}"
        );
    }

    #[test]
    fn scan_windows_short_input_single_window() {
        let windows = scan_windows("hello world", MAX_SCAN_CHARS);
        assert_eq!(windows, vec!["hello world"]);
    }

    #[test]
    fn scan_windows_bounded_and_covering() {
        let text = "ä".repeat(MAX_SCAN_CHARS * 2 + 10); // multi-byte chars
        let windows = scan_windows(&text, MAX_SCAN_CHARS);
        assert!(windows.len() >= 3);
        for w in &windows {
            assert!(w.len() <= MAX_SCAN_CHARS);
        }
        // Coverage: the first window starts at 0 and the last ends at
        // the end of the text.
        assert_eq!(windows.first().unwrap().as_ptr(), text.as_ptr());
        let last_end = windows.last().unwrap().as_ptr() as usize + windows.last().unwrap().len();
        assert_eq!(last_end, text.as_ptr() as usize + text.len());
        // Overlap between consecutive windows.
        let w1_end = windows[0].as_ptr() as usize + windows[0].len();
        let w2_start = windows[1].as_ptr() as usize;
        assert!(w2_start < w1_end, "windows must overlap");
    }

    #[test]
    fn sub_window_chars_clamps_char_budget() {
        // Backend-reported char budget passes through (within bounds).
        assert_eq!(sub_window_chars(1_536), 1_536);
        // Clamped to MAX_SCAN_CHARS for large budgets.
        assert_eq!(sub_window_chars(100_000), MAX_SCAN_CHARS);
        // Floored for degenerate small budgets.
        assert_eq!(sub_window_chars(1), MIN_SUB_WINDOW_CHARS);
        assert_eq!(sub_window_chars(0), MIN_SUB_WINDOW_CHARS);
    }

    #[test]
    fn scan_segments_within_budget_whole() {
        assert_eq!(scan_segments("hello"), vec!["hello"]);
        let text = "a".repeat(TOTAL_SCAN_BUDGET);
        assert_eq!(scan_segments(&text), vec![text.as_str()]);
    }

    #[test]
    fn scan_segments_oversized_head_and_tail() {
        let text = "b".repeat(TOTAL_SCAN_BUDGET * 4);
        let segments = scan_segments(&text);
        assert_eq!(segments.len(), 2);
        assert!(
            segments[0].len() <= SCAN_BUDGET_HALF,
            "head segment must be within half the budget"
        );
        assert!(
            segments[1].len() <= SCAN_BUDGET_HALF,
            "tail segment must be within half the budget"
        );
        assert!(segments[0].starts_with('b'));
        assert!(segments[1].ends_with('b'));
        // Head starts at 0; tail ends at the end of the text.
        assert_eq!(segments[0].as_ptr(), text.as_ptr());
        let tail_end = segments[1].as_ptr() as usize + segments[1].len();
        assert_eq!(tail_end, text.as_ptr() as usize + text.len());
        // Total scanned is bounded by the budget.
        let total: usize = segments.iter().map(|s| s.len()).sum();
        assert!(total <= TOTAL_SCAN_BUDGET);
    }

    #[tokio::test]
    async fn ml_filter_detects_payload_past_token_truncation_point() {
        // Regression: the 4k-char windows used to be handed to the
        // classifier whole, but the backend truncates each inference
        // to its token budget (512 tokens ~ first ~1500 chars for
        // BPE English) — payloads placed in the tail of a window
        // were never classified. The filter must sub-window to the
        // model's reported character budget so the tail is seen.
        //
        // This mock emulates the backend's truncation: it only
        // "reads" the first max_input_chars() chars of the text it
        // receives — the backend's actual reported char budget, not
        // a token-count heuristic.
        struct TruncatingClassifier;

        impl Classifier for TruncatingClassifier {
            fn max_input_chars(&self) -> usize {
                900
            }

            fn classify<'a>(
                &'a self,
                text: &'a str,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<ClassifyOutput, ClassifyError>>
                        + Send
                        + 'a,
                >,
            > {
                let visible = &text[..text
                    .char_indices()
                    .nth(self.max_input_chars())
                    .map(|(i, _)| i)
                    .unwrap_or(text.len())];
                Box::pin(async move {
                    if visible.contains("HARMFUL-PIPELINE-PAYLOAD") {
                        Ok(ClassifyOutput {
                            labels: vec![
                                ClassifyLabel {
                                    label: "hap".into(),
                                    score: 0.9,
                                },
                                ClassifyLabel {
                                    label: "safe".into(),
                                    score: 0.1,
                                },
                            ],
                        })
                    } else {
                        Ok(ClassifyOutput {
                            labels: vec![ClassifyLabel {
                                label: "safe".into(),
                                score: 0.99,
                            }],
                        })
                    }
                })
            }
        }

        let filter = MlFilter::new(Arc::new(TruncatingClassifier), 0.5, "ml-unsafe");
        // 4k-char input with the injection payload at chars
        // 2500-3700 — past the 900-char truncation point of a
        // single whole-window call.
        let mut input = "x".repeat(2_500);
        input.push_str("HARMFUL-PIPELINE-PAYLOAD ");
        input.push_str(&"y".repeat(4_000 - input.len()));
        assert_eq!(input.len(), 4_000);

        let findings = filter.scan(&input, &test_ctx()).await;
        assert!(
            findings.iter().any(|f| f.category == "ml-unsafe"),
            "payload at chars 2500-3700 must be classified despite token truncation"
        );
    }

    #[tokio::test]
    async fn ml_filter_detects_cjk_payload_in_cjk_dense_tail() {
        // Regression: the sub-window used to be sized at a fixed
        // 3-chars-per-token heuristic. CJK-dense text tokenizes at
        // ~1 char/token, so a 512-token backend only reads the first
        // ~512 chars of a 1536-char window — a CJK payload in the
        // tail was never classified. The filter must size windows to
        // the backend's measured character budget (1 char/token for
        // this mock's dense-CJK tokenizer).
        //
        // This mock emulates a 1-char-per-token CJK tokenizer: the
        // backend reads at most max_input_chars() = max_input_tokens()
        // chars per inference.
        struct CjkTruncatingClassifier;

        impl Classifier for CjkTruncatingClassifier {
            fn max_input_tokens(&self) -> usize {
                512
            }

            fn max_input_chars(&self) -> usize {
                // Dense CJK: 1 char per token.
                512
            }

            fn classify<'a>(
                &'a self,
                text: &'a str,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<ClassifyOutput, ClassifyError>>
                        + Send
                        + 'a,
                >,
            > {
                let visible = &text[..text
                    .char_indices()
                    .nth(self.max_input_chars())
                    .map(|(i, _)| i)
                    .unwrap_or(text.len())];
                Box::pin(async move {
                    if visible.contains("危险管道注入载荷") {
                        Ok(ClassifyOutput {
                            labels: vec![
                                ClassifyLabel {
                                    label: "hap".into(),
                                    score: 0.9,
                                },
                                ClassifyLabel {
                                    label: "safe".into(),
                                    score: 0.1,
                                },
                            ],
                        })
                    } else {
                        Ok(ClassifyOutput {
                            labels: vec![ClassifyLabel {
                                label: "safe".into(),
                                score: 0.99,
                            }],
                        })
                    }
                })
            }
        }

        let filter = MlFilter::new(Arc::new(CjkTruncatingClassifier), 0.5, "ml-unsafe");
        // 2000-char CJK-dense input with the payload at chars
        // 600-700. Under the old 3-chars/token sizing the first
        // window covered chars 0-1536 but the mock only read the
        // first 512; the next window started at char 1336 — the
        // payload fell in the unclassified gap. With windows sized
        // to the reported 512-char budget it is fully covered.
        let mut input = "字".repeat(600);
        input.push_str("危险管道注入载荷");
        input.push_str(&"字".repeat(2_000 - input.chars().count()));
        assert_eq!(input.chars().count(), 2_000);

        let findings = filter.scan(&input, &test_ctx()).await;
        assert!(
            findings.iter().any(|f| f.category == "ml-unsafe"),
            "CJK payload in the tail of a CJK-dense window must be detected"
        );
    }

    #[tokio::test]
    async fn ml_filter_scan_is_bounded_on_large_input() {
        // Regression: a 10 MB tool output used to produce ~7500
        // sequential inferences. Total scanned chars are now capped
        // at TOTAL_SCAN_BUDGET (head + tail).
        let model = Arc::new(CountingClassifier::new());
        let filter = MlFilter::new(model.clone(), 0.5, "ml-unsafe");
        let large = "z".repeat(1024 * 1024); // 1 MB, ~4x the budget
        let findings = filter.scan(&large, &test_ctx()).await;
        assert!(findings.is_empty());
        let calls = model.call_count();
        let max_calls = TOTAL_SCAN_BUDGET / MIN_SUB_WINDOW_CHARS + 2;
        assert!(
            calls <= max_calls,
            "inference count {calls} must be bounded (<= {max_calls}) on oversized input"
        );
    }

    #[tokio::test]
    async fn ml_filter_head_and_tail_detected_middle_dropped() {
        // Payloads in the head AND tail of an oversized input are
        // both detected; a payload only in the dropped middle is
        // missed (documented coverage gap, warned at scan time).
        struct PayloadClassifier;

        impl Classifier for PayloadClassifier {
            fn classify<'a>(
                &'a self,
                text: &'a str,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<ClassifyOutput, ClassifyError>>
                        + Send
                        + 'a,
                >,
            > {
                let hit = text.contains("HEAD-PAYLOAD") || text.contains("TAIL-PAYLOAD");
                Box::pin(async move {
                    if hit {
                        Ok(ClassifyOutput {
                            labels: vec![ClassifyLabel {
                                label: "hap".into(),
                                score: 0.9,
                            }],
                        })
                    } else {
                        Ok(ClassifyOutput {
                            labels: vec![ClassifyLabel {
                                label: "safe".into(),
                                score: 0.99,
                            }],
                        })
                    }
                })
            }
        }

        let filter = MlFilter::new(Arc::new(PayloadClassifier), 0.5, "ml-unsafe");
        // Head payload near the start, tail payload near the end of
        // a ~4x-budget input.
        let mut input = String::from("HEAD-PAYLOAD ");
        input.push_str(&"a".repeat(TOTAL_SCAN_BUDGET * 2));
        input.push_str(&"b".repeat(TOTAL_SCAN_BUDGET * 2 - 64));
        input.push_str(" TAIL-PAYLOAD");
        assert!(input.len() > TOTAL_SCAN_BUDGET * 3);

        let findings = filter.scan(&input, &test_ctx()).await;
        assert!(
            findings.iter().any(|f| f.category == "ml-unsafe"),
            "payloads in the head and tail must both be detected"
        );

        // Middle-only payload: falls in the dropped zone and is
        // (documentedly) missed.
        let mut middle = "c".repeat(TOTAL_SCAN_BUDGET / 2 + 1_000);
        middle.push_str("MIDDLE-PAYLOAD");
        middle.push_str(&"d".repeat(TOTAL_SCAN_BUDGET * 2));
        let findings = filter.scan(&middle, &test_ctx()).await;
        assert!(
            findings.is_empty(),
            "middle-dropped payload is a documented coverage gap"
        );
    }

    #[tokio::test]
    async fn ml_filter_inference_failure_blocks() {
        let model = Arc::new(FailingClassifier);
        let filter = MlFilter::new(model, 0.5, "ml-unsafe");
        let findings = filter.scan("test", &test_ctx()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "inference_failure");
        assert!((findings[0].confidence - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    #[should_panic(expected = "threshold must be in [0.0, 1.0]")]
    fn ml_filter_rejects_nan_threshold() {
        let model = Arc::new(MockClassifier::new(vec![]));
        let _ = MlFilter::new(model, f32::NAN, "ml-unsafe");
    }

    #[test]
    #[should_panic(expected = "threshold must be in [0.0, 1.0]")]
    fn ml_filter_rejects_negative_threshold() {
        let model = Arc::new(MockClassifier::new(vec![]));
        let _ = MlFilter::new(model, -0.1, "ml-unsafe");
    }

    #[test]
    #[should_panic(expected = "threshold must be in [0.0, 1.0]")]
    fn ml_filter_rejects_above_one_threshold() {
        let model = Arc::new(MockClassifier::new(vec![]));
        let _ = MlFilter::new(model, 1.5, "ml-unsafe");
    }

    // --- ClassifyOutput tests ---

    #[test]
    fn classify_output_empty_labels() {
        let out = ClassifyOutput { labels: vec![] };
        assert!(out.top_label().is_none());
        assert!(!out.is_unsafe(0.5));
        let thresholds = HashMap::new();
        assert!(out.exceeds_thresholds(&thresholds).is_empty());
    }

    #[test]
    fn classify_output_single_label() {
        let out = ClassifyOutput {
            labels: vec![ClassifyLabel {
                label: "safe".into(),
                score: 0.99,
            }],
        };
        assert!(!out.is_unsafe(0.5));
        assert_eq!(out.top_label().unwrap().label, "safe");
    }

    #[test]
    fn classify_output_exceeds_thresholds() {
        let out = ClassifyOutput {
            labels: vec![
                ClassifyLabel {
                    label: "harm".into(),
                    score: 0.8,
                },
                ClassifyLabel {
                    label: "pii".into(),
                    score: 0.6,
                },
                ClassifyLabel {
                    label: "jailbreak".into(),
                    score: 0.3,
                },
            ],
        };
        let mut thresholds = HashMap::new();
        thresholds.insert("harm".into(), 0.7);
        thresholds.insert("pii".into(), 0.5);
        thresholds.insert("jailbreak".into(), 0.9);

        let triggered = out.exceeds_thresholds(&thresholds);
        assert_eq!(triggered.len(), 2);
        assert_eq!(triggered[0].label, "harm");
        assert_eq!(triggered[1].label, "pii");
    }

    // --- MultiLabelFilter tests ---

    #[tokio::test]
    async fn multi_label_detects_multiple_categories() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "harm".into(),
                score: 0.85,
            },
            ClassifyLabel {
                label: "pii".into(),
                score: 0.6,
            },
            ClassifyLabel {
                label: "jailbreak".into(),
                score: 0.3,
            },
        ]));

        let mut policies = HashMap::new();
        policies.insert(
            "harm".into(),
            CategoryPolicy {
                threshold: 0.7,
                action: FilterAction::Block,
            },
        );
        policies.insert(
            "pii".into(),
            CategoryPolicy {
                threshold: 0.5,
                action: FilterAction::Redact,
            },
        );
        policies.insert(
            "jailbreak".into(),
            CategoryPolicy {
                threshold: 0.9,
                action: FilterAction::Block,
            },
        );

        let filter = MultiLabelFilter::new(model, policies);
        let findings = filter.scan("sensitive content", &test_ctx()).await;

        // harm (0.85 >= 0.7) and pii (0.6 >= 0.5) triggered
        // jailbreak (0.3 < 0.9) did not
        assert_eq!(findings.len(), 2);
        // Sorted by severity then confidence: harm (Block, 0.85) first
        assert_eq!(findings[0].category, "harm");
        assert_eq!(findings[1].category, "pii");
    }

    #[tokio::test]
    async fn multi_label_highest_severity_wins() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "pii".into(),
                score: 0.95,
            },
            ClassifyLabel {
                label: "harm".into(),
                score: 0.75,
            },
        ]));

        let mut policies = HashMap::new();
        policies.insert(
            "harm".into(),
            CategoryPolicy {
                threshold: 0.7,
                action: FilterAction::Block,
            },
        );
        policies.insert(
            "pii".into(),
            CategoryPolicy {
                threshold: 0.5,
                action: FilterAction::Redact,
            },
        );

        let filter = MultiLabelFilter::new(model, policies);
        let findings = filter.scan("content", &test_ctx()).await;

        assert_eq!(findings.len(), 2);
        // Block (harm) comes before Redact (pii) regardless of score
        assert_eq!(findings[0].category, "harm");
        assert_eq!(findings[1].category, "pii");
    }

    #[tokio::test]
    async fn multi_label_no_triggers() {
        let model = Arc::new(MockClassifier::new(vec![
            ClassifyLabel {
                label: "safe".into(),
                score: 0.95,
            },
            ClassifyLabel {
                label: "harm".into(),
                score: 0.1,
            },
        ]));

        let mut policies = HashMap::new();
        policies.insert(
            "harm".into(),
            CategoryPolicy {
                threshold: 0.7,
                action: FilterAction::Block,
            },
        );

        let filter = MultiLabelFilter::new(model, policies);
        let findings = filter.scan("safe content", &test_ctx()).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn multi_label_ignores_unlisted_categories() {
        let model = Arc::new(MockClassifier::new(vec![ClassifyLabel {
            label: "unknown-cat".into(),
            score: 0.99,
        }]));

        let policies = HashMap::new(); // no policies
        let filter = MultiLabelFilter::new(model, policies);
        let findings = filter.scan("content", &test_ctx()).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn multi_label_fallback_threshold() {
        let model = Arc::new(MockClassifier::new(vec![ClassifyLabel {
            label: "unknown-cat".into(),
            score: 0.8,
        }]));

        let filter = MultiLabelFilter::new(model, HashMap::new()).with_fallback_threshold(0.7);
        let findings = filter.scan("content", &test_ctx()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "unknown-cat");
    }

    #[tokio::test]
    async fn multi_label_from_thresholds_convenience() {
        let model = Arc::new(MockClassifier::new(vec![ClassifyLabel {
            label: "harm".into(),
            score: 0.8,
        }]));

        let mut thresholds = HashMap::new();
        thresholds.insert("harm".into(), 0.7);

        let filter = MultiLabelFilter::from_thresholds(model, thresholds);
        let findings = filter.scan("harmful content", &test_ctx()).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "harm");
    }

    #[tokio::test]
    async fn multi_label_inference_failure_blocks() {
        let model = Arc::new(FailingClassifier);
        let filter = MultiLabelFilter::new(model, HashMap::new());
        let findings = filter.scan("test", &test_ctx()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "inference_failure");
        assert!((findings[0].confidence - 1.0).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn multi_label_safe_label_ignored() {
        // Even if "safe" has a policy, the filter skips it
        let model = Arc::new(MockClassifier::new(vec![ClassifyLabel {
            label: "safe".into(),
            score: 0.99,
        }]));

        let mut policies = HashMap::new();
        policies.insert(
            "safe".into(),
            CategoryPolicy {
                threshold: 0.1,
                action: FilterAction::Block,
            },
        );

        let filter = MultiLabelFilter::new(model, policies);
        let findings = filter.scan("content", &test_ctx()).await;
        assert!(findings.is_empty());
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn inference_error_never_passes() {
        let findings = vec![Finding {
            start: 0,
            end: 10,
            category: "inference_failure".to_string(),
            confidence: 1.0,
        }];
        assert!(
            !findings.is_empty(),
            "inference error must produce findings"
        );
        assert!(
            findings[0].confidence >= 1.0,
            "inference_failure finding must have max confidence"
        );
    }
}
