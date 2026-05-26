//! Statistical guardrails for detecting anomalous agent behavior.
//!
//! Two complementary drift detection mechanisms:
//!
//! - **Cosine similarity z-score**: Tracks embedding vectors of agent
//!   outputs over a sliding window. Flags when a new output's cosine
//!   similarity to the running mean drops below a configurable z-score
//!   threshold.
//!
//! - **Shannon entropy monitor**: Tracks the distribution of tool calls.
//!   Flags when entropy drops (agent fixates on one tool) or spikes
//!   (agent scatters across too many tools).
//!
//! The `StatisticalGuardrailHook` wires both detectors into the hook
//! pipeline as a post-hook on tool call results.

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use smgglrs_protocol::CallToolResult;

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Cosine drift detection
// ---------------------------------------------------------------------------

/// Result of observing a new embedding vector.
#[derive(Debug, Clone)]
pub enum DriftResult {
    /// The observation is within normal bounds.
    Normal { z_score: f64 },
    /// The observation deviates beyond the configured threshold.
    Anomalous { z_score: f64, threshold: f64 },
    /// Not enough data to compute statistics yet.
    InsufficientData,
}

/// Tracks cosine similarity of embedding vectors over a sliding window.
///
/// Maintains a rolling mean of cosine similarities. When a new vector's
/// cosine similarity to the centroid drops below a z-score threshold
/// relative to the observed distribution, it flags the observation as
/// anomalous.
pub struct CosineDriftDetector {
    window_size: usize,
    z_threshold: f64,
    /// Recent embedding vectors (sliding window).
    history: VecDeque<Vec<f32>>,
    /// Running cosine similarities for variance computation.
    similarities: VecDeque<f64>,
}

impl CosineDriftDetector {
    /// Create a new detector.
    ///
    /// - `window_size`: number of vectors to keep in the sliding window
    /// - `z_threshold`: z-score threshold for anomaly detection (e.g. 3.0)
    pub fn new(window_size: usize, z_threshold: f64) -> Self {
        Self {
            window_size,
            z_threshold,
            history: VecDeque::with_capacity(window_size),
            similarities: VecDeque::with_capacity(window_size),
        }
    }

    /// Observe a new embedding vector and return a drift result.
    pub fn observe(&mut self, embedding: &[f32]) -> DriftResult {
        if embedding.is_empty() {
            return DriftResult::InsufficientData;
        }

        // Need at least 2 prior observations to compute meaningful stats
        if self.history.len() < 2 {
            self.push_embedding(embedding);
            return DriftResult::InsufficientData;
        }

        // Compute centroid of current history
        let centroid = self.centroid();

        // Cosine similarity between new vector and centroid
        let sim = cosine_similarity(embedding, &centroid);

        // Compute mean and stddev of prior similarities
        let (mean, stddev) = self.similarity_stats();

        // Push into history after computing stats (so current observation
        // doesn't influence its own z-score)
        self.push_embedding(embedding);
        self.push_similarity(sim);

        if stddev < 1e-10 {
            // All prior similarities are essentially identical — any
            // deviation is suspicious, but we can't compute a meaningful
            // z-score. Treat as normal unless similarity is very low.
            if sim < mean - 0.1 {
                return DriftResult::Anomalous {
                    z_score: f64::INFINITY,
                    threshold: self.z_threshold,
                };
            }
            return DriftResult::Normal { z_score: 0.0 };
        }

        let z_score = (mean - sim) / stddev;

        if z_score > self.z_threshold {
            DriftResult::Anomalous {
                z_score,
                threshold: self.z_threshold,
            }
        } else {
            DriftResult::Normal { z_score }
        }
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.history.clear();
        self.similarities.clear();
    }

    fn push_embedding(&mut self, embedding: &[f32]) {
        if self.history.len() >= self.window_size {
            self.history.pop_front();
        }
        self.history.push_back(embedding.to_vec());
    }

    fn push_similarity(&mut self, sim: f64) {
        if self.similarities.len() >= self.window_size {
            self.similarities.pop_front();
        }
        self.similarities.push_back(sim);
    }

    /// Compute the centroid (element-wise mean) of all vectors in history.
    fn centroid(&self) -> Vec<f32> {
        let n = self.history.len();
        if n == 0 {
            return Vec::new();
        }
        let dim = self.history[0].len();
        let mut mean = vec![0.0f32; dim];
        for v in &self.history {
            for (i, &val) in v.iter().enumerate() {
                if i < dim {
                    mean[i] += val;
                }
            }
        }
        let n_f = n as f32;
        for val in &mut mean {
            *val /= n_f;
        }
        mean
    }

    /// Mean and standard deviation of recorded similarities.
    fn similarity_stats(&self) -> (f64, f64) {
        let n = self.similarities.len();
        if n == 0 {
            return (0.0, 0.0);
        }
        let mean: f64 = self.similarities.iter().sum::<f64>() / n as f64;
        let variance: f64 = self
            .similarities
            .iter()
            .map(|s| (s - mean).powi(2))
            .sum::<f64>()
            / n as f64;
        (mean, variance.sqrt())
    }
}

/// Cosine similarity between two vectors. Returns 0.0 if either has zero norm.
pub(crate) fn cosine_similarity(a: &[f32], b: &[f32]) -> f64 {
    let len = a.len().min(b.len());
    let mut dot = 0.0f64;
    let mut norm_a = 0.0f64;
    let mut norm_b = 0.0f64;
    for i in 0..len {
        let ai = a[i] as f64;
        let bi = b[i] as f64;
        dot += ai * bi;
        norm_a += ai * ai;
        norm_b += bi * bi;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom < 1e-12 {
        0.0
    } else {
        dot / denom
    }
}

// ---------------------------------------------------------------------------
// Shannon entropy monitor
// ---------------------------------------------------------------------------

/// Result of recording a tool call for entropy analysis.
#[derive(Debug, Clone)]
pub enum EntropyResult {
    /// Entropy is within the configured bounds.
    Normal { entropy: f64 },
    /// Entropy is below the minimum (agent fixating on one tool).
    TooLow { entropy: f64, min: f64 },
    /// Entropy is above the maximum (agent scattering too widely).
    TooHigh { entropy: f64, max: f64 },
    /// Not enough data to compute entropy.
    InsufficientData,
}

/// Tracks the Shannon entropy of tool call distributions over a sliding
/// window of observation snapshots.
///
/// Each snapshot records a single tool call. When the window is full,
/// the oldest snapshot is dropped. Entropy is computed over the aggregate
/// counts in the current window.
pub struct EntropyMonitor {
    window_size: usize,
    min_entropy: f64,
    max_entropy: f64,
    /// Sliding window of per-snapshot tool counts.
    tool_counts: VecDeque<HashMap<String, usize>>,
}

impl EntropyMonitor {
    /// Create a new entropy monitor.
    ///
    /// - `window_size`: number of tool call snapshots to keep
    /// - `min_entropy`: flag if entropy drops below this (fixation)
    /// - `max_entropy`: flag if entropy rises above this (scatter)
    pub fn new(window_size: usize, min_entropy: f64, max_entropy: f64) -> Self {
        Self {
            window_size,
            min_entropy,
            max_entropy,
            tool_counts: VecDeque::with_capacity(window_size),
        }
    }

    /// Record a tool call and return the current entropy assessment.
    pub fn record_tool_call(&mut self, tool_name: &str) -> EntropyResult {
        // Each call is recorded as its own snapshot (one tool, count 1)
        let mut snapshot = HashMap::new();
        snapshot.insert(tool_name.to_string(), 1usize);

        if self.tool_counts.len() >= self.window_size {
            self.tool_counts.pop_front();
        }
        self.tool_counts.push_back(snapshot);

        // Need at least 2 observations to compute meaningful entropy
        if self.tool_counts.len() < 2 {
            return EntropyResult::InsufficientData;
        }

        let entropy = self.current_entropy();

        if entropy < self.min_entropy {
            EntropyResult::TooLow {
                entropy,
                min: self.min_entropy,
            }
        } else if entropy > self.max_entropy {
            EntropyResult::TooHigh {
                entropy,
                max: self.max_entropy,
            }
        } else {
            EntropyResult::Normal { entropy }
        }
    }

    /// Compute Shannon entropy over the aggregate tool counts in the window.
    pub fn current_entropy(&self) -> f64 {
        let mut aggregate: HashMap<&str, usize> = HashMap::new();
        let mut total = 0usize;

        for snapshot in &self.tool_counts {
            for (tool, count) in snapshot {
                *aggregate.entry(tool.as_str()).or_insert(0) += count;
                total += count;
            }
        }

        if total == 0 {
            return 0.0;
        }

        let total_f = total as f64;
        let mut entropy = 0.0f64;
        for &count in aggregate.values() {
            if count > 0 {
                let p = count as f64 / total_f;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.tool_counts.clear();
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the statistical guardrail system.
#[derive(Debug, Clone)]
pub struct StatisticalConfig {
    /// Whether the guardrail is enabled.
    pub enabled: bool,
    /// Sliding window size for cosine drift detection.
    pub cosine_window: usize,
    /// Z-score threshold for cosine drift anomaly detection.
    pub cosine_z_threshold: f64,
    /// Sliding window size for entropy monitoring.
    pub entropy_window: usize,
    /// Minimum acceptable entropy (below = fixation).
    pub entropy_min: f64,
    /// Maximum acceptable entropy (above = scatter).
    pub entropy_max: f64,
    /// Whether to block tool calls when anomalies are detected.
    /// Default: false (monitor/warn only).
    pub block_on_anomaly: bool,
}

impl Default for StatisticalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cosine_window: 50,
            cosine_z_threshold: 3.0,
            entropy_window: 20,
            entropy_min: 0.5,
            entropy_max: 4.0,
            block_on_anomaly: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Hook implementation
// ---------------------------------------------------------------------------

/// A post-hook that monitors agent behavior for statistical anomalies.
///
/// Tracks tool call distributions (entropy) and optionally embedding
/// drift (cosine similarity). Logs warnings when anomalies are detected
/// and can optionally block tool calls that exceed hard thresholds.
pub struct StatisticalGuardrailHook {
    config: StatisticalConfig,
    /// Per-session entropy monitors, keyed by session ID.
    entropy_monitors: Mutex<HashMap<String, EntropyMonitor>>,
    /// Per-session cosine drift detectors, keyed by session ID.
    drift_detectors: Mutex<HashMap<String, CosineDriftDetector>>,
}

impl StatisticalGuardrailHook {
    /// Create a new statistical guardrail hook with the given config.
    pub fn new(config: StatisticalConfig) -> Self {
        Self {
            config,
            entropy_monitors: Mutex::new(HashMap::new()),
            drift_detectors: Mutex::new(HashMap::new()),
        }
    }

    /// Create a hook with default configuration.
    pub fn default_config() -> Self {
        Self::new(StatisticalConfig::default())
    }

    /// Build a simple bag-of-words vector from text.
    ///
    /// Uses a deterministic hash to map words to fixed-size buckets.
    /// This is a lightweight proxy for real embeddings — in production,
    /// the embedding model would provide these vectors.
    fn text_to_embedding(text: &str, dim: usize) -> Vec<f32> {
        let mut vec = vec![0.0f32; dim];
        for word in text.split_whitespace() {
            let word_lower = word.to_lowercase();
            // Simple hash: sum of byte values mod dim
            let hash: usize = word_lower.bytes().map(|b| b as usize).sum::<usize>() % dim;
            vec[hash] += 1.0;
        }
        // L2-normalize
        let norm: f32 = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
        if norm > 1e-6 {
            for v in &mut vec {
                *v /= norm;
            }
        }
        vec
    }
}

#[async_trait::async_trait]
impl Hook for StatisticalGuardrailHook {
    fn name(&self) -> &str {
        "statistical-guardrail"
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        result: &CallToolResult,
        ctx: &CallContext,
    ) -> HookDecision {
        let session_id = &ctx.session_id;

        // --- Entropy monitoring ---
        let entropy_result = {
            let mut monitors = self.entropy_monitors.lock().unwrap();
            let monitor = monitors.entry(session_id.clone()).or_insert_with(|| {
                EntropyMonitor::new(
                    self.config.entropy_window,
                    self.config.entropy_min,
                    self.config.entropy_max,
                )
            });
            monitor.record_tool_call(tool_name)
        };

        match &entropy_result {
            EntropyResult::TooLow { entropy, min } => {
                tracing::warn!(
                    session = %session_id,
                    agent = %ctx.agent.name,
                    tool = %tool_name,
                    entropy = %entropy,
                    min = %min,
                    "Statistical guardrail: tool call entropy too low (agent may be fixating)"
                );
                if self.config.block_on_anomaly {
                    return HookDecision::Block(format!(
                        "statistical guardrail: tool call entropy {entropy:.3} below minimum {min:.3} — \
                         agent appears to be fixating on a single tool"
                    ));
                }
            }
            EntropyResult::TooHigh { entropy, max } => {
                tracing::warn!(
                    session = %session_id,
                    agent = %ctx.agent.name,
                    tool = %tool_name,
                    entropy = %entropy,
                    max = %max,
                    "Statistical guardrail: tool call entropy too high (agent may be scattering)"
                );
                if self.config.block_on_anomaly {
                    return HookDecision::Block(format!(
                        "statistical guardrail: tool call entropy {entropy:.3} above maximum {max:.3} — \
                         agent appears to be scattering across too many tools"
                    ));
                }
            }
            _ => {}
        }

        // --- Cosine drift detection ---
        // Extract text from result for bag-of-words embedding
        let text: String = result
            .content
            .iter()
            .filter_map(|c| match c {
                smgglrs_protocol::Content::Text(t) => Some(t.text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(" ");

        if !text.is_empty() {
            let embedding = Self::text_to_embedding(&text, 128);
            let drift_result = {
                let mut detectors = self.drift_detectors.lock().unwrap();
                let detector = detectors.entry(session_id.clone()).or_insert_with(|| {
                    CosineDriftDetector::new(
                        self.config.cosine_window,
                        self.config.cosine_z_threshold,
                    )
                });
                detector.observe(&embedding)
            };

            if let DriftResult::Anomalous { z_score, threshold } = &drift_result {
                tracing::warn!(
                    session = %session_id,
                    agent = %ctx.agent.name,
                    tool = %tool_name,
                    z_score = %z_score,
                    threshold = %threshold,
                    "Statistical guardrail: cosine drift anomaly detected in tool output"
                );
                if self.config.block_on_anomaly {
                    return HookDecision::Block(format!(
                        "statistical guardrail: output drift z-score {z_score:.2} exceeds \
                         threshold {threshold:.1} — agent output deviates significantly from recent pattern"
                    ));
                }
            }
        }

        HookDecision::Continue
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AgentIdentity;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
    }

    // -- Cosine similarity tests --

    #[test]
    fn cosine_similarity_identical_vectors() {
        let a = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity(&a, &a);
        assert!(
            (sim - 1.0).abs() < 1e-6,
            "identical vectors should have similarity 1.0"
        );
    }

    #[test]
    fn cosine_similarity_orthogonal_vectors() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert!(
            sim.abs() < 1e-6,
            "orthogonal vectors should have similarity 0.0"
        );
    }

    #[test]
    fn cosine_similarity_opposite_vectors() {
        let a = vec![1.0, 2.0, 3.0];
        let b: Vec<f32> = a.iter().map(|x| -x).collect();
        let sim = cosine_similarity(&a, &b);
        assert!(
            (sim + 1.0).abs() < 1e-6,
            "opposite vectors should have similarity -1.0"
        );
    }

    #[test]
    fn cosine_similarity_zero_vector() {
        let a = vec![1.0, 2.0, 3.0];
        let zero = vec![0.0, 0.0, 0.0];
        let sim = cosine_similarity(&a, &zero);
        assert!(sim.abs() < 1e-6, "zero vector should give similarity 0.0");
    }

    // -- Cosine drift detector tests --

    #[test]
    fn drift_detector_insufficient_data() {
        let mut detector = CosineDriftDetector::new(10, 3.0);
        let v = vec![1.0, 0.0, 0.0];

        // First observation
        assert!(matches!(
            detector.observe(&v),
            DriftResult::InsufficientData
        ));
        // Second observation
        assert!(matches!(
            detector.observe(&v),
            DriftResult::InsufficientData
        ));
    }

    #[test]
    fn drift_detector_normal_with_similar_vectors() {
        let mut detector = CosineDriftDetector::new(10, 3.0);

        // Feed several similar vectors
        for i in 0..5 {
            let v = vec![1.0, 0.1 * i as f32, 0.0];
            detector.observe(&v);
        }

        // A similar vector should be normal
        let similar = vec![1.0, 0.15, 0.0];
        match detector.observe(&similar) {
            DriftResult::Normal { z_score } => {
                assert!(
                    z_score < 3.0,
                    "similar vector should have low z-score, got {z_score}"
                );
            }
            other => panic!("Expected Normal, got {other:?}"),
        }
    }

    #[test]
    fn drift_detector_anomalous_with_divergent_vector() {
        let mut detector = CosineDriftDetector::new(10, 2.0);

        // Build a history of vectors pointing in roughly the same direction
        for _ in 0..8 {
            let v = vec![1.0, 0.0, 0.0, 0.0];
            detector.observe(&v);
        }

        // Inject a completely different vector
        let anomalous = vec![0.0, 0.0, 0.0, 1.0];
        match detector.observe(&anomalous) {
            DriftResult::Anomalous { z_score, threshold } => {
                assert!(
                    z_score > threshold,
                    "anomalous vector should exceed threshold"
                );
            }
            DriftResult::Normal { z_score } => {
                panic!("Expected Anomalous for orthogonal vector, got Normal(z={z_score})");
            }
            DriftResult::InsufficientData => {
                panic!("Expected Anomalous, got InsufficientData");
            }
        }
    }

    #[test]
    fn drift_detector_reset_clears_state() {
        let mut detector = CosineDriftDetector::new(10, 3.0);
        for _ in 0..5 {
            detector.observe(&[1.0, 0.0, 0.0]);
        }
        detector.reset();
        assert!(matches!(
            detector.observe(&[1.0, 0.0, 0.0]),
            DriftResult::InsufficientData
        ));
    }

    #[test]
    fn drift_detector_empty_embedding() {
        let mut detector = CosineDriftDetector::new(10, 3.0);
        assert!(matches!(
            detector.observe(&[]),
            DriftResult::InsufficientData
        ));
    }

    #[test]
    fn drift_detector_window_eviction() {
        let mut detector = CosineDriftDetector::new(3, 3.0);

        // Fill the window
        for _ in 0..5 {
            detector.observe(&[1.0, 0.0, 0.0]);
        }

        // History should be capped at window_size
        assert!(detector.history.len() <= 3);
        assert!(detector.similarities.len() <= 3);
    }

    // -- Shannon entropy tests --

    #[test]
    fn entropy_single_tool_is_zero() {
        let mut monitor = EntropyMonitor::new(20, 0.5, 4.0);

        // First call: insufficient data
        assert!(matches!(
            monitor.record_tool_call("file_read"),
            EntropyResult::InsufficientData
        ));

        // All subsequent calls to same tool -> entropy = 0
        for _ in 0..5 {
            match monitor.record_tool_call("file_read") {
                EntropyResult::TooLow { entropy, .. } => {
                    assert!(
                        entropy.abs() < 1e-6,
                        "single tool should have entropy ~0, got {entropy}"
                    );
                }
                other => panic!("Expected TooLow for single tool, got {other:?}"),
            }
        }
    }

    #[test]
    fn entropy_uniform_distribution() {
        let mut monitor = EntropyMonitor::new(100, 0.5, 4.0);
        let tools = ["file_read", "file_write", "git_status", "git_diff"];

        // Record 5 rounds of each tool (uniform distribution)
        for _ in 0..5 {
            for tool in &tools {
                monitor.record_tool_call(tool);
            }
        }

        // Shannon entropy of uniform distribution over 4 items = log2(4) = 2.0
        let entropy = monitor.current_entropy();
        assert!(
            (entropy - 2.0).abs() < 0.01,
            "uniform 4-tool distribution should have entropy ~2.0, got {entropy}"
        );
    }

    #[test]
    fn entropy_known_distribution() {
        let mut monitor = EntropyMonitor::new(100, 0.0, 10.0);

        // 3 calls to A, 1 call to B -> probabilities 0.75, 0.25
        // H = -0.75*log2(0.75) - 0.25*log2(0.25) = 0.8113
        for _ in 0..3 {
            monitor.record_tool_call("A");
        }
        monitor.record_tool_call("B");

        let entropy = monitor.current_entropy();
        let expected = -0.75_f64 * 0.75_f64.log2() - 0.25_f64 * 0.25_f64.log2();
        assert!(
            (entropy - expected).abs() < 0.01,
            "expected entropy ~{expected:.4}, got {entropy:.4}"
        );
    }

    #[test]
    fn entropy_monitor_too_low() {
        let mut monitor = EntropyMonitor::new(20, 0.5, 4.0);

        // All same tool -> entropy = 0, should be TooLow
        monitor.record_tool_call("file_read");
        match monitor.record_tool_call("file_read") {
            EntropyResult::TooLow { entropy, min } => {
                assert!(entropy < min);
            }
            other => panic!("Expected TooLow, got {other:?}"),
        }
    }

    #[test]
    fn entropy_monitor_too_high() {
        // Set a very low max_entropy so normal usage triggers it
        let mut monitor = EntropyMonitor::new(100, 0.0, 0.5);

        let tools = ["a", "b", "c", "d", "e", "f", "g", "h"];
        for tool in &tools {
            monitor.record_tool_call(tool);
        }

        // Entropy of uniform 8 tools = log2(8) = 3.0, way above 0.5
        match monitor.record_tool_call("i") {
            EntropyResult::TooHigh { entropy, max } => {
                assert!(entropy > max);
            }
            other => panic!("Expected TooHigh, got {other:?}"),
        }
    }

    #[test]
    fn entropy_monitor_normal() {
        let mut monitor = EntropyMonitor::new(20, 0.0, 4.0);

        // Mix of 3 tools should give entropy between 0 and 4
        monitor.record_tool_call("file_read");
        monitor.record_tool_call("file_write");
        match monitor.record_tool_call("git_status") {
            EntropyResult::Normal { entropy } => {
                assert!(entropy > 0.0);
                assert!(entropy <= 4.0);
            }
            other => panic!("Expected Normal, got {other:?}"),
        }
    }

    #[test]
    fn entropy_monitor_window_eviction() {
        let mut monitor = EntropyMonitor::new(3, 0.0, 4.0);

        // Fill window with mixed tools
        monitor.record_tool_call("a");
        monitor.record_tool_call("b");
        monitor.record_tool_call("c");

        // Push more — window should evict oldest
        monitor.record_tool_call("a");

        assert!(monitor.tool_counts.len() <= 3);
    }

    #[test]
    fn entropy_monitor_reset() {
        let mut monitor = EntropyMonitor::new(20, 0.5, 4.0);
        for _ in 0..5 {
            monitor.record_tool_call("file_read");
        }
        monitor.reset();
        assert!(matches!(
            monitor.record_tool_call("file_read"),
            EntropyResult::InsufficientData
        ));
    }

    // -- Bag-of-words embedding tests --

    #[test]
    fn text_to_embedding_normalized() {
        let emb = StatisticalGuardrailHook::text_to_embedding("hello world test", 64);
        assert_eq!(emb.len(), 64);
        let norm: f32 = emb.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-4,
            "embedding should be L2-normalized, got norm {norm}"
        );
    }

    #[test]
    fn text_to_embedding_empty_string() {
        let emb = StatisticalGuardrailHook::text_to_embedding("", 64);
        assert_eq!(emb.len(), 64);
        // All zeros since no words
        assert!(emb.iter().all(|&v| v == 0.0));
    }

    #[test]
    fn text_to_embedding_deterministic() {
        let a = StatisticalGuardrailHook::text_to_embedding("hello world", 64);
        let b = StatisticalGuardrailHook::text_to_embedding("hello world", 64);
        assert_eq!(a, b, "same text should produce same embedding");
    }

    #[test]
    fn text_to_embedding_different_texts_differ() {
        let a = StatisticalGuardrailHook::text_to_embedding("hello world", 128);
        let b =
            StatisticalGuardrailHook::text_to_embedding("completely different content here", 128);
        let sim = cosine_similarity(&a, &b);
        assert!(
            sim < 0.99,
            "different texts should produce different embeddings, sim={sim}"
        );
    }

    // -- Hook integration tests --

    #[tokio::test]
    async fn hook_continues_on_normal_behavior() {
        let hook = StatisticalGuardrailHook::new(StatisticalConfig {
            entropy_window: 20,
            entropy_min: 0.0,
            entropy_max: 10.0,
            cosine_window: 50,
            cosine_z_threshold: 3.0,
            block_on_anomaly: false,
            ..Default::default()
        });

        let result = CallToolResult::text("some output text");
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn hook_warns_but_continues_when_not_blocking() {
        let hook = StatisticalGuardrailHook::new(StatisticalConfig {
            entropy_window: 5,
            entropy_min: 0.5,
            entropy_max: 4.0,
            cosine_window: 50,
            cosine_z_threshold: 3.0,
            block_on_anomaly: false,
            ..Default::default()
        });

        let result = CallToolResult::text("repeated output");
        let ctx = test_ctx();

        // Hammer the same tool to trigger low entropy
        for _ in 0..10 {
            let decision = hook
                .post_tool_use("file_read", &serde_json::json!({}), &result, &ctx)
                .await;
            // Should always continue since block_on_anomaly is false
            assert!(matches!(decision, HookDecision::Continue));
        }
    }

    #[tokio::test]
    async fn hook_blocks_on_low_entropy_when_configured() {
        let hook = StatisticalGuardrailHook::new(StatisticalConfig {
            entropy_window: 5,
            entropy_min: 0.5,
            entropy_max: 4.0,
            cosine_window: 50,
            cosine_z_threshold: 3.0,
            block_on_anomaly: true,
            ..Default::default()
        });

        let result = CallToolResult::text("output");
        let ctx = test_ctx();

        // First call: insufficient data -> continue
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Continue));

        // Repeated same tool -> entropy drops to 0
        for _ in 0..5 {
            hook.post_tool_use("file_read", &serde_json::json!({}), &result, &ctx)
                .await;
        }

        // Should block now
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &ctx)
            .await;
        match decision {
            HookDecision::Block(reason) => {
                assert!(
                    reason.contains("entropy"),
                    "block reason should mention entropy: {reason}"
                );
            }
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hook_tracks_sessions_independently() {
        let hook = StatisticalGuardrailHook::new(StatisticalConfig {
            entropy_window: 5,
            entropy_min: 0.5,
            entropy_max: 4.0,
            block_on_anomaly: true,
            ..Default::default()
        });

        let result = CallToolResult::text("output");

        let ctx1 = CallContext::new(AgentIdentity::new("agent1", "dev"), "session-1");
        let ctx2 = CallContext::new(AgentIdentity::new("agent2", "dev"), "session-2");

        // Hammer session 1 with same tool
        for _ in 0..8 {
            hook.post_tool_use("file_read", &serde_json::json!({}), &result, &ctx1)
                .await;
        }

        // Session 2 should still be fine
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &ctx2)
            .await;
        assert!(
            matches!(decision, HookDecision::Continue),
            "separate session should not be affected"
        );
    }

    #[tokio::test]
    async fn hook_name_is_correct() {
        let hook = StatisticalGuardrailHook::default_config();
        assert_eq!(hook.name(), "statistical-guardrail");
    }
}
