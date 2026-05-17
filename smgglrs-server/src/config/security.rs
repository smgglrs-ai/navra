use serde::Deserialize;

/// Server-side configuration for the statistical guardrail hook.
///
/// ```toml
/// [statistical]
/// enabled = true
/// cosine_window = 50
/// cosine_z_threshold = 3.0
/// entropy_window = 20
/// entropy_min = 0.5
/// entropy_max = 4.0
/// block_on_anomaly = false
/// ```
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct StatisticalGuardrailServerConfig {
    /// Whether statistical guardrails are enabled. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Sliding window size for cosine drift detection. Default: 50.
    #[serde(default = "default_cosine_window")]
    pub cosine_window: usize,
    /// Z-score threshold for cosine drift anomaly detection. Default: 3.0.
    #[serde(default = "default_cosine_z_threshold")]
    pub cosine_z_threshold: f64,
    /// Sliding window size for entropy monitoring. Default: 20.
    #[serde(default = "default_entropy_window")]
    pub entropy_window: usize,
    /// Minimum acceptable entropy (below = fixation). Default: 0.5.
    #[serde(default = "default_entropy_min")]
    pub entropy_min: f64,
    /// Maximum acceptable entropy (above = scatter). Default: 4.0.
    #[serde(default = "default_entropy_max")]
    pub entropy_max: f64,
    /// Whether to block tool calls when anomalies are detected.
    /// Default: false (monitor/warn only).
    #[serde(default)]
    pub block_on_anomaly: bool,
}

fn default_cosine_window() -> usize {
    50
}

fn default_cosine_z_threshold() -> f64 {
    3.0
}

fn default_entropy_window() -> usize {
    20
}

fn default_entropy_min() -> f64 {
    0.5
}

fn default_entropy_max() -> f64 {
    4.0
}

impl Default for StatisticalGuardrailServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cosine_window: default_cosine_window(),
            cosine_z_threshold: default_cosine_z_threshold(),
            entropy_window: default_entropy_window(),
            entropy_min: default_entropy_min(),
            entropy_max: default_entropy_max(),
            block_on_anomaly: false,
        }
    }
}

impl StatisticalGuardrailServerConfig {
    /// Convert to the `StatisticalConfig` used by the hook.
    pub fn to_hook_config(&self) -> smgglrs_core::hooks::StatisticalConfig {
        smgglrs_core::hooks::StatisticalConfig {
            enabled: self.enabled,
            cosine_window: self.cosine_window,
            cosine_z_threshold: self.cosine_z_threshold,
            entropy_window: self.entropy_window,
            entropy_min: self.entropy_min,
            entropy_max: self.entropy_max,
            block_on_anomaly: self.block_on_anomaly,
        }
    }
}
