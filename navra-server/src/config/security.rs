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
    /// Sliding window size for tool-transition anomaly detection (default: 50).
    #[serde(default = "default_transition_window")]
    pub transition_window: usize,
    /// Minimum observations before transition anomalies are flagged (default: 10).
    #[serde(default = "default_transition_min_observations")]
    pub transition_min_observations: usize,
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

fn default_transition_window() -> usize {
    50
}

fn default_transition_min_observations() -> usize {
    10
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
            transition_window: default_transition_window(),
            transition_min_observations: default_transition_min_observations(),
        }
    }
}

impl StatisticalGuardrailServerConfig {
    /// Convert to the `StatisticalConfig` used by the hook.
    pub fn to_hook_config(&self) -> navra_core::hooks::StatisticalConfig {
        navra_core::hooks::StatisticalConfig {
            enabled: self.enabled,
            cosine_window: self.cosine_window,
            cosine_z_threshold: self.cosine_z_threshold,
            entropy_window: self.entropy_window,
            entropy_min: self.entropy_min,
            entropy_max: self.entropy_max,
            block_on_anomaly: self.block_on_anomaly,
            transition_window: self.transition_window,
            transition_min_observations: self.transition_min_observations,
        }
    }
}

/// Server-side configuration for the detect-only monitoring agent.
///
/// ```toml
/// [monitoring]
/// enabled = true
/// buffer_size = 256
/// ```
pub type MonitoringServerConfig = navra_core::hooks::MonitoringConfig;

/// Server-side configuration for temporal behavioral contracts.
///
/// ```toml
/// [temporal_contracts]
/// enabled = true
/// max_history_per_session = 200
///
/// [[temporal_contracts.contracts]]
/// name = "read-before-write"
/// description = "Must read a file before writing"
/// predicate = { type = "requires", tool = "file_write", prerequisite = "file_read" }
/// action = { type = "block", value = "Read the file first" }
/// applies_to = ["*"]
/// ```
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct TemporalContractServerConfig {
    /// Whether temporal contracts are enabled. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum action history entries per session. Default: 200.
    #[serde(default = "default_max_history")]
    pub max_history_per_session: usize,
    /// List of temporal contract definitions.
    #[serde(default)]
    pub contracts: Vec<TemporalContractConfig>,
}

fn default_max_history() -> usize {
    200
}

/// A single temporal contract definition in server config.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct TemporalContractConfig {
    /// Unique contract name for logging and diagnostics.
    pub name: String,
    /// Human-readable description of the contract.
    #[serde(default)]
    pub description: String,
    /// Predicate JSON object (e.g., `{ "type": "requires", "tool": "...", "prerequisite": "..." }`).
    pub predicate: serde_json::Value,
    /// Action JSON object (e.g., `{ "type": "block", "value": "..." }`).
    pub action: serde_json::Value,
    /// Permission sets this contract applies to (glob patterns, "*" = all).
    pub applies_to: Vec<String>,
}
