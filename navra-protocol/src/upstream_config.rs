use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for retry and reconnection behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Base delay for exponential backoff (default: 1s).
    pub base_delay: Duration,
    /// Maximum delay between retries (default: 30s).
    pub max_delay: Duration,
    /// Total time budget for reconnection attempts (default: 10min).
    pub total_budget: Duration,
    /// How long to wait for a single request before timing out (default: 45s).
    pub request_timeout: Duration,
    /// Gap threshold for sleep detection (default: 60s).
    /// If the gap since last successful request exceeds this, the retry
    /// budget is reset (assumes the system was asleep).
    pub sleep_gap_threshold: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            total_budget: Duration::from_secs(600),
            request_timeout: Duration::from_secs(45),
            sleep_gap_threshold: Duration::from_secs(60),
        }
    }
}

/// TLS configuration for an upstream MCP server connection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to CA certificate bundle (PEM). When set, only CAs in this
    /// bundle are trusted.
    pub ca_cert: Option<String>,
    /// Path to client certificate (PEM) for mutual TLS.
    pub client_cert: Option<String>,
    /// Path to client private key (PEM) for mutual TLS.
    pub client_key: Option<String>,
    /// Skip TLS certificate verification (DANGEROUS — only for development).
    #[serde(default)]
    pub danger_skip_verify: bool,
}
