use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub name: String,
    pub token_hash: String,
    pub permissions: String,
    /// Path to an Ed25519 private key for commit signing.
    /// When set, git_commit signs commits with this key using
    /// Git's SSH signing support (gpg.format=ssh).
    #[serde(default)]
    pub signing_key: Option<String>,
    /// Path to Ed25519 public key file for capability token auth.
    #[serde(default)]
    pub pubkey: Option<String>,
    /// DID:key identifier (alternative to pubkey file).
    #[serde(default)]
    pub did: Option<String>,
    /// Enable capability token issuance for this agent.
    #[serde(default)]
    pub capability_token: bool,
    /// Override token TTL for this agent (seconds).
    #[serde(default)]
    pub token_ttl: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Command for stdio transport (e.g., ["python3", "-m", "server"])
    #[serde(default)]
    pub command: Vec<String>,
    /// Working directory for stdio transport
    #[serde(default)]
    pub cwd: Option<String>,
    /// URL for http/sse transport (e.g., "http://localhost:8001/mcp")
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Retry base delay in milliseconds (default: 1000)
    #[serde(default)]
    pub retry_base_delay_ms: Option<u64>,
    /// Maximum retry delay in milliseconds (default: 30000)
    #[serde(default)]
    pub retry_max_delay_ms: Option<u64>,
    /// Total retry budget in seconds (default: 600)
    #[serde(default)]
    pub retry_budget_secs: Option<u64>,
    /// Request timeout in seconds (default: 45)
    #[serde(default)]
    pub request_timeout_secs: Option<u64>,
}

impl UpstreamConfig {
    /// Returns a RetryConfig if any retry fields are set, otherwise None.
    pub fn retry_config(&self) -> Option<smgglrs_core::upstream::RetryConfig> {
        if self.retry_base_delay_ms.is_none()
            && self.retry_max_delay_ms.is_none()
            && self.retry_budget_secs.is_none()
            && self.request_timeout_secs.is_none()
        {
            return None;
        }

        let mut config = smgglrs_core::upstream::RetryConfig::default();
        if let Some(ms) = self.retry_base_delay_ms {
            config.base_delay = std::time::Duration::from_millis(ms);
        }
        if let Some(ms) = self.retry_max_delay_ms {
            config.max_delay = std::time::Duration::from_millis(ms);
        }
        if let Some(secs) = self.retry_budget_secs {
            config.total_budget = std::time::Duration::from_secs(secs);
        }
        if let Some(secs) = self.request_timeout_secs {
            config.request_timeout = std::time::Duration::from_secs(secs);
        }
        Some(config)
    }
}

fn default_transport() -> String {
    "stdio".to_string()
}
