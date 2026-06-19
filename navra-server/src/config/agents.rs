use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct AgentConfig {
    /// Unique agent identifier used in logging and auth.
    pub name: String,
    /// SHA-256 hash of the agent's bearer token.
    pub token_hash: String,
    /// Name of the permission set to apply (must match a key in `[permissions]`).
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

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct UpstreamConfig {
    /// Unique name for this upstream server.
    pub name: String,
    /// Transport protocol: "stdio" (default), "http", or "sse".
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
    /// Enable or disable this upstream. Default: true (absent = enabled).
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
    /// Per-tool operation overrides: "read", "write", or "deny".
    /// Overrides the auto-classification from MCP annotations and
    /// name heuristics. Tools set to "deny" are never registered.
    #[serde(default)]
    pub tool_overrides: std::collections::HashMap<String, String>,
    /// Per-tool semantic classification overrides.
    /// Keys are tool names, values specify domain and operation.
    /// Takes precedence over auto-classification and tool_overrides.
    ///
    /// Example:
    /// ```toml
    /// [upstream.tool_class]
    /// zip_files = { domain = "filesystem", operation = "write" }
    /// ```
    #[serde(default)]
    pub tool_class: std::collections::HashMap<String, super::permissions::ToolClassConfig>,
    /// Maximum response body size in bytes for OpenAPI upstreams.
    /// Responses exceeding this limit are truncated to avoid overwhelming
    /// LLM context windows. Default: 32768 (32 KB).
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
    /// OpenAPI 3.x spec source (URL or file path).
    /// When set, transport/command/url are ignored — navra parses the spec
    /// and exposes operations as MCP tools directly.
    #[serde(default)]
    pub openapi: Option<String>,
    /// Authentication for the target API (used with openapi upstreams).
    #[serde(default)]
    pub auth: Option<OpenApiAuthConfig>,
    /// Tool name filter — only expose operations matching these names.
    /// Matches against both the prefixed tool name and the raw operationId.
    /// Supports glob patterns (e.g., "get_*", "*_search").
    #[serde(default)]
    pub tool_filter: Vec<String>,
    /// OAuth 2.1 configuration for authenticating to this upstream server.
    /// When set, navra acts as an OAuth client and handles token acquisition,
    /// refresh, and 401/403 challenges automatically.
    #[serde(default)]
    pub oauth: Option<UpstreamOAuthConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct OpenApiAuthConfig {
    /// Bearer token (or env var reference like "${JIRA_TOKEN}").
    #[serde(default)]
    pub bearer: Option<String>,
    /// API key header name.
    #[serde(default)]
    pub api_key_name: Option<String>,
    /// API key value (or env var reference).
    #[serde(default)]
    pub api_key_value: Option<String>,
    /// API key location: "header" (default) or "query".
    #[serde(default)]
    pub api_key_location: Option<String>,
    /// Basic auth username.
    #[serde(default)]
    pub basic_username: Option<String>,
    /// Basic auth password (or env var reference).
    #[serde(default)]
    pub basic_password: Option<String>,
}

/// OAuth 2.1 client configuration for upstream MCP servers.
///
/// Enables navra to authenticate to remote upstream servers that require
/// OAuth. Supports Authorization Code + PKCE, Client Credentials, and
/// Device Authorization (RFC 8628) flows.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct UpstreamOAuthConfig {
    /// Pre-registered OAuth client ID. If absent, navra uses Dynamic
    /// Client Registration (RFC 7591) to obtain credentials.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Pre-registered client secret (or env var reference like "${SECRET}").
    /// Required for Client Credentials flow.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// OAuth flow preference: "auto" (default), "code", "client_credentials", "device".
    ///
    /// - "auto": tries client_credentials if secret is present, then device
    ///   auth if headless (no DISPLAY/WAYLAND), else authorization code + PKCE.
    /// - "code": Authorization Code + PKCE with localhost callback.
    /// - "client_credentials": Machine-to-machine, no user interaction.
    /// - "device": Device Authorization Flow (RFC 8628).
    #[serde(default)]
    pub flow: Option<String>,
    /// OAuth scopes to request.
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl UpstreamConfig {
    /// Returns a RetryConfig if any retry fields are set, otherwise None.
    pub fn retry_config(&self) -> Option<navra_core::upstream::RetryConfig> {
        if self.retry_base_delay_ms.is_none()
            && self.retry_max_delay_ms.is_none()
            && self.retry_budget_secs.is_none()
            && self.request_timeout_secs.is_none()
        {
            return None;
        }

        let mut config = navra_core::upstream::RetryConfig::default();
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
