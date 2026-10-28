use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentConfig {
    /// Unique agent identifier used in logging and auth.
    pub name: String,
    /// BLAKE3 hash of the agent's bearer token.
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
    /// Model override (must match a key in `[models]`). Wins over
    /// permission set default.
    #[serde(default)]
    pub model: Option<String>,
    /// Upstream MCP servers visible to this agent (by name). Wins over
    /// permission set default. Empty = inherit from permission set.
    #[serde(default)]
    pub upstream: Vec<String>,
    /// Maximum concurrent tool calls. Wins over permission set default.
    #[serde(default)]
    pub max_concurrent: Option<u32>,
    /// Context window cap. Wins over permission set default.
    #[serde(default)]
    pub max_context: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
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
    #[allow(dead_code)]
    pub retry_base_delay_ms: Option<u64>,
    /// Maximum retry delay in milliseconds (default: 30000)
    #[serde(default)]
    #[allow(dead_code)]
    pub retry_max_delay_ms: Option<u64>,
    /// Total retry budget in seconds (default: 600)
    #[serde(default)]
    #[allow(dead_code)]
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
    /// Signed tool manifest for this upstream. When set, the upstream
    /// is only registered if the manifest signature verifies under
    /// TOFU pinning and the served tools match the signed set exactly.
    /// A key change after pinning rejects the upstream (no re-pin).
    #[serde(default)]
    pub manifest: Option<ManifestConfig>,
    /// Scan tool definitions advertised by this upstream for
    /// supply-chain threats (tool poisoning, typosquatting, schema
    /// abuse, hidden unicode, rug pulls, ...). Tools classified
    /// Malicious are dropped; Suspicious tools are registered with a
    /// warning. Default: `true`. Disabling is discouraged — it removes
    /// the only gate between upstream tool descriptions and agent
    /// context.
    #[serde(default)]
    pub scan_tools: Option<bool>,
    /// Content bounds for this upstream's discovery response. Defaults
    /// are applied per field; see [`UpstreamBoundsConfig`].
    #[serde(default)]
    pub bounds: Option<UpstreamBoundsConfig>,
    /// Minimum interval between `tools/list_changed` refreshes for
    /// this upstream, in milliseconds (debounce against a chatty
    /// upstream). Default: 1000.
    #[serde(default)]
    pub refresh_debounce_ms: Option<u64>,
    /// Override the rug-pull hash store location for this upstream.
    /// Default: `~/.local/share/navra/tool_hashes.json`. Set per
    /// upstream to isolate hash stores between navra instances.
    #[serde(default)]
    pub tool_hash_path: Option<String>,
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
    #[allow(dead_code)]
    pub oauth: Option<UpstreamOAuthConfig>,
    /// Network egress policy for sandboxed execution.
    /// When absent and `--sandbox` is used, defaults to deny-all.
    #[serde(default)]
    #[allow(dead_code)]
    pub network: Option<NetworkPolicy>,
    /// Environment variables to set when launching this upstream.
    /// Values support credential store references: `"${credential:label}"`
    /// resolves the label via the navra credential store (OS keyring or env).
    /// Plain values are passed through as-is.
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
    /// Credential label mappings: env var name → credential store label.
    /// The credential is resolved from the OS keyring at launch time
    /// and injected as an environment variable into the server process.
    /// Credentials are zeroized in navra's memory after injection.
    #[serde(default)]
    pub credentials: std::collections::HashMap<String, String>,
    /// TLS configuration for HTTPS upstream connections.
    /// When absent, standard HTTPS works via rustls with platform
    /// certificate verification. Set this for custom CA bundles,
    /// mutual TLS (client certificates), or to skip verification
    /// in development.
    #[serde(default)]
    #[schemars(skip)]
    pub tls: Option<navra_protocol::TlsConfig>,
}

/// Signed tool manifest configuration for an upstream.
///
/// Exactly one of `path` or `inline` must be set. The manifest is a
/// JSON [`navra_auth::manifest::SignedManifest`] — a tool list signed
/// with the upstream's Ed25519 key. Verification pins the signing key
/// on first use (TOFU); a later key change rejects the upstream.
///
/// ```toml
/// [upstream.manifest]
/// path = "manifests/github.signed.json"
/// keystore = "~/.local/share/navra/manifest_keys.json"  # optional
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ManifestConfig {
    /// Path to the signed manifest JSON file.
    #[serde(default)]
    pub path: Option<String>,
    /// Inline signed manifest JSON (alternative to `path`).
    #[serde(default)]
    pub inline: Option<String>,
    /// TOFU keystore location. Default:
    /// `~/.local/share/navra/manifest_keys.json`.
    #[serde(default)]
    pub keystore: Option<String>,
}

/// Content bounds for upstream discovery responses.
///
/// Upstream `tools/list` responses are untrusted input. Without
/// bounds, a hostile server can flood the gateway with tool
/// definitions or absurdly nested schemas. Exceeding a bound rejects
/// the upstream registration with a clear error (fail closed) unless
/// `truncate_oversized = true`, in which case descriptions are
/// truncated and excess tools dropped with warnings. Schema depth can
/// never be truncated and always rejects.
///
/// ```toml
/// [upstream.bounds]
/// max_tools = 500
/// max_description_length = 2048
/// truncate_oversized = false
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UpstreamBoundsConfig {
    /// Maximum number of tools accepted from one upstream.
    /// Default: 1000.
    #[serde(default)]
    pub max_tools: Option<usize>,
    /// Maximum JSON nesting depth of any tool's input schema.
    /// Default: 32.
    #[serde(default)]
    pub max_input_schema_depth: Option<usize>,
    /// Maximum length (bytes) of any tool description. Default: 4096.
    #[serde(default)]
    pub max_description_length: Option<usize>,
    /// Maximum total size (bytes) of all serialized tool definitions.
    /// Default: 4194304 (4 MiB).
    #[serde(default)]
    pub max_total_definition_bytes: Option<u64>,
    /// Truncate instead of reject where truncation is sound
    /// (descriptions, tool count). Default: `false` (fail closed).
    #[serde(default)]
    pub truncate_oversized: Option<bool>,
}

/// Network egress policy controlling which external endpoints a sandboxed
/// upstream MCP server can reach.
///
/// Both domains and IP addresses are supported. When `deny_all_external`
/// is true (the default), raw IP addresses are blocked unless they appear
/// in `allowed_ips`. This prevents bypassing domain-based rules by
/// resolving to an IP and connecting directly.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NetworkPolicy {
    /// Domains the upstream is allowed to reach (e.g., `"*.googleapis.com"`).
    /// Supports wildcard prefix matching (`*.example.com`).
    #[serde(default)]
    #[allow(dead_code)]
    pub allowed_domains: Vec<String>,
    /// Domains explicitly blocked (deny wins over allow).
    #[serde(default)]
    #[allow(dead_code)]
    pub blocked_domains: Vec<String>,
    /// IP addresses or CIDR ranges allowed (e.g., `"10.0.0.0/8"`).
    /// Raw IP access is blocked by default when `deny_all_external` is true.
    #[serde(default)]
    #[allow(dead_code)]
    pub allowed_ips: Vec<String>,
    /// When true, only `allowed_domains` and `allowed_ips` are reachable.
    /// Default: true.
    #[serde(default = "super::default_true")]
    #[allow(dead_code)]
    pub deny_all_external: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UpstreamOAuthConfig {
    /// Pre-registered OAuth client ID. If absent, navra uses Dynamic
    /// Client Registration (RFC 7591) to obtain credentials.
    #[serde(default)]
    #[allow(dead_code)]
    pub client_id: Option<String>,
    /// Pre-registered client secret (or env var reference like "${SECRET}").
    /// Required for Client Credentials flow.
    #[serde(default)]
    #[allow(dead_code)]
    pub client_secret: Option<String>,
    /// OAuth flow preference: "auto" (default), "code", "client_credentials", "device".
    ///
    /// - "auto": tries client_credentials if secret is present, then device
    ///   auth if headless (no DISPLAY/WAYLAND), else authorization code + PKCE.
    /// - "code": Authorization Code + PKCE with localhost callback.
    /// - "client_credentials": Machine-to-machine, no user interaction.
    /// - "device": Device Authorization Flow (RFC 8628).
    #[serde(default)]
    #[allow(dead_code)]
    pub flow: Option<String>,
    /// OAuth scopes to request.
    #[serde(default)]
    #[allow(dead_code)]
    pub scopes: Vec<String>,
}

#[allow(dead_code)]
impl UpstreamConfig {
    /// Returns a RetryConfig if any retry fields are set, otherwise None.
    pub fn retry_config(&self) -> Option<navra_protocol::RetryConfig> {
        if self.retry_base_delay_ms.is_none()
            && self.retry_max_delay_ms.is_none()
            && self.retry_budget_secs.is_none()
            && self.request_timeout_secs.is_none()
        {
            return None;
        }

        let mut config = navra_protocol::RetryConfig::default();
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
