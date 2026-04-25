use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_socket")]
    pub socket: Option<String>,
    pub tcp: Option<String>,
    /// Per-hook timeout in seconds (default: 10).
    #[serde(default = "default_hook_timeout")]
    pub hook_timeout_secs: u64,
    /// AID discovery configuration. When set, smgglrs serves
    /// `/.well-known/agent` for the AID fallback protocol.
    #[serde(default)]
    pub discovery: Option<DiscoveryConfig>,
    /// Root identity configuration for DID-based auth.
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
    /// Path to PII NER model directory.
    /// Default: ~/.local/share/smgglrs/models/pii-ner/
    #[serde(default)]
    pub pii_model_path: Option<String>,
}

fn default_hook_timeout() -> u64 {
    10
}

/// Root identity configuration.
///
/// Controls where smgglrs stores its Ed25519 root keypair and how
/// capability tokens are issued.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    /// Path to Ed25519 seed file. If omitted, the OS keyring is used.
    #[serde(default)]
    pub key_path: Option<String>,
    /// Default capability token TTL in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_token_ttl")]
    pub token_ttl: u64,
    /// Maximum delegation chain depth (default: 3).
    #[serde(default = "default_max_delegation_depth")]
    pub max_delegation_depth: u8,
    /// Nonce cache TTL in seconds for replay tracking (default: 7200 = 2 hours).
    #[serde(default = "default_nonce_cache_ttl")]
    pub nonce_cache_ttl_secs: u64,
}

fn default_nonce_cache_ttl() -> u64 {
    7200
}

fn default_token_ttl() -> u64 {
    3600
}

fn default_max_delegation_depth() -> u8 {
    3
}

/// AID (Agent Identity & Discovery) configuration.
///
/// Populates the `/.well-known/agent` JSON endpoint per the AID spec.
/// See: https://aid.agentcommunity.org/docs/specification
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    /// Externally-reachable URL of this server's MCP endpoint.
    /// Example: "https://tools.example.com/mcp"
    pub url: String,
    /// Enable mDNS/DNS-SD advertising and browsing on the local network.
    #[serde(default)]
    pub mdns: bool,
    /// Authentication hint: "none", "pat", "apikey", "oauth2_code", "mtls".
    #[serde(default = "default_aid_auth")]
    pub auth: String,
    /// Human-readable description (max 60 bytes per AID spec).
    #[serde(default)]
    pub description: Option<String>,
    /// Documentation URL.
    #[serde(default)]
    pub docs_url: Option<String>,
    /// Timeout in seconds for AID HTTP lookups and mDNS browse (default: 10).
    #[serde(default = "default_discovery_timeout")]
    pub timeout_secs: u64,
    /// mDNS browse duration in seconds (default: 3).
    #[serde(default = "default_mdns_browse_secs")]
    pub mdns_browse_secs: u64,
}

fn default_discovery_timeout() -> u64 {
    10
}

fn default_mdns_browse_secs() -> u64 {
    3
}

fn default_aid_auth() -> String {
    "pat".to_string()
}

/// A whitelisted MCP server for the registry.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryEntry {
    /// Server name (unique identifier).
    pub name: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Registry type: "mcp", "http", "aws_agent_registry".
    /// - "mcp": queries an MCP registry endpoint (default)
    /// - "http": generic HTTP/JSON registry with configurable URL template
    /// - "aws_agent_registry": AWS Agent Registry (future)
    #[serde(default = "default_registry_type")]
    pub registry_type: String,
    /// Transport type: "streamable-http", "sse", "stdio".
    #[serde(default = "default_remote_type")]
    pub remote_type: String,
    /// Remote endpoint URL.
    pub url: String,
    /// Repository URL (optional).
    #[serde(default)]
    pub repository: Option<String>,
    /// URL template for search queries (HTTP type only).
    /// Use `{query}` as placeholder for the search term.
    /// Example: "https://registry.example.com/api/search?q={query}"
    #[serde(default)]
    pub search_url: Option<String>,
    /// JSON path to extract results from the HTTP response (default: root array).
    /// Example: "data.results" to extract from `{"data": {"results": [...]}}`
    #[serde(default)]
    pub results_path: Option<String>,
}

fn default_registry_type() -> String {
    "mcp".to_string()
}

fn default_remote_type() -> String {
    "streamable-http".to_string()
}

pub(super) fn default_socket() -> Option<String> {
    dirs::runtime_dir()
        .map(|d| d.join("smgglrs/smgglrs.sock").to_string_lossy().into_owned())
}

impl ServerConfig {
    pub fn listen_addr(&self) -> String {
        self.tcp
            .clone()
            .unwrap_or_else(|| "127.0.0.1:9315".to_string())
    }
}
