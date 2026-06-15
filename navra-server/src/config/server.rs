use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct ServerConfig {
    /// Unix socket path. Default: `$XDG_RUNTIME_DIR/navra/navra.sock`.
    #[serde(default = "default_socket")]
    pub socket: Option<String>,
    /// TCP listen address (e.g., "127.0.0.1:9315"). Used instead of socket when set.
    pub tcp: Option<String>,
    /// Per-hook timeout in seconds (default: 10).
    #[serde(default = "default_hook_timeout")]
    pub hook_timeout_secs: u64,
    /// AID discovery configuration. When set, navra serves
    /// `/.well-known/agent` for the AID fallback protocol.
    #[serde(default)]
    pub discovery: Option<DiscoveryConfig>,
    /// Root identity configuration for DID-based auth.
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
    /// OpenShell identity federation config.
    /// When set, OpenShellAuthenticator is inserted into the auth chain.
    #[serde(default)]
    pub openshell_auth: Option<navra_core::auth::openshell::OpenShellAuthConfig>,
    /// Path to PII NER model directory (English).
    /// Default: ~/.local/share/navra/models/pii-ner/
    #[serde(default)]
    pub pii_model_path: Option<String>,
    /// Path to multilingual PII NER model directory.
    /// Default: ~/.local/share/navra/models/pii-ner-multilingual/
    #[serde(default)]
    pub pii_multilingual_model_path: Option<String>,
    /// Use containerized agent execution.
    /// `true` = always, `false` = never, absent = auto-detect Podman.
    #[serde(default)]
    pub containerized: Option<bool>,
    /// Allow direct (unsandboxed) execution when no container runtime
    /// is available. Default: `false`.
    #[serde(default)]
    pub allow_direct_execution: bool,
    /// Container image for agent sandboxes.
    #[serde(default = "default_agent_image")]
    pub agent_image: String,
    /// Container image for the shared model server.
    #[serde(default = "default_model_server_image")]
    pub model_server_image: String,
    /// OpenShell compute driver gRPC endpoint for agent sandboxing.
    #[serde(default)]
    pub openshell_gateway: Option<String>,
    /// Memory limit per agent container (e.g., "2g", "512m").
    #[serde(default = "default_container_memory")]
    pub container_memory: String,
    /// CPU limit per agent container (e.g., "2", "0.5").
    #[serde(default = "default_container_cpus")]
    pub container_cpus: String,
    /// Maximum PIDs per agent container.
    #[serde(default = "default_container_pids")]
    pub container_pids: u32,
    /// MCP protocol version: "2026-07-28" (stateless dispatch, default)
    /// or "2025-03-26" (legacy session-based, deprecated).
    #[serde(default = "default_mcp_version")]
    pub mcp_version: String,
    /// Agent bundle signature policy: "enforce", "warn", or "skip".
    /// Controls whether `navra agent install` requires cosign signature
    /// verification. Default: "warn".
    #[serde(default = "default_agent_signature_policy")]
    pub agent_signature_policy: String,
    /// Watch the config file for changes and hot-reload.
    #[serde(default)]
    pub config_watch: bool,
    /// Debounce interval in ms for config file watch events.
    #[serde(default = "default_config_watch_debounce_ms")]
    pub config_watch_debounce_ms: u64,
}

fn default_mcp_version() -> String {
    "2026-07-28".to_string()
}

fn default_config_watch_debounce_ms() -> u64 {
    50
}

fn default_agent_image() -> String {
    "localhost/navra-agent:latest".to_string()
}

fn default_model_server_image() -> String {
    "ghcr.io/ggerganov/llama.cpp:server-cuda".to_string()
}

fn default_container_memory() -> String {
    "2g".to_string()
}

fn default_container_cpus() -> String {
    "2".to_string()
}

fn default_container_pids() -> u32 {
    256
}

fn default_hook_timeout() -> u64 {
    10
}

fn default_agent_signature_policy() -> String {
    "warn".to_string()
}

/// Root identity configuration.
///
/// Controls where navra stores its Ed25519 root keypair and how
/// capability tokens are issued.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
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
    dirs::runtime_dir().map(|d| d.join("navra/navra.sock").to_string_lossy().into_owned())
}

impl ServerConfig {
    pub fn listen_addr(&self) -> String {
        self.tcp
            .clone()
            .unwrap_or_else(|| "127.0.0.1:9315".to_string())
    }
}
