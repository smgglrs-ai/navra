use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_socket")]
    pub socket: Option<String>,
    pub tcp: Option<String>,
    /// AID discovery configuration. When set, smgglrs serves
    /// `/.well-known/agent` for the AID fallback protocol.
    #[serde(default)]
    pub discovery: Option<DiscoveryConfig>,
    /// Root identity configuration for DID-based auth.
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
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
    /// Transport type: "streamable-http", "sse", "stdio".
    #[serde(default = "default_remote_type")]
    pub remote_type: String,
    /// Remote endpoint URL.
    pub url: String,
    /// Repository URL (optional).
    #[serde(default)]
    pub repository: Option<String>,
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
