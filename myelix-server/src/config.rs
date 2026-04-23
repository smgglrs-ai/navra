use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub modules: ModulesConfig,
    #[serde(default)]
    pub approval: ApprovalConfig,
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
    #[serde(default)]
    pub permissions: HashMap<String, PermissionSet>,
    #[serde(default)]
    pub upstream: Vec<UpstreamConfig>,
    /// Credential label → backend source mappings.
    /// Only credentials listed here are accessible to agents.
    #[serde(default)]
    pub credentials: HashMap<String, myelix_core::credentials::CredentialMapping>,
    #[serde(default)]
    pub models: HashMap<String, ModelConfig>,
    /// Path to cognitive core directory (personas, heuristics, directives).
    #[serde(default)]
    pub cognitive_core: Option<String>,
    /// Directories containing flow TOML files.
    #[serde(default)]
    pub flow_dirs: Vec<String>,
    /// Domains to query for AID upstream discovery at startup.
    #[serde(default)]
    pub discover: Vec<String>,
    /// Whitelisted MCP servers to advertise in the registry.
    /// These appear in the /v0.1/servers endpoint alongside
    /// mcpd's own modules and connected upstream servers.
    #[serde(default)]
    pub registry: Vec<RegistryEntry>,
    /// Default resource budget for teams and flows.
    #[serde(default)]
    pub budget: BudgetConfig,
}

/// Default resource budget for teams and flows.
///
/// Configured in `[budget]` and used as defaults when creating teams
/// (team_create) and flows (flow_start). Individual calls can override
/// these values via their own parameters.
///
/// ```toml
/// [budget]
/// max_agents = 30
/// max_depth = 3
/// timeout_secs = 600
/// max_iterations = 50
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetConfig {
    #[serde(default = "default_budget_max_agents")]
    pub max_agents: u32,
    #[serde(default = "default_budget_max_depth")]
    pub max_depth: u32,
    #[serde(default = "default_budget_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_budget_max_iterations")]
    pub max_iterations: usize,
    /// Maximum tasks running simultaneously (GPU throttling).
    /// 0 means no limit.
    #[serde(default = "default_budget_max_parallel")]
    pub max_parallel: usize,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_agents: default_budget_max_agents(),
            max_depth: default_budget_max_depth(),
            timeout_secs: default_budget_timeout(),
            max_iterations: default_budget_max_iterations(),
            max_parallel: default_budget_max_parallel(),
        }
    }
}

fn default_budget_max_agents() -> u32 {
    30
}

fn default_budget_max_depth() -> u32 {
    3
}

fn default_budget_timeout() -> u64 {
    600
}

fn default_budget_max_parallel() -> usize {
    4
}

fn default_budget_max_iterations() -> usize {
    50
}

/// Configuration for a model.
///
/// Models can be loaded from local files (ONNX) or pulled from registries
/// and served via a runtime backend.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelConfig {
    /// Path to a local model file (ONNX). Used directly when no `source` is set.
    #[serde(default)]
    pub model_path: Option<String>,
    /// Hub source URI (e.g. `ollama://granite3.3:8b`, `hf://org/repo`).
    /// When set, the model is pulled and cached via myelix-model-hub.
    #[serde(default)]
    pub source: Option<String>,
    /// Path to the HuggingFace tokenizer.json file.
    #[serde(default)]
    pub tokenizer_path: Option<String>,
    /// Model task: "embedding", "classification", "chat", or "generate".
    #[serde(default = "default_model_task")]
    pub task: String,
    /// Embedding dimensions (for embedding models).
    #[serde(default)]
    pub dimensions: Option<usize>,
    /// Classification labels (for classification models).
    #[serde(default)]
    pub labels: Vec<String>,
    /// Confidence threshold for safety classification (default: 0.5).
    #[serde(default = "default_threshold")]
    pub threshold: Option<f32>,
    /// Runtime backend: "auto", "podman", "direct", or "none" (default).
    /// Used for chat/generate tasks served via myelix-model-runtime.
    #[serde(default)]
    pub runtime: Option<String>,
    /// Context window size for runtime-served models (default: 4096).
    #[serde(default)]
    pub context_size: Option<u32>,
    /// Number of parallel request slots for runtime (default: 1).
    #[serde(default)]
    pub parallel: Option<u32>,
    /// Model name for the OpenAI-compatible API. Defaults to the config key.
    #[serde(default)]
    pub model_name: Option<String>,
    /// Operator-defined agentic capabilities for model selection.
    /// These fields help the lead agent choose the right model
    /// for each teammate based on task requirements.
    #[serde(default)]
    pub agentic: Option<AgenticConfig>,
}

/// Operator-defined agentic capabilities for a model.
///
/// Configured in `[models.<name>.agentic]` and merged into
/// the model card at startup.
///
/// ```toml
/// [models.granite-code.agentic]
/// strengths = ["code generation", "fast inference"]
/// weaknesses = ["limited reasoning", "small context"]
/// recommended_tasks = ["code review", "simple analysis"]
/// avoid_tasks = ["multi-step planning"]
/// tool_use = "basic"
/// cost_tier = "free"
/// speed_tier = "fast"
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AgenticConfig {
    #[serde(default)]
    pub strengths: Vec<String>,
    #[serde(default)]
    pub weaknesses: Vec<String>,
    #[serde(default)]
    pub recommended_tasks: Vec<String>,
    #[serde(default)]
    pub avoid_tasks: Vec<String>,
    #[serde(default)]
    pub tool_use: Option<String>,
    #[serde(default)]
    pub cost_tier: Option<String>,
    #[serde(default)]
    pub speed_tier: Option<String>,
    #[serde(default)]
    pub max_agents: Option<u32>,
    #[serde(default)]
    pub reasoning: Option<String>,
    #[serde(default)]
    pub json_compliance: Option<String>,
    #[serde(default)]
    pub locality: Option<String>,
}

impl AgenticConfig {
    /// Convert to the hub's AgenticMeta for merging into a model card.
    pub fn to_agentic_meta(&self) -> myelix_model_hub::AgenticMeta {
        myelix_model_hub::AgenticMeta {
            strengths: self.strengths.clone(),
            weaknesses: self.weaknesses.clone(),
            recommended_tasks: self.recommended_tasks.clone(),
            avoid_tasks: self.avoid_tasks.clone(),
            tool_use: self.tool_use.clone(),
            cost_tier: self.cost_tier.clone(),
            speed_tier: self.speed_tier.clone(),
            max_agents: self.max_agents,
            reasoning: self.reasoning.clone(),
            json_compliance: self.json_compliance.clone(),
            locality: self.locality.clone(),
        }
    }
}

fn default_model_task() -> String {
    "embedding".to_string()
}

fn default_threshold() -> Option<f32> {
    Some(0.5)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_socket")]
    pub socket: Option<String>,
    pub tcp: Option<String>,
    /// AID discovery configuration. When set, mcpd serves
    /// `/.well-known/agent` for the AID fallback protocol.
    #[serde(default)]
    pub discovery: Option<DiscoveryConfig>,
    /// Root identity configuration for DID-based auth.
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
}

/// Root identity configuration.
///
/// Controls where mcpd stores its Ed25519 root keypair and how
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

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModulesConfig {
    #[serde(default)]
    pub docs: Option<DocsModuleConfig>,
    #[serde(default)]
    pub git: Option<GitModuleConfig>,
    #[serde(default)]
    pub rag: Option<RagModuleConfig>,
    #[serde(default)]
    pub voice: Option<VoiceModuleConfig>,
    #[serde(default)]
    pub vision: Option<VisionModuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitModuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VisionModuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Name of the vision model in [models.*] config.
    #[serde(default = "default_vision_model")]
    pub model: String,
}

fn default_vision_model() -> String {
    "vision".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct RagModuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Database path. Defaults to the same directory as docs, separate file.
    #[serde(default = "default_rag_db_path")]
    pub db: String,
}

fn default_rag_db_path() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mcpd/rag.db")
        .to_string_lossy()
        .into_owned()
}

#[derive(Debug, Clone, Deserialize)]
pub struct VoiceModuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Name of the ASR model in [models.*] config.
    #[serde(default = "default_asr_model")]
    pub asr_model: String,
    /// Name of the TTS model in [models.*] config.
    #[serde(default = "default_tts_model")]
    pub tts_model: String,
    /// VAD energy threshold (RMS). Default: 0.01
    #[serde(default = "default_vad_threshold")]
    pub vad_threshold: f32,
    /// Default voice for TTS.
    #[serde(default)]
    pub voice: Option<String>,
}

fn default_asr_model() -> String {
    "asr".to_string()
}

fn default_tts_model() -> String {
    "tts".to_string()
}

fn default_vad_threshold() -> f32 {
    0.01
}

#[derive(Debug, Clone, Deserialize)]
pub struct DocsModuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_db_path")]
    pub db: String,
    /// Default root path for docs_tree when no path argument is given.
    /// Overrides the top-level `cognitive_core` setting for docs routing.
    #[serde(default)]
    pub default_root: Option<String>,
    /// Directories to watch for auto-reindexing.
    #[serde(default)]
    pub watch: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalConfig {
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_notify")]
    pub notify: String,
}

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
    pub fn retry_config(&self) -> Option<myelix_core::upstream::RetryConfig> {
        if self.retry_base_delay_ms.is_none()
            && self.retry_max_delay_ms.is_none()
            && self.retry_budget_secs.is_none()
            && self.request_timeout_secs.is_none()
        {
            return None;
        }

        let mut config = myelix_core::upstream::RetryConfig::default();
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

#[derive(Debug, Clone, Deserialize)]
pub struct PermissionSet {
    /// Privilege ring (0 = most privileged, 3 = most restricted).
    /// When set, deny rules and approval requirements cascade from
    /// lower-numbered rings, and operations are intersected.
    #[serde(default)]
    pub ring: Option<u8>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub approve: Vec<String>,
    /// Safety profile: "standard", "secrets-only", "block", "none"
    #[serde(default = "default_safety")]
    pub safety: String,
    /// Custom regex patterns for content safety filtering.
    #[serde(default)]
    pub safety_patterns: Vec<SafetyPatternConfig>,
    /// Compliance framework tags for this permission set.
    /// Informational — logged at startup for audit trail.
    /// Example: ["SOC2-CC6.1", "EU-AI-Act-Art-14", "HIPAA-164.312"]
    #[serde(default)]
    pub compliance: Vec<String>,
    /// Per-tool permission rules (evaluated before handler invocation).
    #[serde(default)]
    pub tool_rules: Vec<ToolRuleConfig>,
    /// Default policy for tools not matched by any rule: "allow", "deny", "approve"
    #[serde(default = "default_tool_policy")]
    pub default_tool_policy: String,
    /// Credential labels this permission set can access.
    #[serde(default)]
    pub credentials: Vec<String>,
    /// Whether agents with this permission set can delegate capabilities.
    #[serde(default)]
    pub can_delegate: bool,
    /// Rate limit: maximum tool calls per window (e.g., "60/60" = 60 calls per 60 seconds).
    #[serde(default)]
    pub rate_limit: Option<String>,
    /// IFC policy for tainted writes: "allow", "approve", or "deny".
    /// When an agent reads external data (taint rises to Untrusted),
    /// this policy controls whether subsequent writes are permitted.
    #[serde(default = "default_tainted_write_policy")]
    pub tainted_write_policy: String,
    /// File paths that should keep their Trusted integrity label even
    /// when accessed via external read tools. Supports glob patterns.
    /// Example: ["~/Code/myproject/**", "~/Documents/**"]
    #[serde(default)]
    pub trusted_paths: Vec<String>,
}

fn default_tainted_write_policy() -> String {
    "allow".to_string()
}

/// A per-tool permission rule in config.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolRuleConfig {
    /// Glob pattern matching tool names (e.g., "git_*", "shell_exec").
    pub tool: String,
    /// Policy: "allow", "deny", or "approve".
    pub policy: String,
}

/// A custom regex pattern for safety filtering.
#[derive(Debug, Clone, Deserialize)]
pub struct SafetyPatternConfig {
    /// Category name for this pattern (e.g., "internal-url", "project-secret").
    pub category: String,
    /// Regex pattern to match.
    pub pattern: String,
}

fn default_tool_policy() -> String {
    "allow".to_string()
}

fn default_safety() -> String {
    "standard".to_string()
}

fn default_true() -> bool {
    true
}

fn default_socket() -> Option<String> {
    dirs::runtime_dir()
        .map(|d| d.join("mcpd/mcpd.sock").to_string_lossy().into_owned())
}

fn default_db_path() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mcpd/index.db")
        .to_string_lossy()
        .into_owned()
}

fn default_timeout() -> u64 {
    300
}

fn default_notify() -> String {
    "dbus".to_string()
}

impl Default for DocsModuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            db: default_db_path(),
            default_root: None,
            watch: Vec::new(),
        }
    }
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout(),
            notify: default_notify(),
        }
    }
}

impl ServerConfig {
    pub fn listen_addr(&self) -> String {
        self.tcp
            .clone()
            .unwrap_or_else(|| "127.0.0.1:9315".to_string())
    }
}

impl Config {
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let config_path = match path {
            Some(p) => PathBuf::from(p),
            None => Self::default_config_path(),
        };

        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    fn default_config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("mcpd/config.toml")
    }

    pub fn git_enabled(&self) -> bool {
        self.modules
            .git
            .as_ref()
            .map(|g| g.enabled)
            .unwrap_or(false)
    }

    pub fn docs_enabled(&self) -> bool {
        self.modules
            .docs
            .as_ref()
            .map(|d| d.enabled)
            .unwrap_or(true)
    }

    pub fn docs_db_path(&self) -> String {
        self.modules
            .docs
            .as_ref()
            .map(|d| d.db.clone())
            .unwrap_or_else(default_db_path)
    }

    pub fn rag_enabled(&self) -> bool {
        self.modules
            .rag
            .as_ref()
            .map(|r| r.enabled)
            .unwrap_or(false)
    }

    pub fn voice_enabled(&self) -> bool {
        self.modules
            .voice
            .as_ref()
            .map(|v| v.enabled)
            .unwrap_or(false)
    }

    pub fn vision_enabled(&self) -> bool {
        self.modules
            .vision
            .as_ref()
            .map(|v| v.enabled)
            .unwrap_or(false)
    }

    pub fn rag_db_path(&self) -> String {
        self.modules
            .rag
            .as_ref()
            .map(|r| r.db.clone())
            .unwrap_or_else(default_rag_db_path)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                socket: default_socket(),
                tcp: None,
                discovery: None,
                identity: None,
            },
            modules: ModulesConfig::default(),
            approval: ApprovalConfig::default(),
            agents: Vec::new(),
            permissions: HashMap::new(),
            upstream: Vec::new(),
            credentials: HashMap::new(),
            models: HashMap::new(),
            cognitive_core: None,
            flow_dirs: Vec::new(),
            discover: Vec::new(),
            registry: Vec::new(),
            budget: BudgetConfig::default(),
        }
    }
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    use rand::rngs::OsRng;
    use rand::RngCore;
    OsRng.fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("mcd_{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.server.tcp.as_deref(), Some("127.0.0.1:9315"));
        assert!(config.docs_enabled());
    }

    #[test]
    fn parse_modular_config() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[modules.docs]
enabled = true
db = "/tmp/test.db"

[[agents]]
name = "claude"
token_hash = "abc123"
permissions = "developer"

[permissions.developer]
allow = ["~/Documents/**"]
deny = ["**/.env"]
operations = ["read", "write", "search", "list", "git.status"]
approve = ["write", "git.commit"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.docs_enabled());
        assert_eq!(config.docs_db_path(), "/tmp/test.db");
        assert_eq!(config.agents.len(), 1);
        let dev = &config.permissions["developer"];
        assert!(dev.operations.contains(&"git.status".to_string()));
        assert!(dev.approve.contains(&"git.commit".to_string()));
    }

    #[test]
    fn disable_module() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[modules.docs]
enabled = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.docs_enabled());
    }

    #[test]
    fn default_config_is_valid() {
        let config = Config::default();
        assert!(config.agents.is_empty());
        assert!(config.docs_enabled());
    }

    #[test]
    fn parse_upstream_config() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[[upstream]]
name = "myelix"
command = ["poetry", "run", "python", "-m", "myelix.memory.mcp_server"]
cwd = "/home/user/myelix"

[[upstream]]
name = "api-server"
transport = "http"
url = "http://localhost:8001/mcp"

[[upstream]]
name = "sse-server"
transport = "sse"
url = "http://localhost:8002/sse"

[[upstream]]
name = "disabled-server"
command = ["echo", "noop"]
enabled = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.upstream.len(), 4);

        // stdio (default transport)
        assert_eq!(config.upstream[0].name, "myelix");
        assert_eq!(config.upstream[0].transport, "stdio");
        assert_eq!(config.upstream[0].command[0], "poetry");
        assert_eq!(config.upstream[0].cwd.as_deref(), Some("/home/user/myelix"));

        // http
        assert_eq!(config.upstream[1].name, "api-server");
        assert_eq!(config.upstream[1].transport, "http");
        assert_eq!(
            config.upstream[1].url.as_deref(),
            Some("http://localhost:8001/mcp")
        );

        // sse
        assert_eq!(config.upstream[2].transport, "sse");

        // disabled
        assert_eq!(config.upstream[3].enabled, Some(false));
    }

    #[test]
    fn generate_token_format() {
        let token = generate_token();
        assert!(token.starts_with("mcd_"));
        // 4 prefix chars + 64 hex chars = 68 total
        assert_eq!(token.len(), 68);
        // Verify uniqueness
        let token2 = generate_token();
        assert_ne!(token, token2);
    }

    #[test]
    fn parse_permission_rings() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[permissions.admin]
ring = 0
allow = ["/home/user/**"]
deny = ["**/.env"]
operations = ["read", "write", "git.status", "git.commit", "shell.exec"]

[permissions.developer]
ring = 1
allow = ["/home/user/projects/**"]
operations = ["read", "write", "git.status", "git.commit"]
approve = ["git.commit"]

[permissions.readonly]
ring = 2
allow = ["/home/user/projects/public/**"]
operations = ["read", "search", "list"]
"#;
        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.permissions["admin"].ring, Some(0));
        assert_eq!(config.permissions["developer"].ring, Some(1));
        assert_eq!(config.permissions["readonly"].ring, Some(2));
    }

    #[test]
    fn ring_defaults_to_none() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[permissions.custom]
allow = ["~/Documents/**"]
operations = ["read"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.permissions["custom"].ring, None);
    }

    #[test]
    fn parse_compliance_tags() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[permissions.audited]
allow = ["~/Projects/**"]
operations = ["read", "write"]
compliance = ["SOC2-CC6.1", "EU-AI-Act-Art-14", "HIPAA-164.312"]

[permissions.internal]
allow = ["~/Internal/**"]
operations = ["read"]
"#;
        let config: Config = toml::from_str(toml).unwrap();

        let audited = &config.permissions["audited"];
        assert_eq!(audited.compliance.len(), 3);
        assert!(audited.compliance.contains(&"SOC2-CC6.1".to_string()));
        assert!(audited.compliance.contains(&"EU-AI-Act-Art-14".to_string()));
        assert!(audited.compliance.contains(&"HIPAA-164.312".to_string()));

        // Permission set without compliance tags defaults to empty
        let internal = &config.permissions["internal"];
        assert!(internal.compliance.is_empty());
    }

    #[test]
    fn parse_identity_config() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[server.identity]
key_path = "/etc/mcpd/identity.key"
token_ttl = 1800
max_delegation_depth = 2
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let identity = config.server.identity.as_ref().unwrap();
        assert_eq!(identity.key_path.as_deref(), Some("/etc/mcpd/identity.key"));
        assert_eq!(identity.token_ttl, 1800);
        assert_eq!(identity.max_delegation_depth, 2);
    }

    #[test]
    fn parse_credential_mappings() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[credentials]
"github.pat" = { source = "keyring", path = "mcpd/github-pat" }
"ci.token" = { source = "env", var = "GITHUB_TOKEN" }
"gnome.github" = { source = "keyring", path = "org.gnome.OnlineAccounts/github" }
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.credentials.len(), 3);

        let gh = &config.credentials["github.pat"];
        assert_eq!(gh.source, "keyring");
        assert_eq!(gh.path.as_deref(), Some("mcpd/github-pat"));

        let ci = &config.credentials["ci.token"];
        assert_eq!(ci.source, "env");
        assert_eq!(ci.var.as_deref(), Some("GITHUB_TOKEN"));
    }

    #[test]
    fn parse_agent_capability_fields() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[[agents]]
name = "leader"
token_hash = "abc123"
permissions = "admin"
pubkey = "~/.config/mcpd/agents/leader.pub"
capability_token = true
token_ttl = 900
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let agent = &config.agents[0];
        assert_eq!(agent.pubkey.as_deref(), Some("~/.config/mcpd/agents/leader.pub"));
        assert!(agent.capability_token);
        assert_eq!(agent.token_ttl, Some(900));
    }

    #[test]
    fn parse_permission_credentials() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[permissions.leader]
ring = 1
allow = ["~/Code/**"]
operations = ["read", "write"]
credentials = ["github.pat", "jira.token"]
can_delegate = true
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let leader = &config.permissions["leader"];
        assert_eq!(leader.credentials, vec!["github.pat", "jira.token"]);
        assert!(leader.can_delegate);
    }

    #[test]
    fn parse_model_agentic_config() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[models.granite-code]
task = "chat"
source = "ollama://granite-code:3b"

[models.granite-code.agentic]
strengths = ["code generation", "fast inference"]
weaknesses = ["limited reasoning"]
recommended_tasks = ["code review"]
avoid_tasks = ["multi-step planning"]
tool_use = "basic"
cost_tier = "free"
speed_tier = "fast"
max_agents = 4
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let model = &config.models["granite-code"];
        let agentic = model.agentic.as_ref().unwrap();
        assert_eq!(agentic.strengths, vec!["code generation", "fast inference"]);
        assert_eq!(agentic.tool_use, Some("basic".to_string()));
        assert_eq!(agentic.max_agents, Some(4));
    }

    #[test]
    fn agent_capability_defaults() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[[agents]]
name = "legacy"
token_hash = "xyz"
permissions = "dev"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let agent = &config.agents[0];
        assert!(agent.pubkey.is_none());
        assert!(agent.did.is_none());
        assert!(!agent.capability_token);
        assert!(agent.token_ttl.is_none());
    }
}
