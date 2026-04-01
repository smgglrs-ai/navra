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
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_socket")]
    pub socket: Option<String>,
    pub tcp: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModulesConfig {
    #[serde(default)]
    pub docs: Option<DocsModuleConfig>,
    #[serde(default)]
    pub git: Option<GitModuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitModuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DocsModuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_db_path")]
    pub db: String,
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
    pub fn retry_config(&self) -> Option<mcpd_core::upstream::RetryConfig> {
        if self.retry_base_delay_ms.is_none()
            && self.retry_max_delay_ms.is_none()
            && self.retry_budget_secs.is_none()
            && self.request_timeout_secs.is_none()
        {
            return None;
        }

        let mut config = mcpd_core::upstream::RetryConfig::default();
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
    /// Per-tool permission rules (evaluated before handler invocation).
    #[serde(default)]
    pub tool_rules: Vec<ToolRuleConfig>,
    /// Default policy for tools not matched by any rule: "allow", "deny", "approve"
    #[serde(default = "default_tool_policy")]
    pub default_tool_policy: String,
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                socket: default_socket(),
                tcp: None,
            },
            modules: ModulesConfig::default(),
            approval: ApprovalConfig::default(),
            agents: Vec::new(),
            permissions: HashMap::new(),
            upstream: Vec::new(),
        }
    }
}

pub fn generate_token() -> String {
    format!("mcd_{}", uuid::Uuid::new_v4().as_simple())
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
        assert!(token.len() > 10);
    }
}
