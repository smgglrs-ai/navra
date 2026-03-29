use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub index: IndexConfig,
    #[serde(default)]
    pub approval: ApprovalConfig,
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
    #[serde(default)]
    pub permissions: HashMap<String, PermissionSet>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_socket")]
    pub socket: Option<String>,
    pub tcp: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexConfig {
    #[serde(default = "default_db_path")]
    pub db: String,
    #[serde(default = "default_debounce")]
    pub watch_debounce_ms: u64,
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
pub struct PermissionSet {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub approve: Vec<String>,
}

fn default_socket() -> Option<String> {
    dirs::runtime_dir()
        .map(|d| d.join("mcpd/docs.sock").to_string_lossy().into_owned())
}

fn default_db_path() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mcpd-docs/index.db")
        .to_string_lossy()
        .into_owned()
}

fn default_debounce() -> u64 {
    500
}

fn default_timeout() -> u64 {
    300
}

fn default_notify() -> String {
    "dbus".to_string()
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            db: default_db_path(),
            watch_debounce_ms: default_debounce(),
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
            .join("mcpd-docs/config.toml")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                socket: default_socket(),
                tcp: None,
            },
            index: IndexConfig::default(),
            approval: ApprovalConfig::default(),
            agents: Vec::new(),
            permissions: HashMap::new(),
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
        assert_eq!(config.server.tcp.unwrap(), "127.0.0.1:9315");
        assert!(config.agents.is_empty());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[index]
db = "/tmp/test.db"
watch_debounce_ms = 1000

[approval]
timeout_secs = 60
notify = "none"

[[agents]]
name = "claude"
token_hash = "abc123"
permissions = "developer"

[permissions.developer]
allow = ["~/Documents/**"]
deny = ["**/.env"]
operations = ["read", "search", "list"]
approve = ["write"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.agents.len(), 1);
        assert_eq!(config.agents[0].name, "claude");
        let dev = &config.permissions["developer"];
        assert_eq!(dev.allow, vec!["~/Documents/**"]);
        assert_eq!(dev.deny, vec!["**/.env"]);
        assert_eq!(dev.operations, vec!["read", "search", "list"]);
        assert_eq!(dev.approve, vec!["write"]);
    }

    #[test]
    fn default_config_is_valid() {
        let config = Config::default();
        assert!(config.agents.is_empty());
        assert_eq!(config.approval.timeout_secs, 300);
        assert_eq!(config.index.watch_debounce_ms, 500);
    }

    #[test]
    fn generate_token_format() {
        let token = generate_token();
        assert!(token.starts_with("mcd_"));
        assert!(token.len() > 10);
    }
}
