mod agents;
pub mod import;
mod models;
mod modules;
mod permissions;
mod server;

use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

pub use crate::grpc_manager::GrpcModuleConfig;
pub use agents::{AgentConfig, OpenApiAuthConfig, UpstreamConfig};
pub use models::{BudgetConfig, ModelConfig};
pub use modules::{ApprovalConfig, ModulesConfig};
pub use permissions::{DomainRuleConfig, PermissionSet, PiiPatternConfig, ToolRuleConfig};
pub use server::{RegistryEntry, ServerConfig};

pub use security::{
    MonitoringServerConfig, StatisticalGuardrailServerConfig, TemporalContractServerConfig,
};
mod security;

fn default_true() -> bool {
    true
}

/// Top-level navra configuration, loaded from `~/.config/navra/config.toml`.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct Config {
    /// Server transport, identity, and container settings.
    pub server: ServerConfig,
    /// Per-module enablement and module-specific settings.
    #[serde(default)]
    pub modules: ModulesConfig,
    /// Human-in-the-loop approval workflow settings.
    #[serde(default)]
    pub approval: ApprovalConfig,
    /// Registered agent identities and their permission bindings.
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
    /// Named permission sets referenced by agents.
    #[serde(default)]
    pub permissions: HashMap<String, PermissionSet>,
    /// Upstream MCP servers to proxy through the gateway.
    #[serde(default)]
    pub upstream: Vec<UpstreamConfig>,
    /// Credential label → backend source mappings.
    /// Only credentials listed here are accessible to agents.
    #[serde(default)]
    pub credentials: HashMap<String, navra_core::credentials::CredentialMapping>,
    /// Named model definitions (embedding, classification, chat, generate).
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
    /// navra's own modules and connected upstream servers.
    #[serde(default)]
    pub registry: Vec<RegistryEntry>,
    /// Default resource budget for teams and flows.
    #[serde(default)]
    pub budget: BudgetConfig,
    /// Custom PII patterns applied globally to all safety pipelines.
    /// Categories defined here are treated as PII for IFC labeling.
    #[serde(default)]
    pub pii_patterns: Vec<PiiPatternConfig>,
    /// Out-of-process gRPC modules.
    #[serde(default)]
    pub grpc_modules: Vec<GrpcModuleConfig>,
    /// Detect-only monitoring agent configuration.
    #[serde(default)]
    pub monitoring: MonitoringServerConfig,
    /// Statistical guardrail configuration for anomaly detection.
    #[serde(default)]
    pub statistical: StatisticalGuardrailServerConfig,
    /// Temporal behavioral contracts for trajectory-level policy enforcement.
    #[serde(default)]
    pub temporal_contracts: TemporalContractServerConfig,
    /// Cost-aware model routing configuration.
    #[serde(default)]
    pub routing: navra_core::hooks::RoutingConfig,
    /// Event-driven triggers that start flows automatically.
    #[serde(default)]
    pub triggers: Vec<crate::triggers::TriggerConfig>,
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

    pub fn default_config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("navra/config.toml")
    }

    pub fn git_enabled(&self) -> bool {
        self.modules
            .git
            .as_ref()
            .map(|g| g.enabled)
            .unwrap_or(false)
    }

    pub fn gitlab_enabled(&self) -> bool {
        self.modules
            .gitlab
            .as_ref()
            .map(|g| g.enabled)
            .unwrap_or(false)
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

    pub fn registry_enabled(&self) -> bool {
        self.modules
            .registry
            .as_ref()
            .map(|r| r.enabled)
            .unwrap_or(false)
    }

    pub fn registry_cache_ttl_secs(&self) -> u64 {
        self.modules
            .registry
            .as_ref()
            .map(|r| r.cache_ttl_secs)
            .unwrap_or(3600)
    }

    pub fn memory_pii_filter(&self) -> &str {
        self.modules
            .memory
            .as_ref()
            .map(|m| m.pii_filter.as_str())
            .unwrap_or("standard")
    }

    pub fn memory_retention_days(&self) -> Option<u32> {
        self.modules.memory.as_ref().and_then(|m| m.retention_days)
    }

    pub fn memory_pii_retention_days(&self) -> Option<u32> {
        self.modules
            .memory
            .as_ref()
            .and_then(|m| m.pii_retention_days)
            .or(Some(30))
    }

    pub fn memory_audit_retention_days(&self) -> Option<u32> {
        self.modules
            .memory
            .as_ref()
            .and_then(|m| m.audit_retention_days)
            .or(Some(365))
    }

    pub fn pii_model_dir(&self) -> std::path::PathBuf {
        self.server
            .pii_model_path
            .as_ref()
            .map(|p| {
                let expanded = if p.starts_with("~/") {
                    dirs::home_dir()
                        .map(|h| h.join(&p[2..]))
                        .unwrap_or_else(|| std::path::PathBuf::from(p))
                } else {
                    std::path::PathBuf::from(p)
                };
                expanded
            })
            .unwrap_or_else(navra_core::safety::default_pii_ner_model_dir)
    }

    pub fn pii_multilingual_model_dir(&self) -> std::path::PathBuf {
        self.server
            .pii_multilingual_model_path
            .as_ref()
            .map(|p| {
                if p.starts_with("~/") {
                    dirs::home_dir()
                        .map(|h| h.join(&p[2..]))
                        .unwrap_or_else(|| std::path::PathBuf::from(p))
                } else {
                    std::path::PathBuf::from(p)
                }
            })
            .unwrap_or_else(navra_core::safety::default_pii_ner_multilingual_model_dir)
    }

    pub fn rag_db_path(&self) -> String {
        self.modules
            .rag
            .as_ref()
            .map(|r| r.db.clone())
            .unwrap_or_else(modules::default_rag_db_path)
    }

    pub fn rag_reranker_model_path(&self) -> Option<String> {
        self.modules
            .rag
            .as_ref()
            .and_then(|r| r.reranker_model_path.clone())
    }

    pub fn rag_reranker_tokenizer_path(&self) -> Option<String> {
        self.modules
            .rag
            .as_ref()
            .and_then(|r| r.reranker_tokenizer_path.clone())
    }

    pub fn rag_query_cache_ttl_secs(&self) -> u64 {
        self.modules
            .rag
            .as_ref()
            .map(|r| r.query_cache_ttl_secs)
            .unwrap_or(300)
    }

    pub fn rag_query_cache_max_entries(&self) -> usize {
        self.modules
            .rag
            .as_ref()
            .map(|r| r.query_cache_max_entries)
            .unwrap_or(1000)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                socket: server::default_socket(),
                tcp: None,
                hook_timeout_secs: 10,
                discovery: None,
                identity: None,
                openshell_auth: None,
                pii_model_path: None,
                pii_multilingual_model_path: None,
                containerized: None,
                allow_direct_execution: false,
                agent_image: "localhost/navra-agent:latest".to_string(),
                model_server_image: "ghcr.io/ggerganov/llama.cpp:server-cuda".to_string(),
                openshell_gateway: None,
                container_memory: "2g".to_string(),
                container_cpus: "2".to_string(),
                container_pids: 256,
                mcp_version: "2026-07-28".to_string(),
                agent_signature_policy: "warn".to_string(),
                config_watch: false,
                config_watch_debounce_ms: 50,
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
            pii_patterns: Vec::new(),
            grpc_modules: Vec::new(),
            monitoring: MonitoringServerConfig::default(),
            statistical: StatisticalGuardrailServerConfig::default(),
            temporal_contracts: TemporalContractServerConfig::default(),
            routing: navra_core::hooks::RoutingConfig::default(),
            triggers: Vec::new(),
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
mod tests;
