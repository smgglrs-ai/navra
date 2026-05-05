use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
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
    #[serde(default)]
    pub registry: Option<RegistryModuleConfig>,
    #[serde(default)]
    pub memory: Option<MemoryModuleConfig>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct MemoryModuleConfig {
    /// PII filter profile for memory ingestion and audit logs.
    /// Uses the same profiles as safety: "standard", "secrets-only", "none".
    /// Default: "standard".
    #[serde(default = "default_pii_filter")]
    pub pii_filter: String,
    /// Auto-delete knowledge entries older than N days.
    /// Default: None (keep forever).
    #[serde(default)]
    pub retention_days: Option<u32>,
    /// Stricter TTL for entries flagged as containing PII.
    /// Default: 30 days.
    #[serde(default = "default_pii_retention_days")]
    pub pii_retention_days: Option<u32>,
    /// Auto-delete audit log entries older than N days.
    /// Default: 365 days (1 year).
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: Option<u32>,
}

fn default_pii_filter() -> String {
    "standard".to_string()
}

fn default_pii_retention_days() -> Option<u32> {
    Some(30)
}

fn default_audit_retention_days() -> Option<u32> {
    Some(365)
}

impl Default for MemoryModuleConfig {
    fn default() -> Self {
        Self {
            pii_filter: default_pii_filter(),
            retention_days: None,
            pii_retention_days: default_pii_retention_days(),
            audit_retention_days: default_audit_retention_days(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct GitModuleConfig {
    #[serde(default = "super::default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct VisionModuleConfig {
    #[serde(default = "super::default_true")]
    pub enabled: bool,
    /// Name of the vision model in [models.*] config.
    #[serde(default = "default_vision_model")]
    pub model: String,
}

fn default_vision_model() -> String {
    "vision".to_string()
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct RagModuleConfig {
    #[serde(default = "super::default_true")]
    pub enabled: bool,
    /// Database path. Defaults to the same directory as docs, separate file.
    #[serde(default = "default_rag_db_path")]
    pub db: String,
    /// Path to the ONNX cross-encoder model for reranking (optional).
    #[serde(default)]
    pub reranker_model_path: Option<String>,
    /// Path to the tokenizer.json for the cross-encoder model (optional).
    #[serde(default)]
    pub reranker_tokenizer_path: Option<String>,
    /// Query cache TTL in seconds (default: 300). Set to 0 to disable caching.
    #[serde(default = "default_query_cache_ttl_secs")]
    pub query_cache_ttl_secs: u64,
    /// Maximum number of cached query entries (default: 1000).
    #[serde(default = "default_query_cache_max_entries")]
    pub query_cache_max_entries: usize,
}

fn default_query_cache_ttl_secs() -> u64 {
    300
}

fn default_query_cache_max_entries() -> usize {
    1000
}

pub(super) fn default_rag_db_path() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("smgglrs/rag.db")
        .to_string_lossy()
        .into_owned()
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct VoiceModuleConfig {
    #[serde(default = "super::default_true")]
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
    /// Maximum recording duration in seconds (default: 30).
    #[serde(default = "default_max_record_secs")]
    pub max_record_secs: u64,
    /// Silence timeout in milliseconds before auto-stopping recording (default: 1500).
    #[serde(default = "default_silence_timeout_ms")]
    pub silence_timeout_ms: u64,
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

fn default_max_record_secs() -> u64 {
    30
}

fn default_silence_timeout_ms() -> u64 {
    1500
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct DocsModuleConfig {
    #[serde(default = "super::default_true")]
    pub enabled: bool,
    #[serde(default = "default_db_path")]
    pub db: String,
    /// Default root path for file_tree when no path argument is given.
    /// Overrides the top-level `cognitive_core` setting for docs routing.
    #[serde(default)]
    pub default_root: Option<String>,
    /// Directories to watch for auto-reindexing.
    #[serde(default)]
    pub watch: Vec<String>,
}

pub(super) fn default_db_path() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("smgglrs/index.db")
        .to_string_lossy()
        .into_owned()
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct RegistryModuleConfig {
    #[serde(default = "super::default_true")]
    pub enabled: bool,
    /// Cache TTL for registry responses in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
}

fn default_cache_ttl() -> u64 {
    3600
}

impl Default for RegistryModuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_ttl_secs: default_cache_ttl(),
        }
    }
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

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct ApprovalConfig {
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Time-to-live for cached approval grants in seconds (default: 300 = 5 min).
    /// After approval, the agent has this long to retry the operation.
    #[serde(default = "default_grant_ttl")]
    pub grant_ttl_secs: u64,
    #[serde(default = "default_notify")]
    pub notify: String,
}

fn default_timeout() -> u64 {
    300
}

fn default_grant_ttl() -> u64 {
    300
}

fn default_notify() -> String {
    "dbus".to_string()
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout(),
            grant_ttl_secs: default_grant_ttl(),
            notify: default_notify(),
        }
    }
}
