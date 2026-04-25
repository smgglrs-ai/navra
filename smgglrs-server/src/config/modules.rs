use serde::Deserialize;
use std::path::PathBuf;

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
    #[serde(default)]
    pub registry: Option<RegistryModuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitModuleConfig {
    #[serde(default = "super::default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct RagModuleConfig {
    #[serde(default = "super::default_true")]
    pub enabled: bool,
    /// Database path. Defaults to the same directory as docs, separate file.
    #[serde(default = "default_rag_db_path")]
    pub db: String,
}

pub(super) fn default_rag_db_path() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("smgglrs/rag.db")
        .to_string_lossy()
        .into_owned()
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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
