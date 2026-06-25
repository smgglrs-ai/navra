use serde::Deserialize;
use std::collections::HashMap;

// Re-export ModelConfig from navra-server's config module isn't possible
// since navra-server depends on us. Instead, define a server-side config
// that mirrors the model fields we need. navra-server converts its
// ModelConfig into this when constructing a ModelServer.

/// Configuration for the model server.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelServerConfig {
    /// Models to load, keyed by name.
    #[serde(default)]
    pub models: HashMap<String, ModelEntry>,
    /// Bind address for standalone mode.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Maximum VRAM budget in bytes (0 = no limit).
    #[serde(default)]
    pub vram_budget: u64,
    /// VRAM reserved for desktop/display (bytes, default: 2GB).
    #[serde(default = "default_desktop_reservation")]
    pub desktop_reservation: u64,
}

impl Default for ModelServerConfig {
    fn default() -> Self {
        Self {
            models: HashMap::new(),
            bind: default_bind(),
            vram_budget: 0,
            desktop_reservation: default_desktop_reservation(),
        }
    }
}

fn default_bind() -> String {
    "127.0.0.1:9316".to_string()
}

fn default_desktop_reservation() -> u64 {
    2 * 1024 * 1024 * 1024 // 2 GB
}

/// A single model entry in the server config.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelEntry {
    /// Path to a local model file.
    #[serde(default)]
    pub model_path: Option<String>,
    /// Hub source URI (e.g. `ollama://model`, `hf://org/repo`).
    #[serde(default)]
    pub source: Option<String>,
    /// Path to HuggingFace tokenizer.json.
    #[serde(default)]
    pub tokenizer_path: Option<String>,
    /// Model task: "embedding", "classification", "chat", "generate".
    #[serde(default = "default_task")]
    pub task: String,
    /// ONNX device: "cpu", "cuda", "openvino", etc.
    #[serde(default)]
    pub device: Option<String>,
    /// Embedding dimensions.
    #[serde(default)]
    pub dimensions: Option<usize>,
    /// Classification labels.
    #[serde(default)]
    pub labels: Vec<String>,
    /// Safety classification threshold.
    #[serde(default = "default_threshold")]
    pub threshold: Option<f32>,
    /// Model format: "gguf", "safetensors", "awq", "gptq".
    #[serde(default)]
    pub format: Option<String>,
    /// Execution mode override.
    #[serde(default)]
    pub execution_mode: Option<navra_model_runtime::ExecutionMode>,
    /// Runtime: "auto", "direct", "podman", "ollama", "ogx", "none".
    #[serde(default)]
    pub runtime: Option<String>,
    /// Context window size.
    #[serde(default)]
    pub context_size: Option<u32>,
    /// Parallel request slots.
    #[serde(default)]
    pub parallel: Option<u32>,
    /// Model name for OpenAI-compatible API.
    #[serde(default)]
    pub model_name: Option<String>,
    /// KV cache quantization.
    #[serde(default)]
    pub cache_type: Option<navra_model_runtime::KvCacheType>,
    /// Speculative decoding config.
    #[serde(default)]
    pub speculative: Option<SpeculativeEntry>,
    /// Base URL for remote model servers.
    #[serde(default)]
    pub base_url: Option<String>,
    /// API key for authenticated endpoints.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Data locality: "local" or "remote".
    #[serde(default)]
    pub locality: Option<String>,
}

/// Speculative decoding config entry.
#[derive(Debug, Clone, Deserialize)]
pub struct SpeculativeEntry {
    pub draft_model: String,
    #[serde(default = "default_draft_tokens")]
    pub draft_tokens: u32,
    #[serde(default)]
    pub draft_min_p: f32,
}

fn default_task() -> String {
    "embedding".to_string()
}

fn default_threshold() -> Option<f32> {
    Some(0.5)
}

fn default_draft_tokens() -> u32 {
    5
}
