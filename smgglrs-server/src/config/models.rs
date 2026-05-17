use serde::Deserialize;

/// Configuration for a model.
///
/// Models can be loaded from local files (ONNX) or pulled from registries
/// and served via a runtime backend.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct ModelConfig {
    /// Path to a local model file (ONNX). Used directly when no `source` is set.
    #[serde(default)]
    pub model_path: Option<String>,
    /// Hub source URI (e.g. `ollama://granite3.3:8b`, `hf://org/repo`).
    /// When set, the model is pulled and cached via smgglrs-model-hub.
    #[serde(default)]
    pub source: Option<String>,
    /// Path to the HuggingFace tokenizer.json file.
    #[serde(default)]
    pub tokenizer_path: Option<String>,
    /// Model task: "embedding", "classification", "chat", or "generate".
    #[serde(default = "default_model_task")]
    pub task: String,
    /// Execution device for ONNX models: "cpu", "cuda", "openvino",
    /// "openvino:AUTO", "openvino:NPU", "openvino:GPU".
    /// Defaults to "cpu" if not specified.
    #[serde(default)]
    pub device: Option<String>,
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
    /// Used for chat/generate tasks served via smgglrs-model-runtime.
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
    /// KV cache quantization type for runtime-served models.
    #[serde(default)]
    pub cache_type: Option<smgglrs_model_runtime::KvCacheType>,
    /// Speculative decoding configuration.
    #[serde(default)]
    pub speculative: Option<SpeculativeModelConfig>,
    /// Operator-defined agentic capabilities for model selection.
    #[serde(default)]
    pub agentic: Option<AgenticConfig>,
}

/// Speculative decoding configuration for runtime-served models.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct SpeculativeModelConfig {
    pub draft_model: String,
    #[serde(default = "default_draft_tokens")]
    pub draft_tokens: u32,
    #[serde(default)]
    pub draft_min_p: f32,
}

fn default_draft_tokens() -> u32 {
    5
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
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
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
    pub fn to_agentic_meta(&self) -> smgglrs_model_hub::AgenticMeta {
        smgglrs_model_hub::AgenticMeta {
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

/// Default resource budget for teams and flows.
///
/// Defaults are generous for autonomous operation — agents get
/// enough iterations, time, and depth to converge on thorough
/// results. The operator tunes down via config for cost control.
///
/// ```toml
/// [budget]
/// max_agents = 50       # total across all teams/subflows
/// max_depth = 5         # escalation nesting depth
/// timeout_secs = 1800   # 30 minutes per flow tree
/// max_iterations = 200  # per agent ReAct iterations
/// max_parallel = 4      # concurrent agents (GPU bound)
/// checkpoint = true     # enable SQLite checkpoint for crash recovery
/// checkpoint_db = "~/.local/share/smgglrs/checkpoints.db"
/// ```
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
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
    /// Maximum tool output tokens before truncation (0 = disabled).
    #[serde(default = "default_max_tool_output_tokens")]
    pub max_tool_output_tokens: usize,
    /// Truncation strategy: "truncate", "head_tail", "summarize".
    #[serde(default = "default_truncation_strategy")]
    pub truncation_strategy: String,
    /// Ratio of budget allocated to head in head_tail strategy.
    #[serde(default = "default_head_ratio")]
    pub head_ratio: f32,
    /// Enable SQLite-backed checkpointing for DAG execution crash resilience.
    #[serde(default)]
    pub checkpoint: bool,
    /// Path to the checkpoint SQLite database.
    #[serde(default = "default_checkpoint_db")]
    pub checkpoint_db: String,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_agents: default_budget_max_agents(),
            max_depth: default_budget_max_depth(),
            timeout_secs: default_budget_timeout(),
            max_iterations: default_budget_max_iterations(),
            max_parallel: default_budget_max_parallel(),
            max_tool_output_tokens: default_max_tool_output_tokens(),
            truncation_strategy: default_truncation_strategy(),
            head_ratio: default_head_ratio(),
            checkpoint: false,
            checkpoint_db: default_checkpoint_db(),
        }
    }
}

fn default_max_tool_output_tokens() -> usize {
    0
}

fn default_truncation_strategy() -> String {
    "head_tail".to_string()
}

fn default_head_ratio() -> f32 {
    0.7
}

fn default_budget_max_agents() -> u32 {
    50
}

fn default_budget_max_depth() -> u32 {
    5
}

fn default_budget_timeout() -> u64 {
    3600
}

fn default_budget_max_parallel() -> usize {
    2
}

fn default_budget_max_iterations() -> usize {
    200
}

fn default_checkpoint_db() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("smgglrs/checkpoints.db")
        .display()
        .to_string()
}

