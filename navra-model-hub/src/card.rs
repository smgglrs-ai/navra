//! Composite model card: vendor + operator + runtime metadata.
//!
//! A model card combines three layers of metadata about a model:
//!
//! - **Vendor**: Auto-populated from registry APIs at pull time
//!   (Ollama manifest, HuggingFace model info, OCI referrer artifact).
//! - **Agentic**: Operator-defined capabilities for agent orchestration
//!   (strengths, weaknesses, task suitability). Set in config.toml.
//! - **Runtime**: Learned statistics from actual agent executions
//!   (success rates, latency, token efficiency). Updated after each run.
//!
//! Cards are stored as JSON in `~/.local/share/navra/models/cards/`.
//! The schema is designed for eventual upstream contribution to
//! Kubeflow Model Registry (kubeflow/model-registry#449).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Schema version. Bump on breaking changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Composite model card combining vendor, operator, and runtime metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCard {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// Model URI this card describes.
    pub model_uri: String,
    /// Vendor-provided metadata (auto-populated from registry).
    #[serde(default)]
    pub vendor: VendorMeta,
    /// Operator-defined agentic capabilities.
    #[serde(default)]
    pub agentic: AgenticMeta,
    /// Runtime statistics (learned over time).
    #[serde(default)]
    pub runtime: RuntimeMeta,
}

impl ModelCard {
    /// Create a new card with only the URI set.
    pub fn new(model_uri: &str) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            model_uri: model_uri.to_string(),
            vendor: VendorMeta::default(),
            agentic: AgenticMeta::default(),
            runtime: RuntimeMeta::default(),
        }
    }

    /// The model name for inference API calls (Ollama, vLLM, OpenAI).
    /// Strips hub URI prefixes — agents call models by name, not by
    /// registry address.
    pub fn inference_name(&self) -> &str {
        for prefix in ["ollama://", "hf://", "oci://"] {
            if let Some(bare) = self.model_uri.strip_prefix(prefix) {
                return bare;
            }
        }
        &self.model_uri
    }

    /// Merge operator-defined agentic metadata into this card.
    /// Non-empty fields in `other` overwrite existing values.
    pub fn merge_agentic(&mut self, other: &AgenticMeta) {
        if !other.strengths.is_empty() {
            self.agentic.strengths = other.strengths.clone();
        }
        if !other.weaknesses.is_empty() {
            self.agentic.weaknesses = other.weaknesses.clone();
        }
        if !other.recommended_tasks.is_empty() {
            self.agentic.recommended_tasks = other.recommended_tasks.clone();
        }
        if !other.avoid_tasks.is_empty() {
            self.agentic.avoid_tasks = other.avoid_tasks.clone();
        }
        if other.tool_use.is_some() {
            self.agentic.tool_use = other.tool_use.clone();
        }
        if other.cost_tier.is_some() {
            self.agentic.cost_tier = other.cost_tier.clone();
        }
        if other.speed_tier.is_some() {
            self.agentic.speed_tier = other.speed_tier.clone();
        }
        if other.max_agents.is_some() {
            self.agentic.max_agents = other.max_agents;
        }
        if other.reasoning.is_some() {
            self.agentic.reasoning = other.reasoning.clone();
        }
        if other.json_compliance.is_some() {
            self.agentic.json_compliance = other.json_compliance.clone();
        }
        if other.locality.is_some() {
            self.agentic.locality = other.locality.clone();
        }
    }

    /// Record a completed tool-use run, updating runtime stats.
    pub fn record_run(&mut self, task_type: &str, success: bool, latency_ms: u64, tokens: u32) {
        self.runtime.total_calls += 1;
        self.runtime.total_tokens += tokens as u64;

        // Update rolling average latency
        let n = self.runtime.total_calls as f64;
        let prev = self.runtime.avg_latency_ms;
        self.runtime.avg_latency_ms = prev + (latency_ms as f64 - prev) / n;

        // Update rolling success rate
        let prev_rate = self.runtime.success_rate;
        let s = if success { 1.0 } else { 0.0 };
        self.runtime.success_rate = prev_rate + (s - prev_rate) / n;

        // Per-task stats
        let task_stats = self
            .runtime
            .by_task
            .entry(task_type.to_string())
            .or_default();
        task_stats.calls += 1;
        if success {
            task_stats.successes += 1;
        }
        task_stats.success_rate = task_stats.successes as f64 / task_stats.calls as f64;
    }

    /// Locality: "local" if source is Ollama/File/OCI-local, "remote" otherwise.
    pub fn locality(&self) -> &str {
        match self.vendor.source.as_deref() {
            Some("ollama") | Some("file") => "local",
            Some("vertex-ai") | Some("openai") | Some("anthropic") => "remote",
            Some("huggingface") | Some("oci") => {
                // Could be either; check if runtime is local
                if self.vendor.runtime.as_deref() == Some("remote") {
                    "remote"
                } else {
                    "local"
                }
            }
            _ => "unknown",
        }
    }
}

/// Vendor-provided metadata, auto-populated from registry APIs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VendorMeta {
    /// Registry source: "ollama", "huggingface", "oci", "file",
    /// "vertex-ai", "openai".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Model family (e.g. "granite", "llama", "mistral").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Parameter count as human-readable string (e.g. "8B", "70B").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<String>,
    /// Quantization level (e.g. "Q4_K_M", "fp16").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantization: Option<String>,
    /// Context window size in tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u32>,
    /// Model format (e.g. "gguf", "onnx", "safetensors").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// HuggingFace-style task tags (e.g. "text-generation", "text-classification").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tasks: Vec<String>,
    /// License identifier (e.g. "Apache-2.0", "MIT").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Supported languages (ISO 639 codes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub languages: Vec<String>,
    /// Where the model runs: "local", "remote", or runtime name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Raw custom properties from the registry (Kubeflow customProperties).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Operator-defined agentic capabilities.
///
/// These fields describe what the model is good at for agent
/// orchestration. No existing registry provides this natively;
/// it is set by the operator in config.toml or learned at runtime.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgenticMeta {
    /// What this model excels at (e.g. "code generation", "fast inference").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strengths: Vec<String>,
    /// Known limitations (e.g. "limited reasoning", "no tool use").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weaknesses: Vec<String>,
    /// Task types this model is recommended for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recommended_tasks: Vec<String>,
    /// Task types to avoid with this model.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub avoid_tasks: Vec<String>,
    /// Tool-use capability level: "none", "basic", "advanced".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_use: Option<String>,
    /// Cost tier: "free", "low", "medium", "high".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_tier: Option<String>,
    /// Speed tier: "fast", "medium", "slow".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed_tier: Option<String>,
    /// Max concurrent agents recommended for this model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_agents: Option<u32>,
    /// Reasoning depth: "basic", "extended" (chain-of-thought/thinking mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    /// JSON schema compliance: "strict" (guaranteed), "best-effort".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_compliance: Option<String>,
    /// Locality: "local" (data stays on device), "remote" (cloud API).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
}

/// Runtime statistics learned from actual agent executions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeMeta {
    /// Total tool-use calls made with this model.
    #[serde(default)]
    pub total_calls: u64,
    /// Total tokens consumed across all calls.
    #[serde(default)]
    pub total_tokens: u64,
    /// Rolling average latency in milliseconds.
    #[serde(default)]
    pub avg_latency_ms: f64,
    /// Rolling success rate (0.0 to 1.0).
    #[serde(default)]
    pub success_rate: f64,
    /// Per-task-type statistics.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub by_task: HashMap<String, TaskStats>,
}

/// Statistics for a specific task type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskStats {
    /// Total calls for this task type.
    pub calls: u64,
    /// Number of successful calls.
    pub successes: u64,
    /// Success rate (0.0 to 1.0).
    pub success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_card_has_defaults() {
        let card = ModelCard::new("ollama://granite-code:3b");
        assert_eq!(card.schema_version, SCHEMA_VERSION);
        assert_eq!(card.model_uri, "ollama://granite-code:3b");
        assert!(card.vendor.source.is_none());
        assert!(card.agentic.strengths.is_empty());
        assert_eq!(card.runtime.total_calls, 0);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut card = ModelCard::new("hf://ibm-granite/granite-3.3-8b");
        card.vendor.family = Some("granite".into());
        card.vendor.parameters = Some("8B".into());
        card.vendor.context_window = Some(128_000);
        card.vendor.tasks = vec!["text-generation".into()];
        card.agentic.strengths = vec!["code generation".into()];
        card.agentic.tool_use = Some("advanced".into());
        card.agentic.cost_tier = Some("free".into());

        let json = serde_json::to_string_pretty(&card).unwrap();
        let restored: ModelCard = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.model_uri, card.model_uri);
        assert_eq!(restored.vendor.family, card.vendor.family);
        assert_eq!(restored.agentic.strengths, card.agentic.strengths);
    }

    #[test]
    fn merge_agentic_overwrites_nonempty() {
        let mut card = ModelCard::new("ollama://test:latest");
        card.agentic.strengths = vec!["original".into()];
        card.agentic.cost_tier = Some("free".into());

        let override_meta = AgenticMeta {
            strengths: vec!["overridden".into()],
            cost_tier: None, // should NOT overwrite
            speed_tier: Some("fast".into()),
            ..Default::default()
        };

        card.merge_agentic(&override_meta);
        assert_eq!(card.agentic.strengths, vec!["overridden"]);
        assert_eq!(card.agentic.cost_tier, Some("free".into())); // preserved
        assert_eq!(card.agentic.speed_tier, Some("fast".into())); // added
    }

    #[test]
    fn record_run_updates_stats() {
        let mut card = ModelCard::new("ollama://test:latest");

        card.record_run("code_review", true, 500, 100);
        assert_eq!(card.runtime.total_calls, 1);
        assert_eq!(card.runtime.success_rate, 1.0);
        assert_eq!(card.runtime.avg_latency_ms, 500.0);

        card.record_run("code_review", false, 1000, 200);
        assert_eq!(card.runtime.total_calls, 2);
        assert_eq!(card.runtime.success_rate, 0.5);
        assert_eq!(card.runtime.avg_latency_ms, 750.0);

        let task = card.runtime.by_task.get("code_review").unwrap();
        assert_eq!(task.calls, 2);
        assert_eq!(task.successes, 1);
        assert_eq!(task.success_rate, 0.5);
    }

    #[test]
    fn record_run_multiple_task_types() {
        let mut card = ModelCard::new("ollama://test:latest");
        card.record_run("planning", true, 200, 50);
        card.record_run("code_review", true, 800, 200);
        card.record_run("planning", false, 300, 60);

        assert_eq!(card.runtime.total_calls, 3);
        assert_eq!(card.runtime.by_task.len(), 2);

        let planning = card.runtime.by_task.get("planning").unwrap();
        assert_eq!(planning.calls, 2);
        assert_eq!(planning.successes, 1);
    }

    #[test]
    fn locality_detection() {
        let mut card = ModelCard::new("ollama://test:latest");
        card.vendor.source = Some("ollama".into());
        assert_eq!(card.locality(), "local");

        card.vendor.source = Some("vertex-ai".into());
        assert_eq!(card.locality(), "remote");

        card.vendor.source = Some("openai".into());
        assert_eq!(card.locality(), "remote");

        card.vendor.source = None;
        assert_eq!(card.locality(), "unknown");
    }

    #[test]
    fn skip_serializing_empty_fields() {
        let card = ModelCard::new("ollama://test:latest");
        let json = serde_json::to_string(&card).unwrap();
        // Empty vecs and None fields should be omitted
        assert!(!json.contains("strengths"));
        assert!(!json.contains("source"));
        assert!(!json.contains("by_task"));
    }

    #[test]
    fn deserialize_minimal_json() {
        let json = r#"{
            "schema_version": 1,
            "model_uri": "ollama://granite:3b"
        }"#;
        let card: ModelCard = serde_json::from_str(json).unwrap();
        assert_eq!(card.model_uri, "ollama://granite:3b");
        assert!(card.vendor.family.is_none());
        assert!(card.agentic.strengths.is_empty());
        assert_eq!(card.runtime.total_calls, 0);
    }
}
