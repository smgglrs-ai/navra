//! Cost-aware model routing hook.
//!
//! A pre-hook that classifies incoming tool calls by complexity and
//! routes them to different model tiers. Classification is heuristic-based
//! (v1): tool name pattern matching and input size estimation.
//!
//! The routing decision is injected into the tool arguments as
//! `_routing_tier` and `_routing_model` so the model backend can read it.

use super::{Hook, HookDecision};
use navra_auth::auth::CallContext;

/// A model tier for cost-aware routing.
#[derive(Debug, Clone)]
pub struct ModelTier {
    /// Tier name (e.g. "small", "medium", "large").
    pub name: String,
    /// Model identifier for this tier (e.g. "qwen2.5:3b").
    pub model: String,
    /// Maximum estimated input tokens for this tier.
    pub max_tokens: usize,
    /// Tool name glob patterns that route to this tier.
    pub patterns: Vec<String>,
}

/// Pre-hook that classifies requests and injects routing metadata.
///
/// Routing decision is communicated by injecting `_routing_tier` and
/// `_routing_model` keys into the tool arguments. These are read by
/// the model backend to select the appropriate model.
pub struct RoutingHook {
    /// Model tiers, ordered from smallest to largest.
    tiers: Vec<ModelTier>,
    /// Default tier name when no pattern or size rule matches.
    default_tier: String,
}

impl RoutingHook {
    /// Create a new routing hook with the given tiers and default.
    ///
    /// Tiers should be ordered from smallest (cheapest) to largest.
    pub fn new(tiers: Vec<ModelTier>, default_tier: impl Into<String>) -> Self {
        Self {
            tiers,
            default_tier: default_tier.into(),
        }
    }

    /// Classify a tool call and return the matching tier name.
    ///
    /// Classification order:
    /// 1. Explicit `_routing_hint` in arguments (passthrough)
    /// 2. Tool name matched against tier glob patterns
    /// 3. Estimated input size compared against tier max_tokens
    /// 4. Default tier
    fn classify(&self, tool_name: &str, args: &serde_json::Value) -> &str {
        // 1. Explicit routing hint in arguments
        if let Some(hint) = args.get("_routing_hint").and_then(|v| v.as_str()) {
            if self.tiers.iter().any(|t| t.name == hint) {
                return self
                    .tiers
                    .iter()
                    .find(|t| t.name == hint)
                    .map(|t| t.name.as_str())
                    .unwrap();
            }
        }

        // 2. Tool name pattern matching
        for tier in &self.tiers {
            if tier.patterns.iter().any(|p| glob_matches(p, tool_name)) {
                return &tier.name;
            }
        }

        // 3. Input size estimation
        let input_size = estimate_tokens(&args.to_string());
        for tier in &self.tiers {
            if input_size <= tier.max_tokens {
                return &tier.name;
            }
        }

        // 4. Default
        &self.default_tier
    }

    /// Look up the model for a tier name.
    fn model_for_tier(&self, tier_name: &str) -> Option<&str> {
        self.tiers
            .iter()
            .find(|t| t.name == tier_name)
            .map(|t| t.model.as_str())
    }
}

#[async_trait::async_trait]
impl Hook for RoutingHook {
    fn name(&self) -> &str {
        "routing"
    }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        _ctx: &CallContext,
    ) -> HookDecision {
        let tier_name = self.classify(tool_name, arguments);
        let model = self.model_for_tier(tier_name).unwrap_or("unknown");

        tracing::debug!(
            tool = %tool_name,
            tier = %tier_name,
            model = %model,
            "Routing decision"
        );

        let mut modified = arguments.clone();
        modified["_routing_tier"] = serde_json::json!(tier_name);
        modified["_routing_model"] = serde_json::json!(model);

        HookDecision::ModifyArgs(modified)
    }
}

/// Simple glob matching supporting `*` as a wildcard.
///
/// Supports patterns like `"file_*"`, `"*_create"`, `"git_status"`.
fn glob_matches(pattern: &str, text: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|p| p.matches(text))
        .unwrap_or(false)
}

/// Estimate token count from a string.
///
/// Uses a simple heuristic: ~4 characters per token (GPT-family average).
/// This is intentionally rough — exact tokenization depends on the model
/// and isn't needed for tier routing.
fn estimate_tokens(text: &str) -> usize {
    // Rough estimate: 1 token per 4 chars, minimum 1
    (text.len() / 4).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_auth::auth::AgentIdentity;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
    }

    fn test_tiers() -> Vec<ModelTier> {
        vec![
            ModelTier {
                name: "small".to_string(),
                model: "qwen2.5:3b".to_string(),
                max_tokens: 500,
                patterns: vec![
                    "file_read".to_string(),
                    "git_status".to_string(),
                    "git_log".to_string(),
                ],
            },
            ModelTier {
                name: "medium".to_string(),
                model: "granite3:8b".to_string(),
                max_tokens: 2000,
                patterns: vec![
                    "file_write".to_string(),
                    "git_commit".to_string(),
                    "github_*".to_string(),
                ],
            },
            ModelTier {
                name: "large".to_string(),
                model: "llama3.3:70b".to_string(),
                max_tokens: 8000,
                patterns: vec!["*_create".to_string(), "*_review".to_string()],
            },
        ]
    }

    fn test_hook() -> RoutingHook {
        RoutingHook::new(test_tiers(), "medium")
    }

    // --- classify tests ---

    #[test]
    fn routes_by_exact_tool_name() {
        let hook = test_hook();
        let args = serde_json::json!({});
        assert_eq!(hook.classify("file_read", &args), "small");
        assert_eq!(hook.classify("git_status", &args), "small");
        assert_eq!(hook.classify("git_commit", &args), "medium");
        assert_eq!(hook.classify("file_write", &args), "medium");
    }

    #[test]
    fn routes_by_glob_pattern() {
        let hook = test_hook();
        let args = serde_json::json!({});
        assert_eq!(hook.classify("github_pr_list", &args), "medium");
        assert_eq!(hook.classify("project_create", &args), "large");
        assert_eq!(hook.classify("code_review", &args), "large");
    }

    #[test]
    fn routes_by_input_size() {
        let hook = test_hook();
        // ~100 chars → ~25 tokens → small tier (max_tokens: 500)
        let small_args = serde_json::json!({"query": "hello world"});
        assert_eq!(hook.classify("unknown_tool", &small_args), "small");

        // ~8000 chars → ~2000 tokens → medium tier won't fit, large will
        let large_content = "x".repeat(8001);
        let large_args = serde_json::json!({"content": large_content});
        assert_eq!(hook.classify("unknown_tool", &large_args), "large");
    }

    #[test]
    fn routes_to_default_when_too_large() {
        let hook = test_hook();
        // Content larger than all tier max_tokens
        let huge_content = "x".repeat(40000);
        let args = serde_json::json!({"content": huge_content});
        assert_eq!(hook.classify("unknown_tool", &args), "medium");
    }

    #[test]
    fn explicit_routing_hint_overrides() {
        let hook = test_hook();
        // file_read normally routes to "small", but hint says "large"
        let args = serde_json::json!({"_routing_hint": "large", "path": "/tmp/file"});
        assert_eq!(hook.classify("file_read", &args), "large");
    }

    #[test]
    fn invalid_routing_hint_falls_through() {
        let hook = test_hook();
        let args = serde_json::json!({"_routing_hint": "nonexistent"});
        // Falls through to pattern matching, then size, then default
        assert_eq!(hook.classify("file_read", &args), "small");
    }

    // --- Hook trait tests ---

    #[tokio::test]
    async fn pre_hook_injects_routing_metadata() {
        let hook = test_hook();
        let args = serde_json::json!({"path": "/tmp/test"});
        let decision = hook.pre_tool_use("file_read", &args, &test_ctx()).await;

        match decision {
            HookDecision::ModifyArgs(modified) => {
                assert_eq!(modified["_routing_tier"], "small");
                assert_eq!(modified["_routing_model"], "qwen2.5:3b");
                // Original args preserved
                assert_eq!(modified["path"], "/tmp/test");
            }
            other => panic!("Expected ModifyArgs, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pre_hook_routes_glob_pattern() {
        let hook = test_hook();
        let args = serde_json::json!({"pr": 42});
        let decision = hook
            .pre_tool_use("github_pr_review", &args, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyArgs(modified) => {
                // github_* matches "medium" tier
                assert_eq!(modified["_routing_tier"], "medium");
                assert_eq!(modified["_routing_model"], "granite3:8b");
            }
            other => panic!("Expected ModifyArgs, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pre_hook_uses_default_for_unknown_tool() {
        let hook = test_hook();
        let args = serde_json::json!({"query": "hello"});
        let decision = hook
            .pre_tool_use("some_unknown_tool", &args, &test_ctx())
            .await;

        match decision {
            HookDecision::ModifyArgs(modified) => {
                // Small args, routes to "small" by size
                assert_eq!(modified["_routing_tier"], "small");
            }
            other => panic!("Expected ModifyArgs, got {other:?}"),
        }
    }

    // --- Helper function tests ---

    #[test]
    fn glob_matches_exact() {
        assert!(glob_matches("file_read", "file_read"));
        assert!(!glob_matches("file_read", "file_write"));
    }

    #[test]
    fn glob_matches_wildcard() {
        assert!(glob_matches("github_*", "github_pr_list"));
        assert!(glob_matches("*_create", "project_create"));
        assert!(!glob_matches("github_*", "gitlab_pr_list"));
    }

    #[test]
    fn estimate_tokens_basic() {
        assert_eq!(estimate_tokens(""), 1); // minimum 1
        assert_eq!(estimate_tokens("abcd"), 1); // 4 chars = 1 token
        assert_eq!(estimate_tokens("abcdefgh"), 2); // 8 chars = 2 tokens
    }

    // --- Config tests ---

    #[test]
    fn routing_config_defaults() {
        let config = RoutingConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.default_tier, "medium");
        assert!(config.tiers.is_empty());
    }

    #[test]
    fn routing_config_json_round_trip() {
        let json = serde_json::json!({
            "enabled": true,
            "default_tier": "medium",
            "tiers": [
                {
                    "name": "small",
                    "model": "qwen2.5:3b",
                    "max_tokens": 500,
                    "patterns": ["file_read", "git_status"]
                },
                {
                    "name": "large",
                    "model": "llama3.3:70b",
                    "max_tokens": 8000,
                    "patterns": ["*_create"]
                }
            ]
        });
        let config: RoutingConfig = serde_json::from_value(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.default_tier, "medium");
        assert_eq!(config.tiers.len(), 2);
        assert_eq!(config.tiers[0].name, "small");
        assert_eq!(config.tiers[0].model, "qwen2.5:3b");
        assert_eq!(config.tiers[1].patterns, vec!["*_create"]);
    }

    #[test]
    fn build_hook_from_config() {
        let config = RoutingConfig {
            enabled: true,
            default_tier: "medium".to_string(),
            tiers: vec![ModelTierConfig {
                name: "small".to_string(),
                model: "qwen2.5:3b".to_string(),
                max_tokens: 500,
                patterns: vec!["file_read".to_string()],
            }],
        };
        let hook = RoutingHook::from_config(&config);
        assert_eq!(hook.tiers.len(), 1);
        assert_eq!(hook.default_tier, "medium");
        assert_eq!(hook.classify("file_read", &serde_json::json!({})), "small");
    }
}

/// Configuration for the routing hook, deserializable from TOML.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct RoutingConfig {
    /// Whether routing is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Default tier when no rule matches.
    #[serde(default = "default_tier")]
    pub default_tier: String,
    /// Model tiers, ordered from smallest to largest.
    #[serde(default)]
    pub tiers: Vec<ModelTierConfig>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_tier: "medium".to_string(),
            tiers: Vec::new(),
        }
    }
}

/// A single tier in the routing configuration.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct ModelTierConfig {
    pub name: String,
    pub model: String,
    pub max_tokens: usize,
    #[serde(default)]
    pub patterns: Vec<String>,
}

fn default_tier() -> String {
    "medium".to_string()
}

impl RoutingHook {
    /// Build a RoutingHook from a deserialized config.
    pub fn from_config(config: &RoutingConfig) -> Self {
        let tiers = config
            .tiers
            .iter()
            .map(|tc| ModelTier {
                name: tc.name.clone(),
                model: tc.model.clone(),
                max_tokens: tc.max_tokens,
                patterns: tc.patterns.clone(),
            })
            .collect();
        Self::new(tiers, &config.default_tier)
    }
}
