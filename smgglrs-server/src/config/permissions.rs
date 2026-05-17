use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
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
    /// Safety profile: "standard", "pseudonymize", "secrets-only", "block",
    /// "multi-label", "guardian", "guardian-deep", "none"
    #[serde(default = "default_safety")]
    pub safety: String,
    /// Per-category confidence thresholds for multi-label safety models.
    ///
    /// Used when `safety = "multi-label"`. Each key is a category name
    /// (e.g., "harm", "jailbreak", "pii") and the value is the minimum
    /// confidence score (0.0-1.0) to trigger filtering for that category.
    ///
    /// Example:
    /// ```toml
    /// [permissions.dev.safety_thresholds]
    /// harm = 0.7
    /// jailbreak = 0.9
    /// pii = 0.5
    /// refusal = 0.8
    /// ```
    #[serde(default)]
    pub safety_thresholds: HashMap<String, f32>,
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
    /// Tool disclosure: glob patterns of tools to show in tools/list.
    /// Empty = show all tools. This is UI-level filtering only — agents
    /// can still call hidden tools if they know the name.
    #[serde(default)]
    pub tool_disclosure_include: Vec<String>,
    /// Tool disclosure: glob patterns of tools to hide from tools/list.
    #[serde(default)]
    pub tool_disclosure_exclude: Vec<String>,
}

fn default_tainted_write_policy() -> String {
    "allow".to_string()
}

/// A per-tool permission rule in config.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct ToolRuleConfig {
    /// Glob pattern matching tool names (e.g., "git_*", "shell_exec").
    pub tool: String,
    /// Policy: "allow", "deny", or "approve".
    pub policy: String,
}

/// A custom regex pattern for safety filtering.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct SafetyPatternConfig {
    /// Category name for this pattern (e.g., "internal-url", "project-secret").
    pub category: String,
    /// Regex pattern to match.
    pub pattern: String,
}

/// A custom PII pattern for global content safety filtering.
///
/// Categories defined here are treated as PII for IFC labeling,
/// unlike `SafetyPatternConfig` which only triggers redaction/blocking.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct PiiPatternConfig {
    /// Human-readable name for this pattern (e.g., "employee-id").
    pub name: String,
    /// Regex pattern to match.
    pub regex: String,
    /// PII category name (e.g., "employee-id", "badge", "project-code").
    pub category: String,
}

fn default_tool_policy() -> String {
    "allow".to_string()
}

fn default_safety() -> String {
    "standard".to_string()
}
