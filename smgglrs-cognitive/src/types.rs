//! Cognitive core types: Persona, Directive, Heuristic, Specialization.
//!
//! These types map directly to the YAML schemas in the cognitive_core
//! directory, maintaining compatibility with the the original Python prototype format.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Position where an upstream MCP prompt is injected in the system prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectPosition {
    /// Before the core mandate.
    BeforeMandate,
    /// After the core mandate, before heuristics.
    AfterMandate,
    /// After heuristics, before examples.
    AfterHeuristics,
    /// At the end of the system prompt.
    AfterExamples,
}

/// Source reference for an MCP-sourced persona.
///
/// When a persona YAML includes a `source` field, the core mandate and
/// methodology are fetched at runtime from the upstream MCP server's
/// `prompts/get` endpoint. The YAML becomes a thin pointer: it carries
/// the persona name, source config, and any local overrides (heuristics,
/// mcp_prompts, tools), but the "soul" comes from the upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPersonaSource {
    /// Upstream MCP server name (must match an upstream in the gateway config).
    pub upstream: String,
    /// Prompt name to fetch via `prompts/get`.
    pub prompt: String,
    /// Arguments to pass to `prompts/get`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<HashMap<String, String>>,
}

/// Reference to an upstream MCP prompt to inject into the system prompt.
///
/// The prompt is fetched via `prompts/get` on the named upstream at build
/// time. Template variables like `{{ input }}` are resolved from the user
/// prompt before the call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPromptRef {
    /// Upstream MCP server name.
    pub upstream: String,
    /// Prompt name (as registered via `prompts/list`).
    pub prompt: String,
    /// Where to inject the resolved prompt in the system prompt.
    pub inject_position: InjectPosition,
    /// Arguments to pass to `prompts/get`. Values may contain template
    /// variables like `{{ input }}` that are resolved before the call.
    #[serde(default)]
    pub arguments: Option<HashMap<String, String>>,
}

/// A resolved upstream prompt ready for injection.
///
/// This is the output of fetching a [`McpPromptRef`] via the MCP client.
/// The Weaver receives these pre-resolved and inserts them at the correct
/// position.
#[derive(Debug, Clone)]
pub struct ResolvedPrompt {
    /// Where to inject in the system prompt.
    pub position: InjectPosition,
    /// The resolved prompt text content.
    pub content: String,
    /// Label for the section header (upstream:prompt).
    pub label: String,
}

/// Visibility scope for a persona.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Scope {
    /// Visible to all agents.
    #[default]
    Public,
    /// Visible only within the same organization.
    Internal,
}


/// A persona defines an agent's identity, capabilities, and behavior.
#[derive(Debug, Clone, Deserialize)]
pub struct Persona {
    /// Machine-readable identifier (snake_case).
    pub persona_name: String,
    /// Human-readable name.
    pub display_name: String,
    /// Visibility: public or internal.
    #[serde(default)]
    pub scope: Scope,
    /// MCP source for this persona's core mandate.
    ///
    /// When present, the core mandate is fetched at runtime from the
    /// upstream MCP server via `prompts/get`. The `core_mandate` field
    /// can be empty in YAML — it will be populated at resolution time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<McpPersonaSource>,
    /// Fundamental directive for this persona.
    #[serde(default)]
    pub core_mandate: String,
    /// Heuristic modules and facets to load.
    #[serde(default)]
    pub heuristics: Vec<HeuristicRef>,
    /// Tools available to this persona.
    #[serde(default)]
    pub tools: Vec<String>,
    /// If true, this persona loads all core directives (Guardian flag).
    #[serde(default)]
    pub loads_directives: bool,
    /// Preferred LLM engine.
    #[serde(default)]
    pub preferred_engine: Option<String>,
    /// Platform-agnostic model override.
    #[serde(default)]
    pub model_override: Option<String>,
    /// Model for planning phases.
    #[serde(default)]
    pub planning_model: Option<String>,
    /// Model for execution phases.
    #[serde(default)]
    pub execution_model: Option<String>,
    /// Output schema name for validation.
    #[serde(default)]
    pub output_schema: Option<String>,
    /// Inline JSON schema for structured model output.
    /// When set, the model is constrained to produce output matching
    /// this schema. The schema is passed via response_format on the
    /// model request. Defined per persona, not by the framework.
    #[serde(default)]
    pub output_json_schema: Option<serde_json::Value>,
    /// Few-shot examples.
    #[serde(default)]
    pub examples: Vec<Example>,
    /// Upstream MCP prompts to inject into the system prompt.
    ///
    /// Each entry references a prompt on a named upstream MCP server.
    /// The prompts are fetched at build time and injected at the
    /// specified position in the assembled system prompt.
    #[serde(default)]
    pub mcp_prompts: Vec<McpPromptRef>,
    /// Skill modules (same structure as heuristics).
    #[serde(default)]
    pub skills: Vec<String>,
    /// Max context tokens for planning phases.
    /// When set, the Weaver truncates retrieved context and history
    /// to fit within this budget. System prompt is never truncated.
    #[serde(default)]
    pub planning_context_limit: Option<u32>,
    /// Max context tokens for execution phases.
    #[serde(default)]
    pub execution_context_limit: Option<u32>,
    /// Maximum tokens for a single tool result (default: framework default).
    /// Overrides the agent's max_tool_output_tokens for this persona.
    #[serde(default)]
    pub max_tool_output_tokens: Option<u32>,
}

/// Reference to a heuristic module and specific facets to load.
#[derive(Debug, Clone, Deserialize)]
pub struct HeuristicRef {
    /// Heuristic module name (without .yaml extension).
    pub module: String,
    /// Specific facets to load from this module.
    pub facets: Vec<String>,
}

/// A few-shot example for a persona.
#[derive(Debug, Clone, Deserialize)]
pub struct Example {
    /// Short title describing the example scenario.
    pub title: String,
    /// Example input/request.
    pub input: String,
    /// Expected output/response.
    pub output: String,
    /// Optional chain-of-thought reasoning.
    #[serde(default)]
    pub thought_process: Option<String>,
    /// Optional domain tag for filtering examples.
    #[serde(default)]
    pub domain: Option<String>,
}

/// A directive defines rules, constraints, or output format.
#[derive(Debug, Clone, Deserialize)]
pub struct Directive {
    /// Unique identifier.
    pub directive_name: String,
    /// Brief description of purpose.
    #[serde(default)]
    pub description: Option<String>,
    /// Full directive content (multi-line).
    pub content: String,
    /// Sources and justifications.
    #[serde(default)]
    pub references: Vec<Reference>,
}

/// A heuristic module containing domain-specific reasoning facets.
#[derive(Debug, Clone, Deserialize)]
pub struct HeuristicModule {
    /// Module identifier.
    pub heuristic_name: String,
    /// Brief description of the module's purpose.
    pub description: String,
    /// Actionable principles within this module.
    pub facets: Vec<Facet>,
    /// Sources and justifications.
    #[serde(default)]
    pub references: Vec<Reference>,
}

/// A specific, actionable principle within a heuristic module.
#[derive(Debug, Clone, Deserialize)]
pub struct Facet {
    /// Machine-readable identifier (snake_case).
    pub facet_name: String,
    /// Human-readable display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Detailed description or instruction.
    pub content: String,
}

/// A persona specialization that extends a base persona.
#[derive(Debug, Clone, Deserialize)]
pub struct Specialization {
    /// Name of the base persona to extend.
    pub base_persona: String,
    /// Description of the specialization.
    pub description: String,
    /// Additional heuristic facets ("module.facet" format).
    #[serde(default)]
    pub heuristics: Vec<String>,
    /// Additional tools.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Additional directives to load.
    #[serde(default)]
    pub directives: Vec<String>,
}

/// A reference to a source or justification.
#[derive(Debug, Clone, Deserialize)]
pub struct Reference {
    /// Human-readable description of the reference.
    pub description: String,
    /// URL or identifier for the source material.
    pub source: String,
}

/// A compact skill card for per-turn context injection.
///
/// Skill cards are small, focused instruction snippets (80-150 tokens)
/// loaded from YAML. They are matched against the current task by
/// keyword overlap and injected into the model's context to help small
/// models use tools correctly.
///
/// Inspired by the "Honey I Shrunk the Coding Agent" paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillCard {
    /// Skill card name (e.g. "file_operations").
    pub name: String,
    /// Keywords for matching against task text.
    pub keywords: Vec<String>,
    /// Instruction content (80-150 tokens, ~320-600 chars).
    pub content: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_persona() {
        let yaml = r#"
persona_name: analyst
display_name: "Cognitive Analyst"
scope: internal
core_mandate: "Perform post-mortem analysis on failed tasks."
heuristics:
  - module: analyst_heuristics
    facets: [root_cause_analysis, pattern_recognition]
"#;
        let persona: Persona = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(persona.persona_name, "analyst");
        assert_eq!(persona.scope, Scope::Internal);
        assert_eq!(persona.heuristics.len(), 1);
        assert_eq!(persona.heuristics[0].facets.len(), 2);
        assert!(!persona.loads_directives);
    }

    #[test]
    fn deserialize_persona_with_models() {
        let yaml = r#"
persona_name: leader
display_name: "Leader"
core_mandate: "Orchestrate."
preferred_engine: claude
planning_model: claude-opus-4-5
execution_model: claude-sonnet-4-5
loads_directives: true
"#;
        let persona: Persona = serde_yaml::from_str(yaml).unwrap();
        assert!(persona.loads_directives);
        assert_eq!(persona.preferred_engine.unwrap(), "claude");
        assert_eq!(persona.planning_model.unwrap(), "claude-opus-4-5");
    }

    #[test]
    fn deserialize_directive() {
        let yaml = r#"
directive_name: security_protocol
description: "Security best practices"
content: |
  # Security Protocol
  All inputs must be validated.
references:
  - description: "OWASP Top 10"
    source: "https://owasp.org/"
"#;
        let directive: Directive = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(directive.directive_name, "security_protocol");
        assert!(directive.content.contains("Security Protocol"));
        assert_eq!(directive.references.len(), 1);
    }

    #[test]
    fn deserialize_heuristic() {
        let yaml = r#"
heuristic_name: security
description: "Security heuristics"
facets:
  - facet_name: input_validation
    display_name: "Input Validation"
    content: "Validate all external inputs."
  - facet_name: least_privilege
    content: "Use minimum permissions."
"#;
        let heuristic: HeuristicModule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(heuristic.heuristic_name, "security");
        assert_eq!(heuristic.facets.len(), 2);
        assert_eq!(heuristic.facets[0].display_name.as_deref(), Some("Input Validation"));
        assert!(heuristic.facets[1].display_name.is_none());
    }

    #[test]
    fn deserialize_specialization() {
        let yaml = r#"
base_persona: software_developer
description: "Backend specialist"
heuristics:
  - security.input_validation
  - performance.caching
tools:
  - database_profiler
directives:
  - security_protocol
"#;
        let spec: Specialization = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.base_persona, "software_developer");
        assert_eq!(spec.heuristics.len(), 2);
        assert_eq!(spec.tools.len(), 1);
        assert_eq!(spec.directives.len(), 1);
    }

    #[test]
    fn deserialize_persona_defaults() {
        let yaml = r#"
persona_name: minimal
display_name: "Minimal"
core_mandate: "Do stuff."
"#;
        let persona: Persona = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(persona.scope, Scope::Public);
        assert!(persona.heuristics.is_empty());
        assert!(persona.tools.is_empty());
        assert!(persona.examples.is_empty());
        assert!(persona.model_override.is_none());
        assert!(persona.mcp_prompts.is_empty());
    }

    #[test]
    fn deserialize_mcp_prompt_ref() {
        let yaml = r#"
upstream: syllogis
prompt: legal_analysis
inject_position: after_mandate
arguments:
  case_description: "{{ input }}"
"#;
        let pref: McpPromptRef = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(pref.upstream, "syllogis");
        assert_eq!(pref.prompt, "legal_analysis");
        assert_eq!(pref.inject_position, InjectPosition::AfterMandate);
        let args = pref.arguments.unwrap();
        assert_eq!(args["case_description"], "{{ input }}");
    }

    #[test]
    fn deserialize_mcp_prompt_ref_no_args() {
        let yaml = r#"
upstream: syllogis
prompt: legal_syllogism
inject_position: after_heuristics
"#;
        let pref: McpPromptRef = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(pref.prompt, "legal_syllogism");
        assert_eq!(pref.inject_position, InjectPosition::AfterHeuristics);
        assert!(pref.arguments.is_none());
    }

    #[test]
    fn deserialize_persona_with_mcp_prompts() {
        let yaml = r#"
persona_name: legal_analyst
display_name: "Legal Analyst"
core_mandate: "Analyze French administrative law cases."
mcp_prompts:
  - upstream: syllogis
    prompt: legal_analysis
    inject_position: after_mandate
    arguments:
      case_description: "{{ input }}"
  - upstream: syllogis
    prompt: legal_syllogism
    inject_position: after_heuristics
"#;
        let persona: Persona = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(persona.persona_name, "legal_analyst");
        assert_eq!(persona.mcp_prompts.len(), 2);
        assert_eq!(persona.mcp_prompts[0].upstream, "syllogis");
        assert_eq!(persona.mcp_prompts[0].inject_position, InjectPosition::AfterMandate);
        assert_eq!(persona.mcp_prompts[1].inject_position, InjectPosition::AfterHeuristics);
    }

    #[test]
    fn inject_position_all_variants() {
        for (yaml, expected) in [
            ("before_mandate", InjectPosition::BeforeMandate),
            ("after_mandate", InjectPosition::AfterMandate),
            ("after_heuristics", InjectPosition::AfterHeuristics),
            ("after_examples", InjectPosition::AfterExamples),
        ] {
            let json = format!("\"{yaml}\"");
            let pos: InjectPosition = serde_json::from_str(&json).unwrap();
            assert_eq!(pos, expected);
        }
    }

    #[test]
    fn deserialize_mcp_persona_source() {
        let yaml = r#"
upstream: syllogis
prompt: legal_analyst_persona
arguments:
  jurisdiction: french_admin
"#;
        let source: McpPersonaSource = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(source.upstream, "syllogis");
        assert_eq!(source.prompt, "legal_analyst_persona");
        let args = source.arguments.unwrap();
        assert_eq!(args["jurisdiction"], "french_admin");
    }

    #[test]
    fn deserialize_mcp_persona_source_no_args() {
        let yaml = r#"
upstream: syllogis
prompt: generic_persona
"#;
        let source: McpPersonaSource = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(source.upstream, "syllogis");
        assert_eq!(source.prompt, "generic_persona");
        assert!(source.arguments.is_none());
    }

    #[test]
    fn mcp_persona_source_serialize_roundtrip() {
        let source = McpPersonaSource {
            upstream: "syllogis".to_string(),
            prompt: "legal_analyst_persona".to_string(),
            arguments: Some(
                [("jurisdiction".to_string(), "french_admin".to_string())]
                    .into_iter()
                    .collect(),
            ),
        };

        let yaml = serde_yaml::to_string(&source).unwrap();
        let back: McpPersonaSource = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.upstream, "syllogis");
        assert_eq!(back.prompt, "legal_analyst_persona");
        assert_eq!(back.arguments.unwrap()["jurisdiction"], "french_admin");
    }

    #[test]
    fn deserialize_persona_with_source() {
        let yaml = r#"
persona_name: syllogis_legal
display_name: "Syllogis Legal Analyst"
source:
  upstream: syllogis
  prompt: legal_analyst_persona
  arguments:
    jurisdiction: french_admin
heuristics:
  - module: legal
    facets: [evidence_analysis]
"#;
        let persona: Persona = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(persona.persona_name, "syllogis_legal");
        assert!(persona.source.is_some());
        let source = persona.source.unwrap();
        assert_eq!(source.upstream, "syllogis");
        assert_eq!(source.prompt, "legal_analyst_persona");
        assert!(persona.core_mandate.is_empty());
        assert_eq!(persona.heuristics.len(), 1);
    }

    #[test]
    fn deserialize_persona_without_source_backward_compat() {
        let yaml = r#"
persona_name: developer
display_name: "Developer"
core_mandate: "Write code."
"#;
        let persona: Persona = serde_yaml::from_str(yaml).unwrap();
        assert!(persona.source.is_none());
        assert_eq!(persona.core_mandate, "Write code.");
    }

    #[test]
    fn deserialize_persona_source_with_local_mandate() {
        let yaml = r#"
persona_name: hybrid
display_name: "Hybrid Persona"
source:
  upstream: syllogis
  prompt: base_persona
core_mandate: "Local fallback mandate."
"#;
        let persona: Persona = serde_yaml::from_str(yaml).unwrap();
        assert!(persona.source.is_some());
        assert_eq!(persona.core_mandate, "Local fallback mandate.");
    }

    #[test]
    fn mcp_prompt_ref_serialize_roundtrip() {
        let pref = McpPromptRef {
            upstream: "test".to_string(),
            prompt: "my_prompt".to_string(),
            inject_position: InjectPosition::BeforeMandate,
            arguments: Some(
                [("key".to_string(), "value".to_string())]
                    .into_iter()
                    .collect(),
            ),
        };

        let yaml = serde_yaml::to_string(&pref).unwrap();
        let back: McpPromptRef = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.upstream, "test");
        assert_eq!(back.prompt, "my_prompt");
        assert_eq!(back.inject_position, InjectPosition::BeforeMandate);
        assert_eq!(back.arguments.unwrap()["key"], "value");
    }
}
