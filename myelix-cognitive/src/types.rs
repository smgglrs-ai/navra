//! Cognitive core types: Persona, Directive, Heuristic, Specialization.
//!
//! These types map directly to the YAML schemas in the cognitive_core
//! directory, maintaining compatibility with the Python Myelix format.

use serde::Deserialize;

/// Visibility scope for a persona.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Public,
    Internal,
}

impl Default for Scope {
    fn default() -> Self {
        Self::Public
    }
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
    /// Fundamental directive for this persona.
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
    /// Skill modules (same structure as heuristics).
    #[serde(default)]
    pub skills: Vec<String>,
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
    pub title: String,
    pub input: String,
    pub output: String,
    #[serde(default)]
    pub thought_process: Option<String>,
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
    pub description: String,
    pub source: String,
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
    }
}
