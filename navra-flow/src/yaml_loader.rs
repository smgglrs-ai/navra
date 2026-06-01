//! YAML flow loader with parameter substitution.
//!
//! Supports two flow kinds:
//! - `kind: dag` — parallel task graph with dependency resolution
//! - `kind: handoff` — directed graph with model-driven routing
//!
//! Parameters use `{{ name }}` Mustache-style placeholders that are
//! substituted before YAML parsing.

use crate::definition::{DagConfig, ParameterDef, TaskDefinition};
use std::collections::HashMap;
use thiserror::Error;

/// Errors from YAML flow loading.
#[derive(Debug, Error)]
pub enum YamlLoadError {
    #[error("unknown flow kind: {0} (expected \"dag\" or \"handoff\")")]
    UnknownKind(String),
    #[error("missing required parameter: {0}")]
    MissingParameter(String),
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Top-level YAML flow envelope.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct FlowFile {
    /// Flow kind: "dag" or "handoff".
    pub kind: String,
    /// Flow name.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Parameter definitions.
    #[serde(default)]
    pub parameters: HashMap<String, ParameterDef>,
    /// Task list (for `kind: dag`).
    #[serde(default)]
    pub tasks: Vec<TaskDefinition>,
}

/// Load a YAML flow definition and return a `DagConfig`.
///
/// # Parameters
///
/// - `yaml_str`: Raw YAML content (may contain `{{ key }}` placeholders).
/// - `params`: User-supplied parameter values keyed by name.
///
/// # Errors
///
/// Returns `YamlLoadError::MissingParameter` if a required parameter
/// (one without a default) is not supplied.
/// Returns `YamlLoadError::UnknownKind` if `kind` is not `dag` or `handoff`.
pub fn load_flow_yaml(
    yaml_str: &str,
    params: &HashMap<String, String>,
) -> Result<DagConfig, YamlLoadError> {
    // First pass: parse just to get parameter definitions and kind.
    let envelope: FlowFile = serde_yaml::from_str(yaml_str)?;

    if envelope.kind != "dag" && envelope.kind != "handoff" {
        return Err(YamlLoadError::UnknownKind(envelope.kind));
    }

    // Build effective parameter values: supplied values override defaults.
    let effective = resolve_params(&envelope.parameters, params)?;

    // Substitute {{ key }} placeholders in the raw YAML.
    let substituted = substitute(yaml_str, &effective);

    // Re-parse with substituted values.
    let resolved: FlowFile = serde_yaml::from_str(&substituted)?;

    Ok(DagConfig {
        name: resolved.name,
        description: resolved.description,
        parameters: resolved.parameters,
        tasks: resolved.tasks,
        blackboard_capacity: None,
    })
}

/// Resolve parameter values, filling defaults where needed.
fn resolve_params(
    defs: &HashMap<String, ParameterDef>,
    supplied: &HashMap<String, String>,
) -> Result<HashMap<String, String>, YamlLoadError> {
    let mut effective = HashMap::new();
    for (name, def) in defs {
        if let Some(val) = supplied.get(name) {
            effective.insert(name.clone(), val.clone());
        } else if let Some(ref default) = def.default {
            effective.insert(name.clone(), default.clone());
        } else {
            return Err(YamlLoadError::MissingParameter(name.clone()));
        }
    }
    Ok(effective)
}

/// Replace all `{{ key }}` occurrences with their values.
///
/// Handles `{{ key }}`, `{{key}}`, and variations with whitespace.
fn substitute(template: &str, values: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in values {
        // Replace common variants: "{{ key }}", "{{key}}", "{{ key}}", "{{key }}"
        for pattern in &[
            format!("{{{{ {} }}}}", key),
            format!("{{{{{}}}}}", key),
            format!("{{{{ {}}}}}", key),
            format!("{{{{{} }}}}", key),
        ] {
            result = result.replace(pattern, value);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_DAG_YAML: &str = r#"
kind: dag
name: security-audit
description: Audit a project for security vulnerabilities
parameters:
  target_dir:
    type: string
    description: Directory to audit
  severity:
    type: string
    description: Minimum severity level
    default: medium
tasks:
  - id: scan
    specialist: security_auditor
    mandate: "Scan {{ target_dir }} for {{ severity }}+ vulnerabilities"
    expected_output: "List of findings with CWE IDs"
  - id: synthesize
    specialist: analyst
    mandate: "Synthesize scan findings into a prioritized report"
    depends_on: [scan]
"#;

    #[test]
    fn load_valid_yaml_flow() {
        let mut params = HashMap::new();
        params.insert("target_dir".into(), "/home/user/project".into());

        let dag = load_flow_yaml(VALID_DAG_YAML, &params).unwrap();
        assert_eq!(dag.name, "security-audit");
        assert_eq!(
            dag.description.as_deref(),
            Some("Audit a project for security vulnerabilities")
        );
        assert_eq!(dag.tasks.len(), 2);
        assert_eq!(dag.tasks[0].id, "scan");
        assert_eq!(dag.tasks[0].specialist, "security_auditor");
        assert_eq!(dag.tasks[1].depends_on, vec!["scan"]);
    }

    #[test]
    fn parameter_substitution_works() {
        let mut params = HashMap::new();
        params.insert("target_dir".into(), "/opt/app".into());

        let dag = load_flow_yaml(VALID_DAG_YAML, &params).unwrap();
        assert!(dag.tasks[0].mandate.contains("/opt/app"));
        // Default for severity should be applied.
        assert!(dag.tasks[0].mandate.contains("medium"));
    }

    #[test]
    fn missing_required_parameter_returns_error() {
        let params = HashMap::new(); // target_dir is required, not supplied
        let result = load_flow_yaml(VALID_DAG_YAML, &params);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, YamlLoadError::MissingParameter(ref p) if p == "target_dir"),
            "expected MissingParameter(target_dir), got: {err}"
        );
    }

    #[test]
    fn unknown_kind_returns_error() {
        let yaml = r#"
kind: pipeline
name: test
tasks: []
"#;
        let result = load_flow_yaml(yaml, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, YamlLoadError::UnknownKind(ref k) if k == "pipeline"),
            "expected UnknownKind(pipeline), got: {err}"
        );
    }

    #[test]
    fn roundtrip_yaml_to_dag_config() {
        let mut params = HashMap::new();
        params.insert("target_dir".into(), "/src".into());

        let dag = load_flow_yaml(VALID_DAG_YAML, &params).unwrap();

        // Verify all DagConfig fields.
        assert_eq!(dag.name, "security-audit");
        assert!(dag.description.is_some());
        assert_eq!(dag.parameters.len(), 2);
        assert!(dag.parameters.contains_key("target_dir"));
        assert!(dag.parameters.contains_key("severity"));
        assert_eq!(dag.parameters["severity"].default, Some("medium".into()));
        assert_eq!(dag.tasks.len(), 2);
        assert_eq!(
            dag.tasks[0].mandate,
            "Scan /src for medium+ vulnerabilities"
        );
        assert_eq!(
            dag.tasks[0].expected_output,
            Some("List of findings with CWE IDs".into())
        );
        assert!(dag.tasks[0].depends_on.is_empty());
        assert_eq!(dag.tasks[1].depends_on, vec!["scan"]);
        assert!(dag.blackboard_capacity.is_none());
    }
}
