//! YAML flow loader with parameter substitution.
//!
//! Supports two flow kinds:
//! - `kind: dag` — parallel task graph with dependency resolution
//! - `kind: handoff` — directed graph with model-driven routing
//!
//! Parameters use `{{ name }}` Mustache-style placeholders that are
//! substituted before YAML parsing.

use crate::definition::{
    DagConfig, EdgeDefinition, FlowConfig, NodeDefinition, ParameterDef, TaskDefinition,
};
use std::collections::HashMap;
use thiserror::Error;

/// Errors from YAML flow loading.
#[derive(Debug, Error)]
pub enum YamlLoadError {
    #[error("unknown flow kind: {0} (expected \"dag\" or \"handoff\")")]
    UnknownKind(String),
    #[error("missing required parameter: {0}")]
    MissingParameter(String),
    #[error("{kind} flow missing required field: {field}")]
    MissingField { kind: String, field: String },
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// A loaded flow definition, discriminated by kind.
#[derive(Debug, Clone)]
pub enum LoadedFlow {
    Dag(DagConfig),
    Handoff(FlowConfig),
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
    /// Entry node ID (for `kind: handoff`).
    #[serde(default)]
    pub entry: Option<String>,
    /// Maximum handoff hops (for `kind: handoff`).
    #[serde(default)]
    pub max_hops: Option<usize>,
    /// Node definitions (for `kind: handoff`).
    #[serde(default)]
    pub nodes: Vec<NodeDefinition>,
    /// Edge definitions (for `kind: handoff`).
    #[serde(default)]
    pub edges: Vec<EdgeDefinition>,
}

/// Load a YAML flow definition and return a `DagConfig`.
///
/// Legacy API — callers that only handle DAG flows should use this.
/// For handoff support, use [`load_flow`] instead.
pub fn load_flow_yaml(
    yaml_str: &str,
    params: &HashMap<String, String>,
) -> Result<DagConfig, YamlLoadError> {
    match load_flow(yaml_str, params)? {
        LoadedFlow::Dag(dag) => Ok(dag),
        LoadedFlow::Handoff(_) => Err(YamlLoadError::UnknownKind(
            "handoff (use load_flow for handoff support)".to_string(),
        )),
    }
}

/// Load a YAML flow definition, returning either a DAG or handoff config.
pub fn load_flow(
    yaml_str: &str,
    params: &HashMap<String, String>,
) -> Result<LoadedFlow, YamlLoadError> {
    let envelope: FlowFile = serde_yaml::from_str(yaml_str)?;

    match envelope.kind.as_str() {
        "dag" => load_dag(yaml_str, &envelope, params),
        "handoff" => load_handoff(yaml_str, &envelope, params),
        other => Err(YamlLoadError::UnknownKind(other.to_string())),
    }
}

fn load_dag(
    yaml_str: &str,
    envelope: &FlowFile,
    params: &HashMap<String, String>,
) -> Result<LoadedFlow, YamlLoadError> {
    let effective = resolve_params(&envelope.parameters, params)?;
    let substituted = substitute(yaml_str, &effective);
    let resolved: FlowFile = serde_yaml::from_str(&substituted)?;

    if resolved.tasks.is_empty() {
        return Err(YamlLoadError::MissingField {
            kind: "dag".to_string(),
            field: "tasks".to_string(),
        });
    }

    Ok(LoadedFlow::Dag(DagConfig {
        name: resolved.name,
        description: resolved.description,
        parameters: resolved.parameters,
        tasks: resolved.tasks,
        blackboard_capacity: None,
    }))
}

fn load_handoff(
    yaml_str: &str,
    envelope: &FlowFile,
    params: &HashMap<String, String>,
) -> Result<LoadedFlow, YamlLoadError> {
    let effective = resolve_params(&envelope.parameters, params)?;
    let substituted = substitute(yaml_str, &effective);
    let resolved: FlowFile = serde_yaml::from_str(&substituted)?;

    let entry = resolved.entry.ok_or_else(|| YamlLoadError::MissingField {
        kind: "handoff".to_string(),
        field: "entry".to_string(),
    })?;

    if resolved.nodes.is_empty() {
        return Err(YamlLoadError::MissingField {
            kind: "handoff".to_string(),
            field: "nodes".to_string(),
        });
    }

    Ok(LoadedFlow::Handoff(FlowConfig {
        name: resolved.name,
        entry,
        max_hops: resolved.max_hops.unwrap_or(10),
        mailbox_capacity: None,
        blackboard_capacity: None,
        nodes: resolved.nodes,
        edges: resolved.edges,
    }))
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
fn substitute(template: &str, values: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in values {
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

    const VALID_HANDOFF_YAML: &str = r#"
kind: handoff
name: support-triage
description: Customer support triage flow
entry: router
parameters:
  product:
    type: string
    description: Product name
    default: "widget"
nodes:
  - id: router
    endpoint: "http://localhost:9315/mcp"
    model_url: "http://localhost:11434/v1"
    model_name: "qwen2.5:0.5b"
    system_prompt: "Route {{ product }} support requests."
  - id: billing
    endpoint: "http://localhost:9315/mcp"
    model_url: "http://localhost:11434/v1"
    model_name: "qwen2.5:0.5b"
    system_prompt: "Handle billing inquiries for {{ product }}."
  - id: technical
    endpoint: "http://localhost:9315/mcp"
    model_url: "http://localhost:11434/v1"
    model_name: "qwen2.5:0.5b"
    system_prompt: "Handle technical support for {{ product }}."
edges:
  - from: router
    to: billing
    description: "Customer has a billing question"
  - from: router
    to: technical
    description: "Customer has a technical issue"
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

    // --- LoadedFlow (new) ---

    #[test]
    fn load_flow_returns_dag() {
        let mut params = HashMap::new();
        params.insert("target_dir".into(), "/src".into());

        let loaded = load_flow(VALID_DAG_YAML, &params).unwrap();
        assert!(matches!(loaded, LoadedFlow::Dag(_)));
        if let LoadedFlow::Dag(dag) = loaded {
            assert_eq!(dag.name, "security-audit");
            assert_eq!(dag.tasks.len(), 2);
        }
    }

    #[test]
    fn load_flow_returns_handoff() {
        let loaded = load_flow(VALID_HANDOFF_YAML, &HashMap::new()).unwrap();
        assert!(matches!(loaded, LoadedFlow::Handoff(_)));
        if let LoadedFlow::Handoff(flow) = loaded {
            assert_eq!(flow.name, "support-triage");
            assert_eq!(flow.entry, "router");
            assert_eq!(flow.nodes.len(), 3);
            assert_eq!(flow.edges.len(), 2);
            assert_eq!(flow.max_hops, 10);
            assert!(flow.nodes[0].system_prompt.contains("widget"));
        }
    }

    #[test]
    fn handoff_parameter_substitution() {
        let mut params = HashMap::new();
        params.insert("product".into(), "gizmo".into());

        let loaded = load_flow(VALID_HANDOFF_YAML, &params).unwrap();
        if let LoadedFlow::Handoff(flow) = loaded {
            assert!(flow.nodes[0].system_prompt.contains("gizmo"));
            assert!(flow.nodes[1].system_prompt.contains("gizmo"));
        } else {
            panic!("expected Handoff");
        }
    }

    #[test]
    fn handoff_missing_entry_errors() {
        let yaml = r#"
kind: handoff
name: bad-flow
nodes:
  - id: agent
    endpoint: "http://localhost:9315/mcp"
    model_url: "http://localhost:11434/v1"
    model_name: "test"
edges: []
"#;
        let result = load_flow(yaml, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, YamlLoadError::MissingField { ref field, .. } if field == "entry"),
            "expected MissingField(entry), got: {err}"
        );
    }

    #[test]
    fn handoff_missing_nodes_errors() {
        let yaml = r#"
kind: handoff
name: empty-flow
entry: start
nodes: []
edges: []
"#;
        let result = load_flow(yaml, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, YamlLoadError::MissingField { ref field, .. } if field == "nodes"),
            "expected MissingField(nodes), got: {err}"
        );
    }

    #[test]
    fn dag_missing_tasks_errors() {
        let yaml = r#"
kind: dag
name: empty-dag
tasks: []
"#;
        let result = load_flow(yaml, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, YamlLoadError::MissingField { ref field, .. } if field == "tasks"),
            "expected MissingField(tasks), got: {err}"
        );
    }

    #[test]
    fn load_flow_yaml_rejects_handoff() {
        let result = load_flow_yaml(VALID_HANDOFF_YAML, &HashMap::new());
        assert!(result.is_err());
    }
}
