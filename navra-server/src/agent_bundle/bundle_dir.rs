use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Directory-based agent bundle (v2 format).
///
/// Structure:
/// ```text
/// my-agent/
///   agent.yaml           # personas, model prefs, workflow visibility
///   config-template.yaml # credential requirements (optional)
///   workflows/           # workflow definitions (optional)
///     day-planner.yaml
///     triage.yaml
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBundle {
    pub meta: BundleMeta,
    #[serde(default)]
    pub personas: Vec<Persona>,
    #[serde(default)]
    pub model: ModelPreferences,
    #[serde(default)]
    pub permissions: BundlePermissions,
    #[serde(default)]
    pub upstreams: Vec<BundleUpstream>,
    #[serde(default)]
    pub workflows: HashMap<String, WorkflowEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMeta {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Persona {
    pub name: String,
    #[serde(default)]
    pub system_prompt: Option<String>,
    #[serde(default)]
    pub directives: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelPreferences {
    #[serde(default)]
    pub preferred: Option<String>,
    #[serde(default)]
    pub fallbacks: Vec<String>,
    #[serde(default)]
    pub task: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BundlePermissions {
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub default: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleUpstream {
    pub name: String,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub url: Option<String>,
}

/// Workflow visibility and permission overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEntry {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_expose")]
    pub expose: Vec<String>,
    #[serde(default)]
    pub steps: Vec<WorkflowStep>,
}

/// A single step in a workflow with scoped permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub name: String,
    #[serde(default)]
    pub permissions: HashMap<String, Vec<String>>,
}

/// Credential template for interactive agent setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigTemplate {
    #[serde(default)]
    pub credentials: Vec<CredentialRequirement>,
    #[serde(default)]
    pub preferences: Vec<PreferenceField>,
}

/// A credential the agent needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequirement {
    pub name: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// A user-configurable preference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreferenceField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub options: Vec<String>,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn default_version() -> String {
    "0.1.0".to_string()
}

fn default_transport() -> String {
    "stdio".to_string()
}

fn default_expose() -> Vec<String> {
    vec!["cli".to_string()]
}

fn default_true() -> bool {
    true
}

/// Load an agent bundle from a directory.
pub fn load_bundle(dir: &Path) -> anyhow::Result<AgentBundle> {
    let agent_yaml = dir.join("agent.yaml");
    if !agent_yaml.exists() {
        anyhow::bail!(
            "not a valid agent bundle: {} (missing agent.yaml)",
            dir.display()
        );
    }
    let content = std::fs::read_to_string(&agent_yaml)?;
    let bundle: AgentBundle = serde_yaml::from_str(&content)?;
    Ok(bundle)
}

/// Load the config template if present.
pub fn load_config_template(dir: &Path) -> anyhow::Result<Option<ConfigTemplate>> {
    let path = dir.join("config-template.yaml");
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let template: ConfigTemplate = serde_yaml::from_str(&content)?;
    Ok(Some(template))
}

/// List workflow names from the bundle directory.
pub fn list_workflows(dir: &Path) -> Vec<String> {
    let workflows_dir = dir.join("workflows");
    if !workflows_dir.is_dir() {
        return Vec::new();
    }
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&workflows_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
    }
    names.sort();
    names
}

/// Install a bundle from a local directory to the agent data dir.
pub fn install_from_dir(source: &Path) -> anyhow::Result<InstalledBundle> {
    let bundle = load_bundle(source)?;
    let data_dir = agent_bundles_dir().join(&bundle.meta.name);

    if data_dir.exists() {
        std::fs::remove_dir_all(&data_dir)?;
    }
    copy_dir_recursive(source, &data_dir)?;

    let workflows = list_workflows(&data_dir);

    Ok(InstalledBundle {
        name: bundle.meta.name.clone(),
        version: bundle.meta.version.clone(),
        path: data_dir,
        workflows,
        bundle,
    })
}

pub struct InstalledBundle {
    pub name: String,
    pub version: String,
    pub path: PathBuf,
    pub workflows: Vec<String>,
    pub bundle: AgentBundle,
}

fn agent_bundles_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("navra/agent-bundles")
}

/// Check if a workflow is visible on a given surface.
pub fn workflow_visible(entry: &WorkflowEntry, surface: &str) -> bool {
    entry.expose.iter().any(|e| e == surface)
}

/// Intersect caller permissions with callee step permissions.
///
/// The effective permissions for a cross-bundle call are the intersection
/// of what the caller is allowed to do and what the callee step declares.
/// This implements capability-based security: you can only delegate what
/// you have.
pub fn intersect_permissions(
    caller: &HashMap<String, Vec<String>>,
    callee_step: &HashMap<String, Vec<String>>,
) -> HashMap<String, Vec<String>> {
    let mut result = HashMap::new();
    for (upstream, callee_ops) in callee_step {
        if let Some(caller_ops) = caller.get(upstream) {
            let effective: Vec<String> = callee_ops
                .iter()
                .filter(|op| caller_ops.contains(op))
                .cloned()
                .collect();
            if !effective.is_empty() {
                result.insert(upstream.clone(), effective);
            }
        }
    }
    result
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_agent_yaml() {
        let yaml = r#"
meta:
  name: admin-assistant
  version: "1.0.0"
  description: "Administrative assistant for email and calendar"

personas:
  - name: assistant
    system_prompt: "You are a helpful administrative assistant."
    directives:
      - "Prioritize urgent emails"
      - "Never send without confirmation"

model:
  preferred: granite-8b
  fallbacks: [llama-7b]

permissions:
  operations: [upstream.read, upstream.write]
  default:
    gmail: [read, list, search]
    calendar: [read]

upstreams:
  - name: gmail
    transport: stdio
    command: [npx, -y, "@anthropic/gmail-mcp"]
  - name: calendar
    transport: stdio
    command: [npx, -y, "@anthropic/calendar-mcp"]

workflows:
  day-planner:
    description: "Morning briefing and day planning"
    expose: [cli, tool]
    steps:
      - name: read-inbox
        permissions:
          gmail: [read, list, search]
          calendar: [read]
      - name: summarize
        permissions: {}
  triage:
    description: "Triage incoming emails"
    expose: [cli, tool]
    steps:
      - name: read-context
        permissions:
          gmail: [read, search]
      - name: respond
        permissions:
          gmail: [read, send]
"#;
        let bundle: AgentBundle = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(bundle.meta.name, "admin-assistant");
        assert_eq!(bundle.personas.len(), 1);
        assert_eq!(bundle.model.preferred.as_deref(), Some("granite-8b"));
        assert_eq!(bundle.upstreams.len(), 2);
        assert_eq!(bundle.workflows.len(), 2);

        let triage = &bundle.workflows["triage"];
        assert_eq!(triage.steps.len(), 2);
        assert_eq!(triage.steps[1].name, "respond");
        assert!(triage.steps[1].permissions.get("gmail").unwrap().contains(&"send".to_string()));
    }

    #[test]
    fn parse_minimal_agent_yaml() {
        let yaml = r#"
meta:
  name: simple-agent
"#;
        let bundle: AgentBundle = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(bundle.meta.name, "simple-agent");
        assert_eq!(bundle.meta.version, "0.1.0");
        assert!(bundle.personas.is_empty());
        assert!(bundle.workflows.is_empty());
    }

    #[test]
    fn parse_config_template() {
        let yaml = r#"
credentials:
  - name: gmail
    type: oauth2
    required: true
    scopes: [read, send]
    description: "Gmail access for email management"
  - name: slack
    type: bot-token
    required: false
    description: "Slack bot for notifications"

preferences:
  - name: model
    type: choice
    options: [granite-8b, llama-70b]
    default: granite-8b
  - name: budget
    type: number
    description: "Maximum tokens per day"
    default: "100000"
"#;
        let template: ConfigTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(template.credentials.len(), 2);
        assert!(template.credentials[0].required);
        assert!(!template.credentials[1].required);
        assert_eq!(template.credentials[0].scopes, vec!["read", "send"]);
        assert_eq!(template.preferences.len(), 2);
    }

    #[test]
    fn load_bundle_missing_dir() {
        let result = load_bundle(Path::new("/nonexistent"));
        assert!(result.is_err());
    }

    #[test]
    fn install_from_dir_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle_dir = tmp.path().join("test-agent");
        std::fs::create_dir_all(bundle_dir.join("workflows")).unwrap();

        std::fs::write(
            bundle_dir.join("agent.yaml"),
            "meta:\n  name: test-agent\n  version: '1.0.0'\n",
        )
        .unwrap();
        std::fs::write(
            bundle_dir.join("workflows/hello.yaml"),
            "steps: []\n",
        )
        .unwrap();

        let workflows = list_workflows(&bundle_dir);
        assert_eq!(workflows, vec!["hello"]);

        let bundle = load_bundle(&bundle_dir).unwrap();
        assert_eq!(bundle.meta.name, "test-agent");
    }

    #[test]
    fn workflow_visibility() {
        let entry = WorkflowEntry {
            description: None,
            expose: vec!["cli".to_string(), "tool".to_string()],
            steps: vec![],
        };
        assert!(workflow_visible(&entry, "cli"));
        assert!(workflow_visible(&entry, "tool"));
        assert!(!workflow_visible(&entry, "internal"));

        let internal = WorkflowEntry {
            description: None,
            expose: vec![],
            steps: vec![],
        };
        assert!(!workflow_visible(&internal, "cli"));
        assert!(!workflow_visible(&internal, "tool"));
    }

    #[test]
    fn permission_intersection_basic() {
        let mut caller = HashMap::new();
        caller.insert("gmail".to_string(), vec!["read".to_string(), "search".to_string()]);
        caller.insert("calendar".to_string(), vec!["read".to_string()]);

        let mut callee = HashMap::new();
        callee.insert("gmail".to_string(), vec!["read".to_string(), "send".to_string()]);
        callee.insert("slack".to_string(), vec!["post".to_string()]);

        let result = intersect_permissions(&caller, &callee);

        // gmail: caller has [read, search], callee wants [read, send] → [read]
        assert_eq!(result.get("gmail").unwrap(), &vec!["read".to_string()]);
        // slack: caller doesn't have it → not in result
        assert!(!result.contains_key("slack"));
        // calendar: callee doesn't ask for it → not in result
        assert!(!result.contains_key("calendar"));
    }

    #[test]
    fn permission_intersection_no_overlap() {
        let mut caller = HashMap::new();
        caller.insert("gmail".to_string(), vec!["read".to_string()]);

        let mut callee = HashMap::new();
        callee.insert("gmail".to_string(), vec!["send".to_string()]);

        let result = intersect_permissions(&caller, &callee);
        assert!(result.is_empty());
    }

    #[test]
    fn permission_intersection_empty_caller() {
        let caller = HashMap::new();
        let mut callee = HashMap::new();
        callee.insert("gmail".to_string(), vec!["read".to_string()]);

        let result = intersect_permissions(&caller, &callee);
        assert!(result.is_empty());
    }
}
