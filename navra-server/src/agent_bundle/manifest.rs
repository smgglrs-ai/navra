use crate::config::{DomainRuleConfig, ToolRuleConfig};
use serde::{Deserialize, Serialize};

pub const AGENT_BUNDLE_ARTIFACT_TYPE: &str = "application/vnd.navra.agent-bundle.v1+json";

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentManifest {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub meta: ManifestMeta,
    #[serde(default)]
    pub persona: Option<PersonaConfig>,
    #[serde(default)]
    pub permissions: RequestedPermissions,
    #[serde(default)]
    pub upstreams: Vec<ManifestUpstream>,
    #[serde(default)]
    pub image: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ManifestMeta {
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

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaConfig {
    #[serde(default)]
    pub system_prompt: Option<String>,
    #[serde(default)]
    pub directives: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RequestedPermissions {
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub tool_rules: Vec<ToolRuleConfig>,
    #[serde(default)]
    pub domain_rules: Vec<DomainRuleConfig>,
    #[serde(default)]
    pub ifc: Option<IfcDeclaration>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IfcDeclaration {
    #[serde(default = "default_ifc_reads")]
    pub reads: String,
    #[serde(default = "default_ifc_writes")]
    pub writes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ManifestUpstream {
    pub name: String,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub tool_filter: Vec<String>,
}

fn default_schema_version() -> u32 {
    1
}

fn default_version() -> String {
    "0.1.0".to_string()
}

fn default_transport() -> String {
    "stdio".to_string()
}

fn default_ifc_reads() -> String {
    "trusted".to_string()
}

fn default_ifc_writes() -> String {
    "public".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_manifest() {
        let json = r#"{
            "schema_version": 1,
            "meta": {
                "name": "code-reviewer",
                "version": "1.0.0",
                "publisher": "acme",
                "description": "Reviews code for bugs",
                "license": "Apache-2.0"
            },
            "persona": {
                "system_prompt": "You are a code reviewer.",
                "directives": ["Focus on security issues"]
            },
            "permissions": {
                "operations": ["filesystem.read", "git.read"],
                "tool_rules": [{"tool": "file_read", "policy": "allow"}],
                "domain_rules": [{"domain": "filesystem", "operations": ["read"]}],
                "ifc": {"reads": "untrusted", "writes": "public"}
            },
            "upstreams": [{
                "name": "search",
                "transport": "stdio",
                "command": ["npx", "-y", "@acme/search-mcp"]
            }],
            "image": "quay.io/acme/code-reviewer:1.0"
        }"#;

        let manifest: AgentManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.meta.name, "code-reviewer");
        assert_eq!(manifest.meta.version, "1.0.0");
        assert_eq!(manifest.permissions.operations.len(), 2);
        assert_eq!(manifest.permissions.tool_rules.len(), 1);
        assert_eq!(manifest.permissions.domain_rules.len(), 1);
        assert!(manifest.persona.is_some());
        assert_eq!(manifest.upstreams.len(), 1);
        assert_eq!(
            manifest.image.as_deref(),
            Some("quay.io/acme/code-reviewer:1.0")
        );
    }

    #[test]
    fn parse_minimal_manifest() {
        let json = r#"{"meta": {"name": "simple-agent"}}"#;
        let manifest: AgentManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.meta.name, "simple-agent");
        assert_eq!(manifest.meta.version, "0.1.0");
        assert!(manifest.permissions.operations.is_empty());
        assert!(manifest.persona.is_none());
        assert!(manifest.upstreams.is_empty());
        assert!(manifest.image.is_none());
    }

    #[test]
    fn unknown_fields_ignored() {
        let json = r#"{
            "meta": {"name": "test", "future_field": true},
            "unknown_section": {"data": 42}
        }"#;
        let manifest: AgentManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.meta.name, "test");
    }

    #[test]
    fn roundtrip_serialize() {
        let manifest = AgentManifest {
            schema_version: 1,
            meta: ManifestMeta {
                name: "test".to_string(),
                version: "1.0.0".to_string(),
                publisher: Some("acme".to_string()),
                description: None,
                license: None,
            },
            persona: None,
            permissions: RequestedPermissions::default(),
            upstreams: vec![],
            image: None,
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: AgentManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.meta.name, "test");
    }
}
