//! Map navra McpServer capabilities to ACP AgentManifest.

use super::store::RunStore;
use super::types::{AgentCapability, AgentManifest, AgentMetadata, AgentStatus, FlowSummary};
use crate::server::McpServer;

/// Build ACP agent manifests: one for the gateway + one per flow node.
pub fn build_manifests(server: &McpServer, flows: &[FlowSummary]) -> Vec<AgentManifest> {
    let mut manifests = vec![build_manifest(server)];

    for flow in flows {
        for node in &flow.nodes {
            let agent_name = to_dns_label(&format!("{}-{}", flow.name, node.id));
            manifests.push(AgentManifest {
                name: agent_name,
                description: node.description.clone(),
                input_content_types: vec!["text/plain".to_string(), "application/json".to_string()],
                output_content_types: vec![
                    "text/plain".to_string(),
                    "application/json".to_string(),
                ],
                metadata: Some(AgentMetadata {
                    framework: Some("navra-flow".to_string()),
                    domains: Some(vec![flow.name.clone()]),
                    annotations: None,
                    documentation: None,
                    license: None,
                    programming_language: None,
                    natural_languages: None,
                    capabilities: None,
                    tags: None,
                    author: None,
                    links: None,
                    recommended_models: None,
                }),
                status: None,
            });
        }
    }

    manifests
}

/// Build a single ACP agent manifest from the server's metadata and tools.
pub fn build_manifest(server: &McpServer) -> AgentManifest {
    let info = server.server_info();
    let agent_name = to_dns_label(&info.name);

    let tools = server
        .handle_list_tools(
            &crate::auth::AgentIdentity::new("_acp_discovery", "admin"),
            &Default::default(),
        )
        .tools;

    let capabilities: Vec<AgentCapability> = tools
        .iter()
        .map(|t| AgentCapability {
            name: t.name.clone(),
            description: t.description.clone().unwrap_or_default(),
        })
        .collect();

    let version = info.version.unwrap_or_else(|| "0.0.0".to_string());

    AgentManifest {
        name: agent_name,
        description: format!("navra gateway agent (v{})", version),
        input_content_types: vec!["text/plain".to_string(), "application/json".to_string()],
        output_content_types: vec!["text/plain".to_string(), "application/json".to_string()],
        metadata: Some(AgentMetadata {
            programming_language: Some("Rust".to_string()),
            framework: Some("navra".to_string()),
            capabilities: if capabilities.is_empty() {
                None
            } else {
                Some(capabilities)
            },
            annotations: None,
            documentation: None,
            license: None,
            natural_languages: None,
            domains: None,
            tags: None,
            author: None,
            links: None,
            recommended_models: None,
        }),
        status: None,
    }
}

/// Attach run metrics to a manifest as AgentStatus.
pub fn with_metrics(mut manifest: AgentManifest, store: &RunStore) -> AgentManifest {
    let m = store.metrics();
    if m.total_runs > 0 {
        manifest.status = Some(AgentStatus {
            avg_run_time_seconds: Some(m.avg_run_time()),
            avg_run_tokens: None,
            success_rate: Some(m.success_rate()),
        });
    }
    manifest
}

/// Convert a server name to an RFC 1123 DNS label (ACP requirement).
fn to_dns_label(name: &str) -> String {
    let label: String = name
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let label = label.trim_matches('-').to_string();
    if label.is_empty() {
        "agent".to_string()
    } else if label.len() > 63 {
        label[..63].trim_end_matches('-').to_string()
    } else {
        label
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_label_lowercases_and_replaces() {
        assert_eq!(to_dns_label("My Agent"), "my-agent");
        assert_eq!(to_dns_label("navra-server"), "navra-server");
        assert_eq!(to_dns_label("Test_Agent"), "test-agent");
    }

    #[test]
    fn dns_label_empty_fallback() {
        assert_eq!(to_dns_label(""), "agent");
        assert_eq!(to_dns_label("---"), "agent");
    }

    #[test]
    fn dns_label_truncation() {
        let long = "a".repeat(100);
        let result = to_dns_label(&long);
        assert!(result.len() <= 63);
    }

    #[test]
    fn flow_manifests_appended() {
        let flows = vec![FlowSummary {
            name: "security-audit".to_string(),
            description: "Security audit flow".to_string(),
            nodes: vec![
                super::super::types::FlowNodeSummary {
                    id: "scan".to_string(),
                    description: "Scan for vulnerabilities".to_string(),
                },
                super::super::types::FlowNodeSummary {
                    id: "fix".to_string(),
                    description: "Fix discovered issues".to_string(),
                },
            ],
        }];
        // Can't call build_manifests without a real server,
        // but verify DNS label generation for flow agents
        assert_eq!(to_dns_label("security-audit-scan"), "security-audit-scan");
        assert_eq!(to_dns_label("security-audit-fix"), "security-audit-fix");
        assert_eq!(flows[0].nodes.len(), 2);
    }
}
