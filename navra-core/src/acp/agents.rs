//! Map navra McpServer capabilities to ACP AgentManifest.

use super::types::{AgentCapability, AgentManifest, AgentMetadata, AgentsListResponse};
use crate::server::McpServer;

/// Build a single ACP agent manifest from the server's metadata and tools.
///
/// navra exposes one logical agent per server instance. The agent name
/// is derived from `ServerInfo.name`, converted to the RFC 1123 DNS
/// label format required by ACP.
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

pub fn list_agents(server: &McpServer) -> AgentsListResponse {
    AgentsListResponse {
        agents: vec![build_manifest(server)],
    }
}

/// Convert a server name to an RFC 1123 DNS label (ACP requirement).
fn to_dns_label(name: &str) -> String {
    let label: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
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
}
