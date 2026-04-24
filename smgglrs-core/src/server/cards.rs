use crate::protocol::a2a::{
    AgentCapabilities, AgentCard, AgentProvider, AgentSkill, A2A_PROTOCOL_VERSION,
};

use super::McpServer;

impl McpServer {
    /// Generate a Server Card: static metadata about this server's
    /// capabilities, tools, prompts, and resources.
    ///
    /// Served at `/.well-known/mcp.json` to enable client
    /// autoconfiguration without a full initialize handshake.
    pub fn server_card(&self) -> serde_json::Value {
        let tools: Vec<_> = self
            .tools
            .values()
            .map(|t| {
                serde_json::json!({
                    "name": t.definition.name,
                    "description": t.definition.description,
                })
            })
            .collect();

        let prompts: Vec<_> = self
            .prompts
            .values()
            .map(|p| {
                serde_json::json!({
                    "name": p.definition.name,
                    "description": p.definition.description,
                    "arguments": p.definition.arguments,
                })
            })
            .collect();

        let resources: Vec<_> = self
            .resources
            .values()
            .map(|r| {
                serde_json::json!({
                    "uri": r.definition.uri,
                    "name": r.definition.name,
                    "description": r.definition.description,
                    "mimeType": r.definition.mime_type,
                })
            })
            .collect();

        serde_json::json!({
            "serverInfo": self.server_info(),
            "capabilities": self.capabilities(),
            "protocolVersion": crate::protocol::PROTOCOL_VERSION,
            "tools": tools,
            "prompts": prompts,
            "resources": resources,
        })
    }

    /// Generate an A2A Agent Card describing this server's capabilities
    /// as skills for agent-to-agent discovery.
    ///
    /// Served at `GET /.well-known/agent.json`. Each registered tool
    /// becomes a skill. Tools sharing a prefix (e.g., `docs_*`) are
    /// tagged by module name.
    pub fn agent_card(&self, endpoint_url: &str, root_did: Option<&str>) -> AgentCard {
        let skills: Vec<AgentSkill> = self
            .tools
            .values()
            .map(|t| {
                let name = &t.definition.name;
                let tag = name.split('_').next().unwrap_or(name).to_string();
                AgentSkill {
                    id: name.clone(),
                    name: name.clone(),
                    description: t.definition.description.clone().unwrap_or_default(),
                    tags: vec![tag],
                    examples: vec![],
                    input_modes: None,
                    output_modes: None,
                }
            })
            .collect();

        let has_voice = self.tools.keys().any(|k| k.starts_with("voice_"));
        let mut input_modes = vec!["text/plain".to_string()];
        let mut output_modes = vec!["text/plain".to_string()];
        if has_voice {
            input_modes.push("audio/wav".to_string());
            output_modes.push("audio/wav".to_string());
        }

        AgentCard {
            name: self.name.clone(),
            description: format!(
                "MCP gateway with {} tools across {} capabilities",
                self.tools.len(),
                self.tools
                    .keys()
                    .map(|k| k.split('_').next().unwrap_or(k))
                    .collect::<std::collections::HashSet<_>>()
                    .len()
            ),
            url: endpoint_url.to_string(),
            version: self.version.clone(),
            provider: Some(AgentProvider {
                organization: "smgglrs".to_string(),
                url: endpoint_url.to_string(),
            }),
            did: root_did.map(String::from),
            capabilities: AgentCapabilities {
                streaming: Some(true),
                push_notifications: Some(false),
                state_transition_history: Some(false),
            },
            default_input_modes: input_modes,
            default_output_modes: output_modes,
            skills,
            documentation_url: None,
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        }
    }
}
