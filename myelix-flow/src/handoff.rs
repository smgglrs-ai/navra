//! Handoff tool definition, routing prompt generation, and handoff parsing.

use crate::definition::EdgeDefinition;
use crate::error::FlowError;
use myelix_model::ChatToolDefinition;

/// Name of the virtual handoff tool.
pub const HANDOFF_TOOL_NAME: &str = "handoff";

/// A parsed handoff request from the model.
#[derive(Debug, Clone)]
pub struct HandoffRequest {
    /// Target node ID.
    pub target: String,
    /// Task description for the target agent.
    pub task: String,
}

/// Create the virtual handoff tool definition for model chat.
pub fn handoff_tool_def() -> ChatToolDefinition {
    ChatToolDefinition {
        name: HANDOFF_TOOL_NAME.to_string(),
        description: "Transfer control to another specialist agent. Use this when the task \
                      requires capabilities outside your expertise."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The ID of the agent to hand off to."
                },
                "task": {
                    "type": "string",
                    "description": "A clear description of what the target agent should do, \
                                   including all relevant context."
                }
            },
            "required": ["target", "task"]
        }),
    }
}

/// Generate routing instructions from outgoing edges.
///
/// Appended to a node's system prompt so the model knows which
/// specialists are available and when to hand off.
pub fn routing_instructions(edges: &[EdgeDefinition]) -> String {
    if edges.is_empty() {
        return String::new();
    }
    let mut instructions = String::from(
        "\n\n## Handoff Routing\n\n\
         You have access to a `handoff` tool to delegate tasks to specialist agents. \
         Use it when the task falls outside your expertise. Available targets:\n\n",
    );
    for edge in edges {
        instructions.push_str(&format!("- **{}**: {}\n", edge.to, edge.description));
    }
    instructions.push_str(
        "\nOnly use handoff when the task genuinely requires another specialist. \
         If you can handle the task yourself, do so directly.\n",
    );
    instructions
}

/// Parse a handoff tool call's arguments.
pub fn parse_handoff(arguments: &str) -> Result<HandoffRequest, FlowError> {
    let args: serde_json::Value = serde_json::from_str(arguments)
        .map_err(|e| FlowError::InvalidFlow(format!("invalid handoff arguments: {e}")))?;
    let target = args["target"]
        .as_str()
        .ok_or_else(|| FlowError::InvalidFlow("handoff missing 'target' field".into()))?
        .to_string();
    let task = args["task"]
        .as_str()
        .ok_or_else(|| FlowError::InvalidFlow("handoff missing 'task' field".into()))?
        .to_string();
    Ok(HandoffRequest { target, task })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_tool_has_required_params() {
        let tool = handoff_tool_def();
        assert_eq!(tool.name, "handoff");
        let required = tool.parameters["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "target"));
        assert!(required.iter().any(|v| v == "task"));
    }

    #[test]
    fn routing_instructions_empty_edges() {
        assert_eq!(routing_instructions(&[]), "");
    }

    #[test]
    fn routing_instructions_with_edges() {
        let edges = vec![
            EdgeDefinition {
                from: "a".into(),
                to: "coder".into(),
                description: "Coding tasks".into(),
            },
            EdgeDefinition {
                from: "a".into(),
                to: "writer".into(),
                description: "Writing tasks".into(),
            },
        ];
        let result = routing_instructions(&edges);
        assert!(result.contains("**coder**: Coding tasks"));
        assert!(result.contains("**writer**: Writing tasks"));
        assert!(result.contains("handoff"));
    }

    #[test]
    fn parse_valid_handoff() {
        let args = r#"{"target": "coder", "task": "Write fizzbuzz"}"#;
        let req = parse_handoff(args).unwrap();
        assert_eq!(req.target, "coder");
        assert_eq!(req.task, "Write fizzbuzz");
    }

    #[test]
    fn parse_handoff_missing_target() {
        let args = r#"{"task": "something"}"#;
        assert!(parse_handoff(args).is_err());
    }

    #[test]
    fn parse_handoff_missing_task() {
        let args = r#"{"target": "coder"}"#;
        assert!(parse_handoff(args).is_err());
    }

    #[test]
    fn parse_handoff_invalid_json() {
        assert!(parse_handoff("not json").is_err());
    }
}
