//! Virtual tool definitions for mesh communication.
//!
//! These tools are injected into agent tool lists alongside the handoff
//! tool, allowing agents to send messages via mailbox and read/write
//! shared blackboard entries.

use crate::error::FlowError;
use navra_model::ResponseTool;

/// Virtual tool name for posting a message to another agent's mailbox.
pub const MESH_POST: &str = "mesh_post";
/// Virtual tool name for receiving pending mailbox messages.
pub const MESH_RECV: &str = "mesh_recv";
/// Virtual tool name for publishing a key-value pair to the blackboard.
pub const BB_PUBLISH: &str = "bb_publish";
/// Virtual tool name for reading a key from the blackboard.
pub const BB_READ: &str = "bb_read";
/// Virtual tool name for listing blackboard keys.
pub const BB_KEYS: &str = "bb_keys";
/// Virtual tool name for killing a running flow.
pub const FLOW_KILL: &str = "flow_kill";

pub fn mesh_post_tool_def() -> ResponseTool {
    ResponseTool {
        kind: "function".to_string(),
        name: MESH_POST.to_string(),
        description: Some(
            "Send a message to another agent in the flow. The message will be \
             delivered to the target agent's mailbox for later retrieval."
                .to_string(),
        ),
        strict: None,
        parameters: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The ID of the agent to send the message to."
                },
                "message": {
                    "type": "string",
                    "description": "The message content to send."
                }
            },
            "required": ["target", "message"]
        })),
    }
}

pub fn mesh_recv_tool_def() -> ResponseTool {
    ResponseTool {
        kind: "function".to_string(),
        name: MESH_RECV.to_string(),
        description: Some(
            "Receive all pending messages from your mailbox. Returns a JSON array \
             of messages, each with sender and body fields."
                .to_string(),
        ),
        strict: None,
        parameters: Some(serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        })),
    }
}

pub fn bb_publish_tool_def() -> ResponseTool {
    ResponseTool {
        kind: "function".to_string(),
        name: BB_PUBLISH.to_string(),
        description: Some(
            "Publish a key-value pair to the shared blackboard. Other agents \
             in the flow can read it. Overwrites any existing value for the key."
                .to_string(),
        ),
        strict: None,
        parameters: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "The key to publish under."
                },
                "value": {
                    "description": "The value to publish (any JSON type)."
                }
            },
            "required": ["key", "value"]
        })),
    }
}

pub fn bb_read_tool_def() -> ResponseTool {
    ResponseTool {
        kind: "function".to_string(),
        name: BB_READ.to_string(),
        description: Some(
            "Read a value from the shared blackboard by key. Returns the value \
             and metadata (author, version). Returns an error if the key does not exist."
                .to_string(),
        ),
        strict: None,
        parameters: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "The key to read."
                }
            },
            "required": ["key"]
        })),
    }
}

pub fn bb_keys_tool_def() -> ResponseTool {
    ResponseTool {
        kind: "function".to_string(),
        name: BB_KEYS.to_string(),
        description: Some(
            "List all keys currently on the shared blackboard. Returns a JSON \
             array of key names."
                .to_string(),
        ),
        strict: None,
        parameters: Some(serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        })),
    }
}

pub fn flow_kill_tool_def() -> ResponseTool {
    ResponseTool {
        kind: "function".to_string(),
        name: FLOW_KILL.to_string(),
        description: Some(
            "Kill the current flow immediately. Use this when an unrecoverable \
             error is detected or the flow should be aborted."
                .to_string(),
        ),
        strict: None,
        parameters: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Why the flow is being killed."
                }
            },
            "required": ["reason"]
        })),
    }
}

/// Parse mesh_post arguments.
pub fn parse_mesh_post(arguments: &str) -> Result<(String, String), FlowError> {
    let args: serde_json::Value = serde_json::from_str(arguments)
        .map_err(|e| FlowError::InvalidFlow(format!("invalid mesh_post arguments: {e}")))?;
    let target = args["target"]
        .as_str()
        .ok_or_else(|| FlowError::InvalidFlow("mesh_post missing 'target' field".into()))?
        .to_string();
    let message = args["message"]
        .as_str()
        .ok_or_else(|| FlowError::InvalidFlow("mesh_post missing 'message' field".into()))?
        .to_string();
    Ok((target, message))
}

/// Parse bb_publish arguments.
pub fn parse_bb_publish(arguments: &str) -> Result<(String, serde_json::Value), FlowError> {
    let args: serde_json::Value = serde_json::from_str(arguments)
        .map_err(|e| FlowError::InvalidFlow(format!("invalid bb_publish arguments: {e}")))?;
    let key = args["key"]
        .as_str()
        .ok_or_else(|| FlowError::InvalidFlow("bb_publish missing 'key' field".into()))?
        .to_string();
    let value = args
        .get("value")
        .cloned()
        .ok_or_else(|| FlowError::InvalidFlow("bb_publish missing 'value' field".into()))?;
    Ok((key, value))
}

/// Parse bb_read arguments.
pub fn parse_bb_read(arguments: &str) -> Result<String, FlowError> {
    let args: serde_json::Value = serde_json::from_str(arguments)
        .map_err(|e| FlowError::InvalidFlow(format!("invalid bb_read arguments: {e}")))?;
    let key = args["key"]
        .as_str()
        .ok_or_else(|| FlowError::InvalidFlow("bb_read missing 'key' field".into()))?
        .to_string();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_post_tool_has_required_params() {
        let tool = mesh_post_tool_def();
        assert_eq!(tool.name, MESH_POST);
        let params = tool.parameters.as_ref().unwrap();
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "target"));
        assert!(required.iter().any(|v| v == "message"));
    }

    #[test]
    fn bb_publish_tool_has_required_params() {
        let tool = bb_publish_tool_def();
        assert_eq!(tool.name, BB_PUBLISH);
        let params = tool.parameters.as_ref().unwrap();
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "key"));
        assert!(required.iter().any(|v| v == "value"));
    }

    #[test]
    fn bb_read_tool_has_required_params() {
        let tool = bb_read_tool_def();
        assert_eq!(tool.name, BB_READ);
        let params = tool.parameters.as_ref().unwrap();
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "key"));
    }

    #[test]
    fn parse_mesh_post_valid() {
        let args = r#"{"target": "agent_b", "message": "hello"}"#;
        let (target, msg) = parse_mesh_post(args).unwrap();
        assert_eq!(target, "agent_b");
        assert_eq!(msg, "hello");
    }

    #[test]
    fn parse_mesh_post_missing_target() {
        let args = r#"{"message": "hello"}"#;
        assert!(parse_mesh_post(args).is_err());
    }

    #[test]
    fn parse_bb_publish_valid() {
        let args = r#"{"key": "result", "value": {"score": 95}}"#;
        let (key, value) = parse_bb_publish(args).unwrap();
        assert_eq!(key, "result");
        assert_eq!(value["score"], 95);
    }

    #[test]
    fn parse_bb_read_valid() {
        let args = r#"{"key": "result"}"#;
        let key = parse_bb_read(args).unwrap();
        assert_eq!(key, "result");
    }

    #[test]
    fn parse_bb_read_missing_key() {
        let args = r#"{}"#;
        assert!(parse_bb_read(args).is_err());
    }
}
