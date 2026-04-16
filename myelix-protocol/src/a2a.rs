use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A2A protocol version supported by this implementation.
pub const A2A_PROTOCOL_VERSION: &str = "0.2.5";

// --- A2A Error Codes ---

pub const TASK_NOT_FOUND: i32 = -32001;
pub const TASK_NOT_CANCELABLE: i32 = -32002;
pub const PUSH_NOTIFICATION_NOT_SUPPORTED: i32 = -32003;
pub const UNSUPPORTED_OPERATION: i32 = -32004;
pub const CONTENT_TYPE_NOT_SUPPORTED: i32 = -32005;
pub const INVALID_AGENT_RESPONSE: i32 = -32006;

// --- Agent Card ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    pub name: String,
    pub description: String,
    pub url: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<AgentProvider>,
    /// DID:key identifier for this agent's cryptographic identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    pub capabilities: AgentCapabilities,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
    pub skills: Vec<AgentSkill>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    pub protocol_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProvider {
    pub organization: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_notifications: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_transition_history: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_modes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_modes: Option<Vec<String>>,
}

// --- Message ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub role: MessageRole,
    pub parts: Vec<Part>,
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reference_task_ids: Vec<String>,
    #[serde(default)]
    pub kind: MessageKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    User,
    Agent,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum MessageKind {
    #[default]
    #[serde(rename = "message")]
    Message,
}

// --- Part ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Part {
    Text {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<HashMap<String, serde_json::Value>>,
    },
    File {
        file: FileContent,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<HashMap<String, serde_json::Value>>,
    },
    Data {
        data: HashMap<String, serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<HashMap<String, serde_json::Value>>,
    },
}

impl Part {
    pub fn text(text: impl Into<String>) -> Self {
        Part::Text {
            text: text.into(),
            metadata: None,
        }
    }

    pub fn data(data: HashMap<String, serde_json::Value>) -> Self {
        Part::Data {
            data,
            metadata: None,
        }
    }
}

// --- FileContent ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FileContent {
    Bytes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        bytes: String,
    },
    Uri {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        uri: String,
    },
}

// --- Task ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Task {
    pub id: String,
    pub context_id: String,
    pub status: TaskStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<Message>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<Artifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub kind: TaskKind,
    /// Agent name that created this task (not serialized — internal tracking).
    #[serde(skip)]
    #[serde(default)]
    pub creator: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum TaskKind {
    #[default]
    #[serde(rename = "task")]
    Task,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatus {
    pub state: TaskState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskState {
    Submitted,
    Working,
    InputRequired,
    AuthRequired,
    Completed,
    Failed,
    Canceled,
    Rejected,
    Unknown,
}

impl TaskState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskState::Completed
                | TaskState::Failed
                | TaskState::Canceled
                | TaskState::Rejected
                | TaskState::Unknown
        )
    }
}

// --- Artifact ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub artifact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub parts: Vec<Part>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

// --- Request Params ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSendParams {
    pub message: Message,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<MessageSendConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSendConfiguration {
    #[serde(default)]
    pub accepted_output_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskQueryParams {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskIdParams {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

// --- Streaming Events ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatusUpdateEvent {
    pub task_id: String,
    pub context_id: String,
    pub status: TaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#final: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub kind: StatusUpdateKind,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum StatusUpdateKind {
    #[default]
    #[serde(rename = "status-update")]
    StatusUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskArtifactUpdateEvent {
    pub task_id: String,
    pub context_id: String,
    pub artifact: Artifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub append: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_chunk: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub kind: ArtifactUpdateKind,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum ArtifactUpdateKind {
    #[default]
    #[serde(rename = "artifact-update")]
    ArtifactUpdate,
}

/// Unified streaming result type for SSE events.
///
/// Each SSE `data:` line carries a JSON-RPC response whose `result`
/// is one of these variants, discriminated by the `kind` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StreamingResult {
    Task(Task),
    Message(Message),
    StatusUpdate(TaskStatusUpdateEvent),
    ArtifactUpdate(TaskArtifactUpdateEvent),
}

// --- Timestamp helper ---

pub fn now_iso8601() -> String {
    // Use a simple UTC timestamp without external chrono dependency.
    // Format: seconds since epoch as a string (not ideal but functional).
    // Consumers should treat this as opaque.
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_task_state() {
        assert_eq!(
            serde_json::to_value(TaskState::InputRequired).unwrap(),
            "input-required"
        );
        assert_eq!(
            serde_json::to_value(TaskState::Completed).unwrap(),
            "completed"
        );
    }

    #[test]
    fn deserialize_task_state() {
        let state: TaskState = serde_json::from_str("\"working\"").unwrap();
        assert_eq!(state, TaskState::Working);
    }

    #[test]
    fn terminal_states() {
        assert!(!TaskState::Submitted.is_terminal());
        assert!(!TaskState::Working.is_terminal());
        assert!(!TaskState::InputRequired.is_terminal());
        assert!(TaskState::Completed.is_terminal());
        assert!(TaskState::Failed.is_terminal());
        assert!(TaskState::Canceled.is_terminal());
    }

    #[test]
    fn serialize_text_part() {
        let part = Part::text("hello");
        let json = serde_json::to_value(&part).unwrap();
        assert_eq!(json["kind"], "text");
        assert_eq!(json["text"], "hello");
    }

    #[test]
    fn serialize_data_part() {
        let mut data = HashMap::new();
        data.insert("key".to_string(), serde_json::json!("value"));
        let part = Part::data(data);
        let json = serde_json::to_value(&part).unwrap();
        assert_eq!(json["kind"], "data");
        assert_eq!(json["data"]["key"], "value");
    }

    #[test]
    fn deserialize_message() {
        let json = serde_json::json!({
            "role": "user",
            "parts": [{"kind": "text", "text": "hello"}],
            "messageId": "msg-1",
            "kind": "message"
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.message_id, "msg-1");
        assert_eq!(msg.parts.len(), 1);
    }

    #[test]
    fn serialize_task() {
        let task = Task {
            id: "t-1".to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: Some("1234Z".to_string()),
            },
            history: vec![],
            artifacts: vec![],
            metadata: None,
            kind: TaskKind::Task,
            creator: String::new(),
        };
        let json = serde_json::to_value(&task).unwrap();
        assert_eq!(json["kind"], "task");
        assert_eq!(json["status"]["state"], "completed");
        assert_eq!(json["id"], "t-1");
    }

    #[test]
    fn serialize_agent_card() {
        let card = AgentCard {
            name: "test-agent".to_string(),
            description: "A test agent".to_string(),
            url: "https://example.com/a2a".to_string(),
            version: "0.1.0".to_string(),
            provider: Some(AgentProvider {
                organization: "test".to_string(),
                url: "https://example.com".to_string(),
            }),
            did: None,
            capabilities: AgentCapabilities {
                streaming: Some(true),
                push_notifications: Some(false),
                state_transition_history: Some(false),
            },
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            skills: vec![AgentSkill {
                id: "ping".to_string(),
                name: "ping".to_string(),
                description: "Returns pong".to_string(),
                tags: vec!["test".to_string()],
                examples: vec![],
                input_modes: None,
                output_modes: None,
            }],
            documentation_url: None,
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        };
        let json = serde_json::to_value(&card).unwrap();
        assert_eq!(json["protocolVersion"], "0.2.5");
        assert_eq!(json["name"], "test-agent");
        assert_eq!(json["skills"][0]["id"], "ping");
    }

    #[test]
    fn serialize_status_update_event() {
        let event = TaskStatusUpdateEvent {
            task_id: "t-1".to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            r#final: None,
            metadata: None,
            kind: StatusUpdateKind::StatusUpdate,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["kind"], "status-update");
        assert_eq!(json["status"]["state"], "working");
    }

    #[test]
    fn serialize_artifact_update_event() {
        let event = TaskArtifactUpdateEvent {
            task_id: "t-1".to_string(),
            context_id: "ctx-1".to_string(),
            artifact: Artifact {
                artifact_id: "a-1".to_string(),
                name: None,
                description: None,
                parts: vec![Part::text("result")],
                metadata: None,
            },
            append: None,
            last_chunk: Some(true),
            metadata: None,
            kind: ArtifactUpdateKind::ArtifactUpdate,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["kind"], "artifact-update");
        assert!(json["lastChunk"].as_bool().unwrap());
    }

    #[test]
    fn deserialize_file_content_bytes() {
        let json = serde_json::json!({
            "name": "test.txt",
            "bytes": "aGVsbG8="
        });
        let fc: FileContent = serde_json::from_value(json).unwrap();
        match fc {
            FileContent::Bytes { name, bytes, .. } => {
                assert_eq!(name.unwrap(), "test.txt");
                assert_eq!(bytes, "aGVsbG8=");
            }
            _ => panic!("Expected Bytes variant"),
        }
    }

    #[test]
    fn deserialize_file_content_uri() {
        let json = serde_json::json!({
            "uri": "https://example.com/file.txt"
        });
        let fc: FileContent = serde_json::from_value(json).unwrap();
        match fc {
            FileContent::Uri { uri, .. } => {
                assert_eq!(uri, "https://example.com/file.txt");
            }
            _ => panic!("Expected Uri variant"),
        }
    }

    #[test]
    fn message_send_params_roundtrip() {
        let params = MessageSendParams {
            message: Message {
                role: MessageRole::User,
                parts: vec![Part::text("do something")],
                message_id: "m-1".to_string(),
                task_id: None,
                context_id: None,
                metadata: Some(HashMap::from([(
                    "skill".to_string(),
                    serde_json::json!("ping"),
                )])),
                extensions: vec![],
                reference_task_ids: vec![],
                kind: MessageKind::Message,
            },
            configuration: Some(MessageSendConfiguration {
                accepted_output_modes: vec!["text/plain".to_string()],
                history_length: None,
                blocking: Some(true),
            }),
            metadata: None,
        };
        let json = serde_json::to_value(&params).unwrap();
        let roundtrip: MessageSendParams = serde_json::from_value(json).unwrap();
        assert_eq!(roundtrip.message.message_id, "m-1");
    }
}
