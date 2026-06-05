//! ACP v0.2.0 data types matching the OpenAPI specification.
//!
//! Reference: <https://github.com/i-am-bee/acp/blob/main/docs/spec/openapi.yaml>

use serde::{Deserialize, Serialize};

// --- Errors ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    ServerError,
    InvalidInput,
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl AcpError {
    pub fn server_error(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::ServerError,
            message: message.into(),
            data: None,
        }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InvalidInput,
            message: message.into(),
            data: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::NotFound,
            message: message.into(),
            data: None,
        }
    }
}

// --- Agent types ---

pub type AgentName = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentManifest {
    pub name: AgentName,
    pub description: String,
    pub input_content_types: Vec<String>,
    pub output_content_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AgentMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<AgentStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_run_tokens: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_run_time_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapability {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLink {
    #[serde(rename = "type")]
    pub link_type: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Person {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub programming_language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub natural_languages: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<AgentCapability>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<Person>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<AgentLink>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_models: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentsListResponse {
    pub agents: Vec<AgentManifest>,
}

// --- Message types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum MessageMetadata {
    #[serde(rename = "citation")]
    Citation(CitationMetadata),
    #[serde(rename = "trajectory")]
    Trajectory(TrajectoryMetadata),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitationMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_index: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_index: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrajectoryMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_input: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_output: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePart {
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MessageMetadata>,
}

impl MessagePart {
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content_type: "text/plain".to_string(),
            name: None,
            content: Some(content.into()),
            content_encoding: None,
            content_url: None,
            metadata: None,
        }
    }

    pub fn json(content: impl Into<String>) -> Self {
        Self {
            content_type: "application/json".to_string(),
            name: None,
            content: Some(content.into()),
            content_encoding: None,
            content_url: None,
            metadata: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub parts: Vec<MessagePart>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}

// --- Run types ---

pub type RunId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RunStatus {
    Created,
    InProgress,
    Awaiting,
    Cancelling,
    Cancelled,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    Sync,
    Async,
    Stream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunCreateRequest {
    pub agent_name: AgentName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionSpec>,
    pub input: Vec<Message>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<RunMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResumeRequest {
    pub run_id: RunId,
    pub await_resume: serde_json::Value,
    pub mode: RunMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub agent_name: AgentName,
    pub run_id: RunId,
    pub status: RunStatus,
    pub output: Vec<Message>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub await_request: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AcpError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
}

// --- Session types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSpec {
    pub id: String,
    pub history: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

// --- Event types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Event {
    #[serde(rename = "message.created")]
    MessageCreated { message: Message },
    #[serde(rename = "message.part")]
    MessagePart { part: self::MessagePart },
    #[serde(rename = "message.completed")]
    MessageCompleted { message: Message },
    #[serde(rename = "run.created")]
    RunCreated { run: Run },
    #[serde(rename = "run.in-progress")]
    RunInProgress { run: Run },
    #[serde(rename = "run.awaiting")]
    RunAwaiting { run: Run },
    #[serde(rename = "run.completed")]
    RunCompleted { run: Run },
    #[serde(rename = "run.cancelled")]
    RunCancelled { run: Run },
    #[serde(rename = "run.failed")]
    RunFailed { run: Run },
    #[serde(rename = "error")]
    Error { error: AcpError },
    #[serde(rename = "generic")]
    Generic { generic: serde_json::Value },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunEventsListResponse {
    pub events: Vec<Event>,
}

// --- Pagination ---

#[derive(Debug, Clone, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    10
}

// --- Flow summary (lightweight, avoids pulling navra-flow types) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummary {
    pub name: String,
    pub description: String,
    pub nodes: Vec<FlowNodeSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowNodeSummary {
    pub id: String,
    pub description: String,
}
