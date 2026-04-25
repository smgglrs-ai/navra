//! Outbound A2A (Agent-to-Agent) protocol client.
//!
//! Sends tasks to remote agent endpoints using the A2A protocol.
//! Supports IFC label propagation via `X-Smgglrs-DataLabel` header
//! and authentication via scoped capability tokens.

use crate::a2a::{
    AgentCard, Message, MessageSendParams, Task, TaskIdParams, TaskQueryParams, TaskState,
};
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse, RequestId};
use std::time::Duration;

/// Default timeout for A2A requests.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Custom header for IFC data label propagation.
pub const DATA_LABEL_HEADER: &str = "X-Smgglrs-DataLabel";

/// Client for outbound A2A protocol calls.
///
/// Wraps a JSON-RPC transport over HTTP to communicate with remote
/// agent endpoints following the A2A protocol spec.
pub struct A2aClient {
    /// A2A endpoint URL (e.g., "http://gateway:9315/a2a/teammates/analyst").
    endpoint: String,
    /// Bearer token for authentication.
    auth_token: String,
    /// HTTP client with connection pooling.
    http: reqwest::Client,
    /// Request timeout.
    timeout: Duration,
}

impl A2aClient {
    /// Create a new A2A client targeting the given endpoint.
    pub fn new(endpoint: &str, auth_token: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            auth_token: auth_token.to_string(),
            http: reqwest::Client::new(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Set the request timeout (default: 60 seconds).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send a message to the remote agent and receive a task.
    ///
    /// Uses the `message/send` JSON-RPC method. The response contains
    /// the created or updated task with its current status.
    pub async fn send_message(
        &self,
        msg: Message,
        data_label: Option<&str>,
    ) -> Result<Task, A2aError> {
        let params = MessageSendParams {
            message: msg,
            configuration: None,
            metadata: None,
        };

        let rpc_request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "message/send".to_string(),
            params: Some(serde_json::to_value(&params).map_err(A2aError::Serialization)?),
            id: RequestId::Number(1),
        };

        let response: JsonRpcResponse = self.post(&rpc_request, data_label).await?;

        if let Some(error) = response.error {
            return Err(A2aError::Protocol {
                code: error.code,
                message: error.message,
            });
        }

        let result = response
            .result
            .ok_or_else(|| A2aError::Protocol {
                code: -32600,
                message: "empty result in response".to_string(),
            })?;

        serde_json::from_value(result).map_err(A2aError::Serialization)
    }

    /// Query the status of a previously sent task.
    pub async fn get_task(&self, task_id: &str) -> Result<Task, A2aError> {
        let params = TaskQueryParams {
            id: task_id.to_string(),
            history_length: None,
            metadata: None,
        };

        let rpc_request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "tasks/get".to_string(),
            params: Some(serde_json::to_value(&params).map_err(A2aError::Serialization)?),
            id: RequestId::Number(1),
        };

        let response: JsonRpcResponse = self.post(&rpc_request, None).await?;

        if let Some(error) = response.error {
            return Err(A2aError::Protocol {
                code: error.code,
                message: error.message,
            });
        }

        let result = response
            .result
            .ok_or_else(|| A2aError::Protocol {
                code: -32600,
                message: "empty result in response".to_string(),
            })?;

        serde_json::from_value(result).map_err(A2aError::Serialization)
    }

    /// Cancel a running task.
    pub async fn cancel_task(&self, task_id: &str) -> Result<Task, A2aError> {
        let params = TaskIdParams {
            id: task_id.to_string(),
            metadata: None,
        };

        let rpc_request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "tasks/cancel".to_string(),
            params: Some(serde_json::to_value(&params).map_err(A2aError::Serialization)?),
            id: RequestId::Number(1),
        };

        let response: JsonRpcResponse = self.post(&rpc_request, None).await?;

        if let Some(error) = response.error {
            return Err(A2aError::Protocol {
                code: error.code,
                message: error.message,
            });
        }

        let result = response
            .result
            .ok_or_else(|| A2aError::Protocol {
                code: -32600,
                message: "empty result in response".to_string(),
            })?;

        serde_json::from_value(result).map_err(A2aError::Serialization)
    }

    /// Fetch the remote agent's Agent Card via `GET /.well-known/agent.json`.
    pub async fn discover(&self) -> Result<AgentCard, A2aError> {
        // Agent Card is served at the well-known path relative to the base URL.
        let base = self
            .endpoint
            .trim_end_matches('/')
            .rsplit_once('/')
            .map(|(base, _)| base)
            .unwrap_or(&self.endpoint);
        let url = format!("{base}/.well-known/agent.json");

        let response = self
            .http
            .get(&url)
            .bearer_auth(&self.auth_token)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(A2aError::Network)?;

        let status = response.status();
        if !status.is_success() {
            return Err(A2aError::Protocol {
                code: status.as_u16() as i32,
                message: format!("HTTP {status} from agent card endpoint"),
            });
        }

        response.json().await.map_err(A2aError::Network)
    }

    /// Poll a task until it reaches a terminal state.
    ///
    /// Returns the final task. Polls at the given interval.
    pub async fn poll_until_complete(
        &self,
        task_id: &str,
        interval: Duration,
    ) -> Result<Task, A2aError> {
        loop {
            let task = self.get_task(task_id).await?;
            if task.status.state.is_terminal() {
                return Ok(task);
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Return the endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Send a JSON-RPC request to the A2A endpoint.
    async fn post(
        &self,
        request: &JsonRpcRequest,
        data_label: Option<&str>,
    ) -> Result<JsonRpcResponse, A2aError> {
        let mut req = self
            .http
            .post(&self.endpoint)
            .bearer_auth(&self.auth_token)
            .header("Content-Type", "application/json")
            .timeout(self.timeout)
            .json(request);

        if let Some(label) = data_label {
            req = req.header(DATA_LABEL_HEADER, label);
        }

        let response = req.send().await.map_err(A2aError::Network)?;

        let status = response.status();
        if !status.is_success() {
            return Err(A2aError::Protocol {
                code: status.as_u16() as i32,
                message: format!("HTTP {status}"),
            });
        }

        response.json().await.map_err(A2aError::Network)
    }
}

/// Extract a text response from a completed A2A task.
///
/// Looks through artifacts and history for text parts, returning
/// the first text found or an empty string.
pub fn extract_task_text(task: &Task) -> String {
    // Check artifacts first
    for artifact in &task.artifacts {
        for part in &artifact.parts {
            if let crate::a2a::Part::Text { text, .. } = part {
                return text.clone();
            }
        }
    }

    // Fall back to the status message
    if let Some(ref msg) = task.status.message {
        for part in &msg.parts {
            if let crate::a2a::Part::Text { text, .. } = part {
                return text.clone();
            }
        }
    }

    String::new()
}

/// Check if a task completed successfully.
pub fn task_succeeded(task: &Task) -> bool {
    task.status.state == TaskState::Completed
}

/// Error type for A2A client operations.
#[derive(Debug, thiserror::Error)]
pub enum A2aError {
    /// HTTP/network-level error.
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// A2A protocol-level error (JSON-RPC error response).
    #[error("A2A protocol error: code={code}, message={message}")]
    Protocol {
        code: i32,
        message: String,
    },

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[source] serde_json::Error),

    /// IFC violation detected before sending.
    #[error("IFC violation: {0}")]
    IfcViolation(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a::{
        AgentCapabilities, AgentCard, AgentSkill, Message, MessageKind, MessageRole, Part, Task,
        TaskKind, TaskState, TaskStatus, A2A_PROTOCOL_VERSION,
    };

    #[test]
    fn a2a_client_construction() {
        let client = A2aClient::new("http://localhost:9315/a2a", "token123");
        assert_eq!(client.endpoint(), "http://localhost:9315/a2a");
        assert_eq!(client.auth_token, "token123");
        assert_eq!(client.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn a2a_client_with_timeout() {
        let client = A2aClient::new("http://localhost:9315/a2a", "token123")
            .with_timeout(Duration::from_secs(30));
        assert_eq!(client.timeout, Duration::from_secs(30));
    }

    #[test]
    fn extract_text_from_artifact() {
        let task = Task {
            id: "t-1".into(),
            context_id: "ctx-1".into(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            history: vec![],
            artifacts: vec![crate::a2a::Artifact {
                artifact_id: "a-1".into(),
                name: None,
                description: None,
                parts: vec![Part::text("result text")],
                metadata: None,
            }],
            metadata: None,
            kind: TaskKind::Task,
            creator: String::new(),
        };

        assert_eq!(extract_task_text(&task), "result text");
    }

    #[test]
    fn extract_text_from_status_message() {
        let task = Task {
            id: "t-1".into(),
            context_id: "ctx-1".into(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: Some(Message {
                    role: MessageRole::Agent,
                    parts: vec![Part::text("status response")],
                    message_id: "m-1".into(),
                    task_id: None,
                    context_id: None,
                    metadata: None,
                    extensions: vec![],
                    reference_task_ids: vec![],
                    kind: MessageKind::Message,
                }),
                timestamp: None,
            },
            history: vec![],
            artifacts: vec![],
            metadata: None,
            kind: TaskKind::Task,
            creator: String::new(),
        };

        assert_eq!(extract_task_text(&task), "status response");
    }

    #[test]
    fn extract_text_empty_task() {
        let task = Task {
            id: "t-1".into(),
            context_id: "ctx-1".into(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            history: vec![],
            artifacts: vec![],
            metadata: None,
            kind: TaskKind::Task,
            creator: String::new(),
        };

        assert_eq!(extract_task_text(&task), "");
    }

    #[test]
    fn task_succeeded_check() {
        let completed = Task {
            id: "t-1".into(),
            context_id: "ctx-1".into(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            history: vec![],
            artifacts: vec![],
            metadata: None,
            kind: TaskKind::Task,
            creator: String::new(),
        };
        assert!(task_succeeded(&completed));

        let failed = Task {
            id: "t-2".into(),
            context_id: "ctx-1".into(),
            status: TaskStatus {
                state: TaskState::Failed,
                message: None,
                timestamp: None,
            },
            history: vec![],
            artifacts: vec![],
            metadata: None,
            kind: TaskKind::Task,
            creator: String::new(),
        };
        assert!(!task_succeeded(&failed));
    }

    #[test]
    fn data_label_header_constant() {
        assert_eq!(DATA_LABEL_HEADER, "X-Smgglrs-DataLabel");
    }

    #[test]
    fn a2a_error_display() {
        let err = A2aError::Protocol {
            code: -32001,
            message: "task not found".into(),
        };
        assert!(err.to_string().contains("-32001"));
        assert!(err.to_string().contains("task not found"));
    }
}
