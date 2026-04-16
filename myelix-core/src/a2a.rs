//! A2A task store and message dispatch logic.
//!
//! Maps incoming A2A messages to MCP tool calls. The skill/tool name
//! is resolved from `message.metadata["skill"]`, a `DataPart` with
//! a `"tool"` key, or by matching the message text against registered
//! tool names.

use crate::auth::CallContext;
use crate::protocol::a2a::{
    self, Artifact, Message, MessageSendParams, Part, Task, TaskIdParams,
    TaskQueryParams, TaskState, TaskStatus, TASK_NOT_CANCELABLE, TASK_NOT_FOUND,
    UNSUPPORTED_OPERATION,
};
use crate::protocol::{CallToolParams, JsonRpcError};
use crate::server::McpServer;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Thread-safe in-memory store for A2A tasks.
#[derive(Debug, Clone, Default)]
pub struct TaskStore {
    tasks: Arc<RwLock<HashMap<String, Task>>>,
}

impl TaskStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&self, task: Task) {
        let mut tasks = self.tasks.write().unwrap_or_else(|e| e.into_inner());
        tasks.insert(task.id.clone(), task);
    }

    pub fn get(&self, id: &str) -> Option<Task> {
        let tasks = self.tasks.read().unwrap_or_else(|e| e.into_inner());
        tasks.get(id).cloned()
    }

    pub fn update_status(&self, id: &str, status: TaskStatus) -> Option<Task> {
        let mut tasks = self.tasks.write().unwrap_or_else(|e| e.into_inner());
        if let Some(task) = tasks.get_mut(id) {
            task.status = status;
            Some(task.clone())
        } else {
            None
        }
    }

    pub fn add_artifact(&self, id: &str, artifact: Artifact) -> Option<Task> {
        let mut tasks = self.tasks.write().unwrap_or_else(|e| e.into_inner());
        if let Some(task) = tasks.get_mut(id) {
            task.artifacts.push(artifact);
            Some(task.clone())
        } else {
            None
        }
    }

    pub fn count(&self) -> usize {
        self.tasks.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Resolve which tool to call from the incoming A2A message.
///
/// Strategy:
/// 1. `message.metadata["skill"]` — explicit tool name
/// 2. First `DataPart` containing a `"tool"` key — tool name from data
/// 3. None — caller must handle the error
fn resolve_tool(message: &Message) -> Option<String> {
    // 1. Explicit skill in metadata
    if let Some(meta) = &message.metadata {
        if let Some(skill) = meta.get("skill").and_then(|v| v.as_str()) {
            return Some(skill.to_string());
        }
    }

    // 2. DataPart with a "tool" field
    for part in &message.parts {
        if let Part::Data { data, .. } = part {
            if let Some(tool) = data.get("tool").and_then(|v| v.as_str()) {
                return Some(tool.to_string());
            }
        }
    }

    None
}

/// Extract tool arguments from the message parts.
///
/// - If a `DataPart` with an `"arguments"` key exists, use that.
/// - If a `DataPart` exists (without `"tool"`/`"arguments"`), use the whole data map.
/// - If only `TextPart`s exist, wrap the concatenated text as `{"text": "..."}`.
/// - Otherwise, empty object.
fn extract_arguments(message: &Message) -> serde_json::Value {
    // Look for explicit arguments in DataParts
    for part in &message.parts {
        if let Part::Data { data, .. } = part {
            if let Some(args) = data.get("arguments") {
                return args.clone();
            }
        }
    }

    // Use the first DataPart's content as arguments (excluding "tool" key)
    for part in &message.parts {
        if let Part::Data { data, .. } = part {
            let mut args: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
            for (k, v) in data {
                if k != "tool" {
                    args.insert(k.clone(), v.clone());
                }
            }
            if !args.is_empty() {
                return serde_json::Value::Object(args);
            }
        }
    }

    // Fall back to concatenated text
    let mut texts = Vec::new();
    for part in &message.parts {
        if let Part::Text { text, .. } = part {
            texts.push(text.as_str());
        }
    }
    if !texts.is_empty() {
        return serde_json::json!({"text": texts.join("\n")});
    }

    serde_json::json!({})
}

/// Convert an MCP `CallToolResult` into A2A parts.
fn tool_result_to_parts(result: &crate::protocol::CallToolResult) -> Vec<Part> {
    result
        .content
        .iter()
        .map(|c| match c {
            crate::protocol::Content::Text(tc) => Part::text(&tc.text),
        })
        .collect()
}

/// Handle `message/send` — synchronous A2A request.
///
/// Returns `(result_value, is_error)` where `result_value` is a
/// serialized `Task` on success or a `JsonRpcError`-compatible value
/// on failure.
pub async fn handle_message_send(
    server: &McpServer,
    task_store: &TaskStore,
    params: MessageSendParams,
    agent: crate::auth::AgentIdentity,
) -> Result<Task, JsonRpcError> {
    let tool_name = resolve_tool(&params.message).ok_or_else(|| {
        JsonRpcError::new(
            crate::protocol::ErrorCode::Custom(UNSUPPORTED_OPERATION),
            "No skill specified. Set message.metadata.skill to a tool name.",
        )
    })?;

    let arguments = extract_arguments(&params.message);

    let task_id = uuid::Uuid::new_v4().to_string();
    let context_id = params
        .message
        .context_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Create task in submitted state
    let task = Task {
        id: task_id.clone(),
        context_id: context_id.clone(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: Some(a2a::now_iso8601()),
        },
        history: vec![params.message],
        artifacts: vec![],
        metadata: None,
        kind: Default::default(),
        creator: agent.name.clone(),
    };
    task_store.create(task);

    // Transition to working
    task_store.update_status(
        &task_id,
        TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: Some(a2a::now_iso8601()),
        },
    );

    // Call the MCP tool
    let ctx = CallContext::new(agent, format!("a2a-{}", task_id));
    let tool_result = server
        .handle_call_tool(
            CallToolParams {
                name: tool_name.clone(),
                arguments,
            },
            ctx,
        )
        .await;

    // Build artifact from result
    let artifact = Artifact {
        artifact_id: uuid::Uuid::new_v4().to_string(),
        name: Some(tool_name),
        description: None,
        parts: tool_result_to_parts(&tool_result),
        metadata: None,
    };
    task_store.add_artifact(&task_id, artifact);

    // Transition to terminal state
    let final_state = if tool_result.is_error {
        TaskState::Failed
    } else {
        TaskState::Completed
    };
    task_store.update_status(
        &task_id,
        TaskStatus {
            state: final_state,
            message: None,
            timestamp: Some(a2a::now_iso8601()),
        },
    );

    task_store.get(&task_id).ok_or_else(|| {
        JsonRpcError::internal("Task disappeared after creation")
    })
}

/// Handle `tasks/get` — retrieve an existing task by ID.
///
/// Only the agent that created the task can retrieve it.
pub fn handle_tasks_get(
    task_store: &TaskStore,
    params: TaskQueryParams,
    agent: &crate::auth::AgentIdentity,
) -> Result<Task, JsonRpcError> {
    let mut task = task_store.get(&params.id).ok_or_else(|| {
        JsonRpcError::new(
            crate::protocol::ErrorCode::Custom(TASK_NOT_FOUND),
            format!("Task not found: {}", params.id),
        )
    })?;

    // Ownership check: only the creator can read the task
    if !task.creator.is_empty() && task.creator != agent.name {
        return Err(JsonRpcError::new(
            crate::protocol::ErrorCode::Custom(TASK_NOT_FOUND),
            format!("Task not found: {}", params.id),
        ));
    }

    // Optionally trim history
    if let Some(len) = params.history_length {
        let len = len as usize;
        if task.history.len() > len {
            let start = task.history.len() - len;
            task.history = task.history[start..].to_vec();
        }
    }

    Ok(task)
}

/// Handle `tasks/cancel` — cancel a running task.
///
/// Only the agent that created the task can cancel it.
/// Only non-terminal tasks can be canceled.
pub fn handle_tasks_cancel(
    task_store: &TaskStore,
    params: TaskIdParams,
    agent: &crate::auth::AgentIdentity,
) -> Result<Task, JsonRpcError> {
    let task = task_store.get(&params.id).ok_or_else(|| {
        JsonRpcError::new(
            crate::protocol::ErrorCode::Custom(TASK_NOT_FOUND),
            format!("Task not found: {}", params.id),
        )
    })?;

    // Ownership check: only the creator can cancel the task
    if !task.creator.is_empty() && task.creator != agent.name {
        return Err(JsonRpcError::new(
            crate::protocol::ErrorCode::Custom(TASK_NOT_FOUND),
            format!("Task not found: {}", params.id),
        ));
    }

    if task.status.state.is_terminal() {
        return Err(JsonRpcError::new(
            crate::protocol::ErrorCode::Custom(TASK_NOT_CANCELABLE),
            format!(
                "Task {} is in terminal state {:?} and cannot be canceled",
                params.id, task.status.state
            ),
        ));
    }

    task_store
        .update_status(
            &params.id,
            TaskStatus {
                state: TaskState::Canceled,
                message: None,
                timestamp: Some(a2a::now_iso8601()),
            },
        )
        .ok_or_else(|| JsonRpcError::internal("Task disappeared during cancel"))
}

/// Build SSE events for `message/stream`.
///
/// Returns a vector of JSON-RPC response values to send as SSE `data:` lines.
pub async fn handle_message_stream(
    server: &McpServer,
    task_store: &TaskStore,
    params: MessageSendParams,
    agent: crate::auth::AgentIdentity,
    request_id: crate::protocol::RequestId,
) -> Vec<crate::protocol::JsonRpcResponse> {
    let tool_name = match resolve_tool(&params.message) {
        Some(name) => name,
        None => {
            return vec![crate::protocol::JsonRpcResponse::error(
                request_id,
                JsonRpcError::new(
                    crate::protocol::ErrorCode::Custom(UNSUPPORTED_OPERATION),
                    "No skill specified. Set message.metadata.skill to a tool name.",
                ),
            )];
        }
    };

    let arguments = extract_arguments(&params.message);

    let task_id = uuid::Uuid::new_v4().to_string();
    let context_id = params
        .message
        .context_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Event 1: Task created (submitted)
    let task = Task {
        id: task_id.clone(),
        context_id: context_id.clone(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: Some(a2a::now_iso8601()),
        },
        history: vec![params.message],
        artifacts: vec![],
        metadata: None,
        kind: Default::default(),
        creator: agent.name.clone(),
    };
    task_store.create(task.clone());

    let mut events = Vec::new();
    events.push(crate::protocol::JsonRpcResponse::success(
        request_id.clone(),
        serde_json::to_value(&task).unwrap_or_else(|e| {
            tracing::error!(error = %e, "Failed to serialize task");
            serde_json::json!({"error": "task serialization failed"})
        }),
    ));

    // Event 2: Status update -> working
    task_store.update_status(
        &task_id,
        TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: Some(a2a::now_iso8601()),
        },
    );
    events.push(crate::protocol::JsonRpcResponse::success(
        request_id.clone(),
        serde_json::json!({
            "kind": "status-update",
            "taskId": task_id,
            "contextId": context_id,
            "status": {"state": "working", "timestamp": a2a::now_iso8601()},
        }),
    ));

    // Execute the tool
    let ctx = CallContext::new(agent, format!("a2a-{}", task_id));
    let tool_result = server
        .handle_call_tool(
            CallToolParams {
                name: tool_name.clone(),
                arguments,
            },
            ctx,
        )
        .await;

    // Event 3: Artifact update
    let artifact = Artifact {
        artifact_id: uuid::Uuid::new_v4().to_string(),
        name: Some(tool_name),
        description: None,
        parts: tool_result_to_parts(&tool_result),
        metadata: None,
    };
    task_store.add_artifact(&task_id, artifact.clone());

    events.push(crate::protocol::JsonRpcResponse::success(
        request_id.clone(),
        serde_json::json!({
            "kind": "artifact-update",
            "taskId": task_id,
            "contextId": context_id,
            "artifact": serde_json::to_value(&artifact).unwrap_or_else(|e| {
                tracing::error!(error = %e, "Failed to serialize artifact");
                serde_json::json!({"error": "artifact serialization failed"})
            }),
            "lastChunk": true,
        }),
    ));

    // Event 4: Final status update
    let final_state = if tool_result.is_error {
        "failed"
    } else {
        "completed"
    };
    let final_task_state = if tool_result.is_error {
        TaskState::Failed
    } else {
        TaskState::Completed
    };
    task_store.update_status(
        &task_id,
        TaskStatus {
            state: final_task_state,
            message: None,
            timestamp: Some(a2a::now_iso8601()),
        },
    );
    events.push(crate::protocol::JsonRpcResponse::success(
        request_id,
        serde_json::json!({
            "kind": "status-update",
            "taskId": task_id,
            "contextId": context_id,
            "status": {"state": final_state, "timestamp": a2a::now_iso8601()},
            "final": true,
        }),
    ));

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AgentIdentity, NoAuthenticator};
    use crate::protocol::a2a::{MessageKind, MessageRole};
    use crate::protocol::{CallToolResult, ToolDefinition, ToolInputSchema};

    fn test_server() -> McpServer {
        McpServer::builder()
            .name("test")
            .version("0.1.0")
            .authenticator(NoAuthenticator {
                default_identity: AgentIdentity::new("tester", "dev"),
            })
            .tool(
                ToolDefinition {
                    name: "ping".to_string(),
                    description: Some("Returns pong".to_string()),
                    input_schema: ToolInputSchema {
                        schema_type: "object".to_string(),
                        properties: None,
                        required: None,
                    },
                },
                |_args, _ctx| Box::pin(async { CallToolResult::text("pong") }),
            )
            .tool(
                ToolDefinition {
                    name: "echo".to_string(),
                    description: Some("Echoes text".to_string()),
                    input_schema: ToolInputSchema {
                        schema_type: "object".to_string(),
                        properties: None,
                        required: None,
                    },
                },
                |args, _ctx| {
                    Box::pin(async move {
                        let text = args
                            .get("text")
                            .and_then(|v| v.as_str())
                            .unwrap_or("nil");
                        CallToolResult::text(format!("echo: {text}"))
                    })
                },
            )
            .build()
    }

    fn test_agent() -> AgentIdentity {
        AgentIdentity::new("tester", "dev")
    }

    fn make_message(skill: &str) -> Message {
        Message {
            role: MessageRole::User,
            parts: vec![Part::text("test")],
            message_id: "m-1".to_string(),
            task_id: None,
            context_id: None,
            metadata: Some(HashMap::from([(
                "skill".to_string(),
                serde_json::json!(skill),
            )])),
            extensions: vec![],
            reference_task_ids: vec![],
            kind: MessageKind::Message,
        }
    }

    // --- TaskStore tests ---

    #[test]
    fn task_store_create_and_get() {
        let store = TaskStore::new();
        let task = Task {
            id: "t-1".to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state: TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            history: vec![],
            artifacts: vec![],
            metadata: None,
            kind: Default::default(),
            creator: String::new(),
        };
        store.create(task);
        assert_eq!(store.count(), 1);
        let t = store.get("t-1").unwrap();
        assert_eq!(t.status.state, TaskState::Submitted);
    }

    #[test]
    fn task_store_update_status() {
        let store = TaskStore::new();
        store.create(Task {
            id: "t-1".to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state: TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            history: vec![],
            artifacts: vec![],
            metadata: None,
            kind: Default::default(),
            creator: String::new(),
        });

        let updated = store.update_status(
            "t-1",
            TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
        );
        assert_eq!(updated.unwrap().status.state, TaskState::Working);
    }

    #[test]
    fn task_store_add_artifact() {
        let store = TaskStore::new();
        store.create(Task {
            id: "t-1".to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            history: vec![],
            artifacts: vec![],
            metadata: None,
            kind: Default::default(),
            creator: String::new(),
        });

        let updated = store.add_artifact(
            "t-1",
            Artifact {
                artifact_id: "a-1".to_string(),
                name: None,
                description: None,
                parts: vec![Part::text("result")],
                metadata: None,
            },
        );
        assert_eq!(updated.unwrap().artifacts.len(), 1);
    }

    #[test]
    fn task_store_get_missing() {
        let store = TaskStore::new();
        assert!(store.get("nope").is_none());
    }

    // --- resolve_tool tests ---

    #[test]
    fn resolve_tool_from_metadata() {
        let msg = make_message("ping");
        assert_eq!(resolve_tool(&msg), Some("ping".to_string()));
    }

    #[test]
    fn resolve_tool_from_data_part() {
        let msg = Message {
            role: MessageRole::User,
            parts: vec![Part::Data {
                data: HashMap::from([("tool".to_string(), serde_json::json!("echo"))]),
                metadata: None,
            }],
            message_id: "m-1".to_string(),
            task_id: None,
            context_id: None,
            metadata: None,
            extensions: vec![],
            reference_task_ids: vec![],
            kind: MessageKind::Message,
        };
        assert_eq!(resolve_tool(&msg), Some("echo".to_string()));
    }

    #[test]
    fn resolve_tool_none_when_absent() {
        let msg = Message {
            role: MessageRole::User,
            parts: vec![Part::text("just text")],
            message_id: "m-1".to_string(),
            task_id: None,
            context_id: None,
            metadata: None,
            extensions: vec![],
            reference_task_ids: vec![],
            kind: MessageKind::Message,
        };
        assert!(resolve_tool(&msg).is_none());
    }

    // --- extract_arguments tests ---

    #[test]
    fn extract_args_from_explicit_arguments() {
        let msg = Message {
            role: MessageRole::User,
            parts: vec![Part::Data {
                data: HashMap::from([
                    ("tool".to_string(), serde_json::json!("echo")),
                    (
                        "arguments".to_string(),
                        serde_json::json!({"text": "hello"}),
                    ),
                ]),
                metadata: None,
            }],
            message_id: "m-1".to_string(),
            task_id: None,
            context_id: None,
            metadata: None,
            extensions: vec![],
            reference_task_ids: vec![],
            kind: MessageKind::Message,
        };
        let args = extract_arguments(&msg);
        assert_eq!(args["text"], "hello");
    }

    #[test]
    fn extract_args_from_text_part() {
        let msg = Message {
            role: MessageRole::User,
            parts: vec![Part::text("hello world")],
            message_id: "m-1".to_string(),
            task_id: None,
            context_id: None,
            metadata: None,
            extensions: vec![],
            reference_task_ids: vec![],
            kind: MessageKind::Message,
        };
        let args = extract_arguments(&msg);
        assert_eq!(args["text"], "hello world");
    }

    // --- handle_message_send tests ---

    #[tokio::test]
    async fn message_send_calls_tool() {
        let server = test_server();
        let store = TaskStore::new();

        let params = MessageSendParams {
            message: make_message("ping"),
            configuration: None,
            metadata: None,
        };

        let result = handle_message_send(&server, &store, params, test_agent()).await;
        let task = result.unwrap();
        assert_eq!(task.status.state, TaskState::Completed);
        assert_eq!(task.artifacts.len(), 1);
        match &task.artifacts[0].parts[0] {
            Part::Text { text, .. } => assert_eq!(text, "pong"),
            _ => panic!("Expected text part"),
        }
    }

    #[tokio::test]
    async fn message_send_with_text_args() {
        let server = test_server();
        let store = TaskStore::new();

        let mut msg = make_message("echo");
        msg.parts = vec![Part::text("hello")];
        let params = MessageSendParams {
            message: msg,
            configuration: None,
            metadata: None,
        };

        let result = handle_message_send(&server, &store, params, test_agent()).await;
        let task = result.unwrap();
        assert_eq!(task.status.state, TaskState::Completed);
        match &task.artifacts[0].parts[0] {
            Part::Text { text, .. } => assert_eq!(text, "echo: hello"),
            _ => panic!("Expected text part"),
        }
    }

    #[tokio::test]
    async fn message_send_unknown_tool_fails() {
        let server = test_server();
        let store = TaskStore::new();

        let params = MessageSendParams {
            message: make_message("nonexistent"),
            configuration: None,
            metadata: None,
        };

        let result = handle_message_send(&server, &store, params, test_agent()).await;
        let task = result.unwrap();
        assert_eq!(task.status.state, TaskState::Failed);
    }

    #[tokio::test]
    async fn message_send_no_skill_returns_error() {
        let server = test_server();
        let store = TaskStore::new();

        let params = MessageSendParams {
            message: Message {
                role: MessageRole::User,
                parts: vec![Part::text("no skill")],
                message_id: "m-1".to_string(),
                task_id: None,
                context_id: None,
                metadata: None,
                extensions: vec![],
                reference_task_ids: vec![],
                kind: MessageKind::Message,
            },
            configuration: None,
            metadata: None,
        };

        let result = handle_message_send(&server, &store, params, test_agent()).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, UNSUPPORTED_OPERATION);
    }

    // --- handle_tasks_get tests ---

    #[test]
    fn tasks_get_returns_task() {
        let store = TaskStore::new();
        store.create(Task {
            id: "t-1".to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            history: vec![],
            artifacts: vec![],
            metadata: None,
            kind: Default::default(),
            creator: "tester".to_string(),
        });

        let result = handle_tasks_get(
            &store,
            TaskQueryParams {
                id: "t-1".to_string(),
                history_length: None,
                metadata: None,
            },
            &test_agent(),
        );
        assert_eq!(result.unwrap().status.state, TaskState::Completed);
    }

    #[test]
    fn tasks_get_not_found() {
        let store = TaskStore::new();
        let result = handle_tasks_get(
            &store,
            TaskQueryParams {
                id: "nope".to_string(),
                history_length: None,
                metadata: None,
            },
            &test_agent(),
        );
        assert_eq!(result.unwrap_err().code, TASK_NOT_FOUND);
    }

    // --- handle_tasks_cancel tests ---

    #[test]
    fn tasks_cancel_working_task() {
        let store = TaskStore::new();
        store.create(Task {
            id: "t-1".to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            history: vec![],
            artifacts: vec![],
            metadata: None,
            kind: Default::default(),
            creator: "tester".to_string(),
        });

        let result = handle_tasks_cancel(
            &store,
            TaskIdParams {
                id: "t-1".to_string(),
                metadata: None,
            },
            &test_agent(),
        );
        assert_eq!(result.unwrap().status.state, TaskState::Canceled);
    }

    #[test]
    fn tasks_cancel_terminal_fails() {
        let store = TaskStore::new();
        store.create(Task {
            id: "t-1".to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            history: vec![],
            artifacts: vec![],
            metadata: None,
            kind: Default::default(),
            creator: "tester".to_string(),
        });

        let result = handle_tasks_cancel(
            &store,
            TaskIdParams {
                id: "t-1".to_string(),
                metadata: None,
            },
            &test_agent(),
        );
        assert_eq!(result.unwrap_err().code, TASK_NOT_CANCELABLE);
    }

    #[test]
    fn tasks_cancel_not_found() {
        let store = TaskStore::new();
        let result = handle_tasks_cancel(
            &store,
            TaskIdParams {
                id: "nope".to_string(),
                metadata: None,
            },
            &test_agent(),
        );
        assert_eq!(result.unwrap_err().code, TASK_NOT_FOUND);
    }

    // --- handle_message_stream tests ---

    #[tokio::test]
    async fn message_stream_produces_events() {
        let server = test_server();
        let store = TaskStore::new();

        let params = MessageSendParams {
            message: make_message("ping"),
            configuration: None,
            metadata: None,
        };

        let events = handle_message_stream(
            &server,
            &store,
            params,
            test_agent(),
            crate::protocol::RequestId::Number(1),
        )
        .await;

        // Should produce 4 events: task, working, artifact, completed
        assert_eq!(events.len(), 4);

        // First event: task object
        let first = events[0].result.as_ref().unwrap();
        assert_eq!(first["kind"], "task");

        // Last event: final status update
        let last = events[3].result.as_ref().unwrap();
        assert_eq!(last["kind"], "status-update");
        assert!(last["final"].as_bool().unwrap());
        assert_eq!(last["status"]["state"], "completed");
    }
}
