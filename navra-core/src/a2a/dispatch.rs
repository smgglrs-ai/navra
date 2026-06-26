use crate::auth::CallContext;
use crate::protocol::a2a::{
    self, Artifact, Message, MessageSendParams, Part, Task, TaskIdParams, TaskQueryParams,
    TaskState, TaskStatus, TASK_NOT_CANCELABLE, TASK_NOT_FOUND, UNSUPPORTED_OPERATION,
};
use crate::protocol::{CallToolParams, JsonRpcError};
use crate::server::McpServer;

use super::TaskStore;

/// Resolve which tool to call from the incoming A2A message.
///
/// Strategy:
/// 1. `message.metadata["skill"]` — explicit tool name
/// 2. First `DataPart` containing a `"tool"` key — tool name from data
/// 3. None — caller must handle the error
pub(super) fn resolve_tool(message: &Message) -> Option<String> {
    // 1. Explicit skill in metadata
    if let Some(meta) = &message.metadata
        && let Some(skill) = meta.get("skill").and_then(|v| v.as_str()) {
            return Some(skill.to_string());
        }

    // 2. DataPart with a "tool" field
    for part in &message.parts {
        if let Part::Data { data, .. } = part
            && let Some(tool) = data.get("tool").and_then(|v| v.as_str()) {
                return Some(tool.to_string());
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
pub(super) fn extract_arguments(message: &Message) -> serde_json::Value {
    // Look for explicit arguments in DataParts
    for part in &message.parts {
        if let Part::Data { data, .. } = part
            && let Some(args) = data.get("arguments") {
                return args.clone();
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
        .map(|c| match c.raw.as_text() {
            Some(tc) => Part::text(&tc.text),
            None => Part::text("[unsupported content type]"),
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
    let call_params = {
        let mut p = CallToolParams::new(tool_name.clone());
        if let Some(obj) = arguments.as_object() {
            p = p.with_arguments(obj.clone());
        }
        p
    };
    let tool_result = server.handle_call_tool(call_params, ctx).await;

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
    let final_state = if tool_result.is_error == Some(true) {
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

    task_store
        .get(&task_id)
        .ok_or_else(|| JsonRpcError::internal("Task disappeared after creation"))
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
    let call_params = {
        let mut p = CallToolParams::new(tool_name.clone());
        if let Some(obj) = arguments.as_object() {
            p = p.with_arguments(obj.clone());
        }
        p
    };
    let tool_result = server.handle_call_tool(call_params, ctx).await;

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
    let is_err = tool_result.is_error == Some(true);
    let final_state = if is_err { "failed" } else { "completed" };
    let final_task_state = if is_err {
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
