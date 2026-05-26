use super::dispatch::{extract_arguments, resolve_tool};
use super::*;
use crate::auth::{AgentIdentity, NoAuthenticator};
use crate::protocol::a2a::{
    Artifact, Message, MessageKind, MessageRole, MessageSendParams, Part, Task, TaskIdParams,
    TaskQueryParams, TaskState, TaskStatus, TASK_NOT_CANCELABLE, TASK_NOT_FOUND,
    UNSUPPORTED_OPERATION,
};
use crate::protocol::{CallToolResult, ToolDefinition, ToolInputSchema};
use crate::server::McpServer;
use std::collections::HashMap;

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
                annotations: None,
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
                annotations: None,
            },
            |args, _ctx| {
                Box::pin(async move {
                    let text = args.get("text").and_then(|v| v.as_str()).unwrap_or("nil");
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
