//! ACP run execution logic.
//!
//! Provides the default `ToolDispatcher` which parses tool calls from
//! message text. The `RunDispatcher` trait allows navra-server to plug
//! in an `AgentDispatcher` that uses `run_tool_loop` for model-driven
//! execution.

use super::store::RunStore;
use super::types::*;
use crate::auth::{AgentIdentity, CallContext};
use crate::protocol::{CallToolParams, Content};
use crate::server::McpServer;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Pluggable run executor.
///
/// `ToolDispatcher` (default) parses tool calls from message text.
/// `AgentDispatcher` (navra-server) uses the ReAct tool-use loop.
pub trait RunDispatcher: Send + Sync {
    fn execute(
        &self,
        server: Arc<McpServer>,
        store: RunStore,
        run_id: String,
        input: Vec<Message>,
        agent: AgentIdentity,
    ) -> Pin<Box<dyn Future<Output = Run> + Send>>;

    fn execute_stream(
        &self,
        server: Arc<McpServer>,
        store: RunStore,
        run_id: String,
        input: Vec<Message>,
        agent: AgentIdentity,
    ) -> tokio::sync::mpsc::Receiver<Event>;
}

/// Default dispatcher that parses tool calls from message text.
pub struct ToolDispatcher;

impl RunDispatcher for ToolDispatcher {
    fn execute(
        &self,
        server: Arc<McpServer>,
        store: RunStore,
        run_id: String,
        input: Vec<Message>,
        agent: AgentIdentity,
    ) -> Pin<Box<dyn Future<Output = Run> + Send>> {
        Box::pin(async move { execute_run(&server, &store, &run_id, &input, &agent).await })
    }

    fn execute_stream(
        &self,
        server: Arc<McpServer>,
        store: RunStore,
        run_id: String,
        input: Vec<Message>,
        agent: AgentIdentity,
    ) -> tokio::sync::mpsc::Receiver<Event> {
        execute_run_stream(server, store, run_id, input, agent)
    }
}

pub fn now_iso() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let mins = (time_secs % 3600) / 60;
    let s = time_secs % 60;

    let (year, month, day) = epoch_days_to_date(days as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, mins, s
    )
}

fn epoch_days_to_date(mut days: i64) -> (i64, u32, u32) {
    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = (days - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Create a new `Run` in `created` state.
pub fn create_run(
    store: &RunStore,
    agent_name: &str,
    session_id: Option<String>,
) -> Run {
    let run = Run {
        agent_name: agent_name.to_string(),
        run_id: uuid::Uuid::new_v4().to_string(),
        status: RunStatus::Created,
        output: vec![],
        created_at: now_iso(),
        session_id,
        await_request: None,
        error: None,
        finished_at: None,
    };
    store.create(run.clone());
    store.add_event(
        &run.run_id,
        Event::RunCreated { run: run.clone() },
    );
    run
}

/// Execute a run synchronously: process all input messages, call tools,
/// return the completed `Run`.
pub async fn execute_run(
    server: &McpServer,
    store: &RunStore,
    run_id: &str,
    input: &[Message],
    agent: &AgentIdentity,
) -> Run {
    store.update_status(run_id, RunStatus::InProgress);
    if let Some(run) = store.get(run_id) {
        store.add_event(run_id, Event::RunInProgress { run });
    }

    let session_id = store
        .get(run_id)
        .and_then(|r| r.session_id.clone())
        .unwrap_or_else(|| run_id.to_string());

    let mut output_parts: Vec<MessagePart> = Vec::new();
    let mut trajectory: Vec<MessagePart> = Vec::new();

    for message in input {
        for part in &message.parts {
            let content = part.content.as_deref().unwrap_or("");
            if let Some(tool_call) = parse_tool_call(content) {
                let ctx = CallContext::new(agent.clone(), session_id.clone());
                let call_params = CallToolParams {
                    name: tool_call.tool_name.clone(),
                    arguments: tool_call.arguments.clone(),
                    meta: None,
                };

                let trajectory_input = MessagePart {
                    content_type: "text/plain".to_string(),
                    name: None,
                    content: None,
                    content_encoding: None,
                    content_url: None,
                    metadata: Some(MessageMetadata::Trajectory(TrajectoryMetadata {
                        message: None,
                        tool_name: Some(tool_call.tool_name.clone()),
                        tool_input: Some(tool_call.arguments.clone()),
                        tool_output: None,
                    })),
                };
                store.add_event(
                    run_id,
                    Event::MessagePart {
                        part: trajectory_input.clone(),
                    },
                );
                trajectory.push(trajectory_input);

                let result = server.handle_call_tool(call_params, ctx).await;

                let result_text: String = result
                    .content
                    .iter()
                    .filter_map(|c| match c {
                        Content::Text(t) => Some(t.text.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                let result_part = MessagePart::text(&result_text);
                store.add_event(
                    run_id,
                    Event::MessagePart {
                        part: result_part.clone(),
                    },
                );
                output_parts.push(result_part);

                let trajectory_output = MessagePart {
                    content_type: "text/plain".to_string(),
                    name: None,
                    content: None,
                    content_encoding: None,
                    content_url: None,
                    metadata: Some(MessageMetadata::Trajectory(TrajectoryMetadata {
                        message: None,
                        tool_name: Some(tool_call.tool_name.clone()),
                        tool_input: None,
                        tool_output: Some(serde_json::json!({
                            "is_error": result.is_error,
                            "content": result_text,
                        })),
                    })),
                };
                trajectory.push(trajectory_output);
            } else if !content.is_empty() {
                let ack_part = MessagePart::text(format!("Received: {}", content));
                output_parts.push(ack_part);
            }
        }
    }

    let mut all_parts = output_parts;
    all_parts.extend(trajectory);

    let output_message = Message {
        role: "agent".to_string(),
        parts: all_parts,
        created_at: Some(now_iso()),
        completed_at: Some(now_iso()),
    };

    store.add_event(
        run_id,
        Event::MessageCreated {
            message: output_message.clone(),
        },
    );
    store.add_output_message(run_id, output_message.clone());
    store.add_event(
        run_id,
        Event::MessageCompleted {
            message: output_message,
        },
    );

    let finished_at = now_iso();
    let run = store
        .set_finished(run_id, RunStatus::Completed, finished_at)
        .expect("run exists");

    store.add_event(run_id, Event::RunCompleted { run: run.clone() });
    run
}

/// Execute a run in the background (for async mode). Returns immediately
/// after spawning the task.
pub fn execute_run_async(
    server: Arc<McpServer>,
    store: RunStore,
    run_id: String,
    input: Vec<Message>,
    agent: AgentIdentity,
) {
    tokio::spawn(async move {
        execute_run(&server, &store, &run_id, &input, &agent).await;
    });
}

/// Execute a run and yield events as they occur (for stream mode).
pub fn execute_run_stream(
    server: Arc<McpServer>,
    store: RunStore,
    run_id: String,
    input: Vec<Message>,
    agent: AgentIdentity,
) -> tokio::sync::mpsc::Receiver<Event> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);

    tokio::spawn(async move {
        let session_id = store
            .get(&run_id)
            .and_then(|r| r.session_id.clone())
            .unwrap_or_else(|| run_id.to_string());

        store.update_status(&run_id, RunStatus::InProgress);
        if let Some(run) = store.get(&run_id) {
            let _ = tx.send(Event::RunInProgress { run }).await;
        }

        let mut output_parts: Vec<MessagePart> = Vec::new();

        for message in &input {
            for part in &message.parts {
                let content = part.content.as_deref().unwrap_or("");
                if let Some(tool_call) = parse_tool_call(content) {
                    let ctx = CallContext::new(agent.clone(), session_id.clone());
                    let call_params = CallToolParams {
                        name: tool_call.tool_name.clone(),
                        arguments: tool_call.arguments.clone(),
                        meta: None,
                    };

                    let trajectory_part = MessagePart {
                        content_type: "text/plain".to_string(),
                        name: None,
                        content: None,
                        content_encoding: None,
                        content_url: None,
                        metadata: Some(MessageMetadata::Trajectory(TrajectoryMetadata {
                            message: None,
                            tool_name: Some(tool_call.tool_name.clone()),
                            tool_input: Some(tool_call.arguments.clone()),
                            tool_output: None,
                        })),
                    };
                    let _ = tx
                        .send(Event::MessagePart {
                            part: trajectory_part,
                        })
                        .await;

                    let result = server.handle_call_tool(call_params, ctx).await;
                    let result_text: String = result
                        .content
                        .iter()
                        .filter_map(|c| match c {
                            Content::Text(t) => Some(t.text.clone()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("\n");

                    let result_part = MessagePart::text(&result_text);
                    let _ = tx
                        .send(Event::MessagePart {
                            part: result_part.clone(),
                        })
                        .await;
                    output_parts.push(result_part);
                } else if !content.is_empty() {
                    let ack = MessagePart::text(format!("Received: {}", content));
                    output_parts.push(ack);
                }
            }
        }

        let output_message = Message {
            role: "agent".to_string(),
            parts: output_parts,
            created_at: Some(now_iso()),
            completed_at: Some(now_iso()),
        };
        let _ = tx
            .send(Event::MessageCompleted {
                message: output_message.clone(),
            })
            .await;
        store.add_output_message(&run_id, output_message);

        let finished_at = now_iso();
        let run = store
            .set_finished(&run_id, RunStatus::Completed, finished_at)
            .expect("run exists");
        let _ = tx.send(Event::RunCompleted { run }).await;
    });

    rx
}

struct ToolCall {
    tool_name: String,
    arguments: serde_json::Value,
}

fn parse_tool_call(content: &str) -> Option<ToolCall> {
    let trimmed = content.trim();

    if let Some(rest) = trimmed.strip_prefix("/tool ") {
        let mut parts = rest.splitn(2, ' ');
        let name = parts.next()?.to_string();
        let args_str = parts.next().unwrap_or("{}");
        let arguments = serde_json::from_str(args_str).unwrap_or(serde_json::json!({}));
        return Some(ToolCall {
            tool_name: name,
            arguments,
        });
    }

    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(tool_name) = obj.get("tool").and_then(|v| v.as_str()) {
            let arguments = obj
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            return Some(ToolCall {
                tool_name: tool_name.to_string(),
                arguments,
            });
        }
    }

    None
}
