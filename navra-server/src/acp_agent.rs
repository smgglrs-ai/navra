//! Agent-driven ACP run dispatcher.
//!
//! Uses navra-agent's ReAct tool-use loop so the model decides which
//! tools to call. Falls back to the default ToolDispatcher if no model
//! is configured.

use crate::direct_transport::DirectTransport;
use navra_agent::{McpClient, ToolLoopConfig};
use navra_core::acp::dispatch::RunDispatcher;
use navra_core::acp::store::RunStore;
use navra_core::acp::types::*;
use navra_core::auth::AgentIdentity;
use navra_core::McpServer;
use navra_core::Upstream;
use navra_model::ModelBackend;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub struct AgentDispatcher {
    model: Arc<dyn ModelBackend>,
}

impl AgentDispatcher {
    pub fn new(model: Arc<dyn ModelBackend>) -> Self {
        Self { model }
    }
}

impl RunDispatcher for AgentDispatcher {
    fn execute(
        &self,
        server: Arc<McpServer>,
        store: RunStore,
        run_id: String,
        input: Vec<Message>,
        agent: AgentIdentity,
    ) -> Pin<Box<dyn Future<Output = Run> + Send>> {
        let model = self.model.clone();
        Box::pin(async move {
            execute_agent_run(server, model, store, run_id, input, agent).await
        })
    }

    fn execute_stream(
        &self,
        server: Arc<McpServer>,
        store: RunStore,
        run_id: String,
        input: Vec<Message>,
        agent: AgentIdentity,
    ) -> tokio::sync::mpsc::Receiver<Event> {
        let model = self.model.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(64);

        tokio::spawn(async move {
            let run =
                execute_agent_run(server, model, store.clone(), run_id.clone(), input, agent).await;
            let final_event = match run.status {
                RunStatus::Completed => Event::RunCompleted { run },
                RunStatus::Failed => Event::RunFailed { run },
                _ => Event::RunCompleted { run },
            };
            let _ = tx.send(final_event).await;
        });

        rx
    }
}

fn extract_prompt(input: &[Message]) -> String {
    input
        .iter()
        .flat_map(|m| &m.parts)
        .filter_map(|p| p.content.as_deref())
        .collect::<Vec<_>>()
        .join("\n")
}

async fn execute_agent_run(
    server: Arc<McpServer>,
    model: Arc<dyn ModelBackend>,
    store: RunStore,
    run_id: String,
    input: Vec<Message>,
    agent: AgentIdentity,
) -> Run {
    use navra_core::acp::dispatch::now_iso;

    store.update_status(&run_id, RunStatus::InProgress);
    if let Some(run) = store.get(&run_id) {
        store.add_event(&run_id, Event::RunInProgress { run });
    }

    let prompt = extract_prompt(&input);

    let transport = DirectTransport::new(server, agent.clone());
    let upstream = match Upstream::connect(&agent.name, transport).await {
        Ok(u) => u,
        Err(e) => {
            let error = AcpError::server_error(format!("Failed to connect: {e}"));
            let run = store
                .set_error(&run_id, error, now_iso())
                .expect("run exists");
            store.add_event(&run_id, Event::RunFailed { run: run.clone() });
            return run;
        }
    };
    let mut client = McpClient::new(upstream);

    let mut config = ToolLoopConfig {
        max_iterations: 10,
        temperature: Some(0.7),
        ..Default::default()
    };

    let loop_run_id = uuid::Uuid::new_v4().to_string();
    let result =
        navra_agent::run_tool_loop(model.as_ref(), &mut client, &prompt, &mut config, loop_run_id)
            .await;

    match result {
        Ok(tool_result) => {
            let mut parts = vec![MessagePart::text(&tool_result.response)];

            for action in &tool_result.actions {
                parts.push(MessagePart {
                    content_type: "text/plain".to_string(),
                    name: None,
                    content: None,
                    content_encoding: None,
                    content_url: None,
                    metadata: Some(MessageMetadata::Trajectory(TrajectoryMetadata {
                        message: Some(action.output_preview.clone()),
                        tool_name: Some(format!("{:?}", action.action)),
                        tool_input: None,
                        tool_output: None,
                    })),
                });
            }

            let output_message = Message {
                role: "agent".to_string(),
                parts,
                created_at: Some(now_iso()),
                completed_at: Some(now_iso()),
            };

            store.add_event(
                &run_id,
                Event::MessageCompleted {
                    message: output_message.clone(),
                },
            );
            store.add_output_message(&run_id, output_message);

            let run = store
                .set_finished(&run_id, RunStatus::Completed, now_iso())
                .expect("run exists");
            store.add_event(&run_id, Event::RunCompleted { run: run.clone() });
            run
        }
        Err(e) => {
            let error = AcpError::server_error(format!("Agent error: {e}"));
            let run = store
                .set_error(&run_id, error, now_iso())
                .expect("run exists");
            store.add_event(&run_id, Event::RunFailed { run: run.clone() });
            run
        }
    }
}
