use smgglrs_core::auth::CallContext;
use smgglrs_core::protocol::{CallToolResult, Content, ToolDefinition, ToolInputSchema};
use smgglrs_core::Module;
use smgglrs_core::ToolHandler;
use smgglrs_model_runtime::openshell::{ComputeDriverClient, ExecCommandRequest};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tonic::transport::Channel;

/// Exec module — run commands inside OpenShell agent sandboxes.
///
/// Agents call `exec_run` as a normal MCP tool. The gateway looks up
/// the agent's sandbox via its DID and forwards the command to OpenShell.
pub struct ExecModule {
    state: Arc<ExecState>,
}

pub struct ExecState {
    client: ComputeDriverClient<Channel>,
    /// DID -> sandbox_id, populated by spawn_openshell_agent().
    pub sandboxes: Mutex<HashMap<String, String>>,
}

impl ExecModule {
    pub fn new(client: ComputeDriverClient<Channel>) -> Self {
        Self {
            state: Arc::new(ExecState {
                client,
                sandboxes: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn state(&self) -> &Arc<ExecState> {
        &self.state
    }
}

impl ExecState {
    pub fn register_sandbox(&self, did: String, sandbox_id: String) {
        self.sandboxes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(did, sandbox_id);
    }

    pub fn remove_sandbox(&self, did: &str) {
        self.sandboxes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(did);
    }
}

impl Module for ExecModule {
    fn name(&self) -> &str {
        "exec"
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        let s = self.state.clone();
        vec![make_tool(exec_run_def(), s, handle_exec_run)]
    }
}

fn make_tool<F>(
    def: ToolDefinition,
    state: Arc<ExecState>,
    handler: fn(serde_json::Value, CallContext, Arc<ExecState>) -> F,
) -> (ToolDefinition, ToolHandler)
where
    F: Future<Output = CallToolResult> + Send + 'static,
{
    let h: ToolHandler = Arc::new(move |args, ctx| {
        let s = state.clone();
        Box::pin(handler(args, ctx, s))
    });
    (def, h)
}

fn exec_run_def() -> ToolDefinition {
    ToolDefinition {
        name: "exec_run".to_string(),
        description: Some(
            "Execute a command inside the agent's sandbox workspace. \
             Returns stdout, stderr, and exit code."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "command".to_string(),
                    serde_json::json!({
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Command and arguments, e.g. [\"cargo\", \"build\", \"--release\"]"
                    }),
                ),
                (
                    "working_dir".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Working directory inside the sandbox (default: /workspace)"
                    }),
                ),
                (
                    "timeout_secs".to_string(),
                    serde_json::json!({
                        "type": "integer",
                        "description": "Command timeout in seconds (default: 60, max: 300)"
                    }),
                ),
                (
                    "env".to_string(),
                    serde_json::json!({
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "Additional environment variables for the command"
                    }),
                ),
            ])),
            required: Some(vec!["command".to_string()]),
        },
        annotations: None,
    }
}

async fn handle_exec_run(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<ExecState>,
) -> CallToolResult {
    let command: Vec<String> = match args.get("command").and_then(|v| {
        serde_json::from_value::<Vec<String>>(v.clone()).ok()
    }) {
        Some(c) if !c.is_empty() => c,
        _ => return CallToolResult::error("exec_run requires a non-empty 'command' array"),
    };

    let working_dir = args
        .get("working_dir")
        .and_then(|v| v.as_str())
        .unwrap_or("/workspace")
        .to_string();

    if !working_dir.starts_with("/workspace") {
        return CallToolResult::error(
            "working_dir must be within /workspace (path traversal denied)",
        );
    }

    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(60)
        .min(300) as u32;

    let env: HashMap<String, String> = args
        .get("env")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let did = match &ctx.agent.did {
        Some(d) => d.clone(),
        None => {
            return CallToolResult::error(
                "exec_run requires agent DID to identify sandbox",
            )
        }
    };

    let sandbox_id = {
        let sandboxes = state.sandboxes.lock().unwrap_or_else(|e| e.into_inner());
        match sandboxes.get(&did) {
            Some(id) => id.clone(),
            None => {
                return CallToolResult::error(format!(
                    "no sandbox registered for agent {did}"
                ))
            }
        }
    };

    tracing::info!(
        sandbox = %sandbox_id,
        agent = %did,
        cmd = ?command,
        "exec_run"
    );

    let resp = state
        .client
        .clone()
        .exec_command(ExecCommandRequest {
            sandbox_id,
            command: command.clone(),
            working_dir,
            env,
            timeout_secs,
        })
        .await;

    match resp {
        Ok(resp) => {
            let r = resp.into_inner();
            let mut output = String::new();
            if !r.stdout.is_empty() {
                output.push_str(&r.stdout);
            }
            if !r.stderr.is_empty() {
                if !output.is_empty() {
                    output.push_str("\n--- stderr ---\n");
                }
                output.push_str(&r.stderr);
            }
            if output.is_empty() {
                output.push_str("(no output)");
            }
            output.push_str(&format!("\n\nexit code: {}", r.exit_code));

            CallToolResult {
                content: vec![Content::text(output)],
                is_error: r.exit_code != 0,
                label: Default::default(),
            }
        }
        Err(e) => CallToolResult::error(format!("exec_run failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smgglrs_core::auth::AgentIdentity;

    fn test_ctx(did: Option<&str>) -> CallContext {
        CallContext::new(
            AgentIdentity {
                name: "test-agent".to_string(),
                permissions: "restricted".to_string(),
                signing_key: None,
                did: did.map(String::from),
                capabilities: None,
            },
            "test-session",
        )
    }

    #[tokio::test]
    async fn rejects_path_outside_workspace() {
        let channel = Channel::from_static("http://[::1]:50051")
            .connect_lazy();
        let module = ExecModule::new(ComputeDriverClient::new(channel));

        let args = serde_json::json!({
            "command": ["ls"],
            "working_dir": "/etc/passwd"
        });

        let result = handle_exec_run(
            args,
            test_ctx(Some("did:test:agent")),
            module.state.clone(),
        )
        .await;

        assert!(result.is_error);
        let text = match &result.content[0] {
            Content::Text(t) => t.text.as_str(),
            _ => panic!("expected text content"),
        };
        assert!(text.contains("path traversal denied"));
    }

    #[tokio::test]
    async fn rejects_missing_did() {
        let channel = Channel::from_static("http://[::1]:50051")
            .connect_lazy();
        let module = ExecModule::new(ComputeDriverClient::new(channel));

        let args = serde_json::json!({"command": ["ls"]});
        let result = handle_exec_run(
            args,
            test_ctx(None),
            module.state.clone(),
        )
        .await;

        assert!(result.is_error);
        let text = match &result.content[0] {
            Content::Text(t) => t.text.as_str(),
            _ => panic!("expected text content"),
        };
        assert!(text.contains("requires agent DID"));
    }

    #[tokio::test]
    async fn rejects_unregistered_sandbox() {
        let channel = Channel::from_static("http://[::1]:50051")
            .connect_lazy();
        let module = ExecModule::new(ComputeDriverClient::new(channel));

        let args = serde_json::json!({"command": ["ls"]});
        let result = handle_exec_run(
            args,
            test_ctx(Some("did:test:unknown")),
            module.state.clone(),
        )
        .await;

        assert!(result.is_error);
        let text = match &result.content[0] {
            Content::Text(t) => t.text.as_str(),
            _ => panic!("expected text content"),
        };
        assert!(text.contains("no sandbox registered"));
    }

    #[tokio::test]
    async fn rejects_empty_command() {
        let channel = Channel::from_static("http://[::1]:50051")
            .connect_lazy();
        let module = ExecModule::new(ComputeDriverClient::new(channel));

        let args = serde_json::json!({"command": []});
        let result = handle_exec_run(
            args,
            test_ctx(Some("did:test:agent")),
            module.state.clone(),
        )
        .await;

        assert!(result.is_error);
        let text = match &result.content[0] {
            Content::Text(t) => t.text.as_str(),
            _ => panic!("expected text content"),
        };
        assert!(text.contains("non-empty"));
    }

    #[tokio::test]
    async fn register_and_remove_sandbox() {
        let channel = Channel::from_static("http://[::1]:50051")
            .connect_lazy();
        let module = ExecModule::new(ComputeDriverClient::new(channel));

        module
            .state()
            .register_sandbox("did:test:a".into(), "sandbox-1".into());
        {
            let map = module.state().sandboxes.lock().unwrap();
            assert_eq!(map.get("did:test:a").unwrap(), "sandbox-1");
        }

        module.state().remove_sandbox("did:test:a");
        {
            let map = module.state().sandboxes.lock().unwrap();
            assert!(map.get("did:test:a").is_none());
        }
    }

    #[tokio::test]
    async fn exec_run_tool_registered() {
        let channel = Channel::from_static("http://[::1]:50051")
            .connect_lazy();
        let module = ExecModule::new(ComputeDriverClient::new(channel));
        let tools = module.tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].0.name, "exec_run");
    }
}
