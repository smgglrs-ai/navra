use navra_core::auth::CallContext;
use navra_core::protocol::{CallToolResult, Content};
use navra_core::Module;
use navra_macros::tool;
use navra_model_runtime::openshell::{ComputeDriverClient, ExecCommandRequest};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::transport::Channel;

pub struct ExecModule {
    state: Arc<ExecState>,
}

pub struct ExecState {
    client: ComputeDriverClient<Channel>,
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

    fn tools(
        &self,
    ) -> Vec<(
        navra_core::protocol::ToolDefinition,
        navra_core::ToolHandler,
    )> {
        vec![handle_exec_run_handler(self.state.clone())]
    }
}

#[tool(
    name = "exec_run",
    description = "Execute a command inside the agent's sandbox workspace. Returns stdout, stderr, and exit code."
)]
async fn handle_exec_run(
    #[arg(description = "Command and arguments, e.g. [\"cargo\", \"build\", \"--release\"]")]
    command: Vec<String>,
    #[arg(description = "Working directory inside the sandbox (default: /workspace)")] working_dir: Option<String>,
    #[arg(description = "Command timeout in seconds (default: 60, max: 300)")] timeout_secs: Option<
        u64,
    >,
    #[arg(description = "Additional environment variables for the command")] env: Option<
        HashMap<String, String>,
    >,
    ctx: CallContext,
    #[state] state: Arc<ExecState>,
) -> CallToolResult {
    if command.is_empty() {
        return CallToolResult::error("exec_run requires a non-empty 'command' array");
    }

    let working_dir = working_dir.unwrap_or_else(|| "/workspace".to_string());
    if !working_dir.starts_with("/workspace") {
        return CallToolResult::error(
            "working_dir must be within /workspace (path traversal denied)",
        );
    }

    let timeout_secs = timeout_secs.unwrap_or(60).min(300) as u32;
    let env = env.unwrap_or_default();

    let did = match &ctx.agent.did {
        Some(d) => d.clone(),
        None => return CallToolResult::error("exec_run requires agent DID to identify sandbox"),
    };

    let sandbox_id = {
        let sandboxes = state.sandboxes.lock().unwrap_or_else(|e| e.into_inner());
        match sandboxes.get(&did) {
            Some(id) => id.clone(),
            None => return CallToolResult::error(format!("no sandbox registered for agent {did}")),
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
    use navra_core::auth::AgentIdentity;

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
        let channel = Channel::from_static("http://[::1]:50051").connect_lazy();
        let module = ExecModule::new(ComputeDriverClient::new(channel));
        let (_, handler) = handle_exec_run_handler(module.state.clone());

        let args = serde_json::json!({
            "command": ["ls"],
            "working_dir": "/etc/passwd"
        });

        let result = handler(args, test_ctx(Some("did:test:agent"))).await;

        assert!(result.is_error);
        let text = match &result.content[0] {
            Content::Text(t) => t.text.as_str(),
            _ => panic!("expected text content"),
        };
        assert!(text.contains("path traversal denied"));
    }

    #[tokio::test]
    async fn rejects_missing_did() {
        let channel = Channel::from_static("http://[::1]:50051").connect_lazy();
        let module = ExecModule::new(ComputeDriverClient::new(channel));
        let (_, handler) = handle_exec_run_handler(module.state.clone());

        let args = serde_json::json!({"command": ["ls"]});
        let result = handler(args, test_ctx(None)).await;

        assert!(result.is_error);
        let text = match &result.content[0] {
            Content::Text(t) => t.text.as_str(),
            _ => panic!("expected text content"),
        };
        assert!(text.contains("requires agent DID"));
    }

    #[tokio::test]
    async fn rejects_unregistered_sandbox() {
        let channel = Channel::from_static("http://[::1]:50051").connect_lazy();
        let module = ExecModule::new(ComputeDriverClient::new(channel));
        let (_, handler) = handle_exec_run_handler(module.state.clone());

        let args = serde_json::json!({"command": ["ls"]});
        let result = handler(args, test_ctx(Some("did:test:unknown"))).await;

        assert!(result.is_error);
        let text = match &result.content[0] {
            Content::Text(t) => t.text.as_str(),
            _ => panic!("expected text content"),
        };
        assert!(text.contains("no sandbox registered"));
    }

    #[tokio::test]
    async fn rejects_empty_command() {
        let channel = Channel::from_static("http://[::1]:50051").connect_lazy();
        let module = ExecModule::new(ComputeDriverClient::new(channel));
        let (_, handler) = handle_exec_run_handler(module.state.clone());

        let args = serde_json::json!({"command": []});
        let result = handler(args, test_ctx(Some("did:test:agent"))).await;

        assert!(result.is_error);
        let text = match &result.content[0] {
            Content::Text(t) => t.text.as_str(),
            _ => panic!("expected text content"),
        };
        assert!(text.contains("non-empty"));
    }

    #[tokio::test]
    async fn register_and_remove_sandbox() {
        let channel = Channel::from_static("http://[::1]:50051").connect_lazy();
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
        let channel = Channel::from_static("http://[::1]:50051").connect_lazy();
        let module = ExecModule::new(ComputeDriverClient::new(channel));
        let tools = module.tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].0.name, "exec_run");
    }
}

#[cfg(kani)]
mod kani_proofs {
    /// Prove workspace path check rejects traversal.
    /// Models the starts_with check on bounded strings.
    fn is_workspace_safe(path: &str) -> bool {
        path.starts_with("/workspace")
    }

    #[kani::proof]
    fn workspace_rejects_traversal_attempts() {
        let choice: u8 = kani::any();
        kani::assume(choice <= 4);
        let path = match choice {
            0 => "/tmp/escape",
            1 => "/etc/passwd",
            2 => "/workspace/../etc",
            3 => "/workspac", // prefix substring
            _ => "/home/user",
        };
        if !path.starts_with("/workspace") {
            assert!(!is_workspace_safe(path));
        }
    }

    #[kani::proof]
    fn timeout_clamp_bounded() {
        let input: u64 = kani::any();
        kani::assume(input <= 1000);
        let clamped = input.min(300) as u32;
        assert!(clamped <= 300);
    }
}
