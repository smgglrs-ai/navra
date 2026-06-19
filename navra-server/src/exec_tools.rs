//! Command execution tools for navra.
//!
//! Provides the `exec_run` tool for running shell commands inside
//! OpenShell sandboxes. Extracted from the former `navra-tools-exec` crate.

use navra_core::auth::CallContext;
use navra_core::protocol::{CallToolResult, Content};
use navra_macros::tool;
use navra_model_runtime::openshell::{ComputeDriverClient, ExecCommandRequest};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tonic::transport::Channel;

pub struct ExecState {
    client: ComputeDriverClient<Channel>,
    pub sandboxes: Mutex<HashMap<String, String>>,
}

impl ExecState {
    pub fn new(client: ComputeDriverClient<Channel>) -> Self {
        Self {
            client,
            sandboxes: Mutex::new(HashMap::new()),
        }
    }

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

pub fn exec_run_tool(
    state: Arc<ExecState>,
) -> (
    navra_core::protocol::ToolDefinition,
    navra_core::ToolHandler,
) {
    handle_exec_run_handler(state)
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
    let working_path = Path::new(&working_dir);

    if working_path.components().any(|c| c == std::path::Component::ParentDir) {
        return CallToolResult::error(
            "working_dir must not contain '..' components (path traversal denied)",
        );
    }

    if !working_path.starts_with("/workspace") {
        return CallToolResult::error(
            "working_dir must be within /workspace (path traversal denied)",
        );
    }

    let timeout_secs = timeout_secs.unwrap_or(60).clamp(1, 300) as u32;
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
        let state = Arc::new(ExecState::new(ComputeDriverClient::new(channel)));
        let (_, handler) = handle_exec_run_handler(state);

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
    async fn rejects_workspacefoo_prefix_trick() {
        let channel = Channel::from_static("http://[::1]:50051").connect_lazy();
        let state = Arc::new(ExecState::new(ComputeDriverClient::new(channel)));
        let (_, handler) = handle_exec_run_handler(state);

        let args = serde_json::json!({
            "command": ["ls"],
            "working_dir": "/workspacefoo"
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
    async fn rejects_dotdot_traversal() {
        let channel = Channel::from_static("http://[::1]:50051").connect_lazy();
        let state = Arc::new(ExecState::new(ComputeDriverClient::new(channel)));
        let (_, handler) = handle_exec_run_handler(state);

        let args = serde_json::json!({
            "command": ["ls"],
            "working_dir": "/workspace/../etc"
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
        let state = Arc::new(ExecState::new(ComputeDriverClient::new(channel)));
        let (_, handler) = handle_exec_run_handler(state);

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
        let state = Arc::new(ExecState::new(ComputeDriverClient::new(channel)));
        let (_, handler) = handle_exec_run_handler(state);

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
        let state = Arc::new(ExecState::new(ComputeDriverClient::new(channel)));
        let (_, handler) = handle_exec_run_handler(state);

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
        let state = Arc::new(ExecState::new(ComputeDriverClient::new(channel)));

        state.register_sandbox("did:test:a".into(), "sandbox-1".into());
        {
            let map = state.sandboxes.lock().unwrap();
            assert_eq!(map.get("did:test:a").unwrap(), "sandbox-1");
        }

        state.remove_sandbox("did:test:a");
        {
            let map = state.sandboxes.lock().unwrap();
            assert!(map.get("did:test:a").is_none());
        }
    }

    #[tokio::test]
    async fn exec_run_tool_registered() {
        let channel = Channel::from_static("http://[::1]:50051").connect_lazy();
        let state = Arc::new(ExecState::new(ComputeDriverClient::new(channel)));
        let (def, _) = exec_run_tool(state);
        assert_eq!(def.name, "exec_run");
    }
}

#[cfg(kani)]
mod kani_proofs {
    use std::path::Path;

    fn is_workspace_safe(path: &str) -> bool {
        let p = Path::new(path);
        !p.components()
            .any(|c| c == std::path::Component::ParentDir)
            && p.starts_with("/workspace")
    }

    #[kani::proof]
    fn workspace_rejects_traversal_attempts() {
        let choice: u8 = kani::any();
        kani::assume(choice <= 5);
        let path = match choice {
            0 => "/tmp/escape",
            1 => "/etc/passwd",
            2 => "/workspace/../etc",
            3 => "/workspac",
            4 => "/workspacefoo",
            _ => "/home/user",
        };
        // /workspacefoo is rejected by Path::starts_with (directory semantics)
        // /workspace/../etc is rejected by the dotdot check
        assert!(!is_workspace_safe(path));
    }

    #[kani::proof]
    fn workspace_accepts_valid_paths() {
        let choice: u8 = kani::any();
        kani::assume(choice <= 2);
        let path = match choice {
            0 => "/workspace",
            1 => "/workspace/project",
            _ => "/workspace/a/b/c",
        };
        assert!(is_workspace_safe(path));
    }

    #[kani::proof]
    fn timeout_clamp_bounded() {
        let input: u64 = kani::any();
        kani::assume(input <= 1000);
        let clamped = input.clamp(1, 300) as u32;
        assert!(clamped >= 1);
        assert!(clamped <= 300);
    }
}
