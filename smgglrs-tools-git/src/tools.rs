use smgglrs_core::auth::CallContext;
use smgglrs_core::notify::Notifier;
use smgglrs_core::permissions::{ApprovalStore, PermissionEngine, PermissionResult};
use smgglrs_core::protocol::{CallToolResult, Content, ToolDefinition, ToolInputSchema};
use smgglrs_core::Module;
use smgglrs_core::ToolHandler;
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Git module for smgglrs.
///
/// Provides tools for interacting with git repositories:
/// - `git_status` — show working tree status
/// - `git_diff` — show changes (staged, unstaged, or between refs)
/// - `git_log` — show commit history
/// - `git_branch` — list or show current branch
/// - `git_commit` — create a commit (requires approval)
pub struct GitModule {
    state: Arc<GitState>,
}

struct GitState {
    perm_engine: Arc<PermissionEngine>,
    approvals: Arc<ApprovalStore>,
    notifier: Arc<dyn Notifier>,
}

impl GitModule {
    pub fn new(
        perm_engine: Arc<PermissionEngine>,
        approvals: Arc<ApprovalStore>,
        notifier: Arc<dyn Notifier>,
    ) -> Self {
        Self {
            state: Arc::new(GitState {
                perm_engine,
                approvals,
                notifier,
            }),
        }
    }
}

impl Module for GitModule {
    fn name(&self) -> &str {
        "git"
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        let s = self.state.clone();
        vec![
            make_tool(status_tool_def(), s.clone(), handle_status),
            make_tool(diff_tool_def(), s.clone(), handle_diff),
            make_tool(log_tool_def(), s.clone(), handle_log),
            make_tool(branch_tool_def(), s.clone(), handle_branch),
            make_tool(commit_tool_def(), s.clone(), handle_commit),
        ]
    }
}

/// Helper to create a (ToolDefinition, ToolHandler) pair from an async handler.
fn make_tool<F>(
    def: ToolDefinition,
    state: Arc<GitState>,
    handler: fn(serde_json::Value, CallContext, Arc<GitState>) -> F,
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

// --- Tool definitions ---

fn status_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "git_status".to_string(),
        description: Some("Show the working tree status of a git repository.".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!({"type": "string", "description": "Path to the git repository (directory)"}),
            )])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn diff_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "git_diff".to_string(),
        description: Some(
            "Show changes in a git repository. By default shows unstaged changes. \
             Use 'staged: true' for staged changes, or provide 'ref' for a specific comparison."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Path to the git repository"}),
                ),
                (
                    "staged".to_string(),
                    serde_json::json!({"type": "boolean", "description": "Show staged changes (default: false)"}),
                ),
                (
                    "ref".to_string(),
                    serde_json::json!({"type": "string", "description": "Compare against a ref (e.g., HEAD~3, main)"}),
                ),
            ])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn log_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "git_log".to_string(),
        description: Some("Show commit history of a git repository.".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Path to the git repository"}),
                ),
                (
                    "limit".to_string(),
                    serde_json::json!({"type": "integer", "description": "Number of commits to show (default: 10)"}),
                ),
                (
                    "oneline".to_string(),
                    serde_json::json!({"type": "boolean", "description": "Use one-line format (default: false)"}),
                ),
            ])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn branch_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "git_branch".to_string(),
        description: Some("List branches or show the current branch.".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Path to the git repository"}),
                ),
                (
                    "all".to_string(),
                    serde_json::json!({"type": "boolean", "description": "Show remote branches too (default: false)"}),
                ),
            ])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn commit_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "git_commit".to_string(),
        description: Some(
            "Create a git commit with the staged changes. Requires approval.".to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Path to the git repository"}),
                ),
                (
                    "message".to_string(),
                    serde_json::json!({"type": "string", "description": "Commit message"}),
                ),
            ])),
            required: Some(vec!["path".to_string(), "message".to_string()]),
        },
    }
}

// --- Path validation ---

fn resolve_repo_path(raw: &str) -> Result<PathBuf, String> {
    // Reject paths containing ".." components before any filesystem access
    // to prevent path traversal attacks (CWE-22).
    if raw.split('/').any(|c| c == "..") {
        return Err(format!("Path must not contain '..': {raw}"));
    }

    let expanded: PathBuf = if raw.starts_with("~/") {
        match dirs::home_dir() {
            Some(home) => home.join(&raw[2..]),
            None => return Err("Cannot resolve home directory".to_string()),
        }
    } else {
        PathBuf::from(raw)
    };

    if !expanded.is_absolute() {
        return Err(format!("Path must be absolute: {raw}"));
    }

    // Reject symlinks pointing outside the expanded path's parent.
    // Check before canonicalize to detect symlink escapes.
    if expanded.is_symlink() {
        let target = std::fs::read_link(&expanded)
            .map_err(|e| format!("Cannot read symlink {raw}: {e}"))?;
        let resolved = if target.is_absolute() {
            target
        } else {
            expanded.parent().unwrap_or(Path::new("/")).join(&target)
        };
        let resolved = resolved
            .canonicalize()
            .map_err(|e| format!("Symlink target not accessible: {e}"))?;
        // If the original path had a parent, ensure the symlink stays within it
        if let Some(parent) = expanded.parent() {
            if let Ok(canon_parent) = parent.canonicalize() {
                if !resolved.starts_with(&canon_parent) {
                    return Err(format!(
                        "Symlink escapes allowed directory: {} -> {}",
                        expanded.display(),
                        resolved.display()
                    ));
                }
            }
        }
    }

    let canonical = expanded
        .canonicalize()
        .map_err(|e| format!("Cannot resolve path {raw}: {e}"))?;

    // Verify it's a git repo
    if !canonical.join(".git").exists() {
        return Err(format!("Not a git repository: {}", canonical.display()));
    }

    Ok(canonical)
}

// --- Permission check ---

async fn check_perm(
    state: &GitState,
    ctx: &CallContext,
    op: &str,
    path: &Path,
) -> Result<(), CallToolResult> {
    match state.perm_engine.check_with_capabilities(
        &ctx.agent.permissions, op, path, ctx.agent.capabilities.as_ref(),
    ) {
        PermissionResult::Allowed => Ok(()),
        PermissionResult::NeedsApproval => {
            let path_str = path.display().to_string();

            // Check for a cached grant
            if state
                .approvals
                .check_grant(&ctx.agent.name, op, &path_str)
            {
                tracing::info!(
                    agent = %ctx.agent.name, op, path = %path_str,
                    "Using cached approval grant"
                );
                return Ok(());
            }

            // Create approval request
            let (req, _rx) = state.approvals.request(&ctx.agent.name, op, &path_str);

            if let Err(e) = state
                .notifier
                .notify(&req, state.approvals.clone())
                .await
            {
                tracing::warn!("Failed to send D-Bus notification: {e}");
            }

            Err(CallToolResult::success(vec![Content::text(format!(
                "Approval required: {} on {}\n\n\
                 Request ID: {}\n\
                 Agent: {}\n\n\
                 Approve or deny this request via the system tray or CLI.",
                op, path_str, req.id, ctx.agent.name,
            ))]))
        }
        PermissionResult::DeniedPath => Err(CallToolResult::error(format!(
            "Access denied: {}",
            path.display()
        ))),
        PermissionResult::DeniedOperation => Err(CallToolResult::error(format!(
            "Operation '{}' not permitted for agent '{}'",
            op, ctx.agent.name
        ))),
        PermissionResult::DeniedUnknown => Err(CallToolResult::error(format!(
            "Unknown permission set: {}",
            ctx.agent.permissions
        ))),
    }
}

// --- Git command runner ---

async fn run_git(
    repo_path: &Path,
    args: &[&str],
) -> Result<String, String> {
    let output = tokio::process::Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()
        .await
        .map_err(|e| format!("Failed to run git: {e}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("git error: {stderr}"))
    }
}

// --- Tool handlers ---

async fn handle_status(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<GitState>,
) -> CallToolResult {
    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let repo_path = match resolve_repo_path(path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(result) = check_perm(&state, &ctx, "git.status", &repo_path).await {
        return result;
    }

    match run_git(&repo_path, &["status", "--short", "--branch"]).await {
        Ok(output) => {
            if output.trim().is_empty() {
                CallToolResult::text("Working tree clean".to_string())
            } else {
                CallToolResult::text(output)
            }
        }
        Err(e) => CallToolResult::error(e),
    }
}

async fn handle_diff(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<GitState>,
) -> CallToolResult {
    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let repo_path = match resolve_repo_path(path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(result) = check_perm(&state, &ctx, "git.diff", &repo_path).await {
        return result;
    }

    let staged = args
        .get("staged")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ref_name = args.get("ref").and_then(|v| v.as_str());

    let mut git_args = vec!["diff"];
    if staged {
        git_args.push("--cached");
    }
    if let Some(r) = ref_name {
        if r.starts_with('-') {
            return CallToolResult::error("Invalid ref: must not start with '-'");
        }
        git_args.push(r);
    }

    match run_git(&repo_path, &git_args).await {
        Ok(output) => {
            if output.trim().is_empty() {
                CallToolResult::text("No changes".to_string())
            } else {
                CallToolResult::text(output)
            }
        }
        Err(e) => CallToolResult::error(e),
    }
}

async fn handle_log(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<GitState>,
) -> CallToolResult {
    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let repo_path = match resolve_repo_path(path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(result) = check_perm(&state, &ctx, "git.log", &repo_path).await {
        return result;
    }

    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10);
    let oneline = args
        .get("oneline")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let limit_str = format!("-{limit}");
    let mut git_args = vec!["log", &limit_str];
    if oneline {
        git_args.push("--oneline");
    }

    match run_git(&repo_path, &git_args).await {
        Ok(output) => CallToolResult::text(output),
        Err(e) => CallToolResult::error(e),
    }
}

async fn handle_branch(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<GitState>,
) -> CallToolResult {
    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let repo_path = match resolve_repo_path(path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(result) = check_perm(&state, &ctx, "git.branch", &repo_path).await {
        return result;
    }

    let show_all = args
        .get("all")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut git_args = vec!["branch"];
    if show_all {
        git_args.push("-a");
    }

    match run_git(&repo_path, &git_args).await {
        Ok(output) => CallToolResult::text(output),
        Err(e) => CallToolResult::error(e),
    }
}

async fn handle_commit(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<GitState>,
) -> CallToolResult {
    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };
    let message = match args.get("message").and_then(|v| v.as_str()) {
        Some(m) if !m.is_empty() => m,
        _ => return CallToolResult::error("Missing required parameter: message"),
    };

    let repo_path = match resolve_repo_path(path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    // Commit requires approval
    if let Err(result) = check_perm(&state, &ctx, "git.commit", &repo_path).await {
        return result;
    }

    // Append Signed-off-by trailer
    let full_message = format!(
        "{}\n\nSigned-off-by: {} (via smgglrs)",
        message, ctx.agent.name,
    );

    // Sign commits when the agent has a signing key configured
    if let Some(ref key_path) = ctx.agent.signing_key {
        let key = match std::path::Path::new(key_path).canonicalize() {
            Ok(p) => p,
            Err(e) => {
                return CallToolResult::error(format!(
                    "Signing key not found or inaccessible: {key_path}: {e}"
                ));
            }
        };
        let canonical_key = key.to_string_lossy();
        let signing_key_arg = format!("user.signingkey={canonical_key}");
        match run_git(
            &repo_path,
            &[
                "-c", "gpg.format=ssh",
                "-c", &signing_key_arg,
                "commit", "-S", "-m", &full_message,
            ],
        )
        .await
        {
            Ok(output) => CallToolResult::text(output),
            Err(e) => CallToolResult::error(e),
        }
    } else {
        match run_git(&repo_path, &["commit", "-m", &full_message]).await {
            Ok(output) => CallToolResult::text(output),
            Err(e) => CallToolResult::error(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smgglrs_core::auth::AgentIdentity;
    use smgglrs_core::permissions::PathAcl;
    use std::collections::HashSet;

    fn test_perm_engine(repo_path: &str) -> PermissionEngine {
        let mut engine = PermissionEngine::new();
        engine.add_permission_set(
            "developer".to_string(),
            PathAcl {
                ring: None,
                allow: vec![format!("{repo_path}/**")],
                deny: vec![],
                operations: [
                    "git.status",
                    "git.diff",
                    "git.log",
                    "git.branch",
                    "git.commit",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
                requires_approval: ["git.commit"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
        );
        engine.add_permission_set(
            "readonly".to_string(),
            PathAcl {
                ring: None,
                allow: vec![format!("{repo_path}/**")],
                deny: vec![],
                operations: ["git.status", "git.diff", "git.log", "git.branch"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                requires_approval: HashSet::new(),
            },
        );
        engine
    }

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "developer"), "test-session")
    }

    fn readonly_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("reader", "readonly"), "test-session")
    }

    /// Create a temporary git repo for testing.
    fn init_test_repo(dir: &Path) {
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .expect("git init failed");

        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir)
            .output()
            .expect("git config email failed");

        std::process::Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(dir)
            .output()
            .expect("git config name failed");

        // Create initial commit
        std::fs::write(dir.join("README.md"), "# Test Repo\n").unwrap();
        std::process::Command::new("git")
            .args(["add", "README.md"])
            .current_dir(dir)
            .output()
            .expect("git add failed");
        std::process::Command::new("git")
            .args(["commit", "-m", "Initial commit"])
            .current_dir(dir)
            .output()
            .expect("git commit failed");
    }

    fn test_state(repo_path: &str) -> Arc<GitState> {
        Arc::new(GitState {
            perm_engine: Arc::new(test_perm_engine(repo_path)),
            approvals: Arc::new(ApprovalStore::new(300)),
            notifier: Arc::new(smgglrs_core::notify::NoopNotifier),
        })
    }

    #[test]
    fn module_provides_all_tools() {
        let module = GitModule::new(
            Arc::new(PermissionEngine::new()),
            Arc::new(ApprovalStore::new(300)),
            Arc::new(smgglrs_core::notify::NoopNotifier),
        );
        assert_eq!(module.name(), "git");
        let tools = module.tools();
        assert_eq!(tools.len(), 5);
        let names: Vec<_> = tools.iter().map(|(d, _)| d.name.as_str()).collect();
        assert!(names.contains(&"git_status"));
        assert!(names.contains(&"git_diff"));
        assert!(names.contains(&"git_log"));
        assert!(names.contains(&"git_branch"));
        assert!(names.contains(&"git_commit"));
    }

    #[test]
    fn resolve_repo_path_rejects_relative() {
        assert!(resolve_repo_path("relative/path").is_err());
    }

    #[test]
    fn resolve_repo_path_rejects_nonexistent() {
        assert!(resolve_repo_path("/nonexistent/path").is_err());
    }

    #[tokio::test]
    async fn status_shows_clean_repo() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();
        let state = test_state(repo_str);

        let result = handle_status(
            serde_json::json!({"path": repo_str}),
            test_ctx(),
            state,
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                // Branch line should be present
                assert!(t.text.contains("##") || t.text.contains("clean"));
            }
        }
    }

    #[tokio::test]
    async fn status_shows_modified_file() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        // Modify a file
        std::fs::write(tmp.path().join("README.md"), "# Modified\n").unwrap();

        let state = test_state(repo_str);
        let result = handle_status(
            serde_json::json!({"path": repo_str}),
            test_ctx(),
            state,
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("README.md"));
            }
        }
    }

    #[tokio::test]
    async fn diff_shows_changes() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        std::fs::write(tmp.path().join("README.md"), "# Changed content\n").unwrap();

        let state = test_state(repo_str);
        let result = handle_diff(
            serde_json::json!({"path": repo_str}),
            test_ctx(),
            state,
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Changed content") || t.text.contains("README.md"));
            }
        }
    }

    #[tokio::test]
    async fn diff_no_changes() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        let state = test_state(repo_str);
        let result = handle_diff(
            serde_json::json!({"path": repo_str}),
            test_ctx(),
            state,
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert_eq!(t.text, "No changes");
            }
        }
    }

    #[tokio::test]
    async fn log_shows_history() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        let state = test_state(repo_str);
        let result = handle_log(
            serde_json::json!({"path": repo_str, "limit": 5}),
            test_ctx(),
            state,
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Initial commit"));
            }
        }
    }

    #[tokio::test]
    async fn log_oneline() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        let state = test_state(repo_str);
        let result = handle_log(
            serde_json::json!({"path": repo_str, "oneline": true}),
            test_ctx(),
            state,
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                // Oneline format: hash + message on one line
                let lines: Vec<_> = t.text.lines().collect();
                assert!(!lines.is_empty());
                assert!(lines[0].contains("Initial commit"));
            }
        }
    }

    #[tokio::test]
    async fn branch_shows_current() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        let state = test_state(repo_str);
        let result = handle_branch(
            serde_json::json!({"path": repo_str}),
            test_ctx(),
            state,
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                // Current branch should be marked with *
                assert!(t.text.contains("*"));
            }
        }
    }

    #[tokio::test]
    async fn commit_requires_approval() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        // Stage a change
        std::fs::write(tmp.path().join("new.txt"), "new file\n").unwrap();
        std::process::Command::new("git")
            .args(["add", "new.txt"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let state = test_state(repo_str);
        let result = handle_commit(
            serde_json::json!({"path": repo_str, "message": "Add new file"}),
            test_ctx(),
            state,
        )
        .await;

        // Should return approval-needed (not an error, but a success with approval request)
        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Approval required"));
                assert!(t.text.contains("git.commit"));
            }
        }
    }

    #[tokio::test]
    async fn commit_denied_for_readonly() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        let state = test_state(repo_str);
        let result = handle_commit(
            serde_json::json!({"path": repo_str, "message": "test"}),
            readonly_ctx(),
            state,
        )
        .await;

        assert!(result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("not permitted"));
            }
        }
    }

    #[tokio::test]
    async fn status_denied_outside_allowed_path() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        // Create state with a permission engine that only allows /home/user/**
        let mut engine = PermissionEngine::new();
        engine.add_permission_set(
            "developer".to_string(),
            PathAcl {
                ring: None,
                allow: vec!["/home/user/**".to_string()],
                deny: vec![],
                operations: ["git.status"].into_iter().map(String::from).collect(),
                requires_approval: HashSet::new(),
            },
        );
        let state = Arc::new(GitState {
            perm_engine: Arc::new(engine),
            approvals: Arc::new(ApprovalStore::new(300)),
            notifier: Arc::new(smgglrs_core::notify::NoopNotifier),
        });

        let result = handle_status(
            serde_json::json!({"path": repo_str}),
            test_ctx(),
            state,
        )
        .await;

        assert!(result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Access denied"));
            }
        }
    }

    #[tokio::test]
    async fn missing_path_returns_error() {
        let state = test_state("/tmp");
        let result = handle_status(
            serde_json::json!({}),
            test_ctx(),
            state,
        )
        .await;

        assert!(result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Missing"));
            }
        }
    }

    #[tokio::test]
    async fn not_a_repo_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_str = tmp.path().to_str().unwrap();
        let state = test_state(repo_str);

        let result = handle_status(
            serde_json::json!({"path": repo_str}),
            test_ctx(),
            state,
        )
        .await;

        assert!(result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Not a git repository"));
            }
        }
    }

    // --- Path traversal tests ---

    #[test]
    fn resolve_repo_path_rejects_dotdot() {
        let result = resolve_repo_path("/tmp/repo/../../../etc/passwd");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains(".."), "Expected '..' rejection, got: {err}");
    }

    #[test]
    fn resolve_repo_path_rejects_dotdot_at_start() {
        let result = resolve_repo_path("/../etc/passwd");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains(".."), "Expected '..' rejection, got: {err}");
    }

    #[test]
    fn resolve_repo_path_rejects_dotdot_in_middle() {
        let result = resolve_repo_path("/home/user/../other/repo");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains(".."), "Expected '..' rejection, got: {err}");
    }

    #[test]
    fn resolve_repo_path_rejects_symlink_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir(&repo_dir).unwrap();
        init_test_repo(&repo_dir);

        // Create a symlink that points outside the parent directory
        let link_path = tmp.path().join("escape_link");
        std::os::unix::fs::symlink("/tmp", &link_path).unwrap();

        let result = resolve_repo_path(link_path.to_str().unwrap());
        assert!(result.is_err(), "Symlink escape should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("Symlink escapes") || err.contains("Not a git repository"),
            "Expected symlink escape error, got: {err}"
        );
    }

    #[test]
    fn resolve_repo_path_allows_valid_absolute() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let result = resolve_repo_path(tmp.path().to_str().unwrap());
        assert!(result.is_ok(), "Valid absolute repo path should succeed");
    }
}
