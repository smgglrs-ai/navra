use smgglrs_core::auth::CallContext;
use smgglrs_core::notify::Notifier;
use smgglrs_core::permissions::{ApprovalStore, PermissionEngine, PermissionResult};
use smgglrs_core::protocol::{CallToolResult, Content};
use smgglrs_core::Module;
use smgglrs_macros::tool;
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

pub(crate) struct GitState {
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

    fn tools(
        &self,
    ) -> Vec<(
        smgglrs_core::protocol::ToolDefinition,
        smgglrs_core::ToolHandler,
    )> {
        let s = self.state.clone();
        vec![
            handle_status_handler(s.clone()),
            handle_diff_handler(s.clone()),
            handle_log_handler(s.clone()),
            handle_branch_handler(s.clone()),
            handle_commit_handler(s.clone()),
            handle_fetch_handler(s.clone()),
            handle_pull_handler(s.clone()),
            handle_push_handler(s.clone()),
        ]
    }
}

// --- Tool implementations ---

#[tool(
    name = "git_status",
    description = "Show the working tree status of a git repository."
)]
async fn handle_status(
    #[arg(description = "Path to the git repository (directory)")] path: String,
    ctx: CallContext,
    #[state] state: Arc<GitState>,
) -> CallToolResult {
    let repo_path = match resolve_repo_path(&path) {
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

#[tool(
    name = "git_diff",
    description = "Show changes in a git repository. By default shows unstaged changes. Use 'staged: true' for staged changes, or provide 'ref' for a specific comparison."
)]
async fn handle_diff(
    #[arg(description = "Path to the git repository")] path: String,
    #[arg(description = "Show staged changes (default: false)")] staged: Option<bool>,
    #[arg(
        name = "ref",
        description = "Compare against a ref (e.g., HEAD~3, main)"
    )]
    git_ref: Option<String>,
    ctx: CallContext,
    #[state] state: Arc<GitState>,
) -> CallToolResult {
    let repo_path = match resolve_repo_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(result) = check_perm(&state, &ctx, "git.diff", &repo_path).await {
        return result;
    }

    let mut git_args = vec!["diff"];
    if staged.unwrap_or(false) {
        git_args.push("--cached");
    }
    if let Some(ref r) = git_ref {
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

#[tool(
    name = "git_log",
    description = "Show commit history of a git repository."
)]
async fn handle_log(
    #[arg(description = "Path to the git repository")] path: String,
    #[arg(
        description = "Number of commits to show (default: 10)",
        default = "10"
    )]
    limit: Option<u64>,
    #[arg(description = "Use one-line format (default: false)")] oneline: Option<bool>,
    ctx: CallContext,
    #[state] state: Arc<GitState>,
) -> CallToolResult {
    let repo_path = match resolve_repo_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(result) = check_perm(&state, &ctx, "git.log", &repo_path).await {
        return result;
    }

    let limit_val = limit.unwrap_or(10);
    let limit_str = format!("-{limit_val}");
    let mut git_args = vec!["log", &limit_str];
    if oneline.unwrap_or(false) {
        git_args.push("--oneline");
    }

    match run_git(&repo_path, &git_args).await {
        Ok(output) => CallToolResult::text(output),
        Err(e) => CallToolResult::error(e),
    }
}

#[tool(
    name = "git_branch",
    description = "List branches, show current branch, or create a new branch."
)]
async fn handle_branch(
    #[arg(description = "Path to the git repository")] path: String,
    #[arg(description = "Show remote branches too (default: false)")] all: Option<bool>,
    #[arg(description = "Create and switch to a new branch with this name")] create: Option<String>,
    ctx: CallContext,
    #[state] state: Arc<GitState>,
) -> CallToolResult {
    let repo_path = match resolve_repo_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(result) = check_perm(&state, &ctx, "git.branch", &repo_path).await {
        return result;
    }

    if let Some(ref name) = create {
        if name.starts_with('-') {
            return CallToolResult::error("Branch name must not start with '-'");
        }
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.')
        {
            return CallToolResult::error("Branch name contains invalid characters");
        }
        return match run_git(&repo_path, &["checkout", "-b", name]).await {
            Ok(output) => {
                CallToolResult::text(format!("Created and switched to branch '{name}'\n{output}"))
            }
            Err(e) => CallToolResult::error(e),
        };
    }

    let mut git_args = vec!["branch"];
    if all.unwrap_or(false) {
        git_args.push("-a");
    }

    match run_git(&repo_path, &git_args).await {
        Ok(output) => CallToolResult::text(output),
        Err(e) => CallToolResult::error(e),
    }
}

#[tool(
    name = "git_commit",
    description = "Create a git commit with the staged changes. Requires approval."
)]
async fn handle_commit(
    #[arg(description = "Path to the git repository")] path: String,
    #[arg(description = "Commit message")] message: String,
    ctx: CallContext,
    #[state] state: Arc<GitState>,
) -> CallToolResult {
    if message.is_empty() {
        return CallToolResult::error("Missing required parameter: message");
    }

    let repo_path = match resolve_repo_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(result) = check_perm(&state, &ctx, "git.commit", &repo_path).await {
        return result;
    }

    let full_message = format!(
        "{}\n\nSigned-off-by: {} (via smgglrs)",
        message, ctx.agent.name,
    );

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
                "-c",
                "gpg.format=ssh",
                "-c",
                &signing_key_arg,
                "commit",
                "-S",
                "-m",
                &full_message,
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

#[tool(
    name = "git_fetch",
    description = "Fetch updates from a remote repository without merging."
)]
async fn handle_fetch(
    #[arg(description = "Path to the git repository")] path: String,
    #[arg(description = "Remote name (default: origin)", default = "origin")] remote: Option<
        String,
    >,
    #[arg(description = "Prune deleted remote branches")] prune: Option<bool>,
    ctx: CallContext,
    #[state] state: Arc<GitState>,
) -> CallToolResult {
    let repo_path = match resolve_repo_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(result) = check_perm(&state, &ctx, "git.fetch", &repo_path).await {
        return result;
    }

    let remote_name = remote.as_deref().unwrap_or("origin");
    if let Err(e) = validate_ref_name(remote_name, "Remote") {
        return CallToolResult::error(e);
    }

    let mut git_args = vec!["fetch", remote_name];
    if prune.unwrap_or(false) {
        git_args.push("--prune");
    }

    match run_git(&repo_path, &git_args).await {
        Ok(output) => {
            if output.trim().is_empty() {
                CallToolResult::text(format!("Already up to date ({remote_name})."))
            } else {
                CallToolResult::text(output)
            }
        }
        Err(e) => CallToolResult::error(e),
    }
}

#[tool(
    name = "git_pull",
    description = "Pull commits from a remote repository (fetch + merge)."
)]
async fn handle_pull(
    #[arg(description = "Path to the git repository")] path: String,
    #[arg(description = "Remote name (default: origin)", default = "origin")] remote: Option<
        String,
    >,
    #[arg(description = "Branch to pull (default: tracked branch)")] branch: Option<String>,
    #[arg(description = "Rebase instead of merge")] rebase: Option<bool>,
    ctx: CallContext,
    #[state] state: Arc<GitState>,
) -> CallToolResult {
    let repo_path = match resolve_repo_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(result) = check_perm(&state, &ctx, "git.pull", &repo_path).await {
        return result;
    }

    let remote_name = remote.as_deref().unwrap_or("origin");
    if let Err(e) = validate_ref_name(remote_name, "Remote") {
        return CallToolResult::error(e);
    }

    let mut git_args = vec!["pull"];
    if rebase.unwrap_or(false) {
        git_args.push("--rebase");
    }
    git_args.push(remote_name);
    if let Some(ref b) = branch {
        if let Err(e) = validate_ref_name(b, "Branch") {
            return CallToolResult::error(e);
        }
        git_args.push(b);
    }

    match run_git(&repo_path, &git_args).await {
        Ok(output) => CallToolResult::text(output),
        Err(e) => CallToolResult::error(e),
    }
}

#[tool(
    name = "git_push",
    description = "Push commits to a remote repository. Requires approval."
)]
async fn handle_push(
    #[arg(description = "Path to the git repository")] path: String,
    #[arg(description = "Remote name (default: origin)", default = "origin")] remote: Option<
        String,
    >,
    #[arg(description = "Branch to push (default: current branch)")] branch: Option<String>,
    #[arg(description = "Force push (overwrites remote history)")] force: Option<bool>,
    ctx: CallContext,
    #[state] state: Arc<GitState>,
) -> CallToolResult {
    let repo_path = match resolve_repo_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(result) = check_perm(&state, &ctx, "git.push", &repo_path).await {
        return result;
    }

    let remote_name = remote.as_deref().unwrap_or("origin");
    if let Err(e) = validate_ref_name(remote_name, "Remote") {
        return CallToolResult::error(e);
    }

    let mut git_args = vec!["push"];
    if force.unwrap_or(false) {
        git_args.push("--force");
    }
    git_args.push(remote_name);
    if let Some(ref b) = branch {
        if let Err(e) = validate_ref_name(b, "Branch") {
            return CallToolResult::error(e);
        }
        git_args.push(b);
    }

    match run_git(&repo_path, &git_args).await {
        Ok(output) => {
            if output.trim().is_empty() {
                CallToolResult::text("Push successful.".to_string())
            } else {
                CallToolResult::text(output)
            }
        }
        Err(e) => CallToolResult::error(e),
    }
}

// --- Ref name validation ---

fn validate_ref_name(name: &str, label: &str) -> Result<(), String> {
    if name.starts_with('-') {
        return Err(format!("{label} name must not start with '-'"));
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.')
    {
        return Err(format!("{label} name contains invalid characters"));
    }
    Ok(())
}

// --- Path validation ---

fn resolve_repo_path(raw: &str) -> Result<PathBuf, String> {
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

    if expanded.is_symlink() {
        let target =
            std::fs::read_link(&expanded).map_err(|e| format!("Cannot read symlink {raw}: {e}"))?;
        let resolved = if target.is_absolute() {
            target
        } else {
            expanded.parent().unwrap_or(Path::new("/")).join(&target)
        };
        let resolved = resolved
            .canonicalize()
            .map_err(|e| format!("Symlink target not accessible: {e}"))?;
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
        &ctx.agent.permissions,
        op,
        path,
        ctx.agent.capabilities.as_ref(),
    ) {
        PermissionResult::Allowed => Ok(()),
        PermissionResult::NeedsApproval => {
            let path_str = path.display().to_string();

            if state.approvals.check_grant(&ctx.agent.name, op, &path_str) {
                tracing::info!(
                    agent = %ctx.agent.name, op, path = %path_str,
                    "Using cached approval grant"
                );
                return Ok(());
            }

            let (req, _rx) = state.approvals.request(&ctx.agent.name, op, &path_str);

            if let Err(e) = state.notifier.notify(&req, state.approvals.clone()).await {
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

async fn run_git(repo_path: &Path, args: &[&str]) -> Result<String, String> {
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
                    "git.fetch",
                    "git.pull",
                    "git.push",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
                requires_approval: ["git.commit", "git.push"]
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
        assert_eq!(tools.len(), 8);
        let names: Vec<_> = tools.iter().map(|(d, _)| d.name.as_str()).collect();
        assert!(names.contains(&"git_status"));
        assert!(names.contains(&"git_diff"));
        assert!(names.contains(&"git_log"));
        assert!(names.contains(&"git_branch"));
        assert!(names.contains(&"git_commit"));
        assert!(names.contains(&"git_fetch"));
        assert!(names.contains(&"git_pull"));
        assert!(names.contains(&"git_push"));
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

        let (_, handler) = handle_status_handler(state);
        let result = handler(serde_json::json!({"path": repo_str}), test_ctx()).await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("##") || t.text.contains("clean"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn status_shows_modified_file() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        std::fs::write(tmp.path().join("README.md"), "# Modified\n").unwrap();

        let state = test_state(repo_str);
        let (_, handler) = handle_status_handler(state);
        let result = handler(serde_json::json!({"path": repo_str}), test_ctx()).await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("README.md"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn diff_shows_changes() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        std::fs::write(tmp.path().join("README.md"), "# Changed content\n").unwrap();

        let state = test_state(repo_str);
        let (_, handler) = handle_diff_handler(state);
        let result = handler(serde_json::json!({"path": repo_str}), test_ctx()).await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Changed content") || t.text.contains("README.md"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn diff_no_changes() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        let state = test_state(repo_str);
        let (_, handler) = handle_diff_handler(state);
        let result = handler(serde_json::json!({"path": repo_str}), test_ctx()).await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert_eq!(t.text, "No changes");
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn log_shows_history() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        let state = test_state(repo_str);
        let (_, handler) = handle_log_handler(state);
        let result = handler(
            serde_json::json!({"path": repo_str, "limit": 5}),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Initial commit"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn log_oneline() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        let state = test_state(repo_str);
        let (_, handler) = handle_log_handler(state);
        let result = handler(
            serde_json::json!({"path": repo_str, "oneline": true}),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                let lines: Vec<_> = t.text.lines().collect();
                assert!(!lines.is_empty());
                assert!(lines[0].contains("Initial commit"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn branch_shows_current() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        let state = test_state(repo_str);
        let (_, handler) = handle_branch_handler(state);
        let result = handler(serde_json::json!({"path": repo_str}), test_ctx()).await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("*"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn commit_requires_approval() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        std::fs::write(tmp.path().join("new.txt"), "new file\n").unwrap();
        std::process::Command::new("git")
            .args(["add", "new.txt"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let state = test_state(repo_str);
        let (_, handler) = handle_commit_handler(state);
        let result = handler(
            serde_json::json!({"path": repo_str, "message": "Add new file"}),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Approval required"));
                assert!(t.text.contains("git.commit"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn commit_denied_for_readonly() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

        let state = test_state(repo_str);
        let (_, handler) = handle_commit_handler(state);
        let result = handler(
            serde_json::json!({"path": repo_str, "message": "test"}),
            readonly_ctx(),
        )
        .await;

        assert!(result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("not permitted"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn status_denied_outside_allowed_path() {
        let tmp = tempfile::tempdir().unwrap();
        init_test_repo(tmp.path());
        let repo_str = tmp.path().to_str().unwrap();

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

        let (_, handler) = handle_status_handler(state);
        let result = handler(serde_json::json!({"path": repo_str}), test_ctx()).await;

        assert!(result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Access denied"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn missing_path_marked_required_in_schema() {
        let def = handle_status_tool_def();
        assert!(def
            .input_schema
            .required
            .as_ref()
            .unwrap()
            .contains(&"path".to_string()));
    }

    #[tokio::test]
    async fn missing_path_returns_error() {
        let state = test_state("/tmp");
        let (_, handler) = handle_status_handler(state);
        let result = handler(serde_json::json!({}), test_ctx()).await;
        assert!(result.is_error);
        match &result.content[0] {
            Content::Text(t) => assert!(t.text.contains("Missing required parameter")),
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn not_a_repo_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_str = tmp.path().to_str().unwrap();
        let state = test_state(repo_str);

        let (_, handler) = handle_status_handler(state);
        let result = handler(serde_json::json!({"path": repo_str}), test_ctx()).await;

        assert!(result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Not a git repository"));
            }
            _ => panic!("expected text content"),
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

    // --- Remote operation tests ---

    fn init_repo_with_remote(dir: &Path) -> PathBuf {
        init_test_repo(dir);
        let bare = dir.parent().unwrap().join("remote.git");
        std::process::Command::new("git")
            .args([
                "clone",
                "--bare",
                dir.to_str().unwrap(),
                bare.to_str().unwrap(),
            ])
            .output()
            .expect("git clone --bare failed");
        std::process::Command::new("git")
            .args(["remote", "add", "origin", bare.to_str().unwrap()])
            .current_dir(dir)
            .output()
            .expect("git remote add failed");
        bare
    }

    #[tokio::test]
    async fn fetch_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let _bare = init_repo_with_remote(&repo);
        let repo_str = repo.to_str().unwrap();
        let state = test_state(repo_str);

        let (_, handler) = handle_fetch_handler(state);
        let result = handler(serde_json::json!({"path": repo_str}), test_ctx()).await;

        assert!(!result.is_error);
    }

    #[tokio::test]
    async fn push_requires_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let _bare = init_repo_with_remote(&repo);
        let repo_str = repo.to_str().unwrap();

        std::fs::write(repo.join("new.txt"), "push test\n").unwrap();
        std::process::Command::new("git")
            .args(["add", "new.txt"])
            .current_dir(&repo)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "push commit"])
            .current_dir(&repo)
            .output()
            .unwrap();

        let state = test_state(repo_str);
        let (_, handler) = handle_push_handler(state);
        let result = handler(serde_json::json!({"path": repo_str}), test_ctx()).await;

        assert!(!result.is_error);
        match &result.content[0] {
            Content::Text(t) => {
                assert!(t.text.contains("Approval required"));
                assert!(t.text.contains("git.push"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn push_denied_for_readonly() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let _bare = init_repo_with_remote(&repo);
        let repo_str = repo.to_str().unwrap();
        let state = test_state(repo_str);

        let (_, handler) = handle_push_handler(state);
        let result = handler(serde_json::json!({"path": repo_str}), readonly_ctx()).await;

        assert!(result.is_error);
        match &result.content[0] {
            Content::Text(t) => assert!(t.text.contains("not permitted")),
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn invalid_remote_name_rejected() {
        assert!(validate_ref_name("-evil", "Remote").is_err());
        assert!(validate_ref_name("origin;rm -rf /", "Remote").is_err());
        assert!(validate_ref_name("origin", "Remote").is_ok());
        assert!(validate_ref_name("my-remote_1", "Remote").is_ok());
    }
}
