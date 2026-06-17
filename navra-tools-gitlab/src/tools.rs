use navra_mcp::auth::CallContext;
use navra_mcp::protocol::CallToolResult;
use navra_mcp::Module;
use navra_macros::tool;

/// GitLab forge module for navra.
///
/// Provides tools for interacting with GitLab via the `glab` CLI:
/// - `gitlab_mr_list` — list merge requests
/// - `gitlab_mr_create` — create a merge request
/// - `gitlab_mr_view` — view a merge request
/// - `gitlab_issue_list` — list issues
/// - `gitlab_issue_create` — create an issue
/// - `gitlab_issue_comment` — comment on an issue or MR
pub struct GitlabModule;

impl Module for GitlabModule {
    fn name(&self) -> &str {
        "gitlab"
    }

    fn tools(
        &self,
    ) -> Vec<(
        navra_mcp::protocol::ToolDefinition,
        navra_mcp::ToolHandler,
    )> {
        vec![
            gitlab_mr_list_handler(),
            gitlab_mr_create_handler(),
            gitlab_mr_view_handler(),
            gitlab_issue_list_handler(),
            gitlab_issue_create_handler(),
            gitlab_issue_comment_handler(),
        ]
    }
}

fn validate_repo(repo: &str) -> Result<(), CallToolResult> {
    if !repo.contains('/') || repo.starts_with('/') || repo.ends_with('/') {
        return Err(CallToolResult::error(
            "Invalid project path: expected 'group/project' or 'group/subgroup/project'",
        ));
    }
    if repo.contains("//") {
        return Err(CallToolResult::error(
            "Invalid project path: contains empty segment",
        ));
    }
    if repo.contains(|c: char| {
        c.is_whitespace()
            || c == ';'
            || c == '|'
            || c == '&'
            || c == '$'
            || c == '`'
            || c == '('
            || c == ')'
            || c == '\''
            || c == '"'
            || c == '\\'
            || c == '\n'
    }) {
        return Err(CallToolResult::error(
            "Invalid project path: contains shell metacharacters",
        ));
    }
    Ok(())
}

fn validate_ref_name(name: &str) -> Result<(), CallToolResult> {
    if name.is_empty() {
        return Err(CallToolResult::error("Branch name must not be empty"));
    }
    if name.contains(|c: char| {
        c.is_whitespace()
            || c == ';'
            || c == '|'
            || c == '&'
            || c == '$'
            || c == '`'
            || c == '('
            || c == ')'
            || c == '\''
            || c == '"'
            || c == '\\'
            || c == '\n'
            || c == '~'
            || c == '^'
            || c == ':'
    }) {
        return Err(CallToolResult::error(
            "Branch name contains disallowed characters",
        ));
    }
    if name.contains("..") {
        return Err(CallToolResult::error(
            "Branch name must not contain '..'",
        ));
    }
    Ok(())
}

fn check_permission(ctx: &CallContext, operation: &str) -> Result<(), CallToolResult> {
    let perms = &ctx.agent.permissions;
    if perms == "restricted" || perms == "readonly" {
        return Err(CallToolResult::error(format!(
            "Permission denied: agent '{}' ({}) cannot perform GitLab {} operation",
            ctx.agent.name, perms, operation
        )));
    }
    Ok(())
}

async fn run_glab(args: &[&str]) -> Result<String, CallToolResult> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::process::Command::new("glab").args(args).output(),
    )
    .await
    .map_err(|_| CallToolResult::error("glab command timed out (60s)"))?
    .map_err(|e| {
        CallToolResult::error(format!("Failed to run glab CLI (is it installed?): {e}"))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CallToolResult::error(format!("glab error: {stderr}")));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// --- Tool implementations ---

#[tool(
    name = "gitlab_mr_list",
    description = "List merge requests for a GitLab project."
)]
async fn gitlab_mr_list(
    #[arg(description = "Project path (e.g. group/project or group/subgroup/project)")]
    repo: String,
    #[arg(description = "MR state: opened, closed, merged, all (default: opened)")] state: Option<
        String,
    >,
    #[arg(description = "Maximum number of MRs to return (default: 10)")] limit: Option<i64>,
    _ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = validate_repo(&repo) {
        return e;
    }
    let state = state.unwrap_or_else(|| "opened".to_string());
    let limit = limit.unwrap_or(10).max(1).min(100).to_string();

    match run_glab(&[
        "mr",
        "list",
        "--repo",
        &repo,
        "--state",
        &state,
        "--per-page",
        &limit,
        "--output",
        "json",
    ])
    .await
    {
        Ok(output) => CallToolResult::text(output),
        Err(e) => e,
    }
}

#[tool(
    name = "gitlab_mr_create",
    description = "Create a merge request on a GitLab project."
)]
async fn gitlab_mr_create(
    #[arg(description = "Project path (e.g. group/project or group/subgroup/project)")]
    repo: String,
    #[arg(description = "MR title")] title: String,
    #[arg(description = "Source branch to merge from")] source_branch: String,
    #[arg(description = "Target branch to merge into (default: main)")] target_branch: Option<
        String,
    >,
    #[arg(description = "MR description")] description: Option<String>,
    ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = check_permission(&ctx, "mr_create") {
        return e;
    }
    if let Err(e) = validate_repo(&repo) {
        return e;
    }
    if let Err(e) = validate_ref_name(&source_branch) {
        return e;
    }
    let target = target_branch.unwrap_or_else(|| "main".to_string());
    if let Err(e) = validate_ref_name(&target) {
        return e;
    }

    let mut args = vec![
        "mr",
        "create",
        "--repo",
        &repo,
        "--title",
        &title,
        "--source-branch",
        &source_branch,
        "--target-branch",
        &target,
    ];
    let desc_val;
    if let Some(ref d) = description {
        desc_val = d.clone();
        args.extend_from_slice(&["--description", &desc_val]);
    }

    match run_glab(&args).await {
        Ok(output) => CallToolResult::text(output),
        Err(e) => e,
    }
}

#[tool(
    name = "gitlab_mr_view",
    description = "View details of a specific merge request."
)]
async fn gitlab_mr_view(
    #[arg(description = "Project path (e.g. group/project or group/subgroup/project)")]
    repo: String,
    #[arg(description = "MR IID (project-scoped number)")] number: i64,
    _ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = validate_repo(&repo) {
        return e;
    }
    if number < 1 {
        return CallToolResult::error("MR number must be positive");
    }
    let number_str = number.to_string();

    match run_glab(&[
        "mr",
        "view",
        &number_str,
        "--repo",
        &repo,
        "--output",
        "json",
    ])
    .await
    {
        Ok(output) => CallToolResult::text(output),
        Err(e) => e,
    }
}

#[tool(
    name = "gitlab_issue_list",
    description = "List issues for a GitLab project."
)]
async fn gitlab_issue_list(
    #[arg(description = "Project path (e.g. group/project or group/subgroup/project)")]
    repo: String,
    #[arg(description = "Issue state: opened, closed, all (default: opened)")] state: Option<
        String,
    >,
    #[arg(description = "Maximum number of issues to return (default: 10)")] limit: Option<i64>,
    _ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = validate_repo(&repo) {
        return e;
    }
    let state = state.unwrap_or_else(|| "opened".to_string());
    let limit = limit.unwrap_or(10).max(1).min(100).to_string();

    match run_glab(&[
        "issue",
        "list",
        "--repo",
        &repo,
        "--state",
        &state,
        "--per-page",
        &limit,
        "--output",
        "json",
    ])
    .await
    {
        Ok(output) => CallToolResult::text(output),
        Err(e) => e,
    }
}

#[tool(
    name = "gitlab_issue_create",
    description = "Create an issue on a GitLab project."
)]
async fn gitlab_issue_create(
    #[arg(description = "Project path (e.g. group/project or group/subgroup/project)")]
    repo: String,
    #[arg(description = "Issue title")] title: String,
    #[arg(description = "Issue description")] description: Option<String>,
    #[arg(description = "Comma-separated label names")] labels: Option<String>,
    ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = check_permission(&ctx, "issue_create") {
        return e;
    }
    if let Err(e) = validate_repo(&repo) {
        return e;
    }

    let mut args = vec!["issue", "create", "--repo", &repo, "--title", &title];
    let desc_val;
    if let Some(ref d) = description {
        desc_val = d.clone();
        args.extend_from_slice(&["--description", &desc_val]);
    }
    let labels_val;
    if let Some(ref l) = labels {
        labels_val = l.clone();
        args.extend_from_slice(&["--label", &labels_val]);
    }

    match run_glab(&args).await {
        Ok(output) => CallToolResult::text(output),
        Err(e) => e,
    }
}

#[tool(
    name = "gitlab_issue_comment",
    description = "Add a comment to a GitLab issue or merge request."
)]
async fn gitlab_issue_comment(
    #[arg(description = "Project path (e.g. group/project or group/subgroup/project)")]
    repo: String,
    #[arg(description = "Issue or MR IID")] number: i64,
    #[arg(description = "Comment body")] body: String,
    ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = check_permission(&ctx, "issue_comment") {
        return e;
    }
    if let Err(e) = validate_repo(&repo) {
        return e;
    }
    if number < 1 {
        return CallToolResult::error("Issue number must be positive");
    }
    let number_str = number.to_string();

    match run_glab(&[
        "issue",
        "comment",
        &number_str,
        "--repo",
        &repo,
        "--message",
        &body,
    ])
    .await
    {
        Ok(output) => CallToolResult::text(output),
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_repo_accepts_valid() {
        assert!(validate_repo("group/project").is_ok());
        assert!(validate_repo("org-name/my-project").is_ok());
        assert!(validate_repo("group/subgroup/project").is_ok());
        assert!(validate_repo("a/b/c/d").is_ok());
    }

    #[test]
    fn validate_repo_rejects_invalid() {
        assert!(validate_repo("noslash").is_err());
        assert!(validate_repo("/leading").is_err());
        assert!(validate_repo("trailing/").is_err());
        assert!(validate_repo("has spaces/repo").is_err());
        assert!(validate_repo("semi;colon/repo").is_err());
        assert!(validate_repo("pipe|char/repo").is_err());
        assert!(validate_repo("amp&ersand/repo").is_err());
        assert!(validate_repo("double//slash").is_err());
    }

    #[test]
    fn module_has_correct_name() {
        let m = GitlabModule;
        assert_eq!(m.name(), "gitlab");
    }

    #[test]
    fn module_registers_six_tools() {
        let m = GitlabModule;
        let tools = m.tools();
        assert_eq!(tools.len(), 6);
        let names: Vec<_> = tools.iter().map(|(d, _)| d.name.as_str()).collect();
        assert!(names.contains(&"gitlab_mr_list"));
        assert!(names.contains(&"gitlab_mr_create"));
        assert!(names.contains(&"gitlab_mr_view"));
        assert!(names.contains(&"gitlab_issue_list"));
        assert!(names.contains(&"gitlab_issue_create"));
        assert!(names.contains(&"gitlab_issue_comment"));
    }

    #[test]
    fn validate_repo_rejects_shell_metacharacters() {
        assert!(validate_repo("group$(cmd)/repo").is_err());
        assert!(validate_repo("group`cmd`/repo").is_err());
        assert!(validate_repo("group/repo\n").is_err());
        assert!(validate_repo("group'repo/x").is_err());
        assert!(validate_repo("group\"repo/x").is_err());
        assert!(validate_repo("group\\repo/x").is_err());
    }

    #[test]
    fn validate_ref_name_accepts_valid() {
        assert!(validate_ref_name("main").is_ok());
        assert!(validate_ref_name("feature/my-branch").is_ok());
        assert!(validate_ref_name("fix-123").is_ok());
    }

    #[test]
    fn validate_ref_name_rejects_injection() {
        assert!(validate_ref_name("branch;rm -rf /").is_err());
        assert!(validate_ref_name("branch$(cmd)").is_err());
        assert!(validate_ref_name("branch`cmd`").is_err());
        assert!(validate_ref_name("a..b").is_err());
        assert!(validate_ref_name("").is_err());
        assert!(validate_ref_name("branch\ninjection").is_err());
    }

    #[test]
    fn check_permission_blocks_restricted() {
        use navra_mcp::auth::AgentIdentity;
        let ctx = CallContext::new(
            AgentIdentity::new("test", "restricted"),
            "test-session",
        );
        assert!(check_permission(&ctx, "mr_create").is_err());

        let ctx2 = CallContext::new(
            AgentIdentity::new("test", "readonly"),
            "test-session",
        );
        assert!(check_permission(&ctx2, "issue_create").is_err());
    }

    #[test]
    fn check_permission_allows_developer() {
        use navra_mcp::auth::AgentIdentity;
        let ctx = CallContext::new(
            AgentIdentity::new("test", "developer"),
            "test-session",
        );
        assert!(check_permission(&ctx, "mr_create").is_ok());
    }

    #[test]
    fn all_tools_have_descriptions() {
        let m = GitlabModule;
        for (def, _) in m.tools() {
            assert!(
                def.description.is_some(),
                "tool {} missing description",
                def.name
            );
        }
    }
}
