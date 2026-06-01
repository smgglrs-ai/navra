use navra_core::auth::CallContext;
use navra_core::protocol::CallToolResult;
use navra_core::Module;
use navra_macros::tool;

/// GitHub forge module for navra.
///
/// Provides tools for interacting with GitHub via the `gh` CLI:
/// - `github_pr_list` — list pull requests
/// - `github_pr_create` — create a pull request
/// - `github_pr_view` — view a pull request
/// - `github_issue_list` — list issues
/// - `github_issue_create` — create an issue
/// - `github_issue_comment` — comment on an issue or PR
pub struct GithubModule;

impl Module for GithubModule {
    fn name(&self) -> &str {
        "github"
    }

    fn tools(
        &self,
    ) -> Vec<(
        navra_core::protocol::ToolDefinition,
        navra_core::ToolHandler,
    )> {
        vec![
            github_pr_list_handler(),
            github_pr_create_handler(),
            github_pr_view_handler(),
            github_issue_list_handler(),
            github_issue_create_handler(),
            github_issue_comment_handler(),
        ]
    }
}

fn validate_repo(repo: &str) -> Result<(), CallToolResult> {
    if !repo.contains('/') || repo.starts_with('/') || repo.ends_with('/') {
        return Err(CallToolResult::error(
            "Invalid repo format: expected 'owner/repo'",
        ));
    }
    if repo.contains(|c: char| c.is_whitespace() || c == ';' || c == '|' || c == '&') {
        return Err(CallToolResult::error(
            "Invalid repo: contains disallowed characters",
        ));
    }
    Ok(())
}

async fn run_gh(args: &[&str]) -> Result<String, CallToolResult> {
    let output = tokio::process::Command::new("gh")
        .args(args)
        .output()
        .await
        .map_err(|e| {
            CallToolResult::error(format!("Failed to run gh CLI (is it installed?): {e}"))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CallToolResult::error(format!("gh error: {stderr}")));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// --- Tool implementations ---

#[tool(
    name = "github_pr_list",
    description = "List pull requests for a GitHub repository."
)]
async fn github_pr_list(
    #[arg(description = "Repository in owner/repo format")] repo: String,
    #[arg(description = "PR state: open, closed, merged, all (default: open)")] state: Option<
        String,
    >,
    #[arg(description = "Maximum number of PRs to return (default: 10)")] limit: Option<i64>,
    _ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = validate_repo(&repo) {
        return e;
    }
    let state = state.unwrap_or_else(|| "open".to_string());
    let limit = limit.unwrap_or(10).max(1).min(100).to_string();

    match run_gh(&[
        "pr",
        "list",
        "--repo",
        &repo,
        "--state",
        &state,
        "--limit",
        &limit,
        "--json",
        "number,title,state,author,createdAt,url",
    ])
    .await
    {
        Ok(output) => CallToolResult::text(output),
        Err(e) => e,
    }
}

#[tool(
    name = "github_pr_create",
    description = "Create a pull request on a GitHub repository."
)]
async fn github_pr_create(
    #[arg(description = "Repository in owner/repo format")] repo: String,
    #[arg(description = "PR title")] title: String,
    #[arg(description = "Head branch to merge from")] head: String,
    #[arg(description = "Base branch to merge into (default: main)")] base: Option<String>,
    #[arg(description = "PR body/description")] body: Option<String>,
    _ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = validate_repo(&repo) {
        return e;
    }
    let base = base.unwrap_or_else(|| "main".to_string());

    let mut args = vec![
        "pr", "create", "--repo", &repo, "--title", &title, "--head", &head, "--base", &base,
    ];
    let body_val;
    if let Some(ref b) = body {
        body_val = b.clone();
        args.extend_from_slice(&["--body", &body_val]);
    }

    match run_gh(&args).await {
        Ok(output) => CallToolResult::text(output),
        Err(e) => e,
    }
}

#[tool(
    name = "github_pr_view",
    description = "View details of a specific pull request."
)]
async fn github_pr_view(
    #[arg(description = "Repository in owner/repo format")] repo: String,
    #[arg(description = "PR number")] number: i64,
    _ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = validate_repo(&repo) {
        return e;
    }
    if number < 1 {
        return CallToolResult::error("PR number must be positive");
    }
    let number_str = number.to_string();

    match run_gh(&[
        "pr",
        "view",
        &number_str,
        "--repo",
        &repo,
        "--json",
        "number,title,state,body,author,createdAt,url,reviewDecision,additions,deletions,files",
    ])
    .await
    {
        Ok(output) => CallToolResult::text(output),
        Err(e) => e,
    }
}

#[tool(
    name = "github_issue_list",
    description = "List issues for a GitHub repository."
)]
async fn github_issue_list(
    #[arg(description = "Repository in owner/repo format")] repo: String,
    #[arg(description = "Issue state: open, closed, all (default: open)")] state: Option<String>,
    #[arg(description = "Maximum number of issues to return (default: 10)")] limit: Option<i64>,
    _ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = validate_repo(&repo) {
        return e;
    }
    let state = state.unwrap_or_else(|| "open".to_string());
    let limit = limit.unwrap_or(10).max(1).min(100).to_string();

    match run_gh(&[
        "issue",
        "list",
        "--repo",
        &repo,
        "--state",
        &state,
        "--limit",
        &limit,
        "--json",
        "number,title,state,author,createdAt,url,labels",
    ])
    .await
    {
        Ok(output) => CallToolResult::text(output),
        Err(e) => e,
    }
}

#[tool(
    name = "github_issue_create",
    description = "Create an issue on a GitHub repository."
)]
async fn github_issue_create(
    #[arg(description = "Repository in owner/repo format")] repo: String,
    #[arg(description = "Issue title")] title: String,
    #[arg(description = "Issue body/description")] body: Option<String>,
    #[arg(description = "Comma-separated label names")] labels: Option<String>,
    _ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = validate_repo(&repo) {
        return e;
    }

    let mut args = vec!["issue", "create", "--repo", &repo, "--title", &title];
    let body_val;
    if let Some(ref b) = body {
        body_val = b.clone();
        args.extend_from_slice(&["--body", &body_val]);
    }
    let labels_val;
    if let Some(ref l) = labels {
        labels_val = l.clone();
        args.extend_from_slice(&["--label", &labels_val]);
    }

    match run_gh(&args).await {
        Ok(output) => CallToolResult::text(output),
        Err(e) => e,
    }
}

#[tool(
    name = "github_issue_comment",
    description = "Add a comment to a GitHub issue or pull request."
)]
async fn github_issue_comment(
    #[arg(description = "Repository in owner/repo format")] repo: String,
    #[arg(description = "Issue or PR number")] number: i64,
    #[arg(description = "Comment body")] body: String,
    _ctx: CallContext,
) -> CallToolResult {
    if let Err(e) = validate_repo(&repo) {
        return e;
    }
    if number < 1 {
        return CallToolResult::error("Issue number must be positive");
    }
    let number_str = number.to_string();

    match run_gh(&[
        "issue",
        "comment",
        &number_str,
        "--repo",
        &repo,
        "--body",
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
        assert!(validate_repo("owner/repo").is_ok());
        assert!(validate_repo("org-name/my-repo").is_ok());
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
    }

    #[test]
    fn module_has_correct_name() {
        let m = GithubModule;
        assert_eq!(m.name(), "github");
    }

    #[test]
    fn module_registers_six_tools() {
        let m = GithubModule;
        let tools = m.tools();
        assert_eq!(tools.len(), 6);
        let names: Vec<_> = tools.iter().map(|(d, _)| d.name.as_str()).collect();
        assert!(names.contains(&"github_pr_list"));
        assert!(names.contains(&"github_pr_create"));
        assert!(names.contains(&"github_pr_view"));
        assert!(names.contains(&"github_issue_list"));
        assert!(names.contains(&"github_issue_create"));
        assert!(names.contains(&"github_issue_comment"));
    }

    #[test]
    fn all_tools_have_descriptions() {
        let m = GithubModule;
        for (def, _) in m.tools() {
            assert!(
                def.description.is_some(),
                "tool {} missing description",
                def.name
            );
        }
    }
}
