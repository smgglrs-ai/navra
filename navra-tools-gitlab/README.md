# navra-tools-gitlab

GitLab forge module for navra. Provides tools for interacting with
GitLab repositories via the `glab` CLI.

## Tools

| Tool | Description |
|---|---|
| `gitlab_mr_list` | List merge requests with optional state/label filters |
| `gitlab_mr_create` | Create a merge request with title, body, source/target branches |
| `gitlab_mr_view` | View MR details: diff, approvals, pipeline status |
| `gitlab_issue_list` | List issues with optional state/label/assignee filters |
| `gitlab_issue_create` | Create an issue with title, body, labels, assignee |
| `gitlab_issue_comment` | Add a comment to an existing issue |

## Prerequisites

The `glab` CLI must be installed and authenticated:

```bash
glab auth login
```

## Configuration

Enable in `config.toml`:

```toml
[modules.gitlab]
enabled = true
```

## Dependency layer

```
navra-core
    |
navra-tools-gitlab
```
