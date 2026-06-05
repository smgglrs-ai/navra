# navra-tools-github

GitHub forge module for navra. Provides tools for interacting with
GitHub repositories via the `gh` CLI.

## Tools

| Tool | Description |
|---|---|
| `github_pr_list` | List pull requests with optional state/label filters |
| `github_pr_create` | Create a pull request with title, body, base/head branches |
| `github_pr_view` | View PR details: diff, reviews, checks, comments |
| `github_issue_list` | List issues with optional state/label/assignee filters |
| `github_issue_create` | Create an issue with title, body, labels, assignee |
| `github_issue_comment` | Add a comment to an existing issue |

## Prerequisites

The `gh` CLI must be installed and authenticated:

```bash
gh auth login
```

## Configuration

Enable in `config.toml`:

```toml
[modules.github]
enabled = true
```

## Dependency layer

```
navra-core
    |
navra-tools-github
```
