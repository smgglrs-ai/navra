# navra-tools-git

Git tools for the navra gateway.

## Overview

Provides MCP tools for Git operations on local repositories.
All operations go through navra's permission engine — destructive
actions like `git_push` and `git_commit` can be gated behind
human-in-the-loop approval.

## Tools

| Tool | Description |
|---|---|
| `git_status` | Working tree status (staged, modified, untracked) |
| `git_diff` | Show changes between commits, working tree, or staged |
| `git_log` | Commit history with optional path filter and limit |
| `git_branch` | List, create, or delete branches |
| `git_commit` | Create a commit with message (requires approval if configured) |
| `git_push` | Push commits to remote (requires approval if configured) |
| `git_pull` | Pull from remote with rebase or merge |
| `git_fetch` | Fetch refs from remote without merging |

## Configuration

```toml
[modules.git]
enabled = true
```

Approval for destructive operations is configured in the
permission set:

```toml
[[permissions.dev.tool_rules]]
tool = "git_push"
policy = "approve"

[[permissions.dev.tool_rules]]
tool = "git_commit"
policy = "approve"
```

## Commit Signing

When an agent has a `signing_key` configured in its `[[agents]]`
block, `git_commit` uses that Ed25519 key to sign commits
automatically.

## Dependency Layer

```
navra-core
    |
navra-tools-git
```
