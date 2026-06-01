# navra-tools-git

Git module for the navra gateway.

## Overview

Provides MCP tools for interacting with git repositories through
the gateway's security layer. Destructive operations (commit)
require approval via the permission engine.

## Tools provided

| Tool | Description |
|---|---|
| `git_status` | Show working tree status |
| `git_diff` | Show changes (staged, unstaged, or between refs) |
| `git_log` | Show commit history |
| `git_branch` | List or show current branch |
| `git_commit` | Create a commit (requires approval) |

## Key types

- `GitModule` -- implements `Module` trait, registers git tools

## Dependency layer

```
navra-core
    |
navra-tools-git
```

## Reference

See [DESIGN.md](../DESIGN.md) for the module trait design and
permission model for destructive operations.
