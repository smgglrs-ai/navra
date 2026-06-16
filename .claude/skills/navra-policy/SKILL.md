---
name: navra-policy
description: Generate navra ACL rules from natural language, or audit an existing config for security gaps
---

Convert natural language permission descriptions to navra TOML
configuration, or audit an existing config for weaknesses.

## Usage

- `/navra-policy` — describe what you want, get TOML rules
- `/navra-policy audit` — audit the current config for security gaps

## Generate mode (default)

The user describes permissions in plain language. Translate to navra
TOML config fragments that can be added to `~/.config/navra/config.toml`.

### Translation rules

**Path access:**

| User says | TOML |
|-----------|------|
| "read my code" | `allow = ["~/Code/**"]` + `operations = ["read"]` |
| "read and write in project X" | `allow = ["~/Code/project-x/**"]` + `operations = ["read", "write"]` |
| "no access to secrets" | `deny = ["**/.env", "**/*secret*", "**/credentials*", "**/*.pem", "**/*.key"]` |
| "only this directory" | `allow = ["<exact-path>/**"]` with no broader patterns |

**Tool permissions:**

| User says | TOML |
|-----------|------|
| "allow git but approve pushes" | `[[tool_rules]]` with `git_push → approve`, rest `allow` |
| "no shell access" | `[[tool_rules]]` with `exec_* → deny` |
| "read-only git" | `operations` includes `git.status`, `git.diff`, `git.log` but not `git.commit`, `git.push` |

**Safety levels:**

| User says | TOML |
|-----------|------|
| "strict" / "maximum safety" | `safety = "standard"` + tool_rules deny exec |
| "normal" / "standard" | `safety = "standard"` |
| "just catch secrets" | `safety = "secrets-only"` |
| "I know what I'm doing" | `safety = "secrets-only"` (never suggest `none`) |

**IFC policies:**

| User says | TOML |
|-----------|------|
| "prevent data leaks" | `tainted_write_policy = "deny"` |
| "ask before writing after reading external data" | `tainted_write_policy = "approve"` |
| "trust everything in my project" | `trusted_paths = ["~/Code/myproject/**"]` |

### Output format

Always output a complete permission set block:

```toml
[permissions.<name>]
allow = [...]
deny = [...]
operations = [...]
safety = "..."
default_tool_policy = "allow"

# Tool-specific rules (if needed)
[[permissions.<name>.tool_rules]]
tool = "..."
policy = "..."
```

If the user's request is ambiguous, ask for clarification before
generating. Always include sensible deny rules even if the user
didn't mention them — `**/.env` and `**/*secret*` at minimum.

### Common patterns

**Developer (read/write code, git, no secrets):**

```toml
[permissions.dev]
allow = ["~/Code/**"]
deny = ["**/.env", "**/*secret*", "**/credentials*", "**/*.pem", "**/*.key"]
operations = ["read", "write", "git.status", "git.diff", "git.log",
              "git.branch", "git.commit", "git.fetch", "git.pull", "git.push"]
safety = "standard"
default_tool_policy = "allow"

[[permissions.dev.tool_rules]]
tool = "git_push"
policy = "approve"

[[permissions.dev.tool_rules]]
tool = "exec_*"
policy = "deny"
```

**Read-only reviewer:**

```toml
[permissions.reviewer]
allow = ["~/Code/**", "~/Documents/**"]
deny = ["**/.env", "**/*secret*"]
operations = ["read", "git.status", "git.diff", "git.log"]
safety = "standard"
default_tool_policy = "deny"

[[permissions.reviewer.tool_rules]]
tool = "file_read"
policy = "allow"

[[permissions.reviewer.tool_rules]]
tool = "rag_*"
policy = "allow"
```

**Restricted agent (single project, no network):**

```toml
[permissions.restricted]
allow = ["~/Code/specific-project/**"]
deny = ["**/.env", "**/*secret*", "**/.git/config"]
operations = ["read", "write"]
safety = "standard"
tainted_write_policy = "deny"
default_tool_policy = "deny"

[[permissions.restricted.tool_rules]]
tool = "file_read"
policy = "allow"

[[permissions.restricted.tool_rules]]
tool = "file_write"
policy = "approve"
```

## Audit mode

Read the existing config and identify security weaknesses.

### Steps

1. Read `~/.config/navra/config.toml`
2. For each permission set, check:

**Critical issues (always flag):**

- `allow = ["/**"]` or `allow = ["~/**"]` — overly broad access
- No `deny` rules at all — missing baseline protection
- `safety = "none"` — all content filtering disabled
- `tainted_write_policy = "allow"` — exfiltration prevention disabled
- `default_tool_policy = "allow"` with no `tool_rules` — all tools
  unrestricted

**Warnings (suggest improvement):**

- `deny` list missing `**/.env` — credential files exposed
- `deny` list missing `**/*secret*` — secret files exposed
- `deny` list missing `**/*.pem` or `**/*.key` — private keys exposed
- No `tool_rules` for `exec_*` — shell execution unrestricted
- No `tool_rules` for `git_push` — can push without approval
- `operations` includes `write` but no approval configured
- Agent has `can_delegate = true` without ring restrictions
- Rate limit not set for agents with broad permissions

**Informational:**

- Modules enabled but not used by any permission set
- Permission sets defined but not referenced by any agent
- Multiple agents sharing the same permission set (may be
  intentional but worth noting)

### Output format

Report findings grouped by severity. For each finding, show:
1. What was found (the config line)
2. Why it's a concern
3. The suggested fix (exact TOML)

## Notes

- navra uses deny-wins semantics — a deny rule always beats an allow
- Glob patterns: `*` matches one path segment, `**` matches any depth
- `~` expands to the user's home directory
- Always include `**/.env` and `**/*secret*` in deny rules as baseline
- Never suggest `safety = "none"` — use `secrets-only` as the minimum
- The `operations` field uses dot-namespaced strings: `read`, `write`,
  `git.status`, `git.commit`, etc.
- Tool rules use glob patterns on tool names: `git_*`, `file_write`,
  `exec_*`
