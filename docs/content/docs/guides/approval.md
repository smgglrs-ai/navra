+++
title = "Human-in-the-Loop Approval"
description = "Gate high-risk agent actions on explicit human consent before they execute."
weight = 25

[extra]
toc = true
+++

Navra can pause tool calls that match configurable risk criteria and
wait for a human to approve or deny them before execution proceeds.
This addresses OWASP ASI09 (Insufficient Human Oversight) and gives
operators a practical kill switch for sensitive operations without
disabling tools entirely.

## When approval is triggered

Approval gates activate through two independent mechanisms in the
permission system. Both produce the same result: the server returns
an "Approval required" response immediately (non-blocking) and
creates a pending request that a human must resolve.

### Tool rules with `policy = "approve"`

Per-tool policies in a permission set can require approval for
specific tools or tool patterns:

```toml
[permissions.developer]
default_tool_policy = "deny"
tool_rules = [
  { tool = "file_read", policy = "allow" },
  { tool = "file_write", policy = "approve" },
  { tool = "shell_*", policy = "deny" },
]
```

When an agent calls `file_write`, the server checks the tool rule,
finds `policy = "approve"`, and returns:

```
Approval required: 'file_write'
```

The agent receives this as a normal tool error result. It can retry
the call after approval is granted.

### The `approve` operations list

Permission sets can also list operation namespaces that require
approval regardless of tool rules:

```toml
[permissions.cautious]
operations = ["read", "write"]
approve = ["write"]
```

Any tool classified as a `write` operation triggers the approval
flow when called by an agent using this permission set.

## The four resolution channels

Once a pending approval exists, the human can resolve it through any
of four channels. All four call the same `ApprovalStore::approve()`
or `deny()` method, so the first response wins.

```
Agent: file_write(path="/home/user/doc.md", content="...")
Server: "Approval required. Request ID: abc-123."
        (+ D-Bus notification with Approve/Deny buttons)
        (+ system tray icon shows pending approval)

Resolution via ANY channel:
  1. Agent calls file_approve(request_id=abc-123)     -- MCP-native
  2. User clicks D-Bus notification "Approve" button  -- Desktop
  3. User clicks tray menu "Approve"                  -- System tray
  4. CLI: navra approve abc-123                        -- Terminal
```

### Channel 1: MCP-native (file_approve / file_deny)

The agent itself can call the `file_approve` or `file_deny` tools
with the `request_id` returned in the approval-required response.
This is useful for automated approval workflows where a supervisory
agent decides whether to permit the action.

### Channel 2: D-Bus desktop notifications

On desktop Linux, navra sends a notification via
`org.freedesktop.Notifications` with **Approve** and **Deny** action
buttons. Clicking a button resolves the request immediately. The
notification uses urgency level 2 (critical) so it persists until
acted on.

The notification body shows:

```
navra: write approval
Agent **claude** wants to **write**
/home/user/doc.md
```

If the user dismisses the notification without clicking a button,
the request is denied automatically.

### Channel 3: System tray menu

The navra system tray icon (via `ksni` / StatusNotifierItem) shows
pending approvals as a submenu. Each entry displays which agent
wants to perform which operation on which path, with **Approve** and
**Deny** sub-items. The tray icon status changes to "needs
attention" when approvals are pending.

The tray polls the `ApprovalStore` every second and updates its
menu accordingly. When all pending approvals are resolved, the icon
returns to its normal state.

### Channel 4: CLI

From any terminal (including over SSH):

```bash
navra approve <request-id>
navra deny <request-id>
```

These commands send a JSON-RPC `tools/call` request to the running
server, invoking `file_approve` or `file_deny` with the given
request ID. The server must be listening on TCP (`server.tcp` in
config) for CLI approval to work.

## Grants cache

When an approval resolves as **Approved**, the `ApprovalStore`
creates a cached grant so the agent's retry succeeds without
triggering a second approval prompt.

| Property | Value |
|----------|-------|
| **Key** | `(agent_name, operation, path)` -- exact match, all three fields |
| **TTL** | Configurable via `grant_ttl_secs` (default: 300 seconds) |
| **Usage** | Single-use -- consumed on the next matching permission check |

The grant requires an exact match on all three fields. A grant for
`("claude", "write", "/home/user/doc.md")` does not cover
`/home/user/other.md` or a `read` operation. Once consumed, the
grant is removed. If the agent does not retry within the TTL, the
grant expires silently.

Denied requests do not create grants. The agent receives a denial
error and must request approval again if it retries.

## Non-blocking design

The approval flow is fully non-blocking. When a tool call requires
approval:

1. The server returns an error result immediately (`"Approval
   required: '<tool>'"`) without holding the HTTP connection open.
2. A pending request is created in the `ApprovalStore` with a
   `oneshot` channel.
3. A D-Bus notification is sent in parallel (if configured).
4. The agent receives the error and can continue with other work.
5. When the human resolves the request, the grant is cached.
6. The agent retries the tool call; `check_grant()` finds and
   consumes the cached grant, and the call proceeds.

This design means the server never blocks on human input. Agents
that understand the approval protocol can retry automatically;
agents that do not simply receive an error message explaining what
happened.

## ApprovalGateHook

The `ApprovalGateHook` in `navra-safety-hooks` provides an
alternative, hook-based approval gate that runs in the pre-tool-use
pipeline. Unlike the permission-layer approval (which returns an
error result), the hook returns `HookDecision::Pending(request_id)`,
which suspends the tool call in the hook pipeline.

### Configuration

```rust
ApprovalGateConfig {
    enabled: true,
    risk_keywords: vec!["delete", "exec", "shell", "write"],
    timeout_secs: 300,
    default_on_timeout: TimeoutDefault::Deny,
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Whether the approval gate is active |
| `risk_keywords` | string[] | `["delete", "exec", "shell", "write"]` | Substring patterns matched against tool names |
| `timeout_secs` | u64 | `300` | Seconds to wait before applying the timeout default |
| `default_on_timeout` | string | `"deny"` | What happens on timeout: `deny` (fail-closed) or `allow` (fail-open) |

### How risk matching works

The hook checks whether the tool name **contains** any of the
configured `risk_keywords` as a substring. For example, with the
default keywords:

- `file_delete` matches `"delete"` -- requires approval
- `shell_exec` matches both `"shell"` and `"exec"` -- requires approval
- `file_read` matches nothing -- passes through
- `file_write` matches `"write"` -- requires approval

Low-risk tool calls (no keyword match) pass through with
`HookDecision::Continue` and are never shown to the user.

### Timeout behavior

If no human responds within `timeout_secs`, the hook's
`cleanup_expired()` method marks the request as `TimedOut` and
applies the configured default:

- **`TimeoutDefault::Deny`** (default): the tool call fails. This is
  the fail-closed posture recommended for production.
- **`TimeoutDefault::Allow`**: the tool call proceeds. Use only in
  development environments where blocking on approval is
  unacceptable.

## Headless and SSH mode

When navra runs without a desktop session (headless server, SSH,
containers), D-Bus notifications are unavailable. Configure the
notification backend to `none`:

```toml
[approval]
notify = "none"
```

This selects the `NoopNotifier`, which logs approval requests to
the tracing output instead of sending desktop notifications:

```
INFO navra: Approval required (no notifier -- use CLI: navra approve <id>)
```

In headless mode, approvals must be resolved via the CLI or the
MCP-native `file_approve`/`file_deny` tools. The system tray is
also unavailable (start the server with `--no-tray`).

## Configuration reference

### Approval section

```toml
[approval]
timeout_secs = 300       # How long to wait for a response
grant_ttl_secs = 300     # How long a cached grant remains valid
notify = "dbus"          # Notification backend: "dbus" or "none"
```

### Permission-level approval

```toml
[permissions.developer]
# Require approval for specific tools
tool_rules = [
  { tool = "file_write", policy = "approve" },
  { tool = "file_delete", policy = "approve" },
]

# Or require approval for entire operation namespaces
approve = ["write"]
```

### IFC tainted write approval

When Information Flow Control detects that an agent has read
untrusted external data, subsequent writes can require approval:

```toml
[permissions.dev]
tainted_write_policy = "approve"
trusted_paths = ["~/Code/myproject/**"]
```

### Full example

A configuration that requires approval for writes and deletes,
uses D-Bus notifications on the desktop, and times out after 5
minutes:

```toml
[server]
tcp = "127.0.0.1:9315"

[approval]
timeout_secs = 300
grant_ttl_secs = 300
notify = "dbus"

[permissions.developer]
operations = ["read", "write", "search", "list"]
allow = ["/home/user/projects/**"]
deny = ["**/.env", "**/.ssh/**"]
safety = "standard"
default_tool_policy = "allow"
tool_rules = [
  { tool = "file_write", policy = "approve" },
  { tool = "file_delete", policy = "approve" },
  { tool = "shell_*", policy = "deny" },
]

[[agents]]
name = "claude"
token_hash = "e35f..."
permissions = "developer"
```

With this configuration:

- `file_read` calls pass through (default policy is `allow`).
- `file_write` and `file_delete` calls trigger approval.
- `shell_*` calls are blocked outright.
- The user sees a D-Bus notification with Approve/Deny buttons for
  each gated call.
- If the user does not respond within 5 minutes, the request
  expires.
- After approval, the agent has 5 minutes to retry before the
  grant expires.

### Headless example

```toml
[approval]
timeout_secs = 600
grant_ttl_secs = 600
notify = "none"

[permissions.ops]
operations = ["read", "write"]
approve = ["write"]
```

Start the server with:

```bash
navra serve --no-tray --config ~/.config/navra/config.toml
```

Approve from another terminal:

```bash
navra approve <request-id>
```
