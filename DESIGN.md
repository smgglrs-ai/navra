# mcpd — Design Document

## Overview

**mcpd** is a composable, secure MCP (Model Context Protocol) server
designed to run as a user-level systemd unit on Linux desktops. It
exposes user documents and local resources to AI agents through a rich
permission model with human-in-the-loop approval.

The architecture is modular: feature **modules** plug into a shared
framework. Each module contributes MCP tools. The permission engine,
approval workflow, and transport are shared across all modules.

## Crate Structure

```
mcpd/
├── mcpd-core         MCP framework, permissions, approval, D-Bus, notify
├── mcpd-mod-docs     Document module (search, read, write, edit, delete, list, info)
└── mcpd-server       Binary: config, module loading, system tray
```

| Crate | Role |
|-------|------|
| `mcpd-core` | MCP protocol (JSON-RPC 2.0, Streamable HTTP), Module trait, permission engine (string-based ops, deny-wins ACLs), approval store with grants cache, D-Bus notifier, auth |
| `mcpd-mod-docs` | Document tools, SQLite FTS5 index, file I/O with path security |
| `mcpd-server` | Binary that loads modules from config, system tray (ksni), CLI |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          AI Agent (Claude, etc.)                     │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ MCP Streamable HTTP
                             │ (Unix socket or TCP)
┌────────────────────────────▼─────────────────────────────────────────┐
│                          mcpd-server                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────────┐ │
│  │ System Tray │  │    Config    │  │      Module Loader          │ │
│  │   (ksni)    │  │   (TOML)    │  │ [modules.docs] → DocsModule │ │
│  │ Approve/Deny│  │             │  │ [modules.git]  → (future)   │ │
│  └──────┬──────┘  └─────────────┘  └──────────────┬──────────────┘ │
│         │                                          │                │
│  ┌──────▼──────────────────────────────────────────▼──────────────┐ │
│  │                        mcpd-core                               │ │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐  │ │
│  │  │ JSON-RPC   │ │ MCP Proto  │ │ Streamable │ │   Auth     │  │ │
│  │  │ 2.0        │ │ 2025-03-26 │ │ HTTP(axum) │ │ (token)    │  │ │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘  │ │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐  │ │
│  │  │ Permission │ │  Approval  │ │  D-Bus     │ │  Module    │  │ │
│  │  │ Engine     │ │  Store +   │ │  Notifier  │ │  Trait     │  │ │
│  │  │ (ACLs)     │ │  Grants    │ │            │ │            │  │ │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                     mcpd-mod-docs                              │ │
│  │  ┌──────────────────────────────────────────────────────────┐  │ │
│  │  │ Tools: docs_search, docs_read, docs_write, docs_edit,   │  │ │
│  │  │        docs_delete, docs_list, docs_info,                │  │ │
│  │  │        docs_approve, docs_deny                           │  │ │
│  │  └──────────────────────┬───────────────────────────────────┘  │ │
│  │                         │                                      │ │
│  │  ┌──────────────────────▼───────────────────────────────────┐  │ │
│  │  │              SQLite Index (FTS5)                          │  │ │
│  │  └──────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘

         ┌──────────────────────────────────────────┐
         │         Desktop Integration              │
         │  ┌────────────────────────────────────┐  │
         │  │  D-Bus Notifications               │  │
         │  │  (org.freedesktop.Notifications)   │  │
         │  │  Approve/Deny action buttons       │  │
         │  └────────────────────────────────────┘  │
         │  ┌────────────────────────────────────┐  │
         │  │  System Tray (StatusNotifierItem)  │  │
         │  │  KDE, Gnome, XFCE, Sway, etc.     │  │
         │  │  Pending approvals, agents, pause  │  │
         │  └────────────────────────────────────┘  │
         └──────────────────────────────────────────┘
```

## Module System

### Module Trait

Modules are the unit of composition. Each module is a Rust crate
implementing the `Module` trait:

```rust
pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)>;
}
```

### Registration

Compile-time composition — modules are wired in `main.rs`:

```rust
McpServer::builder()
    .name("mcpd")
    .module(DocsModule::new(perm_engine, index, approvals, notifier))
    // .module(GitModule::new(...))  // future
    .authenticator(token_auth)
    .build()
```

Duplicate tool names are detected at startup (panic on conflict).
Tool names must be prefixed with the module name: `docs_read`,
`git_status`, etc.

### Config-driven

Modules are enabled/disabled in config:

```toml
[modules.docs]
enabled = true
db = "$XDG_DATA_HOME/mcpd/index.db"

# [modules.git]
# enabled = true
```

### Adding a Module

1. Create crate implementing `Module` → provides `(ToolDefinition, ToolHandler)` pairs
2. Add dependency in `mcpd-server/Cargo.toml`
3. Add config struct in `config.rs`
4. Add `if cfg.xxx_enabled() { builder = builder.module(xxx); }` in `main.rs`

## MCP Protocol

### JSON-RPC 2.0 Layer

- `Request` — method + params + id
- `Response` — result or error + id
- `Notification` — method + params (no id)
- Standard error codes (-32700, -32600, -32601, -32602, -32603)

### MCP Lifecycle (2025-03-26 spec)

1. Client sends `initialize` with capabilities and `clientInfo`
2. Server responds with `serverInfo` and capabilities
3. Client sends `notifications/initialized`
4. Normal operation: `tools/list`, `tools/call`

### Streamable HTTP Transport

Single HTTP endpoint (`POST /mcp`):

- **Request-Response**: Client POSTs JSON-RPC, server responds with
  `application/json`.
- **Streaming**: Server may respond with `text/event-stream` (SSE).
- **Session management**: `Mcp-Session-Id` header.

Transport binding:

- **Unix domain socket** (default): `$XDG_RUNTIME_DIR/mcpd/mcpd.sock`
- **TCP** (optional): `127.0.0.1:9315` for development

### Auth

Pluggable via `Authenticator` trait. Token-based implementation included:

```rust
pub trait Authenticator: Send + Sync + 'static {
    fn authenticate(&self, headers: &HeaderMap) -> Result<AgentIdentity, AuthError>;
}
```

`AgentIdentity` carries the agent's name and permission set name,
threaded through `CallContext` to all tool handlers.

## Permission Model

Four dimensions, evaluated in order:

### 1. Agent Identity

Token-based. Agents registered in config with a permission set:

```toml
[[agents]]
name = "claude-code"
token_hash = "$blake3$..."
permissions = "developer"
```

### 2. Path ACLs (deny-wins)

Glob patterns controlling path access per permission set:

```toml
[permissions.developer]
allow = ["~/Documents/**", "~/Code/**"]
deny = ["**/.env", "**/*secret*", "**/credentials*"]
```

- Deny rules checked first (deny-wins)
- Paths canonicalized before matching (prevents traversal)
- Symlinks resolved and re-checked
- `dir/**` also matches `dir` itself (for listing)

### 3. Operation Permissions (string-based, namespaced)

Operations are strings, enabling module namespacing:

```toml
operations = ["read", "write", "search", "list", "git.status", "git.diff"]
```

Modules define their own operations without modifying a central enum.

### 4. Human-in-the-Loop Approval

Operations can require explicit user approval:

```toml
approve = ["write", "git.commit"]
```

## Approval System

### Dual-Channel, Non-Blocking

When a tool requires approval, the server returns immediately with an
approval-needed response (not blocking the HTTP connection) and sends
a D-Bus notification in parallel. Three resolution channels:

```
Agent: docs_write(path, content)
Server: "Approval required. Request ID: abc-123.
         Call docs_approve with this request_id to approve."
        (+ D-Bus notification with Approve/Deny buttons)
        (+ tray icon shows pending approval)

Resolution via ANY channel:
  1. Agent calls docs_approve(request_id=abc-123)     ← MCP-native
  2. User clicks D-Bus notification "Approve" button  ← Desktop
  3. User clicks tray menu Approve                    ← Tray icon
  4. CLI: mcpd approve abc-123                        ← Terminal

Server: "Approved"

Agent: docs_write(path, content)  # retry
Server: "Written 42 bytes to /path"  # grant consumed
```

### Grants Cache

When an approval is resolved as `Approved`, a grant is cached:

- Key: `(agent_name, operation, path)`
- TTL: 5 minutes
- Single-use: consumed on the next matching `check_perm` call

This allows the agent to retry the operation after approval without
needing another approval cycle.

### ApprovalStore

```rust
pub struct ApprovalStore {
    pending: HashMap<String, PendingRequest>,  // request_id → oneshot channel
    grants: Vec<Grant>,                        // cached approvals for retry
    timeout: Duration,                         // approval expiry
    grant_ttl: Duration,                       // grant expiry (5 min)
}
```

- `request()` → creates pending entry, returns `(ApprovalRequest, Receiver)`
- `approve(id)` / `deny(id)` → resolves channel + caches grant (if approved)
- `check_grant(agent, op, path)` → consumes matching grant
- `wait(rx)` → async wait with timeout (for blocking mode if needed)

### Notifier Trait

```rust
pub trait Notifier: Send + Sync + 'static {
    fn notify(&self, request: &ApprovalRequest, store: Arc<ApprovalStore>)
        -> BoxFuture<'_, Result<(), NotifyError>>;
    fn dismiss(&self, request_id: &str)
        -> BoxFuture<'_, Result<(), NotifyError>>;
}
```

Implementations:
- `DbusNotifier` — sends `org.freedesktop.Notifications` with action buttons,
  listens for `ActionInvoked` / `NotificationClosed` signals via zbus
- `NoopNotifier` — logs to tracing (headless/SSH fallback)

## MCP Tools (docs module)

| Tool | Permission | Description |
|------|-----------|-------------|
| `docs_search` | search | Full-text search via FTS5 |
| `docs_read` | read | Read file with optional offset/limit (line-based partial reads) |
| `docs_write` | write | Create or overwrite file, auto-indexes |
| `docs_edit` | write | Surgical string replacement (old_string → new_string, must be unique) |
| `docs_delete` | write | Delete file, removes from index |
| `docs_list` | list | List directory (filters entries by path ACL) |
| `docs_info` | read | File metadata (size, lines, mime, modified, indexed) without content |
| `docs_approve` | — | Approve a pending request by ID |
| `docs_deny` | — | Deny a pending request by ID |

### Path Security

All path-accepting tools pass through `resolve_path()`:

1. Expand `~` to home directory
2. Reject relative paths
3. Canonicalize (resolves symlinks, eliminates `..`)
4. For reads: path must exist
5. For writes: parent directory must exist

Then `check_perm()`:

1. Check grants cache (from previous approval)
2. Check operation permission (string match)
3. Check deny rules (glob, deny-wins)
4. Check allow rules (glob)
5. If `requires_approval`: create request + notify, return approval-needed

### Document Indexing (SQLite FTS5)

Single database at `$XDG_DATA_HOME/mcpd/index.db`:

```sql
CREATE TABLE documents (
    id          INTEGER PRIMARY KEY,
    path        TEXT UNIQUE NOT NULL,
    title       TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL DEFAULT '',
    mime_type   TEXT NOT NULL,
    size        INTEGER NOT NULL,
    modified_at TEXT NOT NULL,
    indexed_at  TEXT NOT NULL,
    checksum    TEXT NOT NULL
);

CREATE VIRTUAL TABLE documents_fts USING fts5(
    path, title, content,
    content=documents,
    content_rowid=id,
    tokenize='porter unicode61'
);
```

Thread-safe via `Mutex<Connection>` with WAL mode enabled.
Auto-indexed on `docs_write` and `docs_edit`.

## System Tray (ksni)

StatusNotifierItem (SNI) via the `ksni` crate. Works with:
KDE, Gnome (AppIndicator extension), XFCE, Cinnamon, Sway/Waybar, MATE.

### Icon States

| State | Meaning |
|-------|---------|
| Active | Running, no pending approvals |
| NeedsAttention | Pending approval(s) — user action needed |
| Passive | Server paused |

### Menu

```
┌─────────────────────────────────────────┐
│  Pending Approvals (N)                  │
│    claude-code wants to write ~/doc.md  │
│      ├ Approve                          │
│      └ Deny                             │
├─────────────────────────────────────────┤
│  Connected Agents                       │
│    claude-code (developer)              │
│    reader-bot (readonly)                │
├─────────────────────────────────────────┤
│  Pause / Resume                         │
│  Quit                                   │
└─────────────────────────────────────────┘
```

### Wiring

- `TrayCommand` channel: menu actions → server event loop
- Background updater polls `ApprovalStore` every 1s
- `--no-tray` flag for headless/systemd operation

## Content Safety

Two-tier filter pipeline applied to all outbound tool responses,
between the tool handler and the MCP transport. Modules are unaware
of filtering — it's a framework-level concern.

```
Tool handler response
        │
        ▼
┌─── Fast Tier (regex) ──────────┐
│ API keys, private keys, tokens │  ~microseconds
│ SSNs, credit cards, phone, PII │  deterministic
└────────────┬───────────────────┘
             │
             ▼
┌─── ML Tier (ONNX, future) ────┐
│ Contextual PII, sensitivity    │  ~1-10ms
│ "medical records", "salaries"  │  confidence-scored
└────────────┬───────────────────┘
             │
             ▼
  FilterAction: Pass / Redact / Block
```

### ContentFilter Trait

```rust
pub trait ContentFilter: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn scan(&self, content: &str, ctx: &FilterContext) -> Vec<Finding>;
}

pub struct Finding {
    pub start: usize,       // byte offset
    pub end: usize,
    pub category: String,   // "aws-key", "ssn", "credit-card"
    pub confidence: f32,    // 1.0 for regex, model score for ML
}
```

### Regex Detectors (implemented)

**SecretFilter** (11 patterns):

| Category | Pattern |
|----------|---------|
| `aws-key` | `AKIA[0-9A-Z]{16}` |
| `aws-secret` | `aws_secret_access_key=...` |
| `github-token` | `ghp_...`, `github_pat_...` |
| `gitlab-token` | `glpat-...` |
| `api-key` | `sk-...` (OpenAI/Anthropic) |
| `bearer-token` | `bearer=...`, `authorization=...` |
| `private-key` | `-----BEGIN...PRIVATE KEY-----` |
| `password` | `password=...`, `passwd:...` |
| `connection-string` | `postgres://user:pass@host` |
| `slack-webhook` | `hooks.slack.com/services/...` |

**PiiFilter** (4 patterns with validators):

| Category | Pattern | Validation |
|----------|---------|------------|
| `ssn` | `\d{3}-\d{2}-\d{4}` | SSA rules (no 000/666/9xx) |
| `credit-card` | 13-19 digit sequences | Luhn algorithm |
| `phone` | US formats with optional +1 | — |
| `email` | Standard email pattern | — |

### ML Tier (future, ONNX Runtime)

For contextual detection that regex can't catch ("John Smith's
medical records show...", "the salary for this position is..."):

- ONNX Runtime (`ort` crate) as optional feature (`safety-model`)
- Auto-detects best execution provider: NPU > GPU > CPU
- Small model (~5-50MB): token classifier for PII/sensitivity
- Runs after regex tier, additive findings

| Hardware | ONNX Execution Provider |
|----------|------------------------|
| CPU | Default (always available) |
| GPU (NVIDIA) | CUDA / TensorRT |
| GPU (AMD) | ROCm |
| NPU (Intel) | OpenVINO (Core Ultra) |
| NPU (Qualcomm) | QNN (Snapdragon X) |

### Redaction

Sensitive spans replaced with category markers:

```
Original:  export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
Redacted:  export AWS_ACCESS_KEY_ID=[REDACTED:aws-key]

Original:  SSN: 123-45-6789
Redacted:  SSN: [REDACTED:ssn]
```

Overlapping findings are merged (longest span wins).

### Safety Profiles

Configured per permission set:

```toml
[permissions.developer]
safety = "standard"     # all regex filters, redact

[permissions.deployer]
safety = "secrets-only" # only secrets, allow PII

[permissions.admin]
safety = "none"         # no filtering (full trust)
```

Profiles: `"standard"` (default), `"secrets-only"`, `"block"`, `"none"`.

### Where Filtering Happens

Applied in `McpServer::handle_call_tool()` — after the tool handler
returns, before the response enters the transport. The pipeline maps
permission set names to `FilterPipeline` instances, set up at server
startup via `builder.safety_profile(name, pipeline)`.

## Security Model

### Defense in Depth

1. **Unix socket** — No network exposure. Filesystem permissions (0600).
2. **Token authentication** — Bearer tokens, BLAKE3-hashed in config.
3. **Path canonicalization** — Symlinks resolved, `..` eliminated.
4. **Deny-first ACLs** — Deny rules always win. Default-deny.
5. **Operation restrictions** — String-based, module-namespaced.
6. **Approval workflow** — Three-channel human-in-the-loop.
7. **Content safety** — Regex + ML filters redact/block sensitive data.
8. **Systemd hardening** — `NoNewPrivileges`, `ProtectHome=read-only`,
   `ProtectSystem=strict`, `MemoryDenyWriteExecute`, etc.

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Agent reads private files | Path ACLs (deny-wins) |
| Agent writes to unauthorized paths | Operation perms + approval |
| Path traversal (`../../etc/passwd`) | Canonicalization before ACL check |
| Token theft | Hashed storage, Unix socket |
| Agent bypasses approval | Non-blocking return, grant is single-use |
| Agent exfiltrates secrets in file content | Content safety filters (redact/block) |
| Agent exfiltrates PII | PII detector with Luhn/SSA validation |
| Prompt injection via documents | Out of scope (agent responsibility) |
| Denial of service | Systemd resource limits |

## Configuration

Default path: `~/.config/mcpd/config.toml`

```toml
[server]
# socket = "$XDG_RUNTIME_DIR/mcpd/mcpd.sock"
tcp = "127.0.0.1:9315"  # development default

[modules.docs]
enabled = true
# db = "$XDG_DATA_HOME/mcpd/index.db"

# [modules.git]
# enabled = true

[approval]
timeout_secs = 300
notify = "dbus"  # "dbus" or "none"

[[agents]]
name = "claude-code"
token_hash = "$blake3$..."
permissions = "developer"

[permissions.developer]
allow = ["~/Documents/**", "~/Notes/**", "~/Code/**"]
deny = ["**/.env", "**/*secret*", "**/credentials*"]
operations = ["read", "write", "search", "list"]
approve = ["write"]
safety = "standard"      # redact secrets + PII in responses

[permissions.readonly]
allow = ["~/Documents/shared/**"]
deny = []
operations = ["read", "search", "list"]
approve = []
safety = "standard"

# [permissions.admin]
# safety = "none"        # full trust, no filtering
```

## Systemd Integration

User unit at `~/.config/systemd/user/mcpd.service`:

```ini
[Unit]
Description=mcpd — Composable MCP Server
Documentation=https://github.com/user/mcpd
After=default.target

[Service]
Type=notify
ExecStart=%h/.cargo/bin/mcpd serve
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/mcpd
RuntimeDirectory=mcpd
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native

[Install]
WantedBy=default.target
```

## CLI

```
mcpd serve [--config path] [--no-tray]   Start the server
mcpd token generate --name N --perms P   Generate agent token
mcpd token list                          List registered agents
mcpd approve <request-id>                Approve a pending request
mcpd deny <request-id>                   Deny a pending request
mcpd status                              Show server status
```

## Future Work

- **ML safety tier** — ONNX Runtime (`ort` crate, optional feature)
  for contextual PII/sensitivity detection. Auto-detect NPU > GPU > CPU.
  Ship with a tiny token classifier (~5-15MB ONNX model).
- **mcpd-mod-git** — Git module (`git_status`, `git_diff`, `git_log`,
  `git_commit`, `git_branch`) with approval for push/commit
- **Vector search** — sqlite-vec for semantic similarity
- **File watcher** — `notify` crate for live re-indexing
- **Content extraction** — PDF, HTML, CSV pipeline
- **WASM modules** — WASI P2 component model for third-party plugins
- **Gnome Keyring** — Token storage via `org.freedesktop.secrets`
- **Custom safety rules** — User-defined regex patterns in config
