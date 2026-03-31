# mcpd — Design Document

## Overview

**mcpd** is a secure MCP (Model Context Protocol) gateway designed to
run as a user-level systemd unit on Linux desktops. It aggregates
multiple MCP servers — both built-in modules and upstream external
servers — behind a unified security layer with authentication, path
ACLs, content safety filtering, and human-in-the-loop approval.

Built-in **modules** contribute tools and prompts directly. External
**upstream** MCP servers (e.g., Myelix for cognitive personas, or
specialized tool servers) are proxied through mcpd, which applies the
same auth, permissions, and safety policies to all traffic regardless
of origin.

## Crate Structure

```
mcpd/
├── mcpd-core         MCP framework, permissions, approval, D-Bus, notify
├── mcpd-mod-docs     Document module (search, read, write, edit, delete, list, info)
└── mcpd-server       Binary: config, module loading, system tray
```

| Crate | Role |
|-------|------|
| `mcpd-core` | MCP protocol (JSON-RPC 2.0, Streamable HTTP, tools + prompts + resources), Module trait, permission engine (string-based ops, deny-wins ACLs), approval store with grants cache, D-Bus notifier, auth |
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
│                          mcpd-server (gateway)                       │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────────┐ │
│  │ System Tray │  │    Config    │  │      Module Loader          │ │
│  │   (ksni)    │  │   (TOML)    │  │ [modules.docs] → DocsModule │ │
│  │ Approve/Deny│  │             │  │                              │ │
│  └──────┬──────┘  └─────────────┘  └──────────────┬──────────────┘ │
│         │                                          │                │
│  ┌──────▼──────────────────────────────────────────▼──────────────┐ │
│  │                        mcpd-core                               │ │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐  │ │
│  │  │ JSON-RPC   │ │ MCP Proto  │ │ Streamable │ │   Auth     │  │ │
│  │  │ 2.0        │ │ 2025-03-26 │ │ HTTP(axum) │ │ (token)    │  │ │
│  │  │            │ │ tools +    │ │            │ │            │  │ │
│  │  │            │ │ prompts +  │ │            │ │            │  │ │
│  │  │            │ │ resources  │ │            │ │            │  │ │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘  │ │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐  │ │
│  │  │ Permission │ │  Approval  │ │  D-Bus     │ │  Module    │  │ │
│  │  │ Engine     │ │  Store +   │ │  Notifier  │ │  Trait     │  │ │
│  │  │ (ACLs)     │ │  Grants    │ │            │ │            │  │ │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘  │ │
│  │  ┌────────────────────────────────────────────────────────┐    │ │
│  │  │ Content Safety (regex + ML)                            │    │ │
│  │  │ Applied to ALL responses: built-in modules + upstreams │    │ │
│  │  └────────────────────────────────────────────────────────┘    │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌─ Built-in Modules ───────────────────────────────────────────┐   │
│  │  mcpd-mod-docs                                               │   │
│  │  Tools: docs_search, docs_read, docs_write, docs_edit, ...  │   │
│  │  SQLite FTS5 index                                           │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌─ Upstream MCP Servers (proxied) ─────────────────────────────┐   │
│  │                                                               │   │
│  │  ┌─────────────────────┐  ┌───────────────────────────────┐  │   │
│  │  │ Myelix MCP Server   │  │ Other MCP Servers (future)    │  │   │
│  │  │ (stdio / SSE)       │  │ (git, CI/CD, ...)             │  │   │
│  │  │                     │  │                               │  │   │
│  │  │ Prompts: personas   │  │ Tools: git_status, ...        │  │   │
│  │  │ Tools: weave_prompt │  │                               │  │   │
│  │  └─────────────────────┘  └───────────────────────────────┘  │   │
│  │                                                               │   │
│  │  mcpd aggregates tools/prompts/resources from all upstreams  │   │
│  │  and applies auth + ACLs + safety uniformly                  │   │
│  └───────────────────────────────────────────────────────────────┘   │
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
    fn prompts(&self) -> Vec<(PromptDefinition, PromptHandler)> { Vec::new() }
    fn resources(&self) -> Vec<(ResourceDefinition, ResourceHandler)> { Vec::new() }
}
```

Modules can contribute tools, prompts, resources, or any combination.
The `prompts()` and `resources()` methods have default empty
implementations so existing modules don't need changes.

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

Duplicate tool and prompt names are detected at startup (panic on
conflict). Tool names must be prefixed with the module name:
`docs_read`, `git_status`, etc.

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
4. Normal operation:
   - `tools/list`, `tools/call` — discover and invoke tools
   - `prompts/list`, `prompts/get` — discover and render prompts
   - `resources/list`, `resources/read` — discover and read resources

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

[approval]
timeout_secs = 300
notify = "dbus"  # "dbus" or "none"

# --- Upstream MCP servers ---
[[upstream]]
name = "myelix"
transport = "stdio"
command = ["poetry", "run", "python", "-m", "myelix.memory.mcp_server"]
cwd = "/home/user/myelix"

# --- Agents ---
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

## Gateway Architecture

### Design Rationale

mcpd is evolving from a standalone MCP server to an **MCP gateway**
that aggregates upstream MCP servers. The motivation:

- **Domain separation**: Each upstream server owns its domain logic
  (cognitive core, git operations, CI/CD). mcpd stays domain-agnostic.
- **Unified security**: Auth, ACLs, content safety, and approval
  workflows apply uniformly to all traffic, whether it comes from a
  built-in module or an upstream server.
- **Model agnosticism**: Upstream servers expose prompts and tools via
  MCP. Any client that speaks MCP can consume them, regardless of the
  underlying model.

### Two Sources of Capabilities

```
┌─ Built-in ────────────────────────┐
│ Modules compiled into mcpd-server │
│ DocsModule: docs_read, docs_write │
│ (future: GitModule, etc.)         │
└───────────────────────────────────┘

┌─ Upstream ─────────────────────────────────────────┐
│ External MCP servers proxied through mcpd           │
│ Myelix: persona prompts + weave_prompt tool         │
│ (future: git server, CI/CD server, etc.)            │
│                                                     │
│ Transports: stdio (subprocess), SSE, streamable-http│
└─────────────────────────────────────────────────────┘
```

Both sources are presented to agents as a single unified MCP server.
Agents see one flat list of tools, one flat list of prompts — they
don't know which are built-in and which are proxied.

### Upstream Transports

mcpd connects to upstream servers using a pluggable `Transport` trait:

```rust
#[async_trait]
pub trait Transport: Send + 'static {
    async fn request(&mut self, body: Value) -> Result<Value, UpstreamError>;
    fn shutdown(&mut self);
}
```

Three implementations:

| Transport | Config field | Wire protocol |
|-----------|-------------|---------------|
| **stdio** | `command`, `cwd` | Subprocess, line-delimited JSON-RPC over stdin/stdout |
| **http** | `url` | POST JSON-RPC to HTTP endpoint (MCP streamable-http) |
| **sse** | `url` | SSE endpoint discovery → POST JSON-RPC to discovered URL |

`Upstream` is transport-agnostic — it handles MCP semantics
(initialize, discover, proxy) while the transport handles the wire
protocol.

### Upstream Configuration

```toml
# Subprocess (stdio) — most common for local servers
[[upstream]]
name = "myelix"
transport = "stdio"
command = ["poetry", "run", "python", "-m", "myelix.memory.mcp_server"]
cwd = "/home/user/myelix"

# HTTP (streamable-http) — for HTTP-based servers
[[upstream]]
name = "api-server"
transport = "http"
url = "http://localhost:8001/mcp"

# SSE — for Server-Sent Events servers
[[upstream]]
name = "sse-server"
transport = "sse"
url = "http://localhost:8002/sse"

# Disabled upstream
[[upstream]]
name = "disabled"
command = ["echo"]
enabled = false
```

### Upstream Lifecycle

1. **Startup**: mcpd connects to each upstream via its configured
   transport, calls `initialize`, then `tools/list`, `prompts/list`,
   and `resources/list` to discover capabilities.
2. **Registration**: Upstream capabilities are wrapped in an
   `UpstreamModule` that implements the `Module` trait. The server
   builder registers it like any built-in module — same conflict
   detection, same dispatch.
3. **Runtime**: When an agent calls a proxied tool/prompt/resource,
   mcpd forwards the request through the `Transport` to the upstream,
   applies safety filters to the response, and returns it to the agent.
4. **Auth + ACLs**: mcpd's own auth and permission checks apply before
   forwarding. The upstream server does not need auth — mcpd is the
   trust boundary.
5. **Error handling**: Spawn/connection failures are logged and the
   upstream is skipped (mcpd starts without it). Runtime errors from
   upstreams are returned as tool/prompt errors to the agent.

### Security Boundary

```
Agent → mcpd (auth, ACLs, safety) → Upstream server
         ▲                            ▲
         │                            │
    Trust boundary              Trusted (local)
    (agent identity,            (no auth needed,
     path checks,               mcpd controls
     content filtering)         access)
```

The upstream server runs locally and trusts mcpd as its sole client.
mcpd handles all agent-facing security concerns.

### Example: Myelix Integration

Myelix's MCP server exposes:
- **Prompts**: `persona:software_developer`, `persona:researcher`, etc.
  — discoverable via `prompts/list`, raw definitions via `prompts/get`
- **Tools**: `weave_prompt` — assembles a fully customized system prompt
  from cognitive core components (persona + heuristics + directives)

Through mcpd, an agent can:
1. `prompts/list` → sees both docs module tools and Myelix personas
2. `prompts/get("persona:software_developer")` → proxied to Myelix
3. `tools/call weave_prompt(...)` → proxied to Myelix, safety-filtered

## Future Work

### Modules
- **Runtime-loadable modules** — Load modules from shared libraries
  or WASI components at startup, enabling distribution without
  recompiling mcpd
- **mcpd-mod-git** — Git module (`git_status`, `git_diff`, `git_log`,
  `git_commit`, `git_branch`) with approval for push/commit

### Safety
- **ML safety tier** — ONNX Runtime (`ort` crate, optional feature)
  for contextual PII/sensitivity detection. Auto-detect NPU > GPU > CPU.
  Ship with a tiny token classifier (~5-15MB ONNX model).
- **Custom safety rules** — User-defined regex patterns in config

### Search & Indexing
- **Vector search** — sqlite-vec for semantic similarity
- **File watcher** — `notify` crate for live re-indexing
- **Content extraction** — PDF, HTML, CSV pipeline

### Platform
- **Gnome Keyring** — Token storage via `org.freedesktop.secrets`
