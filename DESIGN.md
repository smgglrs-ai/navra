# smgglrs — Design Document

## Overview

**smgglrs** is a secure MCP (Model Context Protocol) gateway designed to
run as a user-level systemd unit on Linux desktops. It aggregates
multiple MCP servers — both built-in modules and upstream external
servers — behind a unified security layer with authentication, path
ACLs, per-tool permission rules, content safety filtering (built-in
and custom regex), human-in-the-loop approval, and a hook/middleware
system.

Built-in **modules** contribute tools and prompts directly. External
**upstream** MCP servers (e.g., Myelix for cognitive personas, or
specialized tool servers) are proxied through smgglrs, which applies the
same auth, permissions, and safety policies to all traffic regardless
of origin.

## Crate Structure

See CLAUDE.md for the full 14-crate workspace table. Summary:

```
smgglrs/
├── smgglrs-protocol       MCP/A2A/JSON-RPC types, upstream transports
├── smgglrs-model          Model backend trait + ONNX/OpenAI/Anthropic impls
├── smgglrs-model-hub      Pull/cache models (OCI, HuggingFace, Ollama)
├── smgglrs-model-runtime  Serve models (Podman, direct, libkrun)
├── smgglrs-security       Auth, permissions, IFC, trusted paths, safety, hooks
├── smgglrs-agent          Client SDK: agent builder, MCP client, tool-use loop
├── smgglrs-flow           Declarative multi-agent flows with handoff routing
├── smgglrs-core           Server, module trait, session, transport
├── smgglrs-tools-docs     Document tools (FTS5, file I/O)
├── smgglrs-tools-git      Git tools (status, diff, log, branch, commit)
├── smgglrs-rag            Vector search, sqlite-vec, semantic chunking
├── smgglrs-modal-voice    Speech I/O (ASR + TTS via ONNX)
├── smgglrs-modal-vision   Image/screen understanding (GPU tier)
└── smgglrs-server         Binary: CLI, config, module wiring (smgglrs)
```

| Crate | Role |
|-------|------|
| `smgglrs-protocol` | MCP/A2A/JSON-RPC types, upstream client with stdio/HTTP/SSE + resilient transports |
| `smgglrs-model` | Model backend trait with ONNX (in-process), OpenAI-compatible, and Anthropic (direct + Vertex AI) implementations |
| `smgglrs-model-hub` | Pull and cache models from OCI, HuggingFace, and Ollama registries with content-addressed storage |
| `smgglrs-model-runtime` | Serve models with pluggable isolation: direct (llama-server), Podman (rootless container), libkrun (microVM) |
| `smgglrs-security` | BLAKE3 token auth, capability tokens (CBOR+Ed25519), DID:key identity, path ACLs, per-tool rules, IFC with trusted paths, safety filters, hook pipeline, approval store, D-Bus notifier, process table, rate limiting |
| `smgglrs-agent` | Client SDK for building agents: Agent builder, McpClient (IFC taint tracking), ReAct tool-use loop |
| `smgglrs-flow` | Declarative multi-agent flow engine: directed graph of agents, handoff-based routing, TOML config |
| `smgglrs-core` | MCP server (JSON-RPC 2.0, Streamable HTTP + SSE), Module trait, session store, IFC value store |
| `smgglrs-tools-docs` | Document tools, SQLite FTS5 index, file I/O with path security |
| `smgglrs-tools-git` | Git tools (`git_status`, `git_diff`, `git_log`, `git_branch`, `git_commit`) |
| `smgglrs-rag` | Vector search with sqlite-vec, semantic chunking for context enrichment |
| `smgglrs-modal-voice` | Speech I/O: ASR (Whisper) + TTS via ONNX models |
| `smgglrs-modal-vision` | Image/screen understanding (GPU tier) |
| `smgglrs-server` | Binary: CLI, config, module wiring, model hub/runtime integration, systemd, system tray |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          AI Agent (Claude, etc.)                     │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ MCP Streamable HTTP + SSE
                             │ (Unix socket or TCP)
┌────────────────────────────▼─────────────────────────────────────────┐
│                         smgglrs-server (gateway)                      │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────────┐  │
│  │ System Tray │  │    Config    │  │      Module Loader          │  │
│  │   (ksni)    │  │    (TOML)    │  │ DocsModule, GitModule       │  │
│  │ Approve/Deny│  │              │  │ + upstream MCP servers      │  │
│  │ Pause/Resume│  │              │  │                             │  │
│  └──────┬──────┘  └──────────────┘  └──────────────┬──────────────┘  │
│         │                                          │                 │
│  ┌──────▼──────────────────────────────────────────▼──────────────┐  │
│  │                       smgglrs-core                              │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐   │  │
│  │  │ JSON-RPC   │ │ MCP Proto  │ │ Streamable │ │   Auth     │   │  │
│  │  │ 2.0        │ │ 2025-03-26 │ │ HTTP + SSE │ │ (BLAKE3)   │   │  │
│  │  │            │ │ tools +    │ │ (axum)     │ │            │   │  │
│  │  │            │ │ prompts +  │ │            │ │            │   │  │
│  │  │            │ │ resources  │ │            │ │            │   │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘   │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐   │  │
│  │  │ Permission │ │  Approval  │ │  D-Bus     │ │  Module    │   │  │
│  │  │ Engine     │ │  Store +   │ │  Notifier  │ │  Trait     │   │  │
│  │  │ (ACLs +    │ │  Grants    │ │            │ │            │   │  │
│  │  │ tool rules)│ │            │ │            │ │            │   │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘   │  │
│  │  ┌────────────────────────────┐ ┌────────────────────────────┐ │  │
│  │  │ Hook Pipeline              │ │ Content Safety             │ │  │
│  │  │ Pre/post tool-call hooks   │ │ (regex + custom + ML)      │ │  │
│  │  │ SafetyHook (built-in)      │ │ Applied via hook pipeline  │ │  │
│  │  └────────────────────────────┘ └────────────────────────────┘ │  │
│  │  ┌────────────────────────────────────────────────────────┐    │  │
│  │  │ Resilient Transports (upstream)                        │    │  │
│  │  │ Exponential backoff, timeout, reconnection, sleep      │    │  │
│  │  │ detection. TransportFactory for subprocess respawn.    │    │  │
│  │  └────────────────────────────────────────────────────────┘    │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌─ Built-in Modules ─────────────────────────────────────────────┐  │
│  │  smgglrs-tools-docs: docs_search, docs_read, docs_write, ...    │  │
│  │  smgglrs-tools-git:  git_status, git_diff, git_log, git_branch  │  │
│  │                 git_commit (approval required)                 │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌─ Upstream MCP Servers (proxied) ───────────────────────────────┐  │
│  │  Myelix, other MCP servers — stdio / HTTP / SSE                │  │
│  │  Discovered at startup, registered as Module, safety-filtered  │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘

         ┌──────────────────────────────────────────┐
         │         Desktop Integration              │
         │  D-Bus Notifications (Approve/Deny)      │
         │  System Tray (Pause/Resume, agents)      │
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

### Registration

Compile-time composition — modules are wired in `main.rs`:

```rust
McpServer::builder()
    .name("smgglrs")
    .module(DocsModule::new(perm_engine, index, approvals, notifier))
    .module(GitModule::new(perm_engine, approvals, notifier))
    .authenticator(token_auth)
    .safety_profile("developer", build_pipeline("standard"))
    .hook(SafetyHook::single("developer", pipeline))
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
db = "$XDG_DATA_HOME/smgglrs/index.db"

[modules.git]
enabled = true
```

### Adding a Module

1. Create crate implementing `Module` → provides `(ToolDefinition, ToolHandler)` pairs
2. Add dependency in `smgglrs-server/Cargo.toml`
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
2. Server responds with `serverInfo`, capabilities, and
   `mcp-session-id` header
3. Client sends `notifications/initialized`
4. Normal operation:
   - `tools/list`, `tools/call` — discover and invoke tools
   - `prompts/list`, `prompts/get` — discover and render prompts
   - `resources/list`, `resources/read` — discover and read resources
5. Client may open `GET /mcp` with session ID for SSE notifications

### Streamable HTTP Transport

Dual endpoint:

- **`POST /mcp`**: Client sends JSON-RPC request, server responds with
  `application/json`. Session tracked via `mcp-session-id` header.
- **`GET /mcp`**: SSE stream for server-initiated notifications.
  Requires `mcp-session-id` header from a prior `initialize`.

### SSE Streaming

Per-session broadcast channels (`SseBroadcaster`). The server pushes
JSON-RPC notifications as SSE `message` events:

- `notifications/tools/list_changed` — tool registry changed
- Custom notifications from hooks or approval resolution

Lagged clients log a warning and continue (no disconnect). Keep-alive
prevents connection timeouts.

### Session Management

Sessions are created on `initialize` and tracked via UUID:

1. `handle_initialize()` creates a `Session` in `SessionStore`,
   returns `(InitializeResult, session_id)`
2. Transport layer sets `mcp-session-id` response header
3. Subsequent requests extract session ID from request header
4. `CallContext` carries the real session ID to tool handlers

### Transport Bindings

- **Unix domain socket** (default): `$XDG_RUNTIME_DIR/smgglrs/smgglrs.sock`
  with 0600 permissions. Parent directories created automatically.
- **TCP** (optional): `127.0.0.1:9315` for development
- Both can be active simultaneously.

### Auth

Pluggable via `Authenticator` trait. BLAKE3 token-based implementation:

```rust
pub trait Authenticator: Send + Sync + 'static {
    fn authenticate(&self, headers: &HeaderMap) -> Result<AgentIdentity, AuthError>;
}
```

`TokenAuthenticator` uses BLAKE3 cryptographic hashing for bearer
tokens. Tokens are hashed on registration; incoming tokens are hashed
and compared against stored hashes. Supports `register()` (raw token)
and `register_hash()` (pre-computed hash from config).

`AgentIdentity` carries the agent's name and permission set name,
threaded through `CallContext` to all tool handlers.

## Permission Model

Five dimensions, evaluated in order:

### 1. Agent Identity

Token-based. Agents registered in config with a permission set:

```toml
[[agents]]
name = "claude-code"
token_hash = "20a8c34a..."  # BLAKE3 hex hash
permissions = "developer"
```

Generate tokens via CLI: `smgglrs token generate --name N --perms P`

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

### 4. Per-Tool Permission Rules

Glob-based rules applied per tool name, evaluated before the handler:

```toml
[[permissions.developer.tool_rules]]
tool = "git_push"
policy = "deny"

[[permissions.developer.tool_rules]]
tool = "git_commit"
policy = "approve"

[[permissions.developer.tool_rules]]
tool = "docs_*"
policy = "allow"
```

Priority: deny wins > allow > approve > default policy.
Default policy is configurable: `default_tool_policy = "allow"`.

### 5. Human-in-the-Loop Approval

Operations can require explicit user approval:

```toml
approve = ["write", "git.commit"]
```

## Hook / Middleware System

Extensible pre/post tool-call hooks. Hooks intercept tool calls and
can modify arguments, modify results, or block execution.

### Hook Trait

```rust
#[async_trait]
pub trait Hook: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn pre_tool_use(&self, tool_name, arguments, ctx) -> HookDecision;
    async fn post_tool_use(&self, tool_name, arguments, result, ctx) -> HookDecision;
}

pub enum HookDecision {
    Continue,
    ModifyArgs(Value),
    ModifyResult(CallToolResult),
    Block(String),
}
```

### HookPipeline

- Pre-hooks run in registration order; post-hooks in reverse
- Each hook wrapped in `tokio::time::timeout` (configurable, default 10s)
- Block short-circuits the pre-pipeline
- Timeout logs a warning and continues

### SafetyHook

Content safety filtering is implemented as a built-in post-hook
(`SafetyHook`). It wraps the `FilterPipeline` and applies it to tool
results. This replaces the previous hardcoded safety filter in
`handle_call_tool()`. Legacy `safety_profile()` builder API still works
when no hooks are configured.

### Builder API

```rust
McpServer::builder()
    .hook(SafetyHook::single("dev", pipeline))
    .hook(custom_audit_hook)
    .hook_timeout(Duration::from_secs(5))
    .build()
```

## Approval System

### Dual-Channel, Non-Blocking

When a tool requires approval, the server returns immediately with an
approval-needed response (not blocking the HTTP connection) and sends
a D-Bus notification in parallel. Four resolution channels:

```
Agent: docs_write(path, content)
Server: "Approval required. Request ID: abc-123."
        (+ D-Bus notification with Approve/Deny buttons)
        (+ tray icon shows pending approval)

Resolution via ANY channel:
  1. Agent calls docs_approve(request_id=abc-123)     ← MCP-native
  2. User clicks D-Bus notification "Approve" button  ← Desktop
  3. User clicks tray menu Approve                    ← Tray icon
  4. CLI: smgglrs approve abc-123                        ← Terminal

Agent: docs_write(path, content)  # retry
Server: "Written 42 bytes to /path"  # grant consumed
```

### Grants Cache

When an approval is resolved as `Approved`, a grant is cached:

- Key: `(agent_name, operation, path)`
- TTL: 5 minutes
- Single-use: consumed on the next matching `check_perm` call

### Notifier Trait

Implementations:
- `DbusNotifier` — sends `org.freedesktop.Notifications` with action buttons
- `NoopNotifier` — logs to tracing (headless/SSH fallback)

## Pause / Resume

The system tray Pause action sets a shared `AtomicBool` on the
`McpServer`. When paused, `handle_call_tool()` rejects all tool calls
with "Server is paused" error. Resume clears the flag. The pause flag
is accessible via `server.pause_flag()` for external integration.

## MCP Tools

### Docs Module (`smgglrs-tools-docs`)

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

### Git Module (`smgglrs-tools-git`)

| Tool | Permission | Description |
|------|-----------|-------------|
| `git_status` | git.status | Working tree status (short format with branch) |
| `git_diff` | git.diff | Unstaged, staged (`--cached`), or ref-based diffs |
| `git_log` | git.log | Commit history with limit and oneline options |
| `git_branch` | git.branch | List branches, optionally including remotes |
| `git_commit` | git.commit | Create a commit (requires approval) |

Uses `tokio::process::Command` to run git. Path validation with
tilde expansion, canonicalization, and `.git` directory check.

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

Single database at `$XDG_DATA_HOME/smgglrs/index.db`:

```sql
CREATE TABLE documents (...);
CREATE VIRTUAL TABLE documents_fts USING fts5(
    path, title, content,
    content=documents, content_rowid=id,
    tokenize='porter unicode61'
);
```

Thread-safe via `Mutex<Connection>` with WAL mode enabled.
Auto-indexed on `docs_write` and `docs_edit`. Content checksums
computed with BLAKE3.

## Model Serving (ONNX Runtime)

In-process model inference via the `ort` crate (ONNX Runtime).
Models load at startup and run on CPU with automatic GPU/NPU
fallback when available. Used for safety classification and
text embeddings.

### ModelBackend Trait

```rust
pub trait ModelBackend: Send + Sync + 'static {
    fn embed(&self, request: &EmbedRequest)
        -> Pin<Box<dyn Future<Output = Result<EmbedResponse, ModelError>> + Send + '_>>;
    fn classify(&self, request: &ClassifyRequest)
        -> Pin<Box<dyn Future<Output = Result<ClassifyResponse, ModelError>> + Send + '_>>;
}
```

### OnnxModel

Wraps `ort::Session` with an optional HuggingFace tokenizer.
Thread-safe via `Mutex<Session>`, runs inference via
`block_in_place` to avoid blocking the Tokio executor.

- **Embedding**: mean-pools hidden states, L2-normalizes
- **Classification**: softmax over logits, returns sorted labels

### Tokenization

Uses the `tokenizers` crate (HuggingFace) for proper BPE/WordPiece
tokenization when a `tokenizer.json` is provided. Falls back to
character-level tokenization otherwise.

### Supported Models

| Model | Task | Params | License |
|-------|------|--------|---------|
| Granite Guardian HAP 38M | Safety classification | 38M | Apache 2.0 |
| Granite Embedding R2 | Text embeddings (768-dim) | 149M | Apache 2.0 |

### Model Management CLI

```
smgglrs model available              Show supported models
smgglrs model pull guardian-hap       Download safety classifier
smgglrs model pull granite-embed      Download embedding model
smgglrs model list                    Show installed models with sizes
```

Models are downloaded from HuggingFace to
`~/.local/share/smgglrs/models/<name>/` with streaming progress.
After download, prints a ready-to-paste config snippet.

### Configuration

```toml
[models.safety]
model_path = "~/.local/share/smgglrs/models/guardian-hap/model.onnx"
tokenizer_path = "~/.local/share/smgglrs/models/guardian-hap/tokenizer.json"
task = "classification"
labels = ["safe", "hap"]
threshold = 0.5

[models.embeddings]
model_path = "~/.local/share/smgglrs/models/granite-embed/model.onnx"
tokenizer_path = "~/.local/share/smgglrs/models/granite-embed/tokenizer.json"
task = "embedding"
dimensions = 768
```

## Content Safety

Three-tier filter pipeline applied to all outbound tool responses,
between the tool handler and the MCP transport. Can be applied via
the hook pipeline (`SafetyHook`) or the legacy direct path.

### ContentFilter Trait

```rust
pub trait ContentFilter: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn scan(&self, content: &str, ctx: &FilterContext) -> Vec<Finding>;
}
```

### Built-in Filters

**SecretFilter** (11 patterns): AWS keys, GitHub/GitLab tokens,
OpenAI/Anthropic keys, bearer tokens, private keys, passwords,
connection strings, Slack webhooks.

**PiiFilter** (4 patterns with validators): SSNs (SSA rules), credit
cards (Luhn), US phone numbers, email addresses.

### Custom Filters

User-defined regex patterns in config per permission set:

```toml
[[permissions.developer.safety_patterns]]
category = "internal-url"
pattern = "https://internal\\.corp\\.com/\\S+"

[[permissions.developer.safety_patterns]]
category = "project-secret"
pattern = "PROJ_SECRET_[A-Za-z0-9]{32}"
```

Invalid regex patterns are logged and skipped.

### ML Filter (ONNX)

Contextual detection that regex can't catch, using ONNX models:

```rust
pub struct MlFilter {
    model: Arc<dyn ModelBackend>,
    threshold: f32,
    category: String,
}
```

The `MlFilter` implements `ContentFilter` and runs the full text
through a classification model. If the model detects unsafe content
above the threshold, the entire text is reported as a finding.

Loaded automatically when a classification model is configured:

```toml
[models.safety]
model_path = "~/.local/share/smgglrs/models/guardian-hap/model.onnx"
tokenizer_path = "~/.local/share/smgglrs/models/guardian-hap/tokenizer.json"
task = "classification"
labels = ["safe", "hap"]
threshold = 0.5
```

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

### Redaction

Sensitive spans replaced with category markers:

```
Original:  export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
Redacted:  export AWS_ACCESS_KEY_ID=[REDACTED:aws-key]
```

Overlapping findings are merged (longest span wins).

## Resilient Transports (Upstream)

Upstream transports support automatic retry and reconnection via the
`ResilientTransport` decorator pattern:

### RetryConfig

```rust
pub struct RetryConfig {
    pub base_delay: Duration,       // default 1s
    pub max_delay: Duration,        // default 30s
    pub total_budget: Duration,     // default 10min
    pub request_timeout: Duration,  // default 45s
    pub sleep_gap_threshold: Duration, // default 60s
}
```

### TransportFactory

```rust
pub trait TransportFactory: Send + Sync + 'static {
    async fn create(&self) -> Result<Box<dyn Transport>, UpstreamError>;
}
```

Three factory implementations: `StdioTransportFactory` (respawns
subprocess), `HttpTransportFactory`, `SseTransportFactory`.

### Behavior

- Exponential backoff: `delay = min(base * 2^n, max)`
- Permanent errors (401/403/404, command not found) return immediately
- Transient errors trigger retry with backoff
- Sleep detection: gap > threshold resets the retry budget
- Request timeout via `tokio::time::timeout`

### Configuration

```toml
[[upstream]]
name = "smgglrs"
command = ["poetry", "run", "python", "-m", "smgglrs.memory.mcp_server"]
retry_base_delay_ms = 1000
retry_max_delay_ms = 30000
retry_budget_secs = 600
request_timeout_secs = 45
```

Retry fields are optional. When absent, the transport uses the
non-resilient path (no retry, immediate failure).

### StdioTransport

- Subprocess stderr is captured and logged via `tracing::warn!`
- `is_alive()` method checks subprocess status via `try_wait()`

## System Tray (ksni)

StatusNotifierItem (SNI) via the `ksni` crate. Works with:
KDE, Gnome (AppIndicator extension), XFCE, Cinnamon, Sway/Waybar.

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
├─────────────────────────────────────────┤
│  Pause / Resume                         │
│  Quit                                   │
└─────────────────────────────────────────┘
```

### Wiring

- `TrayCommand` channel: menu actions → server event loop
- Background updater polls `ApprovalStore` every 1s
- Pause/Resume toggles shared `AtomicBool` on `McpServer`
- `--no-tray` flag for headless/systemd operation

## Security Model

### Defense in Depth

1. **Unix socket** — No network exposure. Filesystem permissions (0600).
2. **Token authentication** — Bearer tokens, BLAKE3-hashed.
3. **Path canonicalization** — Symlinks resolved, `..` eliminated.
4. **Deny-first ACLs** — Deny rules always win. Default-deny.
5. **Per-tool rules** — Glob-based allow/deny/approve per tool name.
6. **Operation restrictions** — String-based, module-namespaced.
7. **Approval workflow** — Four-channel human-in-the-loop.
8. **Content safety** — Regex + custom + ML filters redact/block sensitive data.
9. **Hook pipeline** — Extensible pre/post processing with timeouts.
10. **Pause/Resume** — Operator can halt all tool calls instantly.
11. **Systemd hardening** — `NoNewPrivileges`, `ProtectHome=read-only`,
    `ProtectSystem=strict`, `MemoryDenyWriteExecute`, etc.

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Agent reads private files | Path ACLs (deny-wins) |
| Agent writes to unauthorized paths | Operation perms + approval |
| Agent calls dangerous tools | Per-tool deny/approve rules |
| Path traversal (`../../etc/passwd`) | Canonicalization before ACL check |
| Token theft | BLAKE3-hashed storage, Unix socket |
| Agent bypasses approval | Non-blocking return, grant is single-use |
| Agent exfiltrates secrets in file content | Content safety filters (redact/block) |
| Agent exfiltrates PII | PII detector with Luhn/SSA validation |
| Contextual sensitive content | ML classifier (Guardian HAP) via ONNX |
| Custom sensitive data | User-defined regex patterns per permission set |
| Hook bypass | Hooks run with timeout, timeout continues (no bypass) |
| Prompt injection via documents | Out of scope (agent responsibility) |
| Denial of service | Systemd resource limits, pause/resume |

## Configuration

Default path: `~/.config/smgglrs/config.toml`

```toml
[server]
socket = "$XDG_RUNTIME_DIR/smgglrs/smgglrs.sock"
tcp = "127.0.0.1:9315"    # optional, for development

[modules.docs]
enabled = true
# db = "$XDG_DATA_HOME/smgglrs/index.db"
watch = ["~/Documents", "~/Notes"]   # auto-reindex on file changes

[modules.git]
enabled = true

# --- ONNX models (install via: smgglrs model pull <name>) ---
[models.safety]
model_path = "~/.local/share/smgglrs/models/guardian-hap/model.onnx"
tokenizer_path = "~/.local/share/smgglrs/models/guardian-hap/tokenizer.json"
task = "classification"
labels = ["safe", "hap"]
threshold = 0.5

[models.embeddings]
model_path = "~/.local/share/smgglrs/models/granite-embed/model.onnx"
tokenizer_path = "~/.local/share/smgglrs/models/granite-embed/tokenizer.json"
task = "embedding"
dimensions = 768

[approval]
timeout_secs = 300
notify = "dbus"  # "dbus" or "none"

# --- Upstream MCP servers ---
[[upstream]]
name = "smgglrs"
transport = "stdio"
command = ["poetry", "run", "python", "-m", "smgglrs.memory.mcp_server"]
cwd = "/home/user/smgglrs"
retry_base_delay_ms = 1000

[[upstream]]
name = "api-server"
transport = "http"
url = "http://localhost:8001/mcp"

# --- Agents ---
[[agents]]
name = "claude-code"
token_hash = "20a8c34a..."  # BLAKE3 hex hash from `smgglrs token generate`
permissions = "developer"

[permissions.developer]
allow = ["~/Documents/**", "~/Notes/**", "~/Code/**"]
deny = ["**/.env", "**/*secret*", "**/credentials*"]
operations = ["read", "write", "search", "list", "git.status", "git.diff",
              "git.log", "git.branch", "git.commit"]
approve = ["write", "git.commit"]
safety = "standard"
default_tool_policy = "allow"

[[permissions.developer.tool_rules]]
tool = "git_commit"
policy = "approve"

[[permissions.developer.safety_patterns]]
category = "internal-url"
pattern = "https://internal\\.corp\\.com/\\S+"

[permissions.readonly]
allow = ["~/Documents/shared/**"]
deny = []
operations = ["read", "search", "list"]
approve = []
safety = "standard"
```

## CLI

```
smgglrs serve [--config path] [--no-tray]   Start the server
smgglrs token generate --name N --perms P   Generate agent token (prints BLAKE3 hash)
smgglrs token list                          List registered agents from config
smgglrs approve <request-id>                Approve a pending request (via server)
smgglrs deny <request-id>                   Deny a pending request (via server)
smgglrs status                              Query running server status
smgglrs install                             Install systemd user units
smgglrs uninstall                           Uninstall systemd user units
smgglrs model available                     Show supported models for download
smgglrs model pull <name>                   Download model from HuggingFace
smgglrs model list                          Show installed models
```

## Gateway Architecture

### Design Rationale

smgglrs is an **MCP gateway** that aggregates upstream MCP servers:

- **Domain separation**: Each upstream server owns its domain logic.
  smgglrs stays domain-agnostic.
- **Unified security**: Auth, ACLs, per-tool rules, content safety,
  and approval workflows apply uniformly to all traffic.
- **Model agnosticism**: Any MCP client can consume the aggregated
  tools and prompts.

### Upstream Transports

```rust
#[async_trait]
pub trait Transport: Send + 'static {
    async fn request(&mut self, body: Value) -> Result<Value, UpstreamError>;
    fn shutdown(&mut self);
}
```

| Transport | Config field | Wire protocol |
|-----------|-------------|---------------|
| **stdio** | `command`, `cwd` | Subprocess, line-delimited JSON-RPC over stdin/stdout |
| **http** | `url` | POST JSON-RPC to HTTP endpoint (MCP streamable-http) |
| **sse** | `url` | SSE endpoint discovery → POST JSON-RPC to discovered URL |

Each transport can be wrapped in `ResilientTransport` for automatic
retry and reconnection (see Resilient Transports section).

### Upstream Lifecycle

1. **Startup**: Connect via configured transport, call `initialize`,
   discover tools/prompts/resources
2. **Registration**: Wrap in `UpstreamModule` (implements `Module`
   trait), register like any built-in module
3. **Runtime**: Forward requests through `Transport`, apply safety
   filters, return to agent
4. **Error handling**: Connection failures logged, upstream skipped.
   With resilient transport, reconnection is automatic.

## Systemd Integration

Install via `smgglrs install`, uninstall via `smgglrs uninstall`.

Service unit (`~/.config/systemd/user/smgglrs.service`):

```ini
[Unit]
Description=smgglrs — Composable MCP Server
After=default.target

[Service]
Type=simple
ExecStart=%h/.cargo/bin/smgglrs serve --no-tray
Restart=on-failure
RestartSec=5
RuntimeDirectory=smgglrs
ReadWritePaths=%h/.local/share/smgglrs %h/.config/smgglrs
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only

[Install]
WantedBy=default.target
```

Socket unit (`~/.config/systemd/user/smgglrs.socket`):

```ini
[Unit]
Description=smgglrs — MCP Server Socket

[Socket]
ListenStream=%t/smgglrs/smgglrs.sock
SocketMode=0600

[Install]
WantedBy=sockets.target
```

## File Watcher

The docs module can watch directories for file changes using the
`notify` crate (inotify on Linux). On create/modify, files are read
and upserted into the FTS5 index. On delete, removed from the index.

```toml
[modules.docs]
watch = ["~/Documents", "~/Notes"]
```

- Skips hidden files (dotfiles) and binary extensions
- Background processing via `spawn_blocking`
- Uses BLAKE3 checksums for content deduplication

## Agent SDK Design Notes

Design inputs from landscape research (April 2026) for the
future `smgglrs-agent` crate.

### Coding Agent Components (Raschka)

Six core components identified for effective agent harnesses:

1. **Live repository context** — Collect workspace metadata upfront
   (git status, project structure, conventions). smgglrs already provides
   this via smgglrs-tools-git and smgglrs-tools-docs.
2. **Prompt cache separation** — Separate stable content (tool
   descriptions, system prompt) from dynamic state (conversation
   history). Enables prompt cache reuse across turns.
3. **Structured tool access with validation** — Model output →
   validation → optional approval → execution → bounded result.
   Maps to smgglrs's permission engine + hook pipeline.
4. **Context bloat minimization** — Clip verbose outputs, compress
   older history more aggressively than recent events. smgglrs-agent
   should implement transcript reduction.
5. **Dual-layer session memory** — Full transcript (for audit/resume)
   + distilled working memory (for task continuity). Maps to
   smgglrs-core session management.
6. **Bounded subagent delegation** — Child agents inherit sufficient
   context but operate within tighter constraints. Depth limits,
   read-only modes, explicit task boundaries.

Key insight: "a lot of apparent model quality is really context
quality." The harness matters as much as the model.

### AG-UI Interrupt/Resume Model

AG-UI's event streaming and interrupt patterns are relevant for
the hook pipeline:

- **Tool-level approval**: `approval_mode="always_require"` pauses
  workflow, emits interrupt event for human review. Maps to smgglrs's
  existing approval system.
- **Information request interrupts**: Agents can pause and ask
  users for input via `HandoffAgentUserRequest`. Could extend
  smgglrs's hook pipeline to support agent-initiated prompts.
- **Resume mechanism**: `resume.interrupts` carries interrupt ID +
  response payload. The approval store already supports grant
  caching; extend to support arbitrary interrupt/resume.

### Flow Communication Primitives

smgglrs-flow provides three execution modes (handoff flows, DAG
execution, iterative analysis) and three IFC-gated communication
primitives for mesh topologies:

**Agent Mailbox** — Lateral mpsc messaging between agents.
Bell-LaPadula no-write-down enforced on every `mesh_post`.
Audit log for orchestrator visibility.

**Shared Blackboard** — Flow-level key-value store. Per-entry
DataLabel, taint-on-read via lattice join. Agents query what
they need instead of serializing everything into prompts.

**Conditional Back-Edges** — Post-completion routing when
validation fails. Bounded by max_iterations. Stored separately
from DependencyGraph (DAG stays acyclic). Activation invalidates
downstream results via `all_dependents()`.

All three are exposed as virtual tools (mesh_post, mesh_recv,
bb_publish, bb_read, bb_keys) intercepted by the flow engine.

### RamaLama as Prior Art

RamaLama (containers/ramalama) established the model-as-container
pattern: URI-addressed models, GPU auto-detection, rootless Podman
with `--network=none`. Our `smgglrs-model-hub` and
`smgglrs-model-runtime` reimplement this in Rust with the same URI
scheme (`ollama://`, `hf://`, `oci://`) for compatibility.

## Future Work

### Search & Indexing
- **Vector search** — sqlite-vec with Granite Embedding R2 for
  semantic similarity (embedding model infrastructure is ready)
- **Content extraction** — PDF, HTML, CSV pipeline
- **GLM-OCR integration** — 0.9B OCR model for document ingestion
  via managed runtime, feeding structured markdown into smgglrs-rag

### Platform
- **Gnome Keyring** — Token storage via `org.freedesktop.secrets`
- **OpenVINO EP** — Add `OpenVINOExecutionProvider` to OnnxBackend
  for Intel CPU/GPU/NPU acceleration of in-process models
- **OpenTelemetry** — Normalized observability across agent
  harnesses (inspired by Google SCION)
