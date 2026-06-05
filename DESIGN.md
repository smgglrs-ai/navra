# navra — Design Document

## Overview

**navra** is a secure MCP (Model Context Protocol) gateway designed to
run as a user-level systemd unit on Linux desktops. It aggregates
multiple MCP servers — both built-in modules and upstream external
servers — behind a unified security layer with authentication, path
ACLs, per-tool permission rules, content safety filtering (built-in
and custom regex), human-in-the-loop approval, and a hook/middleware
system.

Built-in **modules** contribute tools and prompts directly. External
**upstream** MCP servers (e.g., cognitive personas, or
specialized tool servers) are proxied through navra, which applies the
same auth, permissions, and safety policies to all traffic regardless
of origin.

## Crate Structure

See CLAUDE.md for the full 20-crate workspace table. Summary:

```
navra/
├── navra-protocol       MCP/A2A/JSON-RPC types, upstream transports
├── navra-model          Model backend trait + ONNX/OpenAI/Anthropic impls
├── navra-model-hub      Pull/cache models (OCI, HuggingFace, Ollama)
├── navra-model-runtime  Serve models (direct, Podman, OpenShell)
├── navra-responses      Open Responses API types (spec-compliant)
├── navra-security       Auth, permissions, IFC, trusted paths, safety, hooks
├── navra-cognitive       Persona/directive/heuristic YAML loader + prompt weaver
├── navra-memory         Working memory + knowledge store (FTS5)
├── navra-agent          Client SDK: agent builder, MCP client, tool-use loop
├── navra-flow           Declarative multi-agent flows with handoff routing
├── navra-core           Server, module trait, session, transport
├── navra-tools-file     File tools (FTS5, file I/O)
├── navra-tools-git      Git tools (status, diff, log, branch, commit)
├── navra-tools-exec     Command execution inside OpenShell sandboxes
├── navra-rag            Vector search, sqlite-vec, semantic chunking
├── navra-modal-voice    Speech I/O (ASR + TTS via ONNX)
├── navra-modal-vision   Image/screen understanding (GPU tier)
├── navra-macros         #[tool] proc macro for tool definition generation
├── navra-server         Binary: CLI, config, module wiring (navra)
└── benchmarks             Criterion performance benchmarks
```

| Crate | Role |
|-------|------|
| `navra-protocol` | MCP/A2A/JSON-RPC types, upstream client with stdio/HTTP/SSE + resilient transports |
| `navra-model` | Model backend trait with ONNX (in-process), OpenAI-compatible, and Anthropic (direct + Vertex AI) implementations |
| `navra-model-hub` | Pull and cache models from OCI, HuggingFace, and Ollama registries with content-addressed storage |
| `navra-model-runtime` | Serve models with pluggable isolation: direct (llama-server), Podman (rootless container), OpenShell (gRPC sandbox) |
| `navra-security` | BLAKE3 token auth, capability tokens (CBOR+Ed25519), DID:key identity, path ACLs, per-tool rules, IFC with trusted paths, safety filters, hook pipeline, approval store, D-Bus notifier, process table, rate limiting |
| `navra-agent` | Client SDK for building agents: Agent builder, McpClient (IFC taint tracking), ReAct tool-use loop |
| `navra-flow` | Declarative multi-agent flow engine: directed graph of agents, handoff-based routing, TOML config |
| `navra-core` | MCP server (JSON-RPC 2.0, Streamable HTTP + SSE), Module trait, session store, IFC value store |
| `navra-tools-file` | File tools, SQLite FTS5 index, file I/O with path security |
| `navra-tools-git` | Git tools (`git_status`, `git_diff`, `git_log`, `git_branch`, `git_commit`) |
| `navra-rag` | Vector search with sqlite-vec, semantic chunking for context enrichment |
| `navra-modal-voice` | Speech I/O: ASR (Whisper) + TTS via ONNX models |
| `navra-modal-vision` | Image/screen understanding (GPU tier) |
| `navra-responses` | Open Responses API types — spec-compliant, no client, no runtime |
| `navra-server` | Binary: CLI, config, module wiring, model hub/runtime integration, systemd, system tray |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          AI Agent (Claude, etc.)                     │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ MCP Streamable HTTP + SSE
                             │ (Unix socket or TCP)
┌────────────────────────────▼─────────────────────────────────────────┐
│                         navra-server (gateway)                      │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────────┐  │
│  │ System Tray │  │    Config    │  │      Module Loader          │  │
│  │   (ksni)    │  │    (TOML)    │  │ FileModule, GitModule       │  │
│  │ Approve/Deny│  │              │  │ + upstream MCP servers      │  │
│  │ Pause/Resume│  │              │  │                             │  │
│  └──────┬──────┘  └──────────────┘  └──────────────┬──────────────┘  │
│         │                                          │                 │
│  ┌──────▼──────────────────────────────────────────▼──────────────┐  │
│  │                       navra-core                              │  │
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
│  │  navra-tools-file: file_search, file_read, file_write, ...     │  │
│  │  navra-tools-git:  git_status, git_diff, git_log, git_branch  │  │
│  │                 git_commit (approval required)                 │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌─ Upstream MCP Servers (proxied) ───────────────────────────────┐  │
│  │  External MCP servers — stdio / HTTP / SSE                     │  │
│  │  Discovered at startup, registered as Module, safety-filtered  │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘

         ┌──────────────────────────────────────────┐
         │         Desktop Integration              │
         │  D-Bus Notifications (Approve/Deny)      │
         │  System Tray (Pause/Resume, agents)      │
         └──────────────────────────────────────────┘
```

## Containerized Agent Execution

Agents can run in Podman containers for process isolation. The
architecture separates the GPU-bound model server from CPU-only
agent sandboxes.

### Architecture

```
┌──────────────────────────────────────────────────┐
│              Host (navra-server)                │
│  - Orchestrates flows via navra-flow            │
│  - Spawns containers via Podman                   │
│  - GPU semaphore (max_parallel)                   │
└──────────┬──────────────┬────────────────────────┘
           │              │
    ┌──────▼──────┐  ┌────▼──────────────────┐
    │ Model Server│  │ Agent Container (N)    │
    │ (1 per GPU) │  │ navra-agent binary   │
    │ llama-server│  │ No GPU access          │
    │ --device    │  │ Reads tools via MCP    │
    │ nvidia.com/ │  │ Reads model via        │
    │ gpu=all     │  │   OpenAI-compat API    │
    └─────────────┘  └────────────────────────┘
```

- **Model server** (1 container): runs `llama-server` with GPU
  passthrough (`--device nvidia.com/gpu=all`). Shared by all agents.
- **Agent sandboxes** (N containers): run `navra-agent` binary.
  No GPU access. Connect to the model server for inference and to
  the navra gateway for MCP tools.

### navra-agent Binary

Standalone binary at `navra-agent/src/bin/agent.rs`. Configured
entirely via environment variables:

| Variable | Required | Description |
|---|---|---|
| `NAVRA_ENDPOINT` | yes | Gateway MCP URL |
| `NAVRA_TOKEN` | no | Scoped capability token |
| `NAVRA_MODEL_ENDPOINT` | yes | Model server OpenAI-compat URL |
| `NAVRA_MODEL_NAME` | yes | Model name |
| `NAVRA_PERSONA` | no | Persona name |
| `NAVRA_TASK` | yes | Prompt/mandate to execute |
| `NAVRA_MAX_ITERATIONS` | no | Iteration cap (default 30) |
| `NAVRA_COGNITIVE_CORE` | no | Path to cognitive_core directory |

Output: JSON with `output`, `iterations`, `tokens_in`, `tokens_out`.

### Container Image

`Dockerfile.agent` builds the agent image:

- **Builder stage**: `quay.io/hummingbird/rust:latest-builder`,
  installs ONNX Runtime from GitHub releases.
- **Runtime stage**: `registry.fedoraproject.org/fedora-minimal:latest`,
  copies binary + ONNX shared libraries. Runs as UID 1001.

Build: `podman build -f Dockerfile.agent -t navra-agent:latest .`

### Network

Agent containers use `slirp4netns:allow_host_loopback=true` to
reach the host-bound model server and gateway via `10.0.2.2`.
No direct internet access.

### GPU Semaphore

`[budget] max_parallel` limits concurrent model requests across
all agents, preventing GPU memory exhaustion with large models.

### Fallback

When Podman is unavailable, agents run in-process within the
navra-server. The same `Agent` SDK is used in both paths.

### Configuration

```toml
[budget]
containerized = true
max_parallel = 2
model_server_image = "docker.io/vllm/vllm-openai:latest"
agent_image = "navra-agent:latest"
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
    .name("navra")
    .module(FileModule::new(perm_engine, index, approvals, notifier))
    .module(GitModule::new(perm_engine, approvals, notifier))
    .authenticator(token_auth)
    .safety_profile("developer", build_pipeline("standard"))
    .hook(SafetyHook::single("developer", pipeline))
    .build()
```

Duplicate tool and prompt names are detected at startup (panic on
conflict). Tool names follow a structured naming convention (see
[Tool Naming Convention](#tool-naming-convention) below).

### Config-driven

Modules are enabled/disabled in config:

```toml
[modules.file]
enabled = true
db = "$XDG_DATA_HOME/navra/index.db"

[modules.git]
enabled = true
```

### Adding a Module

1. Create crate implementing `Module` → provides `(ToolDefinition, ToolHandler)` pairs
2. Add dependency in `navra-server/Cargo.toml`
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

- **Unix domain socket** (default): `$XDG_RUNTIME_DIR/navra/navra.sock`
  with 0600 permissions. Parent directories created automatically.
- **TCP** (optional): `127.0.0.1:9315` for development
- Both can be active simultaneously.

### ACP v0.2.0 Transport

navra exposes an ACP-compliant REST API at `/acp/*` alongside
MCP. ACP enables agent discovery and orchestration from IDEs
(Zed, JetBrains) and agent platforms (BeeAI).

Key design decision: ACP runs go through the same security
stack as MCP calls — auth, ACLs, hooks, IFC, safety filters.
This is enforced at the gateway layer via `McpServer.handle_call_tool()`,
not at the agent layer. Agents don't need to be trusted.

The `RunDispatcher` trait makes execution pluggable:
- `ToolDispatcher` (default): parses tool calls from message text
- `AgentDispatcher` (navra-server): ReAct loop via `run_tool_loop`

Runs support `sync`, `async`, and `stream` (SSE) modes. The
`Awaiting` state integrates with the hook pipeline's `ApprovalGateHook`
for human-in-the-loop approval of high-risk operations.

Flow nodes appear as separate ACP agent manifests, discoverable
via `GET /acp/agents`. See `docs/acp.md` for full reference.

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

Generate tokens via CLI: `navra token generate --name N --perms P`

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
tool = "file_*"
policy = "allow"
```

Priority: deny wins > allow > approve > default policy.
Default policy is configurable: `default_tool_policy = "allow"`.

#### Platform tool permission recipes

Platform tools use three-part names (`<provider>_<resource>_<action>`).
Glob patterns work across all segments:

```toml
# Read-only GitHub access (whitelist reads, default deny)
# Note: don't use a github_* deny — deny always wins over
# specific allows. Use default_tool_policy = "deny" instead.
[permissions.reader]
default_tool_policy = "deny"
[[permissions.reader.tool_rules]]
tool = "github_pr_list"
policy = "allow"
[[permissions.reader.tool_rules]]
tool = "github_pr_view"
policy = "allow"
[[permissions.reader.tool_rules]]
tool = "github_issue_list"
policy = "allow"

# PR create with approval, everything else allowed
[[permissions.contributor.tool_rules]]
tool = "github_*"
policy = "allow"
[[permissions.contributor.tool_rules]]
tool = "github_pr_create"
policy = "approve"

# Block all write operations across all providers
[[permissions.observer.tool_rules]]
tool = "github_*_list"
policy = "allow"
[[permissions.observer.tool_rules]]
tool = "gitlab_*_list"
policy = "allow"
[[permissions.observer.tool_rules]]
tool = "*_create"
policy = "deny"
[[permissions.observer.tool_rules]]
tool = "*_comment"
policy = "deny"

# Full GitHub, no GitLab
[[permissions.github_only.tool_rules]]
tool = "github_*"
policy = "allow"
[[permissions.github_only.tool_rules]]
tool = "gitlab_*"
policy = "deny"
```

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
Agent: file_write(path, content)
Server: "Approval required. Request ID: abc-123."
        (+ D-Bus notification with Approve/Deny buttons)
        (+ tray icon shows pending approval)

Resolution via ANY channel:
  1. Agent calls file_approve(request_id=abc-123)     ← MCP-native
  2. User clicks D-Bus notification "Approve" button  ← Desktop
  3. User clicks tray menu Approve                    ← Tray icon
  4. CLI: navra approve abc-123                        ← Terminal

Agent: file_write(path, content)  # retry
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

## Tool Naming Convention

Tool names use a structured `<module>_<resource>_<action>` pattern
that maps directly to MCP resource URIs. The module prefix matches
the crate name suffix.

### Layers

**Layer 1 — Local tools (two-part names).**
Tools that operate on local state use `<module>_<action>`:

| Pattern | Examples | MCP Resource |
|---------|----------|--------------|
| `file_<action>` | `file_read`, `file_write`, `file_search` | `file:///path` |
| `git_<action>` | `git_status`, `git_diff`, `git_commit` | — |

**Layer 2 — Transport-level Git (two-part names).**
Remote Git operations that are provider-agnostic:

| Pattern | Examples | Notes |
|---------|----------|-------|
| `git_<action>` | `git_push`, `git_pull`, `git_fetch` | Pure Git transport, no forge API |

**Layer 3 — Platform-specific (three-part names).**
Operations that interact with forge/platform APIs use
`<provider>_<resource>_<action>`:

| Pattern | Examples | MCP Resource |
|---------|----------|--------------|
| `github_pr_<action>` | `github_pr_create`, `github_pr_list`, `github_pr_review` | `github://org/repo/pulls` |
| `github_issue_<action>` | `github_issue_create`, `github_issue_comment` | `github://org/repo/issues` |
| `gitlab_mr_<action>` | `gitlab_mr_create`, `gitlab_mr_approve` | `gitlab://group/project/merge_requests` |
| `gitlab_issue_<action>` | `gitlab_issue_list` | `gitlab://group/project/issues` |
| `jira_issue_<action>` | `jira_issue_create`, `jira_issue_transition` | `jira://PROJECT/issues` |

### Rules

1. **Module prefix = crate suffix.** `navra-tools-github` → `github_*`.
2. **Resource = noun from the MCP resource URI.** `pr`, `issue`, `mr`, `board`.
3. **Action = verb.** `create`, `list`, `get`, `update`, `delete`,
   `comment`, `review`, `approve`, `transition`.
4. **No aliasing across providers.** GitHub has PRs, GitLab has MRs.
   Different semantics, different tools, different names.
5. **Permission globs follow tool names.** Grant `github_pr_*` without
   `github_issue_*`, or `github_pr_list` without `github_pr_create`.

### Crate mapping

| Crate | Tool prefix | Scope |
|-------|-------------|-------|
| `navra-tools-file` | `file_` | Local filesystem |
| `navra-tools-git` | `git_` | Local + transport (push/pull/fetch) |
| `navra-tools-github` | `github_` | GitHub API (PRs, issues, repos) |
| `navra-tools-gitlab` | `gitlab_` | GitLab API (MRs, issues, projects) |
| `navra-tools-jira` | `jira_` | Jira API (issues, boards, sprints) |

## MCP Tools

### File Module (`navra-tools-file`)

| Tool | Permission | Description |
|------|-----------|-------------|
| `file_search` | search | Full-text search via FTS5 |
| `file_read` | read | Read file with optional offset/limit (line-based partial reads) |
| `file_write` | write | Create or overwrite file, auto-indexes |
| `file_edit` | write | Surgical string replacement (old_string → new_string, must be unique) |
| `file_delete` | write | Delete file, removes from index |
| `file_list` | list | List directory (filters entries by path ACL) |
| `file_info` | read | File metadata (size, lines, mime, modified, indexed) without content |
| `file_approve` | — | Approve a pending request by ID |
| `file_deny` | — | Deny a pending request by ID |

Read-only access is also available via MCP resources with `file://` URIs.

### Git Module (`navra-tools-git`)

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

Single database at `$XDG_DATA_HOME/navra/index.db`:

```sql
CREATE TABLE documents (...);
CREATE VIRTUAL TABLE documents_fts USING fts5(
    path, title, content,
    content=documents, content_rowid=id,
    tokenize='porter unicode61'
);
```

Thread-safe via `Mutex<Connection>` with WAL mode enabled.
Auto-indexed on `file_write` and `file_edit`. Content checksums
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
navra model available              Show supported models
navra model pull guardian-hap       Download safety classifier
navra model pull granite-embed      Download embedding model
navra model list                    Show installed models with sizes
```

Models are downloaded from HuggingFace to
`~/.local/share/navra/models/<name>/` with streaming progress.
After download, prints a ready-to-paste config snippet.

### Configuration

```toml
[models.safety]
model_path = "~/.local/share/navra/models/guardian-hap/model.onnx"
tokenizer_path = "~/.local/share/navra/models/guardian-hap/tokenizer.json"
task = "classification"
labels = ["safe", "hap"]
threshold = 0.5

[models.embeddings]
model_path = "~/.local/share/navra/models/granite-embed/model.onnx"
tokenizer_path = "~/.local/share/navra/models/granite-embed/tokenizer.json"
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

**PiiFilter** — Three detection layers:

1. **Regex patterns (US + EU + custom)**:
   - US: SSNs (SSA validation), credit cards (Luhn), phone numbers,
     email addresses
   - EU: French NIR (numéro de sécurité sociale), IBAN, SIRET/SIREN,
     EU phone formats (+33, +49, etc.), IP addresses (v4/v6),
     passport numbers
   - Negative lookaheads for ISO 8601 timestamps and UUIDs to
     prevent false positives
   - Custom patterns via `[[pii_patterns]]` in config

2. **NER semantic detection (ONNX)**:
   - ProtectAI model for English entity recognition
   - Multilingual XLM-RoBERTa model for non-English PII
   - Detects names, addresses, organizations, and other entities
     that regex cannot catch
   - Download via: `navra pii download [protectai|xlm-roberta]`

3. **File path detection**:
   - `PathPiiFilter` detects PII in file paths (e.g., usernames
     in `/home/jean.dupont/`, personal directory names)

**Four filter actions**:

| Action | Behavior |
|--------|----------|
| `pass` | Log finding, no modification |
| `redact` | Replace with `[REDACTED:category]` marker |
| `pseudonymize` | Replace with consistent pseudonym via `PseudonymMap` (reversible) |
| `block` | Reject the entire response |

`FilterAction::Pseudonymize` uses `PseudonymMap` to maintain
consistent replacements within a session (e.g., `Jean Dupont` always
becomes `Person_A`). This preserves analytical utility while removing
identifying information.

**Storage filtering**: PII filters run on all persistence paths,
not just tool responses:
- Memory ingestion (`KnowledgeStore::store`)
- Audit/blackbox log entries
- Knowledge distillation output
- Vector embeddings (cascade deletion from sqlite-vec when source
  content is purged via `memory_purge_pii`)
- Model reasoning text (agent output between tool calls)

**IFC integration**: `Confidentiality::Pii` is a first-class label
above `Sensitive`. Tool results containing PII are auto-labeled as
`Pii`. IFC enforcement blocks writes from PII-labeled data to
non-PII-safe destinations. Redacted results retain the `Pii` taint
so downstream decisions account for prior PII exposure.

**GDPR compliance tools**:

| Tool | Purpose |
|------|---------|
| `memory_purge_pii` | Purge all PII for a data subject (right to erasure) |
| `memory_forget` | Delete specific memory entries |
| `pii_report` | Generate data subject access report (right of access) |
| `pii_consent` | Record and query per-subject consent status |

**PII model management CLI**:

```
navra pii download protectai     Download English NER model
navra pii download xlm-roberta   Download multilingual NER model
```

Models are downloaded to `~/.local/share/navra/models/pii-*/`.

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

Custom PII patterns use a separate config section:

```toml
[[pii_patterns]]
category = "employee-id"
pattern = "EMP-\\d{6}"
action = "pseudonymize"

[[pii_patterns]]
category = "internal-project"
pattern = "PROJ-[A-Z]{3}-\\d{4}"
action = "redact"
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
model_path = "~/.local/share/navra/models/guardian-hap/model.onnx"
tokenizer_path = "~/.local/share/navra/models/guardian-hap/tokenizer.json"
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
name = "navra"
command = ["poetry", "run", "python", "-m", "navra.memory.mcp_server"]
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
| Agent exfiltrates PII | PII pipeline (regex + NER + path detection), IFC Pii label |
| Contextual sensitive content | ML classifier (Guardian HAP) via ONNX |
| Custom sensitive data | User-defined regex patterns per permission set |
| Hook bypass | Hooks run with timeout, timeout continues (no bypass) |
| Prompt injection via documents | Out of scope (agent responsibility) |
| Denial of service | Systemd resource limits, pause/resume |

### Supply Chain & Dependencies

Workspace dependencies use semver ranges (`"1"`, `"0.8"`) pinned by
`Cargo.lock`. This is standard Rust practice — ranges allow
compatible updates while the lockfile ensures reproducible builds.

**Known pre-release dependencies:**

| Crate | Version | Risk | Mitigation |
|-------|---------|------|------------|
| `ort` | 2.0.0-rc.12 | Pre-release, API may change | No stable alternative for ONNX. Pin in Cargo.lock. |
| `sqlite-vec` | 0.1.x | Pre-1.0, may have breaking changes | Only sqlite-vec crate available. Pin in Cargo.lock. |

**Cognitive core integrity:** YAML files (personas, directives,
heuristics) can be verified via `checksums.sha256` using SHA-256.
ForgeService checks hashes at load time, skipping tampered files.
Run `generate_checksums()` after any YAML modification.

### MAC + DAC: OpenShell Integration

When navra runs inside an OpenShell sandbox, the security model
extends from application-layer DAC to a combined MAC + DAC defense
in depth architecture. Neither layer alone is sufficient.

**Two independent enforcement layers:**

| Layer | Type | Mechanism | Prevents |
|-------|------|-----------|----------|
| OpenShell | MAC (Mandatory) | Network namespace, HTTP CONNECT proxy, OPA policies, Landlock, seccomp | Network exfiltration, lateral movement between sandboxes, filesystem escape, raw socket creation |
| navra | DAC (Discretionary) | Capability tokens, deny-wins ACLs, IFC taint propagation, safety filters, hooks | Unauthorized tool calls, path traversal, data leak via tool results, PII exposure, privilege escalation within the application |

**Why both are necessary:**

- **OpenShell without navra**: The agent can reach navra over
  the network, but without ACLs it could call any tool, read any
  path, and ignore IFC labels. A compromised agent process has
  unrestricted tool access.

- **navra without OpenShell**: The agent respects navra's ACLs
  at the application layer, but a compromised agent process can
  bypass navra entirely: open raw sockets, exfiltrate data to the
  internet, read arbitrary files via the OS, or tamper with other
  processes.

- **Both together**: OpenShell prevents reaching anything except
  navra and the model. navra prevents doing anything except
  what the capability token allows. Compromise of either layer alone
  is insufficient for a full breach.

**Microkernel analogy** (for research papers):

| OS Concept | Traditional OS | Agent Platform |
|------------|---------------|----------------|
| Hardware | CPU rings, MMU, I/O ports | OpenShell sandbox (namespace, Landlock, seccomp) |
| Kernel | Syscall interface, process isolation | navra gateway (tool access, session isolation, IFC) |
| Userland | Applications using syscalls | MCP servers + agents using tool calls |

This maps MAC (SELinux/AppArmor) to OpenShell's mandatory network
isolation, and DAC (Unix permissions) to navra's capability-scoped
ACLs. The combination is the same defense-in-depth pattern used in
production operating systems.

See `docs/designs/openshell-sandbox.md` for the full OpenShell
integration design including identity federation, A2A teammate mesh,
sandbox delegation, and gRPC module architecture.

## Transport Security

### What's secure by default

**Unix domain socket** (default transport): The socket is created
with `0600` permissions, meaning only the owning user can connect.
No network exposure, no port to scan. When managed by systemd socket
activation, the socket unit enforces `SocketMode=0600` independently
of the navra process.

**TCP listener** (optional): Binds to `127.0.0.1` only. Connections
from other machines are refused at the kernel level. This transport
is intended for development and local integration testing.

Both transports carry MCP Streamable HTTP + SSE over plain HTTP.
Because they are local-only (Unix socket or loopback TCP), encryption
is not required — the traffic never traverses a network.

### Current gap: upstream HTTP connections have no TLS

Upstream MCP server connections configured with `transport = "http"`
or `transport = "sse"` use plain HTTP. There is no TLS certificate
validation or encryption on these connections.

This is acceptable when the upstream server is on `localhost` (e.g.,
a subprocess-managed MCP server, or a local service). The traffic
stays on the loopback interface and is not observable to other
machines.

**This is not acceptable for remote upstream servers.** An upstream
configured as `url = "http://remote-host:8080/mcp"` sends requests
and responses — including tool arguments, file contents, and any
data returned by the upstream — in cleartext over the network. A
network observer can read and modify this traffic.

### Production recommendation: reverse proxy with TLS

For any upstream MCP server that is not on localhost, place a TLS-
terminating reverse proxy in front of it. The proxy handles
certificate management and encryption; navra connects to it over
localhost or Unix socket.

**Example: nginx proxying a remote upstream MCP server**

```nginx
# /etc/nginx/conf.d/mcp-upstream.conf
#
# navra connects to http://127.0.0.1:9400/mcp (plain HTTP, loopback).
# nginx forwards to the remote upstream over TLS.

server {
    listen 127.0.0.1:9400;

    location /mcp {
        proxy_pass https://remote-mcp-server.example.com:443/mcp;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/pki/tls/certs/ca-bundle.crt;
        proxy_ssl_server_name on;

        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host remote-mcp-server.example.com;

        # SSE support: disable buffering for streaming responses
        proxy_buffering off;
        proxy_cache off;
    }
}
```

Then configure the upstream in navra to point at the local proxy:

```toml
[[upstream]]
name = "remote-tools"
transport = "http"
url = "http://127.0.0.1:9400/mcp"
```

The same pattern works with Caddy (`reverse_proxy` with automatic
HTTPS) or Envoy (`transport_socket` with TLS context). The key
point: navra talks plain HTTP to localhost; the proxy handles
TLS to the remote server.

### Future: native TLS via rustls

Native TLS support for upstream HTTP transports is planned, using
`rustls` with `webpki-roots` for certificate validation. This will
allow direct `https://` URLs in upstream configuration without
requiring a reverse proxy. Until then, the reverse proxy approach
above is the recommended production pattern.

## Configuration

Default path: `~/.config/navra/config.toml`

```toml
[server]
socket = "$XDG_RUNTIME_DIR/navra/navra.sock"
tcp = "127.0.0.1:9315"    # optional, for development

[modules.file]
enabled = true
# db = "$XDG_DATA_HOME/navra/index.db"
watch = ["~/Documents", "~/Notes"]   # auto-reindex on file changes

[modules.git]
enabled = true

# --- ONNX models (install via: navra model pull <name>) ---
[models.safety]
model_path = "~/.local/share/navra/models/guardian-hap/model.onnx"
tokenizer_path = "~/.local/share/navra/models/guardian-hap/tokenizer.json"
task = "classification"
labels = ["safe", "hap"]
threshold = 0.5

[models.embeddings]
model_path = "~/.local/share/navra/models/granite-embed/model.onnx"
tokenizer_path = "~/.local/share/navra/models/granite-embed/tokenizer.json"
task = "embedding"
dimensions = 768

[approval]
timeout_secs = 300
notify = "dbus"  # "dbus" or "none"

# --- Upstream MCP servers ---
[[upstream]]
name = "navra"
transport = "stdio"
command = ["poetry", "run", "python", "-m", "navra.memory.mcp_server"]
cwd = "/home/user/navra"
retry_base_delay_ms = 1000

[[upstream]]
name = "api-server"
transport = "http"
url = "http://localhost:8001/mcp"

# --- Agents ---
[[agents]]
name = "claude-code"
token_hash = "20a8c34a..."  # BLAKE3 hex hash from `navra token generate`
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
navra serve [--config path] [--no-tray]   Start the server
navra token generate --name N --perms P   Generate agent token (prints BLAKE3 hash)
navra token list                          List registered agents from config
navra approve <request-id>                Approve a pending request (via server)
navra deny <request-id>                   Deny a pending request (via server)
navra status                              Query running server status
navra install                             Install systemd user units
navra uninstall                           Uninstall systemd user units
navra model available                     Show supported models for download
navra model pull <name>                   Download model from HuggingFace
navra model list                          Show installed models
```

## Gateway Architecture

### Design Rationale

navra is an **MCP gateway** that aggregates upstream MCP servers:

- **Domain separation**: Each upstream server owns its domain logic.
  navra stays domain-agnostic.
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

Install via `navra install`, uninstall via `navra uninstall`.

Service unit (`~/.config/systemd/user/navra.service`):

```ini
[Unit]
Description=navra — Composable MCP Server
After=default.target

[Service]
Type=simple
ExecStart=%h/.cargo/bin/navra serve --no-tray
Restart=on-failure
RestartSec=5
RuntimeDirectory=navra
ReadWritePaths=%h/.local/share/navra %h/.config/navra
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only

[Install]
WantedBy=default.target
```

Socket unit (`~/.config/systemd/user/navra.socket`):

```ini
[Unit]
Description=navra — MCP Server Socket

[Socket]
ListenStream=%t/navra/navra.sock
SocketMode=0600

[Install]
WantedBy=sockets.target
```

## File Watcher

The file module can watch directories for file changes using the
`notify` crate (inotify on Linux). On create/modify, files are read
and upserted into the FTS5 index. On delete, removed from the index.

```toml
[modules.file]
watch = ["~/Documents", "~/Notes"]
```

- Skips hidden files (dotfiles) and binary extensions
- Background processing via `spawn_blocking`
- Uses BLAKE3 checksums for content deduplication

## Agent SDK Design Notes

Design inputs from landscape research (April 2026) for the
future `navra-agent` crate.

### Coding Agent Components (Raschka)

Six core components identified for effective agent harnesses:

1. **Live repository context** — Collect workspace metadata upfront
   (git status, project structure, conventions). navra already provides
   this via navra-tools-git and navra-tools-file.
2. **Prompt cache separation** — Separate stable content (tool
   descriptions, system prompt) from dynamic state (conversation
   history). Enables prompt cache reuse across turns.
3. **Structured tool access with validation** — Model output →
   validation → optional approval → execution → bounded result.
   Maps to navra's permission engine + hook pipeline.
4. **Context bloat minimization** — Clip verbose outputs, compress
   older history more aggressively than recent events. navra-agent
   should implement transcript reduction.
5. **Dual-layer session memory** — Full transcript (for audit/resume)
   + distilled working memory (for task continuity). Maps to
   navra-core session management.
6. **Bounded subagent delegation** — Child agents inherit sufficient
   context but operate within tighter constraints. Depth limits,
   read-only modes, explicit task boundaries.

Key insight: "a lot of apparent model quality is really context
quality." The harness matters as much as the model.

### AG-UI Interrupt/Resume Model

AG-UI's event streaming and interrupt patterns are relevant for
the hook pipeline:

- **Tool-level approval**: `approval_mode="always_require"` pauses
  workflow, emits interrupt event for human review. Maps to navra's
  existing approval system.
- **Information request interrupts**: Agents can pause and ask
  users for input via `HandoffAgentUserRequest`. Could extend
  navra's hook pipeline to support agent-initiated prompts.
- **Resume mechanism**: `resume.interrupts` carries interrupt ID +
  response payload. The approval store already supports grant
  caching; extend to support arbitrary interrupt/resume.

### Flow Communication Primitives

navra-flow provides three execution modes (handoff flows, DAG
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
with `--network=none`. Our `navra-model-hub` and
`navra-model-runtime` reimplement this in Rust with the same URI
scheme (`ollama://`, `hf://`, `oci://`) for compatibility.

## Future Work

### Search & Indexing
- **Vector search** — sqlite-vec with Granite Embedding R2 for
  semantic similarity (embedding model infrastructure is ready)
- **Content extraction** — PDF, HTML, CSV pipeline
- **GLM-OCR integration** — 0.9B OCR model for document ingestion
  via managed runtime, feeding structured markdown into navra-rag

### Platform
- **Gnome Keyring** — Token storage via `org.freedesktop.secrets`
- **OpenVINO EP** — Add `OpenVINOExecutionProvider` to OnnxBackend
  for Intel CPU/GPU/NPU acceleration of in-process models
- **OpenTelemetry** — Normalized observability across agent
  harnesses (inspired by Google SCION)
