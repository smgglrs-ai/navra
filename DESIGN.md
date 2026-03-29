# mcpd — Design Document

## Overview

**mcpd** is a workspace of two Rust crates:

- **mcpd-core**: A lightweight, reusable MCP (Model Context Protocol) server
  framework implementing the 2025-03-26 specification.
- **mcpd-docs**: A secure document server built on mcpd-core, designed to run
  as a user-level systemd unit and expose user documents to AI agents through
  a rich permission model.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      AI Agent                           │
│                  (Claude, etc.)                          │
└──────────────────────┬──────────────────────────────────┘
                       │ MCP Streamable HTTP
                       │ (Unix socket or TCP)
┌──────────────────────▼──────────────────────────────────┐
│                    mcpd-docs                             │
│  ┌────────────┐ ┌──────────┐ ┌────────────────────────┐ │
│  │ Permission │ │ Approval │ │    Document Tools      │ │
│  │   Engine   │ │ Workflow │ │ search/read/write/list │ │
│  └─────┬──────┘ └────┬─────┘ └──────────┬─────────────┘ │
│        │              │                  │               │
│  ┌─────▼──────────────▼──────────────────▼─────────────┐ │
│  │              Index Store                             │ │
│  │         SQLite (FTS5 + vec)                          │ │
│  └─────────────────────▲───────────────────────────────┘ │
│                        │                                 │
│  ┌─────────────────────┴───────────────────────────────┐ │
│  │           File Watcher (notify)                     │ │
│  │         Content Extraction Pipeline                 │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────┬──────────────────────────────────┘
                       │ uses
┌──────────────────────▼──────────────────────────────────┐
│                    mcpd-core                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐ │
│  │  JSON-RPC    │ │  MCP Proto   │ │ Streamable HTTP  │ │
│  │  2.0 Types   │ │  Messages    │ │ Transport (axum) │ │
│  └──────────────┘ └──────────────┘ └──────────────────┘ │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐ │
│  │  Session     │ │  Tool/Res    │ │  Auth Trait      │ │
│  │  Manager     │ │  Registry    │ │  (pluggable)     │ │
│  └──────────────┘ └──────────────┘ └──────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## mcpd-core

### JSON-RPC 2.0 Layer

Standard JSON-RPC 2.0 implementation:

- `Request` — method + params + id
- `Response` — result or error + id
- `Notification` — method + params (no id)
- `BatchRequest` / `BatchResponse`
- Standard error codes (-32700 parse, -32600 invalid, -32601 not found,
  -32602 invalid params, -32603 internal)

### MCP Protocol (2025-03-26 spec)

Lifecycle:

1. Client sends `initialize` with capabilities and `clientInfo`
2. Server responds with `serverInfo` and capabilities
3. Client sends `notifications/initialized`
4. Normal operation: `tools/list`, `tools/call`, `resources/list`, etc.

Server capabilities declared:

```json
{
  "capabilities": {
    "tools": { "listChanged": true },
    "resources": { "subscribe": true, "listChanged": true }
  }
}
```

### Streamable HTTP Transport

Single HTTP endpoint (`POST /mcp`) per the 2025-03-26 spec:

- **Request-Response**: Client POSTs JSON-RPC, server responds with
  `application/json`.
- **Streaming**: Server may respond with `text/event-stream` (SSE) for
  long-running operations or server-initiated messages.
- **Session management**: Server issues `Mcp-Session-Id` header on
  `initialize`. Client includes it in subsequent requests.
- **Resumability**: `Last-Event-ID` header for SSE reconnection.

Transport binding:

- **Unix domain socket** (default): `$XDG_RUNTIME_DIR/mcpd/docs.sock`
  — no network exposure, filesystem permissions enforce access.
- **TCP** (optional): `127.0.0.1:port` for development/debugging.

### Tool & Resource Registry

Builder pattern for server construction:

```rust
McpServer::builder()
    .name("mcpd-docs")
    .version("0.1.0")
    .tool(search_tool)
    .tool(read_tool)
    .resource_template("doc://{path}")
    .auth(token_auth)
    .build()
```

Tools implement a trait:

```rust
#[async_trait]
pub trait Tool: Send + Sync + 'static {
    fn definition(&self) -> ToolDefinition;
    async fn call(
        &self,
        params: serde_json::Value,
        ctx: &CallContext,
    ) -> Result<ToolResult, ToolError>;
}
```

### Auth Trait

Pluggable authentication — mcpd-core defines the trait, applications
provide implementations:

```rust
#[async_trait]
pub trait Authenticator: Send + Sync + 'static {
    async fn authenticate(&self, req: &Request) -> Result<AgentIdentity, AuthError>;
}
```

`AgentIdentity` carries the agent's name/ID and is threaded through
`CallContext` so tools and permission checks can access it.

## mcpd-docs

### Permission Model

Four dimensions, evaluated in order:

#### 1. Agent Identity

Each agent has a unique identity (token-based). Agents are registered in
the configuration file with a name, token, and permission set.

```toml
[[agents]]
name = "claude-code"
token = "mcd_..."  # generated via `mcpd-docs token generate`
permissions = "developer"

[[agents]]
name = "background-indexer"
token = "mcd_..."
permissions = "readonly"
```

#### 2. Path ACLs

Glob-pattern rules controlling which paths each permission set can access:

```toml
[permissions.developer]
allow = [
    "~/Documents/**",
    "~/Code/**/*.md",
    "~/Notes/**",
]
deny = [
    "~/Documents/private/**",
    "**/.env",
    "**/*secret*",
    "**/credentials*",
]

[permissions.readonly]
allow = ["~/Documents/shared/**"]
deny = []
```

Evaluation: deny rules are checked first (deny-wins). Paths are
canonicalized before matching to prevent traversal attacks. Symlinks
are resolved and re-checked against ACLs.

#### 3. Operation Permissions

Fine-grained per-operation control:

```toml
[permissions.developer]
operations = ["read", "write", "search", "list", "index"]

[permissions.readonly]
operations = ["read", "search", "list"]
```

Operations:
- `read` — read document content
- `write` — create, update, or delete documents
- `search` — full-text and semantic search
- `list` — list directory contents
- `index` — trigger re-indexing

#### 4. Human-in-the-Loop Approval

Certain operations can require explicit user approval before execution:

```toml
[permissions.developer]
approve = ["write"]  # writes need human approval
```

Approval flow:
1. Agent calls a tool requiring approval
2. Server returns a `pending_approval` response with a request ID
3. Server sends a desktop notification (via D-Bus `org.freedesktop.Notifications`)
4. User approves/denies via:
   - `mcpd-docs approve <request-id>` CLI command
   - D-Bus notification action button
5. Server resolves the pending request

Pending requests expire after a configurable timeout (default: 5 minutes).

### Document Indexing

#### Storage: SQLite

Single database at `$XDG_DATA_HOME/mcpd-docs/index.db`:

```sql
-- Document metadata
CREATE TABLE documents (
    id          INTEGER PRIMARY KEY,
    path        TEXT UNIQUE NOT NULL,
    mime_type   TEXT NOT NULL,
    size        INTEGER NOT NULL,
    modified_at TEXT NOT NULL,  -- ISO 8601
    indexed_at  TEXT NOT NULL,
    checksum    TEXT NOT NULL   -- BLAKE3
);

-- Full-text search (FTS5)
CREATE VIRTUAL TABLE documents_fts USING fts5(
    path, title, content,
    content=documents,
    content_rowid=id,
    tokenize='porter unicode61'
);

-- Vector embeddings (sqlite-vec)
CREATE VIRTUAL TABLE documents_vec USING vec0(
    id INTEGER PRIMARY KEY,
    embedding FLOAT[384]  -- all-MiniLM-L6-v2 dimension
);

-- Chunk-level vectors for large documents
CREATE TABLE chunks (
    id          INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    offset      INTEGER NOT NULL,
    length      INTEGER NOT NULL,
    content     TEXT NOT NULL
);

CREATE VIRTUAL TABLE chunks_vec USING vec0(
    id INTEGER PRIMARY KEY,
    embedding FLOAT[384]
);
```

#### Content Extraction

Pipeline by MIME type:

| Format | Method |
|--------|--------|
| text/plain | Direct read |
| text/markdown | Strip frontmatter, preserve structure |
| text/html | Strip tags, extract text |
| application/pdf | `pdf-extract` crate |
| application/json | Pretty-print + extract string values |
| text/csv | Parse and flatten |
| \*/\* (fallback) | Skip binary, attempt UTF-8 decode |

#### File Watcher

`notify` crate watches configured paths. On file change:

1. Debounce (500ms) to coalesce rapid edits
2. Check against path ACLs (only index permitted paths)
3. Compute BLAKE3 checksum — skip if unchanged
4. Extract content → update FTS5 index
5. Generate embeddings → update vector index

### MCP Tools

| Tool | Operation | Description |
|------|-----------|-------------|
| `docs_search` | search | Full-text search with FTS5 ranking |
| `docs_semantic_search` | search | Vector similarity search |
| `docs_read` | read | Read document content by path |
| `docs_write` | write | Create or update a document |
| `docs_list` | list | List documents in a directory |
| `docs_index` | index | Trigger re-indexing of a path |

### MCP Resources

- `doc://{path}` — Individual document as a resource (supports subscribe)
- `index://status` — Indexing status (document count, last indexed, etc.)

## Security Model

### Defense in Depth

1. **Unix socket** — No network exposure. Filesystem permissions (0600)
   restrict access to the owning user.
2. **Token authentication** — Each agent must present a valid token.
   Tokens are BLAKE3-hashed in the config file (never stored in plaintext
   after initial generation).
3. **Path canonicalization** — All paths are resolved to absolute paths
   before ACL evaluation. Symlinks are followed and re-checked.
   `..` traversal is eliminated.
4. **Deny-first ACLs** — Deny rules always win. Default-deny for
   unmatched paths.
5. **Operation restrictions** — Even with path access, agents can only
   perform explicitly permitted operations.
6. **Approval workflow** — Destructive operations can require human
   confirmation.
7. **Systemd hardening** — The unit file uses `ProtectHome=read-only`,
   `ProtectSystem=strict`, `NoNewPrivileges=yes`,
   `PrivateNetwork=yes` (when using Unix socket only).

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Malicious agent reads private files | Path ACLs with deny-wins |
| Agent writes to unauthorized paths | Operation permissions + approval |
| Path traversal (`../../../etc/passwd`) | Canonicalization before ACL check |
| Token theft | Hashed storage, Unix socket limits exposure |
| Prompt injection via document content | Out of scope (agent responsibility) |
| Denial of service | Systemd resource limits (MemoryMax, CPUQuota) |

## Configuration

Default config path: `$XDG_CONFIG_HOME/mcpd-docs/config.toml`

```toml
[server]
socket = "$XDG_RUNTIME_DIR/mcpd/docs.sock"
# tcp = "127.0.0.1:9315"  # optional, for development

[index]
db = "$XDG_DATA_HOME/mcpd-docs/index.db"
watch_debounce_ms = 500
# embedding_model = "all-MiniLM-L6-v2"  # future

[approval]
timeout_secs = 300
notify = "dbus"  # "dbus" or "none"

[[agents]]
name = "claude-code"
token_hash = "$blake3$..."
permissions = "developer"

[permissions.developer]
allow = ["~/Documents/**", "~/Notes/**"]
deny = ["**/.env", "**/*secret*"]
operations = ["read", "write", "search", "list", "index"]
approve = ["write"]

[permissions.readonly]
allow = ["~/Documents/shared/**"]
deny = []
operations = ["read", "search", "list"]
approve = []
```

## Systemd Integration

User unit at `~/.config/systemd/user/mcpd-docs.service`:

```ini
[Unit]
Description=mcpd-docs — MCP Document Server
Documentation=https://github.com/user/mcpd
After=default.target

[Service]
Type=notify
ExecStart=%h/.cargo/bin/mcpd-docs serve
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/mcpd-docs
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

## CLI Interface

```
mcpd-docs serve              Start the server (foreground or systemd)
mcpd-docs token generate     Generate a new agent token
mcpd-docs token list         List registered agents
mcpd-docs approve <id>       Approve a pending request
mcpd-docs deny <id>          Deny a pending request
mcpd-docs index <path>       Manually trigger indexing
mcpd-docs status             Show server status
```
