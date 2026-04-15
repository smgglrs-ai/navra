# mcpd

Secure MCP gateway daemon for Linux desktops. Rust workspace.

## Build

Requires ONNX Runtime installed system-wide (Fedora: `onnxruntime-devel`).

```bash
# Build
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build

# Run
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo run -- serve
```

These environment variables are required because `ort` is configured
with `default-features = false` (no bundled download) and the system
package only provides shared libraries.

## Workspace

| Crate | Category | Role |
|---|---|---|
| `myelix-protocol` | Infrastructure | MCP/A2A/JSON-RPC types, upstream client transports |
| `myelix-model` | Infrastructure | Model backend trait + ONNX/OpenAI implementations |
| `myelix-model-hub` | Infrastructure | Pull/cache models from OCI, HuggingFace, Ollama registries |
| `myelix-model-runtime` | Infrastructure | Serve models with pluggable isolation (Podman, direct, libkrun) |
| `myelix-security` | Infrastructure | Auth, permissions, IFC, safety filters, hooks |
| `myelix-cognitive` | Cognitive | Persona/directive/heuristic YAML loader + prompt weaver |
| `myelix-memory` | Persistence | Working memory (conversation turns) + knowledge store (FTS5) |
| `myelix-agent` | Infrastructure | Client SDK: agent builder, MCP client, tool-use loop |
| `myelix-flow` | Orchestration | Multi-agent flows: handoff routing, DAG execution, mesh communication (mailbox, blackboard, back-edges), mandate validation |
| `myelix-core` | Infrastructure | Server, module trait, session, transport, re-exports |
| `myelix-tools-docs` | Tool | Document tools, SQLite FTS5 + sqlite-vec |
| `myelix-tools-git` | Tool | Git tools (status, diff, log, branch, commit) |
| `myelix-rag` | Context enrichment | Vector search, sqlite-vec, semantic chunking |
| `myelix-modal-voice` | Modality | Speech I/O (ASR + TTS via ONNX models) |
| `myelix-modal-vision` | Modality | Image/screen understanding (GPU tier) |
| `myelix-server` | Binary | CLI, config, module wiring, systemd, tray (binary: `mcpd`) |

### Dependency layering

```
myelix-protocol          (no myelix deps)
myelix-model             (no myelix deps)
myelix-model-hub         (no myelix deps)
myelix-model-runtime     (no myelix deps)
    ↓
myelix-security          (protocol + model)
    ↓
myelix-cognitive         (no myelix deps)               PERSONAS
myelix-memory            (no myelix deps)               PERSISTENCE
myelix-agent             (protocol + model + security)  CLIENT
myelix-flow              (agent)                        ORCHESTRATION
myelix-core              (protocol + model + security)  SERVER
    ↓
myelix-tools-*  ─────┐
myelix-rag      ─────┼── (core only)
myelix-modal-*  ─────┘
    ↓
myelix-server            (all + hub + runtime)
```

## Architecture

mcpd is an MCP gateway that sits between AI agents and local
resources. It aggregates built-in modules and upstream MCP servers
behind a unified security layer.

```
AI Agent (Claude Code, Myelix, etc.)
    |
    | MCP Streamable HTTP + SSE (Unix socket or TCP)
    v
myelix-server / mcpd (gateway)
    |-- Auth (BLAKE3 tokens)
    |-- Permission engine (path ACLs, tool rules)
    |-- Hook pipeline (pre/post tool-call)
    |-- Safety filters (regex + ML)
    |-- Built-in modules (docs, git, rag, voice, vision)
    |-- Upstream MCP servers (proxied, safety-filtered)
    |-- Discovery (AID, mDNS, MCP registry)
    v
Desktop (D-Bus notifications, system tray, systemd)
```

## Key Design Decisions

- **Gateway, not framework**: mcpd enforces security at the
  infrastructure layer. Orchestration belongs in the agent (Myelix).
- **Module trait**: All capabilities are modules implementing
  `Module` trait. Upstream MCP servers are wrapped in `UpstreamModule`.
- **Deny-wins ACLs**: Path deny rules always beat allow rules.
  Canonicalization before ACL check prevents traversal.
- **Safety is a hook**: Content filtering runs as `SafetyHook` in
  the hook pipeline, not hardcoded in the request path.
- **In-process models**: Small ONNX models (safety, embeddings)
  load directly into the mcpd process. No external dependencies
  for CPU tier.

## Conventions

### Naming

- Tool names are prefixed with module name: `docs_read`, `git_status`
- Operations are string-based, module-namespaced: `"read"`, `"git.commit"`
- Config fields use snake_case in TOML

### Error Handling

- Modules return `CallToolResult::error(msg)` for user-facing errors
- Infrastructure errors use `anyhow::Result` in server code
- Model loading failures are logged and skipped (graceful degradation)

### Testing

- Unit tests live in `#[cfg(test)] mod tests` at the bottom of each file
- Integration tests in `tests/` directories per crate
- Test tools use `echo_tool_def()` and `test_ctx()` helpers from `server.rs`
- All async tests use `#[tokio::test]`

### Adding a Module

1. Create crate implementing `Module` trait (from `myelix-core`)
2. Add dependency in `myelix-server/Cargo.toml`
3. Add config struct in `config.rs`
4. Add `if cfg.xxx_enabled() { builder = builder.module(xxx); }` in `main.rs`

### Adding a Tool

Tools within a module:
1. Define `ToolDefinition` with name, description, input schema
2. Create handler: `Arc<dyn Fn(Value, CallContext) -> Pin<Box<dyn Future<Output = CallToolResult> + Send>> + Send + Sync>`
3. Return `(definition, handler)` pair from `Module::tools()`
4. Tool name must be prefixed with module name

## Config

Default path: `~/.config/mcpd/config.toml`

Key sections: `[server]`, `[modules.*]`, `[models.*]`, `[[agents]]`,
`[permissions.*]`, `[[upstream]]`, `discover`, `[[registry]]`.

See DESIGN.md for full config reference.

## Related Projects

- **Myelix (Python)** (`~/Code/gitlab.cee.redhat.com/smgglrs/myelix/myelix/`):
  Original multi-agent orchestration platform. Being replaced by the
  myelix-* Rust crate family. See `ROADMAP.md` for migration status.
- **Project Jarvis**: Voice-first local assistant combining mcpd
  (secure tools) + myelix-flow (orchestration) + local models.

## Reference Documents

- `DESIGN.md` — Full architecture, protocol, security model, config reference
- `ROADMAP.md` — Gap analysis vs Python Myelix, phased migration plan
- `MODELS.md` — Model integration architecture, CPU/GPU tiers, hardware profiles
- `DISCOVERY.md` — Agent/tool discovery landscape (AID, A2A, MCP Server Cards)
