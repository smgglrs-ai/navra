<p align="center">
  <img src="assets/logo/logo-192.png" alt="smgglrs logo" width="128" />
</p>

<h1 align="center">smgglrs</h1>

<p align="center">
  Secure MCP gateway for Linux desktops
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#security">Security</a> ·
  <a href="#workspace">Workspace</a> ·
  <a href="#license">License</a>
</p>

---

**smgglrs** is a user-level MCP (Model Context Protocol) gateway that sits
between AI agents and local resources. It aggregates built-in tool modules
and upstream MCP servers behind a unified security layer with authentication,
path ACLs, content safety filtering, human-in-the-loop approval, and a
hook pipeline.

```
AI Agent (Claude Code, Goose, custom agents, ...)
    │
    │  MCP Streamable HTTP + SSE (Unix socket or TCP)
    ▼
smgglrs (gateway)
    ├── Auth (BLAKE3 tokens, capability tokens, DID:key)
    ├── Permission engine (path ACLs, per-tool rules)
    ├── Hook pipeline (pre/post tool-call)
    ├── Safety filters (regex + ML)
    ├── Built-in modules (docs, git, RAG, voice, vision)
    └── Upstream MCP servers (proxied, safety-filtered)
```

## Features

- **Gateway, not framework** — enforces security at the infrastructure
  layer; orchestration belongs in the agent.
- **Deny-wins ACLs** — path deny rules always beat allow rules.
  Canonicalization before ACL check prevents traversal.
- **In-process models** — small ONNX models (safety classifiers,
  embeddings) load directly into the process. No external dependencies
  for CPU tier.
- **Information Flow Control** — IFC labels with trusted paths track
  data sensitivity across tool calls.
- **Human-in-the-loop** — D-Bus desktop notifications for approval
  requests, with system tray for session control.
- **Multi-agent flows** — DAG execution, handoff routing, mesh
  communication (mailbox, blackboard, back-edges), mandate validation.
- **Model hub** — pull and cache models from OCI, HuggingFace, and
  Ollama registries with content-addressed storage.
- **Persona system** — YAML-defined personas, directives, and
  heuristics woven into system prompts.
- **Containerized agents** — agents run in Podman sandboxes with a
  shared GPU model server. Falls back to in-process when Podman is
  unavailable.

## Quickstart

### Prerequisites

- Rust stable (1.75+)
- ONNX Runtime (Fedora: `sudo dnf install onnxruntime-devel`)
- Linux (systemd + D-Bus for notifications/tray)

### Build and run

```bash
git clone https://github.com/smgglrs-ai/smgglrs.git
cd smgglrs

# ONNX Runtime is linked dynamically from the system package
export ORT_LIB_PATH=/usr/lib64
export ORT_PREFER_DYNAMIC_LINK=1

cargo build
cargo run -- serve
```

### Generate an agent token

```bash
cargo run -- token generate --name claude --permissions readwrite
```

Add the printed `[[agents]]` block to `~/.config/smgglrs/config.toml`,
then configure your agent to use the token in MCP requests.

## Architecture

smgglrs is a Rust workspace of 17 crates organized in strict dependency
layers:

```
smgglrs-protocol          (no internal deps)
smgglrs-model             (no internal deps)
smgglrs-model-hub         (no internal deps)
smgglrs-model-runtime     (no internal deps)
smgglrs-responses         (no internal deps)
    ↓
smgglrs-security          (protocol + model)
    ↓
smgglrs-cognitive         (no internal deps)             Personas
smgglrs-memory            (no internal deps)             Persistence
smgglrs-agent             (protocol + model + security)  Client SDK
smgglrs-flow              (agent)                        Orchestration
smgglrs-core              (protocol + model + security)  Server
    ↓
smgglrs-tools-*  ─────┐
smgglrs-rag      ─────┼── (core only)
smgglrs-modal-*  ─────┘
    ↓
smgglrs-server            (all crates)                   Binary
```

### Key design decisions

- All capabilities are **modules** implementing the `Module` trait.
  Upstream MCP servers are wrapped in `UpstreamModule`.
- Content filtering runs as `SafetyHook` in the hook pipeline, not
  hardcoded in the request path.
- Resilient upstream transports with exponential backoff, timeout,
  reconnection, and sleep detection.
- **Agent isolation**: agents can run in Podman containers
  (`smgglrs-agent` binary) with a shared model server (GPU) and
  per-agent sandboxes (no GPU). See [DESIGN.md](DESIGN.md) for details.

## Configuration

Default config path: `~/.config/smgglrs/config.toml`

```toml
[server]
transport = "unix"       # "unix" or "tcp"
socket = "/run/user/1000/smgglrs.sock"

[modules.docs]
enabled = true

[modules.git]
enabled = true

[[agents]]
name = "claude"
token_hash = "..."
permissions = "readwrite"

[[upstream]]
name = "filesystem"
command = ["npx", "-y", "@anthropic/mcp-fs"]
```

See [DESIGN.md](DESIGN.md) for the full configuration reference.

## Security

### Transport security

smgglrs's default transport is a **Unix domain socket** with `0600`
permissions, restricting access to the owning user. The optional TCP
listener binds to `127.0.0.1` only, preventing network exposure.
These defaults mean local agent-to-gateway communication is secure
without additional configuration.

### Upstream connections

**Current limitation**: upstream MCP server connections over HTTP
(`transport = "http"` or `transport = "sse"`) do not use TLS.
Connections to `localhost` upstreams are fine (traffic never leaves
the machine), but connecting to remote upstream servers over plain
HTTP exposes requests and responses to network interception.

For any non-localhost upstream, place a reverse proxy (nginx, Caddy,
or Envoy) in front of the upstream server to terminate TLS. See the
[Transport Security](DESIGN.md#transport-security) section in
DESIGN.md for a worked example and full details.

### PII detection and GDPR compliance

smgglrs detects and handles PII across three layers: regex patterns
(US + EU), NER models (English + multilingual ONNX), and file path
analysis. Detected PII can be redacted, pseudonymized, or blocked.
The PII pipeline covers tool responses, memory storage, audit logs,
embeddings, and model reasoning text. GDPR tools (`pii_report`,
`memory_purge_pii`, `pii_consent`) support data subject rights.
See [DESIGN.md](DESIGN.md#content-safety) for details.

### Further reading

See [DESIGN.md](DESIGN.md) for the full security model: defense in
depth layers, threat model, content safety filtering, IFC, and
the approval workflow.

## Workspace

| Crate | Role |
|---|---|
| `smgglrs-protocol` | MCP/A2A/JSON-RPC types, upstream client transports |
| `smgglrs-model` | Model backend trait + ONNX/OpenAI/Anthropic implementations |
| `smgglrs-model-hub` | Pull/cache models from OCI, HuggingFace, Ollama registries |
| `smgglrs-model-runtime` | Serve models via llama-server, Podman, or libkrun |
| `smgglrs-security` | Auth, permissions, IFC, safety filters, hook pipeline |
| `smgglrs-cognitive` | Persona/directive/heuristic YAML loader + prompt weaver |
| `smgglrs-memory` | Working memory (conversation turns) + knowledge store (FTS5) |
| `smgglrs-agent` | Client SDK: agent builder, MCP client, tool-use loop |
| `smgglrs-flow` | Multi-agent flows: DAG execution, handoff routing, mesh |
| `smgglrs-core` | MCP server, module trait, session, transport |
| `smgglrs-tools-docs` | Document tools, SQLite FTS5 + sqlite-vec |
| `smgglrs-tools-git` | Git tools (status, diff, log, branch, commit) |
| `smgglrs-rag` | Vector search, sqlite-vec, semantic chunking |
| `smgglrs-modal-voice` | Speech I/O (ASR + TTS via ONNX models) |
| `smgglrs-modal-vision` | Image/screen understanding (GPU tier) |
| `smgglrs-responses` | Open Responses API types (spec-compliant, no runtime) |
| `smgglrs-server` | CLI, config, module wiring, systemd, tray |

## Documentation

- [DESIGN.md](DESIGN.md) — full architecture, protocol, security model, config reference
- [ROADMAP.md](ROADMAP.md) — gap analysis vs Python Myelix, phased migration plan
- [MODELS.md](MODELS.md) — model integration architecture, CPU/GPU tiers, hardware profiles
- [DISCOVERY.md](DISCOVERY.md) — agent/tool discovery landscape (AID, A2A, MCP Server Cards)
- [OPENSHELL.md](OPENSHELL.md) — OpenShell integration for sandboxed agent execution

## License

[BSD-3-Clause](LICENSE)
