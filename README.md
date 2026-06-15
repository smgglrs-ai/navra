<p align="center">
  <img src="assets/logo/logo-192.png" alt="navra logo" width="128" />
</p>

<h1 align="center">navra</h1>

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

**navra** is a user-level MCP (Model Context Protocol) gateway that sits
between AI agents and local resources. It aggregates built-in tool modules
and upstream MCP servers behind a unified security layer with authentication,
path ACLs, content safety filtering, human-in-the-loop approval, and a
hook pipeline.

```
AI Agent (Claude Code, Goose, custom agents, ...)
    │
    │  MCP Streamable HTTP + SSE (Unix socket or TCP)
    ▼
navra (gateway)
    ├── Auth (BLAKE3 tokens, capability tokens, DID:key)
    ├── Permission engine (path ACLs, per-tool rules)
    ├── Hook pipeline (pre/post tool-call)
    ├── Safety filters (regex + ML)
    ├── Built-in modules (file, git, exec, RAG, voice, vision)
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

**First 5 minutes** — get navra running and connect Claude Code:

```bash
# 1. Install prerequisites (Fedora)
sudo dnf install onnxruntime-devel

# 2. Build
git clone https://github.com/smgglrs-ai/navra.git && cd navra
export ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1
cargo build

# 3. Start the gateway
cargo run -- serve
# Listening on unix:/run/user/$UID/navra/navra.sock
# Listening on tcp:127.0.0.1:9315
# Web UI at http://localhost:9315

# 4. Generate a token for your agent
cargo run -- token generate --name claude --permissions dev
# Prints an [[agents]] block — paste it into ~/.config/navra/config.toml

# 5. Add a permission set (if not already present)
cat >> ~/.config/navra/config.toml << 'EOF'
[permissions.dev]
allow = ["$HOME/Code/**"]
deny = ["**/.env", "**/.git/config"]
safety = "standard"
EOF

# 6. Restart navra, then point Claude Code at it
```

That's it. navra is now filtering tool calls through auth, path ACLs,
safety filters, and audit logging.

### Prerequisites

- Rust stable (1.75+)
- ONNX Runtime (Fedora: `onnxruntime-devel`, Ubuntu: `libonnxruntime-dev`)
- Linux (systemd + D-Bus for notifications/tray)

## Architecture

navra is a Rust workspace of 20 crates organized in strict dependency
layers:

```
navra-protocol          (no internal deps)
navra-model-hub         (no internal deps)
navra-model-runtime     (no internal deps)
navra-responses         (no internal deps)
navra-cognitive         (no internal deps)
navra-macros            (no internal deps, proc-macro)
    ↓
navra-model             (responses)
    ↓
navra-security          (protocol + model)
    ↓
navra-core              (protocol + model + security)  Server
    ↓
navra-memory            (core + model, opt: rag)       Persistence
navra-agent             (protocol + model + security   Client SDK
                           + cognitive)
navra-tools-file ───┐
navra-tools-git  ───┤
navra-tools-exec ───┼── (core, exec also: model-runtime)
navra-rag        ───┤
navra-modal-*    ───┘── (core only)
    ↓
navra-flow              (agent + cognitive + protocol  Orchestration
                           + model + security)
    ↓
navra-server            (all + hub + runtime)          Binary
benchmarks                (dev only)
```

### Key design decisions

- All capabilities are **modules** implementing the `Module` trait.
  Upstream MCP servers are wrapped in `UpstreamModule`.
- Content filtering runs as `SafetyHook` in the hook pipeline, not
  hardcoded in the request path.
- Resilient upstream transports with exponential backoff, timeout,
  reconnection, and sleep detection.
- **Agent isolation**: agents can run in Podman containers
  (`navra-agent` binary) with a shared model server (GPU) and
  per-agent sandboxes (no GPU). See [DESIGN.md](DESIGN.md) for details.

## Configuration

Default config path: `~/.config/navra/config.toml`

```toml
[server]
tcp = "127.0.0.1:9315"   # Unix socket is the default transport

[modules.file]
enabled = true

[modules.git]
enabled = true

[[agents]]
name = "claude"
token_hash = "..."       # navra token --name claude
permissions = "dev"       # references [permissions.dev] below

[permissions.dev]
allow = ["/home/user/projects/**"]
deny = ["/home/user/projects/.env"]
safety = "standard"

[[upstream]]
name = "filesystem"
command = ["npx", "-y", "@anthropic/mcp-fs"]
```

See [DESIGN.md](DESIGN.md) for the full configuration reference.

## Security

### Transport security

navra's default transport is a **Unix domain socket** with `0600`
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

navra detects and handles PII across three layers: regex patterns
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
| `navra-protocol` | MCP/A2A/JSON-RPC types, upstream client transports |
| `navra-model` | Model backend trait + ONNX/OpenAI/Anthropic implementations |
| `navra-model-hub` | Pull/cache models from OCI, HuggingFace, Ollama registries |
| `navra-model-runtime` | Serve models with pluggable isolation (direct, Podman, OpenShell) |
| `navra-responses` | Open Responses API types (spec-compliant, no runtime) |
| `navra-security` | Auth, permissions, IFC, safety filters, hook pipeline |
| `navra-cognitive` | Persona/directive/heuristic YAML loader + prompt weaver |
| `navra-memory` | Working memory (conversation turns) + knowledge store (FTS5) |
| `navra-agent` | Client SDK: agent builder, MCP client, ReAct tool-use loop |
| `navra-flow` | Multi-agent flows: DAG execution, handoff routing, mesh |
| `navra-core` | MCP server, module trait, session, transport |
| `navra-tools-file` | File tools, SQLite FTS5 + sqlite-vec, MCP resources |
| `navra-tools-git` | Git tools (status, diff, log, branch, commit) |
| `navra-tools-exec` | Command execution inside OpenShell sandboxes |
| `navra-tools-gitlab` | GitLab forge tools (MR, issues) via `glab` CLI |
| `navra-rag` | Vector search, sqlite-vec, semantic chunking, reranking |
| `navra-modal-voice` | Speech I/O (ASR + TTS via ONNX models) |
| `navra-modal-vision` | Image/screen understanding (GPU tier) |
| `navra-macros` | `#[tool]` proc macro for tool definition generation |
| `navra-server` | CLI, config, module wiring, systemd, tray |
| `benchmarks` | Criterion performance benchmarks |

## Documentation

- [WHY-NAVRA.md](WHY-NAVRA.md) — what navra does differently and why it exists
- [CONFIG.md](CONFIG.md) — complete configuration reference (every TOML key, type, default)
- [CHANGELOG.md](CHANGELOG.md) — project history by month
- [DESIGN.md](DESIGN.md) — full architecture, protocol, security model
- [TESTING.md](TESTING.md) — test prerequisites, running tests, crate test counts
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guidelines, commit conventions, DCO
- [SECURITY.md](SECURITY.md) — vulnerability disclosure policy
- [ROADMAP.md](ROADMAP.md) — phased development plan
- [MODELS.md](MODELS.md) — model integration architecture, CPU/GPU tiers, hardware profiles
- [DISCOVERY.md](DISCOVERY.md) — agent/tool discovery landscape (AID, A2A, MCP Server Cards)
- [OPENSHELL.md](OPENSHELL.md) — OpenShell integration for sandboxed agent execution
- [examples/config.toml](examples/config.toml) — annotated starter configuration
- [llms.txt](llms.txt) — AI-friendly documentation index ([spec](https://llmstxt.org/))

## License

[Apache License 2.0](LICENSE)
