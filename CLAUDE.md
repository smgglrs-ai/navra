# navra

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
| `navra-protocol` | Infrastructure | MCP/A2A/JSON-RPC types, upstream client transports |
| `navra-model` | Infrastructure | Model backend trait + ONNX/OpenAI/Anthropic implementations |
| `navra-model-hub` | Infrastructure | Pull/cache models from OCI, HuggingFace, Ollama registries |
| `navra-model-runtime` | Infrastructure | Serve models with pluggable isolation (direct, Podman, OpenShell) |
| `navra-responses` | Infrastructure | Open Responses API types (spec-compliant, no client, no runtime) |
| `navra-security` | Infrastructure | Auth, permissions, IFC, safety filters, hooks, upstream tool scanning, cognitive file integrity monitoring |
| `navra-cognitive` | Cognitive | Persona/directive/heuristic YAML loader + prompt weaver |
| `navra-memory` | Persistence | Working memory (conversation turns) + knowledge store (FTS5) |
| `navra-agent` | Client | Agent builder, MCP client, ReAct tool-use loop, deterministic replay, standalone binary (`Dockerfile.agent`) |
| `navra-flow` | Orchestration | Multi-agent flows: handoff routing, DAG execution, mesh communication (mailbox, blackboard, back-edges), mandate validation, hop limits, provenance tracking |
| `navra-core` | Infrastructure | Server, module trait, session, transport, Prometheus metrics, OTel traces, re-exports |
| `navra-tools-file` | Tool | File tools (file_read, file_write, etc.), SQLite FTS5 + sqlite-vec, MCP resources for file:// URIs |
| `navra-tools-git` | Tool | Git tools (status, diff, log, branch, commit, push, pull, fetch) |
| `navra-tools-exec` | Tool | Command execution inside OpenShell sandboxes |
| `navra-rag` | Context enrichment | Hybrid FTS5+vector search (RRF fusion), breadcrumb chunking, cross-encoder reranking (batched), confidence gating |
| `navra-modal-voice` | Modality | Speech I/O (ASR + TTS via ONNX models) |
| `navra-modal-vision` | Modality | Image/screen understanding (GPU tier) |
| `navra-macros` | Dev tooling | `#[tool]` proc macro for generating tool definitions from functions |
| `navra-tools-github` | Tool | GitHub forge tools (PR create/list/view, issue create/list/comment) via `gh` CLI |
| `navra-tools-gitlab` | Tool | GitLab forge tools (MR, issues) via `glab` CLI |
| `navra-server` | Binary | CLI, config, module wiring, systemd, tray, Prometheus /metrics (binary: `navra`) |
| `benchmarks` | Dev tooling | Criterion performance benchmarks |

### Dependency layering

```
navra-protocol          (no navra deps)
navra-model-hub         (no navra deps)
navra-model-runtime     (no navra deps)
navra-responses         (no navra deps)
navra-cognitive         (no navra deps)
navra-macros            (no navra deps, proc-macro)
    ↓
navra-model             (responses)
    ↓
navra-security          (protocol + model)
    ↓
navra-core              (protocol + model + security)  SERVER
    ↓
navra-memory            (core + model, opt: rag)       PERSISTENCE
navra-agent             (protocol + model + security   CLIENT
                           + cognitive)
navra-tools-file ───┐
navra-tools-git  ───┤
navra-tools-exec ───┼── (core, exec also: model-runtime)
navra-rag        ───┤
navra-modal-*    ───┘── (core only)
    ↓
navra-flow              (agent + cognitive + protocol  ORCHESTRATION
                           + model + security)
    ↓
navra-server            (all + hub + runtime)
```

## Architecture

navra is an MCP gateway that sits between AI agents and local
resources. It aggregates built-in modules and upstream MCP servers
behind a unified security layer.

```
AI Agent (Claude Code, etc.)
    |
    | MCP Streamable HTTP + SSE (Unix socket or TCP)
    v
navra-server / navra (gateway)
    |-- Auth (BLAKE3 tokens, OAuth 2.0, capability delegation)
    |-- Permission engine (path ACLs, tool rules, Cedar)
    |-- Hook pipeline (pre/post tool-call)
    |-- Safety filters (regex + ML + NER)
    |-- Upstream tool scanning (8 threat categories)
    |-- Cognitive file integrity monitoring
    |-- Built-in modules (file, git, exec, rag, voice, vision, github)
    |-- Upstream MCP servers (proxied, safety-filtered, scanned)
    |-- Prometheus /metrics + OTel traces
    |-- Discovery (AID, mDNS, MCP registry)
    v
Desktop (D-Bus notifications, system tray, systemd)
```

## Key Design Decisions

- **Gateway, not framework**: navra enforces security at the
  infrastructure layer. Orchestration belongs in the agent.
- **Module trait**: All capabilities are modules implementing
  `Module` trait. Upstream MCP servers are wrapped in `UpstreamModule`.
- **Deny-wins ACLs**: Path deny rules always beat allow rules.
  Canonicalization before ACL check prevents traversal.
- **Safety is a hook**: Content filtering runs as `SafetyHook` in
  the hook pipeline, not hardcoded in the request path.
- **In-process models**: Small ONNX models (safety, embeddings)
  load directly into the navra process. No external dependencies
  for CPU tier.

## Agent Workflow (MANDATORY)

### Commit after every verified feature

After tests pass for a feature, commit immediately. Never accumulate
unstaged changes across multiple features. One feature = one commit.

```bash
git add -A && git commit -s -m "description"
```

### Agents must commit in their worktrees

Every agent prompt MUST include this instruction:

> Before finishing, commit all your changes:
> `git add -A && git commit -s -m "your summary"`

This ensures the worktree branch survives cleanup. Without a commit,
worktree removal destroys all agent work.

### Merge agent work via git merge, not file copy

When an agent completes in a worktree, merge its branch:

```bash
git merge --no-ff worktree-agent-xxx -m "Merge: feature description"
```

Do NOT copy files manually — that loses history, misses files, and
creates merge conflicts with other agents.

### Never let worktrees accumulate

Merge or discard each worktree as soon as the agent completes.
Stale worktrees with uncommitted changes will be lost on cleanup.

## Parallel Development

See `AGENTS.md` for the full agent rules. This section covers
when and how to use parallel workflows.

### When to use parallel agents

- **Yes**: independent crate work (e.g., add tests to navra-rag
  while documenting navra-security)
- **Yes**: cross-cutting work with clear file ownership (frontend
  agent + backend agent, each in their own crate)
- **No**: sequential changes where step 2 depends on step 1
- **No**: changes to the same files (will conflict)

### Decomposition by crate boundary

The 22-crate workspace is designed for parallel work. Each crate
has clear file ownership. Decompose tasks along crate boundaries:

```
Task: "Add embedding support to RAG and voice modules"
  Agent 1 (worktree): navra-rag — embedding integration
  Agent 2 (worktree): navra-modal-voice — embedding integration
  Lead (main): Cargo.toml workspace changes, merge results
```

### Plan on main, implement in worktrees

1. Design the approach in the main session
2. Decompose into crate-scoped work packages
3. Spawn agents with `isolation: worktree`, one per crate
4. Each agent implements, tests, and commits in its worktree
5. Lead merges each branch: `git merge --no-ff <branch>`
6. Lead runs full workspace tests after all merges

### Team coordination

For complex features spanning 3+ crates, use Claude Code teams:

1. Lead creates a task list with one task per crate
2. Lead spawns teammates, each assigned to specific crates
3. Teammates work in worktrees, message the lead on completion
4. Lead merges, resolves conflicts, runs integration tests

Keep teams to 3-5 agents. More than that creates merge overhead
that outweighs the parallelism gains.

## Conventions

### Naming

- Tool names are prefixed with module name: `file_read`, `git_status`
- Operations are string-based, module-namespaced: `"read"`, `"git.commit"`
- Config fields use snake_case in TOML

### Error Handling

- Modules return `CallToolResult::error(msg)` for user-facing errors
- Infrastructure errors use `anyhow::Result` in server code
- Model loading failures are logged and skipped (graceful degradation)

### Testing

2400+ tests. See TESTING.md for per-crate unit/integration/e2e
breakdown.

Prerequisites:
- ONNX Runtime (`onnxruntime-devel` on Fedora)
- Ollama with any model for 1 e2e test (`ollama pull qwen2.5:0.5b`)

```bash
# Unit + integration tests
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test --workspace

# Single crate
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-core

# E2e tests (require Ollama running)
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-server --test e2e

# Build with OTel trace export
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build --features otel
# Then: OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 navra serve
```

Conventions:
- Unit tests live in `#[cfg(test)] mod tests` at the bottom of each file
- Integration tests in `tests/` directories per crate
- `echo_tool_def()` and `test_ctx()` helpers are defined locally
  in `navra-core/src/server/tests.rs`; other crates define their own
  `test_ctx()` for constructing `CallContext` in tests
- All async tests use `#[tokio::test]`

### Adding a Module

1. Create crate implementing `Module` trait (from `navra-core`)
2. Add dependency in `navra-server/Cargo.toml`
3. Add config struct in `config.rs`
4. Add `if cfg.xxx_enabled() { builder = builder.module(xxx); }` in `main.rs`

### Adding a Tool

Tools within a module (manual):
1. Define `ToolDefinition` with name, description, input schema
2. Create handler: `Arc<dyn Fn(Value, CallContext) -> Pin<Box<dyn Future<Output = CallToolResult> + Send>> + Send + Sync>`
3. Return `(definition, handler)` pair from `Module::tools()`
4. Tool name must be prefixed with module name

Or use the `#[tool]` proc macro from `navra-macros`:

```rust
#[navra::tool(name = "file_read", description = "Read a file")]
async fn file_read(
    #[arg(description = "Path to the file")] path: String,
    ctx: CallContext,
) -> CallToolResult {
    // ...
}
```

## Config

Default path: `~/.config/navra/config.toml`

Key sections: `[server]`, `[modules.*]`, `[models.*]`, `[[agents]]`,
`[permissions.*]`, `[[upstream]]`, `discover`, `[[registry]]`.

See DESIGN.md for full config reference.

## Related Projects

- **Voice-first local assistant**: Combining navra (secure tools)
  + navra-flow (orchestration) + local models.
- **OpenShell** (Red Hat/NVIDIA): Secure sandbox platform for
  autonomous agents. navra integrates as the tool access layer
  inside OpenShell sandboxes. See `OPENSHELL.md` for design.

## Roadmap

Two files work together:

- **`roadmap.json`** — Machine-readable dependency graph. Every work
  item has an id, priority, status, dependencies, gates, and feeds.
  Use this to determine what to work on next.
- **`ROADMAP.md`** — Human-readable context. Phase descriptions,
  design rationale, historical log. Read this for the *why* behind
  an item. Never duplicate content between the two files.

### Picking next work

Parse `roadmap.json` to find actionable items:

```python
# Item is actionable when:
# 1. status == "pending" (not completed, not parking_lot)
# 2. No gate (or gate has cleared)
# 3. All depends_on items have status == "completed"
# Sort by: priority (P0 > P1 > P2 > P3), then effort (smallest first)
```

When starting work on an item, set its status to `"in_progress"`.
When done, set it to `"completed"`. Commit the JSON change with
the feature commit.

### After a tech watch

New items from tech watches get `TW` prefix IDs (TW1, TW2, ...).
Add them to both files: JSON for the graph, ROADMAP.md dependency
graph section for the chain placement and ASCII diagram.

### Strategic Priorities (2026-06-02)

The code is ahead of the evidence. Pivot from building features to
proving what's built.

**Tier 1 — Prove the claims (June–July)**
1. `11n` model-runtime dimension refactor — technical debt, unblocks backends
2. `TW1` Benchmark OpenAI privacy-filter on 268V NPU — S7 eval baseline
3. `TW2` Evaluate Glasswing adversarial harness — C3 eval methodology
4. `13a` Paper fixes — FIDES differentiation, gateway positioning
5. `TW6` Cedar OWASP policies — 10a paper evidence
6. `C3` External eval on 3+ OSS projects — statistical significance
7. `10a` Security paper — flagship, submit to ArtSec/USENIX workshop

**Tier 2 — Close gaps (July–August)**
8. `9aa` MCP 2026-07-28 default flip — gated on July 28 final spec
9. `U3` GitLab forge module — enterprise reach
10. `15a`+`15b` Rendra app MVP — demo-able end-user experience

**Tier 3 — Ecosystem (Q3–Q4)**
11. First external user deployment
12. Community docs + getting started guide
13. `10b` Persona orchestration paper

Everything else is parking lot unless it directly supports a tier 1–2 item.

## Reference Documents

- `DESIGN.md` — Full architecture, protocol, security model, config reference
- `TESTING.md` — Test prerequisites, running tests, crate test counts (2400+)
- `ROADMAP.md` — Phased development plan, dependency graph, execution waves
- `roadmap.json` — Machine-readable dependency graph (60 items, queryable)
- `MODELS.md` — Model integration architecture, CPU/GPU tiers, hardware profiles
- `DISCOVERY.md` — Agent/tool discovery landscape (AID, A2A, MCP Server Cards)
- `OPENSHELL.md` — OpenShell integration: identity federation, A2A mesh, gRPC modules
- `docs/acp.md` — ACP v0.2.0 implementation: endpoints, security model, differentiators
- `docs/mcp-tunnels.md` — MCP tunnel compatibility (Anthropic + OpenAI)
