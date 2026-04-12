# Myelix Rust Roadmap

This document tracks the evolution of the myelix-* crate family from
an MCP gateway (mcpd) into a complete multi-agent orchestration
platform — the Rust replacement for the Python Myelix framework.

## Current state (2026-04-12)

14 crates, 593 tests, ~32K LoC.

### Infrastructure (complete)

| Crate | Status | What it does |
|-------|--------|-------------|
| myelix-protocol | Done | MCP/A2A types, upstream client (stdio/HTTP/SSE + retry) |
| myelix-model | Done | ModelBackend trait, ONNX (in-process), OpenAI-compat, Anthropic (direct + Vertex AI) |
| myelix-model-hub | Done | Pull/cache models from OCI, HuggingFace, Ollama registries |
| myelix-model-runtime | Done | Serve models via llama-server, Podman, or libkrun (stub) |
| myelix-security | Done | Auth (BLAKE3, capability tokens, DID:key), ACLs, IFC with trusted paths, safety filters, hooks |
| myelix-core | Done | MCP server, module trait, session, IFC value store, transport |
| myelix-server | Done | Gateway binary (mcpd), config, model hub/runtime integration, CLI |

### Client & Orchestration (v1 complete)

| Crate | Status | What it does |
|-------|--------|-------------|
| myelix-agent | Done | Client SDK: Agent builder, McpClient with taint tracking, ReAct tool-use loop |
| myelix-flow | Done (v1) | Handoff-based multi-agent flows, TOML config, sequential routing |

### Tools & Modalities (scaffolded)

| Crate | Status | What it does |
|-------|--------|-------------|
| myelix-tools-docs | Done | Document CRUD, FTS5, sqlite-vec |
| myelix-tools-git | Done | Git status, diff, log, branch, commit |
| myelix-rag | Done | Vector search, semantic chunking |
| myelix-modal-voice | Scaffolded | ASR + TTS via ONNX (Whisper, Piper) |
| myelix-modal-vision | Scaffolded | Image understanding (GPU tier) |

---

## Gap analysis: Python Myelix → Rust

The Python Myelix (294 files, 64K LoC) has capabilities that the Rust
crate family does not yet replicate. This section maps each gap to a
planned crate or enhancement.

### What Rust already does better

- **Security**: Python has none. Rust has full auth, IFC, capability
  tokens, trusted paths, safety filters, hooks.
- **Protocol**: Python wraps HTTP. Rust has stdio/HTTP/SSE + resilient
  reconnection, A2A Agent Cards, AID discovery, mDNS.
- **Model management**: Python is manual. Rust pulls from registries
  and serves with container isolation.
- **Gateway**: Python is client-only. Rust has a full MCP gateway
  aggregating upstream servers with unified security.

### What's missing

| Python Myelix capability | Rust equivalent | Gap |
|--------------------------|----------------|-----|
| Cognitive core (40 personas, 36 heuristics, 8 directives) | None | **Critical** |
| Weaver (persona + context → structured prompt) | System prompt strings | **Critical** |
| Task decomposition (recursive planning, scope partitioning) | Handoff only | **High** |
| DAG execution (parallel tasks with dependencies) | Sequential handoffs | **High** |
| Persistent memory (working, long-term, cases) | Session value store | **Medium** |
| Anti-drift (mandate validation, drift detection) | None | **Medium** |
| Failure recovery (circular fix detection, attempt history) | Max iterations | **Medium** |
| Observability (structured metrics, monitoring) | tracing only | **Low** |
| TUI (rich terminal interface) | CLI only | **Low** |

---

## Roadmap

### Phase 1: Cognitive core (myelix-cognitive)

**Goal**: Load persona/directive/heuristic YAML files, compile them
into structured system prompts, and integrate with myelix-agent.

New crate: `myelix-cognitive`

- YAML schema for personas (name, mandate, heuristics, skills)
- YAML schema for directives (rules, constraints, output format)
- YAML schema for heuristics (domain-specific reasoning patterns)
- Forge: loader, compiler, validator, cache
- Weaver: assemble persona + directives + heuristics + context →
  structured system prompt (with cache-friendly prefix splitting)
- Integration with myelix-agent: `Agent::builder().persona("analyst")`
- Port the 40 personas, 8 directives, 36 heuristics from Python

**Why first**: The cognitive core is Myelix's identity. Without it,
agents are generic. Every other feature builds on top of personas.

### Phase 2: DAG execution (myelix-flow v2)

**Goal**: Upgrade myelix-flow from sequential handoffs to parallel
task DAGs with dependency resolution.

Enhance `myelix-flow`:

- Task struct: id, specialist (persona), mandate, depends_on,
  inputs, expected_output, success_criteria
- DependencyGraph: topological sort, cycle detection, parallel level
  analysis (replace networkx with petgraph)
- Parallel executor: run independent tasks concurrently via
  tokio::spawn, collect results, feed to dependents
- Scope partitioning: predict which files/modules a task modifies,
  detect conflicts, serialize conflicting tasks
- Spec injection: attach reference docs to task context

**Why second**: The flow engine is the orchestration backbone. DAG
execution enables the complex multi-agent workflows that Python
Myelix uses for software engineering tasks.

### Phase 3: Persistent memory (myelix-memory)

**Goal**: Working memory that survives sessions, backed by SQLite.

New crate: `myelix-memory`

- Working memory: key-value store scoped to agent + session
- Long-term memory: semantic search over past interactions (RAG)
- Case-based reasoning: index of past problem→solution pairs
- Memory MCP tools: `memory_store`, `memory_recall`, `memory_search`
- Integration: agents auto-load relevant memory into context

**Why third**: Memory improves agent quality significantly but isn't
blocking — agents work without it, just less effectively.

### Phase 4: Mandate validation & failure recovery

**Goal**: Ensure agents stay on task and recover from failures.

Enhance `myelix-flow` and `myelix-agent`:

- Mandate validator: check agent output against success_criteria
  before accepting (LLM-as-judge or rule-based)
- Drift detector: compare agent actions against mandate, flag
  divergence
- Failure classifier: categorize failures (timeout, wrong output,
  circular fix, external dependency)
- Attempt history: track fix attempts, detect circular patterns
- Recovery strategies: retry with modified prompt, escalate to
  human, skip and continue

### Phase 5: Paper & benchmarks

- Final LoC counts for all crates
- Latency benchmarks (IFC overhead, hook pipeline, permission checks)
- Comparison with MS Governance Toolkit
- Security evaluation: attack surface, threat model
- Peer review

---

## Crate dependency diagram (planned)

```
myelix-protocol          (no myelix deps)
myelix-model             (no myelix deps)
myelix-model-hub         (no myelix deps)
myelix-model-runtime     (no myelix deps)
    ↓
myelix-security          (protocol + model)
    ↓
myelix-cognitive         (security)             PERSONAS
myelix-agent             (protocol + model + security)  CLIENT
myelix-memory            (security + rag)       PERSISTENCE
    ↓
myelix-flow              (agent + cognitive + memory)   ORCHESTRATION
myelix-core              (protocol + model + security)  SERVER
    ↓
myelix-tools-*  ─────┐
myelix-rag      ─────┼── (core only)
myelix-modal-*  ─────┘
    ↓
myelix-server            (all + hub + runtime)
```

## Non-goals

These capabilities from Python Myelix are intentionally NOT replicated:

- **Docker deployment**: Rust binary is self-contained
- **Python engine wrappers**: replaced by ModelBackend trait
- **Rich TUI**: CLI is sufficient; TUI can be a separate project
- **A2A server**: mcpd already serves Agent Cards; A2A orchestration
  belongs in myelix-flow, not as a separate service
