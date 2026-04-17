# Myelix Rust Roadmap

This document tracks the evolution of the myelix-* crate family from
an MCP gateway (mcpd) into a complete multi-agent orchestration
platform — the Rust replacement for the Python Myelix framework.

## Current state (2026-04-15)

14 crates, 705 tests, ~33K LoC.

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
| myelix-flow | Done (v2) | Multi-agent flows: handoff routing, DAG execution, mesh communication (mailbox, blackboard, back-edges), IFC-gated, mandate validation |

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
| Task decomposition (recursive planning, scope partitioning) | DAG executor + back-edges | **Partial** (scope partitioning not yet done) |
| DAG execution (parallel tasks with dependencies) | DagExecutor with DependencyGraph | **Done** |
| Mesh communication (lateral agent messaging) | Mailbox + Blackboard (IFC-gated) | **Done** |
| Persistent memory (working, long-term, cases) | Session value store | **Medium** |
| Anti-drift (mandate validation, drift detection) | Mandate validator + success_criteria | **Done** |
| Failure recovery (circular fix detection, attempt history) | Attempt history, circular fix detector, recovery strategies | **Done** |
| Observability (structured metrics, monitoring) | tracing only | **Low** |
| TUI (rich terminal interface) | CLI only | **Low** |

---

## Roadmap

### Phase 1: Cognitive core (myelix-cognitive)

**Goal**: Load persona/directive/heuristic YAML files, compile them
into structured system prompts, and integrate with myelix-agent.

New crate: `myelix-cognitive` (**Status**: Forge + Weaver done,
specializations done, output schema done, per-phase model done.
Missing: context management, token budgeting, per-phase context limits.)

#### 1a. Context management and token budgeting (NEW)

Add to the Weaver:

- **Token budget allocator**: Slot-based system with priority order:
  system prompt (fixed) > conversation history (reserved) > retrieved
  docs (remaining). Prevents silent overflow and coherence collapse.
- **Context compaction**: Auto-summarize old conversation turns when
  approaching token limit (triggered at configurable threshold,
  default 80%). Summarize tool outputs older than N calls.
- **Per-phase context limits**: Add `planning_context_limit` and
  `execution_context_limit` fields to Persona YAML schema, alongside
  existing `planning_model` / `execution_model`.
- **Extractive compression**: Query-aware sentence selection within
  budget, returned in document order (not relevance order).

Reference: Goose auto-compaction model, tech watch article on
context layers (2026-04-17).

#### 1b. Remaining cognitive items

- Integration with myelix-agent: `Agent::builder().persona("analyst")`
- Port the 40 personas, 8 directives, 36 heuristics from Python

**Why first**: The cognitive core is Myelix's identity. Without it,
agents are generic. Every other feature builds on top of personas.

### Phase 2: DAG execution & mesh communication (myelix-flow v2) ✓

**Status**: Core done. Enhancements planned.

Implemented in `myelix-flow`:

- Task struct: id, specialist, mandate, depends_on, inputs,
  expected_output, success_criteria, back_edges
- DependencyGraph: topological sort (Kahn's algorithm), cycle
  detection, transitive dependent tracking
- DagExecutor: dependency-ordered execution, parallel readiness
  detection (true parallelism blocked by Agent `&mut self` — future work)
- Iterative executor: scout→map→reduce with convergence detection
- Agent mailbox: IFC-gated lateral messaging (Bell-LaPadula
  no-write-down), per-agent mpsc channels, audit log
- Shared blackboard: flow-level key-value store with per-entry
  IFC labels, taint-on-read (lattice join)
- Conditional back-edges: post-completion routing with bounded
  iterations (ScoreBelow, CriteriaMissing, OutputContains, Always)
- Virtual mesh tools: mesh_post, mesh_recv, bb_publish, bb_read,
  bb_keys injected into agent tool lists
- 112 tests including cross-primitive IFC integration tests

**Remaining**: Scope partitioning (predict file conflicts, serialize
conflicting tasks) and true parallel execution across specialists
(`Arc<Mutex<Agent>>` refactor).

#### 2a. YAML flow definitions and shareable format (NEW)

Switch flow definitions from TOML-only to YAML-primary (keep TOML
support via file extension detection — same serde structs):

- Add fields to flow/DAG definitions: `parameters` (Jinja-style
  template variables), `output_json_schema`, `retry` policy,
  `required_extensions` (MCP servers needed to run the flow).
- `myelix flow import-goose <recipe.yaml>` CLI command to convert
  Goose recipes into Myelix flow definitions (with human review).
- YAML is consistent with cognitive core (personas/heuristics).

#### 2b. Dynamic subflow spawning from tool loop (NEW)

Add a `spawn_subflow` virtual tool to the agent tool loop. An agent
inside a tool-use loop can create a single-node DAG on the fly and
execute it as a subflow (uses existing DagExecutor, no new engine).
This gives ad-hoc delegation without requiring static flow files.

- Max depth: 1 (subflows cannot spawn sub-subflows)
- Max concurrent: 10 (configurable)
- Timeout: 5 minutes default
- Isolated context (no shared conversation history)

### Phase 3: Persistent memory (myelix-memory)

**Goal**: Working memory that survives sessions, knowledge
distillation pipeline, case-based reasoning. Backed by SQLite.

New crate: `myelix-memory` (**Status**: WorkingMemory (SQLite turns)
and KnowledgeStore (FTS5 with categories) done. Missing: session
persistence, distillation pipeline, case extraction, memory decay.)

#### 3a. Session persistence (NEW — implement now)

Unify session metadata with working memory in SQLite:

- Add `sessions` table to existing WorkingMemory SQLite database
  (id, agent_identity, client_info, context_label, created_at,
  last_active, initialized)
- `SessionStore` delegates to `WorkingMemory` instead of in-memory
  HashMap. Sessions survive server restarts.
- Session resume: load session + recent turns on reconnect.
- Session expiry: configurable TTL with automatic cleanup.

#### 3b. Knowledge distillation pipeline (port from Python)

Port the 4-stage Knowledge Cultivation Pipeline from Python Myelix
(`memory/cases/pipeline.py`, ADR-049):

1. **Ingestion**: Load session transcripts + external corpus
   (with `manifest.yaml` authority levels)
2. **Synthesis**: AI extracts StructuredCase from conversation
   segments (goal, actions, outcome, lessons_learned)
3. **Reconciliation**: Deduplication, conflict resolution by
   authority level
4. **Forging & Review**: Human-in-the-loop approval before
   promotion to Tier 2b cases or Tier 3 skills

Port data models: StructuredCase, CaseContext, Action, CaseOutcome,
CaseMetadata, CaseSearchResult. Port extractors, reconcilers,
transcript parsers, session segmenters.

This is DIFFERENT from context compaction (Phase 1a). Compaction
is runtime context management. Distillation is offline knowledge
extraction — turning experience into reusable wisdom.

#### 3c. Memory decay and working memory management (NEW)

- Exponential decay for working memory turns:
  `effective = importance * e^(-decay * age) * freshness + relevance_boost`
- Auto-importance scoring on ingestion (domain keywords, length,
  query-token overlap)
- Deduplication via token-overlap similarity threshold (≥0.72)
- Configurable decay rate per agent/session

Reference: Baddeley's episodic buffer model, tech watch article
on context layers (2026-04-17).

#### 3d. Remaining memory items

- Memory MCP tools: `memory_store`, `memory_recall`, `memory_search`
- Integration: agents auto-load relevant memory into context
- Semantic query caching (paraphrase detection to avoid redundant
  retrieval, ~76% savings on duplicate queries)

**Why third**: Memory improves agent quality significantly but isn't
blocking — agents work without it, just less effectively.

### Phase 4: Mandate validation & failure recovery ✓

**Status**: Done.

Implemented in `myelix-flow`:

- Mandate validator: keyword + success_criteria matching with
  scoring (0-100), expected_output length check
- Failure classifier: categorizes agent_error, validation_failed,
  max_iterations, circular_fix
- Attempt history: tracks error/output per attempt
- Circular fix detector: pattern detection across attempts
- Recovery strategies: RetryWithContext, Skip, Abort
- Back-edges: conditional re-execution when validation fails
  (replaces rigid retry with graph-level feedback loops)

### Phase 5: Ecosystem integration

#### 5a. ACP transport (NEW)

Add Agent Client Protocol support to myelix-server:

- ACP is JSON-RPC 2.0 over Streamable HTTP (single `POST /acp`
  endpoint) — same transport as MCP, different method set.
- Methods: `initialize`, `authenticate`, `session/new`,
  `session/load`, `session/prompt` (streaming responses).
- Enables Myelix agents to appear in Zed and JetBrains IDEs
  without building editor plugins.
- Reuses existing Axum HTTP infrastructure from myelix-server.

Reference: ACP spec (github.com/i-am-bee/acp), Goose's
goose-acp crate, JetBrains AI Assistant ACP support.

#### 5b. MCP permission negotiation (NEW — AAIF contribution)

Design and implement a permission negotiation extension for MCP:

- New MCP method: `permissions/request` — an MCP server can request
  elevated permissions from the client (e.g., write access to a path).
- Client-side: present permission request to user, relay decision
  back to server via `permissions/grant` / `permissions/deny`.
- Server-side (mcpd): update ACLs dynamically based on granted
  permissions. Scoped to session, with optional persistence.
- Integrate with Goose's approval model: when Goose is the client,
  its permission prompt maps to `permissions/request`.
- Propose as MCP specification extension to AAIF.

This bridges the gap between Goose's UI-level permission prompts
and mcpd's infrastructure-level ACLs.

#### 5c. Goose-as-frontend integration (NEW — quick build)

Enable Goose desktop app to connect to mcpd as a single MCP
extension over Streamable HTTP:

- mcpd already speaks MCP over HTTP — Goose can connect today.
- Build a Goose extension config snippet and test end-to-end:
  Goose UI → mcpd gateway → downstream tools with full
  auth/ACL/IFC/safety.
- Document the setup for users.
- Capture feedback on: permission flow UX, latency, tool
  discovery, error messages.
- Stretch: build a Goose deeplink (`goose://extension?...`)
  for one-click mcpd installation.

#### 5d. LLM backend expansion (NEW)

Add missing model backends to myelix-model:

| Backend | Transport | Priority |
|---------|-----------|----------|
| **BedockBackend** | AWS SDK (SigV4 auth) | High (enterprise) |
| **SageMakerBackend** | AWS SDK (custom endpoint) | High (enterprise) |
| **MistralBackend** | Mistral API (separate format) | Medium |
| **CliBackend** | Subprocess stdio | Medium |

**CliBackend architecture:**
- Spawn CLI as subprocess: `Command::new("gemini").args(...)`.
- Pipe prompt via stdin or args, capture stdout as response.
- Supports: `claude` (Claude Code), `gemini` (Gemini CLI),
  `codex` (OpenAI Codex), `goose`, any custom CLI command.
- Optional Podman isolation: `--network=none` container wrapping
  the CLI subprocess (reuses myelix-model-runtime isolation).
- Config: `cli_command`, `cli_args_template`, `isolation: "none" |
  "podman"`, `timeout_secs`.

This enables meta-agent orchestration — an agent can delegate to
another agent runtime as a "model backend."

### Phase 6: RAG enhancements

#### 6a. Two-stage retrieval with cross-encoder reranking (NEW)

Add reranking stage to myelix-rag after sqlite-vec retrieval:

- ColBERT-style late interaction (preferred: preindexable, low
  latency, fits ONNX in-process strategy)
- Fallback: MiniLM-L6-v2 cross-encoder as ONNX model
- Domain fine-tuning with hard negatives (~70 examples for
  significant improvement)
- Knowledge distillation: train fast bi-encoder from cross-encoder
  scores for domain-specific use

#### 6b. Semantic query caching (NEW)

Paraphrase-detection model to identify duplicate queries at
retrieval time. ~76% savings on redundant ranking operations.
Particularly valuable in multi-agent flows where agents rephrase
similar queries.

### Phase 7: Paper & benchmarks

- Final LoC counts for all crates
- Latency benchmarks (IFC overhead, hook pipeline, permission checks)
- Comparison with MS Governance Toolkit
- Security evaluation: attack surface, threat model
- Use Goose as baseline: "agent without infrastructure security"
  vs mcpd as "security microkernel"
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

## Ecosystem positioning

mcpd is infrastructure, not an end-user agent. Desktop agents
(Goose, Claude Code, etc.) connect to mcpd as an MCP server.
mcpd provides the security layer; the agent provides the UX.

```
Goose (desktop)  ──┐              ┌── downstream MCP servers
Claude Code      ──┼── MCP/ACP ──> mcpd ──┼── built-in modules
Zed/JetBrains    ──┘              └── local ONNX models
```

### Goose relationship (April 2026 analysis)

- Goose: Rust agent runtime (~v1.30, Apache-2.0, AAIF/Linux Foundation)
- Different layer: Goose = end-user agent, mcpd = security gateway
- Goose has NO auth tokens, NO ACLs, NO IFC, NO content filtering
- Goose connects to MCP servers directly (no proxy/filter)
- Contribution targets: MCP interceptor pattern (SEP-1763),
  Linux extension sandboxing, safety hook pipeline, ACL engine
- ACP adoption gives Myelix agents IDE integration for free

## Non-goals

These capabilities from Python Myelix are intentionally NOT replicated:

- **Docker deployment**: Rust binary is self-contained
- **Python engine wrappers**: replaced by ModelBackend trait
- **Rich TUI**: CLI is sufficient; Goose or GNOME shell provides UX
- **A2A server**: mcpd already serves Agent Cards; A2A orchestration
  belongs in myelix-flow, not as a separate service
- **Desktop app**: Goose (or similar) serves as the frontend;
  mcpd handles GNOME integration (D-Bus notifications, tray)
