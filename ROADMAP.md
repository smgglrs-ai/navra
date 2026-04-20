# Myelix Rust Roadmap

This document tracks the evolution of the myelix-* crate family from
an MCP gateway (mcpd) into a complete multi-agent orchestration
platform — the Rust replacement for the Python Myelix framework.

## Current state (2026-04-20)

17 crates, 788 tests, ~46K LoC. 43 personas, 36 heuristics, 7 directives.

### Infrastructure (complete)

| Crate | Status | What it does |
|-------|--------|-------------|
| myelix-protocol | Done | MCP/A2A types, upstream client (stdio/HTTP/SSE + retry) |
| myelix-model | Done | ModelBackend trait, ONNX (in-process), OpenAI-compat, Anthropic (direct + Vertex AI) |
| myelix-model-hub | Done | Pull/cache models from OCI, HuggingFace, Ollama registries. Composite model cards (vendor + agentic + runtime) |
| myelix-model-runtime | Done | Serve models via llama-server, Podman, or libkrun (stub) |
| myelix-security | Done | Auth (BLAKE3, capability tokens, DID:key), ACLs, IFC with trusted paths, safety filters, hooks |
| myelix-core | Done | MCP server, module trait, session, IFC value store, transport |
| myelix-server | Done | Gateway binary (mcpd), config, model hub/runtime integration, CLI |

### Client & Orchestration (v1 complete)

| Crate | Status | What it does |
|-------|--------|-------------|
| myelix-agent | Done | Client SDK: Agent builder with `.persona()`, McpClient with taint tracking, ReAct tool-use loop, non-progress iterations, scoped capability tokens |
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

## Code health (2026-04-19 audit)

Verified findings from static analysis. These are pre-requisites
for sustainable development and should be addressed before adding
new features.

### Immediate (< 1 day)

| Item | Detail | Effort |
|------|--------|--------|
| `rust-toolchain.toml` + `rustfmt.toml` | Pin toolchain, enforce formatting | 10 min |
| Fix 88 clippy warnings | ~60 auto-fixable; rest manual (dead code, unused imports, `if let Err(_)` → `.is_err()`, `saturating_sub`) | 30 min |
| Add `justfile` | Targets: `build`, `test`, `clippy`, `fmt` — all set `ORT_LIB_PATH` and `ORT_PREFER_DYNAMIC_LINK` automatically | 30 min |
| ~~Replace `.lock().unwrap()`~~ | ~~Done~~ — all converted to `.unwrap_or_else(\|e\| e.into_inner())` across store, dbus, approval, blackboard, mailbox, SSE, TaskStore, SessionStore | ✅ |

### Short-term (1-2 days)

| Item | Detail | Effort |
|------|--------|--------|
| Extract auth middleware in `ui.rs` | 5 `authenticate(&headers)` blocks added (was missing entirely). Refactor to middleware layer | 1h |
| GitHub Actions CI | `cargo check` + `clippy -D warnings` + `fmt --check` + `test`. Needs ONNX in CI (system package or download-binaries feature) | 1-2h |
| ~~Split `main.rs`~~ | ~~Done~~ — extracted `cli.rs` (304), `demo.rs` (700+), `ui.rs` (296). main.rs now ~2400 lines | ✅ |
| Make hardcoded values configurable | Approval TTL (fixed 5 min in `approval.rs`), file watcher skip-list (hardcoded in `watcher.rs`) → config.toml | 1h |

### Security fixes completed (2026-04-17 through 2026-04-19)

50+ findings fixed across 6 self-audit rounds:

- Hook timeout fail-closed (was fail-open)
- /api/* routes require authentication
- Session enforcement for all MCP methods
- A2A task ownership checks
- Scoped capability tokens for teammates
- JoinHandle tracking with abort on shutdown/timeout
- Graceful shutdown (SIGTERM/SIGINT)
- Symlink skipping in recursive walkers
- IFC canonicalize before glob matching
- Permission checks added to RAG, vision, voice handlers
- Pagination overflow protection
- Identity key CWD fallback → error
- Path leak via strip_prefix → skip
- Retry jitter (±25%) to prevent thundering herd
- Model adapter dedup (shared http_common module)
- Missing docs warnings on 3 crates

### Remaining

| Item | Detail | Effort |
|------|--------|--------|
| `rust-toolchain.toml` + `rustfmt.toml` | Pin toolchain, enforce formatting | 10 min |
| Fix clippy warnings | Auto-fixable dead code, unused imports | 30 min |
| Add `justfile` | Targets: build, test, clippy, fmt with ORT env vars | 30 min |
| Extract auth middleware in `ui.rs` | 5 inline auth checks → single Axum layer | 1h |
| Feature-gate ONNX | Decouple `ort` from crates that don't directly use it | Architecturally invasive; revisit when CI is live |
| GitHub Actions CI | cargo check + clippy + fmt + test | 1-2h |
| Per-teammate operation scoping | `team_add` accepts operations/tools per teammate, token minted accordingly | Design needed |

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
| Cognitive core (40 personas, 36 heuristics, 8 directives) | 43 personas, 36 heuristics, 7 directives + Forge + Weaver | **Done** |
| Weaver (persona + context → structured prompt) | Weaver with budget-aware context, per-phase limits | **Done** |
| Task decomposition (recursive planning, scope partitioning) | DAG executor + back-edges | **Partial** (scope partitioning not yet done) |
| DAG execution (parallel tasks with dependencies) | DagExecutor with DependencyGraph | **Done** |
| Mesh communication (lateral agent messaging) | Mailbox + Blackboard (IFC-gated) | **Done** |
| Persistent memory (working, long-term, cases) | SQLite session store + working memory | **Partial** (knowledge distillation pipeline missing) |
| Anti-drift (mandate validation, drift detection) | Mandate validator + success_criteria | **Done** |
| Failure recovery (circular fix detection, attempt history) | Attempt history, circular fix detector, recovery strategies | **Done** |
| Observability (structured metrics, monitoring) | tracing only | **Low** |
| TUI (rich terminal interface) | CLI only | **Low** |

---

## Roadmap

### Phase 1: Cognitive core (myelix-cognitive)

**Goal**: Load persona/directive/heuristic YAML files, compile them
into structured system prompts, and integrate with myelix-agent.

New crate: `myelix-cognitive` (**Status**: Complete.
Forge + Weaver, specializations, output schema, per-phase model,
token budgeting, context compaction, per-phase context limits,
43 personas (38 from Python + 5 general-purpose), agent `.persona()` builder.)

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

#### 1c. Persona evolution via momentum-based adaptation (NEW)

Add dynamic persona adaptation inspired by PersonaVLM's Personality
Evolving Mechanism (PEM). Personas accumulate interaction-derived
traits over time rather than staying static YAML:

- **Trait vector**: Each persona maintains a vector of behavioral
  scores (e.g., verbosity, formality, risk tolerance) alongside
  its YAML definition.
- **Momentum update**: After each session, extract observed behavioral
  signals and update the trait vector with exponential moving average:
  `trait_new = α * observed + (1 - α) * trait_old` (α configurable,
  default 0.1 for slow adaptation).
- **Prompt injection**: Weaver reads the trait vector and adjusts
  prompt emphasis (e.g., a persona that evolves toward conciseness
  gets stronger brevity instructions).
- **Reset/freeze**: Users can freeze a persona's evolution or reset
  to YAML defaults. Trait history stored in SQLite for auditability.
- **Scope**: Per-user persona evolution (same persona can evolve
  differently for different users).

This is NOT personality simulation — it's adaptive calibration of
agent behavior based on accumulated feedback signals.

Reference: PersonaVLM (arXiv 2604.13074), Personality Evolving
Mechanism with Big Five momentum-based updates.

#### 1d. Lazy-loading persona specializations (NEW)

Inactive persona specializations are represented as name +
description only. Full specialization content (prompts, heuristics,
output schemas) is loaded into context only when the Weaver
activates that specialization:

- **Catalog**: On startup, index all specialization YAML files
  but store only metadata (name, description, trigger conditions).
- **On-demand loading**: When the Weaver selects a specialization
  for prompt assembly, load the full YAML content.
- **Context savings**: Reduces baseline context overhead for personas
  with many specializations (some personas have 5+ specializations).

Reference: SemaClaw skill lazy-loading (arXiv 2604.11548).

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

#### 3b. Memory type classification and keyed supersession (NEW)

Classify memories into typed categories with distinct lifecycle
semantics, inspired by Cloudflare Agent Memory and the Memory
Transfer Learning paper (arXiv 2604.14004):

- **4 memory types**: Facts (keyed, supersede on update), Events
  (timestamped, append-only), Instructions (procedural, versioned),
  Insights (abstract behavioral principles, highest transfer value).
- **Keyed supersession**: Facts and Instructions use content-addressed
  keys (SHA-256). New versions supersede old ones in a version chain,
  preserving history but surfacing latest.
- **Abstraction over traces**: Store high-level Insights ("always
  validate patches before applying") rather than raw action
  trajectories. The MTL paper proves 431 abstract memories outperform
  5.8k raw traces, and raw trajectories cause negative transfer
  (domain-mismatched anchoring, false validation confidence).
- **Ingestion pipeline**: Content-addressed ID → parallel full+detail
  extraction → 8 verification checks → classification → async
  vectorization.

Reference: Cloudflare Agent Memory (2026-04-19), KAIST/NYU Memory
Transfer Learning (arXiv 2604.14004).

#### 3c. Multi-channel retrieval with RRF fusion (NEW)

Replace single-channel vector search with fused multi-channel
retrieval using Reciprocal Rank Fusion:

- **6 retrieval channels** (run in parallel):
  1. Full-text search (existing FTS5)
  2. Fact-key lookup (exact match on keyed facts)
  3. Raw message search (substring match on stored turns)
  4. Direct vector search (existing sqlite-vec)
  5. HyDE — Hypothetical Document Embedding (generate ideal answer,
     embed that, search for similar stored memories)
  6. Temporal retrieval — time-based filtering and recency weighting
     for queries with temporal cues ("this morning", "last week",
     "before the refactor"). Parse temporal expressions into time
     ranges, filter memories by timestamp, boost recency.
- **RRF fusion**: Merge ranked lists from all channels using
  `score = Σ 1/(k + rank_i)` with k=60. No per-channel weight
  tuning needed.
- **Temporal weighting**: When a query contains temporal expressions,
  the temporal channel gets elevated rank contribution in the RRF
  fusion (effectively k=30 instead of k=60 for temporal results).
- Top-N results after fusion feed into context.

Reference: Cloudflare Agent Memory RRF design (2026-04-19),
PersonaVLM temporal-aware retrieval (arXiv 2604.13074).

#### 3d. Knowledge distillation pipeline (port from Python)

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

**Output format**: Distilled knowledge stored as plain Markdown
files with YAML frontmatter (type, name, description, source,
created_at). Directory hierarchy represents topic taxonomy.
User-editable, version-controllable, locally inspectable —
no proprietary database intermediation.

Reference: SemaClaw wiki-based knowledge infrastructure
(arXiv 2604.11548).

This is DIFFERENT from context compaction (Phase 1a). Compaction
is runtime context management. Distillation is offline knowledge
extraction — turning experience into reusable wisdom.

#### 3e. Memory decay and working memory management (NEW)

- Exponential decay for working memory turns:
  `effective = importance * e^(-decay * age) * freshness + relevance_boost`
- Auto-importance scoring on ingestion (domain keywords, length,
  query-token overlap)
- Deduplication via token-overlap similarity threshold (≥0.72)
- Configurable decay rate per agent/session

Reference: Baddeley's episodic buffer model, tech watch article
on context layers (2026-04-17).

#### 3f. Model-aware context compaction strategies (NEW)

Different models respond best to different compaction strategies.
Instead of a fixed approach, support multiple strategies with
adaptive selection:

- **3 candidate strategies**: Keep-Last-N, Summary, Discard-All
- **Model-aware defaults**: Configure preferred strategy per model
  backend (e.g., summary-heavy for DeepSeek, aggressive discard
  for GPT-class models).
- **Optional lookahead routing**: At compaction trigger points, run
  K=3 additional turns with each strategy in parallel, select the
  branch with best continuation quality. Trade token cost for
  precision.
- **Efficiency-precision decomposition**: Aggressive compaction
  hurts search efficiency but boosts terminal precision;
  conservative approaches do the opposite. Make this tradeoff
  configurable per flow/agent.

Reference: AgentSwing (Alibaba, arXiv 2603.27490). Their
probabilistic framework: Pass@1 = search_efficiency ×
terminal_precision.

#### 3g. Remaining memory items

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

#### 5e. A2UI generative UI for approval dialogs (NEW)

Use Google's A2UI v0.9 standard for agent-generated UI in tray
notifications, approval dialogs, and permission prompts:

- A2UI is framework-agnostic, transport-agnostic (supports MCP,
  WebSocket, REST, A2A), with renderers for React, Flutter, Lit.
- Agents select from schema catalogs with version negotiation —
  reduces hallucination vs free-form HTML generation.
- Use case: permission prompts (`permissions/request` from 5b)
  rendered as A2UI widgets in Goose/Zed/GNOME tray.
- Lower priority — only relevant once 5a-5c are in place.

Reference: Google A2UI v0.9 (developers.googleblog.com, 2026-04-19).

#### 5f. Registry proxy module (NEW)

Add a `RegistryModule` to mcpd that aggregates external agent/tool
discovery registries behind the gateway's unified security layer:

- **Proxy to external registries**: AWS Agent Registry, Azure Agent
  Registry, MCP Registry — agents behind mcpd get unified discovery
  without needing provider-specific SDK access.
- **Registry as MCP server**: Expose discovery as MCP tools
  (`registry_search`, `registry_list`, `registry_describe`).
- **Hybrid search**: Forward keyword + semantic queries to upstream
  registries, merge results, apply mcpd's ACLs to filter what the
  requesting agent is allowed to discover.
- **Caching**: Cache registry responses locally with configurable
  TTL (default 1h). Avoid hammering external APIs.
- **Multilingual awareness**: Test non-English semantic search
  quality (AWS registry fails 33% of Japanese queries). Use local
  embedding model as fallback for non-English queries.

This fits the gateway pattern — mcpd aggregates discovery sources
just like it aggregates upstream MCP servers.

Reference: AWS Agent Registry (InfoQ, 2026-04-20), DISCOVERY.md.

#### 5g. Multi-agent cross-validation in flows (NEW)

Add cross-validation pattern to myelix-flow for high-stakes
agent outputs:

- After an agent produces a result, spawn N verifier agents in
  parallel to independently assess the output.
- Verifiers flag issues with severity ranking; only surface
  findings that survive cross-validation (consensus or
  majority agreement).
- Anti-hallucination: agents validate each other's claims before
  surfacing to user. Claude Code Review achieves <1% false
  positive rate with this pattern.
- Configurable per-task: `verification: { agents: 2, threshold: "majority" }`

Reference: Claude Code Review multi-agent architecture
(claude.com/blog/code-review, 2026-04-19).

### Phase 5h. Module trait taxonomy review (NEW)

Review whether myelix-core's flat `Module` trait should be split
into a richer taxonomy, inspired by SemaClaw's 4-layer plugin
architecture:

| Layer | SemaClaw | mcpd equivalent | Example |
|-------|----------|-----------------|---------|
| **Action** | MCP Tools | Tool modules (docs, git) | `myelix-tools-*` |
| **Thought** | Subagents | Cognitive specializations | `myelix-cognitive` |
| **Context** | Skills (lazy-loaded) | Context injectors (RAG, memory) | `myelix-rag`, `myelix-memory` |
| **Harness** | Lifecycle hooks | Hook pipeline, safety filters | `myelix-security` |

Currently all modules implement the same `Module` trait regardless
of their role. Distinguishing tool-providers from context-injectors
from lifecycle hooks could improve composability and make the
architecture self-documenting.

**Decision needed**: Is the added type complexity worth it, or is
the flat trait + convention sufficient? Evaluate when implementing
Phase 3 (memory as context injector vs memory as tool).

Reference: SemaClaw 4-layer plugin taxonomy (arXiv 2604.11548).

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
- Cite "The Agent Tier" pattern (InfoWorld, Nitesh Varma) as
  independent validation of mcpd's two-lane architecture
  (deterministic ACL/hook enforcement + contextual agent reasoning
  through governed tool catalogs). Maps 1:1 to mcpd's design.
- ZeroClaw as additional competitive baseline (Rust trait-based
  agent, similar permission model, but flat runtime vs gateway)
- SemaClaw as harness-layer peer comparison: same problems
  (permissions, DAG orchestration, memory, context management)
  solved at a different architectural layer. mcpd = gateway
  (secures any framework), SemaClaw = harness (wraps one
  framework). Their PermissionBridge is binary vs our IFC taint
  propagation. Cite as validation that harness engineering is an
  emerging discipline (arXiv 2604.11548).
- LangChain Agentic Engineering: cite Worker/Leader pattern as
  industry convergence on multi-agent teams. Note absence of
  security enforcement — validates mcpd's niche.
- AWS Agent Registry: cite as governance-layer complement to
  mcpd's runtime-security layer. Discovery + governance + runtime
  security as three orthogonal concerns.
- PersonaVLM: cite memory type convergence (4-type taxonomy
  independently arrived at by Cloudflare, PersonaVLM, SemaClaw,
  and our Phase 3b). Cite temporal retrieval and persona evolution.
- BLD cross-tokenizer distillation (arXiv 2604.07466): cite if
  discussing heterogeneous model ensemble strategies.
- OpenMythos / RDT architecture: cite if Recurrent Depth
  Transformers validate for CPU-tier model sizing claims.
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

### ZeroClaw (April 2026 analysis)

- ZeroClaw: Rust agent runtime (<5MB memory, <10ms startup, 8.8MB binary)
- Trait-based architecture, TOML config, 3-tier autonomy
  (ReadOnly/Supervised/Full) — similar permission model to mcpd
- 70+ tools, 25+ messaging channels, hardware peripheral traits
  (ESP32/Arduino/RPi) — targets embedded/IoT
- Key difference: flat agent runtime vs mcpd's security gateway
- Potential collaboration: transport adapters, tool interface traits
- Watch for convergence — similar Rust + trait patterns, different layers
- Migrating OpenClaw users (positions as next-gen replacement)

### SemaClaw relationship (April 2026 analysis)

- SemaClaw: Open-source two-layer agent framework (arXiv 2604.11548)
- sema-code-core (Node.js agent runtime) + SemaClaw (application harness)
- Closest architectural parallel to myelix-* crate family
- Same problems: permissions, DAG orchestration, memory with hybrid
  retrieval, structured context injection, persona identity
- Key differences (our advantages):
  - **Layer**: SemaClaw is a harness (wraps one framework).
    mcpd is a gateway (secures any framework that speaks MCP).
  - **Security depth**: Their PermissionBridge is binary
    (internal=allow, external=approve). Our IFC propagates taint
    labels through tool chains; deny-wins ACLs are more granular.
  - **Language**: Node.js vs Rust (type safety, no runtime, WASM,
    in-process ONNX).
  - **Model lifecycle**: No model management (external APIs only).
    We have hub → runtime → backend.
- What we borrowed: 4-layer plugin taxonomy (Phase 5h Module trait
  review), wiki-format knowledge output (Phase 3d), skill
  lazy-loading (Phase 1d).

### LangChain Agentic Engineering (April 2026 analysis)

- LangChain reframes multi-agent systems as "agentic engineering"
- Worker agents (ICs) + Leader agents (PMs) with shared memory
  and tooling. A2A for agent comms, MCP for tools.
- 93% debugging time reduction, 65% dev time reduction in pilot
- No security enforcement whatsoever — their "tool gateway" is an
  API aggregator, not a security layer
- Validates our architecture: their Worker/Leader = our DAG
  orchestrator/specialists, their tool gateway = mcpd (minus security)
- Human PR review as bottleneck supports cross-validation (Phase 5g)

### AWS Agent Registry (April 2026 analysis)

- Centralized agent/tool/MCP server catalog in Amazon Bedrock AgentCore
- MCP + A2A native, hybrid keyword+semantic search, governance workflow
- The registry itself is an MCP server (queryable by Kiro, Claude Code)
- Governance layer (who owns what, is it approved) complements mcpd's
  runtime security layer (what can it access, is the content safe)
- Non-English semantic search fails 33% of tests — test our local
  embeddings for multilingual quality
- Consider RegistryModule to proxy external registries (Phase 5f)

## Non-goals

These capabilities from Python Myelix are intentionally NOT replicated:

- **Docker deployment**: Rust binary is self-contained
- **Python engine wrappers**: replaced by ModelBackend trait
- **Rich TUI**: CLI is sufficient; Goose or GNOME shell provides UX
- **A2A server**: mcpd already serves Agent Cards; A2A orchestration
  belongs in myelix-flow, not as a separate service
- **Desktop app**: Goose (or similar) serves as the frontend;
  mcpd handles GNOME integration (D-Bus notifications, tray)
