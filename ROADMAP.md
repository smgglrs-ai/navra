# Myelix Rust Roadmap

This document tracks the evolution of the myelix-* crate family from
an MCP gateway (mcpd) into a complete multi-agent orchestration
platform — the Rust replacement for the Python Myelix framework.

## Current state (2026-04-21)

17 crates, ~49K LoC. 43 personas, 36 heuristics, 7 directives.
Gateway blackbox audit. 4 paper outlines. Fully local multi-agent demos.

### Infrastructure (complete)

| Crate | Status | What it does |
|-------|--------|-------------|
| myelix-protocol | Done | MCP/A2A types, upstream client (stdio/HTTP/SSE + retry) |
| myelix-model | Done | ModelBackend trait, ONNX (in-process), OpenAI-compat, Anthropic (direct + Vertex AI) |
| myelix-model-hub | Done | Pull/cache models from OCI, HuggingFace, Ollama registries. Composite model cards (vendor + agentic + runtime) |
| myelix-model-runtime | Done | Serve models via llama-server or Podman. libkrun delegated to OpenShell (see OPENSHELL.md) |
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

## Self-analysis protocol

The framework can analyze its own codebase through its own gateway.
This protocol ensures consistent, reproducible self-analysis runs.

### Setup

```bash
# 1. Refresh the analysis copy (ALWAYS do this first)
rm -rf /tmp/mcpd-self-audit
mkdir -p /tmp/mcpd-self-audit
cp -r myelix-*/src /tmp/mcpd-self-audit/
cp -r cognitive_core /tmp/mcpd-self-audit/
cp CLAUDE.md DESIGN.md ROADMAP.md MODELS.md /tmp/mcpd-self-audit/

# 2. Copy self-audit personas (planner, rust_security_auditor, etc.)
cp -r examples/payments-app/personas /tmp/mcpd-self-audit/ 2>/dev/null
# Or use the leader persona from cognitive_core (general-purpose)
```

### Running

```bash
# Security audit (default)
just demo --live --model gemma4:26b --project /tmp/mcpd-self-audit

# Custom analysis with additional read access
just demo --live --model gemma4:26b --project cognitive_core \
  --allow-read /tmp \
  --prompt "Read /tmp/mcpd-analysis.md and verify against reality."

# Business analysis
just demo --live --model gemma4:26b --project cognitive_core \
  --prompt "A company wants to license this. Should we pursue?"
```

### Model selection

The lead selects teammate models from model cards (via `models_list`).
Operator sets `[models.*.agentic]` in config.toml with:
- `cost_tier`: "free" (local Ollama) or "high" (cloud API)
- `speed_tier`: "fast", "medium", "slow" (derived from model size)
- `locality`: "local" (on-device) or "remote" (cloud)
- `reasoning`: "basic" or "extended"
- `tool_use`: "basic" or "advanced"

The lead prefers `locality=local` + `cost_tier=free` for data
gathering, and reserves expensive remote models for synthesis.

### Interpreting results

Many findings from self-analysis of `/tmp/mcpd-self-audit` are
re-discoveries of issues already fixed in the live codebase.
Always cross-reference findings against recent commits before
acting on them. The stale copy is intentional — it tests the
framework's ability to find real issues, not our discipline in
keeping the copy fresh.

### Audit trail gap (2026-04-20 finding)

Current demo runs produce only: final report text, teammate model
assignments, iteration count, token usage. Missing for debug and
legal audit:

- Tool call log (name, args, result, duration, agent, iteration)
- Model reasoning between tool calls (decision trace)
- ACL decisions (allowed/denied per tool call)
- Per-teammate tool call traces
- Provenance chain (what data each agent saw, what it decided, why)

This is addressed by Phase 3h (Structured Audit Log) below.

---

## Code health (updated 2026-04-20)

### Completed ✅

| Item | When |
|------|------|
| `rust-toolchain.toml` + `rustfmt.toml` + `justfile` | 2026-04-20 |
| Clippy auto-fix (103 → 53 warnings) | 2026-04-20 |
| Mutex poison recovery (all `.lock().unwrap()`) | 2026-04-17 |
| main.rs decomposition (cli, demo, ui modules) | 2026-04-17 |
| 50+ security findings across 6 audit rounds | 2026-04-17–20 |

### Remaining

| Item | Detail | Effort |
|------|--------|--------|
| Extract auth middleware in `ui.rs` | 5 inline auth checks → single Axum layer | 1h |
| GitHub Actions CI | `just check` in CI. Needs ONNX in CI (system package or feature-gate) | 1-2h |
| Feature-gate ONNX | Decouple `ort` from crates that don't directly use it | Architecturally invasive; revisit when CI is live |
| Make hardcoded values configurable | Approval TTL, file watcher skip-list → config.toml | 1h |
| Per-teammate operation scoping | `team_add` accepts operations/tools per teammate, token minted accordingly | Design needed |
| Remaining 53 clippy warnings | MSRV, method naming, scaffolded dead code — address when CI enforces `-D warnings` | 1h |

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
| Persistent memory (working, long-term, cases) | SQLite sessions + working memory + FTS5 + distillation pipeline + RRF retrieval | **Partial** (memory decay and MCP tools remaining) |
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

#### 1a. Context management and token budgeting ✅

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

#### 1b. Persona porting and agent integration ✅

- `Agent::builder().persona(forge, name)` — done
- 43 personas (38 from Python + 5 general-purpose), 36 heuristics,
  7 directives — done

#### 1c. Persona evolution via momentum-based adaptation ✅

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

#### 2a. YAML flow definitions and shareable format (design complete)

Switch flow definitions from TOML-only to YAML-primary (keep TOML
support via file extension detection — same serde structs):

- Add fields to flow/DAG definitions: `parameters` (Jinja-style
  template variables), `output_json_schema`, `retry` policy,
  `required_extensions` (MCP servers needed to run the flow).
- `myelix flow import-goose <recipe.yaml>` CLI command to convert
  Goose recipes into Myelix flow definitions (with human review).
- YAML is consistent with cognitive core (personas/heuristics).

#### 2b. Dynamic subflow spawning from tool loop ✅

Add a `spawn_subflow` virtual tool to the agent tool loop. An agent
inside a tool-use loop can create a single-node DAG on the fly and
execute it as a subflow (uses existing DagExecutor, no new engine).
This gives ad-hoc delegation without requiring static flow files.

- Max depth: 1 (subflows cannot spawn sub-subflows)
- Max concurrent: 10 (configurable)
- Timeout: 5 minutes default
- Isolated context (no shared conversation history)

#### 2c. Flow-template-driven orchestration (NEW)

Replace ad-hoc team orchestration (leader manually calling
team_create/team_add/team_message) with template-driven flows
exposed via MCP:

- **Flow templates as YAML**: Parameterized flow definitions for
  common patterns (security audit, code review, research, analysis).
  Each template defines stages (triage → deep review → synthesis),
  model selection hints per stage, and file grouping strategies.
- **Planner as flow selector**: Instead of designing work
  decomposition from scratch, the planner calls `flow_list` to
  discover available templates, picks one, and parameterizes it
  (target directory, depth, focus areas).
- **Leader executes flows**: `flow_start` with parameters replaces
  the manual 12-step team workflow. The flow engine handles
  teammate spawning, dependency ordering, and result collection.
- **Task-specific decomposition**: Audit flows use triage-first
  (fast agent reads all files, flags interesting ones, then
  specialists do deep review). Research flows use parallel
  investigation. Analysis flows use sequential refinement.
- **Model hints per stage**: Templates specify model requirements
  per stage (speed_tier=fast for triage, reasoning=extended for
  synthesis). The flow engine resolves to actual models via
  model cards at runtime.

This bridges the existing `myelix-flow` DAG engine with the
team orchestration tools. The pieces exist (YAML loader with
`{{ param }}` substitution, `ParameterDef`, `single_task_dag()`,
flow MCP tools) — they need to be composed.

**Why**: Ad-hoc team orchestration wastes leader iterations on
boilerplate (create team, add 5 specialists, message each, poll).
Flow templates encode orchestration expertise once and reuse it.
The planner's domain knowledge goes into choosing the right
template and parameters, not reinventing the workflow each time.

### Phase 3: Persistent memory (myelix-memory)

**Goal**: Working memory that survives sessions, knowledge
distillation pipeline, case-based reasoning. Backed by SQLite.

New crate: `myelix-memory` (**Status**: All phases complete —
WorkingMemory, KnowledgeStore, SqliteSessionBackend, distillation
pipeline with Markdown export, RRF retrieval (4 channels + vector
integration test), memory decay with exponential scoring, model-aware
compaction strategies, MCP memory tools, audit log storage.)

#### 3a. Session persistence ✅

- `SessionBackend` trait in myelix-core, `SqliteSessionBackend`
  in myelix-memory. Sessions survive server restarts.
- Wired in myelix-server at `~/.local/share/mcpd/sessions.db`.
- No auto-expiry (sessions persist indefinitely to preserve context
  across long work sessions). `expire()` available for manual use.

#### 3b. Memory type classification and keyed supersession (design complete)

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

#### 3c. Multi-channel retrieval with RRF fusion ✅

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

#### 3d. Knowledge distillation pipeline ✅

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

#### 3e. Memory decay and working memory management ✅

- Exponential decay for working memory turns:
  `effective = importance * e^(-decay * age) * freshness + relevance_boost`
- Auto-importance scoring on ingestion (domain keywords, length,
  query-token overlap)
- Deduplication via token-overlap similarity threshold (≥0.72)
- Configurable decay rate per agent/session

Reference: Baddeley's episodic buffer model, tech watch article
on context layers (2026-04-17).

#### 3f. Model-aware context compaction strategies ✅

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

#### 3g. Memory MCP tools ✅

- `memory_store`, `memory_query`, `memory_forget` MCP tools implemented
- Wired into main.rs module registration
- Remaining: agents auto-load relevant memory into context,
  semantic query caching (paraphrase detection, ~76% savings)

#### 3h. Structured audit log ✅ (gateway blackbox)

Every agent action must be recorded for debugging, compliance,
and legal audit. Without this, multi-agent failures are opaque
and AI decisions have no provenance.

**What to record per tool call:**
- `run_id`: UUID for the entire run (lead + all teammates)
- `agent_id`: which agent (lead, teammate name)
- `iteration`: which ReAct loop iteration
- `timestamp`: wall clock
- `tool_name`: which MCP tool was called
- `tool_args`: arguments passed (redacted for sensitive fields)
- `tool_result`: result returned (truncated to max 4K chars)
- `tool_duration_ms`: how long the call took
- `acl_decision`: allowed/denied/needs_approval
- `ifc_label`: data label after the call

**What to record per model call:**
- `model_name`: which model was used
- `input_tokens`, `output_tokens`: token usage
- `response_type`: "text", "tool_calls", "empty"
- `reasoning_text`: model's text output between tool calls
  (the decision trace — why it chose this tool)

**What to record per run:**
- `run_id`, `prompt`, `persona`, `model`
- `start_time`, `end_time`, `duration`
- `total_iterations`, `total_tokens`
- `teammates`: list of {name, model, persona, operations, tools}
- `final_report`: the synthesis text
- `exit_reason`: "completed", "max_iterations", "error"

**Storage:**
- SQLite table `audit_log` in WorkingMemory DB
- Indexed by `run_id`, `agent_id`, `timestamp`
- Queryable via MCP tool `audit_query` (filter by run, agent, tool)
- Retained indefinitely (no decay — audit logs are immutable)

**Implementation:**
- Add `AuditLog` struct to `myelix-memory`
- `ToolLoopResult` gains `audit_entries: Vec<AuditEntry>`
- Tool loop records each call as it executes
- Demo prints audit summary alongside the report
- `audit_query` MCP tool for retrospective analysis

**Compliance value:**
- EU AI Act Article 14 (human oversight) requires decision traceability
- SOC2 CC6.1 requires audit trails for system operations
- ISO 42001 requires records of AI system decisions

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

#### 5a. ACP transport (skeleton ✅, prompt streaming TODO)

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

#### 5c. Goose-as-frontend integration ✅ (docs + config examples)

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

### Phase 6: OpenShell integration

See OPENSHELL.md for full design.

**Goal**: Integrate with OpenShell (Red Hat/NVIDIA secure sandbox
platform) for identity federation, A2A teammate mesh, sandbox
delegation, and gRPC module architecture.

#### 6a. OpenShell-provided identity (NEW)

Add `OpenShellAuthenticator` to myelix-security that accepts
identity tokens from the OpenShell supervisor (SPIFFE SVIDs,
OIDC JWTs, or gateway-signed tokens). Slots into
`ChainAuthenticator` between capability and legacy auth.
No impact on standalone mcpd.

#### 6b. A2A client and teammate mesh (NEW)

Add `A2aClient` to myelix-protocol for outbound A2A calls.
Currently mcpd can only receive A2A tasks — it cannot call
other agents. The flow engine needs an A2A client to build
teammate meshes where agents communicate via A2A instead of
in-process channels.

The planner persona defines the flow; mcpd builds the A2A mesh
on its behalf:
1. Each teammate gets an A2A endpoint on mcpd
2. Teammate Agent Cards registered in local directory
3. Scoped capability tokens minted per teammate
4. IFC enforcement on all A2A messages

In-process mode (current mailbox/blackboard) remains the default
for single-node. A2A mode enables multi-node and OpenShell
sandbox deployments.

#### 6c. Sandbox delegation to OpenShell (NEW)

Remove the aspirational libkrun feature flag from
myelix-model-runtime (it has zero code behind it). Add an
`openshell` runtime backend that delegates sandbox creation to
OpenShell's compute driver via gRPC.

mcpd requests a sandbox with labels (`gpu=required`,
`isolation=microvm`); OpenShell's driver handles the rest
(Podman, libkrun, K8s, whatever). Direct and Podman backends
remain for standalone mcpd with no OpenShell dependency.

#### 6d. gRPC module architecture (NEW)

Add `GrpcModule` adapter that implements the Module trait by
forwarding calls to gRPC services. Same pattern as
`UpstreamModule` (MCP adapter) but for gRPC. Enables:

- Modules as separate processes (crash isolation)
- Modules on separate nodes (multi-node scaling)
- Modules in any language (language-independent interface)
- Independent module deployment and versioning

Follows OpenShell's driver model: separate binaries, gRPC over
Unix sockets, per-component lifecycle management.

New dependency: `tonic` + `prost` for gRPC.

### Phase 7: RAG enhancements

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

### Phase 8: Paper & benchmarks

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
