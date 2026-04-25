# Myelix Rust Roadmap

This document tracks the evolution of the smgglrs-* crate family from
an MCP gateway (smgglrs) into a complete multi-agent orchestration
platform — the Rust replacement for the Python Myelix framework.

## Current state (2026-04-25)

17 crates, ~68K LoC, ~1044 tests. 43 personas, 36 heuristics,
7 directives. Gateway blackbox audit. 4 paper outlines. Fully local
multi-agent demos. Full PII pipeline (regex + NER + file paths,
pseudonymization, GDPR tools, IFC integration).

### Infrastructure (complete)

| Crate | Status | What it does |
|-------|--------|-------------|
| smgglrs-protocol | Done | MCP/A2A types, upstream client (stdio/HTTP/SSE + retry) |
| smgglrs-model | Done | ModelBackend trait, ONNX (in-process), OpenAI-compat, Anthropic (direct + Vertex AI) |
| smgglrs-model-hub | Done | Pull/cache models from OCI, HuggingFace, Ollama registries. Composite model cards (vendor + agentic + runtime) |
| smgglrs-model-runtime | Done | Serve models via llama-server or Podman. libkrun delegated to OpenShell (see OPENSHELL.md) |
| smgglrs-security | Done | Auth (BLAKE3, capability tokens, DID:key), ACLs, IFC with trusted paths, safety filters, hooks |
| smgglrs-core | Done | MCP server, module trait, session, IFC value store, transport |
| smgglrs-server | Done | Gateway binary (smgglrs), config, model hub/runtime integration, CLI |

### Client & Orchestration (v1 complete)

| Crate | Status | What it does |
|-------|--------|-------------|
| smgglrs-agent | Done | Client SDK: Agent builder with `.persona()`, McpClient with taint tracking, ReAct tool-use loop, non-progress iterations, scoped capability tokens |
| smgglrs-flow | Done (v2) | Multi-agent flows: handoff routing, DAG execution, mesh communication (mailbox, blackboard, back-edges), IFC-gated, mandate validation |

### Tools & Modalities (scaffolded)

| Crate | Status | What it does |
|-------|--------|-------------|
| smgglrs-tools-docs | Done | Document CRUD, FTS5, sqlite-vec |
| smgglrs-tools-git | Done | Git status, diff, log, branch, commit |
| smgglrs-rag | Done | Vector search, semantic chunking |
| smgglrs-modal-voice | Scaffolded | ASR + TTS via ONNX (Whisper, Piper) |
| smgglrs-modal-vision | Scaffolded | Image understanding (GPU tier) |

---

## Self-analysis protocol

The framework can analyze its own codebase through its own gateway.
This protocol ensures consistent, reproducible self-analysis runs.

### Setup

```bash
# 1. Refresh the analysis copy (ALWAYS do this first)
rm -rf /tmp/smgglrs-self-audit
mkdir -p /tmp/smgglrs-self-audit
cp -r smgglrs-*/src /tmp/smgglrs-self-audit/
cp -r cognitive_core /tmp/smgglrs-self-audit/
cp CLAUDE.md DESIGN.md ROADMAP.md MODELS.md /tmp/smgglrs-self-audit/

# 2. Copy self-audit personas (planner, rust_security_auditor, etc.)
cp -r examples/payments-app/personas /tmp/smgglrs-self-audit/ 2>/dev/null
# Or use the leader persona from cognitive_core (general-purpose)
```

### Running

```bash
# Security audit (default)
just demo --live --model gemma4:26b --project /tmp/smgglrs-self-audit

# Custom analysis with additional read access
just demo --live --model gemma4:26b --project cognitive_core \
  --allow-read /tmp \
  --prompt "Read /tmp/smgglrs-analysis.md and verify against reality."

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

Many findings from self-analysis of `/tmp/smgglrs-self-audit` are
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

## PII handling (completed 2026-04-25)

### Original gaps (all resolved) ✅

1. ✅ **Fix false positives** — timestamp/UUID negative lookaheads
   in phone and pattern regexes
2. ✅ **Add EU PII patterns** — NIR, IBAN, SIRET/SIREN, EU phone,
   IP addresses, passport numbers
3. ✅ **Filter on memory ingestion** — PII filter runs on
   KnowledgeStore::store and distillation output
4. ✅ **Redact audit logs** — blackbox entries pass through the
   safety pipeline before persistence
5. ✅ **PII as IFC label** — `Confidentiality::Pii` above Sensitive;
   tool results containing PII auto-label; IFC blocks writes to
   non-PII-safe destinations
6. ✅ **Data retention / purge** — `memory_purge_pii` tool,
   configurable retention TTL, PII scan on existing data

### Additional PII work completed ✅

| Feature | Detail |
|---------|--------|
| NER semantic detection | ProtectAI + multilingual XLM-RoBERTa ONNX models for entity recognition beyond regex patterns |
| Pseudonymization | `FilterAction::Pseudonymize` with `PseudonymMap` for reversible replacement (e.g., `Jean Dupont` → `Person_A`) |
| Custom PII patterns | `[[pii_patterns]]` config section for operator-defined PII categories |
| PII in embeddings | Cascade deletion from vector store when source content is purged |
| Model reasoning filter | PII detection on agent text output (model reasoning), not just tool results |
| File path PII detection | `PathPiiFilter` detects PII leaked via file paths (e.g., `/home/jean.dupont/`) |
| Consent tracking | Per-data-subject consent records; `pii_report` tool for GDPR data subject access requests |
| PII model download | `smgglrs pii download` CLI command to fetch NER models (protectai, xlm-roberta) |

### Detection layers

1. **Regex** — US patterns (SSN, credit card, phone, email) + EU
   patterns (NIR, IBAN, SIRET, EU phone, IP, passport) + custom
   `[[pii_patterns]]`
2. **NER** — ProtectAI (English) + XLM-RoBERTa (multilingual) ONNX
   models for semantic entity recognition
3. **File paths** — `PathPiiFilter` detects usernames, personal
   directories, and name patterns in file paths

### Filter actions

| Action | Behavior |
|--------|----------|
| `pass` | Log finding, no modification |
| `redact` | Replace with `[REDACTED:category]` |
| `pseudonymize` | Replace with consistent pseudonym via `PseudonymMap` |
| `block` | Reject the entire response |

### Storage filtering

PII filters run on all persistence paths: memory ingestion,
audit/blackbox logs, distillation output, and vector embeddings
(cascade deletion on purge).

### GDPR tools

| Tool | Purpose |
|------|---------|
| `memory_purge_pii` | Purge all PII for a data subject |
| `memory_forget` | Delete specific memory entries |
| `pii_report` | Generate data subject access report |
| `pii_consent` | Record/query consent status |

---

## Code health (updated 2026-04-25)

### Completed ✅

| Item | When |
|------|------|
| `rust-toolchain.toml` + `rustfmt.toml` + `justfile` | 2026-04-20 |
| Clippy auto-fix (103 → 53 → 0 warnings) | 2026-04-20, 2026-04-24 |
| Mutex poison recovery (all `.lock().unwrap()`) | 2026-04-17 |
| main.rs decomposition (cli, demo, ui, *_tools modules) | 2026-04-17, 2026-04-24 |
| 50+ security findings across 6 audit rounds | 2026-04-17–20 |
| Extract auth middleware in `ui.rs` | 2026-04-25 |
| GitHub Actions CI | 2026-04-25 |
| Make hardcoded values configurable | 2026-04-25 |
| Per-teammate operation scoping (delegated capability tokens) | 2026-04-25 |
| Split large files (server.rs, tools.rs, streamable.rs, config.rs, a2a.rs) | 2026-04-24 |
| Per-crate README.md files (17 crates) | 2026-04-24 |
| Module-level //! doc comments (all crates) | 2026-04-24 |
| Rename docs_* → file_*, MCP resources for reads | 2026-04-25 |
| Full PII pipeline (regex + NER + paths, pseudonymization, GDPR tools) | 2026-04-25 |

### Remaining

| Item | Detail | Effort |
|------|--------|--------|
| Feature-gate ONNX | Decouple `ort` from crates that don't directly use it | Architecturally invasive; revisit when CI is live |

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
| Task decomposition (recursive planning, scope partitioning) | DAG executor + flow_escalate + dynamic planner tasks + generates_tasks | **Done** (scope partitioning via planner decomposition) |
| DAG execution (parallel tasks with dependencies) | DagExecutor with DependencyGraph | **Done** |
| Mesh communication (lateral agent messaging) | Mailbox + Blackboard (IFC-gated) | **Done** |
| Persistent memory (working, long-term, cases) | SQLite sessions + working memory + FTS5 + distillation + RRF retrieval + decay + MCP tools | **Done** |
| Anti-drift (mandate validation, drift detection) | Mandate validator + success_criteria | **Done** |
| Failure recovery (circular fix detection, attempt history) | Attempt history, circular fix detector, recovery strategies | **Done** |
| Observability (structured metrics, monitoring) | tracing only | **Low** |
| TUI (rich terminal interface) | CLI only | **Low** |

---

## Roadmap

### Phase 1: Cognitive core (smgglrs-cognitive)

**Goal**: Load persona/directive/heuristic YAML files, compile them
into structured system prompts, and integrate with smgglrs-agent.

New crate: `smgglrs-cognitive` (**Status**: Complete.
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

### Phase 2: DAG execution & mesh communication (smgglrs-flow v2) ✓

**Status**: Core done. Enhancements planned.

Implemented in `smgglrs-flow`:

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
- `smgglrs flow import-goose <recipe.yaml>` CLI command to convert
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

#### 2c. Flow-template-driven orchestration ✅

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

This bridges the existing `smgglrs-flow` DAG engine with the
team orchestration tools. The pieces exist (YAML loader with
`{{ param }}` substitution, `ParameterDef`, `single_task_dag()`,
flow MCP tools) — they need to be composed.

**Why**: Ad-hoc team orchestration wastes leader iterations on
boilerplate (create team, add 5 specialists, message each, poll).
Flow templates encode orchestration expertise once and reuse it.
The planner's domain knowledge goes into choosing the right
template and parameters, not reinventing the workflow each time.

### Phase 3: Persistent memory (smgglrs-memory)

**Goal**: Working memory that survives sessions, knowledge
distillation pipeline, case-based reasoning. Backed by SQLite.

New crate: `smgglrs-memory` (**Status**: All phases complete —
WorkingMemory, KnowledgeStore, SqliteSessionBackend, distillation
pipeline with Markdown export, RRF retrieval (4 channels + vector
integration test), memory decay with exponential scoring, model-aware
compaction strategies, MCP memory tools, audit log storage.)

#### 3a. Session persistence ✅

- `SessionBackend` trait in smgglrs-core, `SqliteSessionBackend`
  in smgglrs-memory. Sessions survive server restarts.
- Wired in smgglrs-server at `~/.local/share/smgglrs/sessions.db`.
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
- Add `AuditLog` struct to `smgglrs-memory`
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

Implemented in `smgglrs-flow`:

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

Add Agent Client Protocol support to smgglrs-server:

- ACP is JSON-RPC 2.0 over Streamable HTTP (single `POST /acp`
  endpoint) — same transport as MCP, different method set.
- Methods: `initialize`, `authenticate`, `session/new`,
  `session/load`, `session/prompt` (streaming responses).
- Enables Myelix agents to appear in Zed and JetBrains IDEs
  without building editor plugins.
- Reuses existing Axum HTTP infrastructure from smgglrs-server.

Reference: ACP spec (github.com/i-am-bee/acp), Goose's
goose-acp crate, JetBrains AI Assistant ACP support.

#### 5b. MCP permission negotiation (NEW — AAIF contribution)

Design and implement a permission negotiation extension for MCP:

- New MCP method: `permissions/request` — an MCP server can request
  elevated permissions from the client (e.g., write access to a path).
- Client-side: present permission request to user, relay decision
  back to server via `permissions/grant` / `permissions/deny`.
- Server-side (smgglrs): update ACLs dynamically based on granted
  permissions. Scoped to session, with optional persistence.
- Integrate with Goose's approval model: when Goose is the client,
  its permission prompt maps to `permissions/request`.
- Propose as MCP specification extension to AAIF.

This bridges the gap between Goose's UI-level permission prompts
and smgglrs's infrastructure-level ACLs.

#### 5c. Goose-as-frontend integration ✅ (docs + config examples)

Enable Goose desktop app to connect to smgglrs as a single MCP
extension over Streamable HTTP:

- smgglrs already speaks MCP over HTTP — Goose can connect today.
- Build a Goose extension config snippet and test end-to-end:
  Goose UI → smgglrs gateway → downstream tools with full
  auth/ACL/IFC/safety.
- Document the setup for users.
- Capture feedback on: permission flow UX, latency, tool
  discovery, error messages.
- Stretch: build a Goose deeplink (`goose://extension?...`)
  for one-click smgglrs installation.

#### 5d. LLM backend expansion (NEW)

Add missing model backends to smgglrs-model:

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
  the CLI subprocess (reuses smgglrs-model-runtime isolation).
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

Add a `RegistryModule` to smgglrs that aggregates external agent/tool
discovery registries behind the gateway's unified security layer:

- **Proxy to external registries**: AWS Agent Registry, Azure Agent
  Registry, MCP Registry — agents behind smgglrs get unified discovery
  without needing provider-specific SDK access.
- **Registry as MCP server**: Expose discovery as MCP tools
  (`registry_search`, `registry_list`, `registry_describe`).
- **Hybrid search**: Forward keyword + semantic queries to upstream
  registries, merge results, apply smgglrs's ACLs to filter what the
  requesting agent is allowed to discover.
- **Caching**: Cache registry responses locally with configurable
  TTL (default 1h). Avoid hammering external APIs.
- **Multilingual awareness**: Test non-English semantic search
  quality (AWS registry fails 33% of Japanese queries). Use local
  embedding model as fallback for non-English queries.

This fits the gateway pattern — smgglrs aggregates discovery sources
just like it aggregates upstream MCP servers.

Reference: AWS Agent Registry (InfoQ, 2026-04-20), DISCOVERY.md.

#### 5g. Multi-agent cross-validation in flows (NEW)

Add cross-validation pattern to smgglrs-flow for high-stakes
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

#### 5h. Upstream prompt injection into agent system prompt (NEW)

Upstream MCP servers can expose domain-specific prompts via
`prompts/list` and `prompts/get`. These prompts contain critical
instructions for how the agent should use the upstream's tools
(methodology, constraints, output format). Currently, upstream
prompts are discovered and proxied but **never injected into the
agent's system prompt** — the cognitive weaver only assembles from
persona YAML (directives + mandate + heuristics + examples).

This gap was discovered during Syllogis integration: the legal
analysis upstream exposes a `legal_analysis` prompt that instructs
the agent to "use search_codes to find real articles, follow this
methodology: extract facts → search → syllogism → conclusion."
Without this prompt, the agent (using the generic "leader" persona)
ignored the Syllogis tools and hallucinated article numbers from
its training data.

**Design**: Add an `mcp_prompts` field to the persona YAML schema:

```yaml
persona_name: legal_analyst
core_mandate: "Analyze French administrative law cases..."
heuristics:
  - module: french_admin_law
    facets: [principles, codes]
mcp_prompts:
  - upstream: syllogis
    prompt: legal_analysis
    inject_position: after_mandate
    arguments:
      case_description: "{{ input }}"
  - upstream: syllogis
    prompt: legal_syllogism
    inject_position: after_heuristics
```

**Weaver changes** (`build_cacheable_prefix()`):

1. Accept an optional MCP client (or prompt resolver function)
   alongside the ForgeService
2. After assembling directives + mandate, check for `mcp_prompts`
3. For each entry, call `prompts/get` on the named upstream
   with the specified arguments (template variables like
   `{{ input }}` resolved from the user prompt)
4. Insert the returned messages at the specified position:
   - `before_mandate`: before core_mandate
   - `after_mandate`: after core_mandate, before heuristics
   - `after_heuristics`: after heuristics, before examples
   - `after_examples`: at the end of the system prompt
5. Cache the assembled result (upstream prompts are typically
   static for a given set of arguments)

**CLI extension**: Also support ad-hoc upstream prompt injection
without modifying persona YAML:

```bash
smgglrs run "Analyze this case..." \
  --persona legal_analyst \
  --upstream-prompt syllogis:legal_analysis
```

This fetches the prompt at runtime and appends it after the
persona's system prompt.

**Why this matters**: Upstream servers are domain experts. Their
prompts encode domain methodology that the persona YAML shouldn't
duplicate. A legal analysis persona shouldn't hardcode "use
search_codes" — that coupling belongs in the upstream's prompt.
This separation lets the same persona work with different upstreams
(e.g., a legal analyst persona could work with Syllogis for French
law or a different upstream for German law, each providing their
own methodology prompt).

**Implementation priority**: Medium. The CLI `--upstream-prompt`
flag is a 1-hour change in `main.rs run_agent()`. The YAML schema
+ weaver integration is a half-day change across smgglrs-cognitive
and smgglrs-agent.

**Discovered via**: Syllogis legal workbench integration
(2026-04-24). The agent had 40 tools available (6 from Syllogis)
but never called the Syllogis tools because its system prompt
(generic "leader" persona) contained no instructions to do so.

#### 5i. Module trait taxonomy review (NEW)

Review whether smgglrs-core's flat `Module` trait should be split
into a richer taxonomy, inspired by SemaClaw's 4-layer plugin
architecture:

| Layer | SemaClaw | smgglrs equivalent | Example |
|-------|----------|-----------------|---------|
| **Action** | MCP Tools | Tool modules (docs, git) | `smgglrs-tools-*` |
| **Thought** | Subagents | Cognitive specializations | `smgglrs-cognitive` |
| **Context** | Skills (lazy-loaded) | Context injectors (RAG, memory) | `smgglrs-rag`, `smgglrs-memory` |
| **Harness** | Lifecycle hooks | Hook pipeline, safety filters | `smgglrs-security` |

Currently all modules implement the same `Module` trait regardless
of their role. Distinguishing tool-providers from context-injectors
from lifecycle hooks could improve composability and make the
architecture self-documenting.

**Decision needed**: Is the added type complexity worth it, or is
the flat trait + convention sufficient? Evaluate when implementing
Phase 3 (memory as context injector vs memory as tool).

Reference: SemaClaw 4-layer plugin taxonomy (arXiv 2604.11548).

### Phase 6: OpenShell integration ✅

See `docs/designs/openshell-sandbox.md` for full design.

**Goal**: Integrate with OpenShell (Red Hat/NVIDIA secure sandbox
platform) for identity federation, A2A teammate mesh, sandbox
delegation, and gRPC module architecture.

**Status**: Complete (2026-04-25).

#### 6a. OpenShell-provided identity ✅ (2026-04-24)

`OpenShellAuthenticator` in smgglrs-security accepts identity
tokens from the OpenShell supervisor (SPIFFE SVIDs, OIDC JWTs,
or gateway-signed tokens). Slots into `ChainAuthenticator`
between capability and legacy auth. No impact on standalone smgglrs.

#### 6b. A2A client and teammate mesh ✅ (2026-04-24)

`A2aClient` in smgglrs-protocol for outbound A2A calls.
`MeshRouter` in smgglrs-flow routes messages to in-process
(mailbox) or remote (A2A) teammates transparently.
`AgentCardDirectory` in smgglrs-core for teammate discovery.
IFC enforcement on all A2A messages via `X-Smgglrs-DataLabel` header.

#### 6c. Sandbox delegation to OpenShell ✅ (2026-04-24)

Removed aspirational libkrun feature flag. Added `openshell`
runtime backend that delegates sandbox creation to OpenShell's
compute driver via gRPC. Vendored proto definitions at
`smgglrs-model-runtime/proto/`. Direct and Podman backends
remain for standalone smgglrs.

#### 6d. gRPC module architecture ✅ (2026-04-24)

`GrpcModule` adapter implements Module trait by forwarding calls
to gRPC services. `GrpcModuleManager` handles lifecycle (spawn,
health check, restart). Proto definitions at `smgglrs-core/proto/`.
Configured via `grpc_modules` in server config.

#### 6e. Defense-in-depth network security model ✅ (2026-04-25)

Combined OpenShell + smgglrs security model documented and tested:

- OPA policy template: `docs/openshell/opa-sandbox-policy.rego`
- smgglrs config template: `docs/openshell/smgglrs-sandbox.toml`
- Integration tests: `smgglrs-server/tests/openshell_integration.rs`
  (6 tests covering network isolation, ACLs, IFC, identity, tokens, PII)
- MAC + DAC defense in depth section added to DESIGN.md
- Microkernel analogy for Phase 8 papers

### Phase 7: RAG enhancements

#### 7a. Two-stage retrieval with cross-encoder reranking (NEW)

Add reranking stage to smgglrs-rag after sqlite-vec retrieval:

- ColBERT-style late interaction (preferred: preindexable, low
  latency, fits ONNX in-process strategy)
- Fallback: MiniLM-L6-v2 cross-encoder as ONNX model
- Domain fine-tuning with hard negatives (~70 examples for
  significant improvement)
- Knowledge distillation: train fast bi-encoder from cross-encoder
  scores for domain-specific use

#### 7b. Semantic query caching (NEW)

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
  vs smgglrs as "security microkernel"
- Cite "The Agent Tier" pattern (InfoWorld, Nitesh Varma) as
  independent validation of smgglrs's two-lane architecture
  (deterministic ACL/hook enforcement + contextual agent reasoning
  through governed tool catalogs). Maps 1:1 to smgglrs's design.
- ZeroClaw as additional competitive baseline (Rust trait-based
  agent, similar permission model, but flat runtime vs gateway)
- SemaClaw as harness-layer peer comparison: same problems
  (permissions, DAG orchestration, memory, context management)
  solved at a different architectural layer. smgglrs = gateway
  (secures any framework), SemaClaw = harness (wraps one
  framework). Their PermissionBridge is binary vs our IFC taint
  propagation. Cite as validation that harness engineering is an
  emerging discipline (arXiv 2604.11548).
- LangChain Agentic Engineering: cite Worker/Leader pattern as
  industry convergence on multi-agent teams. Note absence of
  security enforcement — validates smgglrs's niche.
- AWS Agent Registry: cite as governance-layer complement to
  smgglrs's runtime-security layer. Discovery + governance + runtime
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
smgglrs-protocol          (no smgglrs deps)
smgglrs-model             (no smgglrs deps)
smgglrs-model-hub         (no smgglrs deps)
smgglrs-model-runtime     (no smgglrs deps)
    ↓
smgglrs-security          (protocol + model)
    ↓
smgglrs-cognitive         (security)             PERSONAS
smgglrs-agent             (protocol + model + security)  CLIENT
smgglrs-memory            (security + rag)       PERSISTENCE
    ↓
smgglrs-flow              (agent + cognitive + memory)   ORCHESTRATION
smgglrs-core              (protocol + model + security)  SERVER
    ↓
smgglrs-tools-*  ─────┐
smgglrs-rag      ─────┼── (core only)
smgglrs-modal-*  ─────┘
    ↓
smgglrs-server            (all + hub + runtime)
```

## Ecosystem positioning

smgglrs is infrastructure, not an end-user agent. Desktop agents
(Goose, Claude Code, etc.) connect to smgglrs as an MCP server.
smgglrs provides the security layer; the agent provides the UX.

```
Goose (desktop)  ──┐              ┌── downstream MCP servers
Claude Code      ──┼── MCP/ACP ──> smgglrs ──┼── built-in modules
Zed/JetBrains    ──┘              └── local ONNX models
```

### Goose relationship (April 2026 analysis)

- Goose: Rust agent runtime (~v1.30, Apache-2.0, AAIF/Linux Foundation)
- Different layer: Goose = end-user agent, smgglrs = security gateway
- Goose has NO auth tokens, NO ACLs, NO IFC, NO content filtering
- Goose connects to MCP servers directly (no proxy/filter)
- Contribution targets: MCP interceptor pattern (SEP-1763),
  Linux extension sandboxing, safety hook pipeline, ACL engine
- ACP adoption gives Myelix agents IDE integration for free

### ZeroClaw (April 2026 analysis)

- ZeroClaw: Rust agent runtime (<5MB memory, <10ms startup, 8.8MB binary)
- Trait-based architecture, TOML config, 3-tier autonomy
  (ReadOnly/Supervised/Full) — similar permission model to smgglrs
- 70+ tools, 25+ messaging channels, hardware peripheral traits
  (ESP32/Arduino/RPi) — targets embedded/IoT
- Key difference: flat agent runtime vs smgglrs's security gateway
- Potential collaboration: transport adapters, tool interface traits
- Watch for convergence — similar Rust + trait patterns, different layers
- Migrating OpenClaw users (positions as next-gen replacement)

### SemaClaw relationship (April 2026 analysis)

- SemaClaw: Open-source two-layer agent framework (arXiv 2604.11548)
- sema-code-core (Node.js agent runtime) + SemaClaw (application harness)
- Closest architectural parallel to smgglrs-* crate family
- Same problems: permissions, DAG orchestration, memory with hybrid
  retrieval, structured context injection, persona identity
- Key differences (our advantages):
  - **Layer**: SemaClaw is a harness (wraps one framework).
    smgglrs is a gateway (secures any framework that speaks MCP).
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
  orchestrator/specialists, their tool gateway = smgglrs (minus security)
- Human PR review as bottleneck supports cross-validation (Phase 5g)

### AWS Agent Registry (April 2026 analysis)

- Centralized agent/tool/MCP server catalog in Amazon Bedrock AgentCore
- MCP + A2A native, hybrid keyword+semantic search, governance workflow
- The registry itself is an MCP server (queryable by Kiro, Claude Code)
- Governance layer (who owns what, is it approved) complements smgglrs's
  runtime security layer (what can it access, is the content safe)
- Non-English semantic search fails 33% of tests — test our local
  embeddings for multilingual quality
- Consider RegistryModule to proxy external registries (Phase 5f)

## Non-goals

These capabilities from Python Myelix are intentionally NOT replicated:

- **Docker deployment**: Rust binary is self-contained
- **Python engine wrappers**: replaced by ModelBackend trait
- **Rich TUI**: CLI is sufficient; Goose or GNOME shell provides UX
- **A2A server**: smgglrs already serves Agent Cards; A2A orchestration
  belongs in smgglrs-flow, not as a separate service
- **Desktop app**: Goose (or similar) serves as the frontend;
  smgglrs handles GNOME integration (D-Bus notifications, tray)
