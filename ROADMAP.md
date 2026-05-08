# Myelix Rust Roadmap

This document tracks the evolution of the smgglrs-* crate family from
an MCP gateway (smgglrs) into a complete multi-agent orchestration
platform — the Rust replacement for the Python Myelix framework.

## Current state (2026-05-07)

18 crates, ~77K LoC, 1600+ tests, 0 warnings. 43 personas, 36
heuristics, 8 directives. Gateway blackbox audit. 4 paper outlines.
Fully local multi-agent demos. Full PII pipeline (regex + NER + file
paths, pseudonymization, GDPR tools, IFC integration). Containerized
agent execution via Podman (shared model server + per-agent sandboxes).

### Recent (2026-05-07)

- Domain-agnostic review + improve flows with dynamic persona selection
- build_test MCP tool, task-level tool/operation grants in flow YAML
- Planner JSON resilience (markdown stripping, id-boundary recovery,
  schema enforcement on generates_tasks agents)
- response_format plumbed through ChatRequest → Ollama API
- Container agent stdout fix (skip log lines before JSON)
- Comparative flow evaluation: dynamic 3.5x more efficient than hardcoded
- Paper 3 outline with evaluation data
- Phase 12 added: observability + infrastructure debt (8 metrics gaps)
- ROADMAP audit: stale sections updated, items assigned to phases
- Tech watch: 5 articles (NVIDIA Vera Rubin, OpenAI PII filter,
  skill-based agents, systematic prompting, Vercel DeepSec)

### Recent (2026-05-06)

- Renamed smgglrs-tools-docs → smgglrs-tools-file (DocsModule→FileModule)
- WebMCP transport skeleton (feature-gated, CDP bridge pattern)
- Persona semantic validation (cross-reference checks + CLI subcommand)
- Working memory decay wired into turn selection (get_turns_by_score)
- Hermes-format trace export (JSONL with <think>/<tool_call>/<tool_response>)
- ROADMAP reprioritized with tech watch items (13 articles analyzed)

### Recent (2026-05-05)

- Phase 8a: Typed agent action/result model (AgentAction, RiskLevel)
- Phase 8b: MCP config import (Claude Desktop, VSCode, Codex formats)
- Phase 9a-9b: 14 MCP spec types (tool annotations, content variants,
  logging, sampling, completions, roots, progress, cancellation)
- Phase 9c: Cursor-based pagination for all list operations
- Phase 9d-9e: Notification infrastructure (notify/notify_session on
  McpServer, progress tracking via _meta.progressToken)
- Phase 9f: Stdio server transport (`smgglrs stdio` for IDE integration)
- Phase 9g: OAuth 2.0 (provider, authenticator, HTTP endpoints wired)
- Phase 9h: smgglrs-macros crate (`#[tool]` proc macro)
- Two self-review rounds (23+8 agents) with findings fixed
- Self-review findings: zombie process fix, port TOCTOU, pick_free_port
  dedup, git_diff ref fix, vision size limit, memory pagination, SSE
  RwLock, audience validation warnings

### Infrastructure (complete)

| Crate | Status | What it does |
|-------|--------|-------------|
| smgglrs-protocol | Done (Phase 9) | MCP/A2A types, upstream client (stdio/HTTP/SSE + retry). ~35/39 MCP spec features. |
| smgglrs-model | Done | ModelBackend trait, ONNX (in-process), OpenAI-compat, Anthropic (direct + Vertex AI) |
| smgglrs-model-hub | Done | Pull/cache models from OCI, HuggingFace, Ollama registries. Composite model cards (vendor + agentic + runtime) |
| smgglrs-model-runtime | Done | Serve models via llama-server or Podman. libkrun delegated to OpenShell (see OPENSHELL.md) |
| smgglrs-security | Done | Auth (BLAKE3, capability tokens, DID:key), ACLs, IFC with trusted paths, safety filters, hooks |
| smgglrs-core | Done | MCP server, module trait, session, IFC value store, transport |
| smgglrs-server | Done | Gateway binary (smgglrs), config, model hub/runtime integration, CLI |

### Client & Orchestration (v1 complete)

| Crate | Status | What it does |
|-------|--------|-------------|
| smgglrs-agent | Done | Client SDK: Agent builder with `.persona()`, McpClient with taint tracking, ReAct tool-use loop, non-progress iterations, scoped capability tokens. Standalone binary (`smgglrs-agent`) for containerized execution + `Dockerfile.agent` |
| smgglrs-flow | Done (v2) | Multi-agent flows: handoff routing, DAG execution, mesh communication (mailbox, blackboard, back-edges), IFC-gated, mandate validation |

### Tools & Modalities (scaffolded)

| Crate | Status | What it does |
|-------|--------|-------------|
| smgglrs-tools-file | Done | File CRUD, FTS5, sqlite-vec (renamed from smgglrs-tools-docs 2026-05-06) |
| smgglrs-tools-git | Done | Git status, diff, log, branch, commit |
| smgglrs-rag | Done | Vector search, semantic chunking |
| smgglrs-modal-voice | Scaffolded | ASR + TTS via ONNX (Whisper, Piper) |
| smgglrs-modal-vision | Scaffolded | Image understanding (GPU tier) |

---

## Review and improvement flows

The framework reviews and improves projects through its own gateway
using DAG-based multi-agent flows. Four flow templates are available:

| Flow | Persona selection | Use case |
|------|------------------|----------|
| `comprehensive-review.yaml` | Hardcoded (5 personas) | Baseline code review |
| `review.yaml` | Dynamic (scout classifies → planner picks) | Domain-agnostic review |
| `self-improve.yaml` | Hardcoded | Code improvement cycle |
| `improve.yaml` | Dynamic | Domain-agnostic improvement |

### Running

```bash
# Start the server
smgglrs serve

# Run a review via MCP (from any MCP client)
flow_start(flow_name="review", prompt="Review the project",
  parameters={"target_dir": "/path/to/project"})

# Or use the hardcoded variant
flow_start(flow_name="comprehensive-review", ...)

# Improvement cycle (creates git worktree for isolation)
smgglrs improve --target . --cycles 3 --branch self-improve
```

### Comparative results (2026-05-07)

| Metric | Hardcoded | Dynamic | Ratio |
|--------|-----------|---------|-------|
| Wall clock | 32 min | 21 min | 0.66x |
| Total tokens | 3.77M | 1.78M | 0.47x |
| Specialists | 23 | 14 | — |
| Precision (real findings) | 37.5% | 62.5% | 1.67x |
| False positive rate | 25% | 12.5% | 0.50x |
| Real findings / M tokens | 0.80 | 2.81 | 3.5x |
| Cost per real finding | 1.26M tok | 0.36M tok | 3.5x cheaper |

Dynamic persona selection dominates: better quality at lower cost.
The planner picks personas that match the project domain rather
than spreading evenly across hardcoded categories.

### Audit metrics (current state)

**Captured in audit.db:**
- `flow_results`: per-task output, specialist, model, tokens
  (cumulative), started_at, completed_at
- `flow_metadata`: YAML content, parameters, flow-level timing
- `audit_runs`: per-agent run metadata
- `audit_tool_calls`: schema exists but **not populated** for
  flow agents (Phase 12a)
- `audit_model_calls`: schema exists but **not populated** for
  flow agents (Phase 12a)

**Known metrics gaps** (see Phase 12):
- Per-task duration always 0 (started_at == completed_at)
- Per-task iteration count always NULL
- Per-task tokens are cumulative, not per-agent
- Model name stored as "auto" instead of resolved name
- No GPU utilization recording

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

## Code health (updated 2026-05-03)

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
| Containerized agent execution (shared model server + per-agent sandboxes) | 2026-05-03 |
| smgglrs-agent standalone binary + Dockerfile.agent | 2026-05-03 |
| Two self-review rounds: 20+ findings fixed (security, perf, code quality) | 2026-05-05 |
| Phase 8a: Typed agent action/result model (AgentAction, RiskLevel) | 2026-05-05 |
| Phase 8b: MCP config import (Claude Desktop, VSCode, Codex) | 2026-05-05 |
| Phase 9a-9h: MCP spec coverage 14→35/39 (types, pagination, notifications, OAuth, stdio, proc macros) | 2026-05-05 |
| Notification bus: notify()/notify_session() on McpServer | 2026-05-05 |
| OAuth 2.0 endpoints wired into Axum router | 2026-05-05 |
| smgglrs-macros crate: `#[tool]` proc macro (18th crate) | 2026-05-05 |
| Domain-agnostic review + improve flows with dynamic persona selection | 2026-05-07 |
| build_test MCP tool, task-level tool/operation grants in flow YAML | 2026-05-07 |
| Git branch creation, `smgglrs improve` CLI | 2026-05-07 |
| Planner JSON resilience (markdown stripping, id-boundary recovery) | 2026-05-07 |
| Schema enforcement on generates_tasks agents (in-process + container) | 2026-05-07 |
| response_format plumbed through ChatRequest → Ollama API | 2026-05-07 |
| Container agent stdout parsing fix (skip log lines before JSON) | 2026-05-07 |
| Comparative flow evaluation: hardcoded vs dynamic persona selection | 2026-05-07 |

### Remaining

| Item | Phase | Effort | Priority |
|------|-------|--------|----------|
| **TensorRtRuntime backend** | 11a | 2-3 days | Medium-High |
| **TurboQuant KV cache** (--cache-type flags) | 11a | 1 day | Medium |
| Session store sharding (DashMap) | 12b | 1-2 days | Medium |
| Streaming model download (pull → disk) | 12b | 2-3 days | Medium |
| Feature-gate ONNX | 12b | Invasive | Low |
| Upstream TLS (DESIGN.md gap) | 9 or 12b | 2-3 days | Medium |
| Convert tools to `#[tool]` proc macro | 12b | 2 days | Low |
| DeepSec CI integration | Evaluate | — | Low |
| **Statistical guardrails** (cosine z-score drift + Shannon entropy) | 11 | 2-3 days | Medium-High |
| **WebSocket transport** (alongside SSE for agentic loops) | 9/12 | 2-3 days | Medium-High |
| **smgglrs-flow DAG test framework** (PTA/dominator validation) | 12 | 3-4 days | Medium |
| **Event-driven triggers** (Jarvis: email/Slack/calendar → agent) | 5 | 3-5 days | Medium |
| **fd-passing TOCTOU mitigation** (smgglrs-tools-file) | 12b | 1-2 days | Medium |

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
| Observability (structured metrics, monitoring) | tracing + audit.db (flow_results, flow_metadata) + blackbox. Per-agent tool/model call tables exist but are not populated (Phase 12a) | **Partial** |
| TUI (rich terminal interface) | CLI + web UI at localhost:9315. Rich TUI is a non-goal (Goose provides frontend) | **Non-goal** |

---

## Roadmap

### URGENT: Platform tool modules (git remote + forge integration)

**Goal**: Add remote Git operations (push/pull/fetch) to
`smgglrs-tools-git` and create per-provider forge modules
(`smgglrs-tools-github`, `smgglrs-tools-gitlab`, `smgglrs-tools-jira`)
exposing platform-specific tools with scoped permissions.

**Context**: Inspired by [service-gator](https://github.com/LobsterTrap/service-gator)
(Rust MCP server for scoped forge access). smgglrs already has
local git tools but no remote operations or forge API integration.
The tool naming convention (`<provider>_<resource>_<action>`) is
documented in DESIGN.md.

#### U1. Git remote operations

Add `git_push`, `git_pull`, `git_fetch` to `smgglrs-tools-git`.
Provider-agnostic, pure Git transport. Permissions: `git.push`,
`git.pull`, `git.fetch`. Push requires approval by default.

**Effort**: 2 days **Priority**: High
**Acceptance**: `git_push` with approval flow, ACL-gated per-repo.

#### U2. GitHub module (`smgglrs-tools-github`)

New crate. Tools: `github_pr_create`, `github_pr_list`,
`github_pr_review`, `github_issue_create`, `github_issue_list`,
`github_issue_comment`. Uses `gh` CLI or GitHub REST API.
MCP resources: `github://org/repo/pulls`, `github://org/repo/issues`.

**Effort**: 3-4 days **Priority**: High
**Acceptance**: Create a PR from an agent with scoped permissions,
glob-based ACLs on tool names (`github_pr_*`).

#### U3. GitLab module (`smgglrs-tools-gitlab`)

New crate. Tools: `gitlab_mr_create`, `gitlab_mr_list`,
`gitlab_mr_approve`, `gitlab_issue_list`, `gitlab_issue_comment`.
Uses `glab` CLI or GitLab REST API.

**Effort**: 3-4 days **Priority**: Medium-High
**Acceptance**: Create an MR from an agent with fork-only push support.

#### U4. Jira module (`smgglrs-tools-jira`)

New crate. Tools: `jira_issue_create`, `jira_issue_list`,
`jira_issue_get`, `jira_issue_transition`, `jira_issue_comment`.
Uses Jira REST API.

**Effort**: 2-3 days **Priority**: Medium
**Acceptance**: Create and transition an issue from an agent.

#### U5. Permission patterns for platform tools

Validate that deny-wins ACL globs work cleanly with three-part
tool names. Document permission recipes: read-only GitHub access,
push-to-fork-only, PR-create-without-merge, etc.

**Effort**: 1 day **Priority**: High **Depends on**: U2
**Acceptance**: Config examples in DESIGN.md, integration tests.

#### U6. GraphQL scope escape prevention

GitHub's GraphQL API allows a single query to span multiple
repositories, bypassing per-repo permission checks. The GitHub
module must either restrict to REST API only, or parse the GraphQL
AST (via `graphql-parser`) to extract repository arguments and
validate each against allowed repos before forwarding.

**Effort**: 1-2 days **Priority**: High **Depends on**: U2
**Acceptance**: GraphQL query spanning two repos where only one is
allowed is rejected. Unit tests for query extraction.

#### U7. Policy engine sidecar (optional)

Add optional external policy engine integration for conditional
policies (time-based access, multi-approval gates, environment
restrictions). Policy engine runs as a sidecar, queried via
localhost HTTP. Can only further restrict access — never grant
beyond what TOML ACLs allow.

**Cedar first** (preferred):
- Formal verification of policy properties (addresses FIDES gap)
- Explicit deny semantics match our deny-wins ACL model
- 42-60x faster than Rego in benchmarks
- Rust SDK (`cedar-policy` crate) — native integration, no sidecar
  needed. Embed Cedar engine in-process for zero-latency evaluation.
- Deterministic, safe (no loops, no side effects)
- Emerging as the MCP access control standard (Natoma, AWS REX)

**OPA/Rego as fallback** (enterprise compatibility):
- CNCF graduated, massive enterprise adoption
- Enterprises bring existing Rego policy bundles
- Runs as sidecar, queried via localhost HTTP
- Rego learning curve is steep (Datalog-like)

**Other evaluated**: OpenFGA (Zanzibar-style, overkill for current
ACLs), Polar/Oso (app-authz, SaaS pricing), CEL (no deny
semantics), Sentinel (IaC only).

**Effort**: 3-4 days **Priority**: Medium **Depends on**: U5
**Acceptance**: Cedar policy denying a tool call that TOML ACLs
would allow. Feature-gated, zero overhead when disabled. OPA
sidecar as alternative backend behind same interface.

#### U8. Kubernetes-friendly config reload

Watch config parent directory (not file) via inotify for atomic
symlink replacement (Kubernetes ConfigMap pattern). 50ms debounce
for temp-file-then-rename. Graceful degradation: invalid config
keeps the previous valid state, logs the error.

**Effort**: 1-2 days **Priority**: Medium-High
**Acceptance**: ConfigMap-mounted scope file update takes effect
within 1s without restart. Invalid TOML keeps old config.

---

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

#### 1g. Negative constraints in persona schema (NEW)

Add `negative_constraints` as a first-class field in persona YAML.
Currently directives only specify positive behavior ("do X"). Negative
constraints ("do NOT do Y") are proven to narrow the output space and
reduce noise without sacrificing essential information:

- New field: `negative_constraints: [str]` in persona YAML
- Weaver injects as "Do NOT" instructions after the mandate
- Examples: "Do NOT use marketing language", "Do NOT pad responses
  with caveats", "Do NOT explain what the code does"
- Separate from heuristics (which are conditional guidance) — these
  are absolute prohibitions

**Effort**: 0.5 day. **Priority**: Low.
**Acceptance**: Weaver emits negative constraints in system prompt.

Reference: Systematic prompting guide (2026-05-03) — negative
constraints as prompt-layer technique for precision.

**Why first**: The cognitive core is Myelix's identity. Without it,
agents are generic. Every other feature builds on top of personas.

#### 1e. Context budget → tool output compression

**Crate**: `smgglrs-cognitive` (budget.rs) + `smgglrs-core` (CallContext)

`ContextBudget` exists but tools ignore it. Wire budget awareness
into `CallContext` so modules self-compress based on remaining tokens:

- Add `remaining_tokens: Option<usize>` to `CallContext`
- `CallToolResult::compress(max_tokens)` method that truncates
  tool output to fit (RTK pattern: 60-90% token reduction)
- Intent-based compression: `file_read` returns summary if budget
  is tight, full content if budget is ample (Strands pattern)
- Weaver applies budget after tool output injection

**Effort**: 2-3 days. **Priority**: High.
**Acceptance**: Self-review flow completes with 40% fewer tokens.

#### 1f. Bidirectional persona bridge

**Crate**: `smgglrs-cognitive` (new `bridge.rs`)

Import and export personas across agent frameworks:

- **Import**: Anthropic-style agent plugin dirs → cognitive YAML
  (`agents/*.md` → Persona, `skills/*.md` → Directive,
  `scripts/*.py` → upstream tool definitions)
- **Export**: persona + heuristics + directives → single markdown
  for Claude Code, Cursor, or other systems
- CLI: `smgglrs persona import <dir>`, `smgglrs persona export <name>`

**Effort**: 2-3 days. **Priority**: High.
**Acceptance**: Round-trip import/export preserves persona semantics.

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

#### 5j. Event-driven agent triggers (NEW — Jarvis)

**Crate**: `smgglrs-server` (new `triggers/` module)

Add push-triggered agent activation for Project Jarvis. Agents
currently only activate on explicit MCP requests (pull model).
Event triggers start agent flows when external events occur:

- **Email trigger**: IMAP IDLE on configured mailboxes. On new
  email, spawn a flow that reads, summarizes, classifies priority,
  and alerts via D-Bus notification if urgent.
- **Slack trigger**: Slack Events API webhook (or RTM for
  self-hosted). Filter by channel/mention, summarize threads,
  flag action items.
- **Calendar trigger**: CalDAV polling (Google Calendar, Nextcloud).
  Pre-meeting: pull context from relevant docs/emails. Post-meeting:
  summarize notes if integrated with transcription.
- **File trigger**: inotify on configured directories. New file
  triggers indexing, classification, or processing flow.

Each trigger maps to a flow template (Phase 2c) with event
payload as parameters. Triggers respect IFC labels (email content
tagged `Confidentiality::Sensitive` at minimum).

**Use case**: "Agent that reads/summarizes/prioritizes/alerts on
email and Slack so I focus on important things."

**Effort**: 3-5 days (core + email trigger). **Priority**: Medium.
**Acceptance**: New email arrives, agent summarizes and sends
D-Bus notification with priority classification.

Reference: Writer Playbook triggers (VentureBeat, 2026-05-08),
Project Jarvis voice-first assistant design.

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

#### 7c. Agentic RAG L2

**Crate**: `smgglrs-rag` (new `agentic.rs`)

Move from passive retrieval to active, multi-step retrieval:

- **Query decomposition**: Break complex queries into sub-queries
  routed to vector search, FTS5, or upstream MCP resources
- **Self-correction loop**: Evaluate retrieved context relevance
  before sending to the LLM; re-query if below threshold
- **Multi-hop chaining**: Answer requires combining results from
  multiple retrievals (e.g., "find the function that calls X,
  then check its error handling")
- Uses existing `smgglrs-flow` DAG for multi-step orchestration

**Effort**: 3-5 days. **Priority**: High.
**Depends on**: 7a (reranker provides relevance scoring for
self-correction), 7b (caching avoids redundant sub-queries).
**Acceptance**: Multi-hop retrieval test finds correct answer
across 3+ document hops.

#### 7d. Nomic Embed v1.5 evaluation

**Crate**: `smgglrs-model` (OnnxBackend) + `smgglrs-rag` (store)

Evaluate as replacement for current embedding model:

- Matryoshka dimensions: 768 (search) / 1536 / 3072 (re-rank)
- Apache 2.0 license, ONNX export available
- Two-stage retrieval: 768-dim fast search → 3072-dim re-rank
- Also evaluate GeminiEmbedding as cloud-tier fallback
- Benchmark: recall@10 vs current model on project codebase

**Effort**: 2 days. **Priority**: Medium-High.
**Acceptance**: Recall@10 improves or matches at lower latency.

### Phase 8: Warp-informed UX patterns (NEW — 2026-05-04)

Patterns adopted from studying Warp's open-source codebase
(github.com/warpdotdev/warp, AGPL-3.0). All items are clean-room
re-implementations of design patterns, not code copies.

#### 8a. Typed agent action/result model ✅ (2026-05-05)

Adopt Warp's action/result enum symmetry pattern for `smgglrs-agent`.
Currently, tool results are flat `CallToolResult` (text content +
is_error). A typed model enables better rendering, auto-approval,
cancellation, and audit:

- `AgentAction` enum: `FileRead`, `FileWrite`, `GitStatus`,
  `GitCommit`, `RagSearch`, `ShellCommand`, `McpToolCall`,
  `StartAgent`, `SendMessage`, `AskUser`, etc.
- `AgentActionResult` enum: mirrors each action with
  Success/Error/Cancelled variants.
- Metadata methods: `is_read_only()`, `risk_level()`,
  `user_friendly_name()`, `cancelled_result()`.
- Wire into permission engine: `smgglrs-security` ACL decisions
  use `risk_level()` for auto-approval thresholds.
- Audit: structured entries in blackbox log (action type, args,
  result, timing, risk classification).

**Effort**: 2-3 days. ~500 lines in smgglrs-agent + wiring.

#### 8b. MCP config import ✅ (2026-05-05)

Let users import upstream MCP server configs from existing tools
without maintaining separate smgglrs config:

- Parse Claude Desktop format (`.mcp.json` with `mcpServers` key)
- Parse VSCode format (`mcp.servers` key)
- Parse Codex TOML format (`[mcp_servers.name]` tables)
- Normalize all to smgglrs's `[[upstream]]` config entries
- CLI: `smgglrs config import-mcp <path>` to merge into config.toml
- Auto-discovery: scan `~/.claude.json`, `.mcp.json` in project root
- Secret-safe: `#[serde(skip_serializing)]` on credential fields
  to prevent accidental exposure in config dumps.

**Effort**: 1 day. ~200 lines in smgglrs-server/src/config.rs.

#### 8c. Config schema generation (MEDIUM priority)

Generate JSON Schema from smgglrs config types for editor
autocomplete in TOML files:

- Add `schemars::JsonSchema` derives to config structs
- CLI: `smgglrs schema > config.schema.json`
- Hot-reload: file watcher on `config.toml`, update in-memory
  config without restart (load-only, no write-back loop)
- Validate on load with defaults for invalid values

**Effort**: 1 day. Add derives + 50-line CLI subcommand.

#### 8d. Computer use Actor trait (MEDIUM priority)

Clean platform abstraction for `smgglrs-modal-vision`:

- `Actor` trait: `async fn perform_actions(&mut self, actions: &[Action]) -> ActionResult`
- `Action` enum: `Wait`, `MouseDown/Up/Move`, `TypeText`, `KeyDown/Up`
- Platform auto-detection: check `WAYLAND_DISPLAY` / `DISPLAY` env vars
- `ScreenshotParams`: `max_long_edge_px`, `max_total_px` for LLM-friendly sizing
- Use `xcap` (MIT) for actual capture, not Warp's XDG portal code

**Effort**: 2 days. ~300 lines in smgglrs-modal-vision.

#### 8e. Isolation context detection (MEDIUM priority)

Detect runtime isolation environment for OpenShell integration:

- `IsolationContext` struct: detect Podman container, libkrun VM,
  OpenShell sandbox, bare metal via env vars + cgroup heuristics
- Layered detection: explicit env var > heuristic checks
- Workload token abstraction for identity federation
- Memoize with `OnceLock` for process lifetime

**Effort**: 0.5 day. ~100 lines in smgglrs-model-runtime.

#### 8f. ToolBlock structured output (LOW-MEDIUM priority)

Block-based tool execution model for future CLI/TUI:

- `ToolBlock`: `block_id: Uuid`, `tool_name`, `arguments`,
  `result: CallToolResult`, `started_at`, `duration`, `status`
- Each tool execution produces one addressable block
- Blocks carry metadata for rendering (exit code, timing, risk)
- Foundation for eventual terminal-style agent UX

**Effort**: 1 day. ~150 lines in smgglrs-agent.

#### 8g. Intent-based tool grouping

**Crate**: `smgglrs-core` (server, dispatch) + `smgglrs-agent` (tool_loop)

Reduce tool count per request for small models that struggle with
large tool lists:

- Group fine-grained tools into intent-based tools: `file_read` +
  `file_write` + `file_edit` → `file_operate(op, path, ...)`
- Semantic tool discovery: embed tool descriptions at startup,
  match against query, expose only relevant subset to the model
- Config: `[server] tool_grouping = "none" | "intent" | "semantic"`
- Backward compatible — ungrouped mode remains the default

**Effort**: 2-3 days. **Priority**: Medium-High.
**Acceptance**: Small models (≤10B) succeed at tool calling with
grouped tools where they previously failed with 40+ individual tools.

#### 8h. Multi-hypothesis tool routing (NEW)

Use verbalized sampling to improve tool selection in smgglrs-flow
and smgglrs-agent tool loops:

- Instead of the LLM picking one tool, prompt for 3 ranked
  candidates with confidence scores and rationale
- The router applies permissions/IFC checks to each candidate
  in rank order, executing the first viable one
- Reduces re-prompting on permission denials (currently the LLM
  picks a tool, gets denied, re-reasons, picks another — wastes
  iterations and tokens)
- Config: `tool_routing = "single" | "ranked"` (default: single)
- Adds ~200 tokens per tool selection but saves full re-prompt
  cycles on denial (~2000+ tokens each)

**Effort**: 1-2 days. **Priority**: Low.
**Acceptance**: Permission denial triggers fallback to next-ranked
tool without re-prompting the model.

Reference: Verbalized sampling (2026-05-03) — multi-hypothesis
output with confidence scores for decision-making.

### Phase 9: Full MCP spec coverage (2026-05-04, mostly complete)

**Goal**: smgglrs-protocol covers 100% of the MCP 2025-03-26 spec,
including proc macros for third-party module authors. Competitive
parity with rmcp (official Rust MCP SDK, 4.7M downloads) while
maintaining our differentiators (IFC labels, permissions extension,
A2A client, resilient upstream proxy).

**Current coverage**: ~35/39 features. Remaining: completion/complete,
logging/setLevel, resources/subscribe+unsubscribe (4 methods not dispatched).

#### 9a. Missing types — batch 1 ✅ (2026-05-05)

Add missing fields and types that are <50 lines each:

| Feature | What to add | Lines |
|---------|------------|-------|
| `ping` | Match arm in dispatch returning `{}` | 5 |
| `instructions` field | `Option<String>` on `InitializeResult` | 2 |
| Tool annotations | `ToolAnnotations` struct (readOnlyHint, destructiveHint, idempotentHint, openWorldHint, title) + field on `ToolDefinition` | 20 |
| Resource size | `Option<u64>` on `ResourceDefinition` | 2 |
| Image content | `Content::Image { data, mime_type }` | 10 |
| Audio content | `Content::Audio { data, mime_type }` | 10 |
| Embedded resource | `Content::Resource { resource: ResourceContent }` | 10 |
| MCP error codes | Named constants: `RequestCancelled = -32001`, `ContentTooLarge = -32002` | 10 |
| Roots types | `Root { uri, name }`, `ListRootsResult` | 15 |
| Cancellation | `CancelledNotification { request_id, reason }` | 15 |
| Progress notification | `ProgressNotification { progress_token, progress, total, message }` | 15 |

**Effort**: 1 day. ~115 lines of types + tests.

#### 9b. Missing types — batch 2 ✅ (2026-05-05)

| Feature | What to add | Lines |
|---------|------------|-------|
| Logging | `LoggingCapability`, `SetLevelParams`, `LoggingLevel` enum (8 syslog levels), `LoggingMessageNotification` | 60 |
| Sampling | `CreateMessageParams`, `CreateMessageResult`, `ModelPreferences`, `ModelHint`, `SamplingMessage` | 100 |
| Completions | `CompleteParams`, `CompleteResult`, `PromptReference`, `ResourceReference` | 50 |
| Elicitation | `CreateElicitationParams`, `ElicitationResult`, `ElicitationSchema` | 60 |
| Resource templates | `ResourceTemplate` struct + `ListResourceTemplatesResult` | 30 |

**Effort**: 2 days. ~300 lines of types + tests.

#### 9c. Pagination infrastructure ✅ (2026-05-05)

Generic pagination pattern for all list operations:

- `PaginatedParams { cursor: Option<String> }` trait or struct
- `PaginatedResult<T> { items: Vec<T>, next_cursor: Option<String> }`
- Add cursor fields to: `ListToolsResult`, `ListResourcesResult`,
  `ListPromptsResult`, `ListResourceTemplatesResult`
- Add cursor param to list request params
- Server-side: page through module tool registrations (currently
  returns all at once — fine for now, but needed for spec compliance)

**Effort**: 1 day. ~100 lines.

#### 9d. Notification infrastructure ✅ (2026-05-05)

Server-initiated notifications over SSE. This is the biggest
structural gap — blocks 5 features:

- Notification bus: `tokio::broadcast` channel in session state
- `notify()` method on session: serialize notification, push to SSE stream
- Implement: `notifications/tools/list_changed`,
  `notifications/resources/list_changed`,
  `notifications/resources/updated`,
  `notifications/prompts/list_changed`,
  `notifications/progress`
- Module trait gains `on_change(&self) -> broadcast::Receiver<Notification>`
- Resource subscription store: track which resources each session
  has subscribed to, emit `resources/updated` on change

**Effort**: 3 days. ~400 lines across smgglrs-core + smgglrs-protocol.

#### 9e. Progress tracking ✅ (2026-05-05)

Request-level progress reporting:

- `RequestMeta { progress_token: Option<ProgressToken> }` on all
  request params (tools/call, resources/read, prompts/get)
- Module handlers receive progress token, can emit
  `notifications/progress` via notification bus (9d)
- Wire into long-running tools (RAG indexing, file operations)

**Effort**: 1 day. ~100 lines. Depends on 9d.

#### 9f. Stdio server transport ✅ (2026-05-05)

Server-mode stdio transport (currently only client-side exists):

- Read JSON-RPC from stdin, write to stdout
- Reuse existing dispatch logic from HTTP transport
- Enables: `smgglrs stdio` mode for IDE integration (similar
  to how LSP servers work over stdio)
- Claude Desktop and Cursor can spawn smgglrs as a stdio subprocess

**Effort**: 2 days. ~200 lines in smgglrs-core.

#### 9g. OAuth 2.0 authorization framework ✅ (2026-05-05)

MCP spec defines OAuth for client-server auth. smgglrs currently
uses BLAKE3 tokens:

- Implement MCP OAuth flow: discovery → authorize → token → refresh
- Support as alternative to BLAKE3 (not replacement)
- Enables third-party clients (not just trusted local agents)
  to authenticate via standard OAuth
- Reuse existing auth chain in smgglrs-security

**Effort**: 3-4 days. ~500 lines across smgglrs-security + smgglrs-core.

#### 9h. Proc macro crate: `smgglrs-macros` ✅ (2026-05-05)

Proc macro for ergonomic tool/prompt/resource definition,
competing with rmcp's `#[tool]` macro:

```rust
#[smgglrs::tool(
    name = "file_read",
    description = "Read a file from disk",
    annotations(read_only, idempotent),
)]
async fn file_read(
    #[arg(description = "Path to the file")] path: String,
    #[arg(description = "Max lines", default = 100)] limit: u32,
    ctx: CallContext,
) -> CallToolResult {
    // ...
}
```

The macro generates:
- `ToolDefinition` with JSON Schema from Rust types (via `schemars`)
- Handler closure wrapping the function
- `(ToolDefinition, Handler)` pair for `Module::tools()` registration
- Compile-time validation of required vs optional args

Also provide `#[smgglrs::prompt]` and `#[smgglrs::resource]` macros.

**Differentiators over rmcp**: IFC label propagation built into
generated handlers, permission annotation on tool definitions,
CallContext with session/security state.

**Effort**: 4-5 days. New crate ~800 lines (proc macro + tests).

#### 9i. Spec compliance test suite

Automated test suite verifying spec compliance:

- One test per MCP method: correct request/response serialization
- Error code tests: all standard + MCP-specific codes
- Transport tests: stdio and HTTP round-trips
- Notification tests: verify emission on state changes
- Pagination tests: cursor-based iteration
- Run against rmcp's test vectors if available

**Effort**: 2 days. ~500 lines of tests.

#### MCP coverage summary

| Phase | Features | Status |
|-------|----------|--------|
| 9a. Trivial types | 11 features | ✅ Done |
| 9b. Medium types | 5 features | ✅ Done |
| 9c. Pagination | 4 list endpoints | ✅ Done |
| 9d. Notifications | 5 notifications | ✅ Done |
| 9e. Progress | progressToken | ✅ Done |
| 9f. Stdio server | 1 transport | ✅ Done |
| 9g. OAuth | auth flow + endpoints | ✅ Done |
| 9h. Proc macros | `#[tool]` macro | ✅ Done |
| 9i. Test suite | Compliance tests | Remaining |
| **Remaining** | completion, logging, subscribe | ~1 day |

**smgglrs differentiators** (not in rmcp, not in MCP spec):

| Feature | Location | Description |
|---------|----------|-------------|
| IFC data labels | `label.rs` | Bell-LaPadula lattice with PII level. Taint propagation through tool chains. |
| Permission negotiation | `permissions.rs` | 4-method extension (request/grant/deny/list). Scoped, time-bounded. |
| A2A protocol client | `a2a.rs` + `a2a_client.rs` | Full A2A v0.2.5 types + HTTP client with IFC header propagation. |
| Resilient upstream proxy | `upstream/` | 3 transports + exponential backoff, sleep detection, per-request timeout. |
| Safety hook pipeline | smgglrs-security | Content filtering as hook, not hardcoded in request path. |

#### 9j. WebSocket transport for agentic loops (NEW)

**Crate**: `smgglrs-core` (transport) + `smgglrs-protocol` (client)

Add WebSocket as an alternative transport alongside SSE for
multi-step tool-use workflows. OpenAI measured 40% latency
reduction for agentic workloads by eliminating repeated HTTP
handshakes:

- Server-side: `ws://` upgrade on existing Axum router, reuse
  JSON-RPC dispatch. Single persistent connection per session.
- Client-side: `smgglrs-protocol` WebSocket upstream client
  alongside existing stdio/HTTP/SSE transports.
- **Warm-up pattern**: Client sends system prompt + tool
  definitions on connect, before first request. Reduces
  first-tool-call latency.
- Zero Data Retention compatible (same as SSE — no replay buffer).
- Feature-gated: `transport-ws` feature flag.
- Backward compatible: SSE remains the default transport.

Particularly valuable for smgglrs-agent client SDK in tight
tool-use loops (10+ tool calls per turn).

**Effort**: 2-3 days. **Priority**: Medium-High.
**Acceptance**: Agent tool loop over WebSocket shows measurable
latency reduction vs SSE in 10+ call sequences.

Reference: OpenAI WebSocket Responses API (InfoQ, 2026-05-08),
40% latency reduction at Vercel, 30% at Cursor.

### Phase 10: Papers (restructured 2026-05-06)

Restructured from 4 narrow papers to 3 stronger papers.
The audit blackbox paper is absorbed into the security paper.
The model cards paper is absorbed into the persona paper.
A new paper on autonomous multi-domain review is added.

#### 10a. Security Gateway (flagship, full paper)

**Title**: "smgglrs: A Security Microkernel for AI Agent Infrastructure"
**Target**: USENIX Security / IEEE S&P workshop
**Outline**: `docs/papers/security-gateway.md` (471 lines)

Contributions:
1. Gateway architecture for MCP security (single chokepoint)
2. Bell-LaPadula IFC with per-value taint tracking
3. Capability token delegation with privilege attenuation
4. Hash-chained audit blackbox (absorbs old blackbox paper)
5. PII pipeline: regex + NER + file paths + pseudonymization + IFC
6. Containerized agent sandboxes with resource limits
7. Typed action risk levels for auto-approval decisions
8. OAuth 2.0 authorization framework

Updates needed:
- Add OAuth 2.0 (not in current outline)
- Add PII pipeline as content safety contribution
- Add containerized agents as defense in depth
- Add typed AgentAction/RiskLevel as permission mechanism
- Replace "six manual audit rounds" with "automated self-review
  (23+8 containerized agents, 330+ tool calls)"
- Add OpenShell/Kaiden as related work on sandboxing
- Add Claude Code Review cross-validation as related work

References to add: OpenShell, Kaiden, Claude Code Review,
AutoData (if 11c done), Strands (tool compression), OWASP.

#### 10b. Persona-Driven Orchestration (full paper)

**Title**: "Persona-Driven Multi-Agent Orchestration with Cognitive
Identity and Adaptive Memory"
**Target**: AAAI / NeurIPS workshop on agents
**Outline**: `docs/papers/persona-orchestration.md` (388 lines)

Contributions:
1. Cognitive core: Forge + Weaver, 43 personas, token budgeting
2. Composite model cards for agent-driven model selection
   (absorbs old model cards paper)
3. Team orchestration with dynamic persona selection
4. Memory decay + distillation as working memory management
5. Self-review as concrete evaluation (26 agents, 125 files,
   192 tool calls, 2.77M tokens)

Updates needed:
- Self-review flow results as evaluation data
- Model selection scoring (penalize ≤10B, prefer 12-20B)
- CodeAct / plan_execute as execution strategy
- Persona bridge (if 1f done) for generality argument
- Hermes trace export for reproducibility
- TOML model registry (replaces hardcoded constants)
- Context budget + RTK compression (if 1e done)

References to add: CodeAct, Strands, RTK, BLD (2604.07466),
Cloudflare Agent Memory, AgentSwing (2603.27490).

#### 10c. Autonomous Multi-Domain Review (NEW, workshop paper)

**Title**: "Domain-Agnostic Autonomous Review via Dynamic Persona
Selection in Multi-Agent Flows"
**Target**: ISSTA / ASE workshop, or SCORED

Contributions:
1. Domain-agnostic review flow: scout classifies project domain,
   planner selects personas from catalog, specialists execute
2. Comparison: hardcoded vs dynamic persona selection on same
   codebase — quality, coverage, persona relevance, cost
3. Resilient JSON parsing for model-generated task arrays
   (markdown stripping, id-boundary recovery)
4. Flow resumability: persist state to audit.db, resume timed-out
   flows without re-running completed tasks
5. Self-improvement loop: audit → fix → test → verify cycle
   with git worktree isolation

Data collection (in progress):
- Run `comprehensive-review.yaml` (hardcoded) and `review.yaml`
  (dynamic) on smgglrs — compare findings
- Run `review.yaml` on a non-code project — show domain adaptation
- Run `improve.yaml` for 3-5 cycles — convergence curves
- Measure: issues found, fix rate, hallucination rate, token cost

References: Claude Code Review (<1% FPR with cross-validation),
SemaClaw (harness engineering), LangChain (Worker/Leader pattern).

#### Shared bibliography (5 arXiv + 25 named systems)

| Reference | Used in |
|-----------|---------|
| SemaClaw (2604.11548) | All papers |
| PersonaVLM (2604.13074) | 10b (memory types, evolution) |
| MTL (2604.14004) | 10b (abstract > raw traces) |
| AgentSwing (2603.27490) | 10b (context compaction) |
| BLD (2604.07466) | 10b (cross-tokenizer distillation) |
| Goose | 10a (unsecured baseline) |
| OpenShell | 10a (defense in depth) |
| Kaiden | 10a (sandboxing patterns) |
| AWS Agent Registry | 10b (governance layer) |
| Claude Code Review | 10a, 10c (cross-validation) |
| Strands / RTK | 10b (context compression) |
| CodeAct | 10b (plan_execute) |
| AutoData | 10a (adversarial eval, if 11c done) |
| LangChain | 10a, 10c (Worker/Leader convergence) |
| ZeroClaw | 10a (Rust competitor baseline) |
| OWASP Top 10 for LLM | 10a (threat model) |
| EU AI Act Article 14 | 10a (compliance) |
| NVIDIA Vera Rubin | 10b (agentic token economics, 15x multiplier) |
| OpenAI Privacy Filter | 10a (PII detection, if 11d done) |
| Vercel DeepSec | 10a, 10c (AI security scanning, multi-stage pattern) |

### Phase 11: Model & safety research (from tech watch 2026-05-06)

Research-driven items that require evaluation before committing
to implementation. Each item has a research gate.

#### 11a. ONNX/ort deepening

**Crates**: `smgglrs-model` (OnnxBackend), `smgglrs-model-runtime`

Track and contribute to the ONNX/ort-rs ecosystem:

- RDT (Recurrent Depth Transformer) loop/recurrence operators
  in ONNX — required to run RDT models in-process
- ort-rs GenAI API bindings: KV cache management, buffer sharing
  for efficient autoregressive generation
- Moshi/KAME ONNX export viability (see 11b)

**Effort**: Research + upstream PRs. **Priority**: Medium.
**Gate**: Are RDT operators merged in ONNX spec? Is ort-rs GenAI
API stable enough to depend on?

#### 11b. KAME tandem voice architecture

**Crate**: `smgglrs-modal-voice`

Evaluate Moshi-based speech-to-speech as replacement for the
current cascaded ASR → LLM → TTS pipeline:

- Tandem: fast S2S front-end + oracle stream from LLM back-end
- Latency target: <500ms first-byte (vs ~2s cascaded)
- Requires ONNX export of Moshi encoder/decoder (see 11a)
- Evaluate against current Whisper + Piper cascade

**Effort**: Research. **Priority**: Medium.
**Gate**: Is Moshi exported to ONNX? Does latency improve in
practice on our hardware (RTX 5090)?

#### 11d. PII redaction via ONNX token classifier (NEW)

**Crate**: `smgglrs-security` (new `pii_ner_hook.rs`)

Evaluate OpenAI's `privacy-filter` model as an additional PII
detection layer alongside the existing regex + ProtectAI NER:

- Standard `AutoModelForTokenClassification` (HuggingFace)
- 8 PII categories: names, emails, phones, addresses, account
  numbers, secrets, dates, URLs
- BIO tagging with configurable confidence threshold (default 0.50)
- Typed redaction masks: `[PRIVATE_EMAIL]`, `[PRIVATE_PHONE]`, etc.
  (more informative than current `[REDACTED:category]`)

**Implementation as SafetyHook:**
- Export model to ONNX (standard transformers → ONNX pipeline)
- Load in-process via OnnxBackend (same as ProtectAI models)
- Wire as `PiiRedactionHook` in the hook pipeline (pre-call for
  outbound content, post-call for inbound results)
- Reverse-order span replacement preserves index accuracy

**Research gate**: Is the model ONNX-exportable without quality
loss? How does it compare to ProtectAI on our test cases?

**Effort**: 1-2 days (eval) + 1 day (integration). **Priority**: Medium.
**Acceptance**: Model runs in-process, detects PII categories that
regex misses, <50ms latency on typical tool outputs.

Reference: OpenAI Privacy Filter pipeline (2026-04-29).

#### 11c. Adversarial safety evaluation

**Crates**: `smgglrs-security` (safety classifier),
`smgglrs-flow` (pipeline orchestration)

Generate adversarial training data for the safety classifier
using AutoData's Challenger/Weak/Strong/Verifier pattern:

- Challenger generates adversarial prompts targeting specific
  safety categories (jailbreak, PII extraction, prompt injection)
- Weak model produces naive responses
- Strong model produces robust responses
- Verifier scores both; delta becomes training signal
- Orchestrated as a `smgglrs-flow` DAG (4 specialists)

**Effort**: 3-5 days. **Priority**: Medium.
**Depends on**: Flow engine (Phase 2), safety classifier (done).
**Acceptance**: Safety classifier F1 improves on held-out test
set after fine-tuning on generated data.

#### 11e. Statistical guardrails for SafetyHook (NEW)

**Crate**: `smgglrs-security` (new `statistical_hook.rs`)

Add statistical methods alongside regex and ML safety filters,
inspired by two complementary techniques:

- **Semantic drift detection**: Embed agent output, compute cosine
  distance to baseline context, z-score flags statistical outliers.
  High z-score = response drifted off-topic or into unsafe territory.
  Baseline built from per-session context window (moving average of
  recent embeddings).
- **Confidence thresholding**: Shannon entropy on model output token
  distribution detects uncertainty / likely hallucination. High
  entropy = model is guessing. Requires logprobs from model backend
  (available in llama-server, vLLM, OpenAI-compat).

Both are lightweight (<5ms per check with cached embeddings) and
complement the existing regex + ONNX classifier pipeline:

| Layer | Method | Catches |
|-------|--------|---------|
| Regex | Pattern matching | Known-bad content (SSN, profanity) |
| ONNX classifier | ML classification | Trained categories |
| Cosine z-score | Statistical drift | Off-topic, jailbreak steering |
| Shannon entropy | Confidence check | Hallucination, uncertainty |

Wire as `StatisticalGuardrailHook` in the hook pipeline (post-call).
Configurable thresholds per persona (creative personas tolerate
higher drift).

**Effort**: 2-3 days. **Priority**: Medium-High.
**Acceptance**: Detects prompt injection that steers agent off-topic
where regex misses it. <5ms latency overhead.

Reference: Machine Learning Mastery statistical guardrails
(2026-05-06), tech watch 2026-05-08.

### Phase 12: Observability & infrastructure debt

Items collected from Code Health, self-review findings, DESIGN.md
gaps, and audit metrics gaps. Grouped into sub-phases by area.

#### 12a. Flow audit completeness (HIGH — blocks paper data)

**Crate**: `smgglrs-server/src/flow_tools.rs`, `smgglrs-agent`

Fix 8 metrics gaps that prevent accurate paper evaluation:

1. **Per-task duration**: `record_task_results_to_audit` sets
   `started_at = completed_at`. Fix: capture start time when
   task is spawned, end time when result is collected.
2. **Per-task iterations**: always NULL. Fix: parse `iterations`
   from containerized agent JSON output and store.
3. **Per-task tokens**: cumulative not per-task. Fix: record
   delta or per-agent token count.
4. **Resolved model name**: stored as "auto". Fix: record the
   model selected by `select_model_for_task`.
5. **audit_tool_calls**: empty. Fix: wire `AuditLog::record_tool_call`
   into the agent tool loop for flow agents.
6. **audit_model_calls**: empty. Fix: same as above for model calls.
7. **GPU utilization sampling**: no recording. Fix: periodic
   `nvidia-smi` sampling during flow execution.
8. **Structured finding format**: specialists output free-text.
   Fix: define JSON schema for findings with severity, file, line,
   category fields.

**Effort**: 3-4 days. **Priority**: High (blocks papers).
**Acceptance**: Rerun comparative flows, all 8 columns populated.

#### 12d. smgglrs-flow DAG test framework (NEW)

**Crate**: `smgglrs-flow` (new `validation/` module)

Structural validation for non-deterministic flow execution,
beyond unit tests and formal proofs. Adapts GitHub's Prefix
Tree Acceptor / dominator analysis approach:

- **Capture**: Record 2-10 successful flow execution traces
  (agent states, tool calls, outputs at each DAG node).
- **Generalize**: Merge traces into a PTA using semantic
  equivalence (cosine similarity on node outputs, configurable
  threshold).
- **Extract dominators**: Apply compiler-theory dominator analysis
  to identify essential states every successful path must traverse.
  These are the mandatory milestones regardless of routing variation.
- **Validate**: New executions pass if they contain all dominator
  states in topological order, regardless of incidental variation
  (extra tool calls, different specialist ordering).

This addresses a real gap: flow execution is non-deterministic
(model routing, handoff decisions, back-edge conditions), so
exact-match testing is brittle. Dominator extraction gives
stable invariants.

GitHub measured 100% accuracy vs 82% self-assessment with this
approach.

**Effort**: 3-4 days. **Priority**: Medium.
**Depends on**: 12a (flow audit completeness — needs trace data).
**Acceptance**: Validate that a review flow always passes through
scout → planner → specialist stages regardless of which
specialists are selected.

Reference: GitHub "Validating Agentic Behavior" (2026-05-08),
Prefix Tree Acceptors, dominator analysis.

#### 12b. Infrastructure debt (MEDIUM)

Collected from Code Health, self-review findings, and DESIGN.md:

| Item | Source | Effort |
|------|--------|--------|
| Session store sharding (DashMap) | Self-review perf-01 | 1-2 days |
| Streaming model download | Self-review code-03 | 2-3 days |
| Upstream TLS | DESIGN.md gap | 2-3 days |
| Feature-gate ONNX | Code Health | Invasive |
| Convert tools to `#[tool]` macro | Phase 9h | 2 days |
| Sync ureq → async in authenticator | Self-review sec-01 | 1 day |
| fd-passing TOCTOU mitigation in file tools | AWS REX (2026-05-08) | 1-2 days |

#### 12c. Observability (LOW — nice to have)

| Item | Detail |
|------|--------|
| OpenTelemetry | Normalized spans for tool calls, model calls |
| Prometheus metrics | Request latency, token throughput, error rate |
| Structured tracing | JSON-format log output for log aggregation |

### Phase 13: Peer review readiness (2026-05-07 review)

Findings from a comprehensive academic review (5 specialized research
agents covering MCP security landscape, orchestration, memory/RAG,
privacy/compliance, and paper positioning). The landscape moved faster
than the documentation reflects — several claims that were novel in
late 2025 are now contested.

**Genuine differentiators** (confirmed unique after review):
1. Gateway-enforced IFC (vs FIDES planner-enforced)
2. IFC-gated inter-agent messaging (no orchestration framework does this)
3. PII cascade into vector embeddings with IFC taint elevation
4. Capability tokens + IFC + ring enforcement in single gateway

#### 13a. Critical (blocks paper submission)

| ID | Issue | Detail | Effort |
|----|-------|--------|--------|
| C1 | **FIDES differentiation** | Microsoft Research arXiv:2505.23643 (May 2025) does IFC for agents with formal proofs. Must expand from 1 sentence to full paragraph: gateway-enforced (smgglrs) vs planner-enforced (FIDES). Failure to cite prominently = fatal at security venues. | 0.5 day |
| C2 | **10+ competing MCP gateways** | Gravitee 4.10, Microsoft MCP Gateway, Traefik Hub, Kong 3.13, MintMCP (SOC2 Type II), Lunar.dev, Composio, Intercept, systemprompt-template. "No existing gateway provides security" is false as of May 2026. Position on IFC/capability tokens, not on being a gateway. | 0.5 day |
| C3 | **External evaluation** | Self-evaluation on own codebase is circular. Run on c-CRAB benchmark (code review), 5+ OSS projects, 3+ trials with statistical significance. Primary eval must be external; self-review becomes appendix case study. | 3-5 days |
| C4 | **Compliance framing** | EU AI Act Article 14 applies to high-risk AI systems (Annex III), not infrastructure gateways. Reframe all claims: "compliance infrastructure" not "compliance." SOC2/ISO 42001 similarly. | 0.5 day |
| C5 | **Microkernel analogy** | AIOS (COLM 2025, arXiv:2403.16971) and Agent-OS (2025) already use "microkernel" for agents. Either cite and differentiate, or switch to "security reference monitor" (more precise, less contested). | 0.5 day |
| C6 | **Paper 1 scope** | 8 contributions screams "systems paper disguised as security." Narrow to 3: gateway-enforced IFC, capability delegation with attenuation, hash-chained audit. Drop PII (table stakes), containers, typed actions, OAuth (a standard). | 1 day |

#### 13b. Significant (weakens credibility)

| ID | Issue | Detail | Effort |
|----|-------|--------|--------|
| S1 | Tool classification | `is_write_tool` uses substring matching ("write", "commit"). Use MCP tool annotations (`destructiveHint`, `readOnlyHint`) instead. | 1 day |
| S2 | Formal security invariants | FIDES has formal proofs. Add at least informal security invariants for IFC properties. | 1-2 days |
| S3 | HyDE stub | Listed as feature in 6-channel retrieval. Code returns empty. Either implement or remove from claims. | 1 day |
| S4 | Memory decay rate | Flat 0.001 for all entries. FadeMem (arXiv:2601.18642) and YourMemory use importance-modulated rates. Minimal code change. | 0.5 day |
| S5 | Sentence splitting | `split_at_sentences` falls back to fixed-interval (acknowledged in comment). Use tree-sitter for code-heavy workloads. | 1 day |
| S6 | EU identifier gap | Claims SIRET/passport regex but code only has IBAN/NIR. NER covers some via sfermion labels. Fix docs or add patterns. | 0.5 day |
| S7 | PII benchmarks | No F1/precision/recall on any standard benchmark. OpenAI Privacy Filter achieves F1 0.96-0.97. Run on a PII benchmark. | 1-2 days |
| S8 | Token revocation | Capability tokens have expiry/nonces but no revocation. DRS and Grantex emphasize this. | 1 day |
| S9 | Statistical significance | 3.5x efficiency from N=1 run. Need 3+ projects, 3+ runs each, confidence intervals. | 2-3 days |
| S10 | Pseudonym key separation | PseudonymMap reversal key in same process memory. GDPR Article 32 expects separate security domain. | 1 day |

#### 13c. Missing related work (consolidated)

| Reference | Paper | Priority |
|-----------|-------|----------|
| FIDES (arXiv:2505.23643, Microsoft Research) | 1, 2 | **Must cite** |
| AIOS (arXiv:2403.16971, COLM 2025) | 1 | **Must cite** |
| Agent-OS (2025, zero-trust microkernel) | 1 | **Must cite** |
| Gravitee / Kong / Traefik MCP gateways | 1 | **Must cite** |
| OWASP Top 10 for Agentic Applications 2026 | 1 | **Must cite** |
| CoSAI OASIS MCP Security document | 1 | **Must cite** |
| Block "Operation Pale Fire" red team | 1 | Should cite |
| A2ASECBENCH (ICLR 2026) | 1 | Should cite |
| 193-threat taxonomy (arXiv:2603.09002) | 1 | Should cite |
| Open Challenges MAS Security (arXiv:2505.02077) | 1 | Should cite |
| c-CRAB benchmark (arXiv:2603.23448) | 3 | **Must cite** |
| CodeAgent (EMNLP 2024) | 3 | **Must cite** |
| Code Broker (arXiv:2604.23088) | 3 | **Must cite** |
| MorphAgent (arXiv:2410.15048) | 2 | Should cite |
| Graph Harness (arXiv:2604.11378) | 2, 3 | Should cite |
| FadeMem (arXiv:2601.18642) | 2 | Should cite |
| Mem0 (graph + vector + KV hybrid memory) | 2 | Should cite |

#### 13d. Paper restructuring decisions

| Decision | Recommendation | Status |
|----------|---------------|--------|
| Paper 2 standalone vs fold into Paper 1 | Fold cognitive core into Paper 1 as persona-driven security policy. Paper 2's space (PersonaVLM, MTL, SemaClaw) is too crowded without external eval. | Decide |
| Paper 3 contributions | Drop JSON parsing resilience and flow resumability as contributions. Keep dynamic persona selection. Add c-CRAB evaluation. | Decide |
| Paper 1 venue | IEEE S&P workshop (ArtSec 2026) realistic. USENIX Security main requires adversarial eval + formal properties. | Decide |
| Paper 3 venue | SCORED (supply chain security) or ISSTA/ASE workshop. | Decide |

### Phase 14: Agentic OS completeness (2026-05-07)

smgglrs already implements ~80% of an Agentic OS: process table,
IPC (BLP-gated mailbox + taint-on-read blackboard), memory
management (decay, budget, knowledge store), DAG scheduler with
GPU semaphore, MAC (Bell-LaPadula, both properties), capability
tokens, audit blackbox. Five gaps remain to complete the
abstraction.

#### 14a. Agent signal (async interrupt)

**Crate**: `smgglrs-flow` (executor) + `smgglrs-agent` (tool loop)

Currently agents can only be stopped via timeout or `team_shutdown`.
Add async signal delivery to running agents:

- `agent_signal(agent_id, signal)` with signal types: `Interrupt`
  (cancel current tool call, return partial), `Terminate` (graceful
  shutdown), `Pause` / `Resume` (per-agent, not global)
- Wired via `tokio::sync::watch` channel on the Agent's tool loop
- Checked between tool-call iterations (cooperative, not preemptive)
- Preemption of in-flight inference: cancel via llama.cpp abort /
  vLLM request cancellation API

**Effort**: 1-2 days. **Priority**: Medium.
**Acceptance**: `Interrupt` a running specialist mid-review, receive
partial output. `Terminate` cleans up resources.

#### 14b. Kernel state as MCP resources

**Crate**: `smgglrs-core` (resource handlers)

Expose internal kernel state through the existing MCP resource
mechanism. No new namespace — use `smgglrs://` URI scheme:

| Resource URI | Content |
|---|---|
| `smgglrs://proc` | Process table: connected agents, rings, call counts |
| `smgglrs://proc/{agent}/taint` | Current IFC taint label for agent session |
| `smgglrs://proc/{agent}/capabilities` | Active capability set |
| `smgglrs://ifc/labels` | All session taint labels |
| `smgglrs://audit/recent` | Last N blackbox entries |
| `smgglrs://budget/gpu` | GPU semaphore: permits used/available |

These are read-only MCP resources, accessible to agents with
appropriate clearance. Enables self-awareness: an agent can
check its own taint level before deciding whether to attempt a
write.

**Effort**: 1 day. **Priority**: Medium.
**Acceptance**: `resources/read` on `smgglrs://proc` returns
JSON with all connected agents and their privilege levels.

#### 14c. Resource list filtering by agent permissions

**Crate**: `smgglrs-core` (resource dispatch)

Currently `resources/list` returns all resources regardless of
agent permissions. Filter the resource list the same way tools
are filtered — agents only see resources they have clearance
to read.

- Apply path ACLs to `file://` resources
- Apply read clearance (Simple Security Property) to all resources
- Apply tool globs from capability tokens to resource URIs

This completes the capability namespace: an agent with restricted
permissions doesn't know that restricted resources exist.

**Effort**: 0.5 day. **Priority**: Medium.
**Acceptance**: Agent with `readonly` permissions sees fewer
resources in `resources/list` than agent with `developer`.

#### 14d. Agent process hibernation (KV cache checkpoint)

**Crate**: `smgglrs-model-runtime` + `smgglrs-agent`

Save and restore full agent state including model KV cache for
suspend/resume across sessions. The agent equivalent of process
hibernation.

**Two-tier save strategy:**

| Tier | What's saved | Size | Resume | Always |
|---|---|---|---|---|
| Conversation | Turns, taint, variables, DAG position | ~KB | Re-prompt (rebuild KV) | Yes |
| KV cache | llama.cpp state via `llama_state_save_file` | ~GB | Instant (no re-prompt) | Optional |

**KV cache compression**: TurboQuant safe config (q8 keys, turbo3
values) compresses KV cache ~3x with zero quality loss. A 128K
context Gemma 4 KV cache drops from ~18GB to ~6GB — saveable to
NVMe in seconds.

**Runtime compatibility:**

| Runtime | KV save | Mechanism |
|---|---|---|
| llama-server (direct) | Yes | `llama_state_save_file` / `llama_state_load_file` |
| llama-server (Podman) | Yes | Same, via volume mount |
| vLLM | No | Paged attention KV is internal, no save API |
| Ollama | No | No state save API |

Model runtime exposes a `supports_kv_checkpoint: bool` capability
flag. When unavailable, fall back to conversation-only save
(accept re-prompt latency on resume).

**Compile-time KV cache safety** (inspired by TokenSpeed):
Design the save/restore API so invalid cache states are
unrepresentable in the type system. Use Rust ownership to
enforce:
- A saved cache is consumed on load (no double-restore)
- Cache validity is tied to model identity + quantization config
  (type-level association, not runtime check)
- Reuse restrictions enforced at compile time, not by convention
TokenSpeed's dual-plane scheduler achieves this in C++; Rust's
affine types give us stronger guarantees natively.

**Effort**: 3-4 days. **Priority**: Medium-High.
**Acceptance**: Suspend a running agent, restart smgglrs, resume
agent with restored conversation and KV cache. Measure resume
latency vs full re-prompt.

Reference: TokenSpeed compile-time KV cache safety (LightSeek
Foundation, 2026-05-07).

#### 14e. Preemptive scheduling (cancel in-flight generation)

**Crate**: `smgglrs-model` (backend trait) + `smgglrs-agent` (tool loop)

Cancel an ongoing model inference to give priority to a
higher-priority agent (e.g., voice input preempts batch review).

- Add `cancel(&self)` to `ModelBackend` trait
- `OpenAiBackend`: cancel via HTTP request abort
  (vLLM: `DELETE /v1/completions/{id}`, Ollama: close connection)
- llama.cpp: `llama_decode` supports abort flag
- Fair scheduling: per-agent token quotas prevent starvation.
  Agent exceeding quota gets deprioritized (next request queued
  behind others, not cancelled)
- Depends on 14a (agent signal) for the interrupt delivery path

**Effort**: 2-3 days. **Priority**: Medium.
**Depends on**: 14a, 14d (checkpoint before preemption).
**Acceptance**: Voice agent interrupts a batch review agent.
Batch agent's KV cache is checkpointed, voice agent gets GPU.
After voice completes, batch resumes from checkpoint.

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
- **Rich TUI**: CLI is sufficient; Goose or GNOME shell provides UX.
  Warp fork evaluated (2026-05-04) — warpui (MIT) is architecturally
  clean but AGPL contamination from internal deps makes extraction
  impractical. Adopt Warp's UX *patterns* (Phase 8) instead.
- **A2A server**: smgglrs already serves Agent Cards; A2A orchestration
  belongs in smgglrs-flow, not as a separate service
- **Desktop app**: Goose (or similar) serves as the frontend;
  smgglrs handles GNOME integration (D-Bus notifications, tray)
- **Adopt rmcp**: Evaluated (2026-05-04). Our hand-rolled MCP types
  carry IFC labels and permissions extensions that rmcp doesn't
  support. Full spec coverage (Phase 9) closes the gap while
  preserving our differentiators. rmcp's `#[tool]` macro DX is
  replicated in Phase 9h.
