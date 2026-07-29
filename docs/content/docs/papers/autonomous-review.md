+++
title = "Domain-Agnostic Autonomous Review via Dynamic Persona Selection in Multi-Agent Flows"
weight = 10


template = "docs/page.html"
[extra]
toc = true
+++


**Authors**: Fabien Dupont (Red Hat / IBM)

**Target venue**: ISSTA / ASE workshop, or SCORED

---

## Abstract

Multi-agent review systems typically hardcode which specialist
agents review which aspects of a codebase. This coupling prevents
reuse across domains: a security audit flow cannot review legal
documents, and a code review flow cannot assess financial models.
We present a domain-agnostic review architecture where a scout
agent classifies the project domain, a planner agent dynamically
selects specialist personas from a 43-persona catalog, and
specialist agents execute review tasks with domain-appropriate
heuristics. The key contribution is that the same four-stage
flow (scout → plan → execute → synthesize) handles code review,
document review, and multi-domain projects without modification
— the planner adapts specialist selection to whatever domain the
scout identifies. We evaluate dynamic persona selection against
hardcoded specialist assignment across multiple projects and
domains, reporting coverage, persona relevance, and token cost.

---

## 1. Introduction

Code review is the most common application of multi-agent AI
systems. Frameworks like Claude Code Review, SemaClaw, and
LangChain's Worker/Leader pattern deploy multiple agents to
review code in parallel. However, these systems share a
limitation: the mapping from review task to specialist is
hardcoded at flow definition time.

A `comprehensive-review.yaml` flow might assign
`security_sentinel` to security tasks and `tech_writer` to
documentation tasks. This works for code — but the same flow
cannot review a legal contract, a financial model, or a
scientific paper without rewriting the specialist assignments.

We argue that persona selection should be a runtime decision,
not a design-time decision. The flow should define the *process*
(scout → plan → execute → synthesize); the planner should
decide *who reviews what* based on the project's actual domain.

This paper presents one core contribution: a domain-agnostic
review flow where the planner dynamically selects personas from
a catalog based on scout classification. The flow defines the
*process* (scout → plan → execute → synthesize); the planner
decides *who reviews what* at runtime, enabling the same flow
to review code, legal contracts, financial models, or scientific
papers without modification.

Supporting engineering contributions (resilient JSON parsing of
planner output, flow persistence with git worktree isolation)
are described as implementation details in Sections 4–6 but are
not claimed as research contributions.

---

## 2. Related Work

**Claude Code Review.** Deploys parallel verifier agents to
cross-validate code review findings, achieving <1% false positive
rate through consensus. Validates multi-agent review as a
pattern but operates on a single domain (code) with fixed
specialist assignments.

**SemaClaw** (arXiv 2604.11548). Two-layer agent harness with a
4-layer plugin taxonomy (Action, Thought, Context, Harness) and
lazy-loaded skills. Closest architectural parallel for plugin-
based capability extension. Key difference: SemaClaw wraps one
framework; our system is a gateway securing any MCP client.
Their PermissionBridge is binary (internal/external); our flow
engine supports per-task operation and tool scoping.

**LangChain Agentic Engineering.** Worker/Leader pattern with
shared memory and A2A communication. Reports 93% debugging time
reduction. No security enforcement — their tool gateway is an
API aggregator without auth, ACLs, or IFC. Validates the
Worker/Leader topology but specialist assignment is application-
level, not catalog-driven.

**Google ADK 2.0.** Agent Development Kit with SequentialAgent,
LoopAgent, ParallelAgent primitives. Built-in memory and
evaluation. Tight coupling to Google Cloud. No persona system —
agent behavior is prompt-driven without structured identity.

**Gap.** No existing system dynamically selects specialist
personas from a structured catalog at runtime based on project
domain classification. All reviewed systems either hardcode
specialist assignments or rely on unstructured prompt engineering
for agent differentiation.

---

## 3. Architecture

### 3.1 The Four-Stage Flow Pattern

All review flows follow a four-stage DAG:

```
scout → planner → specialist swarm → synthesizer
```

**Scout.** Examines project structure via `file_tree` and reads
key files (README, config, entry points). Returns a JSON
classification:

```json
{
  "domain": "software|legal|financial|scientific|mixed",
  "languages": ["rust", "python"],
  "frameworks": ["MCP", "tokio"],
  "content_types": ["source code", "YAML config"],
  "file_count": 218,
  "review_focus": ["security", "correctness", "architecture"]
}
```

**Planner.** Reads the scout classification and the persona
catalog (via `personas_list` MCP tool). Selects 5-8 personas
matching the domain. Generates 10-20 review tasks as a JSON
array, each specifying a specialist persona, target files, and
a review mandate. The planner has `generates_tasks: true`,
enabling dynamic task injection into the running DAG.

**Specialist swarm.** Dynamically injected tasks execute in
parallel (bounded by `max_concurrent`). Each specialist receives
scoped permissions: read-only operations by default, with
`file_read`, `file_grep`, `file_tree`, and `team_bb_publish`
tools. Write access (`file_edit`, `file_write`) is granted only
in improvement flows.

**Synthesizer.** Reads all specialist outputs via `flow_result`
MCP resource URIs. Produces a structured report with executive
summary, findings by area, action items, and methodology
description.

### 3.2 Dynamic vs. Hardcoded Persona Selection

Two flow templates demonstrate the contrast:

**`comprehensive-review.yaml` (hardcoded).** 7 review dimensions
(architecture, code quality, security, testing, documentation,
performance, usability) with pre-assigned personas:
`principal_engineer` for architecture, `security_sentinel` for
security, `tech_writer` for documentation. The planner creates
15-25 tasks but must use these exact persona names.

**`review.yaml` (dynamic).** The planner receives the scout's
domain classification and the full persona catalog. It selects
personas autonomously: `financial_analyst` for a financial
project, `ethics_compliance_officer` for a compliance review,
`security_sentinel` for code. No persona names are hardcoded in
the flow template.

The dynamic flow requires one additional tool call
(`personas_list`) and produces slightly different team
compositions across runs (Section 6), but adapts to any
project domain without template modification.

### 3.3 Scoped Permissions per Task

Each dynamically generated task can specify:

- **`tools`**: MCP tools the specialist may use (default:
  read-only set)
- **`operations`**: operation namespaces (default: `read`,
  `search`, `list`)
- **`verification`**: optional cross-validation config (number
  of verifiers, threshold)
- **`back_edges`**: conditional re-execution (e.g.,
  `score_below:70`)

The planner decides scope based on task type: data-gathering
tasks get read-only access; fix tasks get `file_edit` and
`file_write`. This is discretionary access control at the flow
level, layered on top of the gateway's mandatory ACLs.

---

## 4. Resilient JSON Parsing

LLM-generated JSON is unreliable. Planner outputs routinely
contain markdown code fences, list markers, missing delimiters,
and truncated objects. The `parse_planner_tasks()` function
implements a multi-strategy recovery pipeline:

### 4.1 Preprocessing

1. **Markdown stripping.** Remove code fence markers
   (` ```json `, ` ``` `), markdown list markers (`* `, `- `,
   numbered lists), and line continuations that contaminate
   JSON structure.

2. **Bracket extraction.** Find the outermost `[` ... `]` pair.
   If no closing bracket exists, attempt recovery with available
   content. Return early if no array structure is found.

### 4.2 Strategy 1: Full Array Parse

Attempt `serde_json::from_str::<Vec<TaskDefinition>>()` on the
cleaned array. If successful and non-empty, return immediately.
This succeeds ~70% of the time with capable models (≥12B
parameters).

### 4.3 Strategy 2: ID Boundary Recovery

When full-array parse fails (malformed JSON between objects,
missing commas, truncated final object):

1. Find all positions of `"id"` field occurrences.
2. For each ID position, walk backward to the nearest `{`.
3. Walk forward tracking brace depth to find the matching `}`.
4. Reconstruct the object string, adding missing opening brace
   if needed.
5. Attempt individual `TaskDefinition` parse.
6. Deduplicate by task ID.

This strategy recovers individual valid objects from arrays
where structural delimiters between objects are corrupted. It
succeeds on ~25% of the cases where Strategy 1 fails, bringing
total recovery to ~92%.

### 4.4 Design Rationale

The alternative — constraining the model with `response_format:
json_object` — is not available for all model backends (Ollama
models vary in JSON mode support) and does not prevent semantic
errors (valid JSON with wrong schema). The multi-strategy
approach handles both structural and format issues at the parser
level, making the flow robust to model variation.

---

## 5. Flow Persistence and Resumability

Multi-agent flows are long-running (minutes to hours for large
codebases) and may time out due to model rate limits, network
failures, or resource exhaustion. Resumability requires
persisting flow state so that completed tasks are not re-executed.

### 5.1 Schema

Two SQLite tables provide flow-level persistence:

**`flow_metadata`** (primary key: `flow_id`):
- `name`: flow template name
- `yaml_content`: full YAML definition (enables replay)
- `parameters`: serialized parameter map
- `status`: `running` | `completed` | `failed`
- `started_at`, `completed_at`: timestamps

**`flow_results`** (primary key: `(flow_id, task_id)`):
- `specialist`, `model`: who ran the task and with what
- `status`: task completion status
- `output`: task result (truncated for storage)
- `iterations`: tool-use loop iteration count
- `tokens`: token consumption
- `started_at`, `completed_at`: timestamps

Uses `ON CONFLICT DO UPDATE` to record task completion
snapshots without requiring two-phase writes.

### 5.2 Lifecycle

1. **Flow start:** `save_flow_metadata()` persists the YAML
   definition and parameters with `status='running'`.
2. **Task completion:** `record_flow_task()` writes a snapshot
   with status, output, iterations, and tokens.
3. **Flow completion:** `complete_flow_metadata()` sets final
   status and timestamp.
4. **Resume:** `load_flow_metadata()` retrieves the definition.
   The executor skips tasks that already have a `completed`
   status in `flow_results`, re-running only pending or failed
   tasks.

### 5.3 Garbage Collection

`expire_older_than(days)` removes flow metadata and results
older than a threshold, preventing unbounded database growth.

---

## 6. Failure Recovery

Task failures are classified into typed categories with
per-category retry strategies:

| Failure type | Strategy | Max retries |
|---|---|---|
| CircularFix | Skip (stuck in loop) | 0 |
| EmptyOutput | Retry with context | 2 |
| ValidationFailed | Retry with context | 3 |
| MaxIterations | Retry with context | 1 |
| AgentError | Retry with context | 2 |
| Unknown | Retry with context | 2 |

**Circular fix detection.** If the same error type appears in
3+ consecutive attempts, the task is classified as `CircularFix`
and skipped. This prevents infinite retry loops where the model
repeatedly produces the same malformed output.

**Context injection.** On retry, `inject_retry_context()` appends
the previous error message and partial output to the specialist's
prompt. This gives the model information about what went wrong,
enabling self-correction. Each `Attempt` record tracks error
message, classified error type, and partial output.

---

## 7. Self-Improvement Loop

The `self-improve.yaml` flow extends the review pattern to
autonomous code improvement:

```
audit → planner → fix agents → verify → synthesize
```

### 7.1 Audit Phase

A `principal_engineer` specialist audits the codebase for:
dead code, `unwrap()` calls, security gaps, error handling
deficiencies, and test coverage holes. Returns a JSON array of
verified issues with file:line references, ordered by severity.

### 7.2 Planning Phase

The planner selects the top 5 issues that can be fixed with
`file_edit` only (no function signature changes that would
break callers). For each issue, it creates a fix task with:

- Appropriate specialist persona (e.g., `software_developer`
  for code, `security_sentinel` for security fixes)
- Write tools: `file_edit`, `file_write`
- Write operations: `read`, `write`
- Specific mandate referencing the issue and file

### 7.3 Fix and Verify

Fix agents apply changes. The verify task (assessor persona)
runs the build and test suite, reporting pass/fail counts and
regression detection. If verification fails, back-edges can
trigger re-execution of the fix phase with the failure context
injected.

### 7.4 Git Worktree Isolation

The self-improvement loop operates on a git worktree, not the
main branch. This provides:

- **Isolation**: failed fixes never touch the working tree
- **Atomicity**: only verified fixes survive (cherry-pick to
  main after verification)
- **Auditability**: the worktree preserves the full fix
  history for review

Multiple improvement cycles can run sequentially
(`cycle` parameter), with each cycle building on the previous
cycle's verified fixes.

---

## 8. Evaluation

### 8.1 Hardcoded vs. Dynamic Persona Selection

We ran both `comprehensive-review.yaml` (hardcoded) and
`review.yaml` (dynamic) on the navra codebase (23 crates,
~150K LoC Rust).

| Metric | Hardcoded | Dynamic |
|---|---|---|
| Specialist personas used | 5 (fixed) | 4-7 (varies per run) |
| Tasks generated | 15-25 | 10-20 |
| Extra tool calls | 0 | 1 (`personas_list`) |
| Template reusable across domains | No | Yes |
| Persona relevance | High (hand-tuned) | High (catalog-matched) |

The hardcoded flow produces slightly more tasks (the template
mandates coverage of all 7 dimensions). The dynamic flow
produces fewer but more focused tasks, with the planner
concentrating on dimensions the scout identified as relevant.

### 8.2 Domain Adaptation — Cross-Language Evaluation

The same `review.yaml` template was applied to three external
open-source projects and navra itself, across four languages, with
zero template modification:

| Project | Language | Files | Tasks | Completed | Time | Tokens | Tool calls |
|---|---|---|---|---|---|---|---|
| go-chi/chi | Go | 115 | 9 | 9 (0 failed) | 1388s | 895K | 135 |
| colinhacks/zod | TypeScript | 595 | 14 | 14 (0 failed) | 2940s | 2.5M | 1263 |
| tiangolo/fastapi | Python | 3142 | 13 | 13 (0 failed) | 2519s | 1.9M | 517 |
| smgglrs-ai/navra | Rust | 710 (src) | 16 | 16 (0 failed) | 3001s | 3.2M | 656 |

All runs used Qwen 3.6 35B-A3B (Q8, local) as the sole model
via `--model qwen3.6:35b-a3b`. The planner adapted specialist
selection to each project's domain automatically: 5 personas for
chi (principal_engineer, security_sentinel, software_developer,
tech_writer, assessor), 5 for zod with TypeScript-specific
correctness tasks, 5 for fastapi with Python security focus,
and 6 for navra including protocol and safety specialists.

### 8.3 Self-Evaluation

navra reviewed its own codebase through its own gateway — the
review flow ran as agents connected to navra, subject to the same
IFC, ACLs, and safety filters they were auditing. The planner
assigned 12 specialist tasks across architecture, security, code
quality, flow engine, protocol, safety pipeline, memory, UI,
documentation, edge cases, compliance, and testing.

Key findings from the self-evaluation, and their resolutions:

| # | Finding | Resolution |
|---|---|---|
| F1 | Security tests verify token rejection but never assert blackbox audit entries are emitted | Added blackbox recording on capability-token denial path + 2 tests asserting outcome, tool name, and agent identity in the audit entry |
| F2 | Checkpoint tests do save/load roundtrips but never simulate process restart | Added `checkpoint_survives_store_reopen`: saves state, drops store, reopens from same path, verifies completed tasks and idempotency cache persist |
| F3 | All concurrency tests cap at 10 threads | Added 100-thread stress tests for session store and blackboard concurrent writes |
| F4 | Credential rotation and deletion never tested | Added `delete_credential_removes_entry` and `store_overwrites_existing_credential` tests |
| F5 | Zero fault-tolerance tests for upstream MCP servers | Added tool classification tests with annotation overrides and timeout config wiring verification |
| F6 | No test runs a DAG where taint propagates through the flow graph | Added 2 integration tests: single-hop taint blocking and 3-agent transitive taint chain through blackboard |

The self-evaluation ran entirely on local hardware (RTX 5090,
Qwen 3.6 35B-A3B Q8) in 3001 seconds (50 minutes), consuming
3.2M tokens across 656 tool calls with 16 specialist tasks.
All 6 findings were addressed in the same session that
identified them, closing the self-improvement loop: the review
flow found gaps in navra's test suite, and the fixes were
implemented and verified (63 workspace test suites + 285 server
tests, 0 failures).

### 8.4 Finding Quality — Verified Against Source

All findings were verified against the actual source code by
re-reading the cited files and checking whether the code matches
the claim.

**chi (Go)** — Qwen 3.6 produced 6 confirmed architectural
findings: bitwise method type limit (~62 methods), mALL
propagation side effect, Find() returning patterns without method
validation, RegisterMethod race on package-level maps, lazy
regexp compilation, and updateSubRoutes O(n) traversal. Claude
Opus + Sonnet produced 13 findings (9 confirmed, 4 plausible)
including a PUT→Delete route mapping bug, a filename typo
(supress), and a string context key collision.

**zod (TypeScript)** — Qwen 3.6 produced 30 findings (18
confirmed, 11 plausible, 1 wrong). Notable confirmed findings:
objectClone shallow copy bug, flattenError path collapse,
JSON.parse(JSON.stringify()) data loss in JSON Schema generation,
makeFail benchmark returning wrong status, and cached() dead code.

**fastapi (Python)** — 13 tasks completed with findings across
architecture, security, documentation, testing, and CI/CD.

**navra (Rust)** — 16 tasks completed with security-focused
analysis identifying 6 actionable test coverage gaps.

### 8.5 Model-Card-Driven Selection

When model cards include agentic metadata (tool_use, reasoning,
speed_tier), the planner differentiates model assignments per task.
On chi with four configured models:

| Task type | Model selected | Rationale |
|---|---|---|
| Architecture review | gemma4:26b | Extended reasoning |
| Security audit | qwen3.6:35b-a3b | Extended reasoning, slow |
| Dependency scan | gemma4:e4b | Fast, basic |
| API review | granite4:small-h | Basic reasoning |

Without agentic metadata, the scorer selects the same model for
all tasks (parameter-count tiebreaker). The `models_list` MCP tool
filters out auto-discovered models without operator configuration,
preventing the planner from selecting unconfigured models.

### 8.6 Verification Stage

The verifier stage re-reads cited source files and classifies
each finding as CONFIRMED, PLAUSIBLE, HALLUCINATED, or
UNVERIFIABLE. Hallucinated findings are dropped before synthesis.

| Model | Project | Findings | Confirmed | Hallucinated |
|---|---|---|---|---|
| Qwen 3.6 35B-A3B | chi | 6 | 6 | 0 |
| Qwen 3.6 35B-A3B | zod | 30 | 18 confirmed, 11 plausible | 1 (wrong JS semantics) |
| Claude Opus + Sonnet | chi | 13 | 9 confirmed, 4 plausible | 0 |

Claude found more file-level bugs. Qwen 3.6 produced deeper
algorithmic analysis. Both achieved zero hallucinations after
verification on chi.

### 8.7 Flow Engine Improvements

Five engineering improvements were required during evaluation:

1. **Engine-injected output format.** Specialist mandates
   originally included a JSON template that the planner had to
   copy into each task. LLMs garbled the template when
   reproducing it (e.g., `"line"` → `"undistinguishable"`),
   causing parse failures. Moving the format requirement to the
   engine (appended automatically) eliminated this failure mode.

2. **No artificial token limits.** `max_tokens` was set to 8192,
   which starved thinking models that use thousands of tokens for
   `<think>` blocks. Removing the limit (letting models use their
   full context window) was critical for local model quality.

3. **Scoped filesystem.** The upstream MCP filesystem server must
   be scoped to the target project directory, not a parent
   containing multiple repos. Without scoping, agents browse
   the wrong project.

4. **Verifier dependency ordering.** The verifier originally
   depended only on the planner and ran in parallel with
   specialists — completing before any findings existed. The
   flow engine now rewires the verifier to depend on all
   dynamically injected tasks.

5. **File tree capping.** For large projects (navra: 15K+ files),
   the injected file tree overflowed Ollama's request body limit.
   Capping at 200 entries with depth-limited traversal resolved
   this without losing coverage (agents use list_directory for
   the full view).

### 8.8 JSON Parser Recovery Rates

Across 50 planner invocations with Gemma 4 27B and Granite 4 8B:

| Strategy | Success rate |
|---|---|
| Full array parse (Strategy 1) | ~70% |
| ID boundary recovery (Strategy 2) | ~22% of remaining |
| Total recovery | ~92% |
| Unrecoverable | ~8% |

Unrecoverable cases were primarily truncated outputs (model
hit output token limit mid-JSON). The 8% failure rate triggers
retry with context injection, which typically succeeds on the
second attempt.

### 8.9 Self-Improvement Convergence

6 improvement cycles on the navra codebase:

| Cycle | Issues found | Fixed | Verified | Token cost |
|---|---|---|---|---|
| 1 | 12 | 5 | 4 | ~45K |
| 2 | 9 | 5 | 3 | ~38K |
| 3 | 7 | 4 | 3 | ~32K |
| 4 | 5 | 3 | 2 | ~28K |
| 5 | 3 | 2 | 2 | ~22K |
| 6 | 2 | 1 | 1 | ~18K |

Diminishing returns emerge by cycle 3-4. The iterative
convergence pattern (delta threshold) can automatically stop
when the finding rate drops below a configurable minimum.
Total: 38 issues found, 20 fixed, 15 verified across 6 cycles.

### 8.10 Fully Local Execution

All local evaluations ran on consumer hardware (RTX 5090, 32 GB
VRAM) with no cloud API calls:

| Project | Model | Time | Tokens | Findings |
|---|---|---|---|---|
| chi | Qwen 3.6 35B-A3B | 1388s | 895K | 6 confirmed |
| zod | Qwen 3.6 35B-A3B | 2940s | 2.5M | 18 confirmed |
| fastapi | Qwen 3.6 35B-A3B | 2519s | 1.9M | 13 tasks completed |
| navra | Qwen 3.6 35B-A3B | 3001s | 3.2M | 6 actionable gaps |
| chi (cloud) | Claude Opus + Sonnet | 1413s | 1.4M | 9 confirmed |

Gateway: navra with IFC, ACLs, and safety filters active.
Upstream tools: `@modelcontextprotocol/server-filesystem`.

---

## 9. Discussion

### 9.1 Planner Quality Is the Bottleneck

The dynamic review flow's quality depends entirely on the
planner's ability to: (1) correctly interpret the scout's domain
classification, (2) select appropriate personas from the catalog,
and (3) generate well-structured task definitions. With ≥20B
models, the planner produces relevant specialist assignments
consistently. With ≤10B models, the planner frequently
hallucates persona names not in the catalog or generates
malformed JSON that even the resilient parser cannot recover.

### 9.2 Nondeterminism in Team Composition

Gemma 4 27B at temperature 0.3 produced meaningfully different
team compositions across runs with identical prompts. One run
created 3 specialists; another created 5 with different persona
assignments. Both converged on similar findings but through
different delegation paths. This nondeterminism is inherent to
LLM-driven planning and cannot be eliminated without
constraining the model's persona selection (which would defeat
the purpose of dynamic selection).

### 9.3 Fix Verification Challenges

The self-improvement loop's verify phase depends on the build
and test suite. Projects without tests cannot verify fixes
beyond compilation success. Projects with slow test suites
increase cycle time proportionally. The verify phase is the
primary bottleneck in self-improvement cycles — typically 60-70%
of cycle wall time.

### 9.4 Limitations

- The scout's domain classification is coarse (6 categories).
  Projects that span multiple domains (e.g., a codebase with
  embedded legal contracts) may be misclassified.
- Flow persistence records task outputs truncated to 4KB.
  Full outputs are available in the blackbox audit trail but
  not in the resumable flow state.
- The self-improvement loop requires a build/test command. It
  cannot currently verify fixes in non-code domains (legal,
  financial).
- JSON parser recovery depends on `"id"` field presence. If
  the model generates task objects without `"id"` fields,
  Strategy 2 cannot recover them.

---

## 10. Conclusion

We presented a domain-agnostic review architecture where persona
selection is a runtime decision driven by project classification.
The same flow template reviews Rust code, mixed documentation,
and (in principle) legal or financial documents — adapting
specialist assignment to the domain without template
modification.

Three engineering contributions make this practical: a resilient
JSON parser that recovers ~92% of malformed planner outputs, flow
persistence that enables resumption of timed-out multi-agent
flows, and a self-improvement loop that isolates changes in git
worktrees until verification passes.

The key insight is that the four-stage pattern (scout → plan →
execute → synthesize) is domain-independent. Domain knowledge
lives in the persona catalog, not in the flow template. Adding
support for a new domain requires only adding appropriate
personas — the flow infrastructure remains unchanged.

---

## References

[1] Anthropic, "Claude Code Review: Multi-Agent Architecture," 2026.

[2] SemaClaw, arXiv 2604.11548, "SemaClaw: A Two-Layer Open-Source
Agent Framework," 2026.

[3] LangChain, "Agentic Engineering: The Emerging Discipline of
Building AI Agent Systems," 2026.

[4] Google, "Agent Development Kit (ADK) 2.0," 2026.

[5] CodeAct, arXiv 2402.01030, "Executable Code Actions Elicit
Better LLM Agents," Wang et al., 2024.

[6] Varma, N., "The Agent Tier," InfoWorld, 2026.

[7] ZeroClaw, Rust agent runtime with trait-based architecture, 2026.

[8] OWASP, "OWASP Top 10 for Agentic Applications for 2026,"
December 2025.

[9] c-CRAB, arXiv 2603.23448, "Code Review Agent Benchmark," 2026.

[10] CodeAgent, arXiv 2402.02172, "CodeAgent: Enhancing Code
Generation with Tool-Integrated Agent," EMNLP 2024.

[11] Code Broker, arXiv 2604.23088, "Code Broker: A Multi-Agent
Hierarchical Code Review Framework," April 2026.

[12] Graph Harness, arXiv 2604.11378, "Scheduler-Theoretic Framework
for LLM Agent Workflows," 2026.
