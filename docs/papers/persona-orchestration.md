# Persona-Driven Multi-Agent Orchestration: A General-Purpose Cognitive Framework for AI Agent Teams

### Review notes (2026-05-07)

- **Consider folding into Paper 1** as the persona-driven security
  policy mechanism. Standalone space is crowded (PersonaVLM CVPR 2026
  Highlight, MTL, SemaClaw, MorphAgent all overlap).
- **If standalone**: Must evaluate on 3-5 external OSS projects, not
  own codebase. Need ablation: does persona selection actually matter
  vs naive prompts on identical models?
- **Missing related work**: MorphAgent (arXiv:2410.15048, self-evolving
  profiles), c-CRAB (arXiv:2603.23448, code review benchmark), FadeMem
  (arXiv:2601.18642, differential memory decay), Mem0 (graph+vector+KV
  hybrid memory), FIDES (arXiv:2505.23643, IFC enforcement layer).
- **Memory decay**: Flat rate is behind state of the art. FadeMem and
  YourMemory use importance-modulated rates.
- **HyDE channel**: Listed as feature but is a stub returning empty.
  Fix or remove from claims.

## Abstract (~200 words)

Multi-agent AI systems typically treat agents as interchangeable
executors differentiated only by their tool access. We present a
cognitive framework where agent identity — defined as structured
persona YAML files with behavioral heuristics, domain-specific
reasoning patterns, and per-phase model selection — drives both
individual agent behavior and team-level orchestration. The
framework separates genotype (static persona definition) from
phenotype (runtime prompt assembly with token budgeting, model-
family-aware compaction, and exponential memory decay). A lead
agent autonomously selects teammates from a persona catalog,
assigns models via three-layer composite model cards (vendor +
agentic + runtime metadata, auto-populated from Ollama/HuggingFace/
OCI registries), and coordinates through shared blackboards with
cross-validation verification. Dual execution modes — YAML
declarative plans and sandboxed Python/CodeAct — support both
sequential tool chains and computational tasks. We demonstrate the
framework on four tasks (self-analysis, domain-agnostic review,
business analysis, self-improving security audit) running fully
locally on consumer hardware with Gemma 4 27B as lead and Granite
4 / Qwen 3.6 as teammates. Results show that persona-driven
delegation with scored model selection produces structured,
role-appropriate outputs that generic agents cannot, while
Hermes trace export enables reproducibility and corpus-building.

---

## 1. Introduction

**Problem.** Current multi-agent frameworks treat agents as generic
tool-callers. An agent assigned to "review code" behaves identically
to one assigned to "write documentation" unless the developer
manually crafts a system prompt. This produces bland, homogeneous
outputs and forces orchestration logic into application code rather
than agent configuration.

**Why personas matter.** Humans working in teams have professional
identities — a security auditor thinks differently from a technical
writer. Personas encode this identity as structured YAML: a core
mandate, domain heuristics (36 modules, 100+ facets), output schemas,
tool restrictions, and per-phase model preferences. The persona is
the agent's genotype; the Weaver's prompt assembly is the phenotype.

**Contribution summary.**

1. A cognitive core architecture (Forge loader + Weaver assembler)
   that compiles 43 personas across 7 domains into structured system
   prompts with model-family-aware compaction and per-phase context
   budgets.
2. Three-layer composite model cards (vendor + agentic + runtime)
   with auto-population from registry APIs and a scoring algorithm
   for automated model selection (12-20B sweet spot, ≤10B penalty,
   IFC-aware locality enforcement).
3. Team orchestration with dynamic persona selection from catalog,
   cross-validation verification (Any/Majority/Unanimous thresholds),
   and iterative Scout → Map → Reduce convergence for large codebases.
4. Dual execution modes: YAML declarative plans with variable
   substitution and sandboxed Python/CodeAct with OpenShell/Podman
   isolation.
5. Working memory with exponential decay scoring and Hermes-format
   JSONL trace export for reproducibility and fine-tuning corpus
   building.
6. A judge panel system (12 judges × 3 perspectives) for multi-axis
   evaluation of agent outputs.
7. Evaluation on four tasks demonstrating persona-driven delegation
   with fully local model execution on consumer hardware.

---

## 2. Related Work

**LangChain Agentic Engineering.** Worker/Leader pattern with shared
memory and A2A communication. Reports 93% debugging time reduction
and 65% dev time reduction. No security enforcement — their "tool
gateway" is an API aggregator without auth, ACLs, or information
flow control. Validates the Worker/Leader topology but leaves
identity and security as application-level concerns.

**Google ADK 2.0.** Agent Development Kit with SequentialAgent,
LoopAgent, ParallelAgent primitives. Built-in memory, evaluation,
and A2A support. Tight coupling to Google Cloud (Vertex AI, Gemini).
No persona system — agent behavior is purely prompt-driven without
structured identity artifacts.

**SemaClaw** (arXiv 2604.11548). Two-layer architecture
(sema-code-core + application harness) with 4-layer plugin taxonomy
(Action, Thought, Context, Harness), lazy-loaded skills, and
wiki-based knowledge output. Closest architectural parallel.
Key difference: SemaClaw is a harness wrapping one framework; our
system is a gateway securing any MCP-speaking framework. Their
PermissionBridge is binary (internal/external); our IFC propagates
taint labels through tool chains with deny-wins ACLs.

**Claude Code Review Multi-Agent.** Parallel verifier agents achieve
< 1% false positive rate through cross-validation. Validates the
multi-agent pattern for high-stakes outputs but operates at a single
task type (code review) without general-purpose persona definitions.

**OpenClaw / ZeroClaw.** Rust-based agent runtimes with trait-based
tool composition. ZeroClaw targets embedded/IoT (< 5 MB memory,
< 10 ms startup, 8.8 MB binary) with 3-tier autonomy
(ReadOnly/Supervised/Full). Flat runtime architecture — no gateway
layer, no persona system, no team orchestration.

**Gap.** None of these systems separate agent identity (genotype) from
runtime behavior (phenotype) through structured, version-controlled
persona artifacts. None provide model-card-driven teammate selection
where the lead reads composite metadata to assign models based on
task requirements and locality constraints.

---

## 3. Architecture

### 3.1 Forge (YAML Loader)

The Forge loads three artifact types from disk:

- **Personas** (43 files): core mandate, heuristic references,
  output schemas, tool restrictions, per-phase model preferences
  (planning_model, execution_model), per-phase context limits
- **Heuristics** (36 modules): reusable reasoning patterns with
  named facets across 8 categories (Architecture, Engineering,
  Analysis, Quality, Security, Leadership, Communication, Identity)
- **Directives** (7 files): immutable operational protocols
  (numbered 01-09 by priority)

Genotype: the persona YAML file defines what an agent *is*.

### 3.2 Weaver (Prompt Assembly)

The Weaver compiles a persona into a structured prompt split into:

- **Cacheable prefix** (stable within session): directives +
  core mandate + resolved heuristics + few-shot examples (up to 3)
- **Dynamic context** (changes per invocation): retrieved documents,
  memory, specialist catalog

This split enables prompt caching — the prefix is sent once and
reused across invocations within a session.

Phenotype: the Weaver transforms genotype into runtime behavior.

### 3.3 ContextBudget

Token budget allocator with priority-ordered slots:

1. System prompt (fixed, never truncated — identity is sacrosanct)
2. Conversation history (60% of remaining, compacted when over 80%)
3. Retrieved context (40% of remaining, truncated at sentence
   boundaries first)

Token estimation uses character-based approximation (3.5
chars/token). Per-phase context limits (`planning_context_limit`,
`execution_context_limit`) allow tighter budgets during execution
when retrieved context matters less.

**Compaction strategies.** When conversation history exceeds the
80% threshold, the budget triggers compaction using one of three
model-family-aware strategies:

| Strategy | Behavior | Default for |
|---|---|---|
| KeepLastN(k) | Retain k most recent turns, drop rest | Granite/Qwen (k=5), Claude/GPT (k=10) |
| Summary | Replace old turns with one-line summaries | Gemma |
| DiscardAll | Keep only the latest turn | Emergency fallback |

Summary compaction produces a single block:
`"[Prior conversation summary (N turns)]\n  1: first line...\n  2: ..."`
preserving a skeletal trace of the full conversation while
freeing tokens for new context. Truncation at sentence boundaries
(`". "`, `".\n"`, or `"\n"` fallback) avoids mid-sentence cuts
and appends a `[truncated — N more chars]` notice.

### 3.4 Per-Phase Model Selection

Personas declare preferred models per phase:

- **Planning phase**: may use a stronger reasoning model
  (reasoning: "extended")
- **Execution phase**: may use a faster model for tool-calling
  (speed_tier: "fast", tool_use: "advanced")

The lead agent reads composite model cards via `models_list` and
matches task requirements to model capabilities without hardcoded
model assignments.

### 3.5 Dual Execution Modes

Agents execute plans through two complementary modes:

**YAML declarative plans.** Sequential tool call chains with
variable substitution (`{{step1.result}}`), conditional execution
(`when: "{{prev.success}}"`), for-each loops over collections,
and error handling policies (`on_error: "stop"|"continue"`).
Each step calls an MCP tool and optionally saves the result to
a named variable. No sandbox required — execution stays within
the MCP gateway's security perimeter.

**Python/CodeAct mode.** Sandboxed Python execution for tasks
that require computation, data transformation, or control flow
beyond sequential tool calls. The gateway injects a bridge
script (`smgglrs_bridge.py`) that provides MCP tool access via
gateway URL, session ID, and auth token environment variables.
Sandbox backend priority: OpenShell (gRPC microVM) → Podman
(rootless container, `10.0.2.2` for gateway access) → Direct
(unsandboxed, requires explicit opt-in via
`SMGGLRS_ALLOW_DIRECT_EXECUTION`). Default timeout: 300 seconds.

The CodeAct mode enables agents to express multi-step reasoning
as executable code rather than tool-call sequences, following
the CodeAct pattern where LLM-generated Python replaces natural
language planning for deterministic execution.

---

## 4. Persona Taxonomy

### 4.1 43 Personas Across 7 Domains

| Domain | Count | Examples |
|--------|-------|---------|
| Engineering | 8 | software_developer, principal_engineer, system_architect, data_scientist |
| Analysis | 6 | analyst, researcher, business_analyst, financial_analyst, sentiment_analyzer |
| Leadership | 3 | leader, project_leader, executive_coach |
| Quality Assurance | 4 | watchdog, viability_challenger, devils_advocate, efficiency_expert |
| Security | 2 | security_sentinel, smgglrs_guardian |
| Creative & Communication | 5 | creative_director, tech_writer, summarizer, synthesizer, interviewer |
| Ethics & Strategy | 3 | ethics_compliance_officer, strategic_advisor, value_champion |
| Judges | 12 | 4 axes x 3 perspectives (see below) |

### 4.2 Judge Panel System

12 judges across 4 evaluation axes, each with 3 perspective variants:

| Axis | Strict | Pragmatic | User Advocate |
|------|--------|-----------|---------------|
| Correctness | correctness_judge_strict | correctness_judge_pragmatic | correctness_judge_user_advocate |
| Completeness | completeness_judge_strict | completeness_judge_pragmatic | completeness_judge_user_advocate |
| Quality | quality_judge_strict | quality_judge_pragmatic | quality_judge_user_advocate |
| Safety | safety_judge_strict | safety_judge_pragmatic | safety_judge_user_advocate |

A meta_jury persona aggregates judge scores into a final verdict.
This enables multi-axis evaluation without single-judge bias.

### 4.3 General-Purpose Expansion

5 personas added beyond the original Python Myelix set to cover
non-engineering domains: executive_coach, creative_director,
strategic_advisor, ethics_compliance_officer, financial_analyst.
These validate that the persona framework generalizes beyond
software engineering.

---

## 5. Agent Orchestration

### 5.1 Team Protocol

The lead agent uses 8 MCP tools for team management:

- `team_create` — create a team with shared blackboard and resource
  budget (max_depth: 2, max_agents: 10, max_tokens: 500K,
  timeout: 600s)
- `team_add` — add teammate with persona, model, locality, scoped
  operations and tools
- `team_message` — send task to teammate (async execution)
- `team_status` / `team_result` — poll progress, read outputs
- `team_bb_publish` / `team_bb_read` — shared blackboard for
  cross-agent knowledge
- `team_shutdown` — tear down team, report final stats

### 5.2 Model Card-Driven Selection

The lead calls `models_list` to receive composite model cards with
three metadata layers:

- **Vendor**: auto-populated from registry APIs (Ollama `/api/show`,
  HuggingFace `/api/models`, OCI Referrers API). Fields: family,
  parameters, quantization, context_window, license, format.
- **Agentic**: operator-defined in TOML config
  (`[models.<name>.agentic]`). Fields: cost_tier, speed_tier,
  locality, reasoning, tool_use, json_compliance, strengths,
  weaknesses, recommended_tasks, avoid_tasks, max_agents.
- **Runtime**: learned after each execution via rolling averages.
  Fields: total_calls, total_tokens, avg_latency_ms, success_rate,
  and per-task-type breakdown (`by_task`).

Non-empty operator fields overwrite auto-populated defaults;
empty fields preserve existing values. Cards are persisted as
JSON in `~/.local/share/smgglrs/models/cards/`.

**Scoring algorithm.** When a teammate's model is set to `"auto"`,
`select_model_for_task()` scores each available model:

| Factor | Score | Condition |
|---|---|---|
| JSON compliance | +15 / +5 | strict / best-effort |
| Tool use | +10 / +5 | advanced / basic |
| Reasoning | +20 / +5 | extended / basic |
| Speed (non-reasoning) | +8 / +4 | fast / medium |
| Locality | +5 | local preferred |
| Cost | +3 / +1 | free / low |
| Parameter count | +20 | 12-20B (sweet spot) |
| Parameter count | -50 | ≤10B (unreliable tool use) |
| Parameter count | +5 | ≥20B (GPU swap risk) |

The ≤10B penalty reflects empirical observation: models under
10B parameters frequently fail to call tools when system prompts
exceed ~1,600 tokens. The 12-20B sweet spot balances capability
with local hardware constraints (fits in 16 GB VRAM at Q4).

**IFC-aware selection.** When the session's taint tracker
indicates sensitive data, the selector restricts candidates to
`locality=local` models, preventing data exfiltration through
cloud API calls.

**Runtime learning.** After each teammate execution, the card's
runtime layer is updated via `record_run()` with rolling
averages. Future selections consult `by_task` success rates,
enabling empirical refinement: if Granite 8B has 95% success
on `file_read` tasks but 40% on `synthesis`, the scorer
prefers it for data gathering and avoids it for synthesis.

### 5.3 Non-Progress Iterations

Status-polling tools (team_status, team_result, team_bb_read,
models_list) are marked as non-progress. Iterations where ALL
tool calls are non-progress do not count toward the 50-iteration
limit. This prevents the lead from timing out while waiting for
async teammates.

### 5.4 Scoped Capability Tokens

Each teammate receives scoped permissions:

- **Operations**: default read-only (read, search, list)
- **Tools**: default safe set (file_tree, file_grep, file_read,
  team_bb_publish)

The lead does NOT get file_read or file_grep — it must delegate
all file analysis to teammates, enforcing the delegation pattern
architecturally.

### 5.5 Cross-Validation

For high-stakes outputs, tasks declare a verification config
that spawns N parallel verifier agents after completion. Each
verifier independently assesses the output against the original
mandate and success criteria, producing a JSON verdict
(`{passed, findings}`). Three threshold modes aggregate
verdicts:

| Mode | Rule |
|---|---|
| Any | ≥1 verifier approves |
| Majority | >N/2 approve |
| Unanimous | All approve |

Findings are deduplicated across verifiers. Failed verification
triggers back-edge re-execution (bounded by `max_iterations`).
This pattern, inspired by Claude Code Review's <1% false positive
rate, prevents hallucinated findings from reaching the final
report.

### 5.6 Iterative Scout → Map → Reduce

For large-codebase analysis, the flow engine provides an
iterative convergence pattern:

1. **Scout** — select files (model-guided or exhaustive batching)
2. **Map** — per-file analysis by specialist (parallelizable)
3. **Reduce** — synthesis, deduplication (findings keyed by ID)
4. **Evaluate** — compute delta (new findings / previous total).
   If delta < threshold (default: 2), converge. Otherwise, next
   round.

Exhaustive mode cycles through ALL files in batches, ensuring
full coverage at the cost of more rounds. Model mode is faster
but may miss files the LLM considers unimportant. Round metrics
(findings, tokens, taint) are tracked for cost analysis.

---

## 6. Memory and Reproducibility

### 6.1 Working Memory with Decay

Conversation turns are persisted in SQLite with per-turn
`importance` and `access_count` metadata. The decay function
computes an effective score using exponential decay:

```
effective_score = importance × e^(-rate × age_hours)
                + min(access_count × 0.1, 0.3)
```

At the default rate (0.001), a turn with importance=0.5 at
30 days old scores ~0.24 — still retrievable but deprioritized.
`get_turns_by_score()` retrieves the top-k turns by score, then
re-sorts chronologically for coherent context assembly.

`cleanup_decayed()` archives turns below a threshold score to a
`memory_archive` table, preventing unbounded growth while
preserving data for audit. Conversation forking (`fork_id`,
`parent_fork`) supports branching explorations without
contaminating the main thread.

### 6.2 Hermes Trace Export

Every agent execution can be exported as a Hermes-format JSONL
trace, compatible with `lambda/hermes-agent-reasoning-traces`.
The trace preserves:

- System prompt (persona + directives + heuristics)
- User prompt
- Thinking blocks (`<think>...</think>`)
- Tool calls (`<tool_call>name\n{args}</tool_call>`)
- Tool responses (`<tool_response>{result}</tool_response>`)
- Final response

Single-line JSON output enables corpus-building for fine-tuning
or post-hoc analysis. The trace captures the full reasoning
chain including intermediate thinking, which model APIs
typically discard.

### 6.3 Insight Injection

The DAG executor supports an `insight_callback` / `insight_retriever`
pattern for cross-session learning. After task completion, the
executor extracts `TaskInsight` records (title, content, tags,
confidence). On subsequent runs, relevant insights are injected
into task prompts via the retriever callback, implementing the
ReasoningBank pattern where past reasoning informs future
execution without full trajectory replay.

---

## 7. Evaluation

### 7.1 Self-Analysis

The framework analyzed its own codebase (18 crates, ~86K LoC)
through its own gateway. Initial persona coverage scored 28/100
(engineering-only). After adding 5 general-purpose personas and
the 12-judge panel, coverage rose to 45/100. The framework
identified its own gaps and proposed the additions that filled
them — a concrete demonstration of persona-driven self-improvement.

### 7.2 Domain-Agnostic Review

The same `review.yaml` flow template was applied to the smgglrs
codebase without modification. The scout classified the project
as `domain: "software"` with `languages: ["rust"]` and
`review_focus: ["security", "correctness", "architecture"]`.
The planner called `personas_list`, selected principal_engineer,
security_sentinel, tech_writer, and assessor from the catalog,
and created 15 review tasks with appropriate specialist
assignments. No task required manual persona specification.

### 7.3 Business Analysis

Prompt: "A company wants to license this. Should we pursue?"
(14 words). Result: full go/no-go recommendation with SWOT
analysis, competitive positioning, licensing model comparison,
and risk assessment. Completed in 39 seconds with a Gemma 4 27B
lead delegating to Granite 4 and Qwen 3.6 teammates. All
execution fully local on consumer hardware via Ollama.

The model selector assigned `granite3.3:8b` (cost_tier=free,
speed_tier=fast) to data-gathering teammates and reserved
`gemma4:26b` (reasoning=extended) for synthesis — matching the
expected behavior of the scoring algorithm without manual
intervention.

### 7.4 Security Audit with Self-Improvement

The `self-improve.yaml` flow executed an autonomous
audit → fix → test → verify cycle on a git worktree:

1. **Audit** (principal_engineer): identified dead code, unwrap
   calls, security gaps, test coverage holes
2. **Planner**: selected top 5 fixable issues (file_edit only,
   no signature changes)
3. **Fix agents** (injected dynamically): applied fixes with
   write access
4. **Verify** (assessor): ran build + test, reported pass/fail
   counts and regressions

6 audit rounds across the codebase produced 50+ security
findings. The iterative convergence pattern (Section 5.6)
stopped when delta dropped below threshold, indicating
diminishing returns.

### 7.5 Fully Local Execution

All evaluations ran on consumer hardware with no cloud API calls:

| Role | Model | Locality | Quantization |
|---|---|---|---|
| Lead | Gemma 4 27B | local | Q4_K_M |
| Data gathering | Granite 4 8B | local | Q4_K_M |
| Data gathering | Qwen 3.6 8B | local | Q4_K_M |

Gateway: smgglrs with IFC, ACLs, and safety filters active.
Transport: MCP Streamable HTTP over localhost. Hardware: consumer
desktop with 32 GB RAM, no dedicated GPU required for Q4
quantized models.

---

## 8. Discussion

### 8.1 Model Quality vs. Persona Quality

Persona quality cannot compensate for model deficiency.
A well-defined security_sentinel persona produces better
structured findings than a generic prompt on the same model,
but a weak model with a strong persona still underperforms a
strong model with a weak prompt. The persona amplifies capability
rather than creating it.

### 8.2 The "." Path Bug

During blackbox testing, the framework's file_tree tool defaulted
to "." (current directory) when no explicit path was provided.
This caused teammates to scan the smgglrs binary's working directory
instead of the project path. Found only because the lead's report
contained irrelevant file listings. This class of bug — path
resolution in delegated contexts — is specific to multi-agent
systems and invisible in single-agent testing.

### 8.3 Gemma 4 Nondeterminism

Gemma 4 27B at temperature 0.3 produced meaningfully different
team compositions across runs with identical prompts. One run
created 3 specialists; another created 5 with different persona
assignments. Both converged on similar findings but through
different delegation paths. Persona-level determinism does not
guarantee orchestration-level determinism.

### 8.4 The list_personas Hallucination

When a Gemma 4 lead was given team orchestration tools but no
explicit persona catalog, it hallucinated a `list_personas` tool
that does not exist. The MCP server returned an error, and the
lead fell back to assigning personas by name from its training
data. This led to adding `personas_list` as a real MCP tool
that returns the catalog from the Forge. The lesson: tools that
agents *expect* to exist should exist.

### 8.5 The ≤10B Tool-Use Cliff

Models with ≤10 billion parameters reliably fail to call tools
when system prompts exceed ~1,600 tokens. The persona framework's
system prompts (directives + mandate + resolved heuristics)
routinely exceed 2,000 tokens. This makes ≤10B models unusable
as teammates despite their speed advantage, motivating the -50
penalty in the scoring algorithm (Section 5.2). The 12-20B
sweet spot (Granite 12B, Gemma 12B) balances tool reliability
with local hardware constraints.

---

## 9. Conclusion and Future Work

We presented a cognitive framework where structured persona
definitions drive multi-agent orchestration. The separation of
genotype (YAML persona) from phenotype (Weaver-assembled prompt)
enables version-controlled, human-auditable agent identity that
survives across sessions and deployments.

The composite model card schema bridges registry metadata and
runtime selection, enabling lead agents to assign appropriate
models based on task requirements, data sensitivity, and
empirical performance — without hardcoded model assignments.
Dual execution modes (YAML declarative and Python/CodeAct)
support both sequential tool chains and computational tasks
within the same security perimeter. Working memory with
exponential decay and Hermes trace export provide persistence
and reproducibility.

### Future Work

**Persona Evolution (PEM).** Inspired by PersonaVLM (arXiv
2604.13074), personas will accumulate interaction-derived
behavioral traits via momentum-based updates:
`trait_new = α × observed + (1 - α) × trait_old`. This
transforms static YAML definitions into adaptive agent
calibration while preserving reset-to-defaults capability.

**Knowledge Distillation.** Port the 4-stage Knowledge
Cultivation Pipeline (Ingestion, Synthesis, Reconciliation,
Forging) to transform session transcripts into reusable Insight
memories. The Memory Transfer Learning paper (arXiv 2604.14004)
demonstrates that 431 abstract memories outperform 5,800 raw
traces, and raw trajectories cause negative transfer through
domain-mismatched anchoring.

**Upstream Model Card Contribution.** Propose the agentic
metadata schema as well-known keys in Kubeflow Model Registry's
`customProperties` (issue #449) and OCI side artifacts
(`application/vnd.smgglrs.model-card.v1+json`). OpenShift AI,
which uses Kubeflow Model Registry as its catalog, would
immediately benefit.

**Context Budget Compression.** Integrate RTK-style
compression where tool outputs are summarized before consuming
context budget. Currently, large tool results (file contents,
git diffs) consume disproportionate context. Strands' token
budget approach provides a reference implementation.

---

## References

- LangChain, "Agentic Engineering: The Emerging Discipline of
  Building AI Agent Systems," 2026.
- SemaClaw, arXiv 2604.11548, "SemaClaw: A Two-Layer Open-Source
  Agent Framework," 2026.
- PersonaVLM, arXiv 2604.13074, "PersonaVLM: Personality Evolving
  Mechanism for Vision-Language Models," 2026.
- Memory Transfer Learning, arXiv 2604.14004, "Memory Transfer
  Learning for Agent Systems," KAIST/NYU, 2026.
- Varma, N., "The Agent Tier," InfoWorld, 2026.
- Anthropic, "Claude Code Review: Multi-Agent Architecture," 2026.
- AgentSwing, arXiv 2603.27490, Alibaba, 2026.
- Cloudflare, "Agent Memory Architecture," 2026.
- CodeAct, arXiv 2402.01030, "Executable Code Actions Elicit
  Better LLM Agents," Wang et al., 2024.
- Strands Agents, "Token Budget Management for Agent Tool Calls,"
  AWS, 2026.
- RTK (Retrieval Toolkit), "Context Window Compression for
  Agentic RAG," 2026.
- BLD, arXiv 2604.07466, "Building Language-Driven Agents," 2026.
- Kubeflow Model Registry, https://github.com/kubeflow/model-registry
- OCI Distribution Spec v1.1, Referrers API,
  https://github.com/opencontainers/distribution-spec/
- HuggingFace Model Cards, https://huggingface.co/docs/hub/model-cards
- Ollama API, https://github.com/ollama/ollama/blob/main/docs/api.md
- Hermes Agent Reasoning Traces,
  https://huggingface.co/datasets/lambda/hermes-agent-reasoning-traces
- MorphAgent, arXiv 2410.15048, "Self-Evolving Multi-Agent Collaboration
  Networks," Lu et al., 2024.
- c-CRAB, arXiv 2603.23448, "Code Review Agent Benchmark," 2026.
- FadeMem, arXiv 2601.18642, "Differential Memory Decay for Agents,"
  Alibaba, 2026.
- Mem0, "Graph + Vector + KV Hybrid Memory," 2026.
- FIDES, arXiv 2505.23643, "Securing AI Agents with Information-Flow
  Control," Microsoft Research, 2025.
