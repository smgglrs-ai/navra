# Persona-Driven Multi-Agent Orchestration: A General-Purpose Cognitive Framework for AI Agent Teams

## Abstract (~150 words)

Multi-agent AI systems typically treat agents as interchangeable
executors differentiated only by their tool access. We present a
cognitive framework where agent identity — defined as structured
persona YAML files with behavioral heuristics, domain-specific
reasoning patterns, and per-phase model selection — drives both
individual agent behavior and team-level orchestration. The
framework separates genotype (static persona definition) from
phenotype (runtime prompt assembly with token budgeting and context
compaction). A lead agent autonomously selects teammates from a
persona catalog, assigns models via composite model cards, and
coordinates through a shared blackboard — without being told which
personas to use. We demonstrate the framework on four tasks
(self-analysis, business analysis, documentation gap-filling,
security audit) running fully locally on consumer hardware with
Gemma 4 27B as lead and Granite 4 / Qwen 3.6 as teammates.
Results show that persona-driven delegation produces structured,
role-appropriate outputs that generic agents cannot.

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
   prompts with token-budget-aware context management.
2. A team orchestration protocol where the lead agent autonomously
   selects personas and models from catalogs, using composite model
   cards (vendor + agentic + runtime metadata).
3. A judge panel system (12 judges x 3 perspectives) for multi-axis
   evaluation of agent outputs.
4. Evaluation on four real-world tasks demonstrating persona-driven
   delegation with fully local model execution.

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

Token estimation uses character-based approximation (3.5 chars/token).
Per-phase context limits (planning_context_limit,
execution_context_limit) allow tighter budgets during execution
when retrieved context matters less.

### 3.4 Per-Phase Model Selection

Personas declare preferred models per phase:

- **Planning phase**: may use a stronger reasoning model
  (reasoning: "extended")
- **Execution phase**: may use a faster model for tool-calling
  (speed_tier: "fast", tool_use: "advanced")

The lead agent reads composite model cards via `models_list` and
matches task requirements to model capabilities without hardcoded
model assignments.

---

## 4. Persona Taxonomy

### 4.1 43 Personas Across 7 Domains

| Domain | Count | Examples |
|--------|-------|---------|
| Engineering | 8 | software_developer, principal_engineer, system_architect, data_scientist |
| Analysis | 6 | analyst, researcher, business_analyst, financial_analyst, sentiment_analyzer |
| Leadership | 3 | leader, project_leader, executive_coach |
| Quality Assurance | 4 | watchdog, viability_challenger, devils_advocate, efficiency_expert |
| Security | 2 | security_sentinel, myelix_guardian |
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

- **Vendor**: auto-populated from registry (family, parameters,
  quantization, context_window, license)
- **Agentic**: operator-defined capabilities (cost_tier, speed_tier,
  locality, reasoning, tool_use, json_compliance)
- **Runtime**: learned statistics (success_rate, avg_latency_ms,
  per-task breakdown)

Selection heuristic: locality=local + cost_tier=free for data
gathering; reasoning=extended for synthesis. Sensitive data (IFC
tainted) requires locality=local.

### 5.3 Non-Progress Iterations

Status-polling tools (team_status, team_result, team_bb_read,
models_list) are marked as non-progress. Iterations where ALL
tool calls are non-progress do not count toward the 50-iteration
limit. This prevents the lead from timing out while waiting for
async teammates.

### 5.4 Scoped Capability Tokens

Each teammate receives scoped permissions:

- **Operations**: default read-only (read, search, list)
- **Tools**: default safe set (docs_tree, docs_grep, docs_read,
  team_bb_publish)

The lead does NOT get docs_read or docs_grep — it must delegate
all file analysis to teammates, enforcing the delegation pattern
architecturally.

---

## 6. Evaluation

### 6.1 Self-Analysis

The framework analyzed its own codebase (17 crates, ~46K LoC)
through its own gateway. Initial persona coverage scored 28/100
(engineering-only). After adding 5 general-purpose personas and
the 12-judge panel, coverage rose to 45/100. The framework
identified its own gaps and proposed the additions that filled them.

### 6.2 Business Analysis

Prompt: "A company wants to license this. Should we pursue?"
(14 words). Result: full go/no-go recommendation with SWOT
analysis, competitive positioning, licensing model comparison,
and risk assessment. Completed in 39 seconds with a Gemma 4 27B
lead delegating to Granite 4 and Qwen 3.6 teammates. All
execution fully local on consumer hardware via Ollama.

### 6.3 Documentation Gap-Filling

Agents identified missing documentation across the 17-crate
workspace and produced structured gap reports. The lead
delegated to a tech_writer persona and an analyst persona
working in parallel via the shared blackboard.

### 6.4 Security Audit

6 audit rounds across the codebase produced 50+ security findings.
The lead delegated file scanning to security_sentinel teammates,
then synthesized findings into a prioritized report with CWE
classifications. Clippy warnings reduced from 103 to 53 as a
side effect.

### 6.5 Fully Local Execution

All evaluations ran on consumer hardware with no cloud API calls:

- **Lead**: Gemma 4 27B (Ollama, locality: local, Q4_K_M)
- **Teammates**: Granite 4 8B, Qwen 3.6 8B (Ollama, locality: local)
- **Gateway**: mcpd with IFC, ACLs, and safety filters active
- **Transport**: MCP Streamable HTTP over localhost

---

## 7. Discussion

### 7.1 Model Quality vs. Persona Quality

Persona quality cannot compensate for model deficiency.
A well-defined security_sentinel persona produces better
structured findings than a generic prompt on the same model,
but a weak model with a strong persona still underperforms a
strong model with a weak prompt. The persona amplifies capability
rather than creating it.

### 7.2 The "." Path Bug

During blackbox testing, the framework's docs_tree tool defaulted
to "." (current directory) when no explicit path was provided.
This caused teammates to scan the mcpd binary's working directory
instead of the project path. Found only because the lead's report
contained irrelevant file listings. This class of bug — path
resolution in delegated contexts — is specific to multi-agent
systems and invisible in single-agent testing.

### 7.3 Gemma 4 Nondeterminism

Gemma 4 27B at temperature 0.3 produced meaningfully different
team compositions across runs with identical prompts. One run
created 3 specialists; another created 5 with different persona
assignments. Both converged on similar findings but through
different delegation paths. Persona-level determinism does not
guarantee orchestration-level determinism.

### 7.4 The list_personas Hallucination

When a Gemma 4 lead was given team orchestration tools but no
explicit persona catalog, it hallucinated a `list_personas` tool
that does not exist. The MCP server returned an error, and the
lead fell back to assigning personas by name from its training
data. This reveals a gap: the lead should receive the persona
catalog as context, not discover it through tool calls.

---

## 8. Conclusion and Future Work

We presented a cognitive framework where structured persona
definitions drive multi-agent orchestration. The separation of
genotype (YAML persona) from phenotype (Weaver-assembled prompt)
enables version-controlled, human-auditable agent identity that
survives across sessions and deployments.

### Future Work

**Persona Evolution (PEM).** Inspired by PersonaVLM (arXiv
2604.13074), personas will accumulate interaction-derived behavioral
traits via momentum-based updates: `trait_new = alpha * observed +
(1 - alpha) * trait_old`. This transforms static YAML definitions
into adaptive agent calibration while preserving reset-to-defaults
capability.

**Knowledge Distillation.** Port the 4-stage Knowledge Cultivation
Pipeline (Ingestion, Synthesis, Reconciliation, Forging) to
transform session transcripts into reusable Insight memories.
The Memory Transfer Learning paper (arXiv 2604.14004) demonstrates
that 431 abstract memories outperform 5,800 raw traces, and raw
trajectories cause negative transfer through domain-mismatched
anchoring.

**ACP Transport.** Adding Agent Client Protocol support (JSON-RPC
2.0 over Streamable HTTP) will expose persona-driven agents to
Zed, JetBrains, and other IDE environments without building
editor-specific plugins.

**Cross-Validation Flows.** Inspired by Claude Code Review's
multi-agent architecture, spawn N parallel verifier agents to
cross-validate high-stakes outputs before surfacing to users.

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
