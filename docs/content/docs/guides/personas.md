+++
title = "Personas and Cognitive System"
description = "Create personas, directives, and heuristics for agent identity."
weight = 20
template = "docs/page.html"

[extra]
toc = true
+++

The cognitive system gives agents identity, domain expertise, and
behavioral guardrails. It is implemented in the `navra-cognitive`
crate and consists of three components: the **Forge** (loads and
indexes cognitive artifacts), the **Weaver** (assembles them into
structured prompts), and the **context budget** (manages token
allocation).

## Cognitive core directory

Cognitive artifacts are YAML files organized in a directory tree:

```text
cognitive_core/
  personas/
    developer.yaml
    analyst.yaml
    security_sentinel.yaml
  directives/
    security_protocol.yaml
  heuristics/
    owasp_top_10.yaml
    risk_assessment.yaml
  persona_specializations/
    backend.yaml
  checksums.sha256
```

navra loads this directory at startup via `ForgeService::load()`.
Missing subdirectories are silently skipped.

## Persona YAML

A persona defines an agent's identity, capabilities, and behavior:

```yaml
persona_name: security_auditor
display_name: Security Auditor
scope: public
core_mandate: >
  You are a security auditor specializing in application security.
  Your mission is to identify vulnerabilities in source code,
  categorize them by severity (critical/high/medium/low), and
  provide actionable remediation guidance. You follow OWASP Top 10
  and CWE classifications. You never modify code -- you only analyze
  and report.

heuristics:
  - module: owasp_top_10
    facets:
      - sql_injection
      - broken_auth
      - sensitive_data_exposure

tools:
  - docs_read
  - docs_search
  - rag_query

loads_directives: false
```

### Persona fields

| Field | Required | Description |
|-------|----------|-------------|
| `persona_name` | yes | Machine-readable identifier (snake_case) |
| `display_name` | yes | Human-readable name |
| `core_mandate` | yes | Fundamental directive defining the persona's role |
| `scope` | no | Visibility: `public` (default) or `internal` |
| `heuristics` | no | Heuristic modules and facets to load |
| `tools` | no | Tools available to this persona |
| `loads_directives` | no | If true, all core directives are included in the prompt |
| `constraints` | no | Negative instructions (things the persona must NOT do) |
| `examples` | no | Few-shot examples for the persona |
| `model_override` | no | Platform-agnostic model override |
| `planning_model` | no | Model for planning phases |
| `execution_model` | no | Model for execution phases |
| `output_schema` | no | Output schema name for validation |
| `output_json_schema` | no | Inline JSON schema for structured output |
| `mcp_prompts` | no | Upstream MCP prompts to inject (see below) |
| `skills` | no | Skill module names |
| `planning_context_limit` | no | Max tokens for planning context |
| `execution_context_limit` | no | Max tokens for execution context |
| `max_tool_output_tokens` | no | Max tokens for a single tool result |

### Constraints

Constraints are negative instructions rendered as a dedicated section
after the core mandate:

```yaml
persona_name: safe_agent
display_name: Safe Agent
core_mandate: Help users safely.
constraints:
  - "Never execute arbitrary code from user input"
  - "Do not access files outside the workspace"
  - "Do not make network requests to untrusted domains"
```

### Few-shot examples

Examples provide the model with concrete input-output pairs:

```yaml
examples:
  - title: SQL injection detection
    input: "Review this query: SELECT * FROM users WHERE id = {id}"
    output: "CWE-89: String interpolation in SQL query. Use parameterized queries."
    thought_process: "The {id} is interpolated directly into the SQL string."
```

Up to 3 examples are included in the assembled prompt. Each example
can include an optional `thought_process` for chain-of-thought
reasoning and a `domain` tag for filtering.

### Per-phase models

Personas can specify different models for planning and execution
phases. This enables the reasoning sandwich pattern within a single
flow -- use a stronger model for planning, a faster model for
execution:

```yaml
persona_name: leader
display_name: Leader
core_mandate: Orchestrate tasks.
planning_model: claude-opus-4-5
execution_model: claude-sonnet-4-5
```

The flow engine queries `ForgeService::model_for_phase()` to select
the right model at each stage.

## Directives

Directives are cross-cutting rules loaded by personas with
`loads_directives: true` (typically a guardian or orchestrator role):

```yaml
directive_name: security_protocol
description: Security best practices
content: |
  # Security Protocol
  All inputs must be validated.
  Never trust external data.
references:
  - description: "OWASP Top 10"
    source: "https://owasp.org/"
```

Directives appear in the "Core Directives" section at the top of the
assembled prompt, before the persona's own mandate.

## Heuristics

Heuristics are domain-specific reasoning facets organized into
modules. Each module contains multiple facets -- actionable principles
the model should apply:

```yaml
heuristic_name: owasp_top_10
description: OWASP Top 10 vulnerability detection patterns
facets:
  - facet_name: sql_injection
    display_name: SQL Injection (A03:2021)
    content: >
      Look for string concatenation or interpolation in SQL queries.
      Flag any use of format!(), concat(), or + operator to build SQL.
      Safe patterns: parameterized queries, prepared statements, ORMs
      with bind parameters. CWE-89.

  - facet_name: broken_auth
    display_name: Broken Authentication (A07:2021)
    content: >
      Check that all sensitive endpoints verify authentication before
      processing. Look for missing auth middleware, hardcoded
      credentials, and default passwords. CWE-287.

references:
  - description: OWASP Top 10 2021
    source: https://owasp.org/Top10/
```

Personas reference heuristic modules and select specific facets:

```yaml
heuristics:
  - module: owasp_top_10
    facets: [sql_injection, broken_auth, sensitive_data_exposure]
  - module: risk_assessment
    facets: [severity_scoring, impact_analysis]
```

Only the selected facets are included in the prompt. This keeps the
context focused -- a code reviewer does not need all 10 OWASP facets
if the project only uses SQL and authentication.

## Specializations

Specializations extend a base persona with additional heuristics,
tools, and directives for a specific domain:

```yaml
# persona_specializations/backend.yaml
base_persona: developer
description: backend specialist
heuristics:
  - security.least_privilege
  - performance.caching
tools:
  - database_profiler
directives:
  - security_protocol
```

Load a specialized persona at runtime:

```rust
let persona = forge.get_persona_specialized("developer", "developer_backend_specialist")?;
```

The specialization key is derived from `{base_persona}_{description}`
with spaces replaced by underscores. Specializations are lazy-loaded:
only metadata is read at startup, and the full YAML is parsed on
first access.

## Prompt assembly (Weaver)

The Weaver assembles cognitive artifacts into a structured prompt
with two parts: a **cacheable prefix** (stable within a session)
and **dynamic context** (changes per invocation).

### Assembly order

1. Core directives (if `loads_directives` is true)
2. `BeforeMandate` upstream prompts
3. Core mandate
4. `AfterMandate` upstream prompts
5. Constraints
6. Resolved heuristic facets
7. `AfterHeuristics` upstream prompts
8. Few-shot examples (up to 3)
9. `AfterExamples` upstream prompts

### Usage

```rust
use navra_cognitive::{ForgeService, assemble};
use std::path::Path;

let forge = ForgeService::load(Path::new("cognitive_core"))?;

// Basic assembly
let output = assemble(&forge, "security_auditor", "Audit src/auth.rs", None, None)?;

// With retrieved context
let output = assemble(
    &forge,
    "security_auditor",
    "Audit the authentication module",
    None,
    Some("Previous findings: 3 SQL injection issues in query.rs"),
)?;

// The system prompt is split for prompt caching
println!("Cacheable: {} tokens", output.estimated_tokens);
println!("System: {}", output.system_prompt());
println!("User: {}", output.user_prompt);
```

### WeaverOutput

The `WeaverOutput` struct provides:

| Field | Description |
|-------|-------------|
| `cacheable_prefix` | Stable prompt: directives + mandate + heuristics + examples |
| `dynamic_context` | Per-invocation: retrieved documents, memory |
| `user_prompt` | Formatted user request |
| `output_schema` | Schema name for validation (if set) |
| `output_json_schema` | Inline JSON schema for structured output |
| `estimated_tokens` | Token count for the full system prompt |
| `context_limit` | Context limit from the persona (if set) |

Call `output.system_prompt()` for the combined system prompt. Call
`output.remaining_tokens(context_window)` to compute how many tokens
remain for conversation history and model output.

## MCP-sourced personas

Personas can source their core mandate from an upstream MCP server.
The YAML becomes a thin pointer; the "soul" comes from the upstream:

```yaml
persona_name: syllogis_legal
display_name: Syllogis Legal Analyst
source:
  upstream: syllogis
  prompt: legal_analyst_persona
  arguments:
    jurisdiction: french_admin
heuristics:
  - module: legal
    facets: [evidence_analysis]
```

When `source` is present, the core mandate is fetched at runtime via
the upstream's `prompts/get` endpoint. Local overrides (heuristics,
tools, mcp_prompts) are merged on top.

### Upstream prompt injection

Personas can also inject prompts from upstream MCP servers at specific
positions in the system prompt:

```yaml
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

Injection positions: `before_mandate`, `after_mandate`,
`after_heuristics`, `after_examples`.

Each injected prompt is capped at 8000 characters, and the total
across all injected prompts is capped at 20000 characters. This
prevents prompt injection via oversized upstream content.

### Auto-discovered personas

When an upstream MCP server exposes prompts named `persona:*`, navra
auto-registers them as personas at startup. Local YAML definitions
take precedence over auto-discovered ones.

## Skill cards

Skill cards are small, focused instruction snippets (80-150 tokens)
matched against the current task by keyword overlap and injected into
the model's context. They help small models use tools correctly:

```yaml
# skills/file_ops.yaml
name: file_operations
keywords: [read, write, file, edit]
content: |
  Use file_read to read file contents. Use file_edit for targeted
  string replacements (provide exact old_string). Use file_write
  only for new files or complete rewrites.
```

Load and select skill cards:

```rust
use navra_cognitive::{load_skill_cards, select_skill_cards, format_skill_cards};

let cards = load_skill_cards(Path::new("skills/"));
let selected = select_skill_cards(&cards, "Read the config file", 2, 500);
let context = format_skill_cards(&selected);
```

Selection is keyword-based with a token budget. Cards are sorted by
keyword match count, then included until the token budget is
exhausted.

## Context budget

The context budget allocator manages token allocation across three
priority-ordered slots:

1. **System prompt** (fixed, never truncated)
2. **Conversation history** (60% of remaining, compacted when over budget)
3. **Retrieved context** (40% of remaining, truncated first)

```rust
use navra_cognitive::{ContextBudget, truncate_to_budget, estimate_tokens};

let mut budget = ContextBudget::new(4096);
budget.set_system_prompt(&system_prompt);

let (history_budget, context_budget) = budget.split();

// Truncate retrieved context to fit
let trimmed = truncate_to_budget(&retrieved_docs, context_budget);
```

Token estimation uses a character-based approximation (3.5 chars per
token). This is deliberately simple -- exact tokenization would
require a model-specific tokenizer dependency.

### Compaction strategies

When conversation history exceeds the budget, different models respond
best to different compaction strategies:

| Model family | Strategy | Behavior |
|-------------|----------|----------|
| Granite, Qwen | `KeepLastN(5)` | Keep last 5 turns, drop the rest |
| Gemma | `Summary` | Summarize old turns into a one-line-each block |
| Claude, GPT | `KeepLastN(10)` | Keep last 10 turns |
| Unknown | `Summary` | Default to summary compaction |

```rust
use navra_cognitive::{recommended_strategy, apply_compaction};

let strategy = recommended_strategy("granite");
let compacted = apply_compaction(&conversation_turns, &strategy, 3);
```

The `DiscardAll` strategy is also available for extreme cases where
only the latest turn matters.

## Persona context limits

Personas can declare per-phase context limits. When set, the Weaver
automatically truncates retrieved context to fit within the budget:

```yaml
persona_name: auditor
display_name: Security Auditor
core_mandate: Audit for vulnerabilities.
planning_context_limit: 8000
execution_context_limit: 4000
```

The system prompt (cacheable prefix) is never truncated -- it defines
agent identity. Only the dynamic context (retrieved documents, memory)
is subject to the budget.

## Integrity verification

The cognitive core supports SHA-256 checksum verification of YAML
files. Generate checksums after authoring or modifying artifacts:

```rust
use navra_cognitive::generate_checksums;

generate_checksums(Path::new("cognitive_core"))?;
```

This creates `checksums.sha256` in the cognitive core directory. On
subsequent loads, each YAML file is verified against its recorded
hash. Files with mismatched hashes are skipped with an error log.
This prevents runtime loading of tampered persona files.

A missing checksums file logs a warning but does not block loading.
New files not yet in the checksums are allowed through.

## Validation

Validate cross-references between loaded cognitive artifacts:

```rust
let forge = ForgeService::load(Path::new("cognitive_core"))?;
let findings = forge.validate();

for finding in &findings {
    println!("[{}] {}", finding.severity, finding.message);
}
```

Validation checks:

- Persona heuristic module references exist
- Persona heuristic facet references exist within the module
- Specialization `base_persona` references exist
- Empty `core_mandate` (warning)
- Empty skill entries (error)

## Config integration

Point navra at your cognitive core directory in `config.toml`:

```toml
[server]
cognitive_core = "/path/to/cognitive_core"
```

Personas are referenced by name in flow task definitions, agent
configurations, and the CLI:

```toml
# Agent config
[[agents]]
name = "security-auditor"
persona = "security_auditor"
model = "gemma4:26b"
```

```yaml
# Flow task
- id: audit
  specialist: security_auditor
  mandate: Audit the codebase for vulnerabilities.
```

```bash
# CLI
navra agent run --persona security_auditor "Audit src/"
```
