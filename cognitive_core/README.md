# Cognitive Core

The persona system for navra multi-agent orchestration. Defines
agent identities, behavioral frameworks, and operational protocols.

## Structure

```
cognitive_core/
├── directives/              Operational protocols (the "laws")
├── heuristics/              Domain-specific reasoning (the "methods")
├── personas/                Agent identities (the "who")
└── persona_specializations/ Domain-specific persona extensions
```

### Directives

Immutable operational protocols that all agents must follow.
Numbered by priority: 01 (mission) through 09 (temporal awareness),
plus domain-specific protocols (security, performance).

### Heuristics

Reusable reasoning patterns organized by domain. Each module
contains facets — specific, actionable principles. Personas
reference heuristics by module + facet name.

### Personas

Agent identity definitions. Each persona has a core mandate,
heuristic references, tool permissions, and optional model
preferences. 43 personas across engineering, analysis, leadership,
quality assurance, coaching, creative, finance, and ethics.

### Persona Specializations

Extensions that merge into a base persona for domain-specific
tasks (e.g. backend_specialist extends software_developer).

## Usage

```rust
let forge = ForgeService::load(Path::new("cognitive_core"))?;
let output = assemble(&forge, "software_developer", "Fix the bug", None, None)?;
println!("{}", output.system_prompt());
```

Or via the agent builder:

```rust
let agent = Agent::builder()
    .endpoint("http://localhost:9315/mcp").await?
    .model(backend)
    .persona(&forge, "analyst")?
    .build()?;
```

## Adding a Persona

### Persona YAML Schema

Every persona file lives in `personas/` and contains these fields:

| Field | Required | Description |
|---|---|---|
| `persona_name` | yes | Snake_case identifier. Must be unique across all personas. Used as the lookup key. |
| `display_name` | yes | Human-readable name shown in logs and UI. |
| `core_mandate` | yes | Multi-line string defining the agent's fundamental purpose and behavioral boundaries. This becomes the core of the system prompt. |
| `scope` | no | `public` (default) or `internal`. Internal personas are hidden from external callers. |
| `heuristics` | no | List of heuristic references. Each entry has `module` (filename without `.yaml`) and `facets` (list of facet names to load from that module). |
| `tools` | no | List of tool/skill names this persona is allowed to use. |
| `loads_directives` | no | If `true`, all core directives from `directives/` are injected into the system prompt. Reserved for orchestrator personas (e.g. guardian, leader). Default: `false`. |
| `preferred_engine` | no | LLM provider name (e.g. `"claude"`, `"ollama"`). |
| `planning_model` | no | Model for planning phases (e.g. `"claude-opus-4-5"`). |
| `execution_model` | no | Model for execution phases (e.g. `"claude-sonnet-4-5"`). |
| `model_override` | no | Fallback model when no phase-specific model is set. |
| `output_schema` | no | Named output schema for validation. |
| `output_json_schema` | no | Inline JSON schema to constrain model output via `response_format`. |
| `examples` | no | Few-shot examples, each with `title`, `input`, `output`, and optional `thought_process` and `domain`. |
| `planning_context_limit` | no | Max tokens for planning context. System prompt is never truncated. |
| `execution_context_limit` | no | Max tokens for execution context. |
| `skills` | no | Skill module names (string list). |

### Step by Step

1. Create `personas/my_persona.yaml` with at least `persona_name`, `display_name`, and `core_mandate`.
2. Reference existing heuristic modules and facets under `heuristics`. Check `heuristics/` for available modules; open each file to see its `facets` list.
3. Set `loads_directives: true` only if this persona orchestrates other agents and needs the full directive stack.
4. Optionally set model preferences. The Forge resolves models with: phase-specific field > `model_override` > caller default.
5. Restart navra or reload the ForgeService. The new persona is available immediately by name.

### How Heuristics and Directives Are Referenced

Heuristics are modular reasoning libraries. A heuristic YAML file (`heuristics/craftsmanship.yaml`) contains a `heuristic_name`, a `description`, and a list of `facets`. Each facet has a `facet_name` and `content` (the actual instruction text).

A persona selects specific facets from specific modules:

```yaml
heuristics:
  - module: craftsmanship        # matches heuristic_name in heuristics/craftsmanship.yaml
    facets:
      - code_quality_standards   # matches facet_name inside that module
  - module: debugging
    facets: [systematic_debugging, error_investigation]
```

The Weaver resolves each reference at assembly time: it looks up the module in the Forge, finds the requested facets, and injects their `content` into the system prompt.

Directives (`directives/`) are global operational rules loaded for personas with `loads_directives: true`. They are numbered by priority (01 through 09) and apply uniformly.

### How Specializations Work

A specialization extends a base persona without modifying its YAML. Specialization files live in `persona_specializations/` and contain:

```yaml
base_persona: software_developer
description: "backend specialist"
heuristics:
  - "security.input_validation"     # format: module.facet
  - "performance.caching"
tools:
  - database_profiler
directives:
  - security_protocol
```

When loaded via `ForgeService::get_persona_specialized()`, the Forge clones the base persona and merges in the specialization: heuristic facets are appended to existing module refs (or a new ref is created), tools are deduplicated and added, and if directives are listed, `loads_directives` is set to `true`.

### Integration with navra-agent

The agent builder wires personas into the tool-use loop:

```rust
use navra_cognitive::{ForgeService, assemble};

let forge = ForgeService::load(Path::new("cognitive_core"))?;

// Direct assembly — returns a WeaverOutput with system_prompt()
let output = assemble(&forge, "my_persona", "User task text", None, None)?;

// Via the agent builder — sets the system prompt automatically
let agent = Agent::builder()
    .endpoint("http://localhost:9315/mcp").await?
    .model(backend)
    .persona(&forge, "my_persona")?
    .build()?;
```

### Minimal Persona Example

```yaml
persona_name: code_reviewer
display_name: "Code Reviewer"
core_mandate: |
  Review code changes for correctness, security, and maintainability.
  Provide actionable feedback with specific line references.
heuristics:
  - module: craftsmanship
    facets: [code_quality_standards]
  - module: security
    facets: [input_validation]
tools: []
```

This persona loads two heuristic facets, has no tools, does not load directives, and uses the caller's default model. Save it as `personas/code_reviewer.yaml` and it is ready to use.
