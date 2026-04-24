# Cognitive Core

The persona system for smgglrs multi-agent orchestration. Defines
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
