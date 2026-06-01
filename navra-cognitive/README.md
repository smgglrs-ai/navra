# navra-cognitive

Cognitive core for AI agent identity: personas, directives, and prompt assembly.

## Overview

Loads persona, directive, and heuristic YAML files from a cognitive
core directory, then assembles them into structured prompts via the
Weaver. Compatible with the Python navra cognitive core format.

## Key types

- `ForgeService` -- loads and indexes a cognitive core directory
- `assemble` / `assemble_with_phase` -- weave persona + directives
  into a system prompt
- `WeaverOutput` -- assembled prompt with sections
- `Persona`, `Directive`, `HeuristicModule` -- YAML-loaded types
- `ContextBudget` -- token budget management
- `TraitStore` / `TraitVector` -- persona trait evolution over time

## Usage

```rust
use navra_cognitive::{ForgeService, assemble};
use std::path::Path;

let forge = ForgeService::load(Path::new("cognitive_core")).unwrap();
let output = assemble(&forge, "developer", "Fix the login bug", None, None).unwrap();
println!("{}", output.system_prompt());
```

## Dependency layer

```
navra-cognitive  (no navra deps -- leaf crate)
```

## Reference

See [DESIGN.md](../DESIGN.md) for the cognitive core architecture
and persona evolution model.
