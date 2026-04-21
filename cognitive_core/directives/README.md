# Directives

Non-negotiable operational protocols. Every agent with
`loads_directives: true` (the Guardian) injects all directives
into its system prompt. Other agents inherit them indirectly
through the orchestration hierarchy.

## Hierarchy

| File | Scope | Purpose |
|------|-------|---------|
| `01_mission_and_identity` | Identity | Who the system is, its role and commitments |
| `02_core_mindsets` | Behavioral | How agents think: proactive architect, adaptive recoverer, project steward |
| `03_operational_protocols` | Procedural | How agents execute: task decomposition, handoff rules, error handling |
| `04_project_ingestion_protocol` | Onboarding | How new projects are analyzed and integrated |
| `09_temporal_awareness_protocol` | Context | How agents handle time-sensitive information |
| `performance_protocol` | Constraint | Latency, throughput, and resource budgets |
| `security_protocol` | Constraint | Input validation, secret handling, access control |

## Numbering

Lower numbers = higher priority. Numbered directives (01-09)
define identity and process. Unnumbered protocols (performance,
security) define operational constraints.

## Adding a directive

Create a YAML file with:

```yaml
directive_name: my_protocol
description: "What this protocol governs"
content: |
  Multi-line protocol content...
references:
  - description: "Source"
    source: "https://..."
```

The Forge loads all `.yaml` files in this directory automatically.
