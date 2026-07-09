+++
title = "DMN Guardrails"
weight = 25
template = "docs/page.html"

[extra]
toc = true
+++

navra can evaluate DMN (Decision Model and Notation) decision tables
as policy guardrails. This lets business analysts and compliance
officers author tool access rules in a standard visual format, using
any DMN 1.3+ editor.

## When to use DMN guardrails

DMN guardrails complement navra's TOML permission rules and Cedar
policies. Use DMN when:

- Compliance officers need to review and modify rules without reading
  code or TOML configuration.
- Your organization already uses BPM tools (Camunda, Trisotech,
  Signavio) for process management.
- Audit requirements mandate that policy rules are expressed in a
  standard, vendor-neutral notation.

## Authoring a decision table

A DMN decision table maps input conditions to output actions. For
navra guardrails, the inputs are request context fields and the output
is an allow/deny decision.

### Input columns

navra evaluates the decision table twice per tool call: once before
execution (pre-call) and once after (post-call output validation).
The `phase` field distinguishes the two evaluations.

| Field | Description |
|---|---|
| `tool_name` | MCP tool being called (e.g., `file_read`, `exec_run`) |
| `agent_name` | Name of the agent making the call |
| `permission_set` | The agent's assigned permission set |
| `session_id` | Current session identifier |
| `resource` | Tool argument path/repo/uri, if present |
| `phase` | `"input"` (pre-call) or `"output"` (post-call validation) |
| `tool_output` | Tool output text, truncated to 2048 chars (only present when `phase = "output"`) |

### Output columns

The decision table must produce one of:

**Single output column** (string): Return `"allow"` or `"permit"` to
allow, any other value (e.g., `"deny"`) to deny.

**Two output columns** (`action` + `reason`): Return action as
`"allow"` or `"deny"`, with a human-readable reason logged in the
audit trail.

### Hit policy

Use `FIRST` hit policy for ordered rules where the first matching
rule wins. The last rule should be a catch-all default.

### Example

The following decision table blocks shell execution for all agents
and blocks git push for the `readonly` permission set:

| tool_name | agent_name | permission_set | action | reason |
|---|---|---|---|---|
| `"exec_run"` | `-` | `-` | `"deny"` | Shell execution blocked |
| `"git_push"` | `-` | `"readonly"` | `"deny"` | Readonly agents cannot push |
| `-` | `-` | `-` | `"allow"` | - |

(`-` means "any value" in DMN notation.)

## DMN file structure

A complete DMN file requires:

1. `<inputData>` elements at the top level for each input column.
2. A `<decision>` element with `<informationRequirement>` references
   to each input.
3. A `<decisionTable>` inside the decision with input expressions,
   output columns, and rules.

See `policies/example-guardrails.dmn` in the navra repository for a
complete, tested example.

## Configuration

Add the DMN file path and decision name to a permission set:

```toml
[permissions.regulated]
dmn_policies = "policies/example-guardrails.dmn"
dmn_decision = "Tool Access"
```

`dmn_policies` is the path to the `.dmn` file (absolute or relative
to the working directory). `dmn_decision` must match the `name`
attribute of a `<decision>` element in the DMN file.

## Evaluation order

The DMN engine is invoked at two points in the pipeline:

**Pre-call** (`phase = "input"`): evaluates after TOML rules, domain
rules, and Cedar policies. Can block the tool call before execution.

```
TOML rules -> Domain rules -> Cedar -> DMN(input) -> Path ACL -> IFC
```

**Post-call** (`phase = "output"`): evaluates after the tool executes
and post-hooks/safety filters run. Can block the result before
delivery to the agent — treating the output as a proposal rather
than a conclusion.

```
Tool execution -> Post-hooks -> Safety filters -> DMN(output) -> Agent
```

Use the `phase` input column in your decision table to write rules
that apply only to one phase. Rules with `-` (any) for `phase`
apply to both.

## Editing tools

Any DMN 1.3+ editor works. Common options:

- [Camunda Modeler](https://camunda.com/download/modeler/) (desktop, free)
- [Trisotech](https://www.trisotech.com/) (web, commercial)
- [bpmn.io DMN editor](https://demo.bpmn.io/dmn/) (web, free)

Export the decision table as `.dmn` (DMN XML) and place it in
navra's policies directory.
