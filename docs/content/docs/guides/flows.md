+++
title = "Flow Authoring"
description = "Define multi-agent workflows with DAG and handoff flows."
weight = 10
template = "docs/page.html"

[extra]
toc = true
+++

Flows orchestrate multiple agents into a coordinated workflow. navra
supports two flow kinds: **DAG flows** for parallel task graphs with
dependency resolution, and **handoff flows** for directed graphs with
model-driven routing. Both are defined in YAML and executed by the
`navra-flow` crate.

## Flow kinds

### DAG flows

A DAG flow defines tasks with explicit dependencies. Independent tasks
run concurrently; dependent tasks wait for their predecessors to
complete. Each task is assigned to a specialist (persona) and receives
its predecessors' outputs as context.

Use DAG flows when you know the work breakdown up front: audits,
multi-stage analysis, review pipelines.

### Handoff flows

A handoff flow defines agent nodes connected by directed edges. A
router node decides at runtime which specialist to delegate to by
calling a virtual `handoff` tool. The model chooses the target based
on natural-language edge descriptions.

Use handoff flows for dynamic routing: support triage, conversational
agents that delegate to domain experts.

## YAML format

All flows share a common envelope:

```yaml
kind: dag          # or "handoff"
name: my-flow
description: What this flow does

parameters:
  target_dir:
    type: string
    description: Root directory to operate on
  severity:
    type: string
    description: Minimum severity level
    default: medium
```

Parameters use `{{ name }}` Mustache-style placeholders. They are
substituted before YAML parsing. Parameters with a `default` are
optional; parameters without a default are required.

### DAG flow structure

```yaml
kind: dag
name: security-audit
description: Security audit via scout, planner, specialist swarm, synthesizer

parameters:
  target_dir:
    type: string
    description: Root directory of the project to audit

tasks:
  - id: scout
    specialist: security_sentinel
    model: granite3.3:8b
    mandate: |
      Use file_tree to list all files in {{ target_dir }}.
      Return the complete file list with exact relative paths.
    expected_output: Complete file list with paths

  - id: planner
    specialist: analyst
    model: qwen3.6:35b-a3b
    depends_on: [scout]
    generates_tasks: true
    mandate: |
      Given the project file list from the scout, create a
      thorough review plan. Output ONLY a JSON array of tasks.
    expected_output: JSON array of tasks covering all files

  - id: synthesize
    specialist: synthesizer
    model: gemma4:26b
    depends_on: [planner]
    mandate: |
      Merge all specialist findings into a security audit report.
    expected_output: Security audit report with verified findings
```

#### Task fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique identifier within the flow |
| `specialist` | yes | Persona name to execute this task |
| `mandate` | yes | What the specialist should accomplish |
| `depends_on` | no | Task IDs that must complete first (default: none) |
| `model` | no | Model override (e.g. `granite3.3:8b`). Uses the default if absent |
| `expected_output` | no | Description of what a good output looks like |
| `success_criteria` | no | List of criteria for mandate validation |
| `generates_tasks` | no | If true, output is parsed as a JSON array of new tasks injected into the DAG |
| `tools` | no | Override the default tool set for this task |
| `operations` | no | Override default capability token operations |
| `temperature` | no | Temperature override for this task's model calls |
| `verification` | no | Cross-validation config (see below) |
| `back_edges` | no | Conditional loops (see below) |

### Handoff flow structure

```yaml
kind: handoff
name: support-triage
description: Customer support triage flow
entry: router

parameters:
  product:
    type: string
    description: Product name
    default: widget

nodes:
  - id: router
    endpoint: "http://localhost:9315/mcp"
    model_url: "http://localhost:11434/v1"
    model_name: "qwen2.5:0.5b"
    system_prompt: "Route {{ product }} support requests."

  - id: billing
    endpoint: "http://localhost:9315/mcp"
    model_url: "http://localhost:11434/v1"
    model_name: "qwen2.5:0.5b"
    system_prompt: "Handle billing inquiries for {{ product }}."

  - id: technical
    endpoint: "http://localhost:9315/mcp"
    model_url: "http://localhost:11434/v1"
    model_name: "qwen2.5:0.5b"
    system_prompt: "Handle technical support for {{ product }}."

edges:
  - from: router
    to: billing
    description: "Customer has a billing question"
  - from: router
    to: technical
    description: "Customer has a technical issue"
```

#### Node fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique node identifier |
| `endpoint` | yes | MCP server endpoint URL |
| `model_url` | yes | Model API URL (OpenAI-compatible) |
| `model_name` | yes | Model name for the API |
| `system_prompt` | no | System prompt for this node |
| `api_key` | no | API key for the model |
| `max_iterations` | no | Max tool-use iterations per hop (default: 10) |
| `temperature` | no | Temperature for model calls |
| `max_tokens` | no | Max tokens per model response |
| `context_window` | no | Context window size in tokens |
| `clearance` | no | IFC clearance: `public`, `sensitive`, or `secret` |

#### Edge fields

| Field | Required | Description |
|-------|----------|-------------|
| `from` | yes | Source node ID |
| `to` | yes | Target node ID |
| `description` | yes | When to use this route (natural language, used by the model) |

The `entry` field specifies where execution starts. `max_hops`
(default: 10) limits the total number of node transitions to prevent
infinite loops.

## Dynamic task generation

A task with `generates_tasks: true` acts as a planner. Its output is
parsed as a JSON array of task definitions and injected into the DAG
at runtime. The synthesizer task automatically depends on all injected
tasks.

This enables patterns like scout-planner-swarm-synthesizer, where the
planner decides at runtime how many specialists to spawn and what
each should do:

```yaml
tasks:
  - id: planner
    specialist: analyst
    generates_tasks: true
    mandate: |
      Call personas_list to see available specialists.
      Create 10-20 review tasks as a JSON array.
      Each task: {"id": "...", "specialist": "...", "mandate": "..."}

  - id: synthesize
    specialist: summarizer
    depends_on: [planner]
    mandate: Merge all specialist findings into a report.
```

The planner's JSON output is parsed with multi-strategy extraction:
markdown code fences are stripped, the outermost `[...]` is found,
and individual `{...}` objects are tried if the whole array fails to
parse. This tolerates common model output quirks.

## Back-edges (conditional loops)

Back-edges let a task re-execute an earlier task when conditions are
not met, creating controlled loops within the DAG:

```yaml
tasks:
  - id: implement
    specialist: software_developer
    mandate: Fix the authentication bug.
    back_edges:
      - target: implement
        condition: "score_below:70"
        max_iterations: 3
```

### Condition types

| Condition | Syntax | Activates when |
|-----------|--------|----------------|
| Score threshold | `score_below:70` | Validation score is below the threshold |
| Missing criteria | `criteria_missing` | Any success criteria are unmet |
| Output pattern | `output_contains:error` | Output contains the substring |
| Always | `always` | Every time (fixed-iteration loops) |

Each back-edge has a `max_iterations` limit (default: 3) to prevent
infinite loops. A global activation bound (1000) caps total back-edge
firings across the entire DAG.

## Cross-validation

For high-stakes outputs, configure multi-agent verification. After a
task completes, N independent verifier agents assess the output:

```yaml
tasks:
  - id: critical_analysis
    specialist: analyst
    mandate: Analyze the contract for compliance issues.
    verification:
      agents: 3
      threshold: unanimous
      verifier_persona: reviewer
```

### Threshold options

| Threshold | Passes when |
|-----------|-------------|
| `any` | At least one verifier approves |
| `majority` | More than half approve (default) |
| `unanimous` | All verifiers approve |

If verification fails, the task is retried with the verifiers'
findings injected as context. This implements a review-revise loop
driven by independent assessment.

## Mesh communication

Flows support two lateral communication patterns for agents that need
to share state beyond the dependency graph.

### Mailbox (point-to-point)

Enable per-agent mailboxes for direct messaging between nodes.
Messages are IFC-gated: a sender tainted with sensitive data cannot
write to a public-clearance receiver (Bell-LaPadula no-write-down).

In handoff flows, enable with `mailbox_capacity`:

```yaml
# FlowBuilder API
Flow::builder("collab")
    .enable_mailbox(16)
    .build()
```

Agents use the virtual `mesh_post` and `mesh_recv` tools to send and
receive messages. All deliveries are recorded in an audit log.

### Blackboard (shared state)

A flow-level key-value store where each entry carries an IFC label.
When an agent reads an entry, the entry's label is absorbed into the
reader's taint tracker (lattice join -- taint only rises).

```yaml
# FlowBuilder API
Flow::builder("shared")
    .enable_blackboard(256)
    .build()
```

Agents use `bb_publish`, `bb_read`, and `bb_keys` tools. Entries are
versioned: each publish increments the version counter and appends
the author to the provenance chain.

## Iterative analysis

The `IterativeExecutor` runs a scout-map-reduce loop for large-context
analysis. Each round:

1. **Scout** identifies items to analyze (files, sections)
2. **Map** analyzes each item individually
3. **Reduce** synthesizes findings
4. **Evaluate** checks convergence (new findings below threshold)

```toml
# IterativeConfig
name = "security-scan"
max_rounds = 5
min_delta = 2
max_items_per_round = 10
scout_specialist = "scout"
map_specialist = "auditor"
reduce_specialist = "analyst"
```

Two scout modes are available:

| Mode | Behavior |
|------|----------|
| `model` | The model picks files each round. Can miss files. |
| `exhaustive` | Cycles through ALL files in batches. Full coverage guaranteed. |

The loop stops when new findings per round drop below `min_delta` or
`max_rounds` is reached.

## Recovery strategies

When a task fails, the executor classifies the failure and applies a
recovery strategy:

| Failure type | Strategy | Max retries |
|-------------|----------|-------------|
| Circular fix (same error repeated) | Skip | 0 |
| Empty output | Retry with context | 2 |
| Validation failed | Retry with context | 3 |
| Max iterations | Retry with context | 1 |
| Agent/model error | Retry with context | 2 |

On retry, the previous attempt's error is injected into the prompt
so the model can address the specific failure. If the last N attempts
all produce the same error type, circular fix detection kicks in and
the task is skipped to prevent infinite loops.

When a task fails permanently, all tasks that depend on it are skipped
with a message indicating which dependency failed.

## Checkpoint and recovery

Enable per-node checkpointing for crash resilience. After each task
completes, its output is saved to a SQLite database. On restart, the
executor resumes from the last checkpoint:

```rust
use navra_flow::{DagCheckpoint, DagExecutor};
use std::sync::Arc;

let checkpoint = Arc::new(
    DagCheckpoint::open(Path::new("~/.local/share/navra/checkpoints.db"))?
);

let executor = DagExecutor::new()
    .with_checkpoint(checkpoint, "flow-001".into());
```

Checkpoints are deleted on successful flow completion. Use
`DagCheckpoint::list_incomplete()` to find flows that were interrupted.

The checkpoint store also provides an idempotency cache for tool calls,
preventing re-execution of non-idempotent operations (like git commits)
on replay.

## Circuit breaker

The executor includes a per-tool circuit breaker. After a configurable
number of consecutive failures on a tool, the circuit opens and
further calls to that tool are blocked until a cooldown period
expires:

```rust
let executor = DagExecutor::new()
    .with_circuit_breaker(5, Duration::from_secs(60));
```

A successful tool call resets the failure count.

## Hop limit

Set `max_hops` to limit the total number of agent-to-agent transitions
in a single execution path. This prevents agent worm propagation
patterns where a compromised agent chains handoffs indefinitely:

```rust
let executor = DagExecutor::new()
    .with_max_hops(20);
```

In handoff flows, `max_hops` defaults to 10.

## Insight callbacks (ReasoningBank)

The executor can emit structured insights after each task for storage
in a knowledge base. On subsequent runs, the most relevant past
insight is retrieved and injected as a "lesson learned":

```rust
let executor = DagExecutor::new()
    .on_insight(Arc::new(|insight| {
        // Store insight.content with insight.tags
    }))
    .with_insight_retriever(Arc::new(|mandate| {
        // Return the single most relevant past insight
        None
    }));
```

This implements the ReasoningBank k=1 pattern: one focused memory per
task beats multiple diluted memories.

## Running flows

### From the CLI

```bash
# Run a DAG flow
navra flow run examples/flows/security-audit.yaml \
    --param target_dir=/path/to/project

# Run the self-improvement cycle
navra improve --target . --cycles 3

# Run a review
navra flow run examples/flows/review.yaml \
    --param target_dir=.
```

### From the Rust API

```rust
use navra_flow::{Flow, FlowBuilder};

// Handoff flow from TOML
let mut flow = Flow::from_toml(&toml_str).await?;
let result = flow.run("Analyze the codebase").await?;
println!("{}", result.response);
println!("Hops: {}, Path: {:?}", result.hops, result.path);

// DAG flow
use navra_flow::{DagExecutor, DagConfig};
use navra_flow::yaml_loader::load_flow_yaml;

let dag = load_flow_yaml(&yaml_str, &params)?;
let mut executor = DagExecutor::new()
    .agent("analyst", analyst_agent)
    .agent("developer", dev_agent);
let result = executor.run(tasks).await?;
```

## Example flows

navra ships with several ready-to-use flow definitions in
`examples/flows/`:

| Flow | Description |
|------|-------------|
| `review.yaml` | Domain-agnostic project review (scout, planner, specialist swarm, synthesizer) |
| `security-audit.yaml` | Security audit with file-level coverage |
| `self-improve.yaml` | Autonomous audit-fix-test-verify cycle |
| `improve.yaml` | Domain-agnostic improvement cycle |
| `deep-research.yaml` | Multi-round research with source verification |
| `review-lite.yaml` | Lightweight review for smaller projects |
| `comprehensive-review.yaml` | Full review with all specialist areas |

## IFC integration

All flow communication respects Information Flow Control:

- **Mailbox messages** are checked against Bell-LaPadula no-write-down.
  A sensitive-tainted sender cannot post to a public-clearance receiver.
- **Blackboard reads** absorb the entry's label into the reader's taint
  (lattice join -- taint only rises, never drops).
- **Task outputs** carry accumulated taint from all tool calls made
  during execution. The `DagResult.taint` field reports the highest
  classification reached.
- **Handoff nodes** can declare a `clearance` level. The flow engine
  enforces that data does not flow downward across clearance boundaries.
