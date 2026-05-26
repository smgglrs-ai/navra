# smgglrs-flow

Multi-agent orchestration engine for smgglrs. Provides three execution
modes -- DAG, Handoff, and Iterative -- plus mesh communication
(mailbox and blackboard), mandate validation, anti-propagation hop
limits, and provenance tracking on inter-agent messages.

## Execution modes

### DAG execution

Parallel task graphs with dependency resolution. Tasks run
concurrently when their dependencies are satisfied.

`DependencyGraph` validates the graph at construction (no dangling
references, no cycles) using Kahn's algorithm for topological sort.
`get_ready_tasks()` returns all tasks whose dependencies are complete,
enabling maximum parallelism.

```rust
use smgglrs_flow::dag::DependencyGraph;

let dag = DependencyGraph::new(tasks)?;
let mut completed = HashSet::new();

loop {
    let ready = dag.get_ready_tasks(&completed);
    if ready.is_empty() { break; }
    for task in ready {
        let result = execute(task).await;
        completed.insert(task.id.clone());
    }
}
```

Task lifecycle: `Pending` -> `Ready` -> `Running` -> `Complete` | `Failed` | `Skipped`.

### Handoff flows

Directed graph of agent nodes with model-driven routing. A virtual
`handoff` tool is injected into each node's tool list, letting the
model decide when to delegate to another specialist.

```rust
// The model sees this tool and calls it when appropriate:
// handoff(target: "coder", task: "Implement the auth module")
```

Routing instructions are generated from `EdgeDefinition` entries and
appended to each node's system prompt. The model sees which
specialists are available and their descriptions, then decides
whether to handle the task itself or hand off.

`max_hops` limits the total number of handoffs to prevent infinite
loops (default: 10).

### Iterative execution

Convergence-based refinement using a scout-map-reduce loop:

1. **Scout** -- select items to analyze (model-driven or exhaustive)
2. **Map** -- analyze each item independently (parallelizable)
3. **Reduce** -- deduplicate and synthesize findings
4. **Evaluate** -- check convergence (`min_delta` threshold)

Repeats until convergence or `max_rounds` is reached.

```rust
let config = IterativeConfig {
    name: "security-audit".into(),
    max_rounds: 5,
    min_delta: 2,
    scout_mode: ScoutMode::Exhaustive,
    scout_specialist: "scout".into(),
    map_specialist: "auditor".into(),
    reduce_specialist: "analyst".into(),
    ..
};
```

## Mesh communication

### Mailbox (agent-to-agent)

IFC-gated mpsc channels between agents. Each `post()` is checked
against Bell-LaPadula no-write-down: a sender tainted with
`Sensitive` data cannot write to a `Public`-clearance receiver.

```rust
let reg = MailboxRegistry::new(&agent_ids, 64);
reg.post("alice", DataLabel::TRUSTED_PUBLIC, "bob", "hello".into())?;
let msg = reg.recv("bob"); // non-blocking
```

All deliveries are recorded in an audit log.

### Blackboard (shared key-value)

Flow-level key-value store where each entry carries a `DataLabel`.
When an agent reads an entry, the entry's label is absorbed into
the reader's taint tracker (lattice join -- taint only rises).

```rust
let bb = Blackboard::new(256);
bb.publish("agent-a", "findings", json!(data), DataLabel::TRUSTED_PUBLIC)?;

let entry = bb.read("findings", &mut taint_tracker)?;
// taint_tracker now carries the entry's label
```

## Back-edges

Conditional re-execution for failure recovery. After a task
completes, its back-edges are evaluated. If a condition is met and
the iteration limit is not exceeded, the target task is re-queued.

Conditions:

| Condition | Triggers when |
|---|---|
| `score_below:N` | Validation score < N |
| `criteria_missing` | Any success criteria not met |
| `output_contains:X` | Output contains substring X |
| `always` | Every time (fixed-iteration loops) |

Each back-edge has a `max_iterations` cap (default: 3) tracked by
`BackEdgeTracker`.

## YAML flow definitions

Flows can be defined in YAML with `{{ param }}` parameter
substitution:

```yaml
kind: dag
name: security-audit
description: Audit a project for security vulnerabilities
parameters:
  target_dir:
    type: string
    description: Directory to audit
  severity:
    type: string
    description: Minimum severity level
    default: medium
tasks:
  - id: scan
    specialist: security_auditor
    mandate: "Scan {{ target_dir }} for {{ severity }}+ vulnerabilities"
    expected_output: "List of findings with CWE IDs"
  - id: fix
    specialist: developer
    mandate: "Fix critical findings from scan"
    depends_on: [scan]
    success_criteria:
      - "Tests pass"
      - "No regressions"
    back_edges:
      - target: scan
        condition: "score_below:80"
        max_iterations: 2
  - id: report
    specialist: analyst
    mandate: "Synthesize findings into a prioritized report"
    depends_on: [fix]
```

Load with parameter substitution:

```rust
let dag = load_flow_yaml(&yaml_str, &params)?;
```

The `generates_tasks` field on a task causes its output to be parsed
as a JSON array of `TaskDefinition` and injected into the DAG at
runtime. The synthesizer task automatically depends on all injected
tasks.

## Mandate validation

`validate_mandate()` checks task output against its mandate:

- **Empty output** -- 30-point penalty
- **Short output** when `expected_output` is set -- 20-point penalty
- **Missing success criteria** -- 15-point penalty per criterion
  (keyword matching against output)

Score >= 70 passes. Score floors at 0.

## IFC integration

Data labels propagate through flows at three levels:

1. **Mailbox** -- Bell-LaPadula no-write-down on every `post()`
2. **Blackboard** -- taint-on-read via `TaintTracker.absorb()`
3. **Mesh router** -- IFC check on all messages regardless of
   teammate location (in-process or remote A2A)

Taint only rises through the lattice (Public -> Sensitive -> Secret).
A task's output carries its accumulated taint label, which propagates
to downstream tasks in the DAG.

## Dependency layer

```
smgglrs-agent (+ protocol, model, security, cognitive)
    |
smgglrs-flow
```

## Reference

See [DESIGN.md](../DESIGN.md) for the full flow engine architecture.
