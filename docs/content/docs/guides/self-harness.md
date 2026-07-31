+++
title = "Self-Harness"
description = "Automatic flow improvement from execution trace analysis."
weight = 30
template = "docs/page.html"

[extra]
toc = true
+++

Self-Harness mines weaknesses from recorded flow execution traces,
proposes concrete improvements, and validates them against historical
data before anyone applies them. The entire process runs out-of-band
-- agents never see it.

## When to use it

Run self-harness after you have accumulated execution traces from
production or staging flows. It is most useful when flows run
repeatedly on similar tasks (review pipelines, analysis workflows,
audit sweeps) because recurring patterns produce actionable findings.

A single flow execution can still produce findings (tool errors,
slow calls), but the regression validation step needs at least one
previously-successful trace to be meaningful.

## Quick start

```bash
# Analyze all recent flows (auto-discovers from event log)
navra self-harness

# Analyze specific flows
navra self-harness --flow review-pipeline-001 --flow audit-sweep-042

# JSON output for scripting
navra self-harness --json

# Tune thresholds
navra self-harness --retry-threshold 5 --slow-tool-ms 20000
```

The command reads the flow event log at
`~/.local/share/navra/flow_events.db` (populated automatically when
flows execute through the gateway).

## Three-phase pipeline

### 1. Weakness mining

The miner scans event log traces for six weakness types:

| Type | What it detects | Default threshold |
|------|----------------|-------------------|
| `tool_error` | Tool calls that returned errors | 1 occurrence |
| `node_failure` | Agent nodes that crashed or timed out | 1 occurrence |
| `retry_loop` | Back-edge iterations exceeding limit | 3 iterations |
| `skipped_node` | Nodes skipped (dependency failures) | 1 occurrence |
| `token_inefficiency` | High prompt tokens, low completion output | ratio < 0.1 |
| `slow_tool_call` | Tool calls exceeding duration threshold | 10,000 ms |

Each finding includes a severity score (0.0--1.0), the affected task
and tool names, occurrence count, and evidence (event sequence
numbers for traceability).

Findings are sorted by severity, so the most impactful issues appear
first.

### 2. Harness proposal

Each weakness generates a structured proposal describing a concrete
configuration change. Five proposal kinds exist:

**BackEdgeAdjust** -- reduce iteration limits or add exit conditions
for retry loops. Generated when a back-edge exceeds the retry
threshold.

**ToolConfig** -- add timeout guards for slow tools. Generated when a
tool consistently exceeds the duration threshold.

**FlowDagEdit (fallback)** -- add a fallback specialist for a
repeatedly failing node. Generated when a node fails two or more
times.

**FlowDagEdit (remove)** -- remove a persistently skipped node.
Generated when a node is skipped three or more times.

**PolicyChange / HookConfig** -- reserved for future safety hook and
permission policy proposals.

Each proposal includes:
- A unique ID (`SH-0001`, `SH-0002`, ...)
- Expected improvement score and regression risk score
- A `ProposalDiff` describing the exact change

### 3. Regression validation

Before a proposal is marked safe, the validator replays it against
every historical trace where the flow completed successfully:

- **BackEdgeLimit** proposals: checks whether any successful trace
  used more iterations than the proposed new limit. If so, applying
  the limit would have prevented that successful run -- regression.
- **RemoveNode** proposals: checks whether any successful trace
  completed the node. If so, removing it could break the flow --
  regression.
- **AddTimeout / AddFallback**: always safe (additive changes).

Outcomes:
- **Safe** -- no regressions detected across all checked traces.
- **Regression** -- at least one successful trace would break.
- **InsufficientData** -- no successful historical traces to validate
  against.

## Reading the report

```
Self-Harness Report
============================================================
Flows analyzed: 3  |  Weaknesses: 5  |  Proposals: 3 (2 safe)

Weaknesses
------------------------------------------------------------
  1. [NodeFailure] Task 'deploy' failed 4 times (severity: 0.90)
  2. [RetryLoop] Back-edge 'review' -> 'fix' reached 5 iterations (severity: 0.83)
  3. [SlowToolCall] Tool 'web_fetch' averaged 12340ms (severity: 0.49)
  4. [ToolError] Tool 'file_read' in task 'analyze' returned errors 2 times (severity: 0.15)
  5. [TokenInefficiency] Task 'analyze' used 1000 prompt tokens for 20 completion tokens (severity: 0.08)

Proposals
------------------------------------------------------------
  SH-0000 [SAFE] FlowDagEdit: Add fallback specialist for task 'deploy'
  SH-0001 [REGRESSION] BackEdgeAdjust: Reduce back-edge iterations for 'review'
    Regression in 1 of 3 traces: review-pipeline-001
  SH-0002 [SAFE] ToolConfig: Add timeout guard for slow tool 'web_fetch'

2 proposal(s) validated as safe to apply.
```

**Safe proposals** (SH-0000, SH-0002 above) can be applied to flow
configuration. **Regression proposals** (SH-0001) should be reviewed
manually -- the regression means a previously-successful trace
relied on the behavior the proposal would remove.

## Applying proposals

Proposals describe changes but do not apply them automatically. To
apply a safe proposal, edit the flow YAML:

### BackEdgeAdjust

In your flow YAML, reduce `max_iterations` on the identified
back-edge:

```yaml
back_edges:
  - from: review
    to: fix
    max_iterations: 2  # was 5, reduced per SH-0001
```

### AddTimeout (ToolConfig)

Add a per-tool timeout in the permission set:

```toml
[permissions.dev]
tool_rules = [
  { tool = "web_fetch", policy = "allow", timeout_ms = 30000 },
]
```

### AddFallback (FlowDagEdit)

Add a recovery fallback in the flow definition:

```yaml
tasks:
  - id: deploy
    specialist: deployer
    fallback: general    # added per SH-0000
```

### RemoveNode (FlowDagEdit)

Remove or comment out the persistently skipped node and update
dependencies that referenced it.

## Configuration

Thresholds are tunable via CLI flags or the `MiningConfig` struct:

| Parameter | CLI flag | Default | Purpose |
|-----------|----------|---------|---------|
| `retry_threshold` | `--retry-threshold` | 3 | Back-edge iterations before flagging |
| `slow_tool_ms` | `--slow-tool-ms` | 10000 | Tool call duration (ms) threshold |
| `efficiency_ratio` | -- | 0.1 | Min completion/prompt token ratio |
| `min_occurrences` | -- | 1 | Minimum occurrences before reporting |

## Programmatic use

The self-harness engine is a library in `navra-flow`. Use it directly
for custom pipelines or integration into CI:

```rust,no_run
use navra_flow::event_log::EventLog;
use navra_flow::self_harness::{MiningConfig, run_self_harness};

let log = EventLog::open(Path::new("/path/to/flow_events.db")).unwrap();
let report = run_self_harness(&log, &["flow-001", "flow-002"], &MiningConfig::default());

for proposal in &report.proposals {
    println!("{}: {:?} — {}", proposal.id, proposal.kind, proposal.description);
}
```

## Design notes

Self-Harness is based on the pattern from arxiv 2606.09498, adapted
for gateway-level observability. The key insight: the gateway sees
every tool call, every failure, every retry across all agents. This
makes it the ideal vantage point for weakness mining -- no
instrumentation of individual agents is needed.

The original paper uses a stronger model as the weakness miner
(teacher-student pattern). In navra, the mining is purely
algorithmic (pattern matching on event traces), making it fast,
deterministic, and model-independent. A future extension could use
an LLM to generate more sophisticated proposals from the weakness
findings.
