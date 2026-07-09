+++
title = "BPMN Workflows"
weight = 26
template = "docs/page.html"

[extra]
toc = true
+++

navra can import BPMN 2.0 process definitions and execute them as
multi-agent workflows. Business analysts design processes in standard
BPMN editors; navra compiles them to its DAG execution engine with
full IFC enforcement.

## Macro/Micro architecture

BPMN operates at the **macro** level — process lifecycle, routing,
human approval gates, and auditing. Each BPMN service task triggers
a navra agent that operates at the **micro** level — running its
reasoning loop with MCP tool access. The agent completes its work
and returns a structured result to the parent process.

## Supported BPMN elements

| BPMN Element | navra Behavior |
|---|---|
| `<startEvent>` | Entry point — tasks with no dependencies |
| `<endEvent>` | Terminal — no downstream tasks |
| `<serviceTask>` | Agent invocation — specialist name from task type or name |
| `<userTask>` | Human-in-the-loop — pauses execution, waits for approval |
| `<exclusiveGateway>` | Conditional routing — downstream tasks depend on the pre-gateway task |
| `<parallelGateway>` | Fork/join — tasks after fork run in parallel, join waits for all |
| `<sequenceFlow>` | Dependency edges between tasks |

## How it works

navra compiles BPMN to its DAG execution model:

1. **Parse**: BPMN XML is parsed into an AST (process, nodes, flows).
2. **Compile**: The AST is compiled into a `DagConfig` — service tasks
   become `TaskDefinition` entries, gateways become dependency edges.
3. **Execute**: The `DagExecutor` runs tasks in dependency order,
   dispatching each to a specialist agent.

Gateways are transparent to the DAG — they are resolved into
dependency edges. A parallel gateway fork creates tasks that share
the same predecessor; a parallel gateway join creates a task that
depends on all fork branches.

## Service task mapping

The specialist name for a service task is determined by:

1. The `type` attribute in a `<taskDefinition>` extension element
   (Camunda-compatible)
2. The `name` attribute of the `<serviceTask>` element
3. Fallback: `"default"`

```xml
<serviceTask id="analyze" name="Analyze code">
  <extensionElements>
    <taskDefinition type="code_analyst"/>
  </extensionElements>
</serviceTask>
```

This creates a task with `specialist = "code_analyst"` and
`mandate = "Analyze code"`.

## Human-in-the-loop (UserTask)

A `<userTask>` compiles to a task with `approval_required = true`.
When the DAG executor reaches this task, it checkpoints state and
pauses execution until external approval is received.

```xml
<userTask id="review" name="Human review"/>
```

## Example workflow

The `examples/workflows/document-review.bpmn` file demonstrates a
complete workflow:

```
Start → Draft document → Human review → Decision gateway
  → [approved] Publish → End
  → [rejected] Revise → Human review (loop)
```

## Loading BPMN workflows

Place `.bpmn` files in your flows directory. navra detects the file
extension and uses the BPMN parser instead of the YAML loader.

You can also load BPMN programmatically:

```rust,no_run
use navra_flow::load_bpmn_file;

let dag = load_bpmn_file("workflows/document-review.bpmn")?;
// dag is a DagConfig ready for DagExecutor
```

## Authoring tools

Any BPMN 2.0 editor works:

- [Camunda Modeler](https://camunda.com/download/modeler/) (desktop, free)
- [bpmn.io](https://demo.bpmn.io/) (web, free)
- [Trisotech](https://www.trisotech.com/) (web, commercial)
- [Signavio](https://www.signavio.com/) (web, commercial)

Export as `.bpmn` (BPMN 2.0 XML) and place in navra's flows
directory.

## Live visualization

Running workflows can be visualized in real time via the flow graph
API. navra provides three output formats:

### JSON graph (React Flow)

```
GET /flows/{id}/graph
```

Returns nodes with status (pending/running/done/failed) and dependency
edges. Consumed by the built-in React Flow UI.

### BPMN XML

```
GET /flows/{id}/graph/bpmn
```

Returns BPMN 2.0 XML with navra-specific status extensions on each
node. Open in any BPMN viewer (bpmn.io, Camunda Modeler) to see the
workflow with highlighted active and completed paths.

Works for all workflows, including those not originally authored in
BPMN — navra generates BPMN XML from the DAG structure.

### Graphviz DOT

```
GET /flows/{id}/graph/dot
```

Returns a DOT-format graph with status-colored nodes. Render with
`dot -Tsvg` for static audit reports.

### SSE event stream

```
GET /flows/{id}/events
```

Server-sent events stream of `FlowEvent` (node started, completed,
failed, skipped, back-edge activated, flow completed). Supports
`Last-Event-ID` header for reconnection with backfill.

## Combining with DMN guardrails

BPMN workflows and DMN guardrails work together. The BPMN process
defines *what* agents do and in what order; DMN decision tables
define *what agents are allowed to do* — input sanitization and
output validation at each step. See the
[DMN guardrails guide]({{< relref "/docs/guides/dmn-guardrails" >}}).
