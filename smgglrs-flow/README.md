# smgglrs-flow

Declarative multi-agent flow engine with handoff-based routing.

## Overview

Two execution modes for orchestrating multiple agents:

- **Handoff flows** -- directed graph of agents with model-driven
  routing and back-edges
- **DAG execution** -- parallel task graphs with dependency resolution

Also supports iterative refinement loops, mesh communication
(mailbox, blackboard), and mandate validation.

## Key types

- `Flow` / `FlowBuilder` / `FlowResult` -- define and run flows
- `FlowDefinition` / `FlowConfig` / `NodeDefinition` -- declarative
  flow configuration (TOML/YAML)
- `DagExecutor` / `DependencyGraph` / `DagResult` -- parallel DAG
  execution
- `IterativeExecutor` / `IterativeConfig` -- refinement loops
- `MailboxRegistry` / `Blackboard` -- inter-agent communication
- `BackEdgeTracker` / `ConditionalEdge` -- cycle handling
- `validate_mandate` -- output validation against requirements
- `classify_failure` / `RecoveryStrategy` -- error recovery

## Usage

```rust
use smgglrs_flow::Flow;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let toml = std::fs::read_to_string("flow.toml")?;
    let mut flow = Flow::from_toml(&toml).await?;
    let result = flow.run("Analyze the codebase").await?;
    println!("{}", result.response);
    Ok(())
}
```

## Dependency layer

```
smgglrs-agent (+ protocol, model, security, cognitive)
    |
smgglrs-flow
```

## Reference

See [DESIGN.md](../DESIGN.md) for the flow engine architecture,
handoff routing, and DAG execution model.
