# smgglrs-agent

Client SDK for building AI agents that connect to MCP servers.

## Overview

Provides a high-level `Agent` with a builder pattern, an MCP client
with IFC taint tracking, and a tool-use loop implementing the ReAct
pattern. External consumers depend only on this crate and reach
protocol/model/security types through its re-exports.

## Key types

- `Agent` / `AgentBuilder` -- configure and run an agent
- `McpClient` -- MCP client with IFC taint tracking
- `run_tool_loop` / `ToolLoopConfig` / `ToolLoopResult` -- ReAct
  tool-use loop
- Re-exports from `smgglrs-protocol`, `smgglrs-model`, and
  `smgglrs-security` for SDK ergonomics

## Usage

```rust
use smgglrs_agent::{Agent, OpenAiBackend, Locality};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let model = OpenAiBackend::new(
        "http://localhost:11434/v1", "granite3.3:8b", None, Locality::Local,
    );
    let mut agent = Agent::builder()
        .endpoint("http://localhost:3000/mcp").await?
        .model(model)
        .system_prompt("You are a helpful assistant.")
        .build()?;
    let result = agent.run("List the git status").await?;
    println!("{}", result.response);
    Ok(())
}
```

## Dependency layer

```
smgglrs-protocol + smgglrs-model + smgglrs-security + smgglrs-cognitive
    |
smgglrs-agent
```

## Reference

See [DESIGN.md](../DESIGN.md) for the agent SDK architecture and
tool-use loop design.
