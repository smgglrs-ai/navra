# navra-agent

Client SDK for building AI agents that connect to MCP servers.

## Overview

Provides a high-level `Agent` with a builder pattern, an MCP client
with IFC taint tracking, a tool-use loop implementing the ReAct
pattern, and deterministic replay for repetitive tasks. Supports
cooperative signal delivery (interrupt/terminate/pause/resume) and
typed action classification with risk levels. External consumers
depend only on this crate and reach protocol/model/security types
through its re-exports.

## Standalone Binary

The crate includes a standalone `navra-agent` binary
(`src/bin/agent.rs`) for containerized execution. It reads
configuration from environment variables and runs a single agent
task, printing the result as JSON.

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `NAVRA_ENDPOINT` | yes | Gateway MCP URL |
| `NAVRA_TOKEN` | no | Scoped capability token |
| `NAVRA_MODEL_ENDPOINT` | yes | Model server OpenAI-compat URL |
| `NAVRA_MODEL_NAME` | yes | Model name (e.g. `granite3.3:8b`) |
| `NAVRA_PERSONA` | no | Persona name (loads from cognitive core) |
| `NAVRA_TASK` | yes | Prompt/mandate to execute |
| `NAVRA_MAX_ITERATIONS` | no | Iteration cap (default 30) |
| `NAVRA_COGNITIVE_CORE` | no | Path to cognitive_core directory |

### Container Usage

Build the container image using `Dockerfile.agent` at the workspace
root:

```bash
podman build -f Dockerfile.agent -t navra-agent:latest .
```

Run an agent in a container:

```bash
podman run --rm \
  --network=slirp4netns:allow_host_loopback=true \
  -e NAVRA_ENDPOINT=http://10.0.2.2:9400/mcp \
  -e NAVRA_MODEL_ENDPOINT=http://10.0.2.2:8091/v1 \
  -e NAVRA_MODEL_NAME=granite3.3:8b \
  -e NAVRA_TASK="Summarize the project status" \
  navra-agent:latest
```

The container uses `slirp4netns:allow_host_loopback=true` to reach
the host-bound model server and gateway via `10.0.2.2`.

### Architecture

In containerized mode, the navra-server orchestrates:

- **Model server** (1 container): `llama-server` with GPU
  passthrough. Shared by all agents.
- **Agent sandboxes** (N containers): `navra-agent` binary,
  no GPU access. Connect to the model server for inference and
  to the gateway for MCP tools.

The `[budget]` config in `config.toml` controls this:

```toml
[budget]
containerized = true
max_parallel = 2
model_server_image = "docker.io/vllm/vllm-openai:latest"
agent_image = "navra-agent:latest"
```

When Podman is unavailable or `containerized` is not set, agents
run in-process within the navra-server.

## Key types

- `Agent` / `AgentBuilder` -- configure and run an agent
- `McpClient` -- MCP client with IFC taint tracking
- `run_tool_loop` / `ToolLoopConfig` / `ToolLoopResult` -- ReAct
  tool-use loop
- Re-exports from `navra-protocol`, `navra-model`, and
  `navra-security` for SDK ergonomics

## Library Usage

```rust
use navra_agent::{Agent, OpenAiBackend, Locality};

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
navra-protocol + navra-model + navra-security + navra-cognitive
    |
navra-agent
```

## Reference

See [DESIGN.md](../DESIGN.md) for the agent SDK architecture,
tool-use loop design, and containerized agent execution.
