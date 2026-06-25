+++
title = "Agent SDK"
description = "Build AI agents in Rust with navra-agent."
weight = 30
template = "docs/section.html"

[extra]
toc = true
+++

navra-agent is a Rust SDK for building AI agents that connect to MCP
servers through the navra gateway. It provides a ReAct tool-use loop,
IFC taint tracking, model backend abstraction, and trace export — all
in a single crate with a builder API.

## Quick start

```rust
use navra_agent::{Agent, OpenAiBackend, Locality};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let model = OpenAiBackend::new(
        "http://localhost:11434/v1",  // Ollama
        "granite3.3:8b",
        None,
        Locality::Local,
    );

    let mut agent = Agent::builder()
        .endpoint("http://localhost:9315/mcp")
        .await?
        .model(model)
        .system_prompt("You are a helpful assistant.")
        .auth_token("mcd_your_token_here")
        .max_iterations(20)
        .build().await?;

    let result = agent.run("List the files in the current directory").await?;
    println!("{}", result.response);
    Ok(())
}
```

## Model backends

navra-agent supports any model through four backends:

| Backend | Use case | Example |
|---------|----------|---------|
| `OpenAiBackend` | Any OpenAI-compatible API | Ollama, vLLM, Mistral, OpenRouter, Together, Groq |
| `AnthropicBackend` | Claude models | Anthropic API directly |
| `OgxBackend` | OGX / Llama Stack | Red Hat AI inference servers |
| `CliBackend` | Any CLI command | Pipe prompt to a local binary |

All backends implement the `ModelBackend` trait, so agents are
model-agnostic. Switch from Ollama to Mistral API by changing one
line:

```rust
// Ollama (local)
let model = OpenAiBackend::new(
    "http://localhost:11434/v1", "granite3.3:8b",
    None, Locality::Local,
);

// Mistral API (remote)
let model = OpenAiBackend::new(
    "https://api.mistral.ai/v1", "mistral-large-latest",
    Some("your-api-key".into()), Locality::Remote,
);

// Claude (remote)
let model = AnthropicBackend::new(
    "your-api-key", "claude-sonnet-4-5",
);
```

## Builder API

`Agent::builder()` returns an `AgentBuilder` with fluent configuration:

```rust
let mut agent = Agent::builder()
    // Connection
    .endpoint("http://localhost:9315/mcp").await?
    .auth_token("mcd_...")

    // Model
    .model(backend)
    .system_prompt("You are a security auditor.")
    .temperature(0.0)
    .max_tokens(4096)

    // Limits
    .max_iterations(50)

    // Tool filtering
    .allowed_tools(vec!["file_read", "file_tree", "git_log"])

    // Identity (for signed requests)
    .identity(signer)

    // Hooks
    .hook_pipeline(pipeline)

    // Audit
    .audit_sink(sink)

    .build().await?;
```

## Running an agent

Call `agent.run(prompt)` to execute the ReAct loop. The agent
calls tools, processes results, and iterates until it has an
answer or hits the iteration limit:

```rust
let result = agent.run("Find security vulnerabilities in src/").await?;

// Result fields
println!("Response: {}", result.response);
println!("Iterations: {}", result.iterations);
println!("Tokens: {} in / {} out", result.input_tokens, result.output_tokens);

// Tool calls made
for block in &result.blocks {
    println!("  {} → {:?} ({:?})",
        block.tool_name, block.status, block.duration);
}
```

## IFC taint tracking

navra enforces Information Flow Control at the gateway level. When
an agent reads sensitive data, its session becomes tainted. Tainted
sessions cannot write to lower-classification outputs — preventing
data exfiltration even if the model is compromised.

The agent SDK tracks taint automatically through `TaintTracker`:

```rust
use navra_agent::TaintTracker;

// Taint is accumulated per-session — you don't manage it manually.
// The gateway enforces the policy (deny/approve/allow) based on
// the permission set configured for the agent.
```

This is navra's primary differentiator: security is enforced at the
gateway, not by trusting the model to follow instructions.

## Tool filtering

Restrict which MCP tools an agent can call:

```rust
agent.builder()
    .allowed_tools(vec![
        "file_read",
        "file_tree",
        "git_status",
        "git_log",
        // file_write, exec_run, etc. are blocked
    ])
```

Combined with domain rules in the gateway config, this creates
defense in depth: the agent can only request allowed tools, and the
gateway independently enforces which tools each permission set allows.

## Trace export

Agent runs can be exported as Hermes-format JSONL for fine-tuning
or audit:

```rust
use navra_agent::{TraceRecord, TraceMetadata};

// After a run, the trace is automatically written if
// ToolLoopConfig.trace_export_dir is set.
// Each trace includes: system prompt, all messages,
// tool schemas, metadata (model, tokens, success).
```

## Signals

Agents support cooperative signal delivery for graceful control:

```rust
use navra_agent::{SignalHandle, AgentSignal};

let handle = agent.signal_handle();

// From another task:
handle.send(AgentSignal::Pause);   // pause the loop
handle.send(AgentSignal::Resume);  // resume
handle.send(AgentSignal::Stop);    // graceful stop
```

## Hibernation

Save and restore agent state for long-running tasks:

```rust
use navra_agent::hibernate::ConversationSnapshot;

// Snapshot captures: system_prompt, conversation history,
// iteration count, token counts, model name, taint label.
// Restore from snapshot to continue where the agent left off.
```

## Deterministic replay

For repetitive tasks, replay a recorded tool-loop trace without
calling the model:

```rust
use navra_agent::replay;

// Record a trace, then replay it deterministically.
// Useful for testing, CI, and cost reduction on repeated tasks.
```

## Multi-agent flows

For orchestrating multiple agents, see navra-flow which provides
DAG execution and handoff routing. Flows are defined in YAML:

```yaml
kind: dag
name: research
tasks:
  - id: search
    specialist: researcher
    mandate: "Search for information about..."
  - id: verify
    specialist: devils_advocate
    depends_on: [search]
    mandate: "Verify the claims..."
  - id: synthesize
    specialist: summarizer
    depends_on: [verify]
    mandate: "Produce a cited report..."
```

See [examples/flows/](https://github.com/smgglrs-ai/navra/tree/main/examples/flows)
for ready-to-run flow definitions.

## Agent bundles

Package agents as OCI artifacts for distribution:

```bash
navra agent install oci://quay.io/navra/researcher:latest
navra agent inspect oci://quay.io/navra/code-reviewer:latest
navra agent list
```

Bundles include persona, permissions, and upstream MCP server
configuration. See [examples/agent-bundles/](https://github.com/smgglrs-ai/navra/tree/main/examples/agent-bundles).

## Standalone binary example

See [examples/standalone-agent/](https://github.com/smgglrs-ai/navra/tree/main/examples/standalone-agent)
for a complete CLI agent binary using the SDK.

## Why Rust?

navra-agent is the only Rust agent SDK with:

- **Gateway-enforced IFC** — security at the infrastructure layer, not the prompt layer
- **In-process ONNX models** — PII detection, embeddings, safety classification without external services
- **Single-binary agents** — deploy as a static binary or distroless container (<20MB)
- **Deterministic replay** — reproduce tool-loop executions exactly
- **Multi-agent flows** — DAG and handoff orchestration built in
- **Typed actions** — 18 classified action types with risk levels for audit

Python SDKs (LangChain, OpenAI Agents, Claude Agent SDK) operate at
the application layer. navra operates at the infrastructure layer —
the gateway enforces security regardless of what the agent code or
model does.
