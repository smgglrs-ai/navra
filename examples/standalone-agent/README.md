# Standalone Agent Example

A CLI binary that runs a single task through a navra MCP gateway using the
`navra-agent` SDK.

## What it does

1. Connects to an MCP server (navra gateway or any MCP-compatible server)
2. Discovers available tools
3. Sends the user's prompt through the ReAct tool-use loop
4. Prints the agent's response and a run summary (iterations, tokens, tool calls)

## Prerequisites

- **navra** running locally: `navra serve`
- **Ollama** with a model pulled: `ollama pull granite3.3:8b`
- **ONNX Runtime** installed (Fedora: `dnf install onnxruntime-devel`)

## Usage

```sh
# Basic usage with Ollama (default)
cargo run -- --prompt "List files in the current directory"

# Specify a different model
cargo run -- --model "qwen2.5:7b" --prompt "What is the git status?"

# Limit to specific tools
cargo run -- --allowed-tools "file_read,file_list" \
  --prompt "Read the contents of Cargo.toml"

# Set max iterations
cargo run -- --max-iterations 5 --prompt "Find all TODO comments"
```

## Using different model backends

### Ollama (default, local)

```sh
cargo run -- \
  --model-url "http://localhost:11434/v1" \
  --model "granite3.3:8b" \
  --prompt "Summarize the project structure"
```

### Mistral API (remote)

```sh
export MODEL_API_KEY="your-mistral-key"
cargo run -- \
  --model-url "https://api.mistral.ai/v1" \
  --model "mistral-small-latest" \
  --prompt "Review the code in src/main.rs"
```

### Anthropic (via navra-model AnthropicBackend)

The example uses `OpenAiBackend` which works with any OpenAI-compatible API.
For native Anthropic support, modify `main.rs` to use `AnthropicBackend`:

```rust
use navra_agent::{AnthropicBackend, Locality};

let model = AnthropicBackend::new(
    "https://api.anthropic.com",
    "claude-sonnet-4-20250514",
    Some(api_key),
    Locality::Remote,
);
```

## Key SDK concepts

- **`Agent::builder()`** -- fluent builder for configuring endpoint, model,
  system prompt, iteration limits, tool filtering, and more.
- **`OpenAiBackend` / `AnthropicBackend`** -- model inference backends that
  translate to Chat Completions or Messages API internally. The `Locality`
  flag controls PII filtering for remote APIs.
- **`agent.run(prompt)`** -- enters the ReAct loop and returns a
  `ToolLoopResult` with the response, token usage, iteration count, and
  structured tool call blocks.
- **`ToolLoopResult`** -- contains `response` (final text), `iterations`,
  `input_tokens`, `output_tokens`, `blocks` (tool call details), and
  `interrupted` (whether a signal stopped the run).
- **`allowed_tools`** -- restricts which MCP tools the agent can see and
  call, useful for sandboxing.
- **`SignalHandle`** -- cooperative signal delivery (Interrupt, Pause,
  Resume, Terminate) for external control of running agents.

## API reference

See the `navra-agent` rustdoc for the full API:

```sh
cargo doc -p navra-agent --open
```
