# navra-core

MCP gateway core: server, module trait, session management, and
transport.

## Overview

Provides the server infrastructure that all navra modules plug into.
Acts as a facade crate: downstream module crates depend only on
`navra-core` and reach security, protocol, and model types through
its re-exports.

## Usage

Build a server with modules:

```rust
use navra_core::{McpServer, Module};
use std::time::Duration;

let server = McpServer::builder()
    .name("navra")
    .version("0.1.0")
    .mcp_version("2026-07-28")
    .hook_timeout(Duration::from_secs(60))
    .build();

// Register modules
let mut builder = server.builder();
builder = builder.module(file_module);
builder = builder.module(git_module);

// Start serving on a Unix socket
server.serve_unix("/run/user/1000/navra.sock").await?;
```

## Key Types

| Type | Description |
|---|---|
| `McpServer` / `McpServerBuilder` | HTTP server with MCP Streamable HTTP + SSE transport |
| `Module` | Trait that all tool modules implement: `tools()`, `resources()`, `prompts()` |
| `UpstreamModule` | Wraps proxied MCP servers as modules with safety filtering and tool scanning |
| `Session` | Per-connection session state (agent identity, taint tracker, approval cache) |
| `ToolHandler` | `Arc<dyn Fn(Value, CallContext) -> Pin<Box<dyn Future<Output = CallToolResult>>>>` |
| `PromptHandler` / `ResourceHandler` | Similar handler types for MCP prompts and resources |
| `Metrics` | Prometheus text-format counters: tool calls, safety blocks, IFC violations, scanning |
| `GrpcModule` | Out-of-process module connected via gRPC |

## The Module Trait

Every capability in navra implements `Module`:

```rust
pub trait Module: Send + Sync {
    fn name(&self) -> &str;
    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)>;
    fn resources(&self) -> Vec<(Resource, ResourceHandler)> { vec![] }
    fn prompts(&self) -> Vec<(Prompt, PromptHandler)> { vec![] }
}
```

Built-in modules: `FileModule`, `GitModule`, `ExecModule`,
`RagModule`, `VoiceModule`, `VisionModule`, `GithubModule`,
`GitlabModule`, `MemoryModule`, `RegistryModule`.

## Re-exports

- `navra_protocol` as `protocol` (+ `upstream`)
- `navra_model` as `models`
- `navra_security` modules: `auth`, `permissions`, `hooks`,
  `safety`, `ifc`, `identity`, `credentials`, `quota`, `process`,
  `notify`

## Owned Modules

- `transport` -- MCP Streamable HTTP + SSE transport
- `blackbox` -- tamper-evident audit log (BLAKE3 hash chain)
- `a2a` -- A2A protocol handler
- `acp` -- Agent Communication Protocol dispatcher
- `session` -- session lifecycle
- `metrics` -- Prometheus `/metrics` endpoint

Kernel resources are exposed as MCP resources: `navra://proc`,
`navra://ifc/labels`, `navra://audit/tail`.

## Dependency Layer

```
navra-protocol + navra-model + navra-security
    |
navra-core
    |
navra-tools-* / navra-rag / navra-modal-* / navra-memory
```

## Reference

See [DESIGN.md](../DESIGN.md) for the full server architecture,
module trait design, and transport protocol.
