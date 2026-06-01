# navra-core

MCP gateway core: server, module trait, session management, and transport.

## Overview

Provides the server infrastructure that all navra modules plug into.
Acts as a facade crate: downstream module crates depend only on
`navra-core` and reach security, protocol, and model types through
its re-exports.

## Key types

- `McpServer` / `McpServerBuilder` -- HTTP server with MCP/SSE/WebSocket transport
- `Module` -- trait that all tool modules implement
- `UpstreamModule` -- wraps proxied MCP servers as modules (with tool scanning)
- `Session` -- per-connection session state
- `ToolHandler` / `PromptHandler` / `ResourceHandler` -- handler types
- `Metrics` -- Prometheus text format counters (tool calls, safety, IFC, scanning)
- Kernel resources: `navra://proc`, `navra://ifc/labels`, etc.

## Re-exports

- `navra_protocol` as `protocol` (+ `upstream`)
- `navra_model` as `models`
- `navra_security` modules: `auth`, `permissions`, `hooks`,
  `safety`, `ifc`, `identity`, `credentials`, `quota`, `process`,
  `notify`

## Owned modules

- `transport` -- MCP Streamable HTTP + SSE transport
- `blackbox` -- tamper-evident audit log (BLAKE3 hash chain)
- `a2a` -- A2A protocol handler
- `session` -- session lifecycle

## Dependency layer

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
