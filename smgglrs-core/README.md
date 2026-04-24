# smgglrs-core

MCP gateway core: server, module trait, session management, and transport.

## Overview

Provides the server infrastructure that all smgglrs modules plug into.
Acts as a facade crate: downstream module crates depend only on
`smgglrs-core` and reach security, protocol, and model types through
its re-exports.

## Key types

- `McpServer` / `McpServerBuilder` -- HTTP server with MCP/SSE transport
- `Module` -- trait that all tool modules implement
- `UpstreamModule` -- wraps proxied MCP servers as modules
- `Session` -- per-connection session state
- `ToolHandler` / `PromptHandler` / `ResourceHandler` -- handler types

## Re-exports

- `smgglrs_protocol` as `protocol` (+ `upstream`)
- `smgglrs_model` as `models`
- `smgglrs_security` modules: `auth`, `permissions`, `hooks`,
  `safety`, `ifc`, `identity`, `credentials`, `quota`, `process`,
  `notify`

## Owned modules

- `transport` -- MCP Streamable HTTP + SSE transport
- `blackbox` -- tamper-evident audit log (BLAKE3 hash chain)
- `a2a` -- A2A protocol handler
- `session` -- session lifecycle

## Dependency layer

```
smgglrs-protocol + smgglrs-model + smgglrs-security
    |
smgglrs-core
    |
smgglrs-tools-* / smgglrs-rag / smgglrs-modal-* / smgglrs-memory
```

## Reference

See [DESIGN.md](../DESIGN.md) for the full server architecture,
module trait design, and transport protocol.
