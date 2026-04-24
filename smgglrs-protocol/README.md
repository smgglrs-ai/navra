# smgglrs-protocol

Wire types for MCP, A2A, and JSON-RPC protocols.

## Overview

This crate provides serializable request/response types for all
protocols that the smgglrs gateway speaks. It has no smgglrs
dependencies and sits at the bottom of the dependency graph.

## Key types

- **MCP** -- `ToolDefinition`, `CallToolParams`, `CallToolResult`,
  `PromptDefinition`, `ResourceDefinition`, capability negotiation
- **JSON-RPC 2.0** -- `JsonRpcRequest`, `JsonRpcResponse`,
  `JsonRpcError`, `BatchRequest`, standard error codes
- **A2A** -- `AgentCard`, `Task`, `Message`, agent-to-agent protocol
- **IFC labels** -- `DataLabel` with `Integrity` and `Confidentiality`
  levels (in the `label` module)
- **Upstream** -- `Upstream` config for proxied MCP servers,
  `RetryConfig` for backoff

## Dependency layer

```
smgglrs-protocol  (no smgglrs deps -- leaf crate)
```

All other smgglrs crates depend on this crate either directly or
through `smgglrs-core` re-exports.

## Usage

```rust
use smgglrs_protocol::{ToolDefinition, CallToolResult, JsonRpcRequest};
use smgglrs_protocol::label::DataLabel;
use smgglrs_protocol::a2a::AgentCard;
```

## Reference

See [DESIGN.md](../DESIGN.md) for the full architecture and protocol
specification.
