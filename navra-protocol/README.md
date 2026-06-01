# navra-protocol

Wire types for MCP, A2A, and JSON-RPC protocols.

## Overview

This crate provides serializable request/response types for all
protocols that the navra gateway speaks. It has no navra
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
navra-protocol  (no navra deps -- leaf crate)
```

All other navra crates depend on this crate either directly or
through `navra-core` re-exports.

## Usage

```rust
use navra_protocol::{ToolDefinition, CallToolResult, JsonRpcRequest};
use navra_protocol::label::DataLabel;
use navra_protocol::a2a::AgentCard;
```

## Reference

See [DESIGN.md](../DESIGN.md) for the full architecture and protocol
specification.
