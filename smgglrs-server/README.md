# smgglrs-server

CLI binary and module wiring for the smgglrs MCP gateway.

## Overview

The `smgglrs` binary that ties the entire workspace together. Loads
configuration, initializes all enabled modules, wires up the security
layer, and starts the MCP server. Also provides CLI commands for
token management, model operations, and agent flows.

## Binary: `smgglrs`

```bash
# Start the gateway
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo run -- serve

# Generate an auth token
cargo run -- token generate --name my-agent --permissions full

# Run a model operation
cargo run -- model pull ollama://granite-code:3b
```

## Internal modules

| Module | Purpose |
|---|---|
| `cli` | Clap CLI definition (serve, token, model commands) |
| `config` | TOML configuration loading and defaults |
| `discover` | Agent/tool discovery (mDNS, registries) |
| `flow_tools` | Flow engine tools exposed via MCP |
| `memory_tools` | Memory tools exposed via MCP |
| `team_tools` | Multi-agent team tools |
| `tray` | System tray icon (ksni) |
| `mdns` | mDNS service advertisement |
| `ui` | TUI / interactive elements |
| `demo` | Demo mode for testing |

## Dependency layer

```
All smgglrs-* crates
    |
smgglrs-server  (top of the dependency graph)
```

## Configuration

Default path: `~/.config/smgglrs/config.toml`

## Reference

See [DESIGN.md](../DESIGN.md) for the full configuration reference
and server architecture.
