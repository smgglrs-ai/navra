# Quickstart

Get navra running in under 5 minutes.

## Prerequisites

- **Rust** stable 1.75+
- **Linux** with systemd and D-Bus (for notifications and tray)

## Build

```bash
git clone https://github.com/smgglrs-ai/navra.git
cd navra
cargo build
```

## Start the Gateway

```bash
cargo run -- serve
```

navra starts listening on a Unix socket at
`~/.run/navra/navra.sock` (or `/run/user/$UID/navra.sock`).

## Generate a Token

```bash
cargo run -- token generate --name claude --permissions readwrite
```

This prints an `[[agents]]` block. Add it to
`~/.config/navra/config.toml`:

```toml
[[agents]]
name = "claude"
token_hash = "b3a1..."
permissions = "dev"

[permissions.dev]
allow = ["file_*", "git_*"]
deny = ["exec_run"]
safety = "standard"
```

## Connect Your Agent

Point your MCP client at the Unix socket. For Claude Code, add
navra as an MCP server in your settings:

```json
{
  "mcpServers": {
    "navra": {
      "command": "socat",
      "args": ["STDIO", "UNIX-CONNECT:~/.run/navra/navra.sock"],
      "env": {
        "NAVRA_TOKEN": "your-token-here"
      }
    }
  }
}
```

## Run the Tests

```bash
cargo test --workspace
```

All 2400+ tests should pass. See [Testing](./testing.md) for
e2e test prerequisites.

## Next Steps

- [Configuration Reference](./configuration.md) — every config option
- [Why navra?](./why-navra.md) — what makes navra different
- [Integration Guide](./integration-guide.md) — detailed setup for
  various MCP clients
