+++
title = "CLI Reference"
description = "navra command-line interface — all subcommands and options."
weight = 45
template = "docs/section.html"

[extra]
toc = true
+++

## Usage

```bash
navra <COMMAND> [OPTIONS]
```

## Commands

### serve

Start the MCP gateway over Streamable HTTP.

```bash
navra serve [--config <path>] [--no-tray] [--dev-mode]
```

| Option | Description |
|--------|-------------|
| `-c, --config` | Path to config file (default: `~/.config/navra/config.toml`) |
| `--no-tray` | Disable system tray icon |
| `--dev-mode` | Enable anonymous access (development only) |

### stdio

Run as a stdio MCP server for direct client integration.

```bash
navra stdio [--config <path>]
```

Connects via stdin/stdout. Used by Claude Desktop, Cursor, and other
MCP clients that launch the server as a child process.

### token

Generate and manage agent capability tokens.

```bash
navra token generate --agent <name> --permissions <set> [--ttl <seconds>]
navra token inspect <token>
navra token revoke <token-id>
```

### audit

Query the gateway audit blackbox.

```bash
navra audit [--limit <N>] [--detail] [--agent <name>] [--tool <name>] [--verify]
```

| Option | Description |
|--------|-------------|
| `-l, --limit` | Number of entries to show (default: 20) |
| `-d, --detail` | Show full args and results |
| `--agent` | Filter by agent name |
| `--tool` | Filter by tool name |
| `--verify` | Verify hash chain integrity |

### approve / deny

Handle pending approval requests.

```bash
navra approve <request-id>
navra deny <request-id>
```

### status

Show gateway server status.

```bash
navra status
```

### schema

Print JSON Schema for config.toml.

```bash
navra schema > config-schema.json
```

### install / uninstall

Manage systemd user service.

```bash
navra install    # Install and enable systemd user units
navra uninstall  # Remove systemd user units
```

### agent

Manage agent bundles.

```bash
navra agent install <bundle-path>
navra agent inspect <bundle-path>
navra agent list
navra agent remove <name>
```

### model

Manage ONNX models.

```bash
navra model list
navra model pull <name>
navra model info <name>
```

### config

Configuration management.

```bash
navra config validate [--config <path>]
navra config list-libraries
```

`list-libraries` scans configured library directories and shows
each library file with the config keys it provides.
