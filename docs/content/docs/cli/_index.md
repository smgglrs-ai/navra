+++
title = "CLI Reference"
description = "navra command-line interface — all subcommands and options."
weight = 25
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

Manage agent bundles and instances.

```bash
navra agent install <path-or-oci-ref> [--allow-unsigned] [--max-permissions <set>]
navra agent init <bundle> [--name <instance>]
navra agent upgrade <bundle> [--allow-unsigned]
navra agent inspect <oci-ref>
navra agent list
navra agent remove <name>
```

| Subcommand | Description |
|------------|-------------|
| `install` | Install an agent bundle from a local directory or OCI registry (e.g., `oci://quay.io/navra/agent:v1`) |
| `init` | Initialize an instance from an installed bundle — generates config, wires credentials |
| `upgrade` | Upgrade an installed bundle to a new version, shows permission diff |
| `inspect` | Inspect an agent bundle without installing |
| `list` | List installed agent bundles and instances |
| `remove` | Remove an installed agent bundle |

| Option | Applies to | Description |
|--------|-----------|-------------|
| `--allow-unsigned` | `install`, `upgrade` | Skip signature verification |
| `--max-permissions <set>` | `install` | Permission set to check against (uses its rules as max allowed) |
| `--name <instance>` | `init` | Instance name (defaults to bundle name) |

### model

Manage models (ONNX and hub-cached).

```bash
navra model serve [--config <path>] [--bind <addr>] [--auto] [--budget <size>]
navra model list
navra model pull <name-or-uri>
navra model available
```

| Subcommand | Description |
|------------|-------------|
| `serve` | Start a standalone model inference server |
| `list` | List installed models (ONNX and hub-cached) |
| `pull` | Download a model by name (from registry) or URI (`ollama://`, `hf://`, `oci://`, `file://`) |
| `available` | Show models available for download from the registry |

| Option | Applies to | Description |
|--------|-----------|-------------|
| `-c, --config` | `serve` | Path to config file |
| `-b, --bind` | `serve` | Bind address (default: `127.0.0.1:9316`) |
| `--auto` | `serve` | Auto-detect hardware and propose resource allocation |
| `--budget` | `serve` | Maximum VRAM budget (e.g., `24GB`, `16GB`) |

### run

Run an agent task or named workflow against a running navra instance.

```bash
navra run <prompt> [OPTIONS]
navra run <prompt> --workflow <instance/workflow>
navra run <prompt> --file <path>
```

| Option | Description |
|--------|-------------|
| `-m, --model` | Model to use (default: auto-detect from Ollama). When the model's GGUF blob exists in Ollama's local store and the `embedded` feature is compiled in, loads the model in-process via llama.cpp — no Ollama server needed. Falls back to Ollama API otherwise. |
| `--no-embedded` | Force Ollama API even when a local GGUF blob exists |
| `-p, --persona` | Persona to use (default: `leader`) |
| `-e, --endpoint` | navra endpoint URL (default: `http://127.0.0.1:9315/mcp`) |
| `-t, --token` | Auth token (reads `MCPD_TOKEN` env if not set) |
| `-n, --max-iterations` | Max iterations (default: 200) |
| `--workflow` | Run a named workflow from an agent instance (e.g., `work-assistant/day-planner`) |
| `--file` | Path to a standalone workflow file (for development) |
| `--config` | Path to agent instance config (overrides default resolution) |
| `--upstream-prompt` | Inject an upstream MCP prompt (repeatable, format: `upstream:prompt_name`) |
| `--dry-run` | Preview the constructed prompt without executing |

Example — run a named workflow:

```bash
navra run "plan my day" --workflow work-assistant/day-planner
```

### config

Configuration management.

```bash
navra config validate [--config <path>]
navra config list-libraries
```

`list-libraries` scans configured library directories and shows
each library file with the config keys it provides.
