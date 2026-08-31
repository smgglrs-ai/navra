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

---

## navra mcp

MCP gateway server commands.

### navra mcp serve

Start the MCP gateway server over Streamable HTTP.

```bash
navra mcp serve [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to config file (default: `~/.config/navra/config.toml`) |
| `--no-tray` | Disable system tray icon |
| `--dev-mode` | Enable anonymous access (dev only -- do not use in production) |

### navra mcp stdio

Run as a stdio MCP server for direct client integration (Claude Desktop, Cursor, etc.).

```bash
navra mcp stdio [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to config file |

---

## navra init

Interactive first-time setup. Generates a config file tuned to your hardware, project type, and safety preferences.

```bash
navra init [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--quiet` | Skip interactive prompts, use defaults and flags |
| `--agent-name <name>` | Agent name (default: auto-detect) |
| `--safety <level>` | Safety level: `standard`, `strict`, `minimal` (default: `standard`) |
| `--project <type>` | Project type: `dev`, `data`, `ops`, `custom` (default: `dev`) |
| `--model <backend>` | Model backend: `ollama`, `mistral`, `anthropic`, `openai-compat`, `none` (default: `none`) |
| `--model-url <url>` | Base URL for `openai-compat` backend |
| `--api-key <key>` | API key for model backend |
| `--allow <globs>` | Allowed directories (comma-separated globs) |
| `--install-service` | Install systemd user service |
| `--dry-run` | Output config to stdout instead of writing to file |
| `-o, --output <path>` | Config output path |
| `--profile <type>` | Hardware profile: `auto`, `desktop`, `laptop`, `headless`. Generates a config optimized for the detected (or specified) hardware. Overrides `--model`/`--safety`/`--project` flags with profile-tuned defaults |

---

## navra token

Generate and manage agent capability tokens.

### navra token generate

```bash
navra token generate --name <name> --permissions <set>
```

| Option | Description |
|--------|-------------|
| `-n, --name <name>` | Agent name |
| `-p, --permissions <set>` | Permission set name |

### navra token list

List registered agents.

```bash
navra token list
```

---

## navra approve / deny

Handle pending approval requests.

```bash
navra approve <id>
navra deny <id>
```

| Argument | Description |
|----------|-------------|
| `<id>` | Request ID to approve or deny |

---

## navra status

Show gateway server status.

```bash
navra status
```

---

## navra schema

Print JSON Schema for config.toml.

```bash
navra schema > config-schema.json
```

---

## navra install / uninstall

Manage the systemd user service.

```bash
navra install    # Install and enable systemd user units
navra uninstall  # Remove systemd user units
```

---

## navra agent

Manage agent bundles and instances.

### navra agent install

Install an agent bundle from an OCI registry or local directory.

```bash
navra agent install <oci-ref> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `<oci-ref>` | OCI reference (e.g., `oci://quay.io/navra/agent:v1`) or local directory path |
| `--allow-unsigned` | Skip signature verification for this install |
| `--max-permissions <set>` | Permission set to check against (uses its rules as max allowed) |

### navra agent inspect

Inspect an agent bundle without installing.

```bash
navra agent inspect <oci-ref>
```

### navra agent init

Initialize an agent instance from an installed bundle.

```bash
navra agent init <bundle> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--name <instance>` | Instance name (defaults to bundle name) |

### navra agent upgrade

Upgrade an installed agent bundle to a new version.

```bash
navra agent upgrade <bundle> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--allow-unsigned` | Skip signature verification |

### navra agent list

List installed agent bundles and instances.

```bash
navra agent list
```

### navra agent remove

Remove an installed agent bundle.

```bash
navra agent remove <name>
```

### navra agent run

Run an agent task against a running navra instance.

```bash
navra agent run <prompt> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-m, --model <model>` | Model to use (default: auto-detect from Ollama) |
| `-p, --persona <name>` | Persona to use (default: `leader`) |
| `-e, --endpoint <url>` | navra endpoint URL (default: `http://127.0.0.1:9315/mcp`) |
| `-t, --token <token>` | Auth token (reads `MCPD_TOKEN` env if not set) |
| `-n, --max-iterations <N>` | Max iterations (default: 200) |
| `--upstream-prompt <ref>` | Inject an upstream MCP prompt (repeatable, format: `upstream:prompt_name`) |
| `--workflow <name>` | Run a named workflow from an agent instance |
| `--config <path>` | Path to agent instance config (overrides default resolution) |
| `--no-embedded` | Force Ollama API even when a local GGUF blob exists |
| `--dry-run` | Preview the constructed prompt without executing |

---

## navra model

Manage ONNX models.

### navra model serve

Start a standalone model inference server.

```bash
navra model serve [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to config file |
| `-b, --bind <addr>` | Bind address (default: `127.0.0.1:9316`) |
| `--auto` | Auto-detect hardware and propose resource allocation |
| `--budget <size>` | Maximum VRAM budget (e.g., `24GB`, `16GB`) |

### navra model pull

Download a model from HuggingFace.

```bash
navra model pull <name>
```

| Argument | Description |
|----------|-------------|
| `<name>` | Model name (e.g., `guardian-hap`, `granite-embed`) |

### navra model list

List installed models.

```bash
navra model list
```

### navra model available

Show available models for download.

```bash
navra model available
```

---

## navra pii

Manage the PII NER model for semantic PII detection.

### navra pii download

Download a NER model for PII detection.

```bash
navra pii download [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--multilingual` | Download the multilingual model (`xlm-roberta-base-ner-hrl`) instead of the default English-only `protectai/bert-base-NER` model. Covers French, German, Spanish, Italian, Portuguese, Dutch, and more |

### navra pii status

Check if the PII NER model is installed.

```bash
navra pii status
```

---

## navra flow

Manage flows, triggers, and flow execution.

### navra flow run

Execute a flow YAML file.

```bash
navra flow run <file> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `<file>` | Path to the flow YAML file |
| `-p, --prompt <text>` | Prompt / input for the flow (default: empty) |
| `-e, --endpoint <url>` | navra endpoint URL (default: `http://127.0.0.1:9315/mcp`) |
| `-t, --token <token>` | Auth token (reads `MCPD_TOKEN` env if not set) |
| `-m, --model <model>` | Model to use |

### navra flow list

List available flows from configured directories and agent instances.

```bash
navra flow list [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to config file |

### navra flow trigger start

Start the trigger engine (loads triggers from config and agent instances).

```bash
navra flow trigger start [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to config file |

### navra flow trigger list

List configured triggers from config and agent instances.

```bash
navra flow trigger list [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to config file |

---

## navra eval

Run adversarial security evaluations.

### navra eval agent-dojo

Run the AgentDojo IFC defense benchmark (requires the `agentdojo` Python package).

```bash
navra eval agent-dojo [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--tasks <N>` | Max user tasks to evaluate (default: 5) |
| `--suite <name>` | AgentDojo task suite (default: `workspace`) |
| `-m, --model <model>` | LLM model to use (default: `claude-sonnet-4-6@default`) |
| `--defense <type>` | Defense to test: `none`, `ifc`, or `both` (default: `both`) |
| `--attack <type>` | Attack type (default: `important_instructions`) |
| `-o, --output <path>` | Output JSON file path |
| `--python <cmd>` | Python interpreter to use (default: `python3`) |

### navra eval mcp-tox

Run the MCPTox tool poisoning detection benchmark.

```bash
navra eval mcp-tox [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--dataset <path>` | Path to MCPTox dataset directory (default: `/tmp/mcptox`) |
| `-o, --output <path>` | Output JSON file path |

### navra eval report

Generate a markdown comparison report from eval result files.

```bash
navra eval report <files>... [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `<files>` | Result JSON files to compare (required, one or more) |
| `-o, --output <path>` | Output markdown file (prints to stdout if omitted) |

---

## navra audit

Query the gateway audit blackbox.

```bash
navra audit [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-l, --limit <N>` | Number of entries to show (default: 20) |
| `-d, --detail` | Show full args and results |
| `--agent <name>` | Filter by agent name |
| `--tool <name>` | Filter by tool name |
| `--verify` | Verify hash chain integrity instead of listing |

---

## navra self-harness

Analyze flow execution traces for weaknesses and propose improvements.

```bash
navra self-harness [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--flow <id>` | Flow IDs to analyze (repeatable; default: auto-discover recent flows) |
| `--json` | Output report as JSON |
| `--retry-threshold <N>` | Back-edge iteration count considered excessive (default: 3) |
| `--slow-tool-ms <ms>` | Tool call duration in ms considered slow (default: 10000) |

---

## navra policy

Generate policy suggestions from audit data.

### navra policy suggest

Generate policy suggestions from audit denials (audit2allow pattern).

```bash
navra policy suggest [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--hours <N>` | Only include denials from the last N hours (default: 24) |
| `--format <fmt>` | Output format: `cedar`, `toml`, or `both` (default: `cedar`) |
| `--db <path>` | Path to blackbox database (default: `~/.local/share/navra/blackbox.db`) |
| `--agent <name>` | Filter by agent name |
| `--min-count <N>` | Minimum denial count to suggest a rule (default: 3) |

---

## navra config

Configuration utilities.

### navra config import-mcp

Import MCP server configs from Claude Desktop, VS Code, or Codex.

```bash
navra config import-mcp [<path>] [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `<path>` | Path to config file (auto-detects format) |
| `--discover` | Auto-discover config files in standard locations |
| `--no-redact` | Show secret values instead of redacting them |

### navra config list-libraries

List installed operator libraries and what they provide.

```bash
navra config list-libraries [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to config file |

### navra config export

Export config as JSON (for TOML-to-JSON migration).

```bash
navra config export [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-i, --input <path>` | Source config file (default: auto-detect) |
| `-o, --output <path>` | Output JSON file (default: `~/.config/navra/config.json`) |

---

## navra improve

Run autonomous self-improvement cycles (audit, fix, test, verify).

```bash
navra improve [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-t, --target <path>` | Path to the project to improve (default: `.`) |
| `-c, --cycles <N>` | Number of improvement cycles to run (default: 3) |
| `-b, --branch <name>` | Git branch name for the worktree (default: `self-improve`) |
| `--config <path>` | Path to config file |

---

## navra wrap

Wrap an MCP server with a secure-by-default gateway in one command.

```bash
navra wrap [OPTIONS] -- <command> [args...]
```

| Option | Description |
|--------|-------------|
| `-b, --bind <addr>` | Bind address for the gateway (default: `127.0.0.1:9315`) |
| `-s, --safety <profile>` | Safety profile: `standard`, `block`, `secrets-only`, `none` (default: `standard`) |
| `-n, --name <name>` | Name for the upstream server (default: derived from command) |
| `--no-tray` | Disable system tray icon |
| `--discover` | Connect, list tools/resources/prompts, suggest policy, then exit |
| `--allow-all` | Skip safety filters entirely (fast iteration, no content scanning) |
| `--sandbox <type>` | Run upstream in a container sandbox (`openshell` or `podman`) |
| `--allow-domain <domain>` | Allow egress to specific domains (repeatable, merged with auto-discovered) |
| `<command> [args...]` | Command and args to start the upstream MCP server (required, trailing) |

Example:

```bash
navra wrap -- npx @anthropic/mcp-server-filesystem /home/user/docs
```

---

## navra validate-cognitive

Validate cognitive core cross-references.

```bash
navra validate-cognitive [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--cognitive-core <path>` | Path to cognitive core directory (default: `~/.config/navra/cognitive_core`) |

---

## navra tui

Interactive terminal UI dashboard.

```bash
navra tui [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-e, --endpoint <url>` | navra endpoint URL (default: `http://127.0.0.1:9315`) |
| `-t, --token <token>` | Auth token (reads `NAVRA_TOKEN` env if not set) |

---

## navra demo

Run the end-to-end security audit demo.

```bash
navra demo [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-p, --project <path>` | Path to the demo project (default: `examples/payments-app`) |
| `--live` | Run with a real LLM (requires Ollama or llama-server) |
| `--model <model>` | Model to use in live mode (default: `granite3.3:2b`) |
| `--max-rounds <N>` | Max analysis rounds (default: 3) |
| `--files-per-round <N>` | Files per round (default: 5) |
| `--min-delta <N>` | Min new findings to continue (default: 2) |
| `--prompt <text>` | Custom prompt (overrides the default audit prompt) |
| `--writable` | Allow write operations in the project directory |
| `--allow-read <path>` | Additional directories to allow reading (repeatable) |
| `--allow-write <path>` | Additional directories to allow writing (repeatable) |

---

## Deprecated aliases

The following commands still work but are deprecated. Use the replacements shown:

| Deprecated | Replacement |
|------------|-------------|
| `navra serve` | `navra mcp serve` |
| `navra stdio` | `navra mcp stdio` |
| `navra run` | `navra agent run` or `navra flow run` |

These aliases are hidden from `navra --help` output and may be removed in a future release.
