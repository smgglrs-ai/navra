---
name: navra-init
description: Set up navra for a new user — detect environment, generate config, create tokens, install service
---

Set up navra for a new user using the built-in `navra init` command.

## Usage

Run `/navra-init` when a user wants to start using navra as their
MCP gateway.

## Primary: `navra init`

If navra is installed and in PATH:

```bash
# Interactive setup (recommended for first-time users)
navra init

# Non-interactive with explicit options
navra init --quiet --agent-name claude-code --project dev --safety standard

# Preview config without writing
navra init --quiet --dry-run --project dev
```

## Fallback: build from source

If navra is not in PATH, build and run from the repo:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo run -- init
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--quiet` | Skip interactive prompts | false |
| `--agent-name NAME` | Agent name | auto-detect |
| `--safety LEVEL` | standard, strict, minimal | standard |
| `--project TYPE` | dev, data, ops, custom | dev |
| `--model BACKEND` | ollama, mistral, anthropic, openai-compat, none | none |
| `--model-url URL` | Base URL for openai-compat | - |
| `--api-key KEY` | API key for model backend | - |
| `--allow DIRS` | Comma-separated directory globs | ~/Code/** |
| `--install-service` | Install systemd user service | false |
| `--dry-run` | Print config to stdout | false |
| `-o, --output PATH` | Config output path | ~/.config/navra/config.toml |

## What it does

1. Detects the agent runtime (Claude Code, Goose, or custom)
2. Selects project type to determine which MCP servers to enable
3. Configures model backend (local Ollama or cloud API)
4. Sets safety level (maps to navra safety profiles)
5. Configures allowed/denied directory patterns
6. Generates a BLAKE3-hashed agent token
7. Writes config.toml (backs up any existing config)
8. Optionally installs systemd user service
9. Prints connection instructions for the detected agent

## Notes

- The token is displayed once and cannot be recovered
- Existing config is backed up to `config.toml.bak.<timestamp>`
- Safety levels map: standard -> standard, strict -> guardian, minimal -> secrets-only
- For `dev` projects, both built-in file/git modules and upstream MCP servers are enabled
