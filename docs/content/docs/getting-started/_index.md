+++
title = "Getting Started"
description = "Install and run navra on your Linux desktop."
weight = 5
template = "docs/section.html"

[extra]
toc = true
+++

## Install

### From source (Fedora/RHEL)

```bash
cargo install --path navra-server
```

### From release binary

Download the latest binary from
[GitHub Releases](https://github.com/smgglrs-ai/navra/releases)
and place it in your `$PATH`.

## First-time setup

Run the interactive setup wizard:

```bash
navra init
```

The wizard walks you through:

1. **Agent detection** — detects Claude Code, Goose, or custom agents
2. **Project type** — dev, data, ops, or custom (drives MCP server recommendations)
3. **Model backend** — Ollama, Mistral, Anthropic, OpenAI-compatible, or none
4. **Safety level** — standard, strict, or minimal
5. **Directory access** — which paths agents can read/write
6. **Systemd service** — optional auto-start on login

It generates a config file, a bearer token, and prints connection
instructions for your agent.

For scripted/CI use:

```bash
navra init --quiet --agent-name claude --project dev --safety standard
```

## Connect a client

After `navra init`, connect your AI agent to the gateway.

### Claude Code

Add to `.claude/settings.json`:

```json
{
  "mcpServers": {
    "navra": {
      "url": "http://localhost:9315/mcp",
      "headers": {
        "Authorization": "Bearer mcd_your_token_here"
      }
    }
  }
}
```

### Goose

Add to `~/.config/goose/config.yaml`:

```yaml
extensions:
  navra:
    type: sse
    uri: http://localhost:9315/mcp
    headers:
      Authorization: "Bearer mcd_your_token_here"
```

### Any MCP client

navra speaks standard MCP over Streamable HTTP. Any MCP client can
connect to `http://localhost:9315/mcp` with a bearer token.

## Verify the setup

```bash
# Check server status
navra status

# Query the audit log
navra audit --limit 5

# List available tools
navra status  # shows tool count and registered agents
```

## Next steps

- [Integrations](/docs/integrations/) — detailed guides for Claude Code, Goose, OpenAI clients, LangGraph
- [Guides](/docs/guides/) — multi-agent flows, personas, RAG, memory, model server, agent bundles
- [Configuration](/docs/configuration/) — full config.toml reference
- [CLI Reference](/docs/cli/) — all commands and flags
- [Architecture](/docs/architecture/) — microkernel design, crate layering, security model
