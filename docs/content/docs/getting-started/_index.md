+++
title = "Getting Started"
description = "Install and run navra on your Linux desktop."
weight = 10
template = "docs/section.html"

[extra]
toc = true
+++

## Install

### From source (Fedora/RHEL)

```bash
sudo dnf install onnxruntime-devel
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo install --path navra-server
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

## Run an agent task

With navra running and Ollama available:

```bash
# Run a one-shot task through the gateway
navra run "List the files in the current directory" \
    --model granite3.3:8b
```

## Run a flow

navra includes multi-agent flows. Try the security audit:

```bash
navra run "Audit examples/payments-app" \
    --model granite3.3:8b \
    --flow examples/flows/security-audit.yaml
```

Available flows in `examples/flows/`:

| Flow | Description |
|------|-------------|
| `review.yaml` | Domain-agnostic review (scout → planner → swarm → synthesize) |
| `deep-research.yaml` | Multi-source research with adversarial verification |
| `security-audit.yaml` | Security-focused review with OWASP coverage |
| `improve.yaml` | Code improvement with iterative refinement |
| `self-improve.yaml` | Self-improving agent pattern |

## Verify the setup

```bash
# Check server status
navra status

# Query the audit log
navra audit --limit 5

# List available tools
navra status  # shows tool count and registered agents
```

## Project structure

navra is a 22-crate Rust workspace:

| Layer | Crates | Role |
|-------|--------|------|
| Protocol | navra-protocol | MCP types (via rmcp SDK), A2A |
| Security | navra-auth, navra-safety-hooks | Auth, ACLs, IFC, safety hooks |
| Kernel | navra-core | Server, module trait, session |
| Models | navra-model, navra-model-hub, navra-model-runtime | Backends, registry |
| Cognitive | navra-cognitive | Personas, prompt weaving |
| Agent | navra-agent | ReAct loop, builder API, typed actions |
| Orchestration | navra-flow | DAG, handoff, mesh |
| Memory | navra-memory | Working memory, entity graph, decay |
| Tools | navra-mcp, navra-openapi | Upstream MCP, OpenAPI gen |
| Modalities | navra-modal-voice, navra-modal-vision | Speech, image |
| RAG | navra-rag | Hybrid search, chunking |
| Binary | navra-server | CLI, config, wiring |

## Next steps

- [Integration guides](/docs/integrations/) — Claude Code, Goose, OpenAI clients, LangGraph, custom MCP
- [Agent SDK guide](/docs/sdk/) — build agents in Rust with navra-agent
- [Configuration reference](/docs/configuration/) — full config.toml reference
- [Architecture](/docs/architecture/) — security model and design decisions
- [Learn](/docs/learn/) — concepts behind IFC, capability tokens, and more
