+++
title = "Quick Start with navra wrap"
description = "Wrap any MCP server with a secure gateway in one command."
weight = 5
template = "docs/page.html"

[extra]
toc = true
+++

`navra wrap` is the fastest path from an unprotected MCP server to a
fully secured gateway. One command, no config file, instant safety
filters. Use it when you want to try navra with an existing MCP server
or iterate quickly during development.

## What it does

`navra wrap` takes any stdio-based MCP server command, generates a
one-shot config with authentication, safety filtering, and egress
controls, then starts a navra gateway in front of it. The gateway
listens on HTTP and proxies MCP requests to the upstream server
through navra's full security pipeline: information flow control,
content scanning, PII detection, and audit logging.

When the process exits, everything stops. No files are written to
disk -- the config lives only in memory for the lifetime of the
session.

## Basic usage

```bash
navra wrap -- npx -y @modelcontextprotocol/server-github
```

Everything after `--` is the command to start the upstream MCP server.
navra spawns it as a child process, connects over stdio, and exposes
the wrapped tools on `http://127.0.0.1:9315/mcp`.

The output includes a generated bearer token:

```
navra wrap: starting secured proxy for 'server-github'

  Upstream:  npx -y @modelcontextprotocol/server-github
  Gateway:   http://127.0.0.1:9315/mcp
  Safety:    standard
  Sandbox:   none (direct)
  Token:     nvr_a1b2c3d4e5f6...

Use with any MCP client:
  export MCPD_TOKEN=nvr_a1b2c3d4e5f6...
  # endpoint: http://127.0.0.1:9315/mcp
```

Point your MCP client at the gateway endpoint and pass the token as a
bearer credential. All calls flow through navra's safety checks before
reaching the upstream server.

## Flags

### --bind

Listen address for the gateway. Default: `127.0.0.1:9315`.

```bash
navra wrap --bind 0.0.0.0:8080 -- ./my-server
```

### --safety

Safety profile applied to all tool calls. Default: `standard`.

| Profile | Behavior |
|---|---|
| `standard` | Full pipeline: content scanning, PII detection, secrets filtering, IFC labels |
| `block` | Like standard but blocks (rather than redacts) any flagged content |
| `secrets-only` | Only scan for secrets and credentials; skip PII and content analysis |
| `none` | No content scanning at all; IFC labels and audit logging still apply |

```bash
navra wrap --safety secrets-only -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### --name

Override the upstream server name. By default navra derives it from
the command binary (e.g., `server-github` from the npx package name).
The name appears in audit logs and policy suggestions.

```bash
navra wrap --name my-github -- npx -y @modelcontextprotocol/server-github
```

### --no-tray

Disable the system tray icon. Useful for headless environments or when
running inside a terminal multiplexer.

```bash
navra wrap --no-tray -- ./my-server
```

### --discover

Probe mode. Connects to the upstream server, lists its tools,
resources, and prompts, analyzes network requirements, and prints a
suggested `config.toml` policy -- then exits. Does not start a
gateway.

```bash
navra wrap --discover -- npx -y @modelcontextprotocol/server-github
```

Output includes:

- **Tool inventory** with read/write classification based on MCP
  annotations (`readOnlyHint`, `destructiveHint`) and navra's
  heuristic fallback
- **Prompts and resources** exposed by the server
- **Network requirements**: domains extracted from the known-server
  registry, domains found in tool descriptions, and tools that accept
  URL parameters (which may need arbitrary egress)
- **Suggested policy**: a ready-to-paste `[[upstream]]`,
  `[upstream.network]`, and `[permissions.*]` block for your
  `config.toml`

This is the recommended first step when integrating a new MCP server
into a permanent config.

### --allow-all

Disable all safety filters and egress filtering. The gateway still
provides authentication and audit logging, but no content is scanned
or blocked. Intended for fast iteration during development only.

```bash
navra wrap --allow-all -- ./my-server
```

A warning is printed when this flag is active.

### --sandbox

Run the upstream MCP server inside a container sandbox. Two backends
are supported:

| Value | Description |
|---|---|
| `openshell` | Route through the OpenShell gateway (must be running on `localhost:50051`) |
| `podman` | Run in a rootless Podman container |

```bash
navra wrap --sandbox podman -- python my_server.py
```

When sandboxing is active, navra also enables egress filtering by
default: all outbound network access from the upstream is denied
unless explicitly allowed via `--allow-domain`.

### --allow-domain

Permit the sandboxed upstream to reach specific external domains. Can
be repeated. Domains are merged with any auto-discovered domains from
navra's known-server registry.

```bash
navra wrap --sandbox podman \
  --allow-domain api.github.com \
  --allow-domain github.com \
  -- npx -y @modelcontextprotocol/server-github
```

For well-known servers (GitHub, GitLab, Slack, Jira, Google Workspace,
Notion, Linear), navra auto-discovers the required domains. You only
need `--allow-domain` for custom endpoints or servers not in the
registry.

## Discovery workflow

The recommended workflow for onboarding a new MCP server:

1. **Discover** what the server exposes:

   ```bash
   navra wrap --discover -- npx -y @modelcontextprotocol/server-github
   ```

2. **Review** the output -- check which tools are classified as write
   operations, whether the server needs network access, and whether
   any tools accept arbitrary URLs.

3. **Test** with `navra wrap` to verify the integration works:

   ```bash
   navra wrap -- npx -y @modelcontextprotocol/server-github
   ```

4. **Promote** to a permanent config by copying the suggested policy
   into your `config.toml` and adjusting permissions.

## Examples

### Wrapping the GitHub MCP server

```bash
# Set the GitHub token for the upstream server
export GITHUB_PERSONAL_ACCESS_TOKEN=ghp_...

# Start the secured gateway
navra wrap -- npx -y @modelcontextprotocol/server-github
```

navra auto-detects that this is the GitHub server and applies
appropriate defaults. In sandboxed mode, it auto-allows
`api.github.com`, `github.com`, and `*.githubusercontent.com`.

### Wrapping a Python MCP server

```bash
navra wrap --name code-analyzer -- python3 ./analyze_server.py
```

For custom servers without a known-server entry, navra derives the
name from the binary (`python3`) unless you override it with `--name`.
Use `--discover` first to see what the server exposes.

### Wrapping with sandboxing

```bash
navra wrap \
  --sandbox podman \
  --allow-domain api.linear.app \
  --safety block \
  -- npx -y @modelcontextprotocol/server-linear
```

This runs the Linear MCP server in a Podman container with:

- All outbound traffic denied except `api.linear.app`
- The `block` safety profile, which rejects any flagged content
  outright rather than redacting it

### Read-only quick test

```bash
navra wrap --safety none --no-tray -- npx -y @modelcontextprotocol/server-filesystem /home/user/docs
```

Minimal overhead for a quick smoke test of a local filesystem server.
Safety filters are off, but authentication and audit logging remain
active.

## When to use wrap vs config.toml

| Scenario | Use |
|---|---|
| Trying a new MCP server for the first time | `navra wrap` |
| Development and local iteration | `navra wrap` |
| Quick demo or proof of concept | `navra wrap` |
| Production deployment with multiple upstreams | `config.toml` |
| Fine-grained per-agent permissions | `config.toml` |
| Custom tool overrides or approval workflows | `config.toml` |
| systemd service with persistent config | `config.toml` |

`navra wrap` generates the same internal config structure that
`config.toml` uses. The `--discover` flag outputs the exact TOML
blocks you need when you are ready to move to a permanent
configuration.
