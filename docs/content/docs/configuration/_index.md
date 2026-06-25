+++
title = "Configuration"
description = "config.toml reference — server, permissions, modules, agents, upstream."
weight = 40
template = "docs/section.html"

[extra]
toc = true
+++

Default path: `~/.config/navra/config.toml`

## Server

```toml
[server]
host = "127.0.0.1"
port = 3100
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | `"127.0.0.1"` | Bind address |
| `port` | u16 | `3100` | HTTP port |

## Permissions

Permission sets define what agents can do. Each set specifies allowed
operations, tools, paths, and safety profiles.

```toml
[permissions.default]
operations = ["read", "search", "list"]
tools = ["file_tree", "file_read", "file_grep"]

[permissions.developer]
operations = ["read", "write", "search", "list"]
tools = ["file_tree", "file_read", "file_write", "file_edit", "file_grep"]
paths = ["/home/user/projects"]
safety = "standard"
```

| Field | Type | Description |
|-------|------|-------------|
| `operations` | string[] | Allowed operation namespaces |
| `tools` | string[] | Allowed tool names |
| `paths` | string[] | Allowed filesystem paths (deny-wins) |
| `safety` | string | Safety profile (`minimal`, `standard`, `strict`) |

### Deny rules

Deny rules take absolute precedence over allow rules.

```toml
[permissions.developer.deny]
tools = ["file_delete"]
paths = ["/etc", "/usr"]
```

## Agents

Agent definitions bind a name and permission set to an identity.

```toml
[[agents]]
name = "claude"
permissions = "developer"
```

### Capability token agents

Agents authenticating with capability tokens:

```toml
[[agents]]
name = "specialist"
permissions = "readonly"
token_ttl = 3600
```

## Agent Bundles

Agent bundles package personas, model preferences, and workflows
into installable directories.

```
my-agent/
  agent.yaml           # personas, model preferences, workflows
  config-template.yaml # credential requirements
  workflows/
    day-planner.yaml
```

| File | Purpose |
|------|---------|
| `agent.yaml` | Agent identity — persona definitions, preferred models, and workflow references |
| `config-template.yaml` | Declares credentials and config values the user must provide at install time |
| `workflows/*.yaml` | Reusable workflow definitions the agent can execute |

## Upstream MCP Servers

Connect external MCP servers through the gateway's security pipeline.

```toml
[[upstream]]
name = "github"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "@keyring:github_token" }

[[upstream]]
name = "filesystem"
url = "http://localhost:3200/mcp"
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Upstream identifier |
| `command` | string | Stdio server command |
| `args` | string[] | Command arguments |
| `url` | string | HTTP upstream URL |
| `env` | map | Environment variables (`@keyring:` for OS keyring) |

### Credentials

Upstream servers can declare credential requirements. Labels are
resolved from the OS keyring at launch time and injected as
environment variables into the MCP server process.

```toml
[[upstream]]
name = "gmail"
command = ["npx", "-y", "@anthropic/gmail-mcp"]
[upstream.credentials]
GMAIL_TOKEN = "gmail-work"
```

The key (`GMAIL_TOKEN`) becomes the environment variable name. The
value (`gmail-work`) is the keyring label used to look up the secret.

## Models

Model configuration for local and remote backends.

```toml
[models.gemma4]
backend = "ollama"
model = "gemma4:27b"

[models.gemma4.agentic]
cost_tier = "free"
speed_tier = "medium"
reasoning = "extended"
tool_use = "advanced"
locality = "local"
```

## Model Server

When set, the gateway connects to an external model server instead
of loading models in-process. When absent, models are loaded directly
(backward-compatible).

```toml
model_server = "http://127.0.0.1:9316"
```

Start the server with `navra model serve`. See
[Model server](/docs/getting-started/#model-server) for usage.

## Operator Libraries

Drop TOML fragments into library directories for config composition.

```toml
[libraries]
library_dirs = ["~/.config/navra/libraries", "/etc/navra/libraries.d"]
```

Library files in these directories are deep-merged into the main
config at startup. Main config wins on key conflicts. Duplicate keys
across libraries produce a startup error.

See `navra config list-libraries` to inspect installed libraries.

## Discovery

Agent discovery via DNS-AID or mDNS.

```toml
[discover]
dns_aid = true
mdns = true
```

## Registry

OCI model registries for model card distribution.

```toml
[[registry]]
url = "ghcr.io/smgglrs-ai/navra-models"
type = "oci"
```
