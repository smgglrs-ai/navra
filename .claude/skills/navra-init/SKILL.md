---
name: navra-init
description: Set up navra for a new user — detect environment, generate config, create tokens, install service
---

Generate a working navra configuration for first-time setup.

## Usage

Run `/navra-init` when a user wants to start using navra as their
MCP gateway. The skill detects the environment, asks a few questions,
and produces a complete setup.

## Workflow

### 1. Detect agent runtime

Check which AI agent the user runs:

- `.claude/` exists in cwd or home → Claude Code
- `~/.config/goose/` exists → Goose
- Otherwise → ask the user

### 2. Gather requirements

Ask the user (use AskUserQuestion):

**Directories**: "Which directories should your agent access?"
- Suggest `~/Code/**` and `~/Documents/**` as defaults
- Always deny `**/.env`, `**/*secret*`, `**/credentials*`

**Safety level**: "What safety filtering do you want?"
- `standard` (recommended) — PII detection + secret filtering + prompt injection detection
- `strict` — all of standard plus ML-based content classification
- `minimal` — secret filtering only (`secrets-only`)

**Modules**: "Which capabilities do you need?"
- File access (default: yes)
- Git operations (default: yes)
- RAG search (default: no)
- Voice I/O (default: no)

### 3. Generate token

Run the token generation command:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 navra token generate --name <agent-name> --permissions <perm-set>
```

Parse the output to extract the token and hash. If `navra` is not
in PATH, build it first:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo run -- token generate --name <agent-name> --permissions <perm-set>
```

### 4. Generate config.toml

Write `~/.config/navra/config.toml` using the gathered information.
Use the example config at `examples/config.toml` as the reference
for field names and structure.

Template:

```toml
[server]
socket = "~/.run/navra/navra.sock"
mcp_version = "2026-07-28"

[modules.file]
enabled = true
db = "~/.local/share/navra/index.db"

[modules.git]
enabled = true    # or false based on user answer

[modules.rag]
enabled = false   # or true

[modules.memory]
pii_filter = "standard"

[[agents]]
name = "<agent-name>"
token_hash = "<hash from step 3>"
permissions = "<perm-set-name>"

[permissions.<perm-set-name>]
allow = [<user directories>]
deny = ["**/.env", "**/*secret*", "**/credentials*", "**/.git/config"]
operations = ["read", "write"]
safety = "<safety level>"
default_tool_policy = "allow"

[[permissions.<perm-set-name>.tool_rules]]
tool = "git_push"
policy = "approve"

[[permissions.<perm-set-name>.tool_rules]]
tool = "exec_*"
policy = "deny"

[approval]
timeout_secs = 300
notify = "dbus"

[budget]
max_agents = 50
max_iterations = 200
max_parallel = 2
timeout_secs = 3600
```

### 5. Install systemd service

```bash
mkdir -p ~/.config/systemd/user
cp navra-server/systemd/navra.service ~/.config/systemd/user/navra.service
systemctl --user daemon-reload
systemctl --user enable navra
systemctl --user start navra
```

Or if navra has the `install` subcommand:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 navra install
systemctl --user start navra
```

### 6. Print connection instructions

Tell the user how to connect their agent:

**Claude Code**: Add to `.claude/settings.json`:
```json
{
  "mcpServers": {
    "navra": {
      "type": "stdio",
      "command": "navra",
      "args": ["connect", "--token", "<bearer-token>"]
    }
  }
}
```

**Goose**: Add to `~/.config/goose/config.yaml` the appropriate
MCP server configuration.

**Other**: Connect to the Unix socket at `~/.run/navra/navra.sock`
with bearer token authentication.

## Notes

- Always create the config directory: `mkdir -p ~/.config/navra`
- Always create the data directory: `mkdir -p ~/.local/share/navra`
- The token is shown once — remind the user to save it
- Check if a config already exists before overwriting — ask first
- If navra binary is not installed, suggest building from source:
  `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo install --path navra-server`
