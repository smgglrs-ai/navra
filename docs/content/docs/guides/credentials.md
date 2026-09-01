+++
title = "Credential Brokering"
description = "Configure credential brokering so agents use secrets without ever seeing them."
weight = 45

[extra]
toc = true
+++

Agents that call external APIs need credentials -- GitHub tokens,
Jira API keys, OAuth client secrets. The obvious approach is to pass
those secrets through the agent's context, but that creates a direct
exfiltration path: a prompt-injected agent can read its own context
and send secrets to an attacker-controlled endpoint.

Navra's credential broker solves this by keeping secrets out of the
agent's context entirely. The gateway resolves credential labels to
real values at call time, injects them into the tool execution
environment, and strips them from results before the agent sees the
response. The agent works with opaque labels; the secret never
appears in the conversation.

## How it works

The broker follows a four-step lifecycle for every tool call that
uses credentials:

1. **Label reference** -- The upstream config references a credential
   by label (e.g., `github_token`), not by value.
2. **Backend resolution** -- At call time, the gateway resolves the
   label through the configured backend (OS keyring or environment
   variable) and gets the raw secret. The resolved value is held in
   a `Secret` struct that is zeroized on drop.
3. **Injection** -- The secret is injected into the upstream process
   environment (for stdio transports) or request headers (for HTTP
   transports). The agent's MCP session never contains the value.
4. **Stripping** -- The safety pipeline scans tool results for
   credential patterns and exfiltration attempts before returning
   them to the agent.

Only credentials explicitly listed in the `[credentials]` config
section are accessible. The store cannot discover or enumerate OS
keyring entries -- unlisted labels are rejected with an error.

## Configuration

Define credential mappings in the `[credentials]` section of your
config file. Each entry maps a label to a backend source.

### Keyring source

The OS keyring is the recommended backend for production. Navra
uses the `keyring` crate, which supports GNOME Keyring (via
Secret Service), KWallet, macOS Keychain, and Windows Credential
Manager.

```toml
[credentials]
"github.pat" = { source = "keyring", path = "navra/github-pat" }
"jira.token" = { source = "keyring", path = "navra/jira-api-key" }
```

The `path` field uses `service/user` format. The part before the
slash is the keyring service name; the part after is the account or
user identifier within that service.

You can also reference credentials already stored by other
applications:

```toml
[credentials]
"gnome.github" = { source = "keyring", path = "org.gnome.OnlineAccounts/github" }
```

### Environment variable source

For CI pipelines, containers, or environments without a keyring,
credentials can be sourced from environment variables:

```toml
[credentials]
"ci.token" = { source = "env", var = "GITHUB_TOKEN" }
"api.key" = { source = "env", var = "MY_API_KEY" }
```

Environment-sourced credentials are read-only -- navra cannot store
or delete them. Attempts to do so return an error.

## Storing credentials in the keyring

Use `secret-tool` (part of `libsecret`) to store credentials in
the GNOME Keyring. The service and user must match the `path` field
in your config.

```bash
# Store a GitHub PAT
secret-tool store --label="navra GitHub PAT" \
    service navra username github-pat

# Store a Jira API key
secret-tool store --label="navra Jira key" \
    service navra username jira-api-key

# Verify it was stored
secret-tool lookup service navra username github-pat
```

On KDE, use `kwalletcli` or `kwallet-query` instead. On macOS, use
the Keychain Access app or `security add-generic-password`.

## Using credentials in upstream config

### The credentials map (recommended)

The `credentials` field in an upstream config maps environment
variable names to credential labels. At startup, navra resolves
each label and injects the value into the upstream process
environment:

```toml
[credentials]
"github.pat" = { source = "keyring", path = "navra/github-pat" }

[[upstream]]
name = "github"
transport = "stdio"
command = ["npx", "-y", "@modelcontextprotocol/server-github"]
credentials = { GITHUB_TOKEN = "github.pat" }
```

When navra spawns the `npx` process, it resolves `github.pat` from
the keyring and sets `GITHUB_TOKEN` in the child process
environment. The agent never sees the token value -- it only knows
that a tool named `github` is available.

If resolution fails (label not found, keyring locked, env var
unset), navra logs a warning and starts the upstream anyway. The
upstream may fail on its own when it tries to use the missing
credential.

### The env map with ${credential:label} syntax

The `env` field also supports credential references using the
`${credential:label}` placeholder syntax:

```toml
[[upstream]]
name = "github"
transport = "stdio"
command = ["npx", "-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "${credential:github_token}" }
```

Both approaches achieve the same result. The `credentials` map is
more explicit and easier to audit.

## Per-agent credential scoping

Permission sets control which credential labels an agent can use.
The `credentials` array in a permission set lists the labels that
agents in that set are allowed to access:

```toml
[credentials]
"github.pat" = { source = "keyring", path = "navra/github-pat" }
"jira.token" = { source = "keyring", path = "navra/jira-api-key" }
"db.password" = { source = "keyring", path = "navra/db-password" }

[permissions.leader]
ring = 1
operations = ["read", "write"]
credentials = ["github.pat", "jira.token", "db.password"]
can_delegate = true

[permissions.readonly]
ring = 2
operations = ["read"]
credentials = ["github.pat"]
```

When a leader agent delegates a capability token to a specialist,
the credential set can only be narrowed -- never widened. A child
token that lists `db.password` when the parent only granted
`github.pat` is rejected at validation time. This enforcement is
cryptographic: the child token includes the parent's signature, and
the gateway verifies the full delegation chain.

```toml
[[agents]]
name = "leader"
token_hash = "..."
permissions = "leader"
capability_token = true

[[agents]]
name = "readonly-helper"
token_hash = "..."
permissions = "readonly"
```

The `readonly-helper` agent can only use credentials listed in the
`readonly` permission set (`github.pat`). Even if it somehow
obtained the label `db.password`, the gateway would refuse to
resolve it.

## How the gateway prevents credential leakage

Credential brokering is one layer in a defense-in-depth strategy.
Several other navra subsystems reinforce it:

### IFC taint propagation

When a credential is injected into a tool call, the IFC pipeline
tags the resulting data flow. If an agent attempts to write
credential-tainted data to a lower-confidentiality channel (e.g.,
posting to a public webhook), the IFC lattice blocks the operation.

### Safety filter stripping

The content safety pipeline scans every tool result for secret
patterns -- API keys, bearer tokens, passwords, and other
credential formats. Matches are redacted before the result reaches
the agent context. The `secrets-only` and `standard` safety
profiles both include these patterns.

### Exfiltration detection

The `ExfilDetectionFilter` scans tool arguments for credential
theft patterns: `curl` commands posting `$TOKEN` or `$SECRET`,
`env | curl` pipelines, base64-encoded key file extraction, and
cloud metadata endpoint access. These are blocked before execution.

### Zeroization

Resolved secrets are held in `Zeroizing<Vec<u8>>` wrappers (from
the `zeroize` crate). When the `Secret` struct is dropped, the
memory is overwritten with zeros. This limits the window in which
secrets exist in process memory.

### Capability tokens carry labels, not values

Capability tokens encode credential labels (e.g., `github.pat`),
never secret values. Even if a token is intercepted or logged, it
reveals only which credentials the agent is authorized to use, not
the credentials themselves.

## Practical examples

### GitHub MCP server

```toml
[credentials]
"github.pat" = { source = "keyring", path = "navra/github-pat" }

[permissions.dev]
operations = ["read", "write"]
credentials = ["github.pat"]

[[agents]]
name = "claude"
token_hash = "..."
permissions = "dev"

[[upstream]]
name = "github"
transport = "stdio"
command = ["npx", "-y", "@modelcontextprotocol/server-github"]
credentials = { GITHUB_TOKEN = "github.pat" }
```

```bash
# Store the token
secret-tool store --label="GitHub PAT" \
    service navra username github-pat
# Paste your token when prompted
```

### Jira API key via environment variable

For CI environments where no keyring is available:

```toml
[credentials]
"jira.key" = { source = "env", var = "JIRA_API_KEY" }

[[upstream]]
name = "jira"
openapi = "https://jira.example.com/v3/api-docs"
[upstream.auth]
bearer = "${JIRA_API_KEY}"
```

```bash
export JIRA_API_KEY="your-api-key-here"
navra serve
```

### OAuth client secret for upstream MCP server

```toml
[credentials]
"oauth.secret" = { source = "keyring", path = "navra/oauth-client-secret" }

[[upstream]]
name = "secure-server"
transport = "http"
url = "https://mcp.example.com/mcp"
credentials = { OAUTH_SECRET = "oauth.secret" }

[upstream.oauth]
client_id = "navra-client"
client_secret = "${OAUTH_SECRET}"
scopes = ["read", "write"]
```

### Multi-agent team with scoped credentials

A leader agent has access to both GitHub and Jira credentials.
It delegates a read-only sub-task to a specialist that only needs
GitHub access:

```toml
[credentials]
"github.pat" = { source = "keyring", path = "navra/github-pat" }
"jira.token" = { source = "keyring", path = "navra/jira-api-key" }

[permissions.team-lead]
ring = 1
operations = ["read", "write"]
credentials = ["github.pat", "jira.token"]
can_delegate = true

[permissions.code-reader]
ring = 2
operations = ["read"]
credentials = ["github.pat"]

[[agents]]
name = "lead"
token_hash = "..."
permissions = "team-lead"
capability_token = true

[[agents]]
name = "reviewer"
token_hash = "..."
permissions = "code-reader"
```

The `reviewer` agent can use GitHub tools but has no access to
Jira credentials. If the leader delegates a capability token to
the reviewer, the token cannot include `jira.token` -- the
delegation validator rejects any credential not present in the
parent's grant.
