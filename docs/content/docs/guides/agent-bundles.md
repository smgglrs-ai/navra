+++
title = "Agent Bundles"
weight = 10
template = "docs/page.html"

[extra]
toc = true
+++

Agent bundles package an agent's identity, permissions, upstream MCP
servers, and workflows into an installable unit. navra supports two
bundle formats: OCI artifacts (v1) for registry distribution and
directory bundles (v2) for local development.

## Bundle formats

### Directory bundle (v2)

The directory format is the primary authoring format. A bundle is a
directory containing an `agent.yaml` file and optional supporting files:

```text
my-agent/
  agent.yaml           # agent identity, personas, permissions, workflows
  config-template.yaml # credential and preference declarations (optional)
  workflows/           # workflow YAML files (optional)
    day-planner.yaml
    triage.yaml
```

### OCI artifact (v1)

OCI bundles are pushed to container registries (Quay, GHCR, Docker Hub)
using the OCI Referrers API. The agent manifest is attached as a
referrer artifact with type `application/vnd.navra.agent-bundle.v1+json`.

OCI bundles use a JSON manifest format with a slightly different
structure than directory bundles. navra handles both transparently.

## agent.yaml reference

The `agent.yaml` file defines the agent's identity and capabilities:

```yaml
meta:
  name: admin-assistant
  version: "1.0.0"
  publisher: acme
  description: "Administrative assistant for email and calendar"
  license: Apache-2.0

personas:
  - name: assistant
    system_prompt: "You are a helpful administrative assistant."
    directives:
      - "Prioritize urgent emails"
      - "Never send without confirmation"

model:
  preferred: granite-8b
  fallbacks: [llama-7b]
  task: chat

permissions:
  operations: [upstream.read, upstream.write]
  default:
    gmail: [read, list, search]
    calendar: [read]

upstreams:
  - name: gmail
    transport: stdio
    command: [npx, -y, "@anthropic/gmail-mcp"]
  - name: calendar
    transport: stdio
    command: [npx, -y, "@anthropic/calendar-mcp"]

workflows:
  day-planner:
    description: "Morning briefing and day planning"
    expose: [cli, tool]
    steps:
      - name: read-inbox
        permissions:
          gmail: [read, list, search]
          calendar: [read]
      - name: summarize
        permissions: {}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `meta.name` | yes | Unique bundle identifier |
| `meta.version` | no | Semver version (default: `0.1.0`) |
| `meta.publisher` | no | Publisher name |
| `meta.description` | no | Human-readable description |
| `meta.license` | no | SPDX license identifier |
| `personas` | no | Named persona definitions with system prompts and directives |
| `model.preferred` | no | Preferred model name from `[models.*]` config |
| `model.fallbacks` | no | Fallback models if preferred is unavailable |
| `permissions.operations` | no | Allowed operation namespaces |
| `permissions.default` | no | Per-upstream default operation permissions |
| `upstreams` | no | MCP servers the agent connects to |
| `workflows` | no | Named multi-step workflow definitions |

### Workflows

Each workflow entry declares:

- `description` -- human-readable purpose
- `expose` -- surfaces where the workflow appears: `cli`, `tool`, or both (default: `["cli"]`)
- `steps` -- ordered list of named steps, each with scoped permissions

Step permissions are per-upstream operation lists. When an agent calls
a workflow step, the effective permissions are the intersection of the
caller's permissions and the step's declared permissions. This
implements capability-based security: you can only delegate what you
have.

## config-template.yaml

The config template declares credentials and preferences the user
must provide at install time:

```yaml
credentials:
  - name: gmail
    type: oauth2
    required: true
    scopes: [read, send]
    description: "Gmail access for email management"
  - name: slack
    type: bot-token
    required: false
    description: "Slack bot for notifications"

preferences:
  - name: model
    type: choice
    options: [granite-8b, llama-70b]
    default: granite-8b
  - name: budget
    type: number
    description: "Maximum tokens per day"
    default: "100000"
```

Credentials are resolved from the OS keyring at runtime.

## Lifecycle

### Install from a local directory

```bash
navra agent install ./my-agent/
```

This copies the bundle to `~/.local/share/navra/agent-bundles/my-agent/`
and lists available workflows. If a bundle with the same name already
exists, navra shows a permission diff before replacing it.

### Install from an OCI registry

```bash
navra agent install oci://quay.io/acme/admin-assistant:1.0
```

For OCI installs, navra:

1. Verifies the cosign signature (per `agent_signature_policy`)
2. Fetches the agent manifest via the OCI Referrers API
3. Compares requested permissions against operator policy
4. Generates a config snippet with token, permissions, and upstream entries
5. Records the installed agent in `~/.local/share/navra/agents/`

The generated config snippet is printed to stdout. Paste it into your
`config.toml` to activate the agent.

### Initialize an instance

After installing a bundle, initialize an instance to generate
per-user configuration with resolved credentials:

```bash
navra agent init admin-assistant
navra agent init admin-assistant --name work-assistant
```

This creates `~/.config/navra/agents/<instance>/config.toml` with:

- Bundle reference and model preferences
- Credential entries (pointing to OS keyring labels)
- Permission envelope from the bundle
- Commented workflow trigger templates

### Upgrade

Re-install from the new source. navra shows a permission diff
automatically:

```bash
navra agent install ./my-agent-v2/
```

For OCI bundles:

```bash
navra agent upgrade admin-assistant
```

### Inspect without installing

```bash
navra agent inspect oci://quay.io/acme/admin-assistant:1.0
```

Prints the agent manifest as JSON.

### List and remove

```bash
navra agent list
navra agent remove admin-assistant
```

## Signature verification

navra uses [cosign](https://docs.sigstore.dev/cosign/) to verify
OCI bundle signatures. The behavior is controlled by
`agent_signature_policy` in `[server]`:

| Policy | Behavior |
|--------|----------|
| `enforce` | Require valid signature; fail if cosign is missing or verification fails |
| `warn` | Warn if signature is missing or invalid; proceed with install |
| `skip` | No signature verification |

Override per-install with `--allow-unsigned`:

```bash
navra agent install oci://quay.io/acme/agent:dev --allow-unsigned
```

## Permission checks

OCI bundles include a permissions declaration in the manifest. During
install, navra compares the requested permissions against the
operator's policy:

```bash
navra agent install oci://quay.io/acme/agent:1.0 --max-permissions developer
```

The `--max-permissions` flag names a permission set from `config.toml`.
If the bundle requests permissions that exceed the policy, the install
is rejected with a detailed diff showing denied operations, tool rules,
domain rules, and IFC violations.

## Running workflows

After installing and initializing a bundle with workflows:

```bash
# Run a named workflow
navra run work-assistant/day-planner

# Run with a specific model
navra run work-assistant/day-planner --model granite-8b

# Preview the constructed prompt
navra run work-assistant/day-planner --dry-run
```
