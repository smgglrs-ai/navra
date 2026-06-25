# Agent Bundle Examples

Agent bundles are OCI artifacts that package an agent's persona, permissions,
and upstream MCP server dependencies into a single installable unit. Each
bundle contains an `AgentManifest` JSON file that declares what the agent
needs to operate.

When you install a bundle, navra generates a config snippet with a scoped
permission set, upstream server entries, and a unique agent token. The
agent operates within its declared permission boundary -- it cannot escalate
beyond what the manifest requests.

## Installing a bundle

```bash
navra agent install oci://quay.io/navra/researcher:latest
```

This pulls the OCI artifact, extracts the manifest, generates a token, and
prints a TOML config snippet to append to your `config.toml`.

## Inspecting a bundle

```bash
navra agent inspect oci://quay.io/navra/researcher:latest
```

This prints the manifest contents without installing, so you can review the
requested permissions and upstreams before granting access.

## Building your own bundle

1. Create a manifest JSON file following the schema in this directory.
   Required fields:

   ```json
   {
     "schema_version": 1,
     "meta": {
       "name": "my-agent",
       "version": "1.0.0",
       "description": "What this agent does"
     }
   }
   ```

2. Add optional sections as needed:

   - `persona` -- system prompt and directives that shape agent behavior.
   - `permissions` -- operations, domain rules, tool rules, and IFC labels.
   - `upstreams` -- MCP servers the agent depends on (web search, databases, etc.).
   - `image` -- container image reference if the agent runs in a sandbox.

3. Push as an OCI artifact:

   ```bash
   navra agent push my-agent.json oci://quay.io/myorg/my-agent:1.0.0
   ```

## Manifest reference

| Field                        | Type       | Description                                      |
|------------------------------|------------|--------------------------------------------------|
| `schema_version`             | integer    | Always `1`                                       |
| `meta.name`                  | string     | Agent name (used as config key)                  |
| `meta.version`               | string     | Semantic version                                 |
| `meta.publisher`             | string     | Publisher name or organization                   |
| `meta.description`           | string     | Human-readable description                       |
| `meta.license`               | string     | SPDX license identifier                          |
| `persona.system_prompt`      | string     | System prompt injected into the agent's context  |
| `persona.directives`         | string[]   | Additional behavioral directives                 |
| `permissions.operations`     | string[]   | Allowed operation scopes                         |
| `permissions.domain_rules`   | object[]   | Per-domain operation allow lists                 |
| `permissions.tool_rules`     | object[]   | Per-tool policy overrides (allow, deny, approve) |
| `permissions.ifc`            | object     | IFC label declaration (reads/writes)             |
| `upstreams`                  | object[]   | MCP servers the agent requires                   |
| `image`                      | string     | Container image for sandboxed execution          |

## Examples in this directory

- `researcher.json` -- research agent with web search upstream and IFC taint tracking
- `code-reviewer.json` -- read-only code review agent using built-in navra tools
- `security-auditor.json` -- security audit agent with strict deny rules on all write operations
