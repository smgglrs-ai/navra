# Integrating an MCP Server with smgglrs

This guide covers how to connect any MCP server to smgglrs as an
upstream, using Syllogis (a French administrative law analysis
server) as the running example. The same patterns apply to any
domain-specific MCP server.

## 1. What smgglrs provides to your MCP server

smgglrs is a security gateway that sits between AI agents and
upstream MCP servers. When your server runs behind smgglrs, every
tool call passes through:

- **Authentication** -- BLAKE3 token verification identifies the
  calling agent.
- **Path ACLs** -- Deny-wins glob rules control which files and
  directories the agent can access through your tools.
- **Per-tool rules** -- Allow, deny, or require approval for
  specific tools by name (glob patterns supported).
- **Information Flow Control (IFC)** -- Data labels propagate
  through tool chains. If an agent reads confidential data, IFC
  prevents it from flowing to lower-trust outputs.
- **Safety filters** -- Regex and ML-based filters redact secrets,
  PII, and custom patterns from all tool inputs and outputs.
- **Human-in-the-loop approval** -- Sensitive operations pause and
  notify the user via D-Bus, system tray, CLI, or MCP.
- **Audit trail** -- Every tool call is logged with agent identity,
  arguments, result, duration, and ACL decision.

Your server does not need to implement any of this. smgglrs
applies it uniformly to all upstream traffic.

### The self-describing MCP server pattern

The most effective upstream servers expose three things:

1. **Tools** -- The operations agents can perform.
2. **Resources** -- Data the agent can read (optional).
3. **Persona prompts** -- Domain methodology that tells the agent
   *how* to use the tools. Without this, the agent may ignore your
   tools entirely.

## 2. Making your MCP server smgglrs-compatible

### No SDK required

smgglrs proxies standard MCP (JSON-RPC 2.0 over stdio or HTTP).
Any MCP server works as an upstream. Your server does not need to
import smgglrs crates or implement smgglrs-specific interfaces.

### Expose a persona prompt

This is the single most impactful thing you can do. Without a
persona prompt, agents use their default persona and may not know
your tools exist. The prompt tells the agent what methodology to
follow and which tools to call.

**Naming convention**: prefix your persona prompt name with
`persona:` (e.g., `persona:legal_analyst`). smgglrs auto-discovers
prompts with this prefix at startup and registers them as available
personas -- no YAML configuration needed on the smgglrs side. You
can also expose non-persona prompts (without the prefix) for
injection into other personas via `mcp_prompts`.

Implement `prompts/list` and `prompts/get` in your MCP server:

```json
// prompts/list response
{
  "prompts": [
    {
      "name": "persona:legal_analyst",
      "description": "French administrative law analyst"
    },
    {
      "name": "legal_analysis",
      "description": "French administrative law analysis methodology",
      "arguments": [
        {
          "name": "case_description",
          "description": "The legal case to analyze",
          "required": false
        }
      ]
    }
  ]
}
```

```json
// prompts/get request
{
  "name": "legal_analysis",
  "arguments": { "case_description": "Refusal of building permit" }
}

// prompts/get response
{
  "messages": [
    {
      "role": "user",
      "content": {
        "type": "text",
        "text": "You are a French administrative law analyst. Follow this methodology:\n\n1. Extract the legal facts from the case description\n2. Use search_codes to find applicable articles in relevant codes\n3. Use search_jurisprudence to find related case law\n4. Build a legal syllogism: major premise (rule) + minor premise (facts) = conclusion\n5. Present your analysis with article citations and case references\n\nAlways cite real article numbers found via search_codes. Never fabricate article numbers from memory."
      }
    }
  ]
}
```

### Structure your persona prompt

Include in your prompt:

- **Methodology** -- Step-by-step process the agent should follow.
- **Tool usage instructions** -- Which of your tools to call and
  when (agents cannot infer this reliably).
- **Constraints** -- What the agent must NOT do (e.g., "never
  fabricate article numbers").
- **Output format** -- How the agent should structure its response.

### Tool naming conventions

Prefix all tool names with your server name. smgglrs aggregates
tools from multiple upstream servers into a single namespace.
Prefixing prevents collisions:

- `syllogis_search_codes` (not `search_codes`)
- `syllogis_search_jurisprudence` (not `search`)
- `syllogis_build_syllogism` (not `build_syllogism`)

### Resource exposure

If your server manages domain-specific data (code databases,
document collections), expose them as MCP resources. smgglrs
proxies `resources/list` and `resources/read`, applying the same
ACLs and safety filters as tool calls.

## 3. Configuration

### Adding your server as an upstream

Edit `~/.config/smgglrs/config.toml`.

**stdio transport** (smgglrs manages the subprocess):

```toml
[[upstream]]
name = "syllogis"
transport = "stdio"
command = ["python3", "-m", "syllogis.mcp_server"]
cwd = "/home/user/syllogis"
retry_base_delay_ms = 1000
retry_max_delay_ms = 30000
retry_budget_secs = 600
request_timeout_secs = 45
```

**HTTP transport** (your server runs independently):

```toml
[[upstream]]
name = "syllogis"
transport = "http"
url = "http://localhost:8200/mcp"
request_timeout_secs = 30
```

Retry fields are optional. When omitted, connection failures are
immediate (no automatic reconnection).

### Permission sets

Create a permission set that grants access to your server's tools
and the paths they need:

```toml
[permissions.legal_analyst]
allow = ["~/Cases/**", "~/Legal/**"]
deny = ["**/.env", "**/*secret*"]
operations = ["read", "search", "list"]
approve = ["write"]
safety = "standard"
default_tool_policy = "allow"

# Allow all Syllogis tools without restriction
[[permissions.legal_analyst.tool_rules]]
tool = "syllogis_*"
policy = "allow"

# Require approval for any tool that writes
[[permissions.legal_analyst.tool_rules]]
tool = "*_write"
policy = "approve"
```

### Register an agent with this permission set

```toml
[[agents]]
name = "claude-code"
token_hash = "<blake3-hash>"
permissions = "legal_analyst"
```

Generate the token:

```bash
smgglrs token generate --name claude-code --permissions legal_analyst
```

### Safety profiles

Choose a safety level per permission set:

| Profile | Behavior |
|---------|----------|
| `standard` | All regex + ML filters, redact matches |
| `secrets-only` | Only secret patterns, allow PII |
| `block` | Block the entire response on any match |
| `none` | No filtering (full trust) |

Add custom patterns for domain-specific sensitive data:

```toml
[[permissions.legal_analyst.safety_patterns]]
category = "case-number"
pattern = "\\bDossier\\s+\\d{4}/\\d{6}\\b"

[[permissions.legal_analyst.safety_patterns]]
category = "national-id"
pattern = "\\b[12]\\s?\\d{2}\\s?\\d{2}\\s?\\d{2}\\s?\\d{3}\\s?\\d{3}\\s?\\d{2}\\b"
```

## 4. MCP-sourced personas

smgglrs's cognitive system (the Weaver) assembles system prompts
from persona definitions. Personas can come from three sources:
auto-discovery from upstream prompts (zero config), thin YAML
pointers, or full local YAML files.

### Auto-discovery (zero config)

If your MCP server exposes a prompt whose name starts with
`persona:`, smgglrs auto-discovers it at startup. No YAML file
is needed on the smgglrs side.

Name your prompt `persona:<name>` in your `prompts/list` response:

```json
{
  "prompts": [
    {
      "name": "persona:legal_analyst",
      "description": "French administrative law analyst"
    }
  ]
}
```

When smgglrs connects to your upstream and calls `prompts/list`,
it scans for prompts with the `persona:` prefix. For each match:

- The part after `persona:` becomes the persona name
  (`legal_analyst`)
- The prompt's `description` becomes the persona's `display_name`
- A `source` is set pointing to the upstream and prompt name
- The `core_mandate` is left empty (resolved at runtime via
  `prompts/get`)

This is the simplest integration path. Add your server as an
upstream in `config.toml`, and the persona is available
immediately.

Local YAML persona files always take precedence. If a persona
named `legal_analyst` exists in `cognitive_core/personas/`, the
auto-discovered one from the upstream is skipped.

### Advanced: thin YAML pointer

For cases where you need local overrides (extra heuristics,
specific tools, prompt injection), create a thin persona YAML
that fetches its mandate from your server:

```yaml
# personas/syllogis_legal.yaml
persona_name: syllogis_legal
display_name: "Syllogis Legal Analyst"
source:
  upstream: syllogis
  prompt: legal_analyst_persona
  arguments:
    jurisdiction: french_admin
heuristics:
  - module: legal
    facets: [evidence_analysis, source_verification]
```

When this persona is loaded, smgglrs calls `prompts/get` on the
`syllogis` upstream with the specified arguments. The returned
prompt becomes the persona's `core_mandate`. The YAML stays thin
-- it carries identity and local overrides, but the domain
methodology lives in your server.

This approach is useful when you want to:
- Add local heuristics or directives not provided by the upstream
- Pass specific arguments to `prompts/get`
- Override the display name or tools list
- Combine prompts from multiple upstreams

### Injecting additional prompts

A persona can also inject specific upstream prompts at precise
positions in the assembled system prompt:

```yaml
persona_name: legal_analyst
display_name: "Legal Analyst"
core_mandate: "Analyze legal cases with rigorous methodology."
heuristics:
  - module: legal
    facets: [evidence_analysis]
mcp_prompts:
  - upstream: syllogis
    prompt: legal_analysis
    inject_position: after_mandate
    arguments:
      case_description: "{{ input }}"
  - upstream: syllogis
    prompt: legal_syllogism
    inject_position: after_heuristics
```

Injection positions:

| Position | Where |
|----------|-------|
| `before_mandate` | Before the core mandate |
| `after_mandate` | After the mandate, before heuristics |
| `after_heuristics` | After heuristics, before examples |
| `after_examples` | At the end of the system prompt |

Template variables like `{{ input }}` are replaced with the user's
prompt before the `prompts/get` call.

### Hybrid personas

Combine an upstream mandate with local heuristics for the best of
both worlds. The upstream provides domain methodology; local
heuristics add behavioral constraints:

```yaml
persona_name: hybrid_legal
display_name: "Hybrid Legal Analyst"
source:
  upstream: syllogis
  prompt: legal_analyst_persona
core_mandate: "Local fallback if upstream is unavailable."
heuristics:
  - module: legal
    facets: [evidence_analysis, source_verification]
  - module: output_quality
    facets: [structured_reasoning, citation_format]
mcp_prompts:
  - upstream: syllogis
    prompt: legal_syllogism
    inject_position: after_heuristics
```

If `source` is present and resolves successfully, its content
replaces `core_mandate`. If resolution fails, the local
`core_mandate` is used as fallback.

### How the Weaver assembles the final prompt

The Weaver builds the system prompt in this order:

1. Core directives (if `loads_directives: true`)
2. `before_mandate` injected prompts
3. Core mandate (from `source` or YAML)
4. `after_mandate` injected prompts
5. Heuristic facets
6. `after_heuristics` injected prompts
7. Few-shot examples
8. `after_examples` injected prompts

Each injected section is labeled (e.g., `[syllogis:legal_analysis]`)
for traceability.

## 5. Runtime behavior

### What happens when an agent connects

1. Agent sends `initialize` to smgglrs with a bearer token.
2. smgglrs authenticates the token, creates a session.
3. Agent calls `tools/list`. smgglrs returns tools from all enabled
   modules (built-in + upstream). Your server's tools appear
   alongside docs, git, and other modules.
4. Agent calls `prompts/list`. smgglrs returns prompts from all
   sources, including your upstream's prompts.
5. If the agent uses a persona with `mcp_prompts` or `source`
   entries pointing to your upstream, smgglrs calls `prompts/get`
   on your server and injects the result into the system prompt.
6. Agent calls your tools via `tools/call`. smgglrs forwards the
   call to your server after checking auth, ACLs, tool rules, and
   safety filters. The response passes through safety filters and
   IFC taint tracking before reaching the agent.

### IFC taint tracking on upstream tool calls

When an agent calls one of your tools, the result may carry data
from your domain. smgglrs assigns an IFC label to the result based
on the tool's data source. If the agent later tries to write that
data to a lower-trust destination, the `tainted_write_policy` in
the permission set controls what happens:

```toml
tainted_write_policy = "approve"  # require human approval
```

Options: `allow`, `approve`, `deny`.

## 6. Multi-agent flows

### Using your tools in DAG flows

smgglrs-flow supports DAG execution where multiple specialist
agents work on tasks with dependencies. Your upstream's tools are
available to any agent in the flow:

```yaml
# flows/legal_analysis.yaml
name: legal_case_analysis
tasks:
  - id: research
    specialist: researcher
    mandate: "Find all applicable codes and jurisprudence"
    tools: [syllogis_search_codes, syllogis_search_jurisprudence]
  - id: analysis
    specialist: legal_analyst
    mandate: "Build legal syllogism from research results"
    depends_on: [research]
    tools: [syllogis_build_syllogism]
  - id: review
    specialist: reviewer
    mandate: "Verify citations and reasoning"
    depends_on: [analysis]
```

### Cross-validation

For high-stakes outputs, configure verifier agents that
independently assess the result:

```yaml
  - id: analysis
    specialist: legal_analyst
    mandate: "Build legal syllogism"
    verification:
      agents: 2
      threshold: majority
```

### Audit trail

Every tool call in a flow is recorded in the audit log with:
`run_id`, `agent_id`, `tool_name`, `tool_args`, `tool_result`
(truncated), `duration_ms`, `acl_decision`, `ifc_label`. Query
the audit log via the `audit_query` MCP tool.

## 7. Complete example: Syllogis integration

Syllogis is an MCP server for French administrative law analysis.
It exposes three tools and a persona prompt.

### Tools

| Tool | Description |
|------|-------------|
| `syllogis_search_codes` | Search legislative codes by keyword and code name |
| `syllogis_search_jurisprudence` | Search administrative court decisions |
| `syllogis_build_syllogism` | Structure a legal syllogism from premises |

### Persona prompt

Syllogis exposes a `persona:legal_analyst` prompt via
`prompts/list`. When smgglrs connects, it auto-discovers this
prompt and registers a `legal_analyst` persona pointing to
Syllogis. No YAML file is needed.

### Zero-config setup

The simplest integration: add Syllogis as an upstream and
configure permissions. The persona is auto-discovered.

```toml
# ~/.config/smgglrs/config.toml

[server]
socket = "$XDG_RUNTIME_DIR/smgglrs/smgglrs.sock"
tcp = "127.0.0.1:9315"

[[upstream]]
name = "syllogis"
transport = "stdio"
command = ["python3", "-m", "syllogis.server"]
cwd = "/home/user/syllogis"
retry_base_delay_ms = 1000

[[agents]]
name = "claude-code"
token_hash = "20a8c34a..."
permissions = "legal_analyst"

[permissions.legal_analyst]
allow = ["~/Cases/**", "~/Legal/**", "~/Code/syllogis/**"]
deny = ["**/.env", "**/*secret*"]
operations = ["read", "search", "list"]
approve = []
safety = "standard"
default_tool_policy = "allow"

[[permissions.legal_analyst.tool_rules]]
tool = "syllogis_*"
policy = "allow"
```

At startup, smgglrs connects to Syllogis, calls `prompts/list`,
finds `persona:legal_analyst`, and registers it as an available
persona. The agent can use this persona immediately.

### Advanced: adding local overrides

If you need local heuristics or prompt injection beyond what the
upstream provides, create an optional persona YAML. This takes
precedence over the auto-discovered persona:

```yaml
# cognitive_core/personas/syllogis_legal.yaml
persona_name: legal_analyst
display_name: "Syllogis Legal Analyst"
source:
  upstream: syllogis
  prompt: persona:legal_analyst
heuristics:
  - module: legal
    facets: [evidence_analysis, source_verification]
mcp_prompts:
  - upstream: syllogis
    prompt: legal_analysis
    inject_position: after_mandate
    arguments:
      case_description: "{{ input }}"
```

This hybrid approach fetches the core mandate from Syllogis but
adds local heuristics and injects the `legal_analysis` prompt
at the right position in the system prompt.

### What the agent sees at runtime

After initialization, the agent's `tools/list` returns all
gateway tools plus the Syllogis tools.

With the zero-config path, the system prompt contains the core
mandate fetched from `syllogis:persona:legal_analyst` at runtime.

With the advanced YAML override, the system prompt contains:

1. The core mandate fetched from `syllogis:persona:legal_analyst`
2. The `legal_analysis` methodology injected after the mandate
3. Local heuristics for evidence analysis and source verification

When the agent processes a query like "Is the refusal of a
building permit by the mayor of Toulouse legal?", it follows the
injected methodology: calls `syllogis_search_codes` to find
applicable urbanisme articles, calls
`syllogis_search_jurisprudence` for relevant case law, then
structures the analysis as a legal syllogism.

## 8. Security considerations

### PII detection on upstream responses

All upstream tool responses pass through the full PII pipeline
before reaching the agent. This includes regex patterns (US + EU),
NER models (English and multilingual), and file path analysis.
By default, detected PII is redacted:

```
Original:  Dossier 2024/123456, SSN 1 85 12 75 123 456 78
Redacted:  Dossier 2024/123456, SSN [REDACTED:pii-ssn]
```

PII can also be pseudonymized (consistent replacement within a
session) instead of redacted, depending on the filter action
configuration. Custom PII patterns can be defined in config via
`[[pii_patterns]]` for domain-specific identifiers:

```toml
[[pii_patterns]]
category = "case-number"
pattern = "\\bDossier\\s+\\d{4}/\\d{6}\\b"
action = "pseudonymize"
```

For data subjects covered by GDPR, the gateway provides tools for
right of access (`pii_report`), right to erasure
(`memory_purge_pii`), and consent tracking (`pii_consent`). These
apply to all data stored by the gateway, including data originating
from upstream tool responses.

### IFC labels on upstream tool results

Data returned by your tools is labeled in the IFC lattice. If
your server handles sensitive data, configure trusted paths so
that reads from known-safe locations keep their Trusted label:

```toml
trusted_paths = ["~/Code/syllogis/data/**"]
```

### Approval gates

Require human approval for sensitive operations exposed by your
server:

```toml
[[permissions.legal_analyst.tool_rules]]
tool = "syllogis_submit_filing"
policy = "approve"
```

The agent receives an approval-needed response. The user is
notified via D-Bus notification, system tray, or CLI. The agent
retries after approval.

### Audit trail for compliance

All upstream tool calls are recorded in the gateway audit log. For
compliance-sensitive domains (legal, medical, financial), tag the
permission set:

```toml
compliance = ["EU-AI-Act-Art-14", "SOC2-CC6.1"]
```

This is informational -- logged at startup for audit trail
purposes. The actual enforcement comes from the ACLs, approval
gates, and safety filters described above.
