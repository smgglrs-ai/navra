+++
title = "Team Orchestration"
description = "Coordinate multiple agents with teams, blackboard state, and signals."
weight = 15
template = "docs/page.html"

[extra]
toc = true
+++

Teams let a lead agent dynamically spawn, message, and coordinate
teammate agents at runtime. Each teammate is a full MCP agent with
scoped tool access, its own model, and an optional persona from the
cognitive core. Teammates share state through a blackboard and can
create subteams for recursive decomposition.

## Teams vs flows

[Flows](@/docs/guides/flows.md) are static YAML definitions — DAG or
handoff graphs — designed for repeatable pipelines where the work
breakdown is known ahead of time. Teams are dynamic: the lead agent
creates teammates, assigns tasks, and reacts to results
programmatically through MCP tool calls. Use teams when the
decomposition emerges during execution (e.g., a code review lead that
spawns reviewers based on which files changed).

| Dimension       | Flows                | Teams                  |
|-----------------|----------------------|------------------------|
| Definition      | YAML (static graph)  | Tool calls (dynamic)   |
| Decomposition   | Known up front       | Emerges at runtime     |
| Communication   | Mesh mailboxes       | Shared blackboard      |
| Lifecycle       | Engine-managed       | Lead-managed           |
| Subdecomposition| Escalation via `flow_escalate` | Subteams via nested `team_create` |

## Creating a team

The lead agent calls `team_create` with a name and optional budget
constraints. Budget fields cap resource consumption across the entire
team tree (including subteams):

```json
{
  "name": "security-audit",
  "description": "Review authentication and authorization code",
  "max_depth": 2,
  "max_agents": 10,
  "max_tokens": 500000,
  "timeout_secs": 600,
  "max_iterations": 50
}
```

| Budget field     | Default | Description                                  |
|------------------|---------|----------------------------------------------|
| `max_depth`      | Config  | Maximum subteam nesting depth (0 = no subteams) |
| `max_agents`     | Config  | Maximum total agents across the team tree     |
| `max_tokens`     | 500,000 | Maximum total tokens (input + output) across the tree |
| `timeout_secs`   | Config  | Wall-clock timeout for the entire team        |
| `max_iterations` | Config  | Maximum ReAct loop iterations per teammate    |

Server-side defaults come from the `[budget]` section in
`config.toml`. Values passed to `team_create` override the
server defaults for that team.

The tool returns a `team_id` that all subsequent calls reference.

## Adding teammates

Call `team_add` to register a teammate before sending it work:

```json
{
  "team_id": "team-1",
  "name": "auth-reviewer",
  "persona": "security_auditor",
  "model": "auto",
  "locality": "local",
  "operations": ["read", "search", "list"],
  "tools": ["file_tree", "file_grep", "file_read"]
}
```

### Persona

An optional persona name from the cognitive core. Personas inject a
specialist system prompt — mandate, heuristic modules, and behavioral
constraints — into the teammate agent. Call `personas_list` to
discover available personas.

### Model selection

The `model` field accepts a specific model name (from `models_list`)
or `"auto"`. Auto-selection scores available models against the
task's requirements:

- **Tool use** — tasks involving file reads, scans, or searches
  prefer models with `tool_use: "advanced"`.
- **Reasoning** — analysis, synthesis, and cross-file review tasks
  prefer models with `reasoning: "extended"`.
- **JSON compliance** — tasks requesting structured output prefer
  `json_compliance: "strict"`.
- **Cost and speed** — local/free models are preferred as tiebreakers
  to minimize API spend.

When no model cards have agentic metadata, auto-selection falls back
to parameter-count heuristics: 12-20B models for specialist tasks
(tool use, reasoning), smaller models for simple gathering.

### Locality

Controls where data is processed:

- `"local"` — data stays on-device; only local models are used.
  Required for sensitive data under IFC constraints.
- `"remote"` — cloud API models (e.g., Claude via Vertex AI).
- `"auto"` — IFC decides based on data labels at runtime.

### Operations and tools

Operations are capability-level permissions (`"read"`, `"search"`,
`"list"`, `"write"`, `"edit"`, `"delete"`, `"git.commit"`). Tools
are the specific MCP tools the teammate can call. Both default to a
safe read-only set if omitted:

- **Default operations**: `read`, `search`, `list`
- **Default tools**: `file_tree`, `file_grep`, `file_read`, plus
  infrastructure tools (`team_bb_publish`, `team_bb_read`,
  `team_bb_notifications`, `models_list`, `personas_list`,
  `flow_escalate`, `flow_status`, `flow_result`)

When `operations` includes write-class operations (`write`, `edit`,
`delete`), the auto-detected tool set expands to include write tools
registered on the server.

### Other parameters

- `temperature` — model temperature (0.0 = deterministic, 1.0 =
  creative). Omit for the model's default.
- `max_tokens` — maximum output tokens per response. Omit for
  unlimited (recommended for local models).
- `force_tool_iterations` — force tool calls for this many initial
  iterations before allowing a text-only response. Default: 1.

## Messaging teammates

Call `team_message` to send a task to a registered teammate:

```json
{
  "team_id": "team-1",
  "to": "auth-reviewer",
  "message": "Review all authentication middleware in src/auth/ for token validation vulnerabilities. Publish findings to the blackboard under 'auth-findings'."
}
```

The teammate runs **asynchronously** as a background task. It is
spawned as a full agent with its own ReAct loop, MCP tool access, and
the system prompt assembled from its persona. The lead agent
continues immediately and can send tasks to other teammates in
parallel.

### Broadcast

Set `to` to `"*"` to broadcast a message to all teammates
simultaneously.

### What happens at spawn time

1. A **scoped capability token** is minted for the teammate, limited
   to its declared operations and tools, with a TTL matching the
   team's remaining timeout. The token uses delegated capabilities
   chained from the server's root payload.
2. The **model is resolved** — `"auto"` triggers the scoring
   algorithm described above; unknown models fall back to auto.
3. The **system prompt** is assembled from the persona (if set) plus
   team context (available tools, team ID).
4. The agent is spawned in the configured execution mode (see
   [Execution modes](#execution-modes) below).
5. The **task handle** is stored so the team can abort it on shutdown
   or timeout.

## Checking status and results

### team_status

Returns a snapshot of the team: each teammate's name, status, model,
tools, and whether output is available; blackboard keys; token usage;
and budget remaining.

```json
{ "team_id": "team-1" }
```

Teammate statuses: `idle` (registered, no task), `working` (task in
progress), `done` (output available), `failed` (error occurred).

### team_result

Reads a specific teammate's output:

```json
{
  "team_id": "team-1",
  "teammate": "auth-reviewer"
}
```

Returns the teammate's name, status, and output text. For
containerized agents, the output is either parsed JSON from stdout or
blackboard findings (the agent can publish results under
`findings/<name>` as a preferred output channel).

## Blackboard state sharing

The blackboard is a key-value store shared across all teammates in a
team. It serves as the primary channel for cross-agent knowledge
sharing.

### Publishing

Any teammate calls `team_bb_publish` to write a key-value pair:

```json
{
  "team_id": "team-1",
  "key": "auth-findings",
  "value": "Found 3 endpoints missing token validation: /api/admin/users, /api/admin/roles, /api/internal/metrics"
}
```

Publishing a key that already exists overwrites the previous value.
Each entry records the author, timestamp (seconds since team
creation), and the IFC data label of the publishing agent's context.

### Reading

Call `team_bb_read` with a key to retrieve the full entry (value,
author, timestamp):

```json
{
  "team_id": "team-1",
  "key": "auth-findings"
}
```

### Notifications

Teammates call `team_bb_notifications` to discover new entries
published by other teammates since their last check. The response
contains only metadata (key, author, timestamp) — not the content
itself. The agent then calls `team_bb_read` on interesting keys.

```json
{ "team_id": "team-1" }
```

Notifications exclude entries authored by the calling agent and
automatically advance the agent's "last seen" timestamp so subsequent
calls only return new entries.

### IFC labels on blackboard entries

Each blackboard entry carries the IFC data label of the context in
which it was published. When another agent reads the entry, the label
propagates via taint-on-read — if the entry was published from a
context handling sensitive data, reading agents inherit that taint.
This prevents sensitive findings from being exfiltrated through the
blackboard to a remote model.

## Agent signals

The `agent_signal` tool sends cooperative signals to a running
in-process teammate. Signals are checked between iterations of the
agent's ReAct loop — they are not preemptive.

```json
{
  "team_id": "team-1",
  "agent_id": "auth-reviewer",
  "signal": "interrupt"
}
```

| Signal      | Behavior                                          |
|-------------|---------------------------------------------------|
| `pause`     | Stop iterating until `resume` is received         |
| `resume`    | Continue after a pause (resets signal to none)     |
| `interrupt` | Cancel current work, return partial result         |
| `terminate` | Graceful shutdown after the current iteration      |

Signals only work for **in-process** agents. Containerized and
OpenShell agents do not have a signal handle — use `team_shutdown` to
stop them.

If the signal sender is dropped (e.g., the team is shut down), a
paused agent treats it as a terminate signal and exits.

## Models and personas discovery

Two tools help the lead agent choose models and personas when
building its team:

### models_list

Returns composite model cards with three layers:

- **vendor** — auto-populated from the model registry (family,
  parameters, quantization, context window, tasks, license).
- **agentic** — operator-defined capabilities for agent selection
  (strengths, weaknesses, recommended tasks, tool use level, cost
  tier, speed tier, reasoning depth, JSON compliance, locality).
- **runtime** — learned from actual agent runs (total calls, success
  rate, average latency, per-task breakdown). Empty until the model
  has been used.

### personas_list

Returns available specialist personas from the cognitive core. Each
persona has a name, display name, core mandate, and heuristic
modules. Use the name in `team_add`'s `persona` field.

## Execution modes

`team_message` spawns teammates in one of three execution modes,
selected automatically based on server configuration:

### OpenShell (preferred when configured)

When `openshell_gateway` is set, teammates are spawned as OpenShell
sandboxes. The `navra-agent` binary runs inside a managed sandbox
with workspace mounted at `/workspace`. The sandbox ID is registered
in the exec state so the agent can call `exec_run` to execute
commands inside its sandbox. Sandboxes are destroyed on completion or
timeout.

### Podman container

When `containerized = true` and Podman is available, teammates run
in rootless Podman containers with:

- `slirp4netns` networking (reaches the host gateway via `10.0.2.2`)
- Read-only filesystem with `no-new-privileges`
- Configurable memory, CPU, and PID limits
- Cognitive core directory mounted read-only (when persona is set)
- A scoped capability token passed via `NAVRA_TOKEN` environment
  variable

Container limits are set in `config.toml`:

```toml
[server]
containerized = true
agent_image = "navra-agent:latest"
container_memory = "2g"
container_cpus = "2"
container_pids = 256
```

### In-process (fallback)

When neither OpenShell nor Podman is available, teammates run as
in-process async tasks using `navra-agent`'s `Agent::builder()`. This
mode supports cooperative signals (pause, resume, interrupt,
terminate) and context management features like tool output
compression and conversation compaction. It also supports the full
range of model backends: local models via Ollama/vLLM through the
gateway's `/v1` endpoint, or Claude via the Anthropic API or
Vertex AI.

All three modes acquire the GPU semaphore before running, ensuring
concurrent agent executions don't exceed the configured
`max_parallel` limit.

## Shutdown

The lead agent **must** call `team_shutdown` before producing its
final response:

```json
{ "team_id": "team-1" }
```

Shutdown performs the following:

1. Sends `Terminate` signal to all in-process agents.
2. Aborts all running task handles.
3. Stops any Podman containers (with a 5-second grace period).
4. Decrements the global agent counter.
5. Returns final statistics: members removed, tasks aborted,
   containers stopped, total tokens used, blackboard entry count,
   and team duration.

If the team timeout expires before shutdown, running teammates are
automatically failed with a timeout error and their containers are
stopped.

## Example: code review team

A complete team orchestration flow for reviewing a pull request:

```text
Lead agent:
  1. team_create("pr-review", max_agents=5, timeout_secs=300)
  2. personas_list() → pick security_auditor, code_quality
  3. models_list() → pick models based on task requirements
  4. team_add("security", persona="security_auditor", model="auto")
  5. team_add("quality", persona="code_quality", model="auto")
  6. team_message("security", "Review src/auth/ for vulnerabilities...")
  7. team_message("quality", "Check error handling patterns in src/...")
  8. team_status() → poll until both are "done"
  9. team_result("security") → read security findings
  10. team_result("quality") → read quality findings
  11. team_shutdown() → clean up
  12. Synthesize findings into a final review
```

Teammates can also coordinate through the blackboard — for example,
the security reviewer might publish high-severity findings that the
quality reviewer reads and cross-references.
