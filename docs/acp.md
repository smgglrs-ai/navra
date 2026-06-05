# ACP v0.2.0 — Agent Communication Protocol

navra implements the [ACP v0.2.0](https://agentcommunicationprotocol.dev)
specification as a RESTful transport under `/acp/`. ACP enables navra
agents to be discovered and orchestrated by any ACP-compatible client
(Zed, JetBrains, BeeAI, custom tooling).

## What Makes navra's ACP Different

Every ACP endpoint inherits navra's full security stack transparently:

- **IFC taint tracking** — every tool result carries a `DataLabel`.
  Session taint only rises (lattice join). Once a session touches
  untrusted or PII data, all subsequent writes are restricted.
- **Deny-wins ACLs** — path-level and tool-level permission rules
  apply to every `tools/call` inside a run, not just MCP calls.
- **Safety hooks** — pre/post tool-call filtering with regex + NER
  models. PII detected in tool output automatically elevates the
  session's confidentiality label.
- **Approval gates** — high-risk tools return `Pending`, pausing
  the ACP run until a human approves via the resume endpoint.
- **Capability tokens** — agents with scoped CBOR+Ed25519 tokens
  get sandboxed permissions. Token delegation via DID:key.

Vanilla ACP has none of this. The security enforcement happens at the
gateway layer, not the agent layer — agents don't need to be trusted.

## Endpoints

All endpoints are prefixed with `/acp/`. Authentication via bearer
token in the `Authorization` header (same as MCP).

### Discovery

| Method | Path | Description |
|--------|------|-------------|
| GET | `/acp/ping` | Health check (returns `{}`) |
| GET | `/acp/agents` | List agent manifests (paginated: `?limit=10&offset=0`) |
| GET | `/acp/agents/{name}` | Get a single agent manifest |

The gateway agent is always listed. Flow nodes appear as separate
agents with `{flow}-{node}` DNS label names.

### Runs

| Method | Path | Description |
|--------|------|-------------|
| POST | `/acp/runs` | Create a run |
| GET | `/acp/runs/{run_id}` | Get run status |
| POST | `/acp/runs/{run_id}` | Resume an awaiting run |
| POST | `/acp/runs/{run_id}/cancel` | Cancel a run |
| GET | `/acp/runs/{run_id}/events` | List run events |

### Sessions

| Method | Path | Description |
|--------|------|-------------|
| GET | `/acp/session/{session_id}` | Get session details + run history |

## Creating a Run

```bash
curl -X POST http://localhost:9315/acp/runs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "navra",
    "input": [{
      "role": "user",
      "parts": [{"content_type": "text/plain", "content": "/tool ping {}"}]
    }],
    "mode": "sync"
  }'
```

### Run Modes

- **`sync`** — blocks until the run completes, returns the final `Run`
  object with output messages. Default when `mode` is omitted.
- **`async`** — returns `202 Accepted` immediately with the `Run` in
  `created` state. Poll `GET /acp/runs/{run_id}` for status.
- **`stream`** — returns `text/event-stream` (SSE) with typed events
  as the run progresses.

### Tool Call Formats

Input messages can contain tool calls in two formats:

```
/tool ping {"key": "value"}
```

```json
{"tool": "ping", "arguments": {"key": "value"}}
```

Plain text messages without tool call syntax are echoed back as
acknowledgements.

### Agent-Driven Runs

When a chat/generate model is configured, navra uses the ReAct
tool-use loop (`navra-agent`) instead of manual tool call parsing.
The model decides which tools to call, processes results, and
synthesizes a final response. This activates automatically — no
configuration change needed.

## SSE Events

In `stream` mode, the following event types are emitted:

| Event | When |
|-------|------|
| `run.created` | Run accepted |
| `run.in-progress` | Execution started |
| `message.part` | Intermediate result (tool call, trajectory) |
| `message.created` | Output message started |
| `message.completed` | Output message finished |
| `run.completed` | Run finished successfully |
| `run.failed` | Run failed with error |
| `run.awaiting` | Run paused, waiting for approval |
| `run.cancelled` | Run was cancelled |
| `error` | Protocol error |

## Await / Resume

When a tool call triggers an approval gate (e.g., `file_write` on
a protected path), the run transitions to `awaiting` state:

```json
{
  "run_id": "abc-123",
  "status": "awaiting",
  "await_request": {
    "request_id": "approval-1",
    "tool_name": "file_write",
    "arguments": {"path": "/etc/config", "content": "..."}
  }
}
```

To approve:

```bash
curl -X POST http://localhost:9315/acp/runs/abc-123 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "run_id": "abc-123",
    "await_resume": {"approved": true},
    "mode": "sync"
  }'
```

To deny:

```bash
curl -X POST http://localhost:9315/acp/runs/abc-123 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "run_id": "abc-123",
    "await_resume": {"approved": false, "reason": "too risky"},
    "mode": "sync"
  }'
```

Denied runs transition to `failed`.

## Multi-Agent via Flows

Flow definitions (YAML files in `flow_dirs`) are scanned at startup.
Each flow node appears as a separate ACP agent:

```yaml
# flows/security-audit.yaml
kind: dag
name: security-audit
tasks:
  - id: scan
    specialist: vulnerability-scanner
    mandate: Scan for security issues
  - id: fix
    specialist: code-fixer
    mandate: Fix discovered issues
    depends_on: [scan]
```

This produces two ACP agents: `security-audit-scan` and
`security-audit-fix`, each discoverable via `GET /acp/agents`.

## Agent Manifest

```json
{
  "name": "navra",
  "description": "navra gateway agent (v0.6.0)",
  "input_content_types": ["text/plain", "application/json"],
  "output_content_types": ["text/plain", "application/json"],
  "metadata": {
    "framework": "navra",
    "programming_language": "Rust",
    "capabilities": [
      {"name": "file_read", "description": "Read a file"},
      {"name": "git_status", "description": "Show git status"}
    ]
  },
  "status": {
    "avg_run_time_seconds": 2.3,
    "success_rate": 95.0
  }
}
```

The `status` field is populated from live run data — `success_rate`
and `avg_run_time_seconds` are computed from actual completed runs.

## Sessions

Every run gets a session ID (auto-generated if not provided in the
request). Sessions persist in navra's session store and accumulate
IFC taint across runs.

```bash
curl http://localhost:9315/acp/session/my-session \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "id": "my-session",
  "history": [
    "/acp/runs/abc-123",
    "/acp/runs/def-456"
  ]
}
```

## Run Expiration

Finished runs (completed, failed, cancelled) are automatically
removed after 1 hour. A background sweep runs every 5 minutes.
In-progress and awaiting runs are never expired.

## Architecture

```
ACP Client (Zed, JetBrains, BeeAI, curl)
    |
    | REST + SSE
    v
/acp/* endpoints (navra-core/src/transport/acp.rs)
    |
    |-- RunDispatcher trait (pluggable execution)
    |   |-- ToolDispatcher: parse tool calls from text
    |   `-- AgentDispatcher: ReAct loop via run_tool_loop
    |
    |-- RunStore: in-memory run + event + session tracking
    |
    v
McpServer (navra-core)
    |-- Auth (BLAKE3 tokens, capability delegation)
    |-- Permission engine (deny-wins ACLs, tool rules)
    |-- Hook pipeline (safety, approval, sandbox)
    |-- IFC taint tracking (Bell-LaPadula lattice)
    |-- Tools (file, git, exec, rag, voice, vision, ...)
    `-- Upstream MCP servers (proxied, filtered)
```

## Code Layout

```
navra-core/src/acp/
├── mod.rs       — re-exports (RunDispatcher, ToolDispatcher)
├── types.rs     — ACP v0.2.0 data types
├── store.rs     — RunStore + RunMetrics
├── agents.rs    — AgentManifest builder + flow mapping
└── dispatch.rs  — Run execution + RunDispatcher trait

navra-core/src/transport/acp.rs  — Axum REST router (9 endpoints)
navra-server/src/acp_agent.rs    — AgentDispatcher (ReAct loop)
navra-server/src/direct_transport.rs — In-process MCP transport
```

## Spec Compliance

Based on [ACP v0.2.0 OpenAPI](https://github.com/i-am-bee/acp):

| Feature | Status |
|---------|--------|
| GET /ping | Implemented |
| GET /agents (paginated) | Implemented |
| GET /agents/{name} | Implemented |
| POST /runs (sync) | Implemented |
| POST /runs (async) | Implemented |
| POST /runs (stream/SSE) | Implemented |
| GET /runs/{run_id} | Implemented |
| POST /runs/{run_id} (resume) | Implemented |
| POST /runs/{run_id}/cancel | Implemented |
| GET /runs/{run_id}/events | Implemented |
| GET /session/{session_id} | Implemented |
| AgentManifest + metadata | Implemented |
| AgentStatus metrics | Implemented |
| Message + MessagePart | Implemented |
| TrajectoryMetadata | Implemented |
| CitationMetadata | Types only (not generated) |
| AwaitRequest / AwaitResume | Implemented |
| RunMode (sync/async/stream) | All three |
| RunStatus lifecycle | Full (created → in-progress → completed/failed/cancelled/awaiting) |
| Error responses | Implemented (server_error, invalid_input, not_found) |
