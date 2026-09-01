+++
title = "Audit Trail"
description = "Using the gateway blackbox and structured audit log to inspect, verify, and retain agent activity records."
weight = 50

[extra]
toc = true
+++

## Overview

navra records every tool call that passes through the MCP gateway.
There is no opt-in and no configuration toggle -- if navra runs, it
records. The audit trail serves two purposes: operational debugging
(what did an agent do and why was it blocked?) and compliance
evidence (provable, tamper-evident records of AI-driven actions).

Two subsystems work together:

| Subsystem | Scope | Storage |
|-----------|-------|---------|
| **Blackbox** (`navra-core`) | Every MCP tool call at the gateway chokepoint | `~/.local/share/navra/blackbox.db` |
| **Structured audit log** (`navra-memory`) | Per-run tracking of agent runs, tool calls, model calls, flow tasks, and findings | `~/.local/share/navra/audit.db` |

Both are SQLite databases in WAL mode. They survive server restarts
and work without network access.

## What the blackbox records

Every tool call -- allowed or denied -- gets an entry. The blackbox
sits at the MCP dispatch chokepoint, so there is no code path that
bypasses it. Agents are not aware they are being recorded.

### Entry fields

| Field | Description |
|-------|-------------|
| `seq` | Monotonically increasing sequence number |
| `timestamp_ms` | Unix epoch milliseconds |
| `agent_name` | Authenticated agent identity |
| `agent_permissions` | Permission set the agent holds |
| `session_id` | Session identifier for grouping calls |
| `tool_name` | Tool that was invoked (e.g. `file_read`, `git_status`) |
| `tool_args` | JSON arguments, truncated to 4 KiB (UTF-8 safe) |
| `tool_result` | JSON result, truncated to 4 KiB (UTF-8 safe) |
| `outcome` | One of: `allowed`, `denied_acl`, `denied_ifc`, `denied_rate`, `error` |
| `duration_us` | Wall-clock execution time in microseconds |
| `ifc_label` | Information flow control label (e.g. `Trusted:Public`) |
| `obo_sub` | On-behalf-of human subject identifier (OAuth-delegated calls) |
| `trace_id` | W3C trace ID for cross-system correlation (OpenTelemetry, OCSF) |
| `act_chain` | Actor delegation chain (serialized JSON) |
| `prev_hash` | SHA-256 hash of the previous entry |
| `hash` | SHA-256 hash of this entry |

The `outcome` field tells you exactly what happened:

- **`allowed`** -- the call executed normally.
- **`denied_acl`** -- the agent's permission set does not include this tool or path.
- **`denied_ifc`** -- information flow control blocked the call (e.g. writing tainted data to a public channel).
- **`denied_rate`** -- the agent exceeded its rate limit.
- **`error`** -- the call was allowed but the tool returned an error.

## SHA-256 hash chain

Each blackbox entry includes the SHA-256 hash of the previous entry
in its `prev_hash` field. The hash of the current entry is computed
over:

```
SHA-256(seq | prev_hash | agent_name | tool_name | tool_args | tool_result | outcome)
```

The first entry chains from a zero hash (64 hex zeros). This creates
a linked chain where modifying any field in any entry -- or inserting,
deleting, or reordering entries -- breaks the chain from that point
forward.

The hash chain property is formally verified with Verus proofs:

- **Preimage determinism** -- identical inputs always produce the same preimage.
- **Field independence** -- changing any single field changes the preimage.
- **Tamper detection** -- a tampered entry produces a different hash than the stored one.

And verified with Kani model-checking proofs for chain link tamper
detection, preimage field independence, and truncation safety.

## CLI usage

### Tabular summary (last 20 entries)

```bash
navra audit
```

Shows a compact table with sequence number, timestamp, agent, tool,
outcome, and duration.

### Full detail with arguments and results

```bash
navra audit --detail --limit 50
```

The `--detail` flag includes the full (truncated) tool arguments and
results for each entry. Use `--limit` to control how many entries
are shown (default: 20).

### Filtered view

```bash
navra audit --agent claude --tool file_read
```

Both `--agent` and `--tool` accept substring matches. They can be
combined to narrow results further:

```bash
navra audit --detail --agent my-agent
```

### Hash chain integrity check

```bash
navra audit --verify
```

Walks the entire chain from the first entry to the last, recomputing
each hash and checking it against the stored value. Reports the
number of valid entries and, if the chain is broken, the sequence
number of the first tampered entry.

A healthy output looks like:

```
Hash chain verified: 1,247 entries, all valid.
```

A broken chain reports:

```
Hash chain broken at seq 893. 892 entries valid before break.
```

## MCP tool: audit_query

Agents can query the structured audit log programmatically through
the `audit_query` MCP tool, which is registered on the gateway
automatically.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `run_id` | string | Filter by run ID. Returns tool calls for that run. |
| `summary` | boolean | If true, return an `AuditSummary` instead of individual entries. |

### Usage examples

An agent calling `audit_query` with `{"run_id": "abc-123"}` receives
a JSON array of all tool calls from that run, ordered by iteration.

With `{"run_id": "abc-123", "summary": true}`, the response is:

```json
{
  "run_id": "abc-123",
  "tool_call_count": 14,
  "model_call_count": 6,
  "top_tools": [
    ["file_read", 8],
    ["git_status", 4],
    ["bash_exec", 2]
  ],
  "duration_ms": 45000
}
```

Without a `run_id`, the tool returns the latest run metadata.

## Structured audit log

The structured audit log (`navra-memory`) tracks higher-level
constructs beyond individual tool calls.

### Runs

Each agent execution is a **run** with:

| Field | Description |
|-------|-------------|
| `run_id` | Unique identifier |
| `agent_id` | Agent that executed the run |
| `prompt` | The prompt that initiated the run |
| `persona` | Cognitive persona used |
| `model` | Model backend |
| `started_at` / `ended_at` | Unix timestamps |
| `teammates` | Other agents involved |
| `final_report` | Agent's final output |
| `exit_reason` | Why the run ended |

### Tool call entries

Each tool call within a run is logged with the run ID, iteration
number, tool name, arguments, result, duration, ACL decision, IFC
label, and W3C trace ID. This gives a per-iteration timeline of
what happened inside an agent run.

### Model call entries

Every LLM inference call is logged with input/output token counts,
model name, response type, and optional reasoning text. This enables
cost tracking and token budget analysis.

### Flow task tracking

For multi-agent flows, each task records its specialist, model,
status, output, iteration count, token usage, and wall-clock timing.
Tasks support upsert semantics -- a running task is updated in place
when it completes.

### Structured findings

When a flow task produces structured output (JSON with a `findings`
array), the audit log parses and stores individual findings with
file, line, severity, category, description, evidence, remediation,
and confidence fields. This enables querying findings across flows
without parsing raw output.

## Retention

### Blackbox retention

```rust
blackbox.expire_older_than(90); // delete entries older than 90 days
```

This deletes entries with a `timestamp_ms` older than the specified
number of days. The hash chain will be broken for the deleted range,
but `verify_chain` validates the remaining contiguous chain starting
from the oldest surviving entry.

### Structured audit log retention

```rust
audit_log.expire_older_than(90)?; // delete runs, tool calls, and model calls older than 90 days
```

This cascades: deleting a run also deletes its tool calls and model
calls.

**Important:** check your compliance requirements before expiring
audit data. Some regulations mandate minimum retention periods
(e.g. EU AI Act may require keeping records for the lifetime of
the AI system).

## PII sanitization

When a PII filter pipeline is attached, tool arguments and results
are sanitized before they are written to the database. This applies
to both the blackbox and the structured audit log.

```rust
// Blackbox: attach during construction
let blackbox = Blackbox::open(&path)?.with_pii_filter(filter_pipeline);

// Audit log: attach during construction
let audit_log = AuditLog::open(&path)?.with_sanitizer(sanitizer_fn);
```

The sanitizer runs synchronously on every `record()` and
`log_tool_call()` invocation. If the sanitizer errors, the content
is replaced with `[redacted by PII filter]` rather than recording
the unsanitized value.

Patterns redacted by the standard pipeline include email addresses,
social security numbers, credit card numbers, and other PII
identified by the NER model (when installed via `navra pii download`).

## Compliance mapping

The blackbox and audit log together address recording requirements
in several compliance frameworks:

| Framework | Requirement | How navra addresses it |
|-----------|-------------|----------------------|
| **EU AI Act, Article 14** | Human oversight: ability to understand and trace AI decisions | Every tool call is recorded with agent identity, outcome, IFC label, and delegation chain. Hash chain provides tamper evidence. |
| **SOC2 CC6.1** | Logical access controls produce audit trails | All access decisions (allowed, denied_acl, denied_ifc, denied_rate) are recorded with timestamps and agent identity. |
| **ISO 42001** | AI management system: decision records and monitoring | Structured audit log tracks full run lifecycle including model calls, token usage, and findings. |

## Storage details

| Database | Default path | Engine |
|----------|-------------|--------|
| Blackbox | `~/.local/share/navra/blackbox.db` | SQLite, WAL mode |
| Audit log | `~/.local/share/navra/audit.db` | SQLite, WAL mode |

Both databases use `PRAGMA busy_timeout=5000` to handle concurrent
access from multiple server threads.

The blackbox schema includes indexes on `agent_name`, `tool_name`,
`timestamp_ms`, and `trace_id` for efficient querying.

The blackbox resumes its sequence counter and hash chain from the
last entry on restart -- no manual recovery is needed.
