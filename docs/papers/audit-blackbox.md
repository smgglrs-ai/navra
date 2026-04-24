# Always-On Audit for AI Agent Gateways: A Hash-Chained Blackbox Approach

**Workshop paper outline -- draft**

## 1. Title and Abstract

**Title**: Always-On Audit for AI Agent Gateways: A Hash-Chained Blackbox Approach

**Abstract** (~100 words):
AI agents increasingly make autonomous decisions through tool calls,
yet most agent frameworks provide no audit trail. When failures occur,
the sequence of tool calls, arguments, and outcomes is lost. We present
a gateway-level blackbox recorder embedded in smgglrs, an MCP gateway
daemon. The blackbox records every tool call at the protocol chokepoint
with no opt-in required. Entries are append-only in SQLite and
SHA-256 hash-chained for tamper detection. We describe the design,
demonstrate its value through a real debugging case study, and map the
approach to EU AI Act, SOC2, and ISO 42001 compliance requirements.

## 2. Problem

AI agents make autonomous decisions through sequences of tool calls.
A single user prompt can trigger dozens of tool invocations across
multiple agents, each reading files, querying databases, or modifying
system state. When something goes wrong -- a wrong file is edited, a
query returns unexpected results, a permission is denied -- the failure
is opaque. The agent reports a vague error or an empty result, and the
operator has no way to reconstruct what happened.

Current approaches to agent observability are inadequate:

- **Agent-level instrumentation** is opt-in. Each agent framework
  (LangChain, CrewAI, Goose) implements its own logging, if any.
  An agent can bypass or disable its own instrumentation.
- **LLM provider logs** capture model calls but not tool calls.
  The critical decision -- which tool was called with which arguments
  and what it returned -- is invisible.
- **Application logging** is fragmented. Each tool logs independently
  (if at all), with no correlation across a session or agent identity.

The result: multi-agent failures are undebuggable, compliance audits
are impossible, and there is no forensic record of AI-driven actions
on a system.

## 3. Design

### 3.1 Gateway-level recording

smgglrs is an MCP (Model Context Protocol) gateway. All tool calls from
any connected agent pass through a single function:
`McpServer::handle_call_tool`. This is the chokepoint. By recording at
this layer, every tool call is captured regardless of which agent made
it, which framework it uses, or whether the agent cooperates.

The blackbox is **always on**. There is no configuration flag, no
opt-in, no per-agent toggle. If smgglrs runs, it records. Agents are
not informed that recording is occurring.

### 3.2 Storage: append-only SQLite

Entries are stored in a SQLite database (`~/.local/share/smgglrs/blackbox.db`).
The table uses `INSERT` only -- no `UPDATE` or `DELETE` operations exist
in the codebase. The schema is a single `blackbox` table with indexes
on `agent_name`, `tool_name`, and `timestamp_ms`.

SQLite provides durability (WAL mode), portability (single file), and
zero-configuration operation. The blackbox database is separate from
application data, preventing accidental deletion during cleanup.

### 3.3 Hash chain: tamper detection

Each entry includes the SHA-256 hash of the previous entry's hash.
The first entry chains from a zero hash (64 hex zeros). The hash
preimage is:

```
SHA-256(seq | prev_hash | agent_name | tool_name | tool_args | tool_result | outcome)
```

Verification walks the chain from entry 1, recomputing each hash and
comparing it to the stored value. A mismatch at sequence N means
entries at or after N have been modified. The `verify_chain` method
returns `(valid_count, Option<first_broken_seq>)`.

On startup, the blackbox resumes from the last stored sequence number
and hash, so the chain is continuous across server restarts.

## 4. What Is Recorded

Each blackbox entry captures:

| Field | Description |
|-------|-------------|
| `agent_name` | Identity of the calling agent (from auth token) |
| `agent_perms` | Permission set of the agent |
| `session_id` | MCP session identifier |
| `tool_name` | Name of the tool invoked |
| `tool_args` | Arguments passed to the tool (truncated to 4 KB) |
| `tool_result` | Result returned by the tool (truncated to 4 KB) |
| `outcome` | One of: `allowed`, `denied_acl`, `denied_ifc`, `denied_rate`, `error` |
| `duration_us` | Wall-clock execution time in microseconds |
| `ifc_label` | Information Flow Control label after the call |
| `timestamp_ms` | Unix timestamp in milliseconds |
| `prev_hash` | SHA-256 hash of the previous entry |
| `hash` | SHA-256 hash of this entry |

Truncation is UTF-8 safe (backs up to the nearest character boundary).
Large tool results (e.g., full file contents) are clipped to 4 KB,
which is sufficient to capture error messages and short outputs while
bounding storage growth.

## 5. CLI Interface

The `smgglrs audit` command queries the blackbox offline (the server
need not be running):

| Command | Effect |
|---------|--------|
| `smgglrs audit` | Tabular summary of last 20 entries (seq, agent, outcome, tool, duration, IFC label) |
| `smgglrs audit --detail` | Full entries with truncated args and result (120 chars in CLI) |
| `smgglrs audit --limit 100` | Show last 100 entries |
| `smgglrs audit --tool docs_tree` | Filter to a specific tool |
| `smgglrs audit --agent claude` | Filter to a specific agent |
| `smgglrs audit --verify` | Verify hash chain integrity, report valid count and first broken sequence |

Filters compose: `--agent X --tool Y` shows only entries matching both.

## 6. Case Study: The docs_tree Bug

During development of a multi-agent security audit demo, the lead
agent delegated file discovery to a teammate. The teammate called
`docs_tree` with the argument `{"path": "."}`. The tool requires
absolute paths and returned an error: "Path must be absolute."

**Without the blackbox**, this failure was invisible. The agent
received an empty file listing, produced an empty report, and exited
normally. No error appeared in stdout. The operator saw only an
unhelpful final report with zero findings. Debugging required reading
agent source code and guessing which tool call failed.

**With the blackbox**, the operator ran `smgglrs audit --detail` and
immediately saw:

```
seq=47 agent=anonymous tool=docs_tree outcome=error duration=12us
  args:   {"path":"."}
  result: Error: Path must be absolute. Received: "."
  ifc:    Trusted/Public
```

The bug -- a relative path passed by the model -- was found in
30 seconds. The fix was a one-line default in `docs_tree` to treat
missing or relative paths as the project root.

This case illustrates the core value proposition: the blackbox
captures failures that agents silently swallow.

## 7. Compliance Mapping

| Requirement | Standard | How the blackbox addresses it |
|-------------|----------|-------------------------------|
| Human oversight of AI decisions | EU AI Act, Article 14 | Every tool call is recorded with agent identity, arguments, result, and outcome. Operators can reconstruct the full decision chain post-hoc. |
| Audit trails for system operations | SOC2 CC6.1 | Append-only, hash-chained entries provide a tamper-detectable log of all gateway operations. |
| Records of AI system decisions | ISO 42001 | Tool call records serve as decision records: what the agent did, what data it accessed, what the system allowed or denied. |

The hash chain provides tamper detection without requiring external
infrastructure (no certificate authority, no blockchain). An auditor
can verify chain integrity with a single CLI command.

## 8. Limitations

- **Anonymous agents**: Without auth configuration, all agents appear
  as "anonymous". The blackbox records the identity the gateway knows;
  if the gateway has no auth, agent attribution is lost.
- **Tool calls only**: The blackbox records MCP tool calls. It does
  not record model calls (prompt, completion, token usage, reasoning
  text). The model's decision process between tool calls is not
  captured at the gateway layer.
- **SHA-256, not signed**: The hash chain detects tampering (modified
  entries break the chain) but does not provide attribution. An
  attacker with write access to the SQLite file can rewrite the
  entire chain with valid hashes. Signing entries with the server's
  Ed25519 identity key would add attribution but is not yet
  implemented.
- **No rotation or archival**: The blackbox grows indefinitely. For
  long-running deployments, external log rotation is required.
- **Truncation loses data**: 4 KB truncation means large tool
  arguments or results are partially recorded. This is a deliberate
  tradeoff between completeness and storage cost.

## 9. Conclusion

Audit trails for AI agents should be infrastructure, not application
features. By recording at the MCP gateway chokepoint, the blackbox
captures every tool call regardless of the agent framework, without
opt-in, and without agent cooperation. The append-only, hash-chained
design provides tamper detection suitable for compliance review.

The approach is simple (under 250 lines of Rust), requires no external
dependencies beyond SQLite, and has proven its value in real debugging
scenarios. We argue that any system serving as an intermediary between
AI agents and tools should include always-on audit recording as a
baseline capability.
