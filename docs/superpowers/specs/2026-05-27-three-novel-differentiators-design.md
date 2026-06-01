# Three Novel Differentiators for navra

**Date**: 2026-05-27
**Status**: Approved

## Problem

navra's MCP gateway market has 13+ competitors. IFC is the only
clear differentiator. The core engine is production-complete (22
crates, ~113K LoC, 2110+ tests). We need genuinely new capabilities
that no competitor has — not repackaging existing features.

## Solution: Three Novel Features

### 1. Temporal Behavioral Contracts

Runtime policy enforcement over agent action history within a session.
Static ACLs operate on individual requests. Temporal contracts operate
on trajectories — the sequence of actions an agent has taken so far.

**Examples**:
- "Cannot write a file unless read first in this session"
- "No more than 3 destructive tools in sequence without human check-in"
- "After accessing PII-labeled data, cannot call external APIs"
- "After 2 denials, must escalate instead of retrying"

**Architecture**: A Hook (pre+post) with Arc-based per-session action
log (DashMap pattern from MemoryExtractionHook). Post-hook records
every tool call. Pre-hook evaluates temporal predicates before each
call. Contracts defined in YAML config.

**Key types**:

```
TemporalPredicate:
  Requires(tool, prerequisite)    -- dependency ordering
  SequenceLimit(pattern, max)     -- consecutive destructive cap
  TaintGate(label, blocked_tools) -- IFC-triggered lockdown
  DenialEscalation(threshold)     -- escalation after N blocks
  Cooldown(tool, min_interval)    -- per-tool rate limit
  All / Any                       -- compound predicates
```

**What makes it novel**: No gateway, security framework, or agent
platform enforces temporal policies over tool-call trajectories.
Cedar policies are conditional but not temporal. RBAC is static.
This is design-by-contract for agent behavior — formalizable as
LTL (Linear Temporal Logic) over action sequences.

### 2. Protocol-Level Capability Sandboxing

The gateway itself becomes the sandbox. Agents get a different "view
of reality" based on their capability token. Tools may simulate,
redact, rate-limit, or transform responses — and the agent cannot
detect it. The protocol responses look identical to real ones.

**Capabilities**:
- **Tool simulation**: Write tools return "success" without writing.
  Agent thinks it wrote. Useful for evaluation, training, auditing.
- **Content redaction**: Tool results filtered based on capability
  level (beyond safety hooks — structural redaction per token).
- **Rate modulation**: Artificial delays for low-trust agents to
  enforce "thinking time" before rapid action sequences.
- **Path rewrites**: Agent sees `/sandbox/project/` but the gateway
  maps to `/real/project/` transparently.

**Architecture**: New `SandboxProfile` embedded in capability tokens.
New `HookDecision::Simulate(CallToolResult)` variant that short-
circuits tool execution. `SandboxHook` (pre+post) reads profile from
CallContext capabilities. Attenuation rules: sandbox restrictions
can only be added or tightened during delegation, never removed.

**What makes it novel**: All agent sandboxing today is container-
or VM-level (OpenShell, NemoClaw, Docker). This is protocol-level
sandboxing — the agent's perception of reality is controlled at the
MCP layer. No infrastructure overhead. Works over any transport.
Relates to capability-based security research (seL4, KeyKOS) applied
to application protocols.

### 3. Causal Provenance Graphs

Track WHY things happened across multi-agent flows, not just what.
Build directed acyclic graphs of causal relationships with typed
edges aligned to W3C PROV-DM.

**Beyond existing provenance**:
- Existing: flat provenance chains `Vec<(agent_id, timestamp)>`
- New: typed edges (WasDerivedFrom, WasGeneratedBy, Used, WasInformedBy)
- New: tool-call-level causality across agent boundaries
- New: queryable graph with BFS traversal (trace causes, find roots)
- New: MCP tools for interactive causal analysis

**Architecture**: SQLite-backed `CausalGraphStore` in navra-flow.
`CausalSink` trait in navra-security (same decoupling as
ExtractionStore). Post-hook records causal nodes/edges. Flow
executor records inter-task causality via blackboard/mailbox
integration. Three MCP tools for querying.

**Causal edge inference**:
- Within session: hash result fragments, match against subsequent args
- Via blackboard: explicit WasGeneratedBy/Used on publish/read
- Via mailbox: WasInformedBy between sender/receiver activities
- Via DAG executor: task output WasDerivedFrom task inputs

**What makes it novel**: Everyone logs what happened. No one tracks
why. Flat audit logs answer "what." Provenance chains answer "who
contributed." Causal graphs answer "which specific output caused
which specific decision." W3C PROV-DM alignment enables
interoperability with provenance ecosystems.

## Implementation

### Order

Feature 1 (smallest) -> Feature 3 (foundational) -> Feature 2 (most
invasive, benefits from provenance integration)

### Files

| Feature | New Files | Key Modifications |
|---------|-----------|-------------------|
| Temporal Contracts | `hooks/temporal_contract.rs` | `hooks/mod.rs`, `builder.rs`, `config/security.rs` |
| Capability Sandboxing | `auth/sandbox_profile.rs`, `hooks/sandbox.rs` | `hooks/mod.rs`, `pipeline.rs`, `capability.rs`, `handlers.rs` |
| Causal Provenance | `causal_graph.rs`, `hooks/provenance_hook.rs`, `provenance_tools.rs` | `blackboard.rs`, `mailbox.rs`, `executor.rs` |

### Effort

| Feature | Days | Tests |
|---------|------|-------|
| Temporal Contracts | 4-5 | ~15 |
| Capability Sandboxing | 6-7 | ~20 |
| Causal Provenance | 7-8 | ~18 |
| **Total** | **18-20** | **~53** |

Features are independent and can be parallelized in worktrees.

### Reused Infrastructure

- Hook trait + HookPipeline (`navra-security/src/hooks/`)
- Arc-based side storage pattern (`ExtractionStore` in `memory_extraction.rs`)
- CapabilityPayload + attenuation (`navra-security/src/auth/capability.rs`)
- AgentAction classification (`navra-agent/src/action.rs`)
- SQLite storage pattern (`navra-flow/src/event_log.rs`)
- glob_match helper (`memory_extraction.rs`)

## Research Value

| Feature | Paper Title | Core Novelty |
|---------|------------|--------------|
| Temporal Contracts | Runtime Temporal Policy for Agentic AI | First LTL formalization over tool-call trajectories |
| Capability Sandboxing | Transparent Protocol-Level Agent Sandboxing | Information-theoretic indistinguishability at MCP |
| Causal Provenance | W3C PROV-DM for Multi-Agent Accountability | First causal graph integration with MCP pipelines |

All three connect to EU AI Act compliance (Articles 12, 14, 18) and
can be evaluated on navra's existing multi-agent flow infrastructure.

## Competitive Impact

After implementation, navra will have four differentiators no
competitor matches:
1. **IFC** (existing) — gateway-enforced information flow control
2. **Temporal contracts** — trajectory-level policy enforcement
3. **Protocol sandboxing** — transparent capability-based reality views
4. **Causal provenance** — W3C-aligned causal accountability graphs
