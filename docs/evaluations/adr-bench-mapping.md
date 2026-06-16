# ADR-Bench Attack Taxonomy → navra Defense Layer Mapping

Mapping Uber's ADR-Bench 17 attack techniques (arxiv:2605.17380)
against navra's defense layers. This is a documentation exercise —
no benchmark runs. The live benchmark is tracked as NAVRA-093.

## navra Defense Layers

| Layer | Crate | Description |
|-------|-------|-------------|
| **IFC** | navra-auth | Information Flow Control via taint tracking. Labels data with confidentiality/integrity levels, prevents cross-level leaks |
| **ACLs** | navra-auth | Per-agent, per-tool permission rules. Path-level, operation-level, and argument-level constraints |
| **Tool Scanner** | navra-auth | Static analysis of tool definitions at registration. Detects risky argument patterns, capability escalation |
| **Safety Hooks** | navra-safety-hooks | Pre/post-hook pipeline: regex safety filters, egress filtering, statistical guardrails, similarity leakage detection, approval gates |
| **Egress Filter** | navra-safety-hooks | Outbound content filtering. Blocks sensitive data from leaving the gateway |
| **Sandbox** | navra-auth, navra-safety-hooks | Process isolation via SandboxProfile (ExecutionRing: Direct/Podman/OpenShell/SreWitnessed). Constrains tool execution environment |
| **Budget/Compression** | navra-safety-hooks | Token budget enforcement, JSON compression. Limits resource consumption per tool call |
| **Upstream Hardening** | navra-core | Error sanitization, stderr rate-limiting for upstream MCP servers. Prevents information leakage from error messages |
| **Trust Score** | navra-auth | Dynamic trust scoring per agent session. Anomalous behavior reduces trust, triggering escalation |
| **Temporal Contracts** | navra-safety-hooks | Session-level action logging and temporal predicates. Detects sequences of actions that violate contracts |

## Attack Taxonomy Mapping

### Tactic 1: Initial Access & Execution

| # | Technique | navra Layer | Coverage | Notes |
|---|-----------|-------------|----------|-------|
| 1 | **Insecure Supply Chain** | Tool Scanner, ACLs | Partial | Tool Scanner analyzes definitions at registration and flags risky patterns. ACLs restrict which upstream servers agents can access. However, navra does not scan MCP server source code or verify package integrity — supply chain attacks in upstream server dependencies are outside navra's perimeter |
| 2 | **Indirect Prompt Injection** | IFC, Safety Hooks | Partial | IFC taint tracking labels data from external sources (tool outputs) with integrity levels, preventing tainted data from being treated as trusted instructions. Safety hooks apply regex-based content filtering on tool outputs. However, semantic prompt injection that passes structural filters remains a known limitation (see DESIGN.md adversarial limits) |
| 3 | **Control-Flow Hijacking** | IFC, Temporal Contracts | Partial | IFC prevents cross-level data flow that could redirect execution. Temporal contracts can detect anomalous action sequences. However, navra operates at the tool-call level — agent-internal reasoning manipulation is outside the gateway's observability |
| 4 | **Code Interpreter Abuse** | Sandbox, ACLs | Strong | Sandbox profiles (ExecutionRing) enforce process-level isolation for code execution tools. ACLs restrict which agents can invoke code execution tools. High-risk tools automatically escalate to OpenShell or SreWitnessed execution rings |
| 5 | **Insecure Output Handling** | Egress Filter, IFC, Safety Hooks | Strong | Egress filter blocks sensitive data in tool outputs. IFC labels prevent confidential data from flowing to low-clearance agents. JSON compression hook strips verbose metadata. Upstream hardening sanitizes error messages |
| 6 | **Tool Rug Pull** | Tool Scanner, Trust Score | Partial | Tool Scanner analyzes definitions at registration, but post-registration tool behavior changes (rug pulls) are harder to detect. Trust Score degrades on anomalous behavior. The `tools/list_changed` notification handler (NAVRA-085) re-evaluates tool definitions when upstream servers update them |

### Tactic 2: Permission Abuse

| # | Technique | navra Layer | Coverage | Notes |
|---|-----------|-------------|----------|-------|
| 7 | **Excessive Tool Permissions** | ACLs, Tool Scanner | Strong | ACLs enforce least-privilege per agent per tool, with argument-level constraints (e.g., allowed paths, operations). Tool Scanner flags tools requesting broad permissions. Permission sets are configured per agent identity, not granted globally |
| 8 | **Agent Identity Spoofing** | ACLs, IFC | Strong | Agent identity is authenticated at session establishment (AgentIdentity with signing key, DID, capabilities). IFC taint tracking is per-session. Capability tokens (IDJAG) support cryptographic verification and on-behalf-of attenuation |

### Tactic 3: Security Control Bypass

| # | Technique | navra Layer | Coverage | Notes |
|---|-----------|-------------|----------|-------|
| 9 | **Tool Shadowing** | Tool Scanner, ACLs | Strong | navra's three-layer tool naming convention (module-namespaced) prevents name collisions. Tool Scanner flags duplicate registrations. ACLs bind permissions to specific tool names, so a shadowed tool inherits no permissions from the legitimate one |
| 10 | **Tool Hallucination Manipulation** | ACLs | Strong | navra only exposes tools that are explicitly registered and permitted. Calls to non-existent tools return errors. ACLs ensure agents can only invoke tools in their permission set — hallucinated tool names fail at the gateway |
| 11 | **Malicious Agent Collusion** | IFC, ACLs, Temporal Contracts | Partial | IFC prevents data leakage between agents at different clearance levels. ACLs are per-agent, so colluding agents cannot combine permissions. Temporal contracts can detect coordinated anomalous patterns. However, agents at the same clearance level with overlapping permissions could coordinate without triggering isolation controls |

### Tactic 4: Reasoning & Data Manipulation

| # | Technique | navra Layer | Coverage | Notes |
|---|-----------|-------------|----------|-------|
| 12 | **Unvetted MCP Server Connection** | ACLs, Upstream Hardening | Strong | Upstream MCP servers are explicitly configured in `config.toml` — agents cannot dynamically connect to arbitrary servers. Upstream hardening applies error sanitization and rate limiting. Discovery mechanisms (AID, DNS-AID) would still require admin approval before connection |
| 13 | **Semantic Data Poisoning** | IFC, Safety Hooks | Partial | IFC labels data with integrity levels — poisoned data from low-integrity sources is tagged and can be quarantined. Safety hooks apply content filtering. However, semantically valid but misleading data within a trusted source is a known limitation |
| 14 | **Long-Term Goal Hijacking** | Temporal Contracts, Trust Score | Weak | Temporal contracts track session-level action patterns and can detect deviations from expected behavior. Trust Score degrades over time with anomalous actions. However, subtle long-term goal drift that stays within normal behavioral parameters is difficult to detect at the gateway level |
| 15 | **Temporal Data Attack** | IFC | Weak | IFC timestamps data labels but does not validate temporal consistency of data content. navra does not currently reason about time-dependent data semantics — this is an agent-level concern |

### Tactic 5: Operational Impact

| # | Technique | navra Layer | Coverage | Notes |
|---|-----------|-------------|----------|-------|
| 16 | **Agent-Facilitated Resource Exhaustion** | Budget/Compression, Sandbox, ACLs | Strong | Budget hook enforces per-tool token limits. JSON compression reduces payload sizes. Sandbox profiles enforce resource limits (CPU, memory, network). ACLs can restrict the number and rate of tool invocations |
| 17 | **Model-Layer Denial of Service** | Budget/Compression | Partial | Budget hook limits context window consumption. However, model-layer DoS targeting the inference backend (Ollama, etc.) is partially outside navra's control — navra can rate-limit requests but cannot prevent the backend from being overwhelmed by legitimate-looking traffic |

## Coverage Summary

| Coverage Level | Count | Techniques |
|----------------|-------|------------|
| **Strong** | 8 | Code Interpreter Abuse, Insecure Output Handling, Excessive Permissions, Agent Identity Spoofing, Tool Shadowing, Tool Hallucination, Unvetted Server, Resource Exhaustion |
| **Partial** | 7 | Insecure Supply Chain, Indirect Prompt Injection, Control-Flow Hijacking, Tool Rug Pull, Malicious Agent Collusion, Semantic Data Poisoning, Model-Layer DoS |
| **Weak** | 2 | Long-Term Goal Hijacking, Temporal Data Attack |
| **Unaddressed** | 0 | — |

## Gap Analysis

No technique is entirely unaddressed, but two areas have weak coverage:

### Long-Term Goal Hijacking (Weak)

navra's session-scoped controls (temporal contracts, trust scores)
detect deviation within a session but not subtle drift across sessions.
Mitigation options:
- Cross-session behavioral profiling (would require persistent agent
  behavior models — not currently planned)
- Operator-defined session-level goal assertions (verifiable in
  temporal contracts)

### Temporal Data Attack (Weak)

navra labels data but does not reason about temporal semantics.
This is fundamentally an agent-level concern — the gateway sees
data as opaque content. Mitigation options:
- Agent-side temporal consistency checks (outside navra's scope)
- IFC metadata extension for temporal provenance (low priority —
  attack surface is narrow for desktop-first deployments)

## Comparison: ADR Prevention Layer vs. navra Safety Hooks

ADR's shift-left prevention layer uses regex-based credential
detection as a pre-prompt hook with 97.2% precision (206/212
credentials detected, 6 false positives).

navra's equivalent is the pre/post-hook pipeline in
navra-safety-hooks, which provides:
- **Regex-based safety filters** (navra-safety): pattern matching
  for sensitive content, similar to ADR's credential detection
- **Egress filter**: outbound content filtering with configurable
  rules
- **Approval gate**: human-in-the-loop for high-risk operations
  (ADR does not have this — it blocks or allows autonomously)
- **Statistical guardrails**: anomaly detection based on behavioral
  baselines (ADR's Tier 1 triage serves a similar function)

Key architectural difference: ADR operates as an observability layer
alongside agents, with a two-tier detector (fast triage + deep
reasoning via MCP). navra operates as an inline gateway — all tool
calls flow through it, giving it the ability to block, modify, or
redirect in real-time rather than detect-and-alert.

## References

- ADR Paper: https://arxiv.org/abs/2605.17380
- ADR-Bench: 302 tasks, 17 techniques, 133 MCP servers
- navra Design: DESIGN.md (crate table, security model)
- navra Adversarial Limits: docs/adversarial-limits.md
