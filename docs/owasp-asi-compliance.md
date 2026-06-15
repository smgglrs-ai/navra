# Compliance Mapping

Mapping of navra security features against three frameworks:

1. **OWASP ASI01-ASI10** — Agentic AI Top 10 (2026)
2. **EU AI Act** — Regulation (EU) 2024/1689 (enforceable Aug 2026)
3. **Microsoft Agentic AI Taxonomy v2.0** — 7 failure modes from red
   team engagements (Jun 2026)

Last updated: 2026-06-15.

---

## 1. OWASP Agentic AI Top 10

Coverage: **9/10 mitigated, 1 gap** (ASI04 partial — manifest signing
planned).

| Risk | Title | Status | Mechanism |
|------|-------|--------|-----------|
| ASI01 | Agent Goal Hijack | **Mitigated** | IFC taint tracking, safety hooks, egress filter |
| ASI02 | Tool Misuse & Exploitation | **Mitigated** | Deny-wins ACLs, tool scanner, egress filter |
| ASI03 | Identity & Privilege Abuse | **Mitigated** | BLAKE3 tokens, capability delegation, OAuth 2.1 |
| ASI04 | Supply Chain Compromise | **Partial** | Tool scanner (8 categories); manifest signing planned |
| ASI05 | Unexpected Code Execution | **Mitigated** | OpenShell sandboxes, sandbox profiles |
| ASI06 | Memory & Context Poisoning | **Mitigated** | Cognitive file integrity, IFC value store |
| ASI07 | Insecure Inter-Agent Comms | **Mitigated** | IFC-gated mailbox, provenance headers |
| ASI08 | Cascading Agent Failures | **Mitigated** | Hop limits, circuit breaker, trust scoring |
| ASI09 | Human-Agent Trust | **Mitigated** | Approval gate hook, risk-tiered HitL, field filtering |
| ASI10 | Rogue Agents | **Mitigated** | Trust scoring with behavioral decay, temporal contracts |

### ASI01: Agent Goal Hijack

Hidden prompts redirect agent objectives via direct/indirect injection.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| IFC taint tracking | navra-auth | `ifc/mod.rs` | `TaintTracker` labels untrusted inputs; tainted data cannot influence privileged operations |
| Per-value IFC | navra-auth | `ifc/value_store.rs` | `ValueStore` tracks taint at individual tool-result granularity via `var://` resolution |
| Safety filters | navra-safety | `regex.rs`, `ner.rs`, `ml.rs` | Regex + NER + ML classifier pipeline detects injection patterns |
| Prompt injection filter | navra-safety | `regex.rs` | `PromptInjectionFilter` detects imperative overrides in content |
| Statistical guardrails | navra-safety-hooks | `hooks/statistical.rs` | `CosineDriftDetector` flags behavioral drift; `ToolTransitionTracker` flags novel sequences |
| Egress filter | navra-safety-hooks | `hooks/egress.rs` | `EgressFilterHook` blocks exfiltration to non-allowlisted endpoints |

### ASI02: Tool Misuse & Exploitation

Tools invoked in unintended or harmful ways.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| Deny-wins ACLs | navra-auth | `permissions/acl.rs` | Path deny rules always beat allow rules; canonicalization before check |
| Tool rules | navra-auth | `permissions/tool_rules.rs` | Per-tool allow/deny/approve policies |
| Tool scanner | navra-auth | `tool_scanner.rs` | 8 threat categories: poisoning, typosquatting, schema abuse, hidden Unicode, description injection, cross-server refs, intent-behavior mismatch, rug pull |
| Risk-tiered approval | navra-auth | `permissions/approval.rs` | Read=auto, write=prompt, delete=confirm |
| Egress filter | navra-safety-hooks | `hooks/egress.rs` | Blocks tool calls to non-allowlisted external endpoints |
| Cedar policies | navra-auth | `permissions/cedar.rs` | Attribute-based conditional policies (feature-gated) |

### ASI03: Identity & Privilege Abuse

Leaked credentials let agents exceed intended scope.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| BLAKE3 tokens | navra-auth | `auth/mod.rs` | Constant-time token comparison (CWE-208 mitigation) |
| Capability delegation | navra-auth | `auth/capability.rs` | Ed25519-signed CBOR tokens with privilege attenuation chains |
| OAuth 2.1 | navra-auth | `auth/oauth.rs` | Ed25519 JWT, RFC 8693 token exchange, OBO identity |
| Sandbox profiles | navra-auth | `auth/sandbox_profile.rs` | Simulate/Redact/RateLimit/PathRewrite per delegated capability |
| Tool disclosure | navra-auth | `permissions/disclosure.rs` | Per-permission-set tool visibility filtering (NAVRA-074) |
| Error sanitization | navra-core | `server/handlers.rs` | Generic error messages prevent architecture disclosure (NAVRA-074) |

### ASI04: Agentic Supply Chain Compromise — PARTIAL

Runtime components (MCP/A2A) poisoned.

| Defense | Crate | Module | How | Coverage |
|---------|-------|--------|-----|----------|
| Tool scanner | navra-auth | `tool_scanner.rs` | Scans upstream tool definitions for 8 threat categories at startup | **Implemented** |
| Rug pull detection | navra-auth | `tool_scanner.rs` | Tool definition hash tracking across reconnections | **Implemented** |
| Signed agent bundles | navra-auth | `manifest.rs` | Ed25519-signed OCI agent bundles with pre-install check (NAVRA-087) | **Implemented** |
| **Missing** | — | — | No cryptographic verification of upstream MCP server manifests | **Gap** |

**Remaining gap**: Manifest signing for upstream MCP servers. Reuses
existing `CapSigner` infrastructure. Not in MCP spec.

### ASI05: Unexpected Code Execution

Sandbox boundary failures enabling arbitrary code.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| OpenShell sandboxes | navra-tools-exec | `tools.rs` | Command execution inside OpenShell sandboxes with resource limits |
| Sandbox profiles | navra-safety-hooks | `hooks/sandbox_hook.rs` | `SandboxHook` enforces Simulate/Redact/RateLimit/PathRewrite |
| Model-runtime isolation | navra-model-runtime | `lib.rs` | Pluggable isolation: direct, Podman, OpenShell |
| Skill hook | navra-safety-hooks | `hooks/skill_hook.rs` | Validates executable guardrails before execution |

### ASI06: Memory & Context Poisoning

Poisoned memory reshapes behavior after initial interaction.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| Cognitive file integrity | navra-safety-hooks | `hooks/integrity_monitor.rs` | SHA-256 baselines + semantic drift detection on persona/directive files |
| IFC value store | navra-auth | `ifc/value_store.rs` | Per-value taint labels track data provenance |
| Memory decay | navra-memory | `decay.rs` | Exponential decay with importance modulation prevents stale poisoned entries |
| Content-addressed storage | navra-memory | `knowledge.rs` | SHA-256 hash of kind+title enables supersession semantics |

### ASI07: Insecure Inter-Agent Communication

Spoofed, replayed, or unauthenticated messages.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| IFC-gated mailbox | navra-flow | `mesh.rs` | Bell-LaPadula enforcement on inter-agent messages; taint-on-read for blackboard |
| Provenance headers | navra-flow | `mesh.rs` | Provenance chain on mailbox messages; circular provenance detection |
| Hop limits | navra-flow | `executor.rs` | `max_hops` prevents agent worm propagation |
| Capability delegation | navra-auth | `auth/capability.rs` | Delegated tokens attenuate — agents cannot escalate privileges in chains |
| Nonce-based replay protection | navra-auth | `auth/mod.rs` | 128-bit random nonces, server-side seen-nonce map, 2-hour TTL |

### ASI08: Cascading Agent Failures

Errors compound across automated pipelines.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| Hop limits | navra-flow | `executor.rs` | `max_hops` on `DagExecutor` prevents unbounded propagation |
| Circuit breaker | navra-flow | `executor.rs` | Per-tool failure tracking; trips after N consecutive failures, cooldown period |
| Trust scoring | navra-auth | `trust_score.rs` | Agents lose trust on failures/safety triggers; degraded agents get restricted |
| Rate limiting | navra-core | `quota.rs` | `max_calls_per_window` prevents runaway tool loops |
| Kill switch | navra-flow | `mesh_tools.rs` | `flow_kill` tool for emergency flow termination |
| Upstream error sanitization | navra-core | `upstream_module.rs` | Stderr rate-limiting, error message length bounds (NAVRA-080) |

### ASI09: Human-Agent Trust Exploitation

Humans over-trust or are deceived by agent outputs.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| Approval gate hook | navra-safety-hooks | `hooks/approval_gate.rs` | Suspends high-risk tool calls pending human approval; fail-closed on timeout |
| Risk-tiered approval | navra-auth | `permissions/approval.rs` | Read=auto, write=prompt, delete=confirm |
| D-Bus + system tray | navra-server | `notify/`, tray | Desktop notifications with approve/deny buttons |
| Field filtering | navra-safety-hooks | `hooks/field_filter.rs` | Strips sensitive fields from tool responses before reaching agent |
| Pause/resume | navra-core | `server/handlers.rs` | Operator can pause all tool execution via tray menu |

### ASI10: Rogue Agents

Agents operating outside policy by design failure, drift, or compromise.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| Trust scoring | navra-auth | `trust_score.rs` | Behavioral decay — agents automatically lose trust; safety triggers accelerate decay |
| Temporal contracts | navra-safety-hooks | `hooks/temporal_contract.rs` | `TemporalPredicate`: Requires, SequenceLimit, TaintGate, DenialEscalation, Cooldown |
| Statistical guardrails | navra-safety-hooks | `hooks/statistical.rs` | Entropy monitoring detects tool fixation/scatter; cosine drift detects behavioral shift |
| IFC enforcement | navra-auth | `ifc/mod.rs` | Monotonic taint — agents cannot shed taint labels once acquired |

---

## 2. EU AI Act — Regulation (EU) 2024/1689

The EU AI Act requires compliance for high-risk AI systems by August
2026 (extended to Dec 2027 for some categories under the Omnibus
amendment). navra is infrastructure (a gateway), not an AI system
itself — but it provides the enforcement layer that deployers need to
meet their obligations.

### Article mapping

| Article | Requirement | navra Coverage | Mechanism |
|---------|-------------|----------------|-----------|
| **Art. 9** Risk management | Ongoing, evidence-based risk management | **Supported** | Trust scoring with decay, statistical guardrails for anomaly detection, tool scanner for supply chain risk, deny-wins ACLs |
| **Art. 12** Logging | Timestamped logs of inputs, outputs, events | **Supported** | Hash-chained blackbox (SHA-256, append-only, tamper-detectable). Records: agent, tool, args, result, outcome, duration, IFC label. Optional PII filtering on audit records |
| **Art. 13** Transparency | System outputs interpretable by deployers | **Supported** | Tool disclosure per permission set (agents only see authorized tools), sanitized error messages (NAVRA-074), provenance chain on inter-agent messages |
| **Art. 14** Human oversight | Mechanism to stop, correct, override | **Supported** | HitL approval flow (D-Bus, system tray, CLI, MCP-native), pause/resume via tray, `flow_kill` emergency termination, approval gate hook with configurable timeout |
| **Art. 50** Transparency for interactions | Users informed they interact with AI | **Deployer** | navra does not generate AI content — deployers must add disclosure at the application layer |
| **Recital 99-100** Multi-agent chains | Compliance extends to every agent in chain | **Supported** | IFC enforced across agent handoffs (Bell-LaPadula), capability tokens attenuate in chains, hop limits prevent unbounded propagation |

### GDPR alignment (for PII handling)

| Requirement | navra Mechanism |
|-------------|-----------------|
| Art. 15 Right of access | `pii_report` tool generates data subject access report |
| Art. 17 Right to erasure | `memory_purge_pii` and `memory_forget` tools |
| Art. 7 Consent management | `pii_consent` tool records/queries per-subject consent |
| Data minimization | Configurable filter actions: redact, pseudonymize, block |
| Retention limits | `pii_retention_days` (default 30), `audit_retention_days` (default 365) |

### Formal verification as evidence

The EU AI Act values evidence-based risk management. navra provides:

- **23 Kani proofs** — exhaustive verification of IFC lattice properties,
  ACL deny-wins semantics, capability delegation safety
- **6 TLA+ specifications** — model-checked state-space exploration
  (IFCLattice, TaintPropagation, SessionIsolation, CapabilityDelegation,
  FlowConcurrency, VarRefCompleteness)
- **116 formal properties** total across proofs and model checking

---

## 3. Microsoft Agentic AI Taxonomy v2.0

Seven failure modes identified from real red team engagements across
Microsoft's agentic AI deployments (Jun 2026). HitL bypass was the
most consistently exploited failure mode.

Reference: [Microsoft Security Blog, Jun 2026](https://www.microsoft.com/en-us/security/blog/2026/06/04/updating-taxonomy-failure-modes-agentic-ai-systems-year-red-teaming-taught-us/)

| # | Failure Mode | navra Status | Mechanism |
|---|-------------|-------------|-----------|
| 1 | **Agentic Supply Chain Compromise** | **Partial** | Tool scanner (8 categories), rug pull detection, signed agent bundles (NAVRA-087). Gap: upstream MCP manifest signing |
| 2 | **Goal Hijacking** | **Mitigated** | IFC taint tracking (Bell-LaPadula), prompt injection filter, statistical guardrails for behavioral drift |
| 3 | **Inter-Agent Trust Escalation** | **Mitigated** | Capability delegation with privilege attenuation (no ring escalation), IFC-gated mailbox, provenance chains |
| 4 | **CUA Visual Attack** | **N/A** | navra does not implement Computer Use Agent. Vision module processes images server-side with permission checks |
| 5 | **Session Context Contamination** | **Mitigated** | IFC session labels (monotonic taint), per-session isolation (TLA+ verified, 41K states), session expiry |
| 6 | **MCP/Plugin Abuse** | **Mitigated** | Tool scanner detects description poisoning and cross-server override. Tool disclosure hides internal tools. Error sanitization prevents architecture probing (NAVRA-074) |
| 7 | **Capability/Architecture Disclosure** | **Mitigated** | Generic error messages for all denial types. Internal tool names, ACL rules, IFC labels, Cedar policy IDs, and safety filter categories are logged but never sent to clients (NAVRA-074) |

### HitL bypass (cross-cutting)

Microsoft's finding: HitL was the most consistently exploited failure
mode. Attackers found ways to bypass, exhaust, or socially engineer
human approval. navra defenses:

| Defense | How it resists bypass |
|---------|---------------------|
| Fail-closed timeout | Approval gate denies on timeout by default — attacker cannot wait out the human |
| Non-blocking return | Server returns immediately, does not hold connection — no opportunity for timeout manipulation |
| Cached grant TTL | Grants expire after 5 minutes — no permanent bypass from one approval |
| Pause/resume | Operator can halt all tool execution while investigating |
| Trust decay | Repeated approval-needed events degrade agent trust score |

### OpenClaw context

The Microsoft report references OpenClaw (CVE-2026-25253: one-click
RCE, 512 vulnerabilities, 336 malicious plugins). navra's gateway
architecture addresses this by design:

- Agents never directly reach upstream MCP servers — all calls route
  through navra
- Tool definitions are scanned before exposure to agents
- Egress filtering prevents lateral movement to non-allowlisted
  endpoints
- STDIO spawn parameters are never influenced by user-controlled input

---

## Gaps and roadmap

| Gap | Framework | Planned | Status |
|-----|-----------|---------|--------|
| Upstream MCP manifest signing | ASI04, MS #1 | Roadmap (no ID yet) | Ed25519 signing infrastructure exists (CapSigner) |
| Quorum logic for high-risk operations | ASI09 | Not planned | Low priority — single-operator approval sufficient for desktop use case |
| CUA visual attack defense | MS #4 | N/A | navra does not implement CUA |
