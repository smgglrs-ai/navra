# OWASP ASI01-ASI10 Compliance Mapping

Mapping of smgglrs security features to the OWASP Agentic AI Top 10
(2026). Each risk lists the crate, module, and mechanism that
addresses it.

## Coverage: 8/10 mitigated, 2 gaps planned (9ab, 9ac)

| Risk | Title | Status | Mechanism |
|------|-------|--------|-----------|
| ASI01 | Agent Goal Hijack | **Mitigated** | IFC taint tracking, safety hooks, egress filter |
| ASI02 | Tool Misuse & Exploitation | **Mitigated** | Deny-wins ACLs, tool scanner, egress filter |
| ASI03 | Identity & Privilege Abuse | **Mitigated** | BLAKE3 tokens, capability delegation, OAuth 2.1 |
| ASI04 | Supply Chain Compromise | **Gap → 9ab** | Tool scanner (partial), manifest signing planned |
| ASI05 | Unexpected Code Execution | **Mitigated** | OpenShell sandboxes, sandbox profiles |
| ASI06 | Memory & Context Poisoning | **Mitigated** | Cognitive file integrity, IFC value store |
| ASI07 | Insecure Inter-Agent Comms | **Mitigated** | IFC-gated mailbox, provenance headers |
| ASI08 | Cascading Agent Failures | **Mitigated** | Hop limits, circuit breaker, trust scoring |
| ASI09 | Human-Agent Trust | **Gap → 9ac** | Approval gate hook planned, AG-UI rendering (5e) |
| ASI10 | Rogue Agents | **Mitigated** | Trust scoring with behavioral decay |

## Detailed mapping

### ASI01: Agent Goal Hijack

Hidden prompts redirect agent objectives via direct/indirect injection.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| IFC taint tracking | smgglrs-security | `ifc/mod.rs` | `TaintTracker` labels untrusted inputs; tainted data cannot influence privileged operations |
| Per-value IFC | smgglrs-security | `ifc/value_store.rs` | `ValueStore` tracks taint at individual tool-result granularity via `var://` resolution |
| Safety filters | smgglrs-security | `safety/regex.rs`, `safety/ner.rs`, `safety/ml.rs` | Regex + NER + ML classifier pipeline detects injection patterns |
| Prompt injection filter | smgglrs-security | `safety/regex.rs` | `PromptInjectionFilter` detects imperative overrides in content |
| Statistical guardrails | smgglrs-security | `hooks/statistical.rs` | `CosineDriftDetector` flags behavioral drift from baseline; `ToolTransitionTracker` flags novel tool sequences |
| Egress filter | smgglrs-security | `hooks/egress.rs` | `EgressFilterHook` blocks exfiltration to non-allowlisted endpoints |

### ASI02: Tool Misuse & Exploitation

Tools invoked in unintended or harmful ways.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| Deny-wins ACLs | smgglrs-security | `permissions/acl.rs` | Path deny rules always beat allow rules; canonicalization before check |
| Tool rules | smgglrs-security | `permissions/tool_rules.rs` | Per-tool allow/deny policies |
| Tool scanner | smgglrs-security | `tool_scanner.rs` | 8 threat categories: poisoning, typosquatting, schema abuse, hidden Unicode, description injection, cross-server refs, intent-behavior mismatch, rug pull |
| Risk-tiered approval | smgglrs-security | `permissions/approval.rs` | Read=auto, write=prompt, delete=confirm |
| Egress filter | smgglrs-security | `hooks/egress.rs` | Blocks tool calls to non-allowlisted external endpoints |
| Cedar policies | smgglrs-security | `permissions/cedar.rs` | Attribute-based conditional policies (feature-gated) |

### ASI03: Identity & Privilege Abuse

Leaked credentials let agents exceed intended scope.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| BLAKE3 tokens | smgglrs-security | `auth/mod.rs` | Constant-time token comparison (CWE-208 mitigation) |
| Capability delegation | smgglrs-security | `auth/capability.rs` | Ed25519-signed CBOR tokens with privilege attenuation chains |
| OAuth 2.1 | smgglrs-security | `auth/oauth.rs` | Ed25519 JWT, RFC 8693 token exchange, OBO identity |
| Sandbox profiles | smgglrs-security | `auth/sandbox_profile.rs` | Simulate/Redact/RateLimit/PathRewrite per delegated capability |
| Tool disclosure | smgglrs-security | `permissions/disclosure.rs` | Per-permission-set tool visibility filtering |

### ASI04: Agentic Supply Chain Compromise — GAP

Runtime components (MCP/A2A) poisoned.

| Defense | Crate | Module | How | Coverage |
|---------|-------|--------|-----|----------|
| Tool scanner | smgglrs-security | `tool_scanner.rs` | Scans upstream tool definitions for 8 threat categories at startup | **Partial** — detects suspicious patterns |
| **Missing** | — | — | No cryptographic verification of upstream MCP server manifests | **Gap** |
| **Missing** | — | — | No Ed25519 signing/verification for tool definitions | **Gap** |

**Mitigation plan**: Roadmap item 9ab — Ed25519 manifest signing in
`UpstreamModule::discover()`, TOFU key pinning. Wave 2. Reuses
existing `CapSigner` infrastructure. Differentiator (not in MCP spec,
NemoClaw Issue #204 not adopted).

### ASI05: Unexpected Code Execution

Sandbox boundary failures enabling arbitrary code.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| OpenShell sandboxes | smgglrs-tools-exec | `tools.rs` | Command execution inside OpenShell sandboxes with resource limits |
| Sandbox profiles | smgglrs-security | `hooks/sandbox_hook.rs` | `SandboxHook` enforces Simulate/Redact/RateLimit/PathRewrite |
| Model-runtime isolation | smgglrs-model-runtime | `lib.rs` | Pluggable isolation: direct, Podman, OpenShell |
| Skill hook | smgglrs-security | `hooks/skill_hook.rs` | `SkillHook` validates executable guardrails before execution |

### ASI06: Memory & Context Poisoning

Poisoned memory reshapes behavior after initial interaction.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| Cognitive file integrity | smgglrs-security | `integrity_monitor.rs` | SHA-256 baselines + semantic drift detection on persona/directive files |
| IFC value store | smgglrs-security | `ifc/value_store.rs` | Per-value taint labels track data provenance; tainted values cannot silently influence clean contexts |
| Memory decay | smgglrs-memory | `decay.rs` | Exponential decay with importance modulation prevents stale poisoned entries from persisting |
| Content-addressed storage | smgglrs-memory | `knowledge.rs` | SHA-256 hash of kind+title enables supersession semantics |

### ASI07: Insecure Inter-Agent Communication

Spoofed, replayed, or unauthenticated messages.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| IFC-gated mailbox | smgglrs-flow | `mesh.rs` | Bell-LaPadula enforcement on inter-agent messages; taint-on-read for blackboard |
| Provenance headers | smgglrs-flow | `mesh.rs` | Provenance chain on mailbox messages; circular provenance detection |
| Hop limits | smgglrs-flow | `executor.rs` | `max_hops` prevents agent worm propagation |
| Capability delegation | smgglrs-security | `auth/capability.rs` | Delegated tokens attenuate — agents cannot escalate privileges in chains |

### ASI08: Cascading Agent Failures

Errors compound across automated pipelines.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| Hop limits | smgglrs-flow | `executor.rs` | `max_hops` on `DagExecutor` prevents unbounded propagation |
| Circuit breaker | smgglrs-flow | `executor.rs` | Per-tool failure tracking; trips after N consecutive failures, cooldown period |
| Trust scoring | smgglrs-security | `trust_score.rs` | Agents lose trust on failures/safety triggers; degraded agents get restricted |
| Rate limiting | smgglrs-agent | `quota.rs` | `max_calls_per_window` prevents runaway tool loops |
| Kill switch | smgglrs-flow | `mesh_tools.rs` | `flow_kill` tool for emergency flow termination |

### ASI09: Human-Agent Trust Exploitation — GAP

Humans over-trust or are deceived by agent outputs.

| Defense | Crate | Module | How | Coverage |
|---------|-------|--------|-----|----------|
| Risk-tiered approval | smgglrs-security | `permissions/approval.rs` | Read=auto, write=prompt, delete=confirm | **Partial** |
| Field filtering | smgglrs-security | `hooks/field_filter.rs` | Strips sensitive fields from tool responses before reaching agent | **Partial** |
| **Missing** | — | — | No quorum logic for high-risk operations | **Gap** |
| **Missing** | — | — | No human-in-the-loop approval gates in hook pipeline | **Gap** |

**Mitigation plan**: Roadmap item 9ac — `ApprovalGateHook` suspends
high-risk tool calls, emits SSE/AG-UI notification, operator
approves/rejects. Fail-closed on timeout. Wave 3 (depends on 15a
Web UI for rendering, works headless). Item 5e adds AG-UI event
format. Differentiator (MCP deprecated `sampling`, AG-UI has no
enforcement).

### ASI10: Rogue Agents

Agents operating outside policy by design failure, drift, or compromise.

| Defense | Crate | Module | How |
|---------|-------|--------|-----|
| Trust scoring | smgglrs-security | `trust_score.rs` | Behavioral decay — agents automatically lose trust over time; safety triggers accelerate decay |
| Temporal contracts | smgglrs-security | `hooks/temporal_contract.rs` | `TemporalPredicate`: Requires, SequenceLimit, TaintGate, DenialEscalation, Cooldown |
| Statistical guardrails | smgglrs-security | `hooks/statistical.rs` | Entropy monitoring detects tool fixation/scatter; cosine drift detects behavioral shift |
| IFC enforcement | smgglrs-security | `ifc/mod.rs` | Monotonic taint — agents cannot shed taint labels once acquired |
