# Ecosystem positioning

navra is a *Claw — a self-hosted AI agent gateway in the same
category as OpenClaw, NemoClaw, and IronClaw. It differentiates on
security depth (gateway-enforced IFC, deny-wins ACLs, in-process ML
safety) and orchestration (navra-flow DAG + mesh + mandates).

navra is domain-agnostic, not developer-only. Developer agents
(Claude Code, Goose) are one client type. Domain apps (lawyer
assistants, ops dashboards) connect as MCP clients and expose their
data as MCP servers — the bidirectional MCP pattern. See Phase 15
for the web UI that serves non-developer users directly.

```
Developer agents ──┐              ┌── downstream MCP servers
  Claude Code      │              │
  Goose            ├── MCP/SSE ──> navra ──┼── built-in modules
  Zed/JetBrains    │              │          └── local ONNX models
Domain apps      ──┘              │
  Lawyer app (↔ bidirectional)    └── domain MCP servers
  Ops dashboard                        (legal DBs, case law, etc.)
  Web UI (Phase 15)
```

### *Claw landscape (May 2026 analysis)

navra sits in the OpenClaw ecosystem — same architectural category
(self-hosted MCP gateway), different depth. Key comparisons:

- **OpenClaw**: Largest ecosystem (370k stars), messaging channels,
  ClawHub marketplace. Weak security (9 CVEs in 4 days, 12% malware
  rate on ClawHub, 135k exposed instances). Node.js.
- **NemoClaw** (NVIDIA): OpenClaw + OpenShell sandbox + YAML policies.
  Wrapper, not purpose-built. Closest to navra's security model
  but bolted-on rather than native.
- **IronClaw** (NEAR AI): Rust, TEEs, WebAssembly tool sandboxes,
  zero-trust capabilities. Independently validates navra's design
  choices. No orchestration.
- **SemaClaw** (Midea AI): DAG orchestration, PermissionBridge,
  three-tier context. Closest to navra-flow. Node.js. No gateway
  security model.
- **Kaiden** (Red Hat/Podman Desktop): Workspace + sandbox management
  for AI coding agents. Complementary layer — Kaiden manages where
  agents run, navra manages what they can access.

What navra has that no *Claw has: IFC as first-class primitive,
in-process ML safety filters, integrated multi-agent orchestration,
cognitive layer, Rust coherent system. What *Claws have that navra
is building: web UI (Phase 15), marketplace/registry (planned).

### Microsoft AGT relationship (May 2026 analysis)

- **Agent Governance Toolkit**: 7-package system (Python, TypeScript,
  Rust, Go, .NET) with Agent OS as stateless policy engine
- Sub-millisecond p99 latency, 13,000+ tests, covers all 10 OWASP
  Agentic Top 10 risks
- Framework-agnostic: hooks into LangChain, CrewAI, Google ADK,
  Microsoft Agent Framework
- **Architecture difference**: AGT is a library (agent embeds it) vs
  navra is a gateway (agent cannot bypass it). Different trust
  models — AGT trusts the agent runtime, navra does not.
- POSIX-inspired capability-based access controls (what agents *can*
  do), vs navra's deny-wins ACLs + IFC (what agents *must not* do
  + information flow tracking)
- **AGT lacks**: IFC/taint tracking, statistical guardrails, budget
  hooks, in-process ML safety, orchestration. These remain navra
  differentiators.
- **AGT has**: Better framework integration story (works with any
  framework via callbacks/decorators), wider language coverage
- **Watch**: AGT Rust package closely — if it gains IFC or gateway
  mode, it becomes a direct competitor

**Updated 2026-05-25**: AGT shipped MCP Extensions for .NET
(`Microsoft.AgentGovernance.Extensions.ModelContextProtocol`).
Adds startup tool scanning (8 threat categories: poisoning,
typosquatting, hidden instructions, schema abuse, hidden Unicode,
description injection, cross-server attacks, rug pulls), response
sanitization (prompt-injection tags, imperative overrides, credential
leakage, exfiltration URLs), YAML policy model (default_action: deny),
DID-based identity, and fail-closed defaults. Broader AGT base includes
execution rings (4 privilege levels), trust decay (0-1000 score),
Ed25519 plugin signing, saga orchestration, circuit breakers, and
kill switches. Upstream tool scanning (9m) is our most critical gap
identified from this comparison.

Reference: Microsoft AGT (github.com/microsoft/agent-governance-toolkit),
AGT architecture deep dive (TechCommunity blog, April 2026),
AGT MCP Extensions for .NET (DevBlogs, May 2026).

### OpenClaw security crisis (June 2026 update)

Microsoft's agentic AI taxonomy v2.0 (June 2026), grounded in a year
of red team operations, confirmed OpenClaw's systemic security failures:

- **CVE-2026-25253**: One-click RCE via WebSocket hijacking (critical)
- **512 vulnerabilities** found in security audit
- **336 malicious plugins** in ClawHub (credential-stealing tools
  disguised as trading bots)
- **1,800+ exposed instances** leaking API keys
- **99 MCP CVEs** published in 2025 alone

The v2.0 taxonomy adds 7 new failure modes for agentic systems:

1. Agentic Supply Chain Compromise (plugin/MCP registries)
2. Goal Hijacking (silent goal-state redirection)
3. Inter-Agent Trust Escalation (confused deputy via NL)
4. CUA Visual Attack (hidden text, off-viewport elements)
5. Session Context Contamination (IFC addresses this directly)
6. MCP / Plugin Abuse (tool description poisoning)
7. Capability / Architecture Disclosure (NAVRA-074)

HitL bypass was the most consistently exploited failure mode. navra's
deterministic HitL invocation (not probabilistic) aligns with the
recommended mitigation. Session Context Contamination (#5) is precisely
what IFC taint tracking addresses — navra's gateway-level enforcement
prevents contaminated context from propagating across tool chains.

navra coverage: IFC addresses #2/#3/#5, deny-wins ACLs address #3,
safety hooks address #6, NAVRA-074 addresses #7. Gap: supply chain
scanning (#1) — see AGT MCP Extensions for prior art.

Reference: https://www.microsoft.com/en-us/security/blog/2026/06/04/updating-taxonomy-failure-modes-agentic-ai-systems-year-red-teaming-taught-us/

### Distroless deployment model (June 2026)

navra agents in distroless containers (gcr.io/distroless/static:nonroot)
with no shell, no coreutils, no Python — the model's ONLY interface
to the outside world is MCP tool calls. Every call passes through
navra's permission/IFC/safety pipeline. This is security by construction:
code execution is impossible, not just restricted.

Filesystem access via rust-mcp-filesystem (upstream MCP server, Rust AI
Stack). Consistent with prefer-existing-MCPs decision — navra doesn't
reimplement filesystem tools, it routes through a purpose-built MCP
server with directory sandboxing and symlink prevention.

Isolation tiers (2026 industry consensus):
- Dev containers (reasonable isolation, easy reset)
- gVisor containers (user-space kernel, Modal uses this)
- Firecracker microVMs (no shared kernel, E2B uses this)
- Hyperlight microVMs (no guest kernel, millisecond boot, CNCF sandbox)

OpenShell already supports libkrun microVMs, Podman, Kata, gVisor.
Hyperlight is a natural addition as an OpenShell compute driver —
`no_std` Rust guest binaries, millisecond boot, CNCF project.

Reference: https://github.com/rust-mcp-stack/rust-mcp-filesystem,
https://github.com/hyperlight-dev/hyperlight

### Microsoft ACP validates navra policy model (June 2026)

Microsoft Power Platform's Advanced Connector Policies (GA June 2026)
govern MCP servers as connectors with allowlist-based, action-level
granularity. Default-deny posture. Single policy per environment.
Validates navra's per-project permission model and the
mcp-google-workspace TOML policy pattern.

Reference: https://www.microsoft.com/en-us/power-platform/blog/2026/06/04/advanced-connector-policies-are-generally-available/

### Competitive landscape update (June 2026 tech watch)

The MCP gateway space exploded: 97M monthly SDK downloads, 30 CVEs
in 60 days, 88% of orgs reporting agent security incidents.

| Gateway | Threat | Key Feature | navra Advantage |
|---------|--------|-------------|-------------------|
| IBM ContextForge | HIGH | Cedar RBAC, A2A, 40+ plugins, 3500+ stars | IFC, in-process ML safety |
| Envoy AI Gateway | MEDIUM | MCPRoute v1beta1, tool multiplexing + regex filtering, 97 contributors | Gateway-enforced IFC, orchestration |
| ClawPatrol (Enkrypt AI) | MEDIUM | 6 gateway hooks (3 hard enforcement), Skill Sentinel (SHA-256 + semantic), skill scanning | In-process ONNX (no cloud API), deny-wins ACLs |
| DefenseClaw (Cisco) | MEDIUM | 5 scan engines (skill/mcp/a2a/CodeGuard/AI-BOM), sub-2s enforcement, OpenShell | IFC, flow orchestration |
| Bifrost | LOW | 11us overhead at 5k RPS, dual client/server | IFC, ML safety, orchestration |
| Lasso Security | LOW | Prompt injection detection, reputation scoring | ML safety depth, IFC |
| Docker MCP Gateway | LOW | Container isolation, Scout scanning | No RBAC, no audit — dev tool only |

navra unique position: **IFC + in-process ML safety + flow
orchestration + OpenShell integration**. No single competitor
covers all four.

**Updated 2026-06-13**: DefenseClaw expanded to 5 scan engines —
skill-scanner, mcp-scanner, a2a-scanner, CodeGuard static analysis,
and AI bill-of-materials generator. Architecture: Python operator
CLI + Go gateway sidecar + OpenClaw TypeScript plugin. Apache 2.0.
Enforces block/allow lists that revoke sandbox permissions, quarantine
files, and remove MCP server endpoints from network allow-lists in
under 2 seconds with no restart. Directly overlaps with navra's
security scanning capabilities.

**Updated 2026-06-13**: Envoy AI Gateway MCPRoute graduated to
v1beta1 in v0.6.0 (May 2026). Now supports MCP server multiplexing
with automatic tool name prefixing (double-underscore delimiter),
tool filtering via exact match or regex, and merging of streaming
notifications from multiple servers into a unified SSE stream.
Claims full June 2025 MCP spec compliance but server-to-client
features (Sampling, elicitation) are unverified. 97 contributors.
Commoditizes the basic MCP proxy layer — navra differentiates on
security depth, not proxy features.

Critical gap from ClawPatrol: cognitive file integrity monitoring
(SHA-256 + semantic drift). Implement before it becomes expected
(Phase 9n).

### MCP supply chain vulnerabilities (June 2026)

OX Security (April 2026) demonstrated systemic RCE in MCP STDIO
transport across ALL Anthropic SDKs (Python, TypeScript, Java, Rust).
User input flowing into StdioServerParameters enables arbitrary
command execution. 14+ CVEs assigned:

- CVE-2026-30615: Windsurf IDE zero-click RCE
- CVE-2025-59536, CVE-2026-21852: SDK-level vulnerabilities
- 9 of 11 MCP registries successfully poisoned with test packages
- Cursor, VS Code, Claude Code, Gemini-CLI also affected

Anthropic acknowledges the behavior as by-design (STDIO is inherently
trust-the-caller). navra mitigates this by: (1) upstream MCP server
spawn parameters are config-defined, never user-influenced;
(2) upstream tool ACL (NAVRA-077) filters what tools are exposed;
(3) distroless deployment (NAVRA-075) eliminates STDIO entirely
for production agents.

### Uber ADR — production MCP security at scale (June 2026)

Uber's ADR framework (arxiv 2605.17380, MLSys 2026 Industry Track)
is the first peer-reviewed, production-validated MCP security system:
- 7,200+ hosts, 10,000+ sessions/day, 10+ months deployment
- ADR-Bench: 302 tasks, 17 attack techniques, 133 MCP servers
- 0% false positives with 67% attack detection (outperforms
  GuardAgent and LlamaFirewall by 2-4x F1)
- Regex-based prevention layer: 97.2% precision, found 206 credential
  exposures across 26 categories

Architecture is analogous to navra's layered approach: regex-based
prevention (≈ navra safety hooks) + LLM-based detection (≈ navra
ML safety models). Key difference: ADR operates per-host, navra
operates per-gateway. ADR-Bench is a strong candidate benchmark
for navra's security evaluation (NAVRA-079).

Reference: https://arxiv.org/abs/2605.17380

Reference: Tech watch 2026-05-25, 2026-06-13, Lunar.dev gateway
comparison, Composio gateway ranking, OX Security STDIO disclosure.

### IFC competitive landscape (May 2026 tech watch)

Three IFC-for-agents systems emerged as direct competitors to
navra-security's IFC module:

| System | Approach | F1 | Advantage | Gap vs navra |
|--------|----------|-----|-----------|----------------|
| FIDES (Microsoft Research) | Planner-level lattice IFC | 0.522 | Formal info-hiding primitives | Gateway-level > planner-level (can't be bypassed) |
| MVAR | Dual-lattice + crypto provenance | N/A (100% on 50-vector) | Execution firewall paradigm | Broader defense-in-depth stack |
| NeuroTaint | Semantic + causal + persistent | 0.928 | Semantic taint tracking | Inline label tracking is faster |
| **navra** | **Gateway-level 2×4 product lattice** | **TBD** | **Per-value IFC + statistical guardrails** | **No semantic/causal tracking** |

Key insights:
- Pure label-only IFC is insufficient (FIDES F1=0.522)
- navra must layer offline semantic audit (NeuroTaint-style) on
  top of inline label tracking for defense-in-depth
- Gateway-level enforcement remains architecturally superior — none
  of the competitors can enforce at the transport layer
- Cryptographic witness for declassification is a gap (11k)
- Adversarial benchmarking needed to establish navra's position (11l)

Reference: FIDES (arXiv:2505.23643), MVAR (github.com/mvar-security/
mvar), NeuroTaint (arXiv:2604.23374).

### Goose relationship (April 2026 analysis)

- Goose: Rust agent runtime (~v1.30, Apache-2.0, AAIF/Linux Foundation)
- Different layer: Goose = end-user agent, navra = security gateway
- Goose has NO auth tokens, NO ACLs, NO IFC, NO content filtering
- Goose connects to MCP servers directly (no proxy/filter)
- Contribution targets: MCP interceptor pattern (SEP-1763),
  Linux extension sandboxing, safety hook pipeline, ACL engine
- ACP adoption gives navra agents IDE integration for free

### ZeroClaw (April 2026 analysis)

- ZeroClaw: Rust agent runtime (<5MB memory, <10ms startup, 8.8MB binary)
- Trait-based architecture, TOML config, 3-tier autonomy
  (ReadOnly/Supervised/Full) — similar permission model to navra
- 70+ tools, 25+ messaging channels, hardware peripheral traits
  (ESP32/Arduino/RPi) — targets embedded/IoT
- Key difference: flat agent runtime vs navra's security gateway
- Potential collaboration: transport adapters, tool interface traits
- Watch for convergence — similar Rust + trait patterns, different layers
- Migrating OpenClaw users (positions as next-gen replacement)

### SemaClaw relationship (April 2026 analysis)

- SemaClaw: Open-source two-layer agent framework (arXiv 2604.11548)
- sema-code-core (Node.js agent runtime) + SemaClaw (application harness)
- Closest architectural parallel to navra-* crate family
- Same problems: permissions, DAG orchestration, memory with hybrid
  retrieval, structured context injection, persona identity
- Key differences (our advantages):
  - **Layer**: SemaClaw is a harness (wraps one framework).
    navra is a gateway (secures any framework that speaks MCP).
  - **Security depth**: Their PermissionBridge is binary
    (internal=allow, external=approve). Our IFC propagates taint
    labels through tool chains; deny-wins ACLs are more granular.
  - **Language**: Node.js vs Rust (type safety, no runtime, WASM,
    in-process ONNX).
  - **Model lifecycle**: No model management (external APIs only).
    We have hub → runtime → backend.
- What we borrowed: 4-layer plugin taxonomy (Phase 5h Module trait
  review), wiki-format knowledge output (Phase 3d), skill
  lazy-loading (Phase 1d).

### LangChain Agentic Engineering (April 2026 analysis)

- LangChain reframes multi-agent systems as "agentic engineering"
- Worker agents (ICs) + Leader agents (PMs) with shared memory
  and tooling. A2A for agent comms, MCP for tools.
- 93% debugging time reduction, 65% dev time reduction in pilot
- No security enforcement whatsoever — their "tool gateway" is an
  API aggregator, not a security layer
- Validates our architecture: their Worker/Leader = our DAG
  orchestrator/specialists, their tool gateway = navra (minus security)
- Human PR review as bottleneck supports cross-validation (Phase 5g)

### AWS Agent Registry (April 2026 analysis)

- Centralized agent/tool/MCP server catalog in Amazon Bedrock AgentCore
- MCP + A2A native, hybrid keyword+semantic search, governance workflow
- The registry itself is an MCP server (queryable by Kiro, Claude Code)
- Governance layer (who owns what, is it approved) complements navra's
  runtime security layer (what can it access, is the content safe)
- Non-English semantic search fails 33% of tests — test our local
  embeddings for multilingual quality
- Consider RegistryModule to proxy external registries (Phase 5f)
