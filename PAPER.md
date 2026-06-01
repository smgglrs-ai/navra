# An Operating System for AI Agents

## Capability-Based Security and Microkernel Architecture for Multi-Agent Systems

### Authors

Fabien Dupont (Red Hat / IBM)

---

## Abstract

As AI agents transition from stateless API consumers to autonomous
processes that read files, execute code, manage credentials, and
collaborate with other agents, they face security challenges
analogous to those that operating systems solve for traditional
processes: isolation, least privilege, auditable identity, and
resource mediation. We present an AI Operating System architecture
that applies classical OS principles — microkernel separation,
capability-based security, graduated privilege rings, and
cryptographic process identity — to the domain of LLM-powered
agents. Our implementation comprises two systems: navra, a Rust
microkernel that enforces security and mediates access to local
resources, and navra, a Python userland that provides multi-agent
orchestration, cognitive personas, and task planning. Agents
communicate via the Model Context Protocol (MCP) for tool
invocation and the Agent-to-Agent (A2A) protocol for inter-process
communication. We show that this separation enables delegation
chains where a leader agent issues attenuated, cryptographically
signed capability tokens to specialist agents, each scoped to the
tools, paths, and credentials required for its task. We evaluate
token overhead (14 μs verification, 375--773 byte tokens),
delegation validation cost, and the security properties targeted
by the capability model. We discuss limitations, notably that
capability tokens constrain but do not prevent prompt injection
attacks, and identify information flow control as a complementary
direction.

---

## 1. Introduction

### 1.1 The Problem

AI agents are no longer simple request-response systems. Modern
agents execute multi-step plans, modify filesystems, commit code,
access databases, and invoke external services. When multiple agents
collaborate — a leader decomposing a task into subtasks assigned to
specialists — the security surface expands dramatically.

Current approaches to agent security are ad hoc:

- **API keys as identity** — Shared secrets with no attenuation,
  no expiry, no delegation model. An agent with an API key has the
  same access whether it's the leader or a sandboxed specialist.

- **No isolation between agents** — Multi-agent frameworks typically
  share a single process context. Every agent can read every file,
  access every credential, and call every tool.

- **Trust-the-model security** — Relying on system prompts ("don't
  access files outside /home/user/projects") for access control.
  Prompt injection, hallucination, and model drift can bypass these
  soft boundaries.

- **No cryptographic identity** — Agents are identified by names
  or session IDs, not by verifiable cryptographic identities. There
  is no audit trail linking an action to a specific agent with
  provable authenticity.

These are the same problems that operating systems solved decades
ago for traditional processes. The solutions — process isolation,
capability tokens, privilege rings, mandatory access control, and
cryptographic identity — are directly applicable.

### 1.2 Thesis

Classical OS abstractions — processes, system calls, capability
tokens, privilege rings — offer a productive framework for AI
agent security, where LLM-powered agents are treated as untrusted
processes and a microkernel enforces security at the infrastructure
layer rather than relying on model compliance.

### 1.3 Contributions

1. **Formalization of the AI OS abstraction** — A systematic mapping
   from OS primitives (rings, capabilities, IPC, credential
   management, process lifecycle) to AI agent infrastructure,
   grounded in a working implementation.

2. **Capability-based security for AI agents** — Ed25519-signed,
   short-lived, attenuable capability tokens with DID:key identity.
   Delegation chains enforce the principle of least privilege across
   multi-agent hierarchies.

3. **Microkernel/userland separation** — A clean architectural
   boundary between security enforcement (navra, Rust) and
   orchestration logic (navra, Python), communicating via standard
   protocols (MCP, A2A).

4. **Credential brokering** — Agents never access raw secrets. The
   microkernel reads credentials from the OS keyring and injects
   them into tool execution contexts, gated by capability tokens.

5. **Post-quantum readiness** — Algorithm-agile signing via a trait
   abstraction, enabling migration from Ed25519 to hybrid
   Ed25519+ML-DSA without protocol changes.

### 1.4 Paper Organization

Section 2 surveys related work. Section 3 defines the architecture.
Section 4 details the security model. Section 5 covers inter-agent
communication. Section 6 describes resource management. Section 7
presents the implementation. Section 8 evaluates performance and
security properties. Section 9 discusses limitations and future
work. Section 10 concludes.

---

## 2. Background and Related Work

### 2.1 Operating System Foundations

- **Capability-based security** — Dennis & Van Horn [2] introduced
  capabilities; KeyKOS [5][8], EROS [11], and Capsicum [16] refined
  them. Unforgeable tokens granting specific access rights, with
  attenuation (narrowing) but never amplification. Saltzer &
  Schroeder [4] formalized the principle of least privilege.
  Miller [14] unified capabilities with concurrency control in
  the object-capability model, while Miller et al. [13] refuted
  common myths about capability limitations. Hardy [7] identified
  the confused deputy problem that capabilities solve.

- **Microkernel architecture** — Mach [6], L4 [9], seL4 [15].
  Minimal kernel providing IPC, memory management, and scheduling;
  all policy in userland. Reduced trusted computing base. seL4
  proved formal verification of a kernel is tractable. Heiser &
  Elphinstone [18] distilled 20 years of L4 deployment lessons.

- **Privilege rings** — Intel x86 ring model (ring 0-3). Hardware-
  enforced privilege levels where outer rings cannot access inner
  ring resources. Deny-wins principle.

- **Access control models** — SELinux [12] provides mandatory
  access control (MAC) enforced by the kernel. Sandhu et al. [10]
  defined the RBAC model family, arguing administrative tractability
  over per-object capabilities. NIST SP 800-162 [17] formalized
  attribute-based access control (ABAC). Multics [1] introduced
  hierarchical protection domains from which rings, MAC, and
  capabilities all descend.

### 2.2 AI Agent Frameworks

- **Model Context Protocol (MCP)** [41] — Anthropic's open protocol
  for LLM tool invocation. JSON-RPC 2.0 over HTTP/SSE/stdio. Defines
  tools, resources, and prompts. No built-in security model. Enables
  tool-augmented agents [45][46][47] but leaves authorization to the
  deployment layer.

- **Agent-to-Agent (A2A)** [42] — Google's protocol for inter-agent
  communication. Agent Cards for discovery, task lifecycle (submitted
  → working → completed), streaming via SSE.

- **Multi-agent systems** — The field predates LLMs. Wooldridge &
  Jennings [38] defined intelligent agents; Rao & Georgeff [39]
  formalized BDI architecture; FIPA [40] standardized agent
  communication. Modern LLM agents inherit these patterns but
  face new security challenges from prompt injection [48] and
  cross-agent infection [51].

- **Microsoft Agent Framework v1.0** [83] — Orchestration SDK
  unifying Semantic Kernel and AutoGen. Multi-agent patterns,
  middleware pipeline, MCP integration. No kernel-level security
  enforcement.

- **Microsoft Agent Governance Toolkit** [83] — Policy engine,
  DID-based identity (Agent Mesh), execution rings (Agent Runtime).
  Closest industry parallel to our security model, but focused on
  governance compliance rather than OS-level resource mediation.

### 2.3 Agent Identity and Discovery

- **Decentralized Identifiers (DIDs)** [31] — W3C standard for
  self-sovereign identity. The `did:key` method [32] derives the
  identifier directly from the public key. No registry dependency.
  Google, Apple, and Mozilla filed formal objections [34] citing
  interoperability concerns; these apply less to single-system
  deployments but matter for federation.

- **Authorization tokens** — Our capability tokens build on a
  lineage from Kerberos [24] through OAuth [26] to Macaroons [27]
  and ZCAP-LD [33]. Macaroons' contextual caveats are the closest
  precursor to our attenuation model. SPKI [22] and KeyNote [20][21]
  formalized decentralized trust management.

- **Agent Identity & Discovery (AID)** [43] — Community
  specification for DNS-based agent discovery. TXT records with MCP
  endpoint URLs, Ed25519 [25] public keys (PKA field), and
  authentication hints. Supports HTTP Message Signatures [35] for
  endpoint proof.

- **mDNS/DNS-SD** — Zero-configuration service discovery on local
  networks. Enables agents to find each other without central
  infrastructure.

### 2.4 Post-Quantum Cryptography

- **ML-DSA (Dilithium)** [36] — NIST FIPS 204. Lattice-based
  digital signature scheme. 3,309-byte signatures (vs 64 bytes
  for Ed25519 [25]).

- **Hybrid signatures** — Transition strategy: sign with both
  Ed25519 and ML-DSA. Quantum-safe if either algorithm holds.

### 2.5 Gap Analysis

Recent surveys [49][58] and benchmarks [53] document the expanding
attack surface of LLM-based agents, while Hammond et al. [54] and
Schroeder de Witt [57] identify multi-agent coordination as a
source of emergent risk. Doshi et al. [59] propose verifiable
safety properties for tool use — a direction our capability model
concretizes. The OWASP Agentic Top 10 [52] catalogs the practical
risks (prompt injection, privilege escalation, credential theft)
that motivate our security architecture.

Indirect prompt injection [48] is the most dangerous threat to
tool-using agents: data retrieved by tools can contain adversarial
instructions that hijack the agent. Recent work demonstrates this
against MCP specifically [56], against tool selection [55], and
across multi-agent boundaries [51][50]. Our capability model limits
the blast radius of such attacks (a compromised specialist can
only misuse its attenuated tool set) but cannot prevent them at the
semantic level — this is a fundamental limitation (Section 9.1).

The trust management lineage from PolicyMaker [20] through
Macaroons [27] to ZCAP-LD [33] shows progressive refinement of
decentralized authorization with contextual attenuation. Our
capability tokens follow this trajectory, adding DID-based
identity and CBOR encoding for compactness.

Gutmann [28] argues that key management — not cryptographic
algorithms — is the hardest unsolved problem in practical
security. This critique applies to our DID:key identities: key
loss means permanent identity loss. The W3C DID formal objections
[34] raise similar concerns about key recovery.

The confinement problem [3] demonstrates that covert channels
cannot be eliminated by access control alone. Timing attacks
[19][23] show that even constant-time crypto implementations can
leak information through microarchitectural side channels [37].
Our safety filtering addresses content-level exfiltration but not
covert channels through timing or resource consumption patterns.

No existing system combines:
- Kernel-enforced security for AI agents
- Cryptographic capability tokens with delegation
- Credential brokering (agents never see secrets)
- Microkernel separation from orchestration

The Microsoft Governance Toolkit [84] comes closest in security
scope but operates as a middleware layer, not as an OS kernel.
Agent frameworks (MAF [83], LangGraph, CrewAI) focus on
orchestration and leave security to deployment infrastructure.
GitHub's agent commit signing [85] addresses identity for a single
agent but not delegation chains or credential brokering. Google's
BeyondCorp [82] pioneered zero-trust for enterprise networks;
NIST SP 800-207 [30] formalized the architecture. Our model
extends zero-trust to agent-to-agent interactions.

---

## 3. Architecture

### 3.1 Design Principles

1. **Gateway, not framework** — Security is enforced at the
   infrastructure layer rather than within agent code. Agents
   interact with resources exclusively through the kernel's
   mediation.

2. **Microkernel separation** — The kernel (navra) provides
   mechanism: identity, capability verification, resource mediation,
   IPC transport. Policy decisions (which agent does what task) live
   in userland (navra).

3. **Deny-wins** — In all permission checks (path ACLs, tool rules,
   ring inheritance), deny rules take absolute precedence over allow
   rules. This prevents privilege escalation through rule ordering.

4. **Capabilities, not identity checks** — Access is determined by
   what the agent's token grants, not by who the agent is. This
   enables delegation: a leader can issue a narrower token to a
   specialist without the specialist needing a separate identity in
   the kernel's configuration.

5. **Credential mediation** — Credentials are resolved by the
   kernel from the OS keyring and injected into tool execution
   contexts. Under normal operation, the agent process does not
   hold raw secret material, though covert channels [3] remain
   a theoretical concern.

### 3.2 System Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Human Operator                     │
│              (approval gates, shell, tray)            │
└──────────────────────┬───────────────────────────────┘
                       │ approve / deny / inspect
┌──────────────────────▼───────────────────────────────┐
│                  navra (Userland)                    │
│                                                      │
│  ┌─────────┐  ┌────────────┐  ┌──────────────────┐  │
│  │ Leader  │  │ Specialist │  │   Specialist      │  │
│  │ Persona │──│ Persona A  │  │   Persona B       │  │
│  └────┬────┘  └─────┬──────┘  └───────┬──────────┘  │
│       │ cap_delegate │                │              │
│       │  (ring 1→2)  │                │              │
│  ┌────▼──────────────▼────────────────▼──────────┐  │
│  │         MCP Client (tool invocation)           │  │
│  │         A2A Client (inter-agent messages)      │  │
│  └────────────────────┬──────────────────────────┘  │
└───────────────────────┤──────────────────────────────┘
                        │ MCP / A2A over HTTP+SSE
┌───────────────────────▼──────────────────────────────┐
│                  navra (Microkernel)                   │
│                                                      │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────┐ │
│  │ Capability │ │ Permission │ │   Credential     │ │
│  │ Verifier   │ │ Engine     │ │   Broker         │ │
│  │ (Ed25519)  │ │ (Rings+ACL)│ │   (OS Keyring)   │ │
│  └─────┬──────┘ └─────┬──────┘ └───────┬──────────┘ │
│        │              │                │             │
│  ┌─────▼──────────────▼────────────────▼──────────┐ │
│  │              Hook Pipeline                      │ │
│  │         (pre/post tool call filtering)          │ │
│  └─────────────────────┬──────────────────────────┘ │
│                        │                             │
│  ┌─────────────────────▼──────────────────────────┐ │
│  │              Module Registry                    │ │
│  │  ┌──────┐ ┌─────┐ ┌─────┐ ┌───────┐ ┌──────┐ │ │
│  │  │ docs │ │ git │ │ rag │ │ voice │ │vision│ │ │
│  │  └──────┘ └─────┘ └─────┘ └───────┘ └──────┘ │ │
│  └────────────────────────────────────────────────┘ │
│                                                      │
│  ┌────────────────────────────────────────────────┐ │
│  │           Upstream MCP Server Proxy             │ │
│  │      (safety-filtered, permission-checked)      │ │
│  └────────────────────────────────────────────────┘ │
│                                                      │
│  ┌────────────────────────────────────────────────┐ │
│  │        Discovery (AID, mDNS, Agent Cards)       │ │
│  └────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   Filesystem       OS Keyring      External APIs
   (local disk)    (GNOME/KDE/      (upstream MCP
                    macOS/Win)       servers)
```

### 3.3 Microkernel Boundary

The kernel's trusted computing base includes:

| Kernel responsibility | Mechanism |
|---|---|
| Identity verification | DID:key, Ed25519 signature verification |
| Capability token issuance | CBOR-encoded, signed tokens |
| Path access control | Deny-wins ACLs with canonicalization |
| Tool access control | Glob-matched tool grants in capabilities |
| Credential brokering | OS keyring read, environment injection |
| Content safety filtering | Regex + ML pipeline (mandatory) |
| Approval gating | Human-in-the-loop for sensitive operations |
| IPC transport | MCP (tool calls) + A2A (agent messages) |
| Discovery | AID, mDNS/DNS-SD, Agent Cards |

Everything else is userland:

| Userland responsibility | Mechanism |
|---|---|
| Agent orchestration | Leader/Specialist patterns |
| Task decomposition | ReAct loops, planning |
| Persona definition | YAML configuration |
| Drift detection | Cognitive Immune System |
| Plugin distribution | OCI containers + sigstore |
| User experience | CLI, chat interface, voice |

### 3.4 Userland Architecture (navra)

navra is the AI OS's userland — a Python-based multi-agent
orchestration framework providing the cognitive layer that
the microkernel deliberately excludes.

#### Cognitive Core

Agent personas are defined declaratively in YAML, validated
by JSON Schema, and compiled into an in-memory registry by
the Forge service. Each persona specifies:

- **Core mandate** — the agent's fundamental directive
- **Heuristics** — modular cognitive knowledge bases with
  faceted organization (e.g., `systems_thinking.system_dynamics`)
- **Skills** — tools the agent can invoke
- **Engine preference** — which LLM to use (Claude Opus for
  planning, Sonnet for execution, Gemini for cost-sensitive tasks)
- **Output schema** — structured output format for validation

Over 40 personas span the cognitive spectrum: system architect,
software developer, researcher, assessor, security sentinel,
tech writer, and specialized judges (correctness, completeness,
safety). Personas compose through specializations — a
`backend_specialist` extends `software_developer` with database
and API heuristics.

#### Orchestration

Three orchestration tiers mirror organizational hierarchy:

1. **Specialist (Tier 1)** — executes specific tasks via ReAct
   loops (Sense-Plan-Act). Each cycle: LLM generates a plan with
   tool calls, tools execute (with user confirmation for writes),
   results feed back for the next reasoning step.

2. **Project Leader (Tier 2)** — decomposes tasks into specialist
   work streams via `ProjectOrchestrator`. DAG-structured plans
   with dependency-aware concurrent execution.

3. **Portfolio Architect (Tier 3)** — orchestrates leaders across
   strategic objectives. The `AdaptiveOrchestrator` enables
   mid-execution replanning: after each task completes, the full
   graph is reevaluated, and tasks can be added, removed, or
   modified dynamically.

#### Cognitive Immune System

A four-tier supervisory architecture detects and recovers from
cognitive failures:

1. **Agent** — primary executor, records all actions
2. **Watchdog** — monitors active tasks every 15 seconds for
   anomalies (repetition, stagnation, drift, quality degradation).
   Critical severity triggers automatic task pause.
3. **Analyst** — performs "cognitive autopsy" on paused tasks,
   identifies root causes, generates diagnostic reports
4. **Replanner** — generates improved plans incorporating
   diagnostic findings while preserving original user intent

Detected cognitive diseases include context fatigue, strategic
drift, repetitive loops, and plan deviation.

#### Memory Hierarchy

Four-tier memory mirrors hardware memory hierarchy:

| Tier | Scope | Analogy |
|---|---|---|
| Working memory | Current session context | CPU registers |
| Session memory | Interaction history within activity | L1/L2 cache |
| Long-term memory | Cross-activity semantic search | RAM |
| Knowledge corpus | Domain-specific knowledge (ADRs, skills) | Disk |

#### Plugin Distribution

Cognitive artifacts (personas, heuristics, directives) are
packaged as OCI artifacts, signed with sigstore (cosign), and
distributed via ORAS-compatible registries. This is the AI OS's
package manager — `navra install researcher` pulls a signed
persona artifact from the registry.

### 3.5 Microkernel Boundary in Practice

The boundary between navra and navra follows one rule: **if it
requires trust, it's kernel; if it requires intelligence, it's
userland.**

| Concern | Where | Why |
|---|---|---|
| Token verification | navra (kernel) | Must not be bypassable |
| Tool permission check | navra (kernel) | Agent cannot grant itself access |
| Credential injection | navra (kernel) | Agent must never see raw secrets |
| Content safety filtering | navra (kernel) | Mandatory access control |
| Rate limiting | navra (kernel) | Agent cannot increase its quota |
| Persona selection | navra (userland) | Policy, not mechanism |
| Task decomposition | navra (userland) | Requires LLM reasoning |
| Drift detection | navra (userland) | Domain-specific cognitive heuristics |
| Model selection | navra (userland) | Cost/quality tradeoff |
| Plugin signing/distribution | navra (userland) | OCI + sigstore (userland trust chain) |

**Overlap resolution:** navra has its own `PermissionManager`
with read-only vs write-enabled toolbelts. This is discretionary
access control (the orchestrator's policy). navra's path ACLs and
tool rules are mandatory access control (the kernel's enforcement).
Both can coexist — the orchestrator applies its policy first, and
the kernel enforces the hard boundary underneath.

### 3.6 Why Microkernel, Not Monolithic

A monolithic AI OS would embed orchestration, personas, and task
planning in the same process as security enforcement. This has
three problems:

1. **Trusted computing base inflation** — Every orchestration bug
   is a potential security bypass. The kernel should be small enough
   to audit.

2. **Language lock-in** — navra is Rust (memory safety, performance
   for cryptographic operations). navra is Python (LLM ecosystem,
   rapid iteration). A monolithic design forces one language.

3. **Composability** — Other orchestrators (Claude Code Agent Teams,
   Microsoft Agent Framework) can connect to navra as userland
   processes without modification. The kernel doesn't care who the
   orchestrator is.

---

## 4. Security Model

### 4.1 Agent Identity (DID:key)

Each agent receives a cryptographic identity derived from an
Ed25519 [25] public key, encoded as a W3C DID:key [32] identifier:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

The encoding is deterministic: multicodec prefix (0xed01) + 32-byte
public key, multibase-encoded as base58btc with 'z' prefix.

The navra microkernel has its own root identity, generated at first
startup and stored in the OS keyring. This root DID is the ultimate
trust anchor — all capability tokens chain back to it.

Properties:
- **Self-certifying** — The DID is derived from the key, not
  assigned by an authority. No registry dependency.
- **Verifiable** — Any party with the DID can verify signatures
  without contacting the issuer.
- **Deterministic** — Same key always produces the same DID.
- **Algorithm-agile** — Multicodec prefix identifies the key type.
  Ed25519 today, ML-DSA tomorrow.

### 4.2 Capability Tokens

Access is controlled by capability tokens — Ed25519-signed, CBOR-
encoded, short-lived grants:

```
navra_cap_v1.<base64url(cbor_payload)>.<base64url(ed25519_sig)>
```

Payload structure:

| Field | Type | Description |
|---|---|---|
| v | u8 | Version (1) |
| iss | String | Issuer DID |
| sub | String | Subject DID (token holder) |
| cap.paths | [String] | Allowed path globs |
| cap.operations | [String] | Permitted operations |
| cap.tools | [String] | Tool name globs |
| cap.credentials | [String] | Credential labels |
| ring | u8 | Maximum privilege ring (0-3) |
| iat | u64 | Issued-at (Unix seconds) |
| exp | u64 | Expiry (Unix seconds) |
| nonce | [u8; 16] | Replay prevention |
| parent | [u8; 16]? | Parent nonce (delegation) |

**Design choice: CBOR [29] over JSON.** Tokens transit HTTP
Authorization headers. CBOR produces ~40% smaller payloads than
JSON for the same structured data. A typical capability token is
under 500 bytes.

**Design choice: Custom format over JWT/PASETO.** JWT's algorithm
negotiation (`alg` header) is a known attack surface. PASETO v4
adds XChaCha20-Poly1305 dependency for local tokens. Our tokens
operate in a closed system where the signing algorithm is fixed by
the multicodec prefix in the issuer's DID [32]. All tokens use
Ed25519 [25] signatures (64 bytes), with a migration path to
hybrid Ed25519+ML-DSA [36]. Our design follows the same
attenuation-by-construction principle as Macaroons [27] and
ZCAP-LD [33], but uses CBOR rather than JSON and embeds
capabilities directly rather than referencing external policy.

### 4.3 Graduated Privilege Rings

Permission sets are assigned ring levels (0 = most privileged,
3 = most restricted). Ring inheritance applies:

- **Deny rules cascade down** — Ring N inherits all deny rules
  from rings 0..N-1.
- **Operations intersect** — Ring N's effective operations are the
  intersection of its declared operations with all lower rings.
- **Approval requirements cascade** — If ring 0 requires approval
  for an operation, all higher rings also require it.

```
Ring 0 (admin)     — full access, all operations
  ↓ inherits denies, intersects ops
Ring 1 (developer) — read/write/git, no shell
  ↓ inherits denies, intersects ops
Ring 2 (readonly)  — read/search/list only
  ↓ inherits denies, intersects ops
Ring 3 (sandboxed) — minimal access, no credentials
```

### 4.4 Delegation Chains

A capability token holder can issue an attenuated sub-token to
another agent. Attenuation rules:

1. `child.ring >= parent.ring` (cannot escalate privilege)
2. `child.exp <= parent.exp` (cannot outlive parent)
3. `child.cap.paths ⊆ parent.cap.paths` (cannot widen scope)
4. `child.cap.operations ⊆ parent.cap.operations`
5. `child.cap.tools ⊆ parent.cap.tools`
6. `child.cap.credentials ⊆ parent.cap.credentials`
7. Chain depth limited (default: 3 levels)

All tokens are signed by the navra root key, even delegated ones.
The delegation chain is tracked via the `parent` nonce field. This
ensures the kernel can verify any token without traversing a chain
of intermediate signers.

### 4.5 Credential Brokering

Agents never access raw credentials. The microkernel acts as a
broker:

1. User maps credential labels to backend sources in configuration
   (explicit consent — navra cannot discover other keyring entries)
2. Capability tokens grant access to specific credential labels
3. At tool execution time, navra reads the credential from the OS
   keyring and injects it into the tool's execution context
4. The credential is scrubbed from the environment after the tool
   completes
5. Every access is logged with agent DID, label, and consuming tool

Supported backends: OS keyring (GNOME Keyring, KWallet, macOS
Keychain, Windows Credential Manager), environment variables.

### 4.6 Mandatory Content Filtering

Content safety filtering runs as a hook in the kernel's pipeline,
not as a userland advisory. This is mandatory access control —
agents cannot disable it. Filters include:

- Regex-based secret detection (API keys, private keys, credentials)
- PII detection (SSN, credit cards, email addresses)
- ML-based classification (ONNX models loaded in-process)
- Custom patterns per permission set

### 4.7 Information Flow Control

The kernel tracks data provenance through tool calls using a
two-dimensional label system inspired by Bell-LaPadula [78]:

**Integrity** — `Trusted` (system-generated) or `Untrusted`
(external data that may contain prompt injection payloads).

**Confidentiality** — `Public` (can flow anywhere), `Sensitive`
(restricted), or `Secret` (cannot leave the system).

Every tool result carries a `DataLabel`. The session maintains
a `TaintTracker` that accumulates labels via lattice join —
taint only rises, never drops. When an agent reads external data
(e.g., `file_read`), the session becomes tainted with
`Untrusted`. Subsequent write operations (e.g., `file_write`,
`git_commit`) are checked against the permission set's IFC
policy:

- **Allow** — tainted writes permitted (default, for backward
  compatibility)
- **Approve** — tainted writes require human approval
- **Deny** — tainted writes rejected entirely

This implements Bell-LaPadula's "no write-down" rule: a session
that has read sensitive data cannot write to a less-sensitive
destination. Applied to prompt injection: an agent that has read
untrusted external data (which may contain injected instructions)
is prevented from executing write operations that could exfiltrate
or corrupt data.

The labeling is automatic: tool outputs from external-read
operations (`file_read`, `file_search`, `git_diff`, `git_log`)
are labeled `Untrusted+Sensitive` by the kernel. Tool handlers
can also set labels explicitly via `CallToolResult::with_label()`.

This approach is consistent with FIDES [63] and CaMeL [67] but
operates at a coarser granularity — we track per-session taint
rather than per-value labels. This is a pragmatic choice: the
LLM between tool calls is opaque, so we conservatively assume
any untrusted input may propagate to any output.

### 4.8 Security Properties

We claim the following properties, subject to the assumptions
that the kernel implementation is correct and the cryptographic
primitives are unbroken:

**Property 1: No privilege escalation.** A capability token should
not grant more access than its issuer holds. Enforced by delegation
validation and deny-wins ACLs. Verified by 5 escalation tests
(Section 8.1).

**Property 2: Credential isolation.** Under normal operation, no
agent process holds raw secret material. Credentials are resolved
and injected by the kernel. This property does not protect against
covert channels [3] or side-channel leakage [19].

**Property 3: Attenuation only.** Delegation is designed to only
narrow capabilities. Ring level can only increase (less privileged).
Expiry can only decrease (shorter-lived). Verified by delegation
validation tests (Section 8.1).

**Property 4: Audit trail.** Tool calls, credential accesses, and
delegation events are logged with the agent's DID, the capability
token's nonce, and the operation performed. The completeness of
the audit trail depends on correct instrumentation of all code
paths.

**Property 5: Tamper evidence.** Tokens are Ed25519-signed.
Modification to payload or capabilities invalidates the signature,
assuming the Ed25519 implementation is constant-time and the
signing key has not been compromised [28].

---

## 5. Inter-Agent Communication

### 5.1 Tool Invocation (MCP)

Agents invoke tools via the Model Context Protocol over HTTP with
Server-Sent Events. Each request carries a capability token in the
Authorization header. The kernel verifies the token, checks the
tool against the token's grants, runs pre-hooks, executes the tool,
runs post-hooks (including safety filtering), and returns the result.

### 5.2 Agent-to-Agent Messaging (A2A)

Agents communicate via the A2A protocol at the `/a2a` endpoint.
Supported methods:

| Method | Description |
|---|---|
| message/send | Synchronous task execution |
| message/stream | Streaming via SSE (submitted → working → artifact → completed) |
| tasks/get | Retrieve task by ID |
| tasks/cancel | Cancel non-terminal tasks |

A2A requests are authenticated with the same capability tokens as
MCP requests.

### 5.3 Intra-Flow Mesh Communication

Within a multi-agent flow, agents communicate through three
IFC-gated primitives that go beyond sequential handoffs:

**Agent Mailbox.** Each agent receives an mpsc-backed mailbox.
Agents post lateral messages via the `mesh_post` virtual tool.
Every message carries the sender's DataLabel and delivery is
checked against the receiver's clearance level using Bell-LaPadula
no-write-down: a Sensitive-tainted sender cannot write to a
Public-clearance receiver. An audit log records all deliveries
for orchestrator inspection.

**Shared Blackboard.** A flow-level key-value store where each
entry carries a DataLabel. Agents publish via `bb_publish` and
read via `bb_read`. The critical IFC property: reading an entry
absorbs its label into the reader's taint tracker via lattice
join. This means an agent that reads sensitive data becomes
sensitive-tainted — and subsequent mailbox posts from that agent
are subject to the higher taint level. Taint only rises, never
drops.

**Conditional Back-Edges.** DAG edges that route execution
backward when post-completion conditions are not met (validation
score below threshold, missing success criteria, output pattern
matching). Back-edges are bounded by `max_iterations` to prevent
infinite loops. They are stored separately from the
DependencyGraph (which remains acyclic for topological sort) and
evaluated as post-completion routing decisions. Activation
invalidates downstream results via transitive dependent tracking.

These primitives are exposed to agents as virtual tools (injected
alongside MCP tools) and intercepted by the flow engine before
reaching the MCP layer. The key invariant: **every communication
path is IFC-gated**. Mailbox delivery checks `can_write_to()`,
blackboard reads propagate taint, and back-edge re-execution
preserves accumulated taint from prior iterations.

### 5.4 Discovery

Agents discover each other through four complementary mechanisms:

| Mechanism | Scope | Protocol |
|---|---|---|
| AID (DNS TXT) | Internet | DNS TXT records with MCP URLs + PKA |
| AID (HTTP fallback) | Internet | `/.well-known/agent` JSON |
| Agent Card | Internet/LAN | `/.well-known/agent.json` (A2A) |
| mDNS/DNS-SD | Local network | Zero-config multicast discovery |

The Agent Card includes the kernel's DID, enabling cryptographic
identity verification before establishing a connection.

---

## 6. Resource Management

### 6.1 Process Table

The kernel maintains a process table tracking every agent that has
made a tool call. Each entry records:

| Field | Description |
|---|---|
| name | Agent identifier |
| permissions | Permission set name (or `cap:ringN` for capability-authenticated agents) |
| did | DID:key identifier (if capability-token authenticated) |
| ring | Privilege ring level |
| call_count | Total tool calls made |
| denied_count | Tool calls denied (permission or quota) |
| uptime_secs | Seconds since first activity |
| idle_secs | Seconds since last activity |
| active_calls | Currently executing tool names |

The process table is exposed via `GET /sys/status` (JSON endpoint,
no authentication required — analogous to `/proc` in Linux). It
returns the process table plus session count.

Unlike traditional OS process tables that track PID/memory/CPU, the
AI OS process table tracks tool calls and privilege levels. The
relevant "resource" for an AI agent is not CPU cycles but API calls,
credential accesses, and tool invocations.

### 6.2 Resource Quotas

The kernel enforces rate limits via a token bucket algorithm. Each
permission set can declare a rate limit:

```toml
[permissions.specialist]
ring = 2
rate_limit = "60/60"   # 60 calls per 60 seconds
```

The quota engine creates a per-agent bucket on first use. Tokens
refill continuously at `max_calls / window_secs` per second. When
an agent exhausts its bucket, tool calls return an error immediately
— the agent must wait for tokens to refill.

Properties:
- **Kernel-enforced** — agents cannot bypass or increase their
  allocation. The check runs before tool permission checks.
- **Per-agent isolation** — each agent has its own bucket. One
  agent exhausting its quota does not affect others.
- **Burst-friendly** — token buckets allow short bursts up to
  `max_calls` while enforcing the average rate over the window.

### 6.3 Agent Lifecycle

The full lifecycle of an agent in the AI OS:

```
1. Registration    — Agent configured in config.toml with
                     token_hash, permissions, optional DID
2. Token issuance  — On startup, navra issues capability tokens
                     for agents with capability_token = true
3. Authentication  — Agent presents Bearer token (cap or BLAKE3)
4. Session         — MCP initialize creates a session (UUID)
5. Tool calls      — Each call: auth → quota → permission → hooks
                     → handler → post-hooks → safety filter
6. Delegation      — Agent calls cap_delegate to issue sub-tokens
7. Monitoring      — Process table tracks calls, denials, activity
8. Expiry          — Capability tokens expire (default: 1 hour)
9. Cleanup         — Session removed, process table entry retained
                     for audit
```

The kernel (navra) runs as a systemd user service, started at login
and stopped at logout. The system tray icon provides pause/resume
and approval UI.

---

## 7. Implementation

### 7.1 navra (Microkernel)

- **Language:** Rust
- **Transport:** Axum (async HTTP), SSE, Unix sockets
- **Cryptography:** `ed25519-dalek` (signing), BLAKE3 (legacy
  tokens), CBOR via `ciborium` (token encoding)
- **Credential store:** `keyring` crate (cross-platform)
- **Safety models:** ONNX Runtime (in-process ML inference)
- **Discovery:** `mdns-sd` crate, custom AID implementation
- **Lines of code:** ~24K (Rust)

### 7.2 navra (Userland)

- **Language:** Python (Poetry, Python 3.14)
- **Orchestration:** Three-tier hierarchy:
  `AdaptiveOrchestrator` (Tier 3, full DAG replanning) →
  `ProjectOrchestrator` (Tier 2, specialist coordination) →
  `ConcurrentOrchestrator` (Tier 1, parallel execution with
  dependency awareness and resource throttling)
- **Personas:** 40+ YAML-defined cognitive agents, JSON Schema
  validated, compiled by ForgeService with pickle caching (~2ms
  startup vs ~50ms from YAML). Composable via specializations.
- **Engines:** Claude (Direct API + Vertex AI), Gemini. Per-persona
  model selection with planning/execution phase distinction.
- **Cognitive immune system:** Four-tier supervision (agent →
  watchdog → analyst → replanner). Anomaly detection every 15s.
  Detects: repetition, stagnation, drift, quality degradation.
- **Memory:** Four-tier hierarchy (working → session → long-term →
  knowledge corpus). SQLite-backed recorder service (event store).
- **Validation:** Jury service (multi-judge consensus), devil's
  advocate (adversarial testing), hierarchical validation.
- **Distribution:** Docker Compose (recorder, cognition, prometheus,
  grafana). OCI artifacts + sigstore for cognitive plugins.
- **MCP integration:** `MCPConnectionManager` (SSE, streamable-HTTP,
  stdio), `MCPToolProvider` (per-task tool tracking),
  `MCPTaskExecutor` (context assembly from dependency results).
- **A2A:** Agent cards generated per persona with capability
  classification (orchestrator, specialist, analyst, synthesizer).
- **Lines of code:** ~64K (Python)

### 7.3 Module Architecture

Kernel modules implement a `Module` trait:

```rust
pub trait Module: Send + Sync {
    fn name(&self) -> &str;
    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)>;
}
```

Built-in modules: docs (FTS5 + sqlite-vec), git, RAG (semantic
search), voice (ASR + TTS), vision (OCR + image understanding).
External MCP servers are wrapped as `UpstreamModule`, subject to
the same security pipeline.

### 7.4 Token Format and Size

See Section 8.2 for measured token sizes and latency benchmarks.

---

## 8. Evaluation

### 8.1 Security Evaluation

We test each of the five security properties (Section 4.7) with
concrete attack scenarios. All tests are in
`navra-core/tests/security_eval.rs` (28 tests).

#### Property 1: No Privilege Escalation (5 tests)

| Attack | Result |
|---|---|
| Delegate with lower ring number (0 vs parent's 1) | Rejected: "ring escalation" |
| Add operation not in parent ("shell.exec") | Rejected: "operation escalation" |
| Add credential not in parent ("aws.secret") | Rejected: "credential escalation" |
| Extend expiry beyond parent's | Rejected: "expiry exceeds parent" |
| Forge parent nonce reference | Rejected: "parent nonce" |

#### Property 2: Credential Isolation (5 tests)

| Attack | Result |
|---|---|
| Resolve unlisted credential label | Rejected: "unknown credential label" |
| Access env var not in config mappings | Rejected: label not configured |
| Delegate with extra credential label | Rejected: "credential escalation" |
| Store value to env-sourced credential | Rejected: "cannot store to env" |
| Token contains labels, not raw secrets | Verified: CBOR payload has label strings only |

#### Property 3: Attenuation Only (2 tests)

| Scenario | Result |
|---|---|
| Valid 2-level attenuation chain (root→leader→specialist) | Passes validation |
| Maximally attenuated child (empty capabilities, ring 3, 60s TTL) | Passes validation |

#### Property 4: Audit Trail (3 tests)

| Scenario | Result |
|---|---|
| Token contains issuer + subject DID | Verified |
| Each token has unique random nonce | Verified (nonces differ across calls) |
| Delegation chain traceable via parent nonce field | Verified (child.parent == parent.nonce) |

#### Property 5: Tamper Evidence (7 tests)

| Attack | Result |
|---|---|
| Sign token with wrong key (impersonation) | Rejected: signature verification fails |
| Modify CBOR payload bytes after signing | Rejected: signature verification fails |
| Truncate signature to 32 bytes (half) | Rejected: invalid signature length |
| Present expired token with valid signature | Rejected: "token expired" |
| Set unsupported version (v=99) | Rejected: "unsupported token version" |
| Malformed token strings (empty, wrong prefix, bad base64) | Rejected: format validation |
| Forged cap token presented to ChainAuthenticator | Rejected: cap auth fails, falls through to BLAKE3 which also rejects |

#### Auth Chain Integration (3 tests)

| Scenario | Result |
|---|---|
| BLAKE3-authenticated agent has no capabilities | Verified: `identity.capabilities` is None |
| Cap-authenticated agent has resolved capabilities | Verified: ring, operations, tools present |
| Chain: cap token handled first, BLAKE3 falls through, unknown rejected | Verified: correct dispatch |

#### Rate Limiting (3 tests)

| Scenario | Result |
|---|---|
| Agent exceeds configured rate limit | Denied on call N+1 |
| Unconfigured permission set is unlimited | No limit applied |
| Per-agent isolation (Alice's exhaustion doesn't affect Bob) | Verified |

**Summary:** All 28 attack scenarios are correctly handled. No
false negatives (attacks that should be blocked but aren't). No
false positives (legitimate operations incorrectly blocked).

### 8.2 Performance Evaluation

Measured on AMD Ryzen (Fedora 43, Rust 1.x release build,
10,000 iterations, `ed25519-dalek` 2.x, `ciborium` 0.2):

#### Token Operation Latency

| Operation | Latency/op | Throughput |
|---|---|---|
| BLAKE3 hash (baseline) | 101 ns | 9.9M ops/sec |
| Delegation validation | 131 ns | 7.6M ops/sec |
| Token encode + Ed25519 sign | 11.4 μs | 87K ops/sec |
| Token verify + decode | 14.0 μs | 72K ops/sec |

**Overhead vs BLAKE3:** Capability token verification (14 μs) is
~140x slower than BLAKE3 hashing (0.1 μs), but still sub-millisecond
and negligible relative to LLM inference latency (100ms-10s per
agent turn). At 72K verifications/second, the auth layer is never
the bottleneck.

**Delegation validation** is sub-microsecond (no cryptography —
pure subset checks on strings and integers). This means delegation
chains add no measurable overhead beyond the initial token
verification.

#### Token Size

| Payload | Size (bytes) |
|---|---|
| Minimal (1 op, 1 tool glob, ring 3) | 375 |
| Typical (5 ops, 3 tool globs, 2 paths, 2 creds) | 541 |
| Large (15 ops, 10 tool globs, 10 paths, 5 creds) | 773 |

All tokens fit comfortably in HTTP Authorization headers (typical
limit: 8KB). CBOR encoding contributes ~40% size reduction vs
equivalent JSON payloads.

### 8.3 Comparison with Existing Approaches

We compare our approach against four alternatives along seven
security dimensions. Each cell indicates whether the property is
fully provided (+), partially provided (~), or absent (-).

| Property | No isolation | API keys | OAuth 2.0 [26] | MS Governance [84] | **navra (ours)** |
|---|---|---|---|---|---|
| Agent isolation | - | - | ~ | + | **+** |
| Least privilege | - | - | ~ (scopes) | ~ (rings) | **+ (capabilities)** |
| Delegation chains | - | - | - | - | **+ (attenuation)** |
| Credential isolation | - | - | - | ~ | **+** |
| Cryptographic identity | - | - | ~ (client_id) | + (DIDs) | **+ (DID:key)** |
| Token expiry | - | ~ (rotation) | + (exp claim) | + | **+** |
| Audit trail | - | ~ (logs) | ~ (logs) | + | **+** |

#### No isolation (shared-context multi-agent)

Frameworks like Claude Code Agent Teams, LangGraph, and CrewAI
run multiple agents in a shared process. Every agent can read
every file, call every tool, and access every credential. There
is no security boundary — all isolation depends on the model
following system prompt instructions. Prompt injection [48] or
model drift breaks any soft boundary.

#### Plain API keys

Each agent gets a static API key (e.g., BLAKE3 hashed bearer
token as in navra's legacy mode). Keys have no expiry, no scope,
and no delegation model. An agent with a key has the same access
as any other agent with the same key. Revocation requires
configuration change and restart. Key theft grants full access
with no attenuation.

#### OAuth 2.0 with scopes [26]

OAuth 2.0 provides token expiry, refresh flows, and scope-based
access control. However, scopes are coarse-grained strings
defined by the authorization server — they cannot express path
globs, tool patterns, or credential labels. Delegation is not
part of the OAuth 2.0 core specification (it requires the Token
Exchange extension, RFC 8693, which is rarely implemented for
AI agents). Credential isolation is absent — the agent receives
the access token directly.

#### Microsoft Agent Governance Toolkit [84]

The closest industry parallel. Provides DID-based identity
(Agent Mesh), execution rings (Agent Runtime), and policy
enforcement. However:

- **Middleware, not kernel** — operates as an interceptor in the
  agent framework pipeline, not as a system-level enforcer. An
  agent that bypasses the framework bypasses governance.
- **No capability delegation** — identity is verified, but there
  is no mechanism for a leader agent to issue attenuated tokens
  to specialists.
- **No credential brokering** — secrets are managed at the
  deployment layer, not mediated by the governance runtime.
- **Policy language (OPA/Cedar)** — more expressive than our
  TOML-based configuration, but adds complexity and a learning
  curve.

#### navra (ours)

Our capability model aims to provide all seven properties. The
key differentiators relative to existing approaches are:

1. **Delegation with attenuation** — to our knowledge, no other
   agent security system supports a leader agent issuing a
   cryptographically signed, narrower token to a specialist.
   This enables least privilege in multi-agent hierarchies.
2. **Credential brokering** — the kernel reads credentials from
   the OS keyring and injects them into tool execution contexts,
   reducing the exposure of raw secret material to agent processes.
3. **Kernel enforcement** — security is enforced at the
   infrastructure layer (Rust process), not in the agent
   framework (Python/TypeScript). This makes security less
   dependent on correct agent implementation.

#### Performance comparison

| Approach | Auth latency | Token size | Notes |
|---|---|---|---|
| No isolation | 0 | 0 | No auth check |
| API key (BLAKE3) | 0.1 μs | 36 bytes | Hash comparison |
| OAuth 2.0 (JWT) | ~5--50 μs | 300--800 bytes | RSA/ECDSA verify |
| MS Governance | N/A (middleware) | N/A | Policy engine check |
| **navra cap token** | **14 μs** | **375--773 bytes** | Ed25519 verify + CBOR decode |

Our 14 μs verification latency is higher than BLAKE3 (0.1 μs)
but negligible relative to LLM inference (100 ms--10 s). The
trade-off buys cryptographic non-forgeability, delegation chains,
embedded capabilities, and token expiry — none of which BLAKE3
hashing provides.

---

## 9. Discussion

### 9.1 Limitations

- **No formal verification** — The capability model is tested but
  not formally verified (unlike seL4 [15]). A Coq/Lean
  formalization would strengthen the security argument.

- **Trust in the kernel** — navra is the TCB. A vulnerability in
  navra compromises all security properties. Rust's memory safety
  mitigates but does not eliminate this risk. The confused deputy
  problem [7] applies: navra's tool handlers execute with system-
  level ambient authority [14] while acting on behalf of agents.

- **Prompt injection is out of scope** — The kernel enforces which
  tools an agent may call, but does not address indirect prompt
  injection [48], which can manipulate the agent into misusing its
  *legitimately granted* tools. The MCP-specific attack in [56]
  and cross-agent infection in [51] suggest that capability
  tokens limit blast radius but do not prevent semantic-level
  attacks. We consider this the most significant limitation of
  the current architecture.

- **Covert channels** — Lampson's confinement problem [3] applies.
  Safety filters catch content-level exfiltration, but information
  can leak through timing, error patterns, or resource consumption.
  Timing attacks [19][23] and microarchitectural side channels [37]
  are additional vectors. The `ed25519-dalek` crate provides
  constant-time operations, but the broader auth path needs
  auditing.

- **Key management** — Gutmann [28] argues key management defeats
  theoretically sound systems. Our DID:key identities have no key
  recovery mechanism by design [34]. Key rotation requires token
  reissuance across all delegated agents.

- **Administrative scalability** — As agent populations grow, per-
  agent capability tokens are harder to manage than role
  assignments [10]. A role-to-capability mapping layer may be
  needed.

- **Single-machine scope** — The current implementation assumes
  navra and all agents run on the same machine. Distributed
  deployment would require network-level token verification,
  encrypted IPC, and federated trust management [20][21].

### 9.2 Toward Structural Prompt Injection Defenses

A recurring pattern emerges across six domains: **classification-
based defenses tend to be fragile against adaptive adversaries,
while structural separation offers stronger guarantees.**

| Domain | Failed approach | Structural solution |
|---|---|---|
| Immunology [69] | Self/non-self classification | Danger signals from effects |
| Byzantine systems [72] | Trust individual nodes | Consensus among N >= 3f+1 |
| Capability runtimes [16] | Check permissions at call time | Pre-opened handles, no ambient authority |
| Social engineering | Train humans to detect lies | Mandatory out-of-band verification |
| Game theory [77] | Assume rational cooperation | Incentive-compatible mechanism design |
| Computability [79] | Build a perfect detector | Separate control from data flow [67] |

Two recent systems embody this principle for LLM agents:

**CaMeL** [67] (Google DeepMind) attaches capability metadata to
every value flowing through the agent, tracking provenance so
that data from untrusted sources can never influence control
flow. This achieves provable security on 77% of AgentDojo tasks.

**FIDES** [63] (Microsoft Research) applies classical information
flow control [60][61] to LLM agents, tracking confidentiality
and integrity labels at tool-call sinks. It achieves zero
policy-violating injections in AgentDojo.

Both approaches are consistent with our architectural thesis: that
structural separation of concerns may offer more durable defenses
than detection-based approaches. However, our current capability
model gates *access* to tools but does not yet track *data flow*
through them — bridging this gap by integrating IFC-style taint
labels into navra's hook pipeline is the primary direction for
future work.

Matzinger's danger model [69] suggests an orthogonal approach:
instead of classifying instructions as legitimate or injected,
monitor for *damage patterns* in system behavior (unexpected
writes, anomalous API calls, credential access outside normal
patterns). navra's Cognitive Immune System already implements
this via the watchdog/analyst supervisory architecture — the
same principle that Forrest et al. [70][71] applied to intrusion
detection by monitoring system call sequences for anomalies.

Nasr et al. [68] tested 12 published defenses with adaptive
attacks and bypassed all with >90% success. This sobering result
suggests that detection-based defenses alone may be insufficient
against sophisticated adversaries. Architectural separation
(CaMeL, FIDES) and blast-radius containment (our capability
model) appear more resilient, though further evaluation against
adaptive attacks is needed for our specific implementation.

### 9.3 Future Work

- **Per-value information flow control** — Our current IFC
  implementation (Section 4.7) tracks per-session taint. A finer-
  grained approach would track per-value labels as in FIDES [63],
  enabling agents to continue making trusted writes even after
  reading some untrusted data, as long as the write content does
  not derive from the untrusted input.

- **Byzantine consensus for sensitive operations** — For high-risk
  tool calls (git push, credential access), require consensus
  from multiple agents [74] or a separate verification agent
  before execution.

- **Agent behavioral contracts** [75] — Formalize preconditions,
  postconditions, and invariants for tool calls. Runtime
  verification [76] can enforce these contracts deterministically.

- **Post-quantum migration** — Implementing the `HybridSigner`
  (Ed25519 + ML-DSA-65) and the v2 token format with embedded
  composite signatures.

- **Formal verification** — Formalizing the capability model's
  security properties in a proof assistant.

- **Distributed kernel** — Extending navra to a cluster of kernels
  with federated identity and cross-kernel capability delegation.

- **AI OS shell** — An interactive interface for humans to manage
  agents, inspect state, issue tokens, and approve operations.

### 9.4 Broader Implications

The AI OS abstraction suggests that decades of operating system
research — from Multics [1] to seL4 [15] — may be more directly
applicable to AI agent infrastructure than is commonly recognized.
As agents become more autonomous, the case for kernel-enforced
security strengthens, though the right balance between protection
and usability remains an open question.

---

## 10. Conclusion

We presented an AI Operating System architecture that applies
classical OS principles to multi-agent AI systems. The microkernel
(navra) provides capability-based security with DID:key identity,
graduated privilege rings, credential brokering, and mandatory
content filtering. The userland (navra) provides multi-agent
orchestration, cognitive personas, and task planning. The two
communicate via standard protocols (MCP for tool invocation, A2A
for inter-agent messaging), enabling clean separation of mechanism
and policy.

Our capability token model targets five security properties:
no privilege escalation, credential isolation, attenuation-only
delegation, audit trail, and tamper evidence. These properties
are verified by 28 security evaluation tests but have not been
formally proven. The system is algorithm-agile, with a migration
path to post-quantum cryptography.

Significant limitations remain. Prompt injection can manipulate
agents into misusing legitimately granted permissions — a problem
that capability tokens constrain but do not solve. Information
flow control [63][67] and behavioral contracts [75] are promising
complementary directions. Key management [28] and administrative
scalability [10] are practical challenges that grow with agent
populations.

The implementation runs on commodity Linux desktops and
demonstrates that classical OS security principles — capabilities,
rings, mandatory access control, credential mediation — can be
applied to AI agent infrastructure. Whether this architectural
approach scales to the diversity and autonomy of future agent
ecosystems remains to be seen, but we believe the OS analogy
provides a productive framework for reasoning about the problem.

---

## References

### Operating System Foundations

[1] Corbato, F. J. and Vyssotsky, V. A. "Introduction and
    Overview of the Multics System." In *Proc. AFIPS Fall Joint
    Computer Conference*, vol. 27, part 1, pp. 185--196, 1965.

[2] Dennis, J. B. and Van Horn, E. C. "Programming Semantics for
    Multiprogrammed Computations." *Communications of the ACM*,
    9(3):143--155, March 1966. DOI: 10.1145/365230.365252.

[3] Lampson, B. W. "A Note on the Confinement Problem."
    *Communications of the ACM*, 16(10):613--615, October 1973.
    DOI: 10.1145/362375.362389.

[4] Saltzer, J. H. and Schroeder, M. D. "The Protection of
    Information in Computer Systems." *Proceedings of the IEEE*,
    63(9):1278--1308, September 1975. DOI: 10.1109/PROC.1975.9939.

[5] Hardy, N. "The KeyKOS Architecture." *Operating Systems
    Review*, 19(4), September 1985.

[6] Accetta, M., Baron, R., Bolosky, W., Golub, D., Rashid, R.,
    Tevanian, A., and Young, M. "Mach: A New Kernel Foundation
    for UNIX Development." In *Proc. USENIX Summer Conference*,
    pp. 93--112, Atlanta, GA, July 1986.

[7] Hardy, N. "The Confused Deputy: (or why capabilities might
    have been invented)." *ACM SIGOPS Operating Systems Review*,
    22(4):36--38, October 1988. DOI: 10.1145/54289.871709.

[8] Bomberger, A. C., Frantz, W. S., Hardy, A. C., Hardy, N.,
    Landau, C. R., and Shapiro, J. S. "The KeyKOS Nanokernel
    Architecture." In *Proc. USENIX Workshop on Micro-Kernels
    and Other Kernel Architectures*, pp. 95--112, April 1992.

[9] Liedtke, J. "On Micro-Kernel Construction." In *Proc. 15th
    ACM SOSP*, pp. 237--250, December 1995. DOI: 10.1145/224056.224075.

[10] Sandhu, R. S., Coyne, E. J., Feinstein, H. L., and Youman,
     C. E. "Role-Based Access Control Models." *IEEE Computer*,
     29(2):38--47, February 1996. DOI: 10.1109/2.485845.

[11] Shapiro, J. S., Smith, J. M., and Farber, D. J. "EROS: A
     Fast Capability System." In *Proc. 17th ACM SOSP*, pp. 170--185,
     December 1999. DOI: 10.1145/319151.319163.

[12] Loscocco, P. and Smalley, S. "Integrating Flexible Support
     for Security Policies into the Linux Operating System." In
     *Proc. FREENIX Track, 2001 USENIX Annual Technical Conference*,
     pp. 29--42, Boston, MA, 2001.

[13] Miller, M. S., Yee, K.-P., and Shapiro, J. "Capability
     Myths Demolished." Technical Report SRL2003-02, Johns Hopkins
     University, 2003.

[14] Miller, M. S. *Robust Composition: Towards a Unified Approach
     to Access Control and Concurrency Control.* PhD thesis, Johns
     Hopkins University, May 2006.

[15] Klein, G., Elphinstone, K., Heiser, G., et al. "seL4: Formal
     Verification of an OS Kernel." In *Proc. 22nd ACM SOSP*,
     pp. 207--220, October 2009. DOI: 10.1145/1629575.1629596.

[16] Watson, R. N. M., Anderson, J., Laurie, B., and Kennaway, K.
     "Capsicum: Practical Capabilities for UNIX." In *Proc. 19th
     USENIX Security Symposium*, August 2010.

[17] Hu, V. C., Ferraiolo, D., Kuhn, R., et al. *Guide to
     Attribute Based Access Control (ABAC) Definition and
     Considerations.* NIST SP 800-162, January 2014.

[18] Heiser, G. and Elphinstone, K. "L4 Microkernels: The Lessons
     from 20 Years of Research and Deployment." *ACM Transactions
     on Computer Systems*, 34(1), 2016.

### Cryptography, Identity, and Trust

[19] Kocher, P. C. "Timing Attacks on Implementations of Diffie-
     Hellman, RSA, DSS, and Other Systems." In *CRYPTO '96*,
     LNCS 1109, pp. 104--113, 1996. DOI: 10.1007/3-540-68697-5_9.

[20] Blaze, M., Feigenbaum, J., and Lacy, J. "Decentralized Trust
     Management." In *Proc. IEEE S&P '96*, pp. 164--173, 1996.

[21] Blaze, M., Feigenbaum, J., Ioannidis, J., and Keromytis, A. D.
     "The KeyNote Trust-Management System Version 2." RFC 2704,
     September 1999.

[22] Ellison, C., Frantz, B., Lampson, B., Rivest, R., Thomas, B.,
     and Ylonen, T. "SPKI Certificate Theory." RFC 2693, September
     1999.

[23] Brumley, D. and Boneh, D. "Remote Timing Attacks Are
     Practical." In *12th USENIX Security Symposium*, August 2003.

[24] Neuman, B. C. and Ts'o, T. "Kerberos: An Authentication
     Service for Computer Networks." *IEEE Communications
     Magazine*, 32(9):33--38, 1994.

[25] Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., and
     Yang, B.-Y. "High-Speed High-Security Signatures." *Journal
     of Cryptographic Engineering*, 2(2):77--89, 2012.
     DOI: 10.1007/s13389-012-0027-1.

[26] Hardt, D., Ed. "The OAuth 2.0 Authorization Framework."
     RFC 6749, October 2012. DOI: 10.17487/RFC6749.

[27] Birgisson, A., Politz, J. G., Erlingsson, U., Taly, A.,
     Vrable, M., and Lentczner, M. "Macaroons: Cookies with
     Contextual Caveats for Decentralized Authorization in the
     Cloud." In *NDSS '14*, 2014. DOI: 10.14722/NDSS.2014.23212.

[28] Gutmann, P. *Engineering Security.* University of Auckland,
     2014. https://www.cs.auckland.ac.nz/~pgut001/pubs/book.pdf

[29] Bormann, C. and Hoffman, P. "Concise Binary Object
     Representation (CBOR)." STD 94, RFC 8949, December 2020.
     DOI: 10.17487/RFC8949.

[30] Rose, S., Borchert, O., Mitchell, S., and Connelly, S.
     *Zero Trust Architecture.* NIST SP 800-207, August 2020.
     DOI: 10.6028/NIST.SP.800-207.

[31] W3C. "Decentralized Identifiers (DIDs) v1.0." W3C
     Recommendation, July 2022.
     https://www.w3.org/TR/did-core/

[32] Sporny, M., Ed. "The did:key Method v0.9." W3C Credentials
     Community Group, Editor's Draft.
     https://w3c-ccg.github.io/did-key-spec/

[33] Longley, D., Sporny, M., and Zagidulin, D. *Authorization
     Capabilities for Linked Data (ZCAP-LD)*, v0.3. W3C CCG, 2022.
     https://w3c-ccg.github.io/zcap-spec/

[34] W3C DID Working Group. "DID Formal Objection FAQ." 2021.
     https://www.w3.org/2019/did-wg/faqs/2021-formal-objections/

[35] Backman, A., Ed., Richer, J., Ed., and Sporny, M. "HTTP
     Message Signatures." RFC 9421, February 2024.
     DOI: 10.17487/RFC9421.

[36] NIST. "Module-Lattice-Based Digital Signature Standard
     (ML-DSA)." FIPS 204, August 2024.
     https://csrc.nist.gov/pubs/fips/204/final

[37] Ge, Q., Yarom, Y., Cock, D., and Heiser, G. "A Survey of
     Microarchitectural Timing Attacks and Countermeasures on
     Contemporary Hardware." *Journal of Cryptographic Engineering*,
     8:1--27, 2018. DOI: 10.1007/s13389-016-0141-6.

### Multi-Agent Systems

[38] Wooldridge, M. and Jennings, N. R. "Intelligent Agents:
     Theory and Practice." *The Knowledge Engineering Review*,
     10(2):115--152, 1995. DOI: 10.1017/S0269888900008122.

[39] Rao, A. S. and Georgeff, M. P. "BDI Agents: From Theory to
     Practice." In *Proc. First International Conference on
     Multiagent Systems (ICMAS-95)*, pp. 312--319, 1995.

[40] Foundation for Intelligent Physical Agents (FIPA). *FIPA ACL
     Message Structure Specification.* SC00061G, 2002.
     http://www.fipa.org/specs/fipa00061/

### AI Agent Protocols

[41] Anthropic. "Model Context Protocol Specification." November
     2024. https://modelcontextprotocol.io/specification

[42] Google. "Agent-to-Agent (A2A) Protocol." April 2025.
     https://google.github.io/A2A/

[43] AID Community. "Agent Identity & Discovery Specification."
     2025. https://aid.agentcommunity.org/docs/specification

### LLM Agent Tool Use

[44] Nakano, R., Hilton, J., Balaji, S., et al. "WebGPT: Browser-
     Assisted Question-Answering with Human Feedback."
     arXiv:2112.09332, December 2021.

[45] Schick, T., Dwivedi-Yu, J., Dessi, R., et al. "Toolformer:
     Language Models Can Teach Themselves to Use Tools." In
     *NeurIPS 2023*. arXiv:2302.04761.

[46] Yao, S., Zhao, J., Yu, D., et al. "ReAct: Synergizing
     Reasoning and Acting in Language Models." In *ICLR 2023*.
     arXiv:2210.03629.

[47] Mialon, G., Dessi, R., Lomeli, M., et al. "Augmented
     Language Models: a Survey." *Transactions on Machine Learning
     Research (TMLR)*, 2023. arXiv:2302.07842.

### AI Agent Security

[48] Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T.,
     and Fritz, M. "Not What You've Signed Up For: Compromising
     Real-World LLM-Integrated Applications with Indirect Prompt
     Injection." In *ACM AISec '23*, 2023.
     DOI: 10.1145/3605764.3623985.

[49] He, Y., Wang, E., Rong, Y., Cheng, Z., and Chen, H.
     "Security of AI Agents." arXiv:2406.08689, June 2024.

[50] Zhan, Y., et al. "INJECAGENT: Benchmarking Indirect Prompt
     Injections in Tool-Integrated LLM Agents." In *Findings of
     ACL 2024*, 2024.

[51] "Prompt Infection: LLM-to-LLM Prompt Injection within
     Multi-Agent Systems." arXiv:2410.07283, October 2024.

[52] OWASP GenAI Security Project. "OWASP Top 10 for Agentic
     Applications for 2026." December 2025.
     https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

[53] Zhang, H., Huang, J., Mei, K., et al. "Agent Security
     Bench (ASB): Formalizing and Benchmarking Attacks and
     Defenses in LLM-based Agents." In *ICLR 2025*.
     arXiv:2410.02644.

[54] Hammond, L., Chan, A., Clifton, J., et al. "Multi-Agent
     Risks from Advanced AI." Cooperative AI Foundation,
     Technical Report #1, February 2025. arXiv:2502.14143.

[55] "Prompt Injection Attack to Tool Selection in LLM Agents
     (ToolHijacker)." arXiv:2504.19793, April 2025.

[56] "Log-To-Leak: Prompt Injection Attacks on Tool-Using LLM
     Agents via Model Context Protocol." OpenReview, October 2025.
     https://openreview.net/forum?id=UVgbFuXPaO

[57] Schroeder de Witt, C. "Open Challenges in Multi-Agent
     Security: Towards Secure Systems of Interacting AI Agents."
     arXiv:2505.02077, May 2025.

[58] "The Emerged Security and Privacy of LLM Agent: A Survey."
     *ACM Computing Surveys*, 2025. DOI: 10.1145/3773080.

[59] Doshi, A., Hong, Y., Xu, C., Kang, E., Kapravelos, A., and
     Kastner, C. "Towards Verifiably Safe Tool Use for LLM Agents."
     In *ICSE-NIER '26*, April 2026. arXiv:2601.08012.

### Information Flow Control

[60] Myers, A. C. and Liskov, B. "A Decentralized Model for
     Information Flow Control." In *Proc. 16th ACM SOSP*,
     pp. 129--142, 1997. Extended: *ACM TOSEM*, 9(4):410--442,
     2000. DOI: 10.1145/363516.363526.

[61] Stefan, D., Russo, A., Mitchell, J., and Mazieres, D.
     "Flexible Dynamic Information Flow Control in Haskell."
     In *Haskell Symposium 2011*. DOI: 10.1145/2034675.2034688.

[62] Stefan, D., Yang, E. Z., Marchenko, P., et al. "Protecting
     Users by Confining JavaScript with COWL." In *OSDI 2014*,
     pp. 131--146.

[63] Costa, M., Kopf, B., Kolluri, A., et al. "Securing AI
     Agents with Information-Flow Control (FIDES)." Microsoft
     Research, arXiv:2505.23643, May 2025.

### Prompt Injection Defenses

[64] Hines, K., Lopez, G., Hall, M., et al. "Defending Against
     Indirect Prompt Injection Attacks With Spotlighting." In
     *CAMLIS 2024*. arXiv:2403.14720.

[65] Wallace, E., Xiao, K., Leike, R., et al. "The Instruction
     Hierarchy: Training LLMs to Prioritize Privileged
     Instructions." OpenAI, arXiv:2404.13208, April 2024.

[66] Abdelnabi, S., et al. "Design Patterns for Securing LLM
     Agents against Prompt Injections." IBM/Invariant/ETH/Google/
     Microsoft, arXiv:2506.08837, June 2025.

[67] Debenedetti, E., Shumailov, I., Fan, T., et al. "Defeating
     Prompt Injections by Design (CaMeL)." Google DeepMind/ETH,
     arXiv:2503.18813, March 2025.

[68] Nasr, M., Carlini, N., Sitawarin, C., et al. "The Attacker
     Moves Second." OpenAI/Anthropic/DeepMind, arXiv:2510.09023,
     October 2025.

### Biological and Artificial Immune Systems

[69] Matzinger, P. "Tolerance, Danger, and the Extended Family."
     *Annual Review of Immunology*, 12:991--1045, 1994.

[70] Forrest, S., Perelson, A. S., Allen, L., and Cherukuri, R.
     "Self-Nonself Discrimination in a Computer." In *IEEE S&P*,
     1994.

[71] Somayaji, A., Hofmeyr, S. A., and Forrest, S. "Principles
     of a Computer Immune System." In *NSPW*, 1998.

### Byzantine Fault Tolerance

[72] Lamport, L., Shostak, R., and Pease, M. "The Byzantine
     Generals Problem." *ACM TOPLAS*, 4(3):382--401, July 1982.

[73] Castro, M. and Liskov, B. "Practical Byzantine Fault
     Tolerance." In *OSDI '99*, 1999.

[74] Zheng, L., Tian, Y., et al. "Rethinking the Reliability of
     Multi-agent System: A Perspective from Byzantine Fault
     Tolerance." In *AAAI 2026*. arXiv:2511.10400.

### Formal Methods for Agent Safety

[75] "Agent Behavioral Contracts: Formal Specification and Runtime
     Enforcement for Reliable Autonomous AI Agents."
     arXiv:2602.22302, February 2026.

[76] "AgentSpec: Customizable Runtime Enforcement for Safe and
     Reliable LLM Agents." arXiv:2503.18666, March 2025.

### Game Theory and Mechanism Design

[77] Duetting, P., Mirrokni, V., Paes Leme, R., et al. "Mechanism
     Design for Large Language Models." In *Proc. ACM Web
     Conference*, pp. 144--155, 2024.

### Mandatory Access Control and Information Flow

[78] Bell, D. E. and LaPadula, L. J. "Secure Computer Systems:
     Mathematical Foundations." MITRE Technical Report MTR-2547,
     vol. I, 1973.

### Computability and Impossibility

[79] Brcic, M. and Yampolskiy, R. V. "Impossibility Results in
     AI: A Survey." *ACM Computing Surveys*, 56(1), Article 8,
     2023. arXiv:2109.00484.

### Container and Sandbox Isolation

[80] Agache, A., Brooker, M., Iordache, A., et al. "Firecracker:
     Lightweight Virtualization for Serverless Applications." In
     *NSDI '20*, pp. 419--434, 2020.

[81] Young, E. G., Zhu, P., Caraza-Harter, T., Arpaci-Dusseau,
     A. C., and Arpaci-Dusseau, R. H. "The True Cost of
     Containing: A gVisor Case Study." In *HotCloud '19*, 2019.

### Industry Frameworks

[82] Ward, R. and Beyer, B. "BeyondCorp: A New Approach to
     Enterprise Security." *;login: The USENIX Magazine*,
     39(6):6--11, 2014.

[83] Microsoft. "Agent Framework v1.0." April 2026.
     https://devblogs.microsoft.com/agent-framework/

[84] Microsoft. "Agent Governance Toolkit: Open-Source Runtime
     Security for AI Agents." April 2026.
     https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit/

[85] GitHub. "Copilot Cloud Agent Commit Signing." April 2026.
     https://github.blog/changelog/2026-04-03-copilot-cloud-agent-signs-its-commits/
