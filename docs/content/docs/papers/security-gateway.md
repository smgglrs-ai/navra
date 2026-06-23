+++
title = "navra: A Security Microkernel for AI Agent Infrastructure"
weight = 10


template = "docs/page.html"
[extra]
toc = true
+++


**Authors**: Fabien Dupont et al.

**Target venue**: USENIX Security / IEEE S&P workshop track (ArtSec 2026 realistic)

### Review notes (2026-05-07, updated 2026-06-19)

- **DECIDED — Standalone, priority 2 for submission** (see
  `restructuring-decisions.md`). Flagship workshop paper.
- **DONE — Microkernel framing**: Security microkernel with 146 Kani
  proofs, process table, IPC, memory management, scheduler, MAC.
- **DONE — Narrow to 3 contributions**: (1) gateway-enforced IFC, (2)
  capability delegation with attenuation, (3) hash-chained audit.
- **DONE — FIDES differentiation**: §10, gateway vs planner enforcement.
- **DONE — MCP gateway landscape**: §10 acknowledges 10+ gateways.
- **DONE — Compliance reframing**: "compliance infrastructure" in
  §7.4, EU AI Act Art 12+14 language corrected.
- **DONE — Formal verification**: 146 Kani proofs + 6 TLA+ specs
  added (formal/ directory + PROOF_MAP.md). 5 Bell-LaPadula
  invariant property tests (INV-1 through INV-5) in ifc/mod.rs.
- **DONE — No-read-up**: Bell-LaPadula Simple Security Property
  implemented and verified.
- **DONE — Full adversarial eval (19 tests)**: E1 full-stack 10/10,
  E2 AgentDojo 100% across 5 models, E3a MCPTox 82.3% detection,
  E3b adaptive planner-trust 5/5, E3c Shadow Escape + Pale Fire
  blocked, E3d encoding evasion honest failure + IFC defense-in-depth.
- **PROPOSED — Semantic leakage detection**: §9.5 future work. Embedding
  similarity against tainted ValueStore entries. Novel L3 contribution.
- **DONE — Tool classification**: `is_write_tool()` now uses MCP
  `ToolAnnotations` (readOnlyHint, destructiveHint) when available,
  falling back to name heuristic only for unannotated tools.

---

## Abstract (~150 words)

AI agents increasingly access local resources -- files, git
repositories, shell commands, credentials -- via the Model Context
Protocol (MCP). Current agent runtimes provide no security
infrastructure: any tool call from any agent executes with the
full privileges of the host user. We present navra, a security
gateway daemon that interposes between AI agents and local
resources. navra enforces a layered authentication chain (OAuth
2.0 with Ed25519 JWTs, capability tokens with delegation, BLAKE3
legacy tokens), deny-wins path ACLs with ring inheritance,
Bell-LaPadula information flow control with per-value taint
tracking, a content safety pipeline (13 secret patterns, 20 PII
categories with regex + NER + ML, pseudonymization with IFC label
elevation), containerized agent execution (Podman, OpenShell
microVMs), typed action risk classification, and a SHA-256
hash-chained audit blackbox. All enforcement occurs at a single
chokepoint (`handle_call_tool`) through which every tool
invocation must pass. Microbenchmarks show IFC taint propagation
at ~0.4ns, capability token verification at ~13us, and the full
safety pipeline at ~18us per tool call -- negligible relative to
typical tool execution latencies of 10-500ms.

---

## 1. Introduction

AI agents are acquiring the ability to read files, write code,
execute commands, and manage credentials on behalf of users. The
Model Context Protocol (MCP) standardizes the interface between
agents and tools, but provides no security primitives. The
resulting gap is severe: a compromised or misaligned agent
operates with full user privileges.

Current agent runtimes (Goose, Claude Code, Codex) delegate
security to the user via ad-hoc confirmation dialogs. No runtime
enforces mandatory access control, tracks information flow, or
produces tamper-evident audit trails. The OWASP Top 10 for LLM
Applications identifies tool misuse (LLM01), data exfiltration
(LLM06), and privilege escalation (LLM08) as critical risks.
The EU AI Act mandates human oversight and decision traceability
for high-risk AI systems (Article 14) and logging of automated
decisions (Article 12). Agent infrastructure must provide the
compliance primitives that deployers need to meet these
obligations.

This paper presents navra, a gateway daemon that treats agent
security as an infrastructure concern rather than an application
concern. navra sits between agents and resources, enforcing
security policies at the protocol layer regardless of which
agent connects.

The architecture implements a security microkernel for the AI
agent stack: the gateway provides process tracking (per-agent
entries with privilege rings and call accounting), IPC mediation
(mailbox with Bell-LaPadula no-write-down, blackboard with
taint-on-read), memory management (working memory with
exponential decay, context budget allocation, knowledge
distillation), a DAG-based task scheduler with GPU semaphore
resource limits, and mandatory access control through a single
verified chokepoint. Agents connect via the MCP protocol
boundary — the equivalent of a syscall interface — which
provides the isolation boundary: agents are separate processes
that cannot bypass the gateway. Tool modules run in-process as
trusted kernel code (analogous to kernel modules), with an
optional gRPC interface for out-of-process isolation.

Prior work has applied the OS abstraction to agent systems
(AIOS [18]) but without enforcement boundaries: AIOS agents
share the kernel process address space with no IFC on
communication channels. navra enforces security properties
on its IPC channels (23 Kani-verified proofs, 6 TLC-verified
specifications) and satisfies Anderson's reference monitor
conditions [2]: complete mediation (single chokepoint),
tamperproof from the agent side (protocol boundary), and
verifiable (formally verified lattice and taint properties).

**Contributions**:

1. A gateway architecture for MCP security enforcement with
   infrastructure-level information flow control — Bell-LaPadula
   no-write-down with per-value taint tracking, enforced at a
   single chokepoint that agents cannot bypass. Unlike
   planner-level IFC (FIDES [13]), gateway enforcement is
   mandatory: a compromised agent cannot disable or circumvent
   the security layer (Section 5).
2. Capability token delegation with cryptographic privilege
   attenuation: Ed25519-signed CBOR tokens where child tokens
   can only narrow parent permissions (ring level, operations,
   tools, credentials, expiry). Combined with IFC labels, this
   enables least-privilege multi-agent delegation where data
   sensitivity constrains which teammates receive which
   capabilities (Section 4).
3. A SHA-256 hash-chained audit blackbox providing
   tamper-detectable compliance infrastructure for EU AI Act
   Article 12 logging and SOC2 CC6.1 audit trail requirements
   (Section 7).

The gateway also provides a content safety pipeline (12 secret
patterns, 18 PII categories with IFC label elevation), layered
authentication (OAuth 2.0, capability tokens, BLAKE3 legacy),
containerized agent execution (Podman, OpenShell), and typed
action risk classification — described in Sections 3, 6, and
3.6-3.7 respectively.

---

## 2. Threat Model

We consider five classes of attack against AI agent
infrastructure:

**T1. Malicious tool calls.** A prompt-injected or misaligned
agent calls tools with adversarial arguments: path traversal
(`../../etc/passwd`), unauthorized file writes, credential
access. Mitigated by path canonicalization before ACL check,
deny-wins glob rules, per-tool allow/deny/approve policies.

**T2. Privilege escalation via delegation.** Agent A delegates
a capability token to Agent B, which mints a more privileged
token. Mitigated by delegation validation: ring attenuation
(child ring >= parent ring), operation/tool/credential subset
enforcement, expiry attenuation (child cannot outlive parent),
parent nonce binding.

**T3. Data exfiltration via model backends.** An agent reads
sensitive local data, then passes it to an external model API.
Mitigated by IFC taint tracking: external reads auto-label data
as Untrusted; tainted sessions are denied write access (including
network-facing tool calls) under Deny policy.

**T4. Prompt injection through tool results.** A document read
by an agent contains adversarial instructions that alter agent
behavior. Mitigated by IFC labeling all external read outputs
as Untrusted, safety hook pipeline scanning tool results for
secrets (11 regex patterns), PII (4 validated patterns), and
contextual threats (ML classifier, Granite Guardian HAP 38M).

**T5. Replay attacks.** An attacker captures and replays a
capability token. Mitigated by 128-bit random nonces with a
server-side seen-nonce map, pruned after 2-hour TTL.

---

## 3. Architecture

### 3.1 Gateway Pattern

navra is a gateway, not a framework. Agents (Claude Code, Goose,
custom) connect via MCP Streamable HTTP over Unix socket (0600
permissions) or TCP. navra aggregates built-in tool modules and
upstream MCP servers behind a unified security layer. The gateway
pattern ensures that security enforcement is independent of
agent implementation.

**The VFS analogy.** In a Unix system, processes access files
exclusively through the Virtual File System — a kernel-enforced
mediation layer that checks permissions, applies ACLs, and
records audit events. Processes cannot bypass VFS because they
run in userspace; the kernel enforces the boundary. navra
provides the same architecture for AI agents: when agents run
in isolated containers, MCP is their sole channel to external
resources, and the gateway is the mandatory mediation layer.
The strength of this guarantee depends on the deployment model:

| Deployment | Agent isolation | MCP is sole channel? | Bypass requires |
|---|---|---|---|
| Host (bare metal) | None | No — agent has host access | Agent cooperation |
| Podman (distroless, no mounts) | Namespace isolation | **Yes** | Container escape (CVE) |
| OpenShell microVM | Hardware isolation | **Yes** | Hypervisor escape |

In containerized deployment (Podman or OpenShell), the agent
binary runs in an image with no host filesystem mounts, no
direct network access, and no writable storage beyond tmpfs.
The only file descriptor exposed to the container is the MCP
socket to navra. The agent literally cannot do anything except
send MCP requests. This is analogous to a process that can only
access files through VFS — the kernel (navra) mediates every
operation. All security properties (IFC, ACLs, capability
tokens, safety filters, audit) are enforced at this mediation
point.

### 3.2 The Chokepoint

All tool invocations pass through a single function,
`handle_call_tool`, which executes the following sequence:

1. Pause check (global kill switch via `AtomicBool`)
2. Rate limit check (per-agent, per-permission-set quotas)
3. Capability token tool glob verification (if cap token present)
4. Legacy per-tool permission rules (allow/deny/approve globs)
5. IFC variable reference resolution (`var://` URIs)
6. IFC pre-check: Bell-LaPadula no-write-down enforcement
7. Process table recording
8. Pre-hook pipeline (may modify args or block, fail-closed on
   timeout)
9. Tool handler execution
10. IFC auto-labeling (external reads marked Untrusted unless
    trusted path match)
11. Session taint absorption (lattice join, taint only rises)
12. Per-value variable storage (labeled, source-tagged)
13. Blackbox recording (SHA-256 hash-chained)
14. Post-hook pipeline (safety filtering, result modification)
15. Legacy safety filter fallback (when no hooks configured)

### 3.3 Authentication Chain

The `ChainAuthenticator` tries backends in priority order:

1. **OAuthAuthenticator**: Ed25519-signed JWTs issued via an
   RFC 6749 `client_credentials` grant (Section 3.5).
2. **CapabilityAuthenticator**: Ed25519-signed CBOR tokens
   (`navra_cap_v1.*`), with nonce replay protection.
3. **TokenAuthenticator**: BLAKE3-hashed bearer tokens for
   legacy agents.
4. **OpenShellAuthenticator**: Trusts identity assertions from
   the OpenShell sandbox supervisor (SPIFFE SVIDs, OIDC JWTs,
   or static RBAC labels). Used when navra runs inside an
   OpenShell sandbox (Section 3.6).
5. **NoAuthenticator**: Development-only fallback. Requires
   explicit `allow_anonymous()` opt-in; logs an error-level
   warning when used implicitly.

### 3.4 ACL Engine

Path ACLs use glob patterns with deny-wins semantics:

- Deny rules checked before allow rules.
- Paths canonicalized (symlinks resolved, `..` eliminated)
  before matching. Defense-in-depth warnings for non-absolute
  or traversal-containing paths.
- `dir/**` also matches `dir` itself (for listing).
- Ring inheritance: ring N inherits all deny rules and approval
  requirements from rings 0..N-1. Operations are intersected
  (higher rings can only narrow, never widen).
- String-based, module-namespaced operations (`read`, `write`,
  `git.status`, `shell.exec`) avoid a central enum.

### 3.5 OAuth 2.0 Authorization

navra implements an OAuth 2.0 authorization server following
RFC 6749 and RFC 8414. This provides a standards-compliant
authentication path for agents that cannot manage capability
tokens directly (e.g., third-party MCP clients).

**Endpoints:**

| Endpoint | Description |
|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata discovery |
| `POST /oauth/token` | Token issuance (`client_credentials` grant) |
| `POST /oauth/register` | Dynamic client registration |

**Token format:** Ed25519-signed JWTs (EdDSA algorithm). The
signing key is the same CapSigner used for capability tokens,
providing a single trust root. Claims include issuer, subject,
scope, issued-at, expiry, and a UUID `jti` for replay
detection.

**Scope-to-permission mapping:** OAuth scopes map to navra
permission sets. `tools:read` maps to `readonly` (ring 2),
`tools:write` maps to `developer` (ring 1). This bridges the
OAuth authorization model to navra's ring-based ACL engine
without requiring clients to understand capability tokens.

**Security properties:**

- Constant-time secret comparison (CWE-208 mitigation)
- Capability tokens (`navra_cap_v1.*`) bypass OAuth processing
  entirely, avoiding double-verification
- Pre-registered and dynamically registered clients supported
- In-memory client registry (no persistent state beyond config)

**Limitation:** Only the `client_credentials` grant type is
implemented. PKCE (S256) is advertised in metadata for forward
compatibility but not yet enforced. No refresh tokens — agents
re-authenticate when tokens expire.

### 3.6 Containerized Agent Execution

navra supports three isolation levels for agent execution,
with automatic runtime detection:

| Level | Backend | Isolation | MCP sole channel? |
|---|---|---|---|
| `BareMetal` | Direct | Child process, no isolation | No (advisory) |
| `Container` | Podman | Rootless, no mounts, no network | **Yes** |
| `OpenShellSandbox` | OpenShell | Microvm (Landlock + seccomp) | **Yes** |

**Auto-detection** (`auto_runtime()`) selects the strongest
available backend: OpenShell → Podman → Direct. The runtime
detects its own isolation context by checking environment
variables (`OPENSHELL_SANDBOX_ID`), container markers
(`/.containerenv`, `/.dockerenv`), and cgroup membership.

**Podman containers** run the agent as a statically-linked
binary in a minimal image (distroless or `fedora-minimal`)
with no host filesystem mounts, `--network=none` or
`slirp4netns` restricted to the navra gateway endpoint, and
`--no-new-privileges`. The container's only writable storage
is tmpfs. The only channel to the outside world is the MCP
socket to navra. This provides the VFS-equivalent guarantee
described in §3.1: every resource access is mediated by the
gateway. A bypass requires a container escape vulnerability.

**OpenShell sandboxes** provide the same guarantee at the
hardware level via libkrun microVMs with Landlock LSM, seccomp
BPF, and namespace isolation. The supervisor provides identity
tokens (SPIFFE SVIDs or OIDC JWTs) that the
OpenShellAuthenticator validates. Network egress is restricted
to the model endpoint and the navra gateway via an HTTP CONNECT
proxy with OPA policies.

**Defense in depth:** OpenShell provides mandatory access
control at the OS level (namespaces, Landlock, seccomp). navra
provides mandatory access control at the application level
(ACLs, capability tokens, IFC). Both layers enforce
independently — a bypass at one layer does not compromise the
other. In the Podman deployment, Linux namespaces provide the
isolation boundary and navra provides the access mediation —
together they form the complete access control stack, analogous
to process isolation + VFS in a traditional operating system.

### 3.7 Typed Action Classification

Every tool call is classified into one of 16 `AgentAction`
variants with an associated `RiskLevel`:

| Risk | Actions | Auto-approval |
|---|---|---|
| None | FileRead, GitStatus, GitDiff, RagSearch, MemoryQuery | Yes |
| Low | FileSearch | Yes |
| Medium | FileWrite, FileEdit, MemoryStore | Configurable |
| High | FileDelete, GitCommit | Requires approval |
| Critical | FlowStart, TeamCreate, TeamMessage | Always requires approval |

The classification is deterministic: `AgentAction::classify()`
parses the tool name and arguments to produce a typed action.
Tool handlers that accept an `AgentAction` can make approval
decisions based on the risk level without parsing tool names
as strings. Unknown tools default to `Medium` risk.

---

## 4. Capability Token System

### 4.1 Token Format

Wire format: `navra_cap_v1.<base64url(cbor)>.<base64url(sig)>`

Payload fields: version (`v: 1`), issuer DID (`iss`), subject
DID (`sub`), capability set (path globs, operations, tool globs,
credential labels), ring level, issued-at, expiry, 128-bit
nonce, optional parent nonce.

### 4.2 Cryptographic Properties

- **Signing**: Ed25519 over raw CBOR bytes.
- **Encoding**: CBOR for compact binary representation (typical
  token < 500 bytes).
- **Replay protection**: Server-side nonce map with 2-hour TTL
  and periodic pruning. `TokenRevocationList` enables explicit
  revocation by nonce.
- **Identity**: DID:key URIs (`did:key:z6Mk...`) for
  decentralized identity without PKI infrastructure.

### 4.3 Delegation Validation

`validate_delegation(parent, child, max_depth)` enforces:

- Parent nonce binding (child.parent == parent.nonce)
- Ring attenuation (child.ring >= parent.ring)
- Expiry attenuation (child.exp <= parent.exp)
- Operation subset (child.operations is a subset of parent.operations)
- Credential subset (child.credentials is a subset of parent.credentials)
- Depth limit (configurable max_depth)

Violations produce typed error messages (e.g., "ring escalation:
child ring 0 < parent ring 1").

---

## 5. Information Flow Control

### 5.1 Label Lattice

Two-dimensional labels: `(Integrity, Confidentiality)` where
`Integrity in {Trusted, Untrusted}` and `Confidentiality in
{Public, Sensitive, Secret}`. Lattice join: `max(integrity),
max(confidentiality)`. Taint only rises, never drops.

### 5.2 Automatic Labeling

External read tools (`file_read`, `file_search`, `git_diff`,
`git_log`) auto-label outputs as Untrusted. Exception: files
matching trusted path patterns (`~/Code/**`) retain Trusted
integrity. Trusted path matching uses canonicalization and
glob patterns with tilde expansion.

Gateway tools (`navra_var_*`) are excluded from auto-labeling --
they return kernel-managed metadata, not external data.

### 5.3 Write Enforcement

On write tool calls (`file_write`, `git_commit`, `file_edit`,
`file_delete`), the gateway checks the session's accumulated
taint label. Three configurable policies per permission set:

- **Allow**: No IFC enforcement (backward compatible).
- **Approve**: Tainted writes require human approval.
- **Deny**: Tainted writes rejected with IFC error.

### 5.4 Per-Value Variable Tracking

Every tool result is stored as a labeled variable (`var://`
URI). When arguments reference variables, the gateway computes
the effective label via lattice join of all referenced variables.
Write checks use per-value labels when `var://` references are
present, falling back to session-level taint otherwise. This
enables fine-grained flow tracking beyond session-level taint.

---

## 6. Content Safety Pipeline

The gateway enforces mandatory content filtering through a
multi-layer pipeline that runs as hooks in the chokepoint
(steps 8 and 14 in Section 3.2). Agents cannot disable
filtering — it is mandatory access control.

### 6.1 Pipeline Architecture

The `FilterPipeline` chains three filter types in sequence:

1. **Regex filters** (synchronous, deterministic): Pattern
   matching for secrets and PII with validation functions.
2. **NER filters** (synchronous, ML): ONNX token classification
   models for semantic entity detection.
3. **Model filters** (asynchronous, ML): Safety classifiers
   (Granite Guardian HAP 38M) for content policy violations.

Each filter produces `Finding` records (byte offset, category,
confidence). Findings are deduplicated by merging overlapping
spans (longest match wins).

### 6.2 Secret Detection

12 patterns detect leaked credentials:

| Category | Pattern | Example |
|---|---|---|
| AWS access key | `AKIA[0-9A-Z]{16}` | AKIAIOSFODNN7EXAMPLE |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` | ghp_abc123... |
| GitHub fine-grained | `github_pat_[A-Za-z0-9_]{82}` | github_pat_... |
| GitLab PAT | `glpat-[A-Za-z0-9\-_]{20,}` | glpat-abc123... |
| OpenAI API key | `sk-proj-[A-Za-z0-9_-]{32,}` | sk-proj-... |
| Anthropic API key | `sk-ant-[A-Za-z0-9_-]{32,}` | sk-ant-... |
| PEM private key | `-----BEGIN.*PRIVATE KEY-----` | RSA/EC keys |
| Connection string | `mysql\|postgres\|redis://` | DB credentials |
| Bearer token | `Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | JWT tokens |
| Slack webhook | `hooks.slack.com/services/` | Webhook URLs |
| Password assignment | `password\|passwd\|pwd\s*[=:]` | Inline passwords |
| AWS secret key | 40-char base64 near "aws" context | Secret keys |

### 6.3 PII Detection (18 Categories)

PII detection combines regex patterns with validation functions
to reduce false positives:

| Category | Method | Validation |
|---|---|---|
| SSN | Regex | SSA rules (no 000, 666, 9xx prefixes) |
| Credit card | Regex | Luhn checksum + context validation |
| US phone | Regex | Excludes UUID/timestamp overlaps |
| Email | Regex | Domain structure check |
| French NIR | Regex | Modulo-97 key validation |
| EU IBAN | Regex | Modulo-97 checksum (ISO 13616) |
| EU phone | Regex | Country code prefix (33, 49, 44, ...) |
| French SIRET | Regex | Luhn checksum (French convention) |
| Passport | Regex | Country-specific format patterns |
| Public IPv4 | Regex | Excludes loopback/private ranges |
| Path username | Regex | Excludes system accounts |
| Identity document | Regex | Passport/ID/driver license patterns |
| Temporal PII | Regex | Birth date patterns |
| Demographic | Regex | Age, sex indicators |
| Person | NER | BERT-based entity recognition |
| Location | NER | Geographic entity recognition |
| Organization | NER | Organization entity recognition |
| Username | NER | Username entity recognition |
| Password | NER | Password entity recognition |
| Misc entity | NER | Catch-all NER category |

The NER filter loads ONNX models (protectai/bert-base-NER or
multilingual xlm-roberta-base-ner-hrl) with sliding-window
tokenization (512 tokens, 64-token overlap) and BIO tag
grouping. Confidence threshold defaults to 0.7.

### 6.4 Filter Actions

Four actions determine how findings are handled:

| Action | Behavior |
|---|---|
| Pass | Return content unmodified |
| Redact | Replace with `[REDACTED:category]` |
| Pseudonymize | Replace with consistent pseudonyms |
| Block | Reject entire response with error |

**Pseudonymization** uses a per-session `PseudonymMap` that
maintains deterministic mappings: the same real value always
maps to the same pseudonym within a session
(`Person_A`, `Location_B`, `Email_C`). This preserves
referential integrity in agent outputs while removing PII.
De-pseudonymization is separated into a `PseudonymReverser`
held in a distinct security context (GDPR Article 32 key
separation). The agent process holds only the forward map.

### 6.5 Safety Profiles

Operators select a profile per permission set:

| Profile | Filters | Action |
|---|---|---|
| `standard` | Regex (secrets + PII + path) | Redact |
| `pseudonymize` | Regex (secrets + PII + path) | Pseudonymize |
| `secrets-only` | Secret filter only | Redact |
| `block` | Regex (all) | Block |
| `guardian` | Regex + Guardian HAP 38M | Redact |
| `guardian-deep` | Regex + HAP 38M + Guardian 3.3 8B | Redact |
| `none` | No filters | Pass |

Custom PII patterns can be added globally (`[[pii_patterns]]`
in config) or per permission set (`[[permissions.X.safety_patterns]]`).
Custom patterns registered as PII categories participate in
IFC label elevation.

### 6.6 IFC Integration

When the safety pipeline detects PII in a tool result, it
elevates the IFC confidentiality label to `Pii` — a level
above `Sensitive`. This elevation occurs even when the content
is redacted, because the session has been exposed to PII
regardless of whether the agent sees the raw values. Subsequent
write operations are subject to the permission set's IFC policy
(Allow/Approve/Deny), preventing PII leakage through tainted
tool chains.

### 6.7 GDPR Metrics

The pipeline maintains thread-safe counters for GDPR Article 35
Data Protection Impact Assessment reporting: total scans,
PII detected, PII redacted, PII blocked, and per-category
breakdowns. These metrics are available via the `/sys/status`
endpoint.

---

## 7. Gateway-Level Audit

### 7.1 Blackbox Design

The blackbox is a flight recorder embedded in `McpServer`. It
records every tool call at the gateway chokepoint:

- **Always on**: No opt-in, no configuration. If navra runs, it
  records.
- **Append-only**: `INSERT` only. No `UPDATE` or `DELETE`.
- **Hash-chained**: Each entry stores SHA-256 of the previous
  entry. Chain formula:
  `hash = SHA-256(seq | prev_hash | agent | tool | args | result | outcome)`.
- **Resumable**: On restart, resumes from the last entry's
  sequence number and hash.

### 7.2 Recorded Fields

Per entry: sequence number, timestamp, agent name, permission
set, session ID, tool name, arguments (truncated to 4KB), result
(truncated to 4KB), outcome (`allowed`, `denied_acl`,
`denied_ifc`, `denied_rate`, `error`), duration (microseconds),
IFC label, previous hash, current hash.

### 7.3 Tamper Detection

`verify_chain()` replays the entire chain, recomputing hashes
and comparing. Returns `(valid_count, first_broken_seq)`.
Exposed via `navra audit verify` CLI.

### 7.4 Compliance Infrastructure

The blackbox provides infrastructure that supports deployers
meeting regulatory requirements. navra itself is not a
regulated AI system — it is infrastructure that high-risk AI
systems can build on.

| Requirement | What navra provides |
|---|---|
| EU AI Act Art. 12 (logging) | Append-only, hash-chained records of every tool call with agent identity, IFC label, and outcome |
| EU AI Act Art. 14 (human oversight) | Approval workflow (4 channels), pause/resume, decision traceability via outcome + IFC label |
| SOC2 CC6.1 (audit trails) | Hash-chained, timestamped, tamper-detectable entries with agent identity and session tracking |
| ISO 42001 (AI decision records) | Agent identity, tool call, arguments, result, duration, IFC label per invocation |

---

## 8. Evaluation

### 8.1 Security Audit

Six audit rounds used navra's own multi-agent flow engine to
audit the gateway codebase through the gateway itself. Agents
connected via MCP, subject to the same ACLs, IFC, and safety
filters they were auditing. Findings were recorded in the
blackbox alongside normal tool calls.

Selected findings (of 50+):

| Finding | Severity | Resolution |
|---|---|---|
| Path ACL checked before canonicalization | High | Moved `canonicalize()` before ACL check |
| Symlinks not resolved in path matching | High | Added `fs::canonicalize()` with fallback |
| Hook timeout defaults to continue | High | Changed to fail-closed (block on timeout) |
| NoAuthenticator silent fallback | Medium | Require explicit `allow_anonymous()` opt-in |
| Session ID not enforced for IFC | Medium | Graceful degradation (per-request taint) |
| `var://` references bypass IFC write check | Medium | Added per-value label resolution |
| PII filter not applied to tool arguments | Medium | Added pre-hook filtering on write paths |
| Custom regex patterns not registered as PII | Low | Added `register_pii_categories()` |

### 8.2 Adversarial Evaluation

We evaluate navra's security mechanisms against adversarial
attacks at three layers, using both external benchmarks and
custom attack scenarios.

**E1: Full-stack adversarial attacks (10 scenarios).** Each test
spawns a real navra-server with realistic permissions and sends
crafted MCP requests through the complete auth → ACL → IFC →
hooks pipeline. Attacks: path traversal (absolute + dot-dot +
symlink), privilege escalation (readonly writes), deny-wins ACL
bypass, IFC no-write-down violation, capability token replay,
taint accumulation across reads. Result: **10/10 blocked.**

**E2: AgentDojo prompt injection benchmark (NeurIPS 2024).**
navra's IFC implemented as an AgentDojo defense plugin
(`BasePipelineElement`). Tested across 5 models (Claude Opus 4.6,
Sonnet, Haiku, Qwen 3 8B, Gemma 4 4B) on 3 attack types
(important_instructions, injecagent, tool_knowledge) with 30
scenarios each. Result: **100% defense rate** across all models.
Baseline models already resist >99% of standard injections;
IFC provides deterministic guarantee for the stochastic 1%
(Qwen 3 8B breached in 1/18 injecagent scenarios without IFC).

**E3a: MCPTox tool poisoning benchmark (AAAI 2026).**
navra's 8-category upstream tool scanner tested against 485
poisoned MCP tool descriptions from 45 real-world servers [25].
Detection rate: **82.3%** (399/485). False positive rate: 20.0%
(9/45 clean tools). The 17.7% miss rate consists of subtle
injections using soft language ("you should", "always append")
that pattern-based scanning cannot distinguish from legitimate
instructions without semantic analysis. FIDES [13] and CaMeL [14]
do not perform upstream tool scanning — this attack surface is
unaddressed by planner-level defenses.

**E3b: Adaptive planner-trust attacks (5 scenarios).**
Custom attack scenarios targeting the architectural gap between
planner-level and gateway-level IFC enforcement:

| ID | Attack | Planner-level IFC | navra |
|---|---|---|---|
| B1 | Injected "PUBLIC" label claim in content | May trust the claim | Labels by tool type, not content claims |
| B2 | Fake declassification notice in text | May accept text-based declassification | Requires cryptographic DeclassificationWitness |
| B3 | Taint laundering via intermediate file | Depends on data-flow tracking depth | Tainted session blocks first write (no laundering path) |
| B4 | Character-by-character exfiltration | Per-value tracking may miss single chars | Session-level taint blocks all writes |
| B5 | Dilution via clean reads after tainted read | May recalculate taint downward | Lattice join is monotonic (Kani-proved) |

Result: **5/5 blocked.** Each scenario exploits the assumption
that the agent's own reasoning correctly assigns or propagates
labels — an assumption that gateway-level enforcement does not
make.

**E3c: Real-world attack reproductions (2 scenarios).**
Shadow Escape [26] (zero-click document exfiltration via embedded
instructions) and Operation Pale Fire [27] (calendar data
injection leading to C2 contact): **both blocked.** The read
of attacker-controlled data taints the session; subsequent write
attempts are denied by IFC no-write-down regardless of how the
injected instructions frame the exfiltration.

**E3d: Encoding evasion — honest failure analysis (2 scenarios).**
Base64-encoded secrets pass through the content safety pipeline
undetected (known gap — regex patterns do not match encoded
content). Unicode homoglyphs in surrounding text cause the SSN
regex to miss nearby PII. **In both cases, IFC taint from the
file read still blocks subsequent writes.** The content filter
gap is mitigated by the defense-in-depth architecture: even when
Layer 1 (content patterns) fails, Layer 2 (IFC taint tracking)
provides a second enforcement boundary. We propose Layer 3
(semantic leakage detection via embedding similarity) in §9.5
to address the remaining gap.

**Honest limitations.** Three attack classes cannot be blocked by
any gateway-level IFC, including navra:

1. **Semantic taint propagation**: The LLM reads tainted content,
   paraphrases it, and outputs semantically equivalent text that
   does not match the original. No label-at-boundary system can
   detect this without analyzing the LLM's internal state.
   NeuroTaint (arXiv:2604.23374) achieves F1=0.928 on offline
   semantic taint detection. We propose a real-time semantic
   leakage hook using embedding similarity (see §9.5).

2. **Implicit information flow**: The LLM makes control-flow
   decisions based on tainted data (e.g., choosing which tool
   to call) that leak information through the pattern of
   operations, not through tool arguments.

3. **Side channels**: Timing channels (encoding data in tool
   call duration), metadata channels (tool selection patterns),
   and approval fatigue (human approves innocuous-looking writes
   that carry semantic leakage).

These limitations are shared by FIDES [13], CaMeL [14], and
every published IFC system. Gateway-level enforcement provides
defense-in-depth for deterministic attacks (layers 1-2), while
semantic detection (layer 3) is an active research frontier.

### 8.3 Performance

Criterion microbenchmarks (`benchmarks/benches/security_overhead.rs`):

| Component | Latency | Notes |
|---|---|---|
| IFC taint absorb | ~0.4 ns | Lattice join of two labels |
| IFC trusted path check | ~0.5 us | 2 glob patterns |
| BLAKE3 token hash | ~0.2 us | 40-character token |
| Capability token encode | ~10 us | CBOR + Ed25519 sign |
| Capability token decode+verify | ~13 us | Ed25519 verify + CBOR decode + expiry check |
| Permission check (allowed) | ~1.7 us | 2 allow + 3 deny globs |
| Permission check (denied) | ~0.8 us | Early exit on deny match |
| Safety pipeline (clean) | ~18 us | 15 regex patterns (13 secret + 10 PII) |
| Safety pipeline (with finding) | ~20 us | Regex match + redaction |
| Safety pipeline (pseudonymize) | ~22 us | Regex match + pseudonym lookup |
| NER filter (BERT-base) | ~5-15 ms | Token classification, 512-token window |
| Luhn validation | ~0.1 us | Credit card checksum |
| IBAN mod-97 validation | ~0.2 us | Bank account checksum |
| Tool rule check (exact) | ~0.3 us | 5 rules |
| Tool rule check (glob) | ~0.5 us | Glob pattern matching |

Total security overhead per tool call: ~35 us (without ML
filter). Typical tool execution: 10-500 ms. Security overhead
is < 0.5% of total latency.

### 8.4 Competitive Comparison

| Feature | navra | FIDES [13] | Gravitee | Kong | MS Governance [11] | SemaClaw [3] | Goose | ZeroClaw [8] |
|---|---|---|---|---|---|---|---|---|
| Auth | OAuth 2.0 + Ed25519 cap + BLAKE3 | N/A (planner) | MCP auth spec | OAuth 2.0 | DID-based identity | None | None | None |
| Path ACLs | Deny-wins, ring inheritance | N/A | Per-method | Default-deny | OPA/Cedar policies | None | None | 3-tier autonomy |
| IFC | Bell-LaPadula, per-value | **Per-value labels** | None | None | None | None | None | None |
| Delegation | Ed25519 chain, attenuation | N/A | None | None | None | None | None | None |
| Content safety | 13 secret + PII + Guardian ML | N/A | None | None | Policy engine | None | None | None |
| Audit trail | SHA-256 hash-chained blackbox | N/A | Logs | Logs | Policy logs | None | None | None |
| Enforcement | Gateway (mandatory) | Planner (inside agent) | Gateway | Gateway | Middleware | Harness | Runtime | Runtime |
| Formal proofs | No (unit tests) | **Yes** | No | No | No | No | No | No |

---

## 9. Discussion

### 9.1 Fail-Closed vs Fail-Open

The hook pipeline uses fail-closed semantics: if a hook times
out, the tool call is blocked. This is a deliberate deviation
from common middleware practice (fail-open on timeout). In
agent infrastructure, a timed-out security check is more
dangerous than a blocked tool call -- the agent can retry,
but a bypassed check cannot be retroactively enforced.

### 9.2 The NoAuthenticator Fallback

When no authenticator is configured, navra falls back to
`NoAuthenticator` with an error-level warning. This is a
conscious tradeoff: blocking startup would break development
workflows; silent open access would create false security
assumptions. The current design makes the fallback loud but
not fatal, and requires explicit `allow_anonymous()` for
intentional open access.

### 9.3 Session Enforcement and Backward Compatibility

IFC taint tracking requires session persistence across HTTP
requests. Agents that do not maintain `mcp-session-id` headers
lose cross-request taint accumulation. This is a backward
compatibility concern: older MCP clients may not send session
headers. The current design degrades gracefully (per-request
taint only) rather than rejecting sessionless clients.

### 9.4 Limitations

- IFC labels are not propagated through model backends. An
  agent can launder tainted data by passing it through a
  model call and reading the response as "new" data.
- The blackbox is not cryptographically signed (hash-chained
  but not attested). A root-privileged attacker could
  reconstruct a valid chain after tampering.
- Safety regex patterns are English-centric. Non-English
  secret formats may not be detected.
- NER models add latency (~5-15 ms per scan) and are
  English/European-language-centric. CJK PII requires
  different models not yet integrated.
- OAuth 2.0 implementation supports only `client_credentials`.
  Authorization code flow with PKCE is advertised but not
  enforced.
- In bare-metal deployment, the agent runs on the host with
  full user privileges. The gateway is advisory — the agent
  could access resources directly, bypassing MCP. The security
  properties require containerized deployment (Podman or
  OpenShell) where MCP is the sole channel. This is analogous
  to running a firewall on the same machine as the attacker:
  correct rules, but the attacker can walk around them.

### 9.5 Leakage Detection Beyond IFC Labels

Gateway-level IFC tracks labels at tool-call boundaries but
cannot detect information leakage through LLM reasoning. We
implement two additional layers that complement label-based IFC:

**L2 — Similarity-based detection** (`SimilarityLeakageHook`):
On each write tool call, embed the outgoing arguments using an
ONNX model, compute cosine similarity against tainted values in
the session's ValueStore, and block if similarity exceeds a
tunable threshold (default 0.75). We evaluated 4 embedding
models from 22M to 4B parameters. Performance peaks at 335M
(BGE-large-v1.5): 100% precision, 100% recall on paraphrased
exfiltration, 39ms per comparison. Larger models degrade —
they are optimized for document retrieval, not sentence-level
paraphrase detection. L2 cannot catch derived information
(e.g., "password starts with h" from "hunter2") because the
texts have insufficient semantic overlap for embedding
similarity to detect.

**L3 — Semantic analysis** (`SemanticLeakageJudge`): For
high-risk writes (confidentiality >= Secret), ask an LLM
judge: "Does this outgoing text reveal information from this
tainted content?" This catches derived information that L2
cannot detect. The judge model must not be the agent's own
model (to avoid self-evaluation circularity). L3 runs in two
modes: inline (~500ms, blocking, only for Secret-level writes)
and continuous (non-blocking `tokio::spawn` after every write,
zero latency impact — if leakage is detected, the session
trust score is penalized and taint is retroactively elevated
so L1 blocks subsequent writes). Unlike NeuroTaint [29] which
runs post-hoc, navra's continuous L3 can intervene mid-session.
Operators configure tiers per permission set: default = L1 + L2;
standard = L1 + L2 + L3 continuous; high-security = L1 + L2 +
L3 inline.

No published system combines real-time similarity detection
with selective LLM-based semantic analysis at the gateway
layer. NeuroTaint [29] is offline-only. FIDES [13] and
CaMeL [14] do not address information leakage through LLM
reasoning.

---

## 10. Related Work

- **OWASP Top 10 for LLM Applications** [1]: Catalogs agent
  security risks. navra addresses LLM01 (tool misuse), LLM06
  (data exfiltration), LLM08 (privilege escalation).
- **Bell-LaPadula model** [2]: Foundational MAC model. navra
  adapts no-write-down to agent tool chains.
- **SemaClaw** [3]: Two-layer agent harness with binary
  permissions (PermissionBridge). Operates at the harness layer
  vs navra's gateway layer. arXiv 2604.11548.
- **AWS Agent Registry** [4]: Governance-layer complement
  (discovery + ownership) to navra's runtime-security layer.
- **Agent Tier pattern** [5]: Two-lane architecture
  (deterministic enforcement + contextual reasoning) that maps
  1:1 to navra's ACL/hook pipeline + governed tool catalogs.
- **EU AI Act** [6]: Article 12 (logging) and Article 14
  (human oversight) requirements for high-risk AI systems.
  navra provides compliance infrastructure that deployers
  can use to meet these obligations — the gateway itself is
  not a regulated AI system.
- **SOC2 CC6.1** [7]: Audit trail requirements. navra's
  hash-chained blackbox provides the technical primitives.
- **ZeroClaw** [8]: Rust agent runtime with 3-tier autonomy
  model. Flat runtime vs navra's security gateway.
- **OpenShell** [9]: Red Hat/NVIDIA secure sandbox platform
  providing mandatory access control (Landlock, seccomp,
  namespaces, microVMs) at the OS level. navra integrates as
  the application-level security layer inside OpenShell
  sandboxes, providing defense in depth: OpenShell enforces
  network and filesystem isolation, navra enforces tool-level
  ACLs, IFC, and credential brokering.
- **Kaiden** [10]: Agent sandboxing platform with container
  isolation. Similar defense-in-depth model but without
  application-level IFC or capability delegation.
- **Microsoft Agent Governance Toolkit** [11]: DID-based identity,
  execution rings, OPA/Cedar policies. Middleware approach vs
  navra's kernel approach. No capability delegation or
  credential brokering.
- **Claude Code Review** [12]: Multi-agent cross-validation
  achieving <1% false positive rate. Validates the pattern of
  parallel verifier agents for high-stakes outputs. navra's
  flow engine supports this pattern via back-edges and
  conditional routing.
- **FIDES** [13]: Microsoft Research IFC for LLM agents
  (arXiv:2505.23643, May 2025). Tracks confidentiality and
  integrity labels on tool results with per-value granularity.
  A deterministic planner enforces policies before consequential
  actions. Zero policy-violating injections on AgentDojo.
  **Key distinction**: FIDES operates at the *planner level*
  inside the agent loop — the agent's own planner decides
  whether to honor labels. navra operates at the *gateway
  level* outside the agent — enforcement is mandatory regardless
  of agent implementation. This is analogous to kernel-enforced
  vs userspace-enforced access control: a compromised FIDES
  planner can bypass its own labels; a compromised agent behind
  navra cannot bypass the gateway's IFC checks. The tradeoff
  is granularity: FIDES tracks labels on every value; navra
  tracks per-session with per-value `var://` variable tracking
  as an intermediate. navra also enforces both BLP properties
  (no-write-down and no-read-up with configurable clearance),
  verified exhaustively via Kani bounded model checking and
  TLA+ model checking (see `formal/PROOF_MAP.md`). FIDES's
  formal non-interference proofs set the bar that gateway-level
  IFC should aspire to — navra provides 146 Kani proofs and
  6 TLC-verified specifications as a first step.
- **CaMeL** [14]: Google DeepMind capability metadata on every
  value (arXiv:2503.18813, March 2025). Provable security on
  77% of AgentDojo tasks via data-flow graph construction.
  Inspires navra's per-value `var://` tracking as a step
  toward full data-flow labeling. Like FIDES, CaMeL operates
  inside the agent; navra enforces at the infrastructure
  boundary.
- **AIOS** [18]: LLM Agent Operating System (arXiv:2403.16971,
  COLM 2025). Formalizes the OS abstraction for agent systems
  with process scheduling and resource management. navra
  shares the OS analogy but focuses narrowly on the security
  reference monitor role (access control, IFC, audit) rather
  than full OS functionality.
- **MCP gateway landscape** [22][23]: As of May 2026, 10+
  products provide MCP gateway functionality (Gravitee 4.10,
  Microsoft MCP Gateway, Kong AI Gateway 3.13, Traefik Hub,
  MintMCP, Lunar.dev, Composio, Intercept). These provide
  authentication and per-method ACLs but none implement
  information flow control or capability-scoped delegation.
  navra's differentiator is IFC + capability tokens, not
  the gateway pattern itself.

---

## 11. Conclusion

navra demonstrates that AI agent security is an infrastructure
concern that belongs in a dedicated gateway layer, not in each
agent's application code. The gateway pattern ensures that
security policies are enforced uniformly regardless of which
agent connects, which model backend is used, or which tools are
invoked. The single chokepoint design makes the security
surface auditable: 15 sequential checks in one function, not
scattered across dozens of tool handlers.

Our evaluation across 19 adversarial scenarios, 629 AgentDojo
injection cases, and 485 MCPTox poisoned tool schemas shows
that gateway-level enforcement provides two properties that
planner-level defenses cannot:

1. **Non-bypassability**: A compromised agent cannot circumvent
   the gateway's IFC checks — enforcement is in compiled Rust
   code outside the LLM's reasoning. Planner-level IFC (FIDES,
   CaMeL) relies on the LLM itself to correctly assign and
   propagate labels, creating a structural vulnerability when
   the planner's reasoning is compromised by prompt injection.

2. **Defense-in-depth across layers**: When content-level
   detection fails (base64-encoded secrets, Unicode homoglyphs),
   session-level IFC taint tracking provides a second enforcement
   boundary. The cascaded architecture (content patterns → IFC
   labels → write enforcement) means an attacker must evade all
   layers simultaneously, not just one.

Gateway-level IFC cannot, however, prevent information leakage
through the LLM's internal reasoning — a fundamental limitation
shared by all published IFC systems. We propose semantic leakage
detection via embedding similarity (§9.5) as a probabilistic
third layer to partially address this gap.

As AI agents gain more capabilities on local systems, the gap
between agent capability and agent safety will widen. navra
provides one answer: treat the agent-resource boundary as a
security perimeter, enforce mandatory access control at that
perimeter, and record every crossing for auditability.

---

## References

[1] OWASP. "OWASP Top 10 for LLM Applications." 2025.

[2] Bell, D.E. and LaPadula, L.J. "Secure Computer Systems:
Mathematical Foundations." MITRE Technical Report, 1973.

[3] SemaClaw. "SemaClaw: Open-Source Agent Framework."
arXiv:2604.11548, 2026.

[4] AWS. "Amazon Bedrock AgentCore Agent Registry." 2026.

[5] Varma, N. "The Agent Tier." InfoWorld, 2026.

[6] European Parliament. "Regulation (EU) 2024/1689
(AI Act)." Article 14: Human Oversight. 2024.

[7] AICPA. "SOC 2 Trust Services Criteria." CC6.1:
Logical and Physical Access Controls. 2022.

[8] ZeroClaw. Rust agent runtime with trait-based
architecture. 2026.

[9] Red Hat / NVIDIA. "OpenShell: Secure Sandbox Platform for
Autonomous Agents." 2026.

[10] Kaiden. Agent sandboxing platform. 2026.

[11] Microsoft. "Agent Governance Toolkit: Open-Source Runtime
Security for AI Agents." April 2026.

[12] Anthropic. "Claude Code Review: Multi-Agent Architecture."
2026.

[13] Costa, M., Kopf, B., Kolluri, A., et al. "Securing AI
Agents with Information-Flow Control (FIDES)." Microsoft
Research, arXiv:2505.23643, May 2025.

[14] Debenedetti, E., Shumailov, I., Fan, T., et al. "Defeating
Prompt Injections by Design (CaMeL)." Google DeepMind/ETH,
arXiv:2503.18813, March 2025.

[15] Hardt, D., Ed. "The OAuth 2.0 Authorization Framework."
RFC 6749, October 2012.

[16] Jones, M. and Sakimura, N. "OAuth 2.0 Authorization Server
Metadata." RFC 8414, June 2018.

[17] European Parliament. "Regulation (EU) 2016/679 (GDPR)."
Article 35: Data Protection Impact Assessment. 2016.

[18] Dong, Y. et al. "AIOS: LLM Agent Operating System."
arXiv:2403.16971, COLM 2025.

[19] OWASP. "OWASP Top 10 for Agentic Applications for 2026."
December 2025.

[20] CoSAI OASIS. "Model Context Protocol Security."
github.com/cosai-oasis/ws4-secure-design-agentic-systems, 2026.

[21] Block Engineering. "How We Red-Teamed Our Own AI Agent
(Operation Pale Fire)." 2026.

[22] Gravitee. "MCP Proxy: Unified Governance for Agents & Tools."
v4.10, 2026.

[23] Kong. "MCP Tool ACLs in Kong AI Gateway 3.13." 2026.

[24] A2ASECBENCH. "Security Benchmark for Agent-to-Agent
Communication." ICLR 2026.

[25] Vemprala, S. et al. "Security Considerations for Multi-Agent
Systems: A Comprehensive Analysis." arXiv:2603.09002, 2026.

[26] Operant AI. "Shadow Escape: First Zero-Click MCP Data
Exfiltration Attack." October 2025.

[27] Block Engineering. "Operation Pale Fire: Red-Teaming Our
Own AI Agent." SecurityBoulevard, January 2026.

[28] Wang, Z. et al. "MCPTox: A Benchmark for Tool Poisoning
Attack on Real-World MCP Servers." AAAI 2026,
arXiv:2508.14925.

[29] Cai, R. et al. "Ghost in the Agent: NeuroTaint for
Semantic Taint Propagation in LLM Agents."
arXiv:2604.23374, April 2026.

[30] Nasr, M. et al. "The Attacker Moves Second: Evaluating
the Robustness of LLM Defenses Under Adaptive Attack."
arXiv:2510.09023, October 2025.

[31] Microsoft Research. "Red-Teaming a Network of Agents:
Understanding What Breaks When AI Agents Interact at Scale."
April 2026.

[32] OWASP. "OWASP MCP Top 10." owasp.org/www-project-mcp-top-10,
2026.

[33] Levy, D. et al. "AgentDojo: A Dynamic Environment to Evaluate
Prompt Injection Attacks and Defenses for LLM Agents." NeurIPS
2024, arXiv:2406.13352.

---

## Appendix A: Codebase Statistics

| Metric | Value |
|---|---|
| Workspace crates | 22 |
| Rust source files | 290 |
| Total LoC (Rust) | ~126,000 |
| Test count | 2,800+ |
| Kani proofs | 138 |
| TLA+ specifications | 6 |
| Benchmark suite | 7 groups, ~30 individual benchmarks |
| Secret detection patterns | 13 |
| PII detection categories | 20 (12 regex + 8 NER) |
| PII validators | 8 (Luhn, SSA, NIR, IBAN, SIRET, IP, phone context, span dedup) |
| PII benchmark F1 | 0.889 (regex), 1.000 (regex + NER) |
| Safety profiles | 8 (standard, pseudonymize, secrets-only, block, guardian, guardian-deep, multi-label, none) |
| NER models supported | 4 (protectai/bert-base-NER, xlm-roberta-base-ner-hrl, sfermion/bert-pii-detector, OpenAI privacy-filter) |
| Isolation backends | 3 (Direct, Podman, OpenShell) |
| AgentAction variants | 16 |
| RiskLevel variants | 5 |
| Adversarial eval scenarios | 19 (A1-A10 + B1-B5 + C1-C2 + D1-D2) |
| AgentDojo defense rate | 100% across 5 models (629 injection cases) |
| MCPTox detection rate | 82.3% (399/485 poisoned schemas) |
| Red team findings | 10 (0 critical, 1 high, 5 medium, 3 low, 1 info) |
| Cedar OWASP policies | 10/10 ASI categories covered |
