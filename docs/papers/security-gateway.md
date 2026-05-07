# smgglrs: A Security Microkernel for AI Agent Infrastructure

**Authors**: Fabien Dupont et al.

**Target venue**: USENIX Security / IEEE S&P workshop track

---

## Abstract (~150 words)

AI agents increasingly access local resources -- files, git
repositories, shell commands, credentials -- via the Model Context
Protocol (MCP). Current agent runtimes provide no security
infrastructure: any tool call from any agent executes with the
full privileges of the host user. We present smgglrs, a security
gateway daemon that interposes between AI agents and local
resources. smgglrs enforces a layered authentication chain (OAuth
2.0 with Ed25519 JWTs, capability tokens with delegation, BLAKE3
legacy tokens), deny-wins path ACLs with ring inheritance,
Bell-LaPadula information flow control with per-value taint
tracking, a content safety pipeline (12 secret patterns, 18 PII
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
The EU AI Act Article 14 mandates human oversight and decision
traceability for high-risk AI systems.

This paper presents smgglrs, a gateway daemon that treats agent
security as an infrastructure concern rather than an application
concern. smgglrs sits between agents and resources, enforcing
security policies at the protocol layer regardless of which
agent connects. The architecture follows the microkernel pattern:
a minimal, auditable security core with all capabilities
implemented as modules.

**Contributions**:

1. A gateway architecture for MCP security enforcement with a
   single chokepoint (15 sequential checks) for all tool calls.
2. A layered authentication chain: OAuth 2.0 (RFC 6749/8414),
   Ed25519 capability tokens with delegation and ring attenuation,
   BLAKE3 legacy tokens, and OpenShell sandbox identity federation.
3. Information flow control with per-value taint tracking and
   trusted path exceptions, enforcing Bell-LaPadula no-write-down
   at the gateway level.
4. A content safety pipeline with 12 secret detection patterns,
   18 PII categories (regex with validation + ONNX NER + ML
   classifiers), pseudonymization with IFC label elevation, and
   GDPR Article 35 metrics.
5. Containerized agent execution with three isolation levels
   (direct, Podman rootless, OpenShell microVM) and typed action
   risk classification (16 actions, 5 risk levels).
6. A hash-chained audit blackbox providing tamper-detectable
   compliance records (EU AI Act Art. 14, SOC2 CC6.1).
7. Microbenchmarks showing sub-microsecond IFC overhead and
   <0.5% total security overhead per tool call.

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

smgglrs is a gateway, not a framework. Agents (Claude Code, Goose,
custom) connect via MCP Streamable HTTP over Unix socket (0600
permissions) or TCP. smgglrs aggregates built-in tool modules and
upstream MCP servers behind a unified security layer. The gateway
pattern ensures that security enforcement is independent of
agent implementation.

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
   (`smgglrs_cap_v1.*`), with nonce replay protection.
3. **TokenAuthenticator**: BLAKE3-hashed bearer tokens for
   legacy agents.
4. **OpenShellAuthenticator**: Trusts identity assertions from
   the OpenShell sandbox supervisor (SPIFFE SVIDs, OIDC JWTs,
   or static RBAC labels). Used when smgglrs runs inside an
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

smgglrs implements an OAuth 2.0 authorization server following
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

**Scope-to-permission mapping:** OAuth scopes map to smgglrs
permission sets. `tools:read` maps to `readonly` (ring 2),
`tools:write` maps to `developer` (ring 1). This bridges the
OAuth authorization model to smgglrs's ring-based ACL engine
without requiring clients to understand capability tokens.

**Security properties:**

- Constant-time secret comparison (CWE-208 mitigation)
- Capability tokens (`smgglrs_cap_v1.*`) bypass OAuth processing
  entirely, avoiding double-verification
- Pre-registered and dynamically registered clients supported
- In-memory client registry (no persistent state beyond config)

**Limitation:** Only the `client_credentials` grant type is
implemented. PKCE (S256) is advertised in metadata for forward
compatibility but not yet enforced. No refresh tokens — agents
re-authenticate when tokens expire.

### 3.6 Containerized Agent Execution

smgglrs supports three isolation levels for model serving and
agent execution, with automatic runtime detection:

| Level | Backend | Isolation |
|---|---|---|
| `BareMetal` | Direct | Child process, no isolation |
| `Container` | Podman | Rootless container, network-isolated |
| `OpenShellSandbox` | OpenShell | Microvm with Landlock + seccomp |

**Auto-detection** (`auto_runtime()`) selects the strongest
available backend: OpenShell → Podman → Direct. The runtime
detects its own isolation context by checking environment
variables (`OPENSHELL_SANDBOX_ID`), container markers
(`/.containerenv`, `/.dockerenv`), and cgroup membership.

**Podman containers** run rootless with `--network=none`
(prevents data exfiltration from inference), `--no-new-privileges`,
and read-only model mounts (`-v model:/model:ro`). GPU
passthrough uses CDI for NVIDIA and device bind-mounting for
AMD/Intel.

**OpenShell sandboxes** delegate to the OpenShell compute driver
via gRPC. The supervisor provides identity tokens (SPIFFE SVIDs
or OIDC JWTs) that the OpenShellAuthenticator validates. Network
egress is restricted to the model endpoint and the smgglrs
gateway via an HTTP CONNECT proxy with OPA policies.

**Defense in depth:** OpenShell provides mandatory access control
at the OS level (namespaces, Landlock, seccomp). smgglrs provides
discretionary access control at the application level (ACLs,
capability tokens, IFC). Both layers enforce independently — a
bypass at one layer does not compromise the other.

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

Wire format: `smgglrs_cap_v1.<base64url(cbor)>.<base64url(sig)>`

Payload fields: version (`v: 1`), issuer DID (`iss`), subject
DID (`sub`), capability set (path globs, operations, tool globs,
credential labels), ring level, issued-at, expiry, 128-bit
nonce, optional parent nonce.

### 4.2 Cryptographic Properties

- **Signing**: Ed25519 over raw CBOR bytes.
- **Encoding**: CBOR for compact binary representation (typical
  token < 500 bytes).
- **Replay protection**: Server-side nonce map with 2-hour TTL
  and periodic pruning.
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

Gateway tools (`smgglrs_var_*`) are excluded from auto-labeling --
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
The map supports reverse lookup for authorized audit.

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

- **Always on**: No opt-in, no configuration. If smgglrs runs, it
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
Exposed via `smgglrs audit verify` CLI.

### 7.4 Compliance Mapping

| Requirement | Blackbox coverage |
|---|---|
| EU AI Act Art. 14 (human oversight) | Decision traceability via outcome + IFC label |
| SOC2 CC6.1 (audit trails) | Append-only, hash-chained, timestamped |
| ISO 42001 (AI decision records) | Agent identity, tool call, result, duration |

---

## 8. Evaluation

### 8.1 Security Audit

Six audit rounds used smgglrs's own multi-agent flow engine to
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

### 8.2 Performance

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
| Safety pipeline (clean) | ~18 us | 15 regex patterns (12 secret + 10 PII) |
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

### 8.3 Competitive Comparison

| Feature | smgglrs | MS Governance [11] | SemaClaw [3] | Goose | ZeroClaw [8] |
|---|---|---|---|---|---|
| Auth | OAuth 2.0 + Ed25519 cap + BLAKE3 | DID-based identity | None | None | None |
| Path ACLs | Deny-wins, ring inheritance | OPA/Cedar policies | None | None | 3-tier autonomy |
| IFC | Bell-LaPadula, per-value | None | None | None | None |
| Delegation | Ed25519 chain, attenuation | None | None | None | None |
| PII detection | 18 categories, regex+NER+ML | None | None | None | None |
| Pseudonymization | Per-session consistent mapping | None | None | None | None |
| Content safety | 12 secret + PII + Guardian ML | Policy engine | None | None | None |
| Audit trail | SHA-256 hash-chained blackbox | Policy logs | None | None | None |
| Container isolation | Podman + OpenShell microVM | None | None | None | None |
| Action classification | 16 types, 5 risk levels | None | None | None | None |
| Permission model | 6-dimensional | Role-based | Binary | None | 3-tier |
| Architecture | Gateway | Middleware | Harness | Runtime | Runtime |

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

When no authenticator is configured, smgglrs falls back to
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
- Containerized execution isolates model inference but not the
  agent process itself — the agent's MCP client runs on the
  host (or in its own container managed externally).

---

## 10. Related Work

- **OWASP Top 10 for LLM Applications** [1]: Catalogs agent
  security risks. smgglrs addresses LLM01 (tool misuse), LLM06
  (data exfiltration), LLM08 (privilege escalation).
- **Bell-LaPadula model** [2]: Foundational MAC model. smgglrs
  adapts no-write-down to agent tool chains.
- **SemaClaw** [3]: Two-layer agent harness with binary
  permissions (PermissionBridge). Operates at the harness layer
  vs smgglrs's gateway layer. arXiv 2604.11548.
- **AWS Agent Registry** [4]: Governance-layer complement
  (discovery + ownership) to smgglrs's runtime-security layer.
- **Agent Tier pattern** [5]: Two-lane architecture
  (deterministic enforcement + contextual reasoning) that maps
  1:1 to smgglrs's ACL/hook pipeline + governed tool catalogs.
- **EU AI Act Article 14** [6]: Human oversight and decision
  traceability requirements for high-risk AI.
- **SOC2 CC6.1** [7]: Audit trail requirements for system
  operations.
- **ZeroClaw** [8]: Rust agent runtime with 3-tier autonomy
  model. Flat runtime vs smgglrs's security gateway.
- **OpenShell** [9]: Red Hat/NVIDIA secure sandbox platform
  providing mandatory access control (Landlock, seccomp,
  namespaces, microVMs) at the OS level. smgglrs integrates as
  the application-level security layer inside OpenShell
  sandboxes, providing defense in depth: OpenShell enforces
  network and filesystem isolation, smgglrs enforces tool-level
  ACLs, IFC, and credential brokering.
- **Kaiden** [10]: Agent sandboxing platform with container
  isolation. Similar defense-in-depth model but without
  application-level IFC or capability delegation.
- **Microsoft Agent Governance Toolkit** [11]: DID-based identity,
  execution rings, OPA/Cedar policies. Middleware approach vs
  smgglrs's kernel approach. No capability delegation or
  credential brokering.
- **Claude Code Review** [12]: Multi-agent cross-validation
  achieving <1% false positive rate. Validates the pattern of
  parallel verifier agents for high-stakes outputs. smgglrs's
  flow engine supports this pattern via back-edges and
  conditional routing.
- **FIDES** [13]: Microsoft Research IFC for LLM agents.
  Per-value label tracking at tool-call sinks. Zero policy-
  violating injections in AgentDojo. smgglrs implements a
  compatible but coarser-grained approach (per-session with
  per-value variable tracking).
- **CaMeL** [14]: Google DeepMind capability metadata on every
  value. Provable security on 77% of AgentDojo tasks. Inspires
  smgglrs's per-value `var://` tracking as a step toward full
  data-flow labeling.

---

## 11. Conclusion

smgglrs demonstrates that AI agent security is an infrastructure
concern that belongs in a dedicated gateway layer, not in each
agent's application code. The gateway pattern ensures that
security policies are enforced uniformly regardless of which
agent connects, which model backend is used, or which tools are
invoked. The single chokepoint design makes the security
surface auditable: 15 sequential checks in one function, not
scattered across dozens of tool handlers.

The layered security model — OAuth 2.0 and capability token
authentication, deny-wins ACLs with ring inheritance, Bell-
LaPadula IFC with per-value taint tracking, an 18-category PII
pipeline with pseudonymization, containerized execution with
three isolation levels, typed action risk classification, and a
hash-chained audit blackbox — addresses the full OWASP Agentic
Top 10 attack surface while adding less than 0.5% overhead to
typical tool call latencies.

As AI agents gain more capabilities on local systems, the gap
between agent capability and agent safety will widen. smgglrs
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

---

## Appendix A: Codebase Statistics

| Metric | Value |
|---|---|
| Workspace crates | 18 |
| Rust source files | 218 |
| Total LoC (Rust) | ~86,000 |
| Test count | ~1,700 (1,388 sync + 330 async) |
| Benchmark suite | 7 groups, ~30 individual benchmarks |
| Secret detection patterns | 12 |
| PII detection categories | 18 (10 regex + 8 NER) |
| PII validators | 6 (Luhn, SSA, NIR, IBAN, IP, phone context) |
| Safety profiles | 7 (standard, pseudonymize, secrets-only, block, guardian, guardian-deep, none) |
| NER models supported | 3 (protectai/bert-base-NER, xlm-roberta-base-ner-hrl, sfermion/bert-pii-detector) |
| Isolation backends | 3 (Direct, Podman, OpenShell) |
| AgentAction variants | 16 |
| RiskLevel variants | 5 |
| Self-audit rounds | 6 |
| Security findings | 50+ |
