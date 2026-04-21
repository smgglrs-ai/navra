# mcpd: A Security Microkernel for AI Agent Infrastructure

**Authors**: Fabien Dupont et al.

**Target venue**: USENIX Security / IEEE S&P workshop track

---

## Abstract (~150 words)

AI agents increasingly access local resources -- files, git
repositories, shell commands, credentials -- via the Model Context
Protocol (MCP). Current agent runtimes provide no security
infrastructure: any tool call from any agent executes with the
full privileges of the host user. We present mcpd, a security
gateway daemon that interposes between AI agents and local
resources. mcpd enforces authentication (BLAKE3 tokens, Ed25519
capability tokens, DID:key identity), deny-wins path ACLs with
ring inheritance, Bell-LaPadula information flow control with
per-value taint tracking, a fail-closed hook pipeline for content
safety filtering, and a SHA-256 hash-chained audit blackbox. All
enforcement occurs at a single chokepoint (`handle_call_tool`)
through which every tool invocation must pass. Six rounds of
self-audit uncovered 50+ security findings. Microbenchmarks show
IFC taint propagation at ~0.4ns, capability token verification
at ~13us, and the full safety pipeline at ~18us per tool call --
negligible relative to typical tool execution latencies of
10-500ms.

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

This paper presents mcpd, a gateway daemon that treats agent
security as an infrastructure concern rather than an application
concern. mcpd sits between agents and resources, enforcing
security policies at the protocol layer regardless of which
agent connects. The architecture follows the microkernel pattern:
a minimal, auditable security core with all capabilities
implemented as modules.

**Contributions**:

1. A gateway architecture for MCP security enforcement with a
   single chokepoint for all tool calls.
2. A capability token system with Ed25519 signing, CBOR encoding,
   delegation chains, and ring attenuation.
3. Information flow control with per-value taint tracking and
   trusted path exceptions, enforcing Bell-LaPadula no-write-down
   at the gateway level.
4. A hash-chained audit blackbox providing tamper-detectable
   compliance records (EU AI Act Art. 14, SOC2 CC6.1).
5. Empirical evaluation: 50+ findings from 6 self-audit rounds
   and microbenchmarks showing sub-microsecond IFC overhead.

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

mcpd is a gateway, not a framework. Agents (Claude Code, Goose,
custom) connect via MCP Streamable HTTP over Unix socket (0600
permissions) or TCP. mcpd aggregates built-in tool modules and
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

1. **CapabilityAuthenticator**: Ed25519-signed CBOR tokens
   (`mcpd_cap_v1.*`), with nonce replay protection.
2. **TokenAuthenticator**: BLAKE3-hashed bearer tokens for
   legacy agents.
3. **NoAuthenticator**: Development-only fallback. Requires
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

---

## 4. Capability Token System

### 4.1 Token Format

Wire format: `mcpd_cap_v1.<base64url(cbor)>.<base64url(sig)>`

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

External read tools (`docs_read`, `docs_search`, `git_diff`,
`git_log`) auto-label outputs as Untrusted. Exception: files
matching trusted path patterns (`~/Code/**`) retain Trusted
integrity. Trusted path matching uses canonicalization and
glob patterns with tilde expansion.

Gateway tools (`myelix_var_*`) are excluded from auto-labeling --
they return kernel-managed metadata, not external data.

### 5.3 Write Enforcement

On write tool calls (`docs_write`, `git_commit`, `docs_edit`,
`docs_delete`), the gateway checks the session's accumulated
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

## 6. Gateway-Level Audit

### 6.1 Blackbox Design

The blackbox is a flight recorder embedded in `McpServer`. It
records every tool call at the gateway chokepoint:

- **Always on**: No opt-in, no configuration. If mcpd runs, it
  records.
- **Append-only**: `INSERT` only. No `UPDATE` or `DELETE`.
- **Hash-chained**: Each entry stores SHA-256 of the previous
  entry. Chain formula:
  `hash = SHA-256(seq | prev_hash | agent | tool | args | result | outcome)`.
- **Resumable**: On restart, resumes from the last entry's
  sequence number and hash.

### 6.2 Recorded Fields

Per entry: sequence number, timestamp, agent name, permission
set, session ID, tool name, arguments (truncated to 4KB), result
(truncated to 4KB), outcome (`allowed`, `denied_acl`,
`denied_ifc`, `denied_rate`, `error`), duration (microseconds),
IFC label, previous hash, current hash.

### 6.3 Tamper Detection

`verify_chain()` replays the entire chain, recomputing hashes
and comparing. Returns `(valid_count, first_broken_seq)`.
Exposed via `mcpd audit verify` CLI.

### 6.4 Compliance Mapping

| Requirement | Blackbox coverage |
|---|---|
| EU AI Act Art. 14 (human oversight) | Decision traceability via outcome + IFC label |
| SOC2 CC6.1 (audit trails) | Append-only, hash-chained, timestamped |
| ISO 42001 (AI decision records) | Agent identity, tool call, result, duration |

---

## 7. Evaluation

### 7.1 Security Audit

Six rounds of self-audit (the framework auditing its own
codebase through its own gateway) uncovered 50+ security
findings, including: missing path canonicalization before ACL
checks, absent symlink resolution, hook timeout handling
(changed from continue to fail-closed), NoAuthenticator silent
fallback (changed to require explicit opt-in), missing session
enforcement, and IFC bypass via direct variable references.

### 7.2 Performance

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
| Safety pipeline (clean) | ~18 us | 15 regex patterns (11 secret + 4 PII) |
| Safety pipeline (with finding) | ~20 us | Regex match + redaction |
| Tool rule check (exact) | ~0.3 us | 5 rules |
| Tool rule check (glob) | ~0.5 us | Glob pattern matching |

Total security overhead per tool call: ~35 us (without ML
filter). Typical tool execution: 10-500 ms. Security overhead
is < 0.5% of total latency.

### 7.3 Competitive Comparison

| Feature | mcpd | SemaClaw | Goose | ZeroClaw |
|---|---|---|---|---|
| Auth tokens | BLAKE3 + Ed25519 cap | None | None | None |
| Path ACLs | Deny-wins, ring inheritance | None | None | 3-tier autonomy |
| IFC | Bell-LaPadula, per-value | None | None | None |
| Delegation | Ed25519 chain, ring attenuation | None | None | None |
| Content safety | Regex + ML (in-process ONNX) | None | None | None |
| Audit trail | SHA-256 hash-chained blackbox | None | None | None |
| Permission model | 5-dimensional (identity, path, operation, tool, approval) | Binary (internal/external) | None | 3-tier (ReadOnly/Supervised/Full) |
| Architecture | Gateway (secures any MCP client) | Harness (wraps one framework) | Agent runtime | Agent runtime |

---

## 8. Discussion

### 8.1 Fail-Closed vs Fail-Open

The hook pipeline uses fail-closed semantics: if a hook times
out, the tool call is blocked. This is a deliberate deviation
from common middleware practice (fail-open on timeout). In
agent infrastructure, a timed-out security check is more
dangerous than a blocked tool call -- the agent can retry,
but a bypassed check cannot be retroactively enforced.

### 8.2 The NoAuthenticator Fallback

When no authenticator is configured, mcpd falls back to
`NoAuthenticator` with an error-level warning. This is a
conscious tradeoff: blocking startup would break development
workflows; silent open access would create false security
assumptions. The current design makes the fallback loud but
not fatal, and requires explicit `allow_anonymous()` for
intentional open access.

### 8.3 Session Enforcement and Backward Compatibility

IFC taint tracking requires session persistence across HTTP
requests. Agents that do not maintain `mcp-session-id` headers
lose cross-request taint accumulation. This is a backward
compatibility concern: older MCP clients may not send session
headers. The current design degrades gracefully (per-request
taint only) rather than rejecting sessionless clients.

### 8.4 Limitations

- IFC labels are not propagated through model backends. An
  agent can launder tainted data by passing it through a
  model call and reading the response as "new" data.
- The blackbox is not cryptographically signed (hash-chained
  but not attested). A root-privileged attacker could
  reconstruct a valid chain after tampering.
- Safety regex patterns are English-centric. Non-English
  secret formats may not be detected.

---

## 9. Related Work

- **OWASP Top 10 for LLM Applications** [1]: Catalogs agent
  security risks. mcpd addresses LLM01 (tool misuse), LLM06
  (data exfiltration), LLM08 (privilege escalation).
- **Bell-LaPadula model** [2]: Foundational MAC model. mcpd
  adapts no-write-down to agent tool chains.
- **SemaClaw** [3]: Two-layer agent harness with binary
  permissions (PermissionBridge). Operates at the harness layer
  vs mcpd's gateway layer. arXiv 2604.11548.
- **AWS Agent Registry** [4]: Governance-layer complement
  (discovery + ownership) to mcpd's runtime-security layer.
- **Agent Tier pattern** [5]: Two-lane architecture
  (deterministic enforcement + contextual reasoning) that maps
  1:1 to mcpd's ACL/hook pipeline + governed tool catalogs.
- **EU AI Act Article 14** [6]: Human oversight and decision
  traceability requirements for high-risk AI.
- **SOC2 CC6.1** [7]: Audit trail requirements for system
  operations.
- **ZeroClaw** [8]: Rust agent runtime with 3-tier autonomy
  model. Flat runtime vs mcpd's security gateway.

---

## 10. Conclusion

mcpd demonstrates that AI agent security is an infrastructure
concern that belongs in a dedicated gateway layer, not in each
agent's application code. The gateway pattern ensures that
security policies are enforced uniformly regardless of which
agent connects, which model backend is used, or which tools are
invoked. The single chokepoint design makes the security
surface auditable: 15 sequential checks in one function, not
scattered across dozens of tool handlers.

The performance evaluation confirms that comprehensive security
enforcement -- authentication, authorization, information flow
control, content safety, and tamper-evident audit -- adds less
than 0.5% overhead to typical tool call latencies. Security
need not be traded for performance.

As AI agents gain more capabilities on local systems, the gap
between agent capability and agent safety will widen. mcpd
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

---

## Appendix A: Codebase Statistics

| Metric | Value |
|---|---|
| Workspace crates | 17 |
| Total LoC | ~46,000 |
| Test count | 788 |
| Security crate LoC | (myelix-security) |
| Core crate LoC | (myelix-core) |
| Benchmark suite | 7 groups, ~30 individual benchmarks |
| Personas | 43 |
| Safety regex patterns | 15 (11 secret + 4 PII) |
| Self-audit rounds | 6 |
| Security findings | 50+ |
