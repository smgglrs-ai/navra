# Security Model

navra enforces security at the gateway layer through six mechanisms.
All are verified with formal methods (138 Kani proofs, 6 TLA+ specs).

## Defense Layers

### 1. Authentication

Every agent connection is authenticated via BLAKE3 token hashing.
Tokens are generated with `navra token generate` and their SHA-256
hashes are stored in config. Capability tokens with Ed25519 signing
and DID:key identifiers enable delegation chains with attenuation.

### 2. Authorization (Deny-Wins ACLs)

Permission sets define allowed and denied tool patterns. **Deny
always wins** — a deny rule on `exec_*` cannot be overridden by
an allow rule. Path canonicalization (symlink resolution, `..`
collapse) runs before every check.

### 3. Content Safety Pipeline

Three layers, configurable per permission set:

| Layer | Method | Coverage |
|---|---|---|
| Regex | Pattern matching | US + EU PII formats (SSN, IBAN, passport) |
| ML | ONNX classifier | Harm, unsafe content, prompt injection |
| NER | Named entity recognition | Names, addresses, organizations (EN + multilingual) |

Safety profiles: `standard`, `pseudonymize`, `secrets-only`,
`block`, `multi-label`, `guardian`, `guardian-deep`, `none`.

### 4. Information Flow Control

IFC labels track data sensitivity across tool calls. When an
agent reads sensitive data, that taint propagates through the
session. Bell-LaPadula no-read-up is enforced: a lower-clearance
agent cannot read higher-sensitivity data. Taint only rises
(Public → Sensitive → Secret).

### 5. Hook Pipeline

Pre-hooks and post-hooks run on every tool call. The pipeline
includes safety filters, IFC checks, approval gates, statistical
anomaly detection, temporal behavioral contracts, and audit
logging. All hooks are composable.

### 6. Audit Trail

Every tool call is recorded in a hash-chained SQLite log. The
chain is BLAKE3-hashed — tampering with any entry breaks the
chain. Always on, no opt-in required.

## Formal Verification

| Method | Count | What it verifies |
|---|---|---|
| Kani proofs | 138 | ACL evaluation, capability delegation, token verification, IFC lattice |
| TLA+ specs | 6 | Flow concurrency, taint propagation, deny-wins semantics |

Bell-LaPadula no-read-up is machine-verified. See
[Proof Map](./papers/formal.md) for the full traceability
from specifications to Rust implementations.

## OWASP ASI Compliance

navra covers all 10 OWASP Agentic Security Initiative controls.
See [OWASP ASI Compliance](./owasp-asi.md) for the control-by-control
mapping.
