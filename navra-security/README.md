# navra-security

Security layer for the MCP gateway.

## Overview

Enforces authentication, authorization, and content safety between
AI agents and local resources. This is the infrastructure that makes
navra a security gateway rather than a plain MCP server.

138 Kani proofs and 6 TLA+ specifications verify core security
properties. See [formal/PROOF_MAP.md](../formal/PROOF_MAP.md).

## Subsystems

| Module | Purpose |
|---|---|
| `auth` | BLAKE3 tokens, OAuth 2.0, capability delegation with OBO identity |
| `permissions` | Deny-wins path ACLs, tool-level rules, optional Cedar policy engine |
| `hooks` | Pre/post tool-call pipeline (`HookPipeline`) |
| `safety` | Regex + ML + NER content filters, PII detection + pseudonymization |
| `ifc` | Information flow control with `DataLabel` taint tracking |
| `identity` | Ed25519 `did:key` signing (`CapSigner`, `Ed25519Signer`) |
| `credentials` | Secret storage via `CredentialStore` trait |
| `quota` | Per-agent rate limiting (`QuotaEngine`) |
| `process` | Live call tracking (`ProcessTable`) |
| `notify` | Desktop notification trait (D-Bus) |
| `tool_scanner` | Upstream MCP tool definition scanning (8 threat categories) |
| `integrity_monitor` | Cognitive file integrity monitoring (SHA-256 + semantic drift) |

## Security Model

### Deny-Wins ACLs

Deny rules always beat allow rules. Path canonicalization runs
before every ACL check to prevent traversal:

```rust
use navra_security::permissions::{PathAcl, AclResult};

let acl = PathAcl::new(
    vec!["/home/user/projects".into()],  // allow
    vec!["/home/user/projects/.env".into()],  // deny
);

// deny wins even when path is inside an allowed directory
assert_eq!(acl.check("/home/user/projects/.env"), AclResult::Denied);
```

### Information Flow Control

IFC labels track data sensitivity across tool calls. Taint only
rises through the lattice (Public → Sensitive → Secret):

```rust
use navra_security::ifc::{DataLabel, TaintTracker};

let mut tracker = TaintTracker::new();
tracker.absorb(DataLabel::Sensitive);

// once tainted, cannot write to Public destinations
assert!(!tracker.can_write_to(DataLabel::Public));
```

### Hook Pipeline

Pre-hook and post-hook functions run on every tool call. Safety
filters, IFC checks, approval gates, and statistical guardrails
are all hooks:

```rust
use navra_security::hooks::HookPipeline;

let pipeline = HookPipeline::new()
    .pre_hook(safety_hook)
    .pre_hook(ifc_hook)
    .pre_hook(approval_hook)
    .post_hook(audit_hook);
```

### Content Safety

Three-layer pipeline:

1. **Regex** — US + EU PII patterns (SSN, IBAN, passport, etc.)
2. **ML** — ONNX safety classifier (in-process, CPU)
3. **NER** — Named entity recognition for PII detection (EN + multilingual)

Safety profiles: `standard`, `pseudonymize`, `secrets-only`,
`block`, `multi-label`, `guardian`, `guardian-deep`, `none`.

## Dependency Layer

```
navra-protocol
navra-model
    |
navra-security
```

Downstream crates access security types either directly or through
`navra-core` re-exports.

## Reference

See [DESIGN.md](../DESIGN.md) for the full security model, ACL
semantics, and hook pipeline design.
