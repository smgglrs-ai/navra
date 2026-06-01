# navra-security

Security layer for the MCP gateway.

## Overview

Enforces authentication, authorization, and content safety between
AI agents and local resources. This is the infrastructure that makes
navra a security gateway rather than a plain MCP server.

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

## Dependency layer

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
