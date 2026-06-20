+++
title = "Security Model"
description = "Capability tokens, IFC, privilege rings, and credential brokering."
weight = 30
template = "docs/section.html"

[extra]
toc = true
+++

## Capability Tokens

Agents authenticate with Ed25519-signed capability tokens that encode:

- **Identity** — DID:key of the issuing agent
- **Permissions** — Allowed operations, tools, and path patterns
- **Delegation chain** — Parent tokens, with each child ≤ parent scope
- **Expiry** — Short-lived by default (configurable TTL)

Tokens are CBOR-encoded (375–773 bytes) with 14 μs verification overhead.

## Delegation Chains

A leader agent issues attenuated tokens to specialist agents:

```
Leader (full access)
  └── Specialist A (read-only, file tools only)
  └── Specialist B (write, git tools, /src/ paths only)
```

Each delegation step can only narrow permissions — never widen.
This is enforced cryptographically: the child token includes the
parent's signature, and the kernel verifies the full chain.

## Information Flow Control

navra enforces a 2×4 product lattice:

- **Confidentiality**: Public < Internal < Confidential < Restricted
- **Integrity**: Untrusted < Validated

Taint labels propagate through tool chains. When an agent reads a
Confidential file, all subsequent tool calls in that session carry
the Confidential label. The IFC pipeline blocks exfiltration
attempts (e.g., writing Confidential data to a Public channel).

## Privilege Rings

Three-ring model inspired by x86 architecture:

| Ring | Access | Example |
|------|--------|---------|
| Ring 0 | Full system access | Gateway operator |
| Ring 1 | Scoped to permission set | Leader agent |
| Ring 2 | Read-only, attenuated | Specialist agent |

Outer rings cannot access inner ring resources. The deny-wins
principle ensures that explicit denials in any ring override
allows in all rings.

## Credential Brokering

Agents never see raw secrets. The kernel:

1. Reads credentials from the OS keyring (`secret-tool`)
2. Injects them into tool execution contexts at call time
3. Strips them from tool results before returning to the agent

This prevents credential theft via prompt injection — even a
compromised agent cannot extract secrets from its own context.

## Privacy Pipeline

Five-layer content filtering:

1. **Regex PII filter** — SSN, credit card, email, phone patterns
2. **Path PII filter** — Filesystem path patterns containing usernames
3. **NER filter** — ONNX-based named entity recognition
4. **Privacy model** — Statistical PII classification
5. **Custom patterns** — Operator-defined regex patterns

The PrivacyRouter coordinates these components with short-circuit
optimization: when regex filters find sufficient PII, expensive
ONNX inference is skipped.
