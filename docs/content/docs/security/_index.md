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

## Audit Blackbox

The blackbox is a gateway-level flight recorder. It captures every
tool call at the MCP chokepoint with no opt-in — if navra runs,
it records.

### What is recorded

Each entry stores agent identity, tool name, arguments, result,
outcome (`allowed`, `denied_acl`, `denied_ifc`, `denied_rate`,
`error`), wall-clock duration, IFC label, and an optional
on-behalf-of human subject (`obo_sub` for OAuth-delegated calls).
Arguments and results are truncated to 4 KiB (UTF-8 safe).

When the privacy pipeline is enabled, PII in tool arguments and
results is redacted before recording.

### Hash chain

Entries are SHA-256 hash-chained: each entry includes the hash of
the previous entry. Tampering with any entry breaks the chain from
that point forward. Verify integrity at any time:

```bash
navra audit --verify
```

### Querying the audit log

```bash
# Last 20 entries (tabular summary)
navra audit

# Full detail with args/result
navra audit --detail --limit 50

# Filter by agent and tool
navra audit --agent claude --tool file_read

# Reconstruct a session timeline
navra audit --detail --agent my-agent
```

### Storage and retention

The blackbox lives at `~/.local/share/navra/blackbox.db` (SQLite,
WAL mode). The chain resumes seamlessly across server restarts.

Retention is manual — the `expire_older_than` API deletes entries
older than a given number of days. This breaks the hash chain for
deleted entries, but `verify_chain` validates the remaining
contiguous chain. Check your compliance requirements before expiring
audit data.

### Compliance

The blackbox addresses recording requirements in the EU AI Act
(Article 14, human oversight), SOC2 CC6.1 (audit trails), and
ISO 42001 (AI decision records). See the
[workshop paper](/docs/papers/audit-blackbox/) for a full
compliance mapping.
