+++
title = "Security Model"
description = "Capability tokens, IFC, privilege rings, and credential brokering."
weight = 45
template = "docs/section.html"

[extra]
toc = true
+++

## Agent Authentication

Agents authenticate to the gateway via bearer tokens. The token is
sent as `Authorization: Bearer <token>` or as `x-api-key: <token>`.
Both headers are checked against BLAKE3 hashes stored in the agent
config using constant-time comparison (CWE-208 mitigation).

The `x-api-key` fallback exists so Anthropic SDK clients (e.g.
Claude Code) can authenticate using `ANTHROPIC_API_KEY`, which the
SDK sends as `x-api-key`. When both headers are present,
`Authorization` takes precedence.

Token hashes are generated with `navra token generate` and stored
in `config.toml` — the plaintext token is never persisted.

### Model proxy auth flow

When an agent calls `/v1/messages` or `/v1/chat/completions`, the
gateway authenticates the agent, then uses separate credentials to
call the upstream model provider. The agent never sees the upstream
API key or OAuth token. For Vertex AI, the gateway obtains OAuth
tokens from Application Default Credentials and caches them until
60 seconds before expiry.

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

- **Confidentiality**: Public < Sensitive < Pii < Secret
- **Integrity**: Trusted < Untrusted

Taint labels propagate through tool chains. When an agent reads a
Secret file, all subsequent tool calls in that session carry
the Secret label. The IFC pipeline blocks exfiltration
attempts (e.g., writing Secret data to a Public channel).

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

## Safety Hooks Pipeline

Every tool call passes through an ordered pipeline of hooks before
and after execution. Pre-hooks can modify arguments, block execution,
simulate results, or suspend pending human approval. Post-hooks can
modify or suppress results. The pipeline is fail-closed: if any hook
times out, the tool call is blocked. The following hook types are
available:

### Execution order

Pre-hooks run in registration order. Post-hooks run in reverse order,
so the first-registered hook is the outermost wrapper (same layering
as HTTP middleware). A `Block` or `Simulate` decision in any pre-hook
short-circuits the pipeline — later hooks do not run.

### Hook types

| Hook | Phase | Purpose |
|------|-------|---------|
| **ApprovalGate** | Pre | Suspends high-risk calls pending human approval (OWASP ASI09) |
| **EgressFilter** | Pre | Blocks tool arguments targeting external endpoints not on an allowlist |
| **ToolGuard** | Pre | Validates arguments and catches small-model mistakes before execution |
| **RoutingHook** | Pre | Classifies tool calls by complexity and routes to model tiers |
| **SkillHook** | Pre | Applies HASP-style program functions as executable guardrails |
| **SandboxHook** | Pre/Post | Enforces per-agent sandbox profiles (simulate, redact, rate limit, path rewrite) |
| **SafetyHook** | Pre/Post | Applies regex + ML content filters to arguments and results |
| **FieldFilter** | Post | Strips unnecessary JSON fields from results to reduce token use |
| **BudgetHook** | Post | Truncates oversized tool outputs to protect the agent context window |
| **StatisticalGuardrail** | Post | Detects anomalous agent behavior via cosine drift and entropy monitoring |
| **LeakageDetection** | Post | Blocks paraphrased exfiltration using embedding similarity (L2) and semantic analysis (L3) |
| **TemporalContract** | Pre/Post | Enforces trajectory-level constraints over agent action history |
| **ProvenanceHook** | Post | Records causal relationships between tool calls (observation only) |
| **VerifierHook** | Post | Checks results against rubrics and tracks false-pass rates |
| **MonitoringHook** | Post | Observes outcomes and escalates anomalies to the audit trail |

### Model-call hooks

The same pipeline intercepts agent-to-model calls in the tool loop.
Pre-model hooks can modify or block outgoing requests. Post-model
hooks can modify responses, request a retry with altered parameters,
or block the response entirely. Budget enforcement and temperature
override are typical pre-model hooks.

### Configuration

Hooks are registered at server startup. Most accept per-permission-set
configuration:

```toml
[hooks.approval_gate]
enabled = true
risk_keywords = ["delete", "exec", "deploy"]
timeout_secs = 300
default_on_timeout = "deny"

[hooks.egress]
enabled = true
allowed_domains = ["github.com", "*.example.com"]
deny_all_external = false
block_tainted_egress = true

[hooks.budget]
max_tool_output_tokens = 4096
truncation_strategy = "head_tail"

[hooks.temporal_contracts]
max_history_per_session = 200
```

## Tool Scanner

The tool scanner inspects upstream MCP tool definitions for
supply-chain threats before exposing them to agents. It runs
automatically during upstream server discovery.

### Threat categories

The scanner checks for eight categories:

| Category | Severity | What it detects |
|----------|----------|-----------------|
| **ToolPoisoning** | Critical | Hidden prompt injection in descriptions ("ignore previous instructions") |
| **Typosquatting** | High–Critical | Names within edit distance of known tools, or Unicode homoglyph attacks |
| **SchemaAbuse** | High | Input fields requesting secrets (api_key, password, credentials) |
| **HiddenUnicode** | Critical | Zero-width characters, RTL overrides, invisible formatters |
| **DescriptionInjection** | High | Imperative overrides ("you must always call this tool first") |
| **CrossServerReference** | Medium | References to tools on other servers |
| **IntentBehaviorMismatch** | Medium | Read-only description with required write parameters |
| **RugPull** | High | Tool definition changed since last scan (hash comparison) |

### Verdicts

Findings are aggregated into three verdicts:

- **Safe** — No high or critical findings
- **Suspicious** — At least one high-severity finding (logged, optionally blocked)
- **Malicious** — At least one critical finding (blocked by default)

### Manifest verification

navra extends MCP with Ed25519 tool manifest signing. Each upstream
server's tool list is hashed and signed. On subsequent connections,
the scanner verifies the signature against a TOFU (trust-on-first-use)
key store. A key change triggers a `KeyChanged` alert.

### Configuration

```toml
[tool_scanner]
enabled = true
block_malicious = true
typosquatting_threshold = 2
sensitive_schema_fields = [
    "password", "secret", "token", "api_key",
    "ssh_key", "private_key", "credentials"
]
```

Populate `known_tool_names` with your expected tool inventory to
enable typosquatting detection:

```toml
known_tool_names = ["file_read", "file_write", "git_status"]
```

## Rate Limiting

Per-agent rate limiting protects against runaway agents and resource
exhaustion. The quota engine uses a token bucket algorithm — each
agent gets a bucket that refills at a steady rate, allowing short
bursts while enforcing a sustained ceiling.

### How it works

Each permission set can define a rate limit (maximum calls per time
window). When an agent makes a tool call, the gateway checks its
bucket:

1. Refill tokens based on elapsed time since last check
2. If at least one token is available, consume it and allow the call
3. If no tokens remain, deny the call with outcome `denied_rate`

Buckets are created on first use and refill continuously. An agent
with a 60-call/minute limit can burst up to 60 calls instantly, then
must wait for tokens to refill at 1 per second.

### Per-agent isolation

Each agent gets its own bucket. Agent A exhausting its quota has no
effect on Agent B, even if they share the same permission set.

### Configuration

Rate limits are set per permission set in `config.toml`:

```toml
[permissions.dev]
rate_limit = "120/60"   # 120 tool calls per 60-second window

[permissions.restricted]
rate_limit = "30/60"    # 30 tool calls per 60-second window
```

Permission sets without a `rate_limit` field are unlimited. Query
remaining quota at runtime via the gateway status API. Denied calls
are recorded in the audit blackbox with outcome `denied_rate`.
