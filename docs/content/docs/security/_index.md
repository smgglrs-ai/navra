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
[workshop paper](@/docs/papers/audit-blackbox.md) for a full
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
| **HtmlToMarkdownHook** | Post | Converts HTML content in tool results to clean markdown, reducing token consumption |
| **JsonCompressHook** | Post | Compresses large JSON tool responses via key stripping, array truncation, and depth flattening |
| **PolicyYamlHook** | Pre/Post | Ingests ACS-compatible YAML policy files and maps rules into the hook pipeline |

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
| **CrossServerReference** | High–Critical | Descriptions or schema text directing the agent to another server's tools; Critical when targeting credentials |
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

## Cedar Action Dispatch

When a Cedar policy engine is configured, every tool call is checked
against it as a second gate (it can only further restrict, never
grant). Two action dispatch versions exist, selected with
`cedar_action_version` in `[server]`:

- **Version 1 (default)** dispatches the bare tool name as the Cedar
  action — compatible with policies written against tool names.
- **Version 2** namespaces upstream tool calls: tools registered from
  upstream MCP servers dispatch the modeled
  `Action::"upstream_tool_call"` with the concrete tool in
  `context.tool_name`, so the bundled OWASP ASI policies (ASI01
  prompt-injection and ASI10 rogue-agent rules) apply to upstream
  calls as a class, and per-tool refinements are possible via
  `context.tool_name`. Gateway-local tools keep bare-name actions in
  both versions.

`Action::"upstream_discover"` is dispatched where upstream discovery
results are accepted for registration (principal `navra-gateway`),
with `context.manifest_signed` and `context.trust_on_first_use` — a
policy can therefore refuse unsigned upstreams entirely.

### Migration note (v1 → v2)

Version 2 changes Cedar evaluation semantics for upstream tool calls:
policies matching the bare upstream tool names no longer see those
calls, and policies matching `Action::"upstream_tool_call"` begin to.
The bundled baseline (`policies/owasp-asi-baseline.cedar` and the
equivalent Rego) ships permits so v2 remains usable as-is; custom
policy sets should be audited for bare-tool-name rules that were
intended to govern upstream tools before enabling v2. A literal
`upstream_tool_call:<tool>` action id is deliberately not used —
Cedar matches action ids exactly, so no generic policy could match a
concatenated id and deny-by-default would block every upstream call.

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

## Residual Risks (Accepted Tradeoffs)

The following limitations are known and accepted design tradeoffs.
They are documented here so operators can account for them in their
threat model rather than discover them during an incident.

### Upstream tool names can impersonate module names

Upstream MCP tools are exposed with names prefixed by the module
that registered them, and audit attribution uses that registering
module. This prevents one upstream from spoofing another upstream's
namespaced tools. However, the model-facing tool name itself can
still resemble a tool the operator never configured — for example,
an upstream registering a tool named `file_read` surfaces as
`<module>.file_read`, which may mislead a model (or an operator
reading the audit log) into treating it as the gateway's built-in
`file_read`. The typosquatting scanner flags near-misses against
`known_tool_names`, but operators should populate that inventory
and treat upstream-prefixed names as untrusted.

### Dev mode is loopback single-user only

`--dev-mode` allows anonymous access without authentication. All
anonymous clients share one process-wide session, and a
protocol-level re-initialization starts that shared session with a
clean IFC label — an anonymous client can reset accumulated taint
by re-initializing. This is deliberate: persisting taint across
anonymous re-inits would poison every subsequent local client
forever, and dev mode assumes a single trusted local user on a
loopback bind. Never expose a dev-mode gateway to other hosts or
multiple users.

### `tool_overrides` is the reliable protection against annotation lies

Upstream tool definitions self-report metadata such as the MCP
`readOnlyHint` annotation, and a malicious or buggy upstream can
lie about it. The tool scanner flags intent/behavior mismatches at
scan time, but scan-time heuristics cannot prove runtime behavior.
Operator-configured `tool_overrides` (forcing a tool to `read`,
`write`, or `deny`) is the only protection that does not depend on
upstream-provided annotations. Treat upstream annotations as hints,
and pin overrides for any upstream tool whose blast radius matters.

### The egress blocklist cannot express punycode domains

Domain patterns (`allowed_domains` / `blocked_domains`) are matched
literally against the extracted host; there is no punycode/IDNA
normalization step. When domain lists are configured, a host in
ASCII punycode form (`xn--…`) does not match any human-readable
pattern, so such hosts are rejected outright rather than decoded
and compared. This is fail-closed (an `xn--` host cannot sneak
through an allowlist entry for its Unicode equivalent), but it also
means operators cannot allowlist a punycode-encoded domain by its
readable form — a legitimate IDN must be listed by its exact
`xn--` encoding.


### Config-API mutation is elevation-gated with immutable auth fields

All mutating routes under `/api` (permission-set and agent
upsert/delete, config reload, approval listing and resolution)
require an elevated permission set (`admin`/`root`), and the
reserved set names `admin`/`root` can only be defined in
`config.toml` — never through the API. A non-elevated agent may
edit only its own config, and only the non-authorization fields
(`token_hash` rotation, `model`, concurrency/context limits);
`permissions`, `did`, signing keys, `capability_token`, `upstream`,
and token TTL are immutable without elevation. Capability-token
identities are additionally never eligible for self-edit:
delegated token subjects must be DID-shaped (`did:…`, `agent:…`,
`obo:…`), so a delegated token cannot forge a config agent's name.
The internal agent-label endpoint is restricted to the caller's
own agent unless elevated.
