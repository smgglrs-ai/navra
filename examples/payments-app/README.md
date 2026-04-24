# Security Audit Demo — payments-app

End-to-end demonstration of the smgglrs-* framework performing a
multi-agent security audit on a vulnerable payment application.

## What it demonstrates

| Act | Feature | What happens |
|-----|---------|-------------|
| 1 | **Gateway + Auth** | Agents authenticate with capability tokens (BLAKE3 + Ed25519). Scoped permissions: auditor=read-only, developer=read+write+approve, analyst=read+memory. |
| 2 | **Cognitive Core** | Forge loads persona YAMLs (security_auditor, code_specialist, analyst). Weaver assembles system prompts with OWASP heuristics. Cache-friendly prefix splitting. |
| 3 | **DAG Execution** | Flow engine decomposes audit into 7 tasks. T1-T3 run in parallel (scan auth, injection, secrets). T4+ run sequentially with dependencies. |
| 4 | **IFC Taint Tracking** | `secrets.rs` is labeled Confidential. Reading it taints the agent context. Tainted content cannot reach Remote model backends — only Local (on-device) models. |
| 5 | **Safety Filtering** | Regex filters catch the hardcoded Stripe API key (`sk_live_...`) in `config.rs` and redact it before it reaches the agent. |
| 6 | **Path ACLs** | Developer is denied access to `secrets.rs` (deny rule). Auditor has read-only access everywhere. Deny-wins semantics. |
| 7 | **Memory + RAG** | Analyst recalls previous audit findings from March 2026 (SQL injection was found but unresolved). Cross-references with current scan. |
| 8 | **Mandate Validation** | After fixes are proposed, the flow engine validates each task output against `success_criteria`. Drift detector checks agents stayed on mandate. |
| 9 | **Failure Recovery** | If review-fixes rejects a fix, the flow engine routes back to propose-fixes with feedback (retry with context). Circular fix detector prevents infinite loops. |
| 10 | **Human-in-the-Loop** | `git_commit` requires approval. D-Bus notification sent to desktop. User approves via system tray or `smgglrs approve <id>`. |
| 11 | **Agent Commit Signing** | Commit is signed with the agent's Ed25519 key, traceable to the DID:key identity. |
| 12 | **Managed Models** | Granite model pulled from hub and served via Podman at startup. Safety classifier loaded in-process via ONNX Runtime. |

## The vulnerable app

Four source files with intentional vulnerabilities:

- `src/config.rs` — Hardcoded Stripe API key, webhook secret, DB password
- `src/handler.rs` — SQL injection (2 locations), missing auth, negative amount fraud, PII in logs
- `src/secrets.rs` — Encryption keys in source (PCI DSS violation)
- `src/api.rs` — Missing auth middleware, IDOR, no CSRF, no rate limiting, unverified webhooks

## File structure

```
examples/payments-app/
├── src/                          # Vulnerable application
│   ├── config.rs                 # Hardcoded secrets
│   ├── handler.rs                # SQL injection, missing auth
│   ├── secrets.rs                # Confidential (IFC labeled)
│   └── api.rs                    # Missing auth, IDOR
├── personas/                     # Agent personas (YAML)
│   ├── security_auditor.yaml     # Reads code, reports findings
│   ├── code_specialist.yaml      # Proposes fixes, commits
│   └── analyst.yaml              # Synthesizes, uses memory
├── heuristics/                   # Domain knowledge (YAML)
│   ├── owasp_top_10.yaml         # Vulnerability patterns
│   ├── secure_coding.yaml        # Fix patterns
│   └── risk_assessment.yaml      # Prioritization
└── config/                       # smgglrs + flow configuration
    ├── demo-config.toml           # smgglrs gateway config
    ├── audit-flow.toml            # 7-task DAG definition
    └── seed-memory.json           # Previous audit findings
```

## Running the demo

```bash
# Build smgglrs
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build

# Run the demo (future: smgglrs demo --project examples/payments-app)
smgglrs serve --config examples/payments-app/config/demo-config.toml
```

## Expected output

The demo produces a structured terminal output showing each act:

```
━━━ Act 1: Gateway & Identity ━━━
  ✓ Agent "security-auditor" authenticated (ring 2, DID:key:demo-auditor)
  ✓ Agent "code-specialist" authenticated (ring 3, DID:key:demo-coder)
  ✓ Agent "analyst" authenticated (ring 2, DID:key:demo-analyst)
  ✓ Capability tokens issued with scoped permissions

━━━ Act 2: Cognitive Core ━━━
  ✓ Loaded persona: security_auditor (5 OWASP heuristic facets)
  ✓ Loaded persona: code_specialist (4 secure coding facets)
  ✓ Loaded persona: analyst (3 risk assessment facets)
  ✓ Weaver assembled 3 system prompts (stable prefix cached)

━━━ Act 3: Parallel Scan [T1|T2|T3] ━━━
  ┌─ T1: scan-auth (security_auditor) ────────────────────
  │ Reading: src/handler.rs → IFC: Trusted
  │ Reading: src/api.rs → IFC: Trusted
  │ Finding: CWE-287 Missing authentication on admin_refund()
  │ Finding: CWE-639 IDOR on handle_user_payments()
  │ Finding: CWE-287 Missing webhook signature verification
  └─ 3 findings (1 critical, 2 high)

  ┌─ T2: scan-injection (security_auditor) ──────────────
  │ Reading: src/handler.rs → IFC: Trusted
  │ Finding: CWE-89 SQL injection in process_payment()
  │ Finding: CWE-89 SQL injection in get_history()
  └─ 2 findings (2 critical)

  ┌─ T3: scan-secrets (security_auditor) ────────────────
  │ Reading: src/config.rs → IFC: Trusted
  │ ⚠ Safety filter: redacted "sk_live_4eC39HqLyjW..."
  │ ⚠ Safety filter: redacted "whsec_MfKQ9r8GKY..."
  │ Finding: CWE-798 Hardcoded API key in config.rs
  │ Reading: src/secrets.rs → IFC: Confidential ⚡
  │ ⚡ Context tainted: Confidential (Bell-LaPadula)
  │ ⚡ Remote model backend BLOCKED (locality: Remote)
  │ ✓ Local model backend allowed (locality: Local)
  │ Finding: CWE-312 Encryption keys in source code
  └─ 2 findings (2 critical)

━━━ Act 4: Synthesis [T4] ━━━
  ┌─ T4: synthesize (analyst) ──────────────────────────
  │ Memory recall: "Previous audit March 2026: SQL injection
  │   in process_payment() — UNRESOLVED (ticket VULN-142)"
  │ Memory recall: "PCI DSS Q1 review: encryption key in
  │   secrets.rs — must move to KMS before Q2 deadline"
  │ ⚡ PATTERN MATCH: SQL injection found again (was in
  │   previous audit, still unresolved after 1 month)
  │ Report: 7 findings total
  │   Critical (4): 2× SQL injection, API key exposure, PCI violation
  │   High (2): missing admin auth, IDOR
  │   Medium (1): PII in logs
  └─ Prioritized report generated

━━━ Act 5: Fix & Review [T5→T6] ━━━
  ┌─ T5: propose-fixes (code_specialist) ────────────────
  │ Fix 1: SQL injection → parameterized queries (.bind())
  │ Fix 2: Hardcoded secrets → env::var() with error handling
  │ Fix 3: Missing auth → auth middleware on admin endpoints
  │ ✓ Mandate check: each fix maps to a specific CWE
  └─ 3 patches proposed

  ┌─ T6: review-fixes (security_auditor) ────────────────
  │ Fix 1 (SQL injection): ✓ Approved
  │ Fix 2 (secrets): ✓ Approved
  │ Fix 3 (auth): ⚠ Change requested — "also add rate limiting"
  │ → Routing back to T5 with feedback
  └─ 2 approved, 1 revision needed

  ┌─ T5 (retry): propose-fixes (code_specialist) ────────
  │ Fix 3 (revised): auth middleware + rate limiter
  │ ✓ Circular fix detector: attempt 2/3, no loop
  └─ Revised fix proposed

  ┌─ T6 (retry): review-fixes (security_auditor) ────────
  │ Fix 3 (revised): ✓ Approved
  └─ All fixes approved

━━━ Act 6: Commit [T7] ━━━
  ┌─ T7: prepare-commit (code_specialist) ───────────────
  │ Applying 3 fixes to src/handler.rs, src/config.rs, src/api.rs
  │ ⏳ git_commit requires approval (permission: "approve")
  │ 🔔 D-Bus notification: "Agent wants to commit 3 files"
  │ ⏳ Waiting for human approval...
  │ ✓ Approved by user
  │ ✓ Commit signed (Ed25519, DID:key:demo-coder)
  │ ✓ Working memory updated: audit findings saved
  └─ Commit: "fix: remediate SQL injection, secret exposure,
     and missing auth (CWE-89, CWE-798, CWE-287)"

━━━ Summary ━━━
  Tasks:     7 completed (2 retried)
  Findings:  7 (4 critical, 2 high, 1 medium)
  Fixes:     3 applied, reviewed, committed
  IFC:       1 Confidential taint event (secrets.rs)
  Safety:    2 secrets redacted (Stripe key, webhook secret)
  Approvals: 1 human approval (git commit)
  Memory:    3 items recalled, 1 new item stored
  Personas:  3 active (security_auditor, code_specialist, analyst)
  Time:      ~45 seconds
```
