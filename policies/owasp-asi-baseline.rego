# OWASP Agentic Security Initiative (ASI) Top 10 — baseline Rego policies.
#
# Equivalent to owasp-asi-baseline.cedar. Load via config.toml:
#
#   [permissions.default]
#   opa_policies = "policies/owasp-asi-baseline.rego"
#   opa_package = "navra.authz"
#
# Semantics: Cedar uses default-deny with forbid-wins-over-permit.
# This Rego policy mirrors that: `deny` is true when any forbid rule
# matches OR when no allow rule matches (default-deny).

package navra.authz

import rego.v1

default allow = false
default deny = false

# ── Forbid rules (security invariants — cannot be overridden) ───────

# ASI01: Goal Hijack / Prompt Injection
deny if {
    input.action == "upstream_tool_call"
    input.manifest_verified == "false"
    not input.trust_score == "high"
}

# ASI02: Tool Misuse — high-risk writes without approval
deny if {
    input.action == "file_write"
    input.risk_tier in {"high", "critical"}
    not input.approval_granted == "true"
}

deny if {
    input.action == "file_delete"
    not input.approval_granted == "true"
}

# ASI03: Privilege Escalation
deny if {
    input.action == "capability_delegate"
    input.exceeds_parent_scope == "true"
}

deny if {
    input.trust_state == "suspended"
}

# ASI04: Supply Chain
deny if {
    input.action == "upstream_discover"
    input.manifest_signed == "false"
    not input.trust_on_first_use == "true"
}

# ASI05: Data Leakage — PII to external
deny if {
    input.ifc_confidentiality == "pii"
    input.destination_trust == "external"
}

deny if {
    input.action == "http_request"
    input.egress_allowed == "false"
}

# ASI06: Excessive Permissions — read-only agents
deny if {
    input.action == "file_write"
    input.trust_state == "read_only"
}

deny if {
    input.action == "exec_command"
    input.trust_state == "read_only"
}

deny if {
    input.action == "git_push"
    input.trust_state == "read_only"
}

# ASI07: Insecure Output
deny if {
    input.action == "response_send"
    input.safety_filtered == "false"
    input.safety_required == "true"
}

# ASI08: Cascading Failures
deny if {
    input.circuit_breaker == "open"
}

deny if {
    input.rate_limited == "true"
}

# ASI09: Human Trust — irreversible ops need approval
deny if {
    input.action == "git_push"
    not input.approval_granted == "true"
}

deny if {
    input.action == "github_pr_create"
    not input.approval_granted == "true"
}

deny if {
    input.action == "exec_command"
    input.risk_tier == "critical"
    not input.approval_granted == "true"
}

# ASI10: Rogue Agents
deny if {
    input.cognitive_integrity == "violated"
}

deny if {
    input.action == "upstream_tool_call"
    input.scan_category_blocked == "true"
}

# ── Allow rules (operational permits) ───────────────────────────────

# Write/push permits (require approval + normal trust)
allow if {
    input.action == "file_write"
    input.trust_state == "normal"
    input.approval_granted == "true"
}

allow if {
    input.action == "file_delete"
    input.trust_state == "normal"
    input.approval_granted == "true"
}

allow if {
    input.action == "git_push"
    input.trust_state == "normal"
    input.approval_granted == "true"
}

allow if {
    input.action == "github_pr_create"
    input.trust_state == "normal"
    input.approval_granted == "true"
}

allow if {
    input.action == "exec_command"
    input.trust_state == "normal"
    input.approval_granted == "true"
}

# Read-only operations — allowed for normal agents
allow if {
    input.action == "file_read"
    input.trust_state == "normal"
}

allow if {
    input.action == "file_tree"
    input.trust_state == "normal"
}

allow if {
    input.action == "git_status"
    input.trust_state == "normal"
}

allow if {
    input.action == "git_log"
    input.trust_state == "normal"
}

allow if {
    input.action == "git_diff"
    input.trust_state == "normal"
}

allow if {
    input.action == "memory_query"
    input.trust_state == "normal"
}

allow if {
    input.action == "rag_search"
    input.trust_state == "normal"
}

# ── Default deny (mirrors Cedar's implicit deny-without-permit) ─────
# Any action without a matching `allow` rule is denied.
# This rule fires when no explicit deny matched but also no allow matched.
deny if {
    not allow
}
