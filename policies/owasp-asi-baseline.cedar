// OWASP Agentic Security Initiative (ASI) Top 10 — baseline Cedar policies.
//
// These policies implement default-deny with explicit permits for safe
// operations. Load via config.toml (requires building navra with the
// `cedar` feature):
//
//   [permissions.default]
//   cedar_policies = ["policies/owasp-asi-baseline.cedar"]
//
// Operator can override by loading additional .cedar files that further
// restrict or (via permit) open specific paths. Cedar forbid always wins
// over permit — these baseline forbids cannot be overridden.
//
// Convention: every context attribute reference is `has`-guarded
// (`context has x && context.x == "..."`) so a MISSING attribute means
// "condition does not match" — the same semantics Rego gives missing
// input keys. Without the guard, Cedar treats a missing attribute as an
// evaluation error and skips the policy entirely, which diverges from
// the Rego baseline (notably inside `unless` clauses). Keep this
// convention when adding rules; the equivalence tests enforce it by
// checking both engines agree on empty-context vectors.

// ── ASI01: Goal Hijack / Prompt Injection ──────────────────────────
// Deny tool calls that could inject instructions into agent context.
// Upstream MCP servers with unverified schemas are blocked by default.

forbid(
    principal,
    action == Action::"upstream_tool_call",
    resource
) when { (context has manifest_verified && context.manifest_verified == "false") }
unless { (context has trust_score && context.trust_score == "high") };

// ── ASI02: Tool Misuse ─────────────────────────────────────────────
// Deny destructive file operations unless agent has explicit write grant.

forbid(
    principal,
    action == Action::"file_write",
    resource
) when { (context has risk_tier && context.risk_tier == "high") || (context has risk_tier && context.risk_tier == "critical") }
unless { (context has approval_granted && context.approval_granted == "true") };

forbid(
    principal,
    action == Action::"file_delete",
    resource
) unless { (context has approval_granted && context.approval_granted == "true") };

// ── ASI03: Privilege Escalation ────────────────────────────────────
// Deny capability delegation that exceeds parent scope.

forbid(
    principal,
    action == Action::"capability_delegate",
    resource
) when { (context has exceeds_parent_scope && context.exceeds_parent_scope == "true") };

// Deny operations when trust score is in suspended state.
forbid(
    principal,
    action,
    resource
) when { (context has trust_state && context.trust_state == "suspended") };

// ── ASI04: Supply Chain ────────────────────────────────────────────
// Deny loading upstream MCP servers without manifest signature.

forbid(
    principal,
    action == Action::"upstream_discover",
    resource
) when { (context has manifest_signed && context.manifest_signed == "false") }
unless { (context has trust_on_first_use && context.trust_on_first_use == "true") };

// ── ASI05: Data Leakage ────────────────────────────────────────────
// Deny sending PII-tainted data to external endpoints.

forbid(
    principal,
    action,
    resource
) when {
    (context has ifc_confidentiality && context.ifc_confidentiality == "pii") &&
    (context has destination_trust && context.destination_trust == "external")
};

// Deny egress to non-allowlisted endpoints.
forbid(
    principal,
    action == Action::"http_request",
    resource
) when { (context has egress_allowed && context.egress_allowed == "false") };

// ── ASI06: Excessive Permissions ───────────────────────────────────
// Read-only agents cannot write or execute.

forbid(
    principal,
    action == Action::"file_write",
    resource
) when { (context has trust_state && context.trust_state == "read_only") };

forbid(
    principal,
    action == Action::"exec_command",
    resource
) when { (context has trust_state && context.trust_state == "read_only") };

forbid(
    principal,
    action == Action::"git_push",
    resource
) when { (context has trust_state && context.trust_state == "read_only") };

// ── ASI07: Insecure Output ─────────────────────────────────────────
// Deny returning unfiltered content when safety profile requires it.

forbid(
    principal,
    action == Action::"response_send",
    resource
) when {
    (context has safety_filtered && context.safety_filtered == "false") &&
    (context has safety_required && context.safety_required == "true")
};

// ── ASI08: Cascading Failures ──────────────────────────────────────
// Deny tool calls when circuit breaker is open.

forbid(
    principal,
    action,
    resource
) when { (context has circuit_breaker && context.circuit_breaker == "open") };

// Deny when rate limit is exceeded.
forbid(
    principal,
    action,
    resource
) when { (context has rate_limited && context.rate_limited == "true") };

// ── ASI09: Human Trust ─────────────────────────────────────────────
// Require approval for irreversible operations.

forbid(
    principal,
    action == Action::"git_push",
    resource
) unless { (context has approval_granted && context.approval_granted == "true") };

forbid(
    principal,
    action == Action::"github_pr_create",
    resource
) unless { (context has approval_granted && context.approval_granted == "true") };

forbid(
    principal,
    action == Action::"exec_command",
    resource
) when { (context has risk_tier && context.risk_tier == "critical") }
unless { (context has approval_granted && context.approval_granted == "true") };

// ── ASI10: Rogue Agents ────────────────────────────────────────────
// Deny agents with low trust score from accessing sensitive resources.

forbid(
    principal,
    action,
    resource
) when {
    (context has trust_state && context.trust_state == "suspended") ||
    (context has cognitive_integrity && context.cognitive_integrity == "violated")
};

// Deny agents that failed upstream tool scanning.
forbid(
    principal,
    action == Action::"upstream_tool_call",
    resource
) when { (context has scan_category_blocked && context.scan_category_blocked == "true") };

// ── Write/push permits (require approval) ──────────────────────────

// Upstream tool calls (dispatched as Action::"upstream_tool_call"
// under cedar_action_version = 2, with context.tool_name carrying the
// concrete tool). Permitted under trust-on-first-use, navra's
// upstream trust model; ASI01/ASI10 forbids above still apply.
permit(
    principal,
    action == Action::"upstream_tool_call",
    resource
) when { (context has trust_state && context.trust_state == "normal") };

// Accepting upstream discovery results for registration (dispatched
// where discover() results are accepted). Permitted under
// trust-on-first-use; ASI04's forbid above still applies when an
// operator policy withdraws that trust.
permit(
    principal,
    action == Action::"upstream_discover",
    resource
) when { (context has trust_on_first_use && context.trust_on_first_use == "true") };

permit(
    principal,
    action == Action::"file_write",
    resource
) when {
    (context has trust_state && context.trust_state == "normal") &&
    (context has approval_granted && context.approval_granted == "true")
};

permit(
    principal,
    action == Action::"file_delete",
    resource
) when {
    (context has trust_state && context.trust_state == "normal") &&
    (context has approval_granted && context.approval_granted == "true")
};

permit(
    principal,
    action == Action::"git_push",
    resource
) when {
    (context has trust_state && context.trust_state == "normal") &&
    (context has approval_granted && context.approval_granted == "true")
};

permit(
    principal,
    action == Action::"github_pr_create",
    resource
) when {
    (context has trust_state && context.trust_state == "normal") &&
    (context has approval_granted && context.approval_granted == "true")
};

permit(
    principal,
    action == Action::"exec_command",
    resource
) when {
    (context has trust_state && context.trust_state == "normal") &&
    (context has approval_granted && context.approval_granted == "true")
};

// ── Baseline permits ───────────────────────────────────────────────
// Read-only operations are allowed for all agents in normal state.

permit(
    principal,
    action == Action::"file_read",
    resource
) when { (context has trust_state && context.trust_state == "normal") };

permit(
    principal,
    action == Action::"file_tree",
    resource
) when { (context has trust_state && context.trust_state == "normal") };

permit(
    principal,
    action == Action::"git_status",
    resource
) when { (context has trust_state && context.trust_state == "normal") };

permit(
    principal,
    action == Action::"git_log",
    resource
) when { (context has trust_state && context.trust_state == "normal") };

permit(
    principal,
    action == Action::"git_diff",
    resource
) when { (context has trust_state && context.trust_state == "normal") };

permit(
    principal,
    action == Action::"memory_query",
    resource
) when { (context has trust_state && context.trust_state == "normal") };

permit(
    principal,
    action == Action::"rag_search",
    resource
) when { (context has trust_state && context.trust_state == "normal") };
