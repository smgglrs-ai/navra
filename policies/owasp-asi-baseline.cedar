// OWASP Agentic Security Initiative (ASI) Top 10 — baseline Cedar policies.
//
// These policies implement default-deny with explicit permits for safe
// operations. Load via config.toml:
//
//   [permissions.default]
//   cedar_policies = "policies/owasp-asi-baseline.cedar"
//
// Operator can override by loading additional .cedar files that further
// restrict or (via permit) open specific paths. Cedar forbid always wins
// over permit — these baseline forbids cannot be overridden.

// ── ASI01: Goal Hijack / Prompt Injection ──────────────────────────
// Deny tool calls that could inject instructions into agent context.
// Upstream MCP servers with unverified schemas are blocked by default.

forbid(
    principal,
    action == Action::"upstream_tool_call",
    resource
) when { context.manifest_verified == "false" }
unless { context.trust_score == "high" };

// ── ASI02: Tool Misuse ─────────────────────────────────────────────
// Deny destructive file operations unless agent has explicit write grant.

forbid(
    principal,
    action == Action::"file_write",
    resource
) when { context.risk_tier == "high" || context.risk_tier == "critical" }
unless { context.approval_granted == "true" };

forbid(
    principal,
    action == Action::"file_delete",
    resource
) unless { context.approval_granted == "true" };

// ── ASI03: Privilege Escalation ────────────────────────────────────
// Deny capability delegation that exceeds parent scope.

forbid(
    principal,
    action == Action::"capability_delegate",
    resource
) when { context.exceeds_parent_scope == "true" };

// Deny operations when trust score is in suspended state.
forbid(
    principal,
    action,
    resource
) when { context.trust_state == "suspended" };

// ── ASI04: Supply Chain ────────────────────────────────────────────
// Deny loading upstream MCP servers without manifest signature.

forbid(
    principal,
    action == Action::"upstream_discover",
    resource
) when { context.manifest_signed == "false" }
unless { context.trust_on_first_use == "true" };

// ── ASI05: Data Leakage ────────────────────────────────────────────
// Deny sending PII-tainted data to external endpoints.

forbid(
    principal,
    action,
    resource
) when {
    context.ifc_confidentiality == "pii" &&
    context.destination_trust == "external"
};

// Deny egress to non-allowlisted endpoints.
forbid(
    principal,
    action == Action::"http_request",
    resource
) when { context.egress_allowed == "false" };

// ── ASI06: Excessive Permissions ───────────────────────────────────
// Read-only agents cannot write or execute.

forbid(
    principal,
    action == Action::"file_write",
    resource
) when { context.trust_state == "read_only" };

forbid(
    principal,
    action == Action::"exec_command",
    resource
) when { context.trust_state == "read_only" };

forbid(
    principal,
    action == Action::"git_push",
    resource
) when { context.trust_state == "read_only" };

// ── ASI07: Insecure Output ─────────────────────────────────────────
// Deny returning unfiltered content when safety profile requires it.

forbid(
    principal,
    action == Action::"response_send",
    resource
) when {
    context.safety_filtered == "false" &&
    context.safety_required == "true"
};

// ── ASI08: Cascading Failures ──────────────────────────────────────
// Deny tool calls when circuit breaker is open.

forbid(
    principal,
    action,
    resource
) when { context.circuit_breaker == "open" };

// Deny when rate limit is exceeded.
forbid(
    principal,
    action,
    resource
) when { context.rate_limited == "true" };

// ── ASI09: Human Trust ─────────────────────────────────────────────
// Require approval for irreversible operations.

forbid(
    principal,
    action == Action::"git_push",
    resource
) unless { context.approval_granted == "true" };

forbid(
    principal,
    action == Action::"github_pr_create",
    resource
) unless { context.approval_granted == "true" };

forbid(
    principal,
    action == Action::"exec_command",
    resource
) when { context.risk_tier == "critical" }
unless { context.approval_granted == "true" };

// ── ASI10: Rogue Agents ────────────────────────────────────────────
// Deny agents with low trust score from accessing sensitive resources.

forbid(
    principal,
    action,
    resource
) when {
    context.trust_state == "suspended" ||
    context.cognitive_integrity == "violated"
};

// Deny agents that failed upstream tool scanning.
forbid(
    principal,
    action == Action::"upstream_tool_call",
    resource
) when { context.scan_category_blocked == "true" };

// ── Write/push permits (require approval) ──────────────────────────

permit(
    principal,
    action == Action::"file_write",
    resource
) when {
    context.trust_state == "normal" &&
    context.approval_granted == "true"
};

permit(
    principal,
    action == Action::"file_delete",
    resource
) when {
    context.trust_state == "normal" &&
    context.approval_granted == "true"
};

permit(
    principal,
    action == Action::"git_push",
    resource
) when {
    context.trust_state == "normal" &&
    context.approval_granted == "true"
};

permit(
    principal,
    action == Action::"github_pr_create",
    resource
) when {
    context.trust_state == "normal" &&
    context.approval_granted == "true"
};

permit(
    principal,
    action == Action::"exec_command",
    resource
) when {
    context.trust_state == "normal" &&
    context.approval_granted == "true"
};

// ── Baseline permits ───────────────────────────────────────────────
// Read-only operations are allowed for all agents in normal state.

permit(
    principal,
    action == Action::"file_read",
    resource
) when { context.trust_state == "normal" };

permit(
    principal,
    action == Action::"file_tree",
    resource
) when { context.trust_state == "normal" };

permit(
    principal,
    action == Action::"git_status",
    resource
) when { context.trust_state == "normal" };

permit(
    principal,
    action == Action::"git_log",
    resource
) when { context.trust_state == "normal" };

permit(
    principal,
    action == Action::"git_diff",
    resource
) when { context.trust_state == "normal" };

permit(
    principal,
    action == Action::"memory_query",
    resource
) when { context.trust_state == "normal" };

permit(
    principal,
    action == Action::"rag_search",
    resource
) when { context.trust_state == "normal" };
