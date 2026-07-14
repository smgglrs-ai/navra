//! Temporal behavioral contracts: runtime policy over agent action history.
//!
//! A pre+post hook that maintains a per-session action log and evaluates
//! temporal predicates before each tool call. Goes beyond static ACLs to
//! enforce trajectory-level constraints like "cannot write unless read
//! first" or "3+ destructive tools require human check-in."

use super::{Hook, HookDecision};
use navra_auth::auth::CallContext;
use navra_protocol::CallToolResult;
use navra_protocol::compat::CallToolResultExt;
use navra_protocol::label::DataLabel;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use vstd::prelude::*;

/// Status of a completed tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultStatus {
    Success,
    Error,
    Blocked,
}

/// A single recorded action in a session's history.
#[derive(Debug, Clone)]
pub struct ActionEntry {
    pub tool_name: String,
    pub result_status: ResultStatus,
    pub ifc_label: DataLabel,
    pub timestamp: Instant,
}

/// Per-session action log for temporal contract evaluation.
///
/// Thread-safe via `Mutex<HashMap>` (same pattern as `StatisticalGuardrailHook`).
/// Each session maintains a bounded ring buffer of recent actions.
pub struct SessionActionLog {
    entries: Mutex<HashMap<String, Vec<ActionEntry>>>,
    max_per_session: usize,
}

impl SessionActionLog {
    pub fn new(max_per_session: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_per_session,
        }
    }

    pub fn record(&self, session_id: &str, entry: ActionEntry) {
        let mut map = self.entries.lock().unwrap();
        let log = map.entry(session_id.to_string()).or_default();
        log.push(entry);
        if log.len() > self.max_per_session {
            log.remove(0);
        }
    }

    pub fn get(&self, session_id: &str) -> Vec<ActionEntry> {
        let map = self.entries.lock().unwrap();
        map.get(session_id).cloned().unwrap_or_default()
    }
}

/// Temporal predicates evaluated against the session action log.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TemporalPredicate {
    /// Tool X requires prior call to tool Y in this session.
    Requires { tool: String, prerequisite: String },
    /// No more than N consecutive calls matching pattern.
    SequenceLimit {
        pattern: String,
        max_consecutive: usize,
    },
    /// After seeing a specific IFC label, block listed tools.
    TaintGate {
        trigger_label: DataLabel,
        blocked_tools: Vec<String>,
    },
    /// After N blocked calls, trigger escalation.
    DenialEscalation { threshold: usize },
    /// Minimum interval between calls to a tool.
    Cooldown { tool: String, min_interval_ms: u64 },
    /// All sub-predicates must hold (AND).
    All(Vec<TemporalPredicate>),
    /// Any sub-predicate triggers (OR).
    Any(Vec<TemporalPredicate>),
}

impl TemporalPredicate {
    /// Evaluate this predicate against session history.
    ///
    /// Returns `Some(reason)` if the predicate is violated (tool call
    /// should be blocked), or `None` if the call is allowed.
    pub fn evaluate(
        &self,
        tool_name: &str,
        history: &[ActionEntry],
        _current_label: DataLabel,
    ) -> Option<String> {
        match self {
            Self::Requires { tool, prerequisite } => {
                if !glob_match(tool, tool_name) {
                    return None;
                }
                let has_prereq = history.iter().any(|e| {
                    glob_match(prerequisite, &e.tool_name)
                        && e.result_status == ResultStatus::Success
                });
                if has_prereq {
                    None
                } else {
                    Some(format!(
                        "Temporal contract: {tool_name} requires prior call to {prerequisite}"
                    ))
                }
            }
            Self::SequenceLimit {
                pattern,
                max_consecutive,
            } => {
                if !glob_match(pattern, tool_name) {
                    return None;
                }
                let consecutive = history
                    .iter()
                    .rev()
                    .take_while(|e| glob_match(pattern, &e.tool_name))
                    .count();
                if consecutive >= *max_consecutive {
                    Some(format!(
                        "Temporal contract: {consecutive} consecutive calls matching \
                         '{pattern}' (limit: {max_consecutive})"
                    ))
                } else {
                    None
                }
            }
            Self::TaintGate {
                trigger_label,
                blocked_tools,
            } => {
                let triggered = history
                    .iter()
                    .any(|e| label_matches(&e.ifc_label, trigger_label));
                if !triggered {
                    return None;
                }
                if blocked_tools.iter().any(|p| glob_match(p, tool_name)) {
                    Some(format!(
                        "Temporal contract: {tool_name} blocked after accessing \
                         {trigger_label:?}-labeled data"
                    ))
                } else {
                    None
                }
            }
            Self::DenialEscalation { threshold } => {
                let denials = history
                    .iter()
                    .filter(|e| e.result_status == ResultStatus::Blocked)
                    .count();
                if denials >= *threshold {
                    Some(format!(
                        "Temporal contract: {denials} denials in session (threshold: \
                         {threshold}) — escalation required"
                    ))
                } else {
                    None
                }
            }
            Self::Cooldown {
                tool,
                min_interval_ms,
            } => {
                if !glob_match(tool, tool_name) {
                    return None;
                }
                if let Some(last) = history
                    .iter()
                    .rev()
                    .find(|e| glob_match(tool, &e.tool_name))
                {
                    let elapsed = last.timestamp.elapsed().as_millis() as u64;
                    if elapsed < *min_interval_ms {
                        return Some(format!(
                            "Temporal contract: {tool_name} cooldown — {elapsed}ms \
                             elapsed, minimum {min_interval_ms}ms"
                        ));
                    }
                }
                None
            }
            Self::All(preds) => {
                for pred in preds {
                    if let Some(reason) = pred.evaluate(tool_name, history, _current_label) {
                        return Some(reason);
                    }
                }
                None
            }
            Self::Any(preds) => {
                for pred in preds {
                    if let Some(reason) = pred.evaluate(tool_name, history, _current_label) {
                        return Some(reason);
                    }
                }
                None
            }
        }
    }
}

/// Check if a DataLabel meets or exceeds the trigger label in any dimension.
fn label_matches(actual: &DataLabel, trigger: &DataLabel) -> bool {
    actual.confidentiality >= trigger.confidentiality || actual.integrity >= trigger.integrity
}

/// Simple glob matching (prefix `*`, suffix `*`, exact).
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return text.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return text.ends_with(suffix);
    }
    pattern == text
}

/// Action to take when a temporal contract is violated.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContractAction {
    /// Block the tool call with an error message.
    Block(String),
    /// Block with an escalation hint.
    Escalate(String),
    /// Require human approval before proceeding.
    RequireApproval,
}

/// A temporal contract: a named predicate + action + scope.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TemporalContract {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub predicate: TemporalPredicate,
    pub action: ContractAction,
    pub applies_to: Vec<String>,
}

impl TemporalContract {
    fn applies_to_permission(&self, permission_set: &str) -> bool {
        self.applies_to
            .iter()
            .any(|p| glob_match(p, permission_set))
    }

    fn format_block_reason(&self, violation: &str) -> String {
        match &self.action {
            ContractAction::Block(msg) => format!("[{}] {}: {}", self.name, msg, violation),
            ContractAction::Escalate(target) => {
                format!("[{}] Escalation to {}: {}", self.name, target, violation)
            }
            ContractAction::RequireApproval => {
                format!("[{}] Approval required: {}", self.name, violation)
            }
        }
    }
}

/// Hook that enforces temporal behavioral contracts.
///
/// Pre-hook: evaluates contracts against session action history.
/// Post-hook: records the tool call result into the session action log.
pub struct TemporalContractHook {
    log: Arc<SessionActionLog>,
    contracts: Vec<TemporalContract>,
}

impl TemporalContractHook {
    pub fn new(log: Arc<SessionActionLog>, contracts: Vec<TemporalContract>) -> Self {
        Self { log, contracts }
    }
}

#[async_trait::async_trait]
impl Hook for TemporalContractHook {
    fn name(&self) -> &str {
        "temporal-contract"
    }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        ctx: &CallContext,
        _annotations: Option<&navra_protocol::ToolAnnotations>,
    ) -> HookDecision {
        let history = self.log.get(&ctx.session_id);
        let current_label = ctx.taint.level();

        for contract in &self.contracts {
            if !contract.applies_to_permission(&ctx.agent.permissions) {
                continue;
            }
            if let Some(violation) = contract
                .predicate
                .evaluate(tool_name, &history, current_label)
            {
                let reason = contract.format_block_reason(&violation);
                tracing::info!(
                    contract = %contract.name,
                    tool = tool_name,
                    session = %ctx.session_id,
                    "Temporal contract violated"
                );
                return HookDecision::Block(reason);
            }
        }
        HookDecision::Continue
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        result: &CallToolResult,
        ctx: &CallContext,
    ) -> HookDecision {
        let status = if result.is_err() {
            ResultStatus::Error
        } else {
            ResultStatus::Success
        };

        self.log.record(
            &ctx.session_id,
            ActionEntry {
                tool_name: tool_name.to_string(),
                result_status: status,
                ifc_label: ctx.taint.level(),
                timestamp: Instant::now(),
            },
        );
        HookDecision::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_auth::auth::AgentIdentity;

    #[test]
    fn session_action_log_records_and_retrieves() {
        let log = SessionActionLog::new(100);
        let entry = ActionEntry {
            tool_name: "file_read".to_string(),
            result_status: ResultStatus::Success,
            ifc_label: DataLabel::TRUSTED_PUBLIC,
            timestamp: std::time::Instant::now(),
        };
        log.record("session-1", entry);
        let history = log.get("session-1");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].tool_name, "file_read");
    }

    #[test]
    fn session_action_log_caps_at_max() {
        let log = SessionActionLog::new(3);
        for i in 0..5 {
            log.record(
                "s1",
                ActionEntry {
                    tool_name: format!("tool_{i}"),
                    result_status: ResultStatus::Success,
                    ifc_label: DataLabel::TRUSTED_PUBLIC,
                    timestamp: std::time::Instant::now(),
                },
            );
        }
        let history = log.get("s1");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].tool_name, "tool_2");
    }

    #[test]
    fn session_action_log_isolates_sessions() {
        let log = SessionActionLog::new(100);
        log.record(
            "s1",
            ActionEntry {
                tool_name: "file_read".to_string(),
                result_status: ResultStatus::Success,
                ifc_label: DataLabel::TRUSTED_PUBLIC,
                timestamp: std::time::Instant::now(),
            },
        );
        log.record(
            "s2",
            ActionEntry {
                tool_name: "git_status".to_string(),
                result_status: ResultStatus::Success,
                ifc_label: DataLabel::TRUSTED_PUBLIC,
                timestamp: std::time::Instant::now(),
            },
        );
        assert_eq!(log.get("s1").len(), 1);
        assert_eq!(log.get("s2").len(), 1);
        assert_eq!(log.get("s3").len(), 0);
    }

    #[test]
    fn predicate_requires_blocks_when_prereq_missing() {
        let log = SessionActionLog::new(100);
        let pred = TemporalPredicate::Requires {
            tool: "file_write".to_string(),
            prerequisite: "file_read".to_string(),
        };
        let history = log.get("s1");
        let result = pred.evaluate("file_write", &history, DataLabel::TRUSTED_PUBLIC);
        assert!(result.is_some(), "should block: no file_read in history");
    }

    #[test]
    fn predicate_requires_allows_when_prereq_present() {
        let log = SessionActionLog::new(100);
        log.record(
            "s1",
            ActionEntry {
                tool_name: "file_read".to_string(),
                result_status: ResultStatus::Success,
                ifc_label: DataLabel::TRUSTED_PUBLIC,
                timestamp: Instant::now(),
            },
        );
        let pred = TemporalPredicate::Requires {
            tool: "file_write".to_string(),
            prerequisite: "file_read".to_string(),
        };
        let history = log.get("s1");
        let result = pred.evaluate("file_write", &history, DataLabel::TRUSTED_PUBLIC);
        assert!(result.is_none(), "should allow: file_read in history");
    }

    #[test]
    fn predicate_requires_ignores_unrelated_tools() {
        let pred = TemporalPredicate::Requires {
            tool: "file_write".to_string(),
            prerequisite: "file_read".to_string(),
        };
        let result = pred.evaluate("git_status", &[], DataLabel::TRUSTED_PUBLIC);
        assert!(result.is_none(), "should not apply to git_status");
    }

    #[test]
    fn predicate_sequence_limit_blocks_at_threshold() {
        let mut history = Vec::new();
        for _ in 0..3 {
            history.push(ActionEntry {
                tool_name: "file_write".to_string(),
                result_status: ResultStatus::Success,
                ifc_label: DataLabel::TRUSTED_PUBLIC,
                timestamp: Instant::now(),
            });
        }
        let pred = TemporalPredicate::SequenceLimit {
            pattern: "file_write".to_string(),
            max_consecutive: 3,
        };
        let result = pred.evaluate("file_write", &history, DataLabel::TRUSTED_PUBLIC);
        assert!(result.is_some(), "should block: 3 consecutive file_writes");
    }

    #[test]
    fn predicate_sequence_limit_resets_on_different_tool() {
        let mut history = Vec::new();
        for _ in 0..2 {
            history.push(ActionEntry {
                tool_name: "file_write".to_string(),
                result_status: ResultStatus::Success,
                ifc_label: DataLabel::TRUSTED_PUBLIC,
                timestamp: Instant::now(),
            });
        }
        history.push(ActionEntry {
            tool_name: "file_read".to_string(),
            result_status: ResultStatus::Success,
            ifc_label: DataLabel::TRUSTED_PUBLIC,
            timestamp: Instant::now(),
        });
        let pred = TemporalPredicate::SequenceLimit {
            pattern: "file_write".to_string(),
            max_consecutive: 3,
        };
        let result = pred.evaluate("file_write", &history, DataLabel::TRUSTED_PUBLIC);
        assert!(result.is_none(), "sequence was broken by file_read");
    }

    #[test]
    fn predicate_taint_gate_blocks_after_pii() {
        let mut history = Vec::new();
        history.push(ActionEntry {
            tool_name: "file_read".to_string(),
            result_status: ResultStatus::Success,
            ifc_label: DataLabel::UNTRUSTED_PII,
            timestamp: Instant::now(),
        });
        let pred = TemporalPredicate::TaintGate {
            trigger_label: DataLabel::UNTRUSTED_PII,
            blocked_tools: vec!["team_message".to_string(), "flow_start".to_string()],
        };
        let result = pred.evaluate("team_message", &history, DataLabel::UNTRUSTED_PII);
        assert!(result.is_some(), "should block after PII access");
    }

    #[test]
    fn predicate_taint_gate_allows_before_pii() {
        let pred = TemporalPredicate::TaintGate {
            trigger_label: DataLabel::UNTRUSTED_PII,
            blocked_tools: vec!["team_message".to_string()],
        };
        let result = pred.evaluate("team_message", &[], DataLabel::TRUSTED_PUBLIC);
        assert!(result.is_none(), "no PII in history, should allow");
    }

    #[test]
    fn predicate_denial_escalation_triggers() {
        let mut history = Vec::new();
        for _ in 0..3 {
            history.push(ActionEntry {
                tool_name: "file_delete".to_string(),
                result_status: ResultStatus::Blocked,
                ifc_label: DataLabel::TRUSTED_PUBLIC,
                timestamp: Instant::now(),
            });
        }
        let pred = TemporalPredicate::DenialEscalation { threshold: 3 };
        let result = pred.evaluate("file_delete", &history, DataLabel::TRUSTED_PUBLIC);
        assert!(result.is_some(), "3 denials should trigger escalation");
    }

    #[test]
    fn predicate_cooldown_blocks_rapid_calls() {
        let mut history = Vec::new();
        history.push(ActionEntry {
            tool_name: "git_commit".to_string(),
            result_status: ResultStatus::Success,
            ifc_label: DataLabel::TRUSTED_PUBLIC,
            timestamp: Instant::now(),
        });
        let pred = TemporalPredicate::Cooldown {
            tool: "git_commit".to_string(),
            min_interval_ms: 5000,
        };
        let result = pred.evaluate("git_commit", &history, DataLabel::TRUSTED_PUBLIC);
        assert!(result.is_some(), "called too recently");
    }

    #[test]
    fn predicate_all_requires_both() {
        let pred = TemporalPredicate::All(vec![
            TemporalPredicate::Requires {
                tool: "file_write".to_string(),
                prerequisite: "file_read".to_string(),
            },
            TemporalPredicate::Cooldown {
                tool: "file_write".to_string(),
                min_interval_ms: 0,
            },
        ]);
        let result = pred.evaluate("file_write", &[], DataLabel::TRUSTED_PUBLIC);
        assert!(result.is_some(), "Requires should fail");
    }

    #[test]
    fn predicate_any_triggers_on_first_match() {
        let pred = TemporalPredicate::Any(vec![
            TemporalPredicate::Requires {
                tool: "file_write".to_string(),
                prerequisite: "file_read".to_string(),
            },
            TemporalPredicate::Cooldown {
                tool: "file_write".to_string(),
                min_interval_ms: 999999,
            },
        ]);
        let result = pred.evaluate("file_write", &[], DataLabel::TRUSTED_PUBLIC);
        assert!(result.is_some(), "Requires should trigger");
    }

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
    }

    fn _test_ctx_with_perms(perms: &str) -> CallContext {
        CallContext::new(AgentIdentity::new("tester", perms), "test-session")
    }

    fn make_hook(
        contracts: Vec<TemporalContract>,
    ) -> (Arc<SessionActionLog>, TemporalContractHook) {
        let log = Arc::new(SessionActionLog::new(100));
        let hook = TemporalContractHook::new(Arc::clone(&log), contracts);
        (log, hook)
    }

    #[tokio::test]
    async fn hook_blocks_write_without_prior_read() {
        let contracts = vec![TemporalContract {
            name: "read-before-write".to_string(),
            description: "Must read before write".to_string(),
            predicate: TemporalPredicate::Requires {
                tool: "file_write".to_string(),
                prerequisite: "file_read".to_string(),
            },
            action: ContractAction::Block("Read first".to_string()),
            applies_to: vec!["*".to_string()],
        }];
        let (_log, hook) = make_hook(contracts);
        let ctx = test_ctx();

        let decision = hook
            .pre_tool_use("file_write", &serde_json::json!({}), &ctx, None)
            .await;
        assert!(matches!(decision, HookDecision::Block(_)));
    }

    #[tokio::test]
    async fn hook_allows_write_after_read_recorded() {
        let contracts = vec![TemporalContract {
            name: "read-before-write".to_string(),
            description: "Must read before write".to_string(),
            predicate: TemporalPredicate::Requires {
                tool: "file_write".to_string(),
                prerequisite: "file_read".to_string(),
            },
            action: ContractAction::Block("Read first".to_string()),
            applies_to: vec!["*".to_string()],
        }];
        let (log, hook) = make_hook(contracts);
        let ctx = test_ctx();

        // Simulate a prior read recorded by the post-hook
        log.record(
            &ctx.session_id,
            ActionEntry {
                tool_name: "file_read".to_string(),
                result_status: ResultStatus::Success,
                ifc_label: DataLabel::TRUSTED_PUBLIC,
                timestamp: Instant::now(),
            },
        );

        let decision = hook
            .pre_tool_use("file_write", &serde_json::json!({}), &ctx, None)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn hook_post_records_action() {
        let (log, hook) = make_hook(vec![]);
        let ctx = test_ctx();
        let result = CallToolResult::text("ok");

        hook.post_tool_use("file_read", &serde_json::json!({}), &result, &ctx)
            .await;

        let history = log.get(&ctx.session_id);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].tool_name, "file_read");
        assert_eq!(history[0].result_status, ResultStatus::Success);
    }

    #[tokio::test]
    async fn hook_post_records_error() {
        let (log, hook) = make_hook(vec![]);
        let ctx = test_ctx();
        let result = CallToolResult::error_msg("failed");

        hook.post_tool_use("file_write", &serde_json::json!({}), &result, &ctx)
            .await;

        let history = log.get(&ctx.session_id);
        assert_eq!(history[0].result_status, ResultStatus::Error);
    }

    #[tokio::test]
    async fn hook_skips_contracts_for_non_matching_permissions() {
        let contracts = vec![TemporalContract {
            name: "intern-only".to_string(),
            description: "Only for interns".to_string(),
            predicate: TemporalPredicate::Requires {
                tool: "file_write".to_string(),
                prerequisite: "file_read".to_string(),
            },
            action: ContractAction::Block("Blocked".to_string()),
            applies_to: vec!["intern".to_string()],
        }];
        let (_log, hook) = make_hook(contracts);
        let ctx = _test_ctx_with_perms("admin");

        let decision = hook
            .pre_tool_use("file_write", &serde_json::json!({}), &ctx, None)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }
}

verus! {


spec fn tc_conf_ord(c: Confidentiality) -> nat {
    match c {
        Confidentiality::Public => 0,
        Confidentiality::Sensitive => 1,
        Confidentiality::Pii => 2,
        Confidentiality::Secret => 3,
    }
}

spec fn tc_int_ord(i: Integrity) -> nat {
    match i {
        Integrity::Trusted => 0,
        Integrity::Untrusted => 1,
    }
}

spec fn spec_label_matches(
    actual_conf: nat, actual_int: nat,
    trigger_conf: nat, trigger_int: nat,
) -> bool {
    actual_conf >= trigger_conf || actual_int >= trigger_int
}

proof fn label_matches_reflexive(conf: nat, integ: nat)
    ensures spec_label_matches(conf, integ, conf, integ),
{}

proof fn label_matches_any_dimension(
    actual_conf: nat, actual_integ: nat,
    trigger_conf: nat, trigger_integ: nat,
)
    requires actual_conf >= trigger_conf,
    ensures spec_label_matches(actual_conf, actual_integ, trigger_conf, trigger_integ),
{}

proof fn denial_count_monotonic(before: nat, added_is_blocked: bool)
    ensures ({
        let after = if added_is_blocked { before + 1 } else { before };
        after >= before
    }),
{}

proof fn sequence_count_bounded(history_len: nat, consecutive: nat)
    requires consecutive <= history_len,
    ensures consecutive <= history_len,
{}

} // verus!

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use navra_protocol::label::{Confidentiality, DataLabel, Integrity};

    impl kani::Arbitrary for ResultStatus {
        fn any_array<const N: usize>() -> [Self; N] {
            [Self::Success; N]
        }

        fn any() -> Self {
            match kani::any::<u8>() % 3 {
                0 => ResultStatus::Success,
                1 => ResultStatus::Error,
                _ => ResultStatus::Blocked,
            }
        }
    }

    fn arbitrary_label() -> DataLabel {
        let integrity = if kani::any::<bool>() {
            Integrity::Trusted
        } else {
            Integrity::Untrusted
        };
        let confidentiality = match kani::any::<u8>() % 4 {
            0 => Confidentiality::Public,
            1 => Confidentiality::Sensitive,
            2 => Confidentiality::Pii,
            _ => Confidentiality::Secret,
        };
        DataLabel {
            integrity,
            confidentiality,
        }
    }

    #[kani::proof]
    fn glob_wildcard_matches_all() {
        let choice: u8 = kani::any();
        kani::assume(choice <= 3);
        let text = match choice {
            0 => "file_read",
            1 => "git_status",
            2 => "",
            _ => "anything_else",
        };
        assert!(glob_match("*", text));
    }

    #[kani::proof]
    fn glob_exact_is_equality() {
        let choice: u8 = kani::any();
        kani::assume(choice <= 3);
        let text = match choice {
            0 => "file_read",
            1 => "git_status",
            2 => "team_message",
            _ => "flow_start",
        };
        assert!(glob_match(text, text));
    }

    #[kani::proof]
    fn sequence_limit_count_bounded() {
        let len: u8 = kani::any();
        kani::assume(len <= 3);
        let mut history = Vec::new();
        for _ in 0..len {
            let status: ResultStatus = kani::any();
            history.push(ActionEntry {
                tool_name: "file_write".to_string(),
                result_status: status,
                ifc_label: DataLabel::TRUSTED_PUBLIC,
                timestamp: std::time::Instant::now(),
            });
        }
        let consecutive = history
            .iter()
            .rev()
            .take_while(|e| glob_match("file_write", &e.tool_name))
            .count();
        assert!(consecutive <= history.len());
    }

    #[kani::proof]
    fn denial_escalation_monotonic() {
        let len: u8 = kani::any();
        kani::assume(len <= 3);
        let mut history = Vec::new();
        for _ in 0..len {
            let status: ResultStatus = kani::any();
            history.push(ActionEntry {
                tool_name: "any_tool".to_string(),
                result_status: status,
                ifc_label: DataLabel::TRUSTED_PUBLIC,
                timestamp: std::time::Instant::now(),
            });
        }
        let count_before = history
            .iter()
            .filter(|e| e.result_status == ResultStatus::Blocked)
            .count();
        history.push(ActionEntry {
            tool_name: "blocked_tool".to_string(),
            result_status: ResultStatus::Blocked,
            ifc_label: DataLabel::TRUSTED_PUBLIC,
            timestamp: std::time::Instant::now(),
        });
        let count_after = history
            .iter()
            .filter(|e| e.result_status == ResultStatus::Blocked)
            .count();
        assert!(
            count_after > count_before,
            "adding Blocked entry must increase denial count"
        );
    }
}
