# Temporal Behavioral Contracts — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add runtime policy enforcement over agent action history — temporal constraints on tool-call trajectories, not just per-request ACLs.

**Architecture:** A `TemporalContractHook` in `navra-security` that maintains a per-session action log via `Mutex<HashMap>` (same pattern as `StatisticalGuardrailHook`) and evaluates YAML-defined temporal predicates before each tool call. Post-hook records actions; pre-hook evaluates contracts.

**Tech Stack:** Rust, async-trait, serde/serde_yaml for config, tokio, navra-security hook pipeline.

**Environment:** `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1` required for all cargo commands.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `navra-security/src/hooks/temporal_contract.rs` | Create | SessionActionLog, predicates, contract engine, hook impl, tests |
| `navra-security/src/hooks/mod.rs` | Modify (lines 8-26) | Add module declaration + pub use |
| `navra-security/Cargo.toml` | Modify | Add `serde_yaml` dependency |
| `navra-server/src/config/security.rs` | Modify | Add `TemporalContractServerConfig` |
| `navra-server/src/main.rs` | Modify (~line 3468) | Wire hook from config |

---

### Task 1: SessionActionLog and ActionEntry types

**Files:**
- Create: `navra-security/src/hooks/temporal_contract.rs`
- Modify: `navra-security/src/hooks/mod.rs`

- [ ] **Step 1: Write failing test for SessionActionLog**

In `navra-security/src/hooks/temporal_contract.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use navra_protocol::DataLabel;

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
            log.record("s1", ActionEntry {
                tool_name: format!("tool_{i}"),
                result_status: ResultStatus::Success,
                ifc_label: DataLabel::TRUSTED_PUBLIC,
                timestamp: std::time::Instant::now(),
            });
        }
        let history = log.get("s1");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].tool_name, "tool_2");
    }

    #[test]
    fn session_action_log_isolates_sessions() {
        let log = SessionActionLog::new(100);
        log.record("s1", ActionEntry {
            tool_name: "file_read".to_string(),
            result_status: ResultStatus::Success,
            ifc_label: DataLabel::TRUSTED_PUBLIC,
            timestamp: std::time::Instant::now(),
        });
        log.record("s2", ActionEntry {
            tool_name: "git_status".to_string(),
            result_status: ResultStatus::Success,
            ifc_label: DataLabel::TRUSTED_PUBLIC,
            timestamp: std::time::Instant::now(),
        });
        assert_eq!(log.get("s1").len(), 1);
        assert_eq!(log.get("s2").len(), 1);
        assert_eq!(log.get("s3").len(), 0);
    }
}
```

- [ ] **Step 2: Register module in mod.rs**

Add to `navra-security/src/hooks/mod.rs` after line 16 (`mod tool_guard;`):

```rust
pub mod temporal_contract;
```

Add to the `pub use` block after line 26:

```rust
pub use temporal_contract::{
    ContractAction, SessionActionLog, TemporalContract, TemporalContractHook, TemporalPredicate,
};
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security temporal_contract -- --nocapture 2>&1 | tail -20`

Expected: Compile errors — types not defined yet.

- [ ] **Step 4: Implement SessionActionLog and ActionEntry**

Write the implementation at the top of `temporal_contract.rs`:

```rust
//! Temporal behavioral contracts: runtime policy over agent action history.
//!
//! A pre+post hook that maintains a per-session action log and evaluates
//! temporal predicates before each tool call. Goes beyond static ACLs to
//! enforce trajectory-level constraints like "cannot write unless read
//! first" or "3+ destructive tools require human check-in."

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use navra_protocol::{CallToolResult, DataLabel};

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security temporal_contract -- --nocapture 2>&1 | tail -10`

Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add navra-security/src/hooks/temporal_contract.rs navra-security/src/hooks/mod.rs
git commit -s -m "feat(security): add SessionActionLog for temporal contracts"
```

---

### Task 2: TemporalPredicate engine

**Files:**
- Modify: `navra-security/src/hooks/temporal_contract.rs`

- [ ] **Step 1: Write failing tests for each predicate variant**

Add to the `tests` module:

```rust
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
        log.record("s1", ActionEntry {
            tool_name: "file_read".to_string(),
            result_status: ResultStatus::Success,
            ifc_label: DataLabel::TRUSTED_PUBLIC,
            timestamp: Instant::now(),
        });
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
```

- [ ] **Step 2: Run tests to verify compile failure**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security temporal_contract -- --nocapture 2>&1 | tail -5`

Expected: Compile error — `TemporalPredicate` not defined.

- [ ] **Step 3: Implement TemporalPredicate enum and evaluate()**

Add after `SessionActionLog` in `temporal_contract.rs`:

```rust
/// Temporal predicates evaluated against the session action log.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TemporalPredicate {
    /// Tool X requires prior call to tool Y in this session.
    Requires {
        tool: String,
        prerequisite: String,
    },
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
    DenialEscalation {
        threshold: usize,
    },
    /// Minimum interval between calls to a tool.
    Cooldown {
        tool: String,
        min_interval_ms: u64,
    },
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
    actual.confidentiality >= trigger.confidentiality
        || actual.integrity >= trigger.integrity
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security temporal_contract -- --nocapture 2>&1 | tail -20`

Expected: All 14 tests pass.

- [ ] **Step 5: Commit**

```bash
git add navra-security/src/hooks/temporal_contract.rs
git commit -s -m "feat(security): add TemporalPredicate engine with 7 predicate types"
```

---

### Task 3: TemporalContract and TemporalContractHook

**Files:**
- Modify: `navra-security/src/hooks/temporal_contract.rs`

- [ ] **Step 1: Write failing tests for the hook**

Add to `tests` module:

```rust
    use crate::auth::AgentIdentity;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
    }

    fn test_ctx_with_perms(perms: &str) -> CallContext {
        CallContext::new(AgentIdentity::new("tester", perms), "test-session")
    }

    fn make_hook(contracts: Vec<TemporalContract>) -> (Arc<SessionActionLog>, TemporalContractHook) {
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
            .pre_tool_use("file_write", &serde_json::json!({}), &ctx)
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
        log.record(&ctx.session_id, ActionEntry {
            tool_name: "file_read".to_string(),
            result_status: ResultStatus::Success,
            ifc_label: DataLabel::TRUSTED_PUBLIC,
            timestamp: Instant::now(),
        });

        let decision = hook
            .pre_tool_use("file_write", &serde_json::json!({}), &ctx)
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
        let result = CallToolResult::error("failed");

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
        let ctx = test_ctx_with_perms("admin");

        let decision = hook
            .pre_tool_use("file_write", &serde_json::json!({}), &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }
```

- [ ] **Step 2: Run tests to verify compile failure**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security hook_blocks -- --nocapture 2>&1 | tail -5`

Expected: Compile error — `TemporalContract`, `ContractAction`, `TemporalContractHook` not defined.

- [ ] **Step 3: Implement TemporalContract, ContractAction, and TemporalContractHook**

Add after `TemporalPredicate` in `temporal_contract.rs`:

```rust
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

use std::sync::Arc;

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
    ) -> HookDecision {
        let history = self.log.get(&ctx.session_id);
        let current_label = ctx.taint.level();

        for contract in &self.contracts {
            if !contract.applies_to_permission(&ctx.agent.permissions) {
                continue;
            }
            if let Some(violation) = contract.predicate.evaluate(tool_name, &history, current_label)
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
        let status = if result.is_error {
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
```

- [ ] **Step 4: Run all tests**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security temporal_contract -- --nocapture 2>&1 | tail -20`

Expected: All 19 tests pass.

- [ ] **Step 5: Commit**

```bash
git add navra-security/src/hooks/temporal_contract.rs
git commit -s -m "feat(security): add TemporalContractHook with pre/post enforcement"
```

---

### Task 4: Server config and wiring

**Files:**
- Modify: `navra-server/src/config/security.rs`
- Modify: `navra-server/src/main.rs`
- Modify: `navra-security/Cargo.toml`

- [ ] **Step 1: Add serde_yaml to navra-security deps**

In `navra-security/Cargo.toml`, add after the `glob = "0.3"` line:

```toml
serde_yaml = "0.9"
```

- [ ] **Step 2: Add config struct**

In `navra-server/src/config/security.rs`, add after the existing `StatisticalGuardrailServerConfig` impl block:

```rust
/// Server-side configuration for temporal behavioral contracts.
#[derive(Debug, Clone, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct TemporalContractServerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_history")]
    pub max_history_per_session: usize,
    #[serde(default)]
    pub contracts: Vec<TemporalContractConfig>,
}

fn default_max_history() -> usize {
    200
}

#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct TemporalContractConfig {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub predicate: serde_json::Value,
    pub action: serde_json::Value,
    pub applies_to: Vec<String>,
}
```

- [ ] **Step 3: Add field to main server config**

Find the server config struct that holds `statistical: StatisticalGuardrailServerConfig` and add:

```rust
    #[serde(default)]
    pub temporal_contracts: TemporalContractServerConfig,
```

- [ ] **Step 4: Wire hook in main.rs**

After the statistical guardrail hook wiring (~line 3468), add:

```rust
    // Temporal behavioral contracts
    if cfg.temporal_contracts.enabled && !cfg.temporal_contracts.contracts.is_empty() {
        let action_log = std::sync::Arc::new(
            navra_core::hooks::SessionActionLog::new(
                cfg.temporal_contracts.max_history_per_session,
            ),
        );
        let mut contracts = Vec::new();
        for tc in &cfg.temporal_contracts.contracts {
            match serde_json::from_value::<navra_core::hooks::TemporalContract>(
                serde_json::json!({
                    "name": tc.name,
                    "description": tc.description,
                    "predicate": tc.predicate,
                    "action": tc.action,
                    "applies_to": tc.applies_to,
                }),
            ) {
                Ok(contract) => contracts.push(contract),
                Err(e) => {
                    tracing::warn!(
                        contract = %tc.name,
                        error = %e,
                        "Failed to parse temporal contract — skipping"
                    );
                }
            }
        }
        tracing::info!(
            count = contracts.len(),
            "Temporal behavioral contracts enabled"
        );
        builder = builder.hook(navra_core::hooks::TemporalContractHook::new(
            action_log, contracts,
        ));
    }
```

- [ ] **Step 5: Verify full workspace builds**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build --workspace 2>&1 | tail -5`

Expected: Build succeeds with no errors.

- [ ] **Step 6: Run full test suite**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test --workspace 2>&1 | tail -20`

Expected: All tests pass (2110+ existing + 19 new).

- [ ] **Step 7: Commit**

```bash
git add navra-security/Cargo.toml navra-server/src/config/security.rs navra-server/src/main.rs
git commit -s -m "feat(server): wire temporal contracts into config and hook pipeline"
```

---

### Task 5: Clippy clean + final verification

- [ ] **Step 1: Run clippy**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo clippy --workspace 2>&1 | tail -20`

Expected: 0 warnings. Fix any that appear.

- [ ] **Step 2: Run full workspace tests one final time**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test --workspace 2>&1 | tail -10`

Expected: All tests pass.

- [ ] **Step 3: Commit any clippy fixes**

```bash
git add -A && git commit -s -m "chore: clippy fixes for temporal contracts"
```

(Skip if no fixes needed.)
