//! Approval gate hook: suspends high-risk tool calls pending human approval.
//!
//! Addresses OWASP ASI09 (Insufficient Human Oversight) by requiring
//! explicit approval for tool calls that match configurable risk patterns.
//! Low-risk calls pass through automatically.

use super::{Hook, HookDecision};
use navra_auth::auth::CallContext;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// What to do when an approval request times out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutDefault {
    /// Block the tool call (fail-closed).
    Deny,
    /// Allow the tool call (fail-open).
    Allow,
}

/// Configuration for the approval gate hook.
#[derive(Debug, Clone)]
pub struct ApprovalGateConfig {
    /// Whether the approval gate is active.
    pub enabled: bool,
    /// Patterns that identify high-risk tool calls (substring match on tool name).
    pub risk_keywords: Vec<String>,
    /// How long to wait for approval before applying the default.
    pub timeout_secs: u64,
    /// What to do when approval times out.
    pub default_on_timeout: TimeoutDefault,
}

impl Default for ApprovalGateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            risk_keywords: vec![
                "delete".to_string(),
                "exec".to_string(),
                "shell".to_string(),
                "write".to_string(),
            ],
            timeout_secs: 300,
            default_on_timeout: TimeoutDefault::Deny,
        }
    }
}

/// Status of a pending approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied(String),
    TimedOut,
}

/// A tool call awaiting human approval.
#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub request_id: String,
    pub tool_name: String,
    pub arguments_summary: String,
    pub agent_name: String,
    pub created_at: Instant,
    pub status: ApprovalStatus,
}

/// Hook that gates high-risk tool calls on human approval.
pub struct ApprovalGateHook {
    config: ApprovalGateConfig,
    pending: Mutex<HashMap<String, PendingApproval>>,
    next_id: Mutex<u64>,
}

impl ApprovalGateHook {
    /// Create a new approval gate hook with the given configuration.
    pub fn new(config: ApprovalGateConfig) -> Self {
        Self {
            config,
            pending: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }

    /// Check whether a tool name matches any risk keyword.
    fn is_high_risk(&self, tool_name: &str) -> bool {
        self.config
            .risk_keywords
            .iter()
            .any(|kw| tool_name.contains(kw))
    }

    /// Generate a unique request ID.
    fn next_request_id(&self) -> String {
        let mut id = self.next_id.lock().unwrap();
        let request_id = format!("approval-{id}");
        *id += 1;
        request_id
    }

    /// Summarise arguments for human review (truncated).
    fn summarise_args(args: &serde_json::Value) -> String {
        let s = args.to_string();
        if s.len() > 200 {
            format!("{}...", &s[..200])
        } else {
            s
        }
    }

    /// Approve a pending request. Returns `true` if the request existed
    /// and was still pending.
    pub fn approve(&self, request_id: &str) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if let Some(entry) = pending.get_mut(request_id) {
            if entry.status == ApprovalStatus::Pending {
                entry.status = ApprovalStatus::Approved;
                return true;
            }
        }
        false
    }

    /// Deny a pending request with a reason. Returns `true` if the
    /// request existed and was still pending.
    pub fn deny(&self, request_id: &str, reason: String) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if let Some(entry) = pending.get_mut(request_id) {
            if entry.status == ApprovalStatus::Pending {
                entry.status = ApprovalStatus::Denied(reason);
                return true;
            }
        }
        false
    }

    /// List all pending approval requests.
    pub fn pending_requests(&self) -> Vec<PendingApproval> {
        let pending = self.pending.lock().unwrap();
        pending
            .values()
            .filter(|p| p.status == ApprovalStatus::Pending)
            .cloned()
            .collect()
    }

    /// Remove expired requests, applying the configured timeout default.
    /// Returns the number of requests cleaned up.
    pub fn cleanup_expired(&self) -> usize {
        let timeout = Duration::from_secs(self.config.timeout_secs);
        let mut pending = self.pending.lock().unwrap();
        let mut cleaned = 0;
        for entry in pending.values_mut() {
            if entry.status == ApprovalStatus::Pending && entry.created_at.elapsed() > timeout {
                entry.status = ApprovalStatus::TimedOut;
                cleaned += 1;
            }
        }
        // Remove all non-pending entries.
        pending.retain(|_, v| v.status == ApprovalStatus::Pending);
        cleaned
    }
}

#[async_trait::async_trait]
impl Hook for ApprovalGateHook {
    fn name(&self) -> &str {
        "approval-gate"
    }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        ctx: &CallContext,
    ) -> HookDecision {
        if !self.config.enabled {
            return HookDecision::Continue;
        }

        if !self.is_high_risk(tool_name) {
            return HookDecision::Continue;
        }

        let request_id = self.next_request_id();
        let approval = PendingApproval {
            request_id: request_id.clone(),
            tool_name: tool_name.to_string(),
            arguments_summary: Self::summarise_args(arguments),
            agent_name: ctx.agent.name.clone(),
            created_at: Instant::now(),
            status: ApprovalStatus::Pending,
        };

        {
            let mut pending = self.pending.lock().unwrap();
            pending.insert(request_id.clone(), approval);
        }

        tracing::info!(
            request_id = %request_id,
            tool = %tool_name,
            agent = %ctx.agent.name,
            "Tool call requires approval"
        );

        HookDecision::Pending(request_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_auth::auth::AgentIdentity;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
    }

    fn test_config(keywords: Vec<&str>) -> ApprovalGateConfig {
        ApprovalGateConfig {
            enabled: true,
            risk_keywords: keywords.into_iter().map(String::from).collect(),
            timeout_secs: 1,
            default_on_timeout: TimeoutDefault::Deny,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn low_risk_auto_approved() {
        let hook = ApprovalGateHook::new(test_config(vec!["delete", "exec"]));
        let decision = hook
            .pre_tool_use("file_read", &serde_json::json!({}), &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn high_risk_creates_pending() {
        let hook = ApprovalGateHook::new(test_config(vec!["delete", "exec"]));
        let decision = hook
            .pre_tool_use("file_delete", &serde_json::json!({"path": "/tmp/x"}), &test_ctx())
            .await;
        match decision {
            HookDecision::Pending(id) => {
                assert!(id.starts_with("approval-"));
            }
            other => panic!("Expected Pending, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn approve_resolves() {
        let hook = ApprovalGateHook::new(test_config(vec!["exec"]));
        let decision = hook
            .pre_tool_use("shell_exec", &serde_json::json!({"cmd": "ls"}), &test_ctx())
            .await;
        let id = match decision {
            HookDecision::Pending(id) => id,
            other => panic!("Expected Pending, got {other:?}"),
        };

        assert!(hook.approve(&id));
        // Verify status changed.
        let pending = hook.pending.lock().unwrap();
        assert_eq!(pending[&id].status, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn deny_resolves() {
        let hook = ApprovalGateHook::new(test_config(vec!["exec"]));
        let decision = hook
            .pre_tool_use("shell_exec", &serde_json::json!({"cmd": "rm -rf /"}), &test_ctx())
            .await;
        let id = match decision {
            HookDecision::Pending(id) => id,
            other => panic!("Expected Pending, got {other:?}"),
        };

        assert!(hook.deny(&id, "too dangerous".to_string()));
        let pending = hook.pending.lock().unwrap();
        assert_eq!(
            pending[&id].status,
            ApprovalStatus::Denied("too dangerous".to_string())
        );
    }

    #[tokio::test]
    async fn timeout_defaults() {
        let mut config = test_config(vec!["exec"]);
        config.timeout_secs = 0; // instant expiry
        let hook = ApprovalGateHook::new(config);

        let decision = hook
            .pre_tool_use("shell_exec", &serde_json::json!({}), &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Pending(_)));

        // Wait a tiny bit so elapsed > 0.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let cleaned = hook.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert!(hook.pending_requests().is_empty());
    }

    #[tokio::test]
    async fn disabled_passes() {
        let config = ApprovalGateConfig {
            enabled: false,
            risk_keywords: vec!["delete".to_string()],
            ..Default::default()
        };
        let hook = ApprovalGateHook::new(config);

        let decision = hook
            .pre_tool_use("file_delete", &serde_json::json!({}), &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn pending_list() {
        let hook = ApprovalGateHook::new(test_config(vec!["exec"]));

        // No pending initially.
        assert!(hook.pending_requests().is_empty());

        // Create two pending requests.
        hook.pre_tool_use("shell_exec", &serde_json::json!({}), &test_ctx())
            .await;
        hook.pre_tool_use("cmd_exec", &serde_json::json!({}), &test_ctx())
            .await;

        let pending = hook.pending_requests();
        assert_eq!(pending.len(), 2);

        // Approve one.
        hook.approve(&pending[0].request_id);
        assert_eq!(hook.pending_requests().len(), 1);
    }

    #[tokio::test]
    async fn cleanup_expired() {
        let mut config = test_config(vec!["exec"]);
        config.timeout_secs = 0;
        let hook = ApprovalGateHook::new(config);

        hook.pre_tool_use("shell_exec", &serde_json::json!({}), &test_ctx())
            .await;
        hook.pre_tool_use("cmd_exec", &serde_json::json!({}), &test_ctx())
            .await;

        tokio::time::sleep(Duration::from_millis(10)).await;

        let cleaned = hook.cleanup_expired();
        assert_eq!(cleaned, 2);
        assert!(hook.pending_requests().is_empty());
    }
}
