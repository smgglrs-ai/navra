//! Per-agent token quotas for fair scheduling.
//!
//! Prevents any single agent from monopolizing model inference.
//! Agents exceeding their quota get deprioritized (next request
//! queued behind others), not cancelled outright.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use vstd::prelude::*;

/// Token quota configuration for an agent.
#[derive(Debug, Clone)]
pub struct TokenQuota {
    /// Maximum tokens allowed within a single time window.
    pub max_tokens_per_window: u64,
    /// Duration of the sliding time window in seconds.
    pub window_secs: u64,
}

impl Default for TokenQuota {
    fn default() -> Self {
        Self {
            max_tokens_per_window: 100_000,
            window_secs: 300,
        }
    }
}

/// Usage record for a single agent.
#[derive(Debug, Clone)]
struct AgentUsage {
    tokens_used: u64,
    window_start: Instant,
}

/// Thread-safe token quota tracker across agents.
#[derive(Debug, Clone, Default)]
pub struct TokenQuotaTracker {
    quotas: Arc<RwLock<HashMap<String, TokenQuota>>>,
    usage: Arc<RwLock<HashMap<String, AgentUsage>>>,
}

/// Result of a quota check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaStatus {
    /// Agent is within quota.
    WithinBudget,
    /// Agent has exceeded quota and should be deprioritized.
    Exceeded {
        /// Number of tokens consumed beyond the quota limit.
        tokens_over: u64,
    },
}

impl TokenQuotaTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the token quota for an agent.
    pub fn set_quota(&self, agent_id: &str, quota: TokenQuota) {
        self.quotas
            .write()
            .unwrap()
            .insert(agent_id.to_string(), quota);
    }

    /// Record token usage for an agent.
    pub fn record_usage(&self, agent_id: &str, tokens: u64) {
        let mut usage = self.usage.write().unwrap();
        let entry = usage.entry(agent_id.to_string()).or_insert(AgentUsage {
            tokens_used: 0,
            window_start: Instant::now(),
        });

        let quotas = self.quotas.read().unwrap();
        let window_secs = quotas.get(agent_id).map(|q| q.window_secs).unwrap_or(300);

        // Reset window if expired
        if entry.window_start.elapsed().as_secs() > window_secs {
            entry.tokens_used = 0;
            entry.window_start = Instant::now();
        }

        entry.tokens_used += tokens;
    }

    /// Check if an agent is within its token quota.
    pub fn check(&self, agent_id: &str) -> QuotaStatus {
        let quotas = self.quotas.read().unwrap();
        let quota = match quotas.get(agent_id) {
            Some(q) => q,
            None => return QuotaStatus::WithinBudget,
        };

        let usage = self.usage.read().unwrap();
        let agent_usage = match usage.get(agent_id) {
            Some(u) => u,
            None => return QuotaStatus::WithinBudget,
        };

        // Check if window expired
        if agent_usage.window_start.elapsed().as_secs() > quota.window_secs {
            return QuotaStatus::WithinBudget;
        }

        if agent_usage.tokens_used > quota.max_tokens_per_window {
            QuotaStatus::Exceeded {
                tokens_over: agent_usage.tokens_used - quota.max_tokens_per_window,
            }
        } else {
            QuotaStatus::WithinBudget
        }
    }

    /// Get current usage for an agent.
    pub fn usage(&self, agent_id: &str) -> u64 {
        self.usage
            .read()
            .unwrap()
            .get(agent_id)
            .map(|u| u.tokens_used)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_quota_allows_usage() {
        let tracker = TokenQuotaTracker::new();
        assert_eq!(tracker.check("agent-1"), QuotaStatus::WithinBudget);
    }

    #[test]
    fn within_budget() {
        let tracker = TokenQuotaTracker::new();
        tracker.set_quota(
            "agent-1",
            TokenQuota {
                max_tokens_per_window: 1000,
                window_secs: 300,
            },
        );
        tracker.record_usage("agent-1", 500);
        assert_eq!(tracker.check("agent-1"), QuotaStatus::WithinBudget);
    }

    #[test]
    fn exceeds_budget() {
        let tracker = TokenQuotaTracker::new();
        tracker.set_quota(
            "agent-1",
            TokenQuota {
                max_tokens_per_window: 1000,
                window_secs: 300,
            },
        );
        tracker.record_usage("agent-1", 1200);
        assert_eq!(
            tracker.check("agent-1"),
            QuotaStatus::Exceeded { tokens_over: 200 }
        );
    }

    #[test]
    fn no_quota_always_within_budget() {
        let tracker = TokenQuotaTracker::new();
        tracker.record_usage("agent-1", 999_999);
        assert_eq!(tracker.check("agent-1"), QuotaStatus::WithinBudget);
    }

    #[test]
    fn usage_accumulates() {
        let tracker = TokenQuotaTracker::new();
        tracker.record_usage("agent-1", 100);
        tracker.record_usage("agent-1", 200);
        assert_eq!(tracker.usage("agent-1"), 300);
    }

    #[test]
    fn agents_isolated() {
        let tracker = TokenQuotaTracker::new();
        tracker.set_quota(
            "agent-1",
            TokenQuota {
                max_tokens_per_window: 100,
                window_secs: 300,
            },
        );
        tracker.record_usage("agent-1", 200);
        tracker.record_usage("agent-2", 200);

        assert_eq!(
            tracker.check("agent-1"),
            QuotaStatus::Exceeded { tokens_over: 100 }
        );
        assert_eq!(tracker.check("agent-2"), QuotaStatus::WithinBudget);
    }
}

verus! {

spec fn spec_check_quota(used: nat, max: nat) -> (bool, nat) {
    if used <= max { (true, 0) } else { (false, (used - max) as nat) }
}

proof fn quota_check_correct(used: nat, max: nat)
    ensures ({
        let (within, over) = spec_check_quota(used, max);
        (used <= max ==> within && over == 0)
        && (used > max ==> !within && over == used - max)
    }),
{}

} // verus!

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Pure quota check logic for Kani verification.
    fn check_quota(tokens_used: u64, max_tokens: u64) -> QuotaStatus {
        if tokens_used > max_tokens {
            QuotaStatus::Exceeded {
                tokens_over: tokens_used - max_tokens,
            }
        } else {
            QuotaStatus::WithinBudget
        }
    }

    #[kani::proof]
    fn quota_check_correct() {
        let used: u64 = kani::any();
        let max: u64 = kani::any();
        kani::assume(used <= 1_000_000);
        kani::assume(max <= 1_000_000);
        let status = check_quota(used, max);
        if used <= max {
            assert_eq!(status, QuotaStatus::WithinBudget);
        } else {
            match status {
                QuotaStatus::Exceeded { tokens_over } => {
                    assert_eq!(tokens_over, used - max);
                }
                _ => panic!("should be Exceeded"),
            }
        }
    }
}
