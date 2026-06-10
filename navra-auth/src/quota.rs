//! Resource quotas for AI OS agent processes.
//!
//! Token bucket rate limiter: each agent gets a bucket with a
//! configured capacity and refill rate. Kernel-enforced — agents
//! cannot bypass or increase their allocation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Rate limit configuration for a permission set.
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Maximum calls per window.
    pub max_calls: u64,
    /// Window duration in seconds.
    pub window_secs: u64,
}

/// A token bucket for a single agent.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl Bucket {
    fn new(limit: &RateLimit) -> Self {
        let max_tokens = limit.max_calls as f64;
        let refill_rate = max_tokens / limit.window_secs as f64;
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed.
    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Remaining tokens (for status reporting).
    fn remaining(&mut self) -> u64 {
        self.refill();
        self.tokens as u64
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }
}

/// Quota engine enforcing rate limits per agent.
#[derive(Debug, Clone, Default)]
pub struct QuotaEngine {
    /// Rate limits keyed by permission set name.
    limits: HashMap<String, RateLimit>,
    /// Active buckets keyed by agent name.
    buckets: Arc<RwLock<HashMap<String, Bucket>>>,
}

impl QuotaEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a rate limit for a permission set.
    pub fn add_limit(&mut self, permission_set: String, limit: RateLimit) {
        self.limits.insert(permission_set, limit);
    }

    /// Check if an agent is within its rate limit. Returns true if allowed.
    /// Creates a bucket on first call for the agent.
    pub fn check(&self, agent_name: &str, permission_set: &str) -> bool {
        let limit = match self.limits.get(permission_set) {
            Some(l) => l,
            None => return true, // no limit configured
        };

        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets
            .entry(agent_name.to_string())
            .or_insert_with(|| Bucket::new(limit));
        bucket.try_consume()
    }

    /// Get remaining quota for an agent.
    pub fn remaining(&self, agent_name: &str, permission_set: &str) -> Option<u64> {
        if !self.limits.contains_key(permission_set) {
            return None; // unlimited
        }
        let mut buckets = self.buckets.write().unwrap();
        buckets.get_mut(agent_name).map(|b| b.remaining())
    }

    /// Whether any rate limits are configured.
    pub fn has_limits(&self) -> bool {
        !self.limits.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_limit_always_allows() {
        let engine = QuotaEngine::new();
        assert!(engine.check("agent", "dev"));
        assert!(engine.check("agent", "dev"));
    }

    #[test]
    fn limit_allows_up_to_max() {
        let mut engine = QuotaEngine::new();
        engine.add_limit(
            "dev".to_string(),
            RateLimit {
                max_calls: 3,
                window_secs: 60,
            },
        );

        assert!(engine.check("agent", "dev"));
        assert!(engine.check("agent", "dev"));
        assert!(engine.check("agent", "dev"));
        // 4th call exceeds limit
        assert!(!engine.check("agent", "dev"));
    }

    #[test]
    fn different_agents_have_separate_buckets() {
        let mut engine = QuotaEngine::new();
        engine.add_limit(
            "dev".to_string(),
            RateLimit {
                max_calls: 2,
                window_secs: 60,
            },
        );

        assert!(engine.check("alice", "dev"));
        assert!(engine.check("alice", "dev"));
        assert!(!engine.check("alice", "dev"));

        // Bob has his own bucket
        assert!(engine.check("bob", "dev"));
        assert!(engine.check("bob", "dev"));
        assert!(!engine.check("bob", "dev"));
    }

    #[test]
    fn unconfigured_permission_set_unlimited() {
        let mut engine = QuotaEngine::new();
        engine.add_limit(
            "limited".to_string(),
            RateLimit {
                max_calls: 1,
                window_secs: 60,
            },
        );

        // "dev" has no limit
        assert!(engine.check("agent", "dev"));
        assert!(engine.check("agent", "dev"));
        assert!(engine.check("agent", "dev"));
    }

    #[test]
    fn remaining_reports_tokens() {
        let mut engine = QuotaEngine::new();
        engine.add_limit(
            "dev".to_string(),
            RateLimit {
                max_calls: 10,
                window_secs: 60,
            },
        );

        assert!(engine.check("agent", "dev")); // consume 1
        let remaining = engine.remaining("agent", "dev").unwrap();
        assert_eq!(remaining, 9);
    }

    #[test]
    fn remaining_none_for_unlimited() {
        let engine = QuotaEngine::new();
        assert_eq!(engine.remaining("agent", "dev"), None);
    }

    #[test]
    fn has_limits() {
        let mut engine = QuotaEngine::new();
        assert!(!engine.has_limits());
        engine.add_limit(
            "dev".to_string(),
            RateLimit {
                max_calls: 10,
                window_secs: 60,
            },
        );
        assert!(engine.has_limits());
    }
}
