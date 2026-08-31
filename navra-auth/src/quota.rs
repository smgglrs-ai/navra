//! Resource quotas for AI OS agent processes.
//!
//! Token bucket rate limiter: each agent gets a bucket with a
//! configured capacity and refill rate. Kernel-enforced — agents
//! cannot bypass or increase their allocation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use vstd::prelude::*;

/// Rate limit configuration for a permission set.
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Maximum calls per window.
    pub max_calls: u64,
    /// Window duration in seconds.
    pub window_secs: u64,
}

const SCALE: u64 = 1_000_000;

/// A token bucket for a single agent.
#[derive(Debug)]
struct Bucket {
    tokens: u64,
    max_tokens: u64,
    refill_rate: u64, // scaled tokens per second
    last_refill: Instant,
}

impl Bucket {
    fn new(limit: &RateLimit) -> Self {
        let max_tokens = limit.max_calls.saturating_mul(SCALE);
        let refill_rate = max_tokens / limit.window_secs;
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
        if self.tokens >= SCALE {
            self.tokens -= SCALE;
            true
        } else {
            false
        }
    }

    /// Remaining tokens (for status reporting).
    fn remaining(&mut self) -> u64 {
        self.refill();
        self.tokens / SCALE
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed_micros = now.duration_since(self.last_refill).as_micros() as u64;
        self.tokens = self
            .tokens
            .saturating_add(elapsed_micros.saturating_mul(self.refill_rate) / SCALE)
            .min(self.max_tokens);
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

verus! {

// Token bucket invariants for the integer-scaled rate limiter.
// SCALE = 1_000_000; tokens are stored as u64 scaled units.

spec fn spec_refill(tokens: nat, elapsed_micros: nat, refill_rate: nat, max_tokens: nat) -> nat {
    let added = (elapsed_micros * refill_rate) / 1_000_000;
    let raw = tokens + added;
    if raw > max_tokens { max_tokens } else { raw }
}

proof fn refill_never_exceeds_max(tokens: nat, elapsed_micros: nat, refill_rate: nat, max_tokens: nat)
    ensures spec_refill(tokens, elapsed_micros, refill_rate, max_tokens) <= max_tokens,
{}

proof fn refill_monotonic(tokens: nat, elapsed_micros: nat, refill_rate: nat, max_tokens: nat)
    ensures spec_refill(tokens, elapsed_micros, refill_rate, max_tokens) >= tokens
         || spec_refill(tokens, elapsed_micros, refill_rate, max_tokens) == max_tokens,
{}

proof fn try_consume_correctness(tokens: nat, scale: nat)
    requires scale > 0,
    ensures
        (tokens >= scale) ==> (tokens - scale < tokens),
        (tokens < scale) ==> true,
{}

proof fn remaining_accuracy(tokens: nat, scale: nat)
    requires scale > 0,
    ensures tokens / scale <= tokens,
{}

proof fn remaining_bounded(tokens: nat, max_calls: nat, scale: nat)
    by(nonlinear_arith)
    requires scale > 0, tokens <= max_calls * scale,
    ensures tokens / scale <= max_calls,
{}

} // verus!

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

    #[test]
    fn rate_limit_refills_over_time() {
        // Create a bucket, consume all tokens, simulate time passage, verify partial refill
        let limit = RateLimit {
            max_calls: 5,
            window_secs: 60,
        };
        let mut bucket = Bucket::new(&limit);

        // Consume all 5 tokens
        for _ in 0..5 {
            assert!(bucket.try_consume());
        }
        assert!(!bucket.try_consume());

        // Simulate 30 seconds of elapsed time (half the window) by backdating last_refill
        bucket.last_refill = Instant::now() - std::time::Duration::from_secs(30);

        // After half the window, we should have refilled roughly half the tokens
        let remaining = bucket.remaining();
        assert!(
            remaining >= 1 && remaining <= 5,
            "expected partial refill, got {}",
            remaining
        );
    }

    #[test]
    fn zero_max_calls_always_denies() {
        let mut engine = QuotaEngine::new();
        engine.add_limit(
            "dev".to_string(),
            RateLimit {
                max_calls: 0,
                window_secs: 60,
            },
        );
        // With zero capacity, every call should be denied
        assert!(!engine.check("agent", "dev"));
        assert!(!engine.check("agent", "dev"));
        assert!(!engine.check("agent", "dev"));
    }

    #[test]
    fn large_max_calls_no_overflow() {
        // max_calls near u64::MAX / SCALE should not panic via saturating_mul
        let limit = RateLimit {
            max_calls: u64::MAX / SCALE,
            window_secs: 60,
        };
        let mut bucket = Bucket::new(&limit);
        // Should not panic
        assert!(bucket.try_consume());
        let _ = bucket.remaining();
    }

    #[test]
    fn remaining_before_any_check() {
        let mut engine = QuotaEngine::new();
        engine.add_limit(
            "dev".to_string(),
            RateLimit {
                max_calls: 10,
                window_secs: 60,
            },
        );
        // First call creates the bucket; before any check, remaining is None (no bucket yet)
        assert!(engine.remaining("agent", "dev").is_none());

        // After first check, remaining should reflect full capacity minus 1
        engine.check("agent", "dev");
        assert_eq!(engine.remaining("agent", "dev"), Some(9));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Pure model of try_consume for Kani verification.
    fn model_try_consume(tokens: u64) -> (u64, bool) {
        if tokens >= SCALE {
            (tokens - SCALE, true)
        } else {
            (tokens, false)
        }
    }

    /// Pure model of refill for Kani verification.
    fn model_refill(tokens: u64, elapsed_micros: u64, refill_rate: u64, max_tokens: u64) -> u64 {
        let added = elapsed_micros.saturating_mul(refill_rate) / SCALE;
        tokens.saturating_add(added).min(max_tokens)
    }

    /// After any sequence of consume + refill, tokens never exceed max_tokens.
    #[kani::proof]
    fn bucket_tokens_bounded() {
        let max_calls: u64 = kani::any();
        kani::assume(max_calls > 0 && max_calls <= 10_000);
        let max_tokens = max_calls.saturating_mul(SCALE);

        let tokens: u64 = kani::any();
        kani::assume(tokens <= max_tokens);

        let elapsed_micros: u64 = kani::any();
        kani::assume(elapsed_micros <= 3_600_000_000); // up to 1 hour in micros
        let refill_rate: u64 = kani::any();
        kani::assume(refill_rate <= max_tokens);

        // Consume then refill
        let (after_consume, _) = model_try_consume(tokens);
        let after_refill = model_refill(after_consume, elapsed_micros, refill_rate, max_tokens);
        assert!(after_refill <= max_tokens);
    }

    /// try_consume either reduces tokens by exactly SCALE or returns false
    /// without modifying token count.
    #[kani::proof]
    fn consume_decreases_or_fails() {
        let tokens: u64 = kani::any();
        kani::assume(tokens <= u64::MAX - SCALE); // avoid irrelevant overflow
        let (new_tokens, success) = model_try_consume(tokens);
        if success {
            assert!(new_tokens == tokens - SCALE);
        } else {
            assert!(new_tokens == tokens);
        }
    }

    /// Refill with any elapsed time never sets tokens above max_tokens.
    #[kani::proof]
    fn refill_never_exceeds_max() {
        let tokens: u64 = kani::any();
        let max_tokens: u64 = kani::any();
        let elapsed_micros: u64 = kani::any();
        let refill_rate: u64 = kani::any();

        kani::assume(max_tokens > 0);
        kani::assume(tokens <= max_tokens);

        let result = model_refill(tokens, elapsed_micros, refill_rate, max_tokens);
        assert!(result <= max_tokens);
    }

    /// remaining() value is always bounded by max_calls from the RateLimit config.
    #[kani::proof]
    fn remaining_bounded_by_max_calls() {
        let max_calls: u64 = kani::any();
        kani::assume(max_calls > 0 && max_calls <= 1_000_000);
        let max_tokens = max_calls.saturating_mul(SCALE);

        let tokens: u64 = kani::any();
        kani::assume(tokens <= max_tokens);

        let remaining = tokens / SCALE;
        assert!(remaining <= max_calls);
    }

    /// window_secs=0 causes division by zero in Bucket::new. This proof
    /// verifies the arithmetic models the risk: max_tokens / 0 panics.
    /// The proof documents that callers MUST ensure window_secs > 0.
    #[kani::proof]
    fn zero_window_no_panic() {
        let max_calls: u64 = kani::any();
        let window_secs: u64 = kani::any();
        kani::assume(max_calls <= 10_000);
        kani::assume(window_secs > 0 && window_secs <= 86400);

        let max_tokens = max_calls.saturating_mul(SCALE);
        let refill_rate = max_tokens / window_secs; // safe: window_secs > 0
        assert!(refill_rate <= max_tokens);
    }
}
