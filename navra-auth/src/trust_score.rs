//! Dynamic trust scoring with time decay per session.
//!
//! Each session starts at a baseline score. Positive signals (successful
//! bounded tool calls) increase trust; negative signals (denials, safety
//! triggers) decrease it. Score decays by 1 point per minute of inactivity.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

/// Trust score for a session.
pub struct TrustScore {
    score: AtomicI64,
    last_activity: std::sync::Mutex<Instant>,
    gain_this_minute: std::sync::Mutex<(Instant, i64)>,
    config: TrustConfig,
}

/// Configuration for trust scoring.
#[derive(Debug, Clone)]
pub struct TrustConfig {
    pub baseline: i64,
    pub max_score: i64,
    pub positive_delta: i64,
    pub denial_penalty: i64,
    pub safety_penalty: i64,
    pub decay_per_minute: i64,
    pub read_only_threshold: i64,
    pub suspend_threshold: i64,
    /// Maximum positive score gain per minute (prevents trust ramp-up
    /// attacks via rapid harmless operations). 0 = unlimited.
    pub max_gain_per_minute: i64,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            baseline: 500,
            max_score: 1000,
            positive_delta: 10,
            denial_penalty: 50,
            safety_penalty: 100,
            decay_per_minute: 1,
            read_only_threshold: 300,
            suspend_threshold: 100,
            max_gain_per_minute: 50,
        }
    }
}

/// Current trust state after applying decay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    Normal,
    ReadOnly,
    Suspended,
}

impl TrustScore {
    pub fn new(config: TrustConfig) -> Self {
        let baseline = config.baseline;
        Self {
            score: AtomicI64::new(baseline),
            last_activity: std::sync::Mutex::new(Instant::now()),
            gain_this_minute: std::sync::Mutex::new((Instant::now(), 0)),
            config,
        }
    }

    pub fn record_success(&self) {
        if self.config.max_gain_per_minute > 0 {
            let mut gain = self.gain_this_minute.lock().unwrap();
            if gain.0.elapsed().as_secs() >= 60 {
                *gain = (Instant::now(), 0);
            }
            if gain.1 >= self.config.max_gain_per_minute {
                *self.last_activity.lock().unwrap() = Instant::now();
                return;
            }
            gain.1 += self.config.positive_delta;
        }

        let current = self.score.load(Ordering::Relaxed);
        let new = current
            .saturating_add(self.config.positive_delta)
            .min(self.config.max_score);
        self.score.store(new, Ordering::Relaxed);
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    pub fn record_denial(&self) {
        let current = self.score.load(Ordering::Relaxed);
        let new = current.saturating_sub(self.config.denial_penalty).max(0);
        self.score.store(new, Ordering::Relaxed);
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    pub fn record_safety_trigger(&self) {
        let current = self.score.load(Ordering::Relaxed);
        let new = current.saturating_sub(self.config.safety_penalty).max(0);
        self.score.store(new, Ordering::Relaxed);
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    pub fn current_score(&self) -> i64 {
        let raw = self.score.load(Ordering::Relaxed);
        let elapsed = self.last_activity.lock().unwrap().elapsed().as_secs() as i64 / 60;
        let decay = elapsed * self.config.decay_per_minute;
        (raw - decay).max(0)
    }

    pub fn state(&self) -> TrustState {
        let score = self.current_score();
        if score < self.config.suspend_threshold {
            TrustState::Suspended
        } else if score < self.config.read_only_threshold {
            TrustState::ReadOnly
        } else {
            TrustState::Normal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_baseline() {
        let ts = TrustScore::new(TrustConfig::default());
        assert_eq!(ts.current_score(), 500);
        assert_eq!(ts.state(), TrustState::Normal);
    }

    #[test]
    fn success_increases_score() {
        let ts = TrustScore::new(TrustConfig::default());
        ts.record_success();
        assert_eq!(ts.current_score(), 510);
    }

    #[test]
    fn denial_decreases_score() {
        let ts = TrustScore::new(TrustConfig::default());
        ts.record_denial();
        assert_eq!(ts.current_score(), 450);
    }

    #[test]
    fn safety_trigger_large_penalty() {
        let ts = TrustScore::new(TrustConfig::default());
        ts.record_safety_trigger();
        assert_eq!(ts.current_score(), 400);
    }

    #[test]
    fn multiple_triggers_cause_read_only() {
        let ts = TrustScore::new(TrustConfig::default());
        // 500 - 3*100 = 200 < 300 threshold
        ts.record_safety_trigger();
        ts.record_safety_trigger();
        ts.record_safety_trigger();
        assert_eq!(ts.state(), TrustState::ReadOnly);
    }

    #[test]
    fn severe_triggers_cause_suspension() {
        let ts = TrustScore::new(TrustConfig::default());
        // 500 - 5*100 = 0 < 100 threshold
        for _ in 0..5 {
            ts.record_safety_trigger();
        }
        assert_eq!(ts.state(), TrustState::Suspended);
    }

    #[test]
    fn score_capped_at_max() {
        let ts = TrustScore::new(TrustConfig::default());
        for _ in 0..100 {
            ts.record_success();
        }
        assert!(ts.current_score() <= 1000);
    }

    #[test]
    fn success_rate_limited_per_minute() {
        let ts = TrustScore::new(TrustConfig {
            max_gain_per_minute: 30, // 3 successes at +10 each
            ..TrustConfig::default()
        });
        for _ in 0..10 {
            ts.record_success();
        }
        // Should cap at baseline + 30, not baseline + 100
        assert!(
            ts.current_score() <= 530,
            "score {} should be <= 530 (rate limited)",
            ts.current_score()
        );
    }

    #[test]
    fn score_floors_at_zero() {
        let ts = TrustScore::new(TrustConfig {
            baseline: 50,
            ..TrustConfig::default()
        });
        ts.record_safety_trigger(); // 50 - 100 = -50 → clamped to 0
        assert_eq!(ts.current_score(), 0);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Pure trust score transition logic for Kani verification.
    /// Models record_success / record_denial / record_safety_trigger
    /// without atomics or clocks.
    fn trust_transition(score: i64, max_score: i64, delta: i64, is_penalty: bool) -> i64 {
        if is_penalty {
            score.saturating_sub(delta).max(0)
        } else {
            score.saturating_add(delta).min(max_score)
        }
    }

    /// Pure state classification for Kani verification.
    fn classify_state(score: i64, suspend: i64, read_only: i64) -> TrustState {
        if score < suspend {
            TrustState::Suspended
        } else if score < read_only {
            TrustState::ReadOnly
        } else {
            TrustState::Normal
        }
    }

    #[kani::proof]
    fn score_bounded_after_success() {
        let score: i64 = kani::any();
        let max: i64 = kani::any();
        let delta: i64 = kani::any();
        kani::assume(score >= 0 && score <= 1000);
        kani::assume(max >= 0 && max <= 1000);
        kani::assume(delta >= 0 && delta <= 100);
        let new = trust_transition(score, max, delta, false);
        assert!(new >= 0);
        assert!(new <= max);
    }

    #[kani::proof]
    fn score_bounded_after_penalty() {
        let score: i64 = kani::any();
        let delta: i64 = kani::any();
        kani::assume(score >= 0 && score <= 1000);
        kani::assume(delta >= 0 && delta <= 200);
        let new = trust_transition(score, 1000, delta, true);
        assert!(new >= 0);
        assert!(new <= 1000);
    }

    #[kani::proof]
    fn state_thresholds_monotonic() {
        let s1: i64 = kani::any();
        let s2: i64 = kani::any();
        kani::assume(s1 >= 0 && s1 <= 1000);
        kani::assume(s2 >= 0 && s2 <= 1000);
        kani::assume(s2 >= s1);
        let suspend = 100i64;
        let read_only = 300i64;
        let state1 = classify_state(s1, suspend, read_only);
        let state2 = classify_state(s2, suspend, read_only);
        let rank = |s: &TrustState| -> u8 {
            match s {
                TrustState::Suspended => 0,
                TrustState::ReadOnly => 1,
                TrustState::Normal => 2,
            }
        };
        assert!(rank(&state2) >= rank(&state1));
    }

    #[kani::proof]
    fn default_config_satisfies_invariants() {
        let c = TrustConfig::default();
        assert!(c.baseline <= c.max_score);
        assert!(c.suspend_threshold < c.read_only_threshold);
        assert!(c.suspend_threshold >= 0);
        assert!(c.read_only_threshold <= c.max_score);
        assert!(c.positive_delta >= 0);
        assert!(c.denial_penalty >= 0);
        assert!(c.safety_penalty >= 0);
        assert!(c.decay_per_minute >= 0);
    }

    #[kani::proof]
    fn all_trust_states_reachable() {
        let c = TrustConfig::default();
        let normal = classify_state(c.max_score, c.suspend_threshold, c.read_only_threshold);
        let read_only = classify_state(
            c.suspend_threshold + (c.read_only_threshold - c.suspend_threshold) / 2,
            c.suspend_threshold,
            c.read_only_threshold,
        );
        let suspended = classify_state(0, c.suspend_threshold, c.read_only_threshold);
        assert_eq!(normal, TrustState::Normal);
        assert_eq!(read_only, TrustState::ReadOnly);
        assert_eq!(suspended, TrustState::Suspended);
    }

    /// Decay multiplication overflow proof.
    /// Proves that for reasonable elapsed times (≤ 1 year in minutes)
    /// and default decay rate, no overflow occurs.
    #[kani::proof]
    fn decay_multiplication_bounded() {
        let elapsed_minutes: u32 = kani::any();
        let decay_per_min: u16 = kani::any();
        kani::assume(elapsed_minutes <= 525600); // 1 year in minutes
        kani::assume(decay_per_min <= 100);
        let decay = (elapsed_minutes as i64) * (decay_per_min as i64);
        assert!(decay >= 0);
        assert!(decay <= 52_560_000);
    }
}
