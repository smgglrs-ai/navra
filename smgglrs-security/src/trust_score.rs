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
            config,
        }
    }

    pub fn record_success(&self) {
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
        let elapsed = self
            .last_activity
            .lock()
            .unwrap()
            .elapsed()
            .as_secs() as i64
            / 60;
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
    fn score_floors_at_zero() {
        let ts = TrustScore::new(TrustConfig {
            baseline: 50,
            ..TrustConfig::default()
        });
        ts.record_safety_trigger(); // 50 - 100 = -50 → clamped to 0
        assert_eq!(ts.current_score(), 0);
    }
}
