//! Risk-tiered approval: graduated access control based on action risk level.
//!
//! Upgrades binary allow/deny to three tiers:
//! - Read-only (None/Low risk) → auto-approve, log only
//! - Write (Medium risk) → require approval
//! - Irreversible (High/Critical risk) → hard gate with explicit confirmation

use serde::{Deserialize, Serialize};

/// Risk tier for an action, determined by the action's risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    AutoApprove,
    RequireApproval,
    HardGate,
}

/// Configuration for risk-tiered approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskTierConfig {
    pub auto_approve_max: RiskLevelThreshold,
    pub require_approval_max: RiskLevelThreshold,
}

/// Threshold expressed as a risk level name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevelThreshold {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for RiskTierConfig {
    fn default() -> Self {
        Self {
            auto_approve_max: RiskLevelThreshold::Low,
            require_approval_max: RiskLevelThreshold::Medium,
        }
    }
}

impl RiskTierConfig {
    pub fn is_valid(&self) -> bool {
        self.auto_approve_max <= self.require_approval_max
    }

    pub fn classify(&self, risk_level: RiskLevelThreshold) -> RiskTier {
        if risk_level <= self.auto_approve_max {
            RiskTier::AutoApprove
        } else if risk_level <= self.require_approval_max {
            RiskTier::RequireApproval
        } else {
            RiskTier::HardGate
        }
    }
}

impl PartialOrd for RiskLevelThreshold {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskLevelThreshold {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn rank(r: &RiskLevelThreshold) -> u8 {
            match r {
                RiskLevelThreshold::None => 0,
                RiskLevelThreshold::Low => 1,
                RiskLevelThreshold::Medium => 2,
                RiskLevelThreshold::High => 3,
                RiskLevelThreshold::Critical => 4,
            }
        }
        rank(self).cmp(&rank(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_tiers() {
        let config = RiskTierConfig::default();
        assert_eq!(
            config.classify(RiskLevelThreshold::None),
            RiskTier::AutoApprove
        );
        assert_eq!(
            config.classify(RiskLevelThreshold::Low),
            RiskTier::AutoApprove
        );
        assert_eq!(
            config.classify(RiskLevelThreshold::Medium),
            RiskTier::RequireApproval
        );
        assert_eq!(
            config.classify(RiskLevelThreshold::High),
            RiskTier::HardGate
        );
        assert_eq!(
            config.classify(RiskLevelThreshold::Critical),
            RiskTier::HardGate
        );
    }

    #[test]
    fn custom_config() {
        let config = RiskTierConfig {
            auto_approve_max: RiskLevelThreshold::Medium,
            require_approval_max: RiskLevelThreshold::High,
        };
        assert_eq!(
            config.classify(RiskLevelThreshold::Medium),
            RiskTier::AutoApprove
        );
        assert_eq!(
            config.classify(RiskLevelThreshold::High),
            RiskTier::RequireApproval
        );
        assert_eq!(
            config.classify(RiskLevelThreshold::Critical),
            RiskTier::HardGate
        );
    }

    #[test]
    fn risk_level_ordering() {
        assert!(RiskLevelThreshold::None < RiskLevelThreshold::Low);
        assert!(RiskLevelThreshold::Low < RiskLevelThreshold::Medium);
        assert!(RiskLevelThreshold::Medium < RiskLevelThreshold::High);
        assert!(RiskLevelThreshold::High < RiskLevelThreshold::Critical);
    }

    #[test]
    fn serialization_roundtrip() {
        let config = RiskTierConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: RiskTierConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.auto_approve_max, RiskLevelThreshold::Low);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    impl kani::Arbitrary for RiskLevelThreshold {
        fn any_array<const N: usize>() -> [Self; N] {
            [Self::None; N]
        }

        fn any() -> Self {
            match kani::any::<u8>() % 5 {
                0 => RiskLevelThreshold::None,
                1 => RiskLevelThreshold::Low,
                2 => RiskLevelThreshold::Medium,
                3 => RiskLevelThreshold::High,
                _ => RiskLevelThreshold::Critical,
            }
        }
    }

    #[kani::proof]
    fn rank_is_total_order() {
        let a: RiskLevelThreshold = kani::any();
        let b: RiskLevelThreshold = kani::any();
        let c: RiskLevelThreshold = kani::any();
        // Transitivity: a <= b && b <= c => a <= c
        if a <= b && b <= c {
            assert!(a <= c);
        }
    }

    #[kani::proof]
    fn classify_monotonic() {
        let auto_max: RiskLevelThreshold = kani::any();
        let approval_max: RiskLevelThreshold = kani::any();
        kani::assume(auto_max <= approval_max);
        let config = RiskTierConfig {
            auto_approve_max: auto_max,
            require_approval_max: approval_max,
        };

        let r1: RiskLevelThreshold = kani::any();
        let r2: RiskLevelThreshold = kani::any();
        kani::assume(r1 <= r2);
        let t1 = config.classify(r1);
        let t2 = config.classify(r2);
        // Higher risk level never gets a less restrictive tier
        let tier_rank = |t: &RiskTier| -> u8 {
            match t {
                RiskTier::AutoApprove => 0,
                RiskTier::RequireApproval => 1,
                RiskTier::HardGate => 2,
            }
        };
        assert!(tier_rank(&t2) >= tier_rank(&t1));
    }

    #[kani::proof]
    fn valid_config_auto_below_approval() {
        let auto_max: RiskLevelThreshold = kani::any();
        let approval_max: RiskLevelThreshold = kani::any();
        let config = RiskTierConfig {
            auto_approve_max: auto_max,
            require_approval_max: approval_max,
        };
        assert_eq!(config.is_valid(), auto_max <= approval_max);
    }

    #[kani::proof]
    fn default_config_is_valid() {
        assert!(RiskTierConfig::default().is_valid());
    }

    #[kani::proof]
    fn classify_safe_even_if_invalid() {
        let auto_max: RiskLevelThreshold = kani::any();
        let approval_max: RiskLevelThreshold = kani::any();
        let risk: RiskLevelThreshold = kani::any();
        let config = RiskTierConfig {
            auto_approve_max: auto_max,
            require_approval_max: approval_max,
        };
        // classify() never panics regardless of config validity
        let _tier = config.classify(risk);
    }

    #[kani::proof]
    fn all_trust_states_reachable() {
        // Prove every TrustState variant can be produced by classify
        let config = RiskTierConfig::default();
        let auto = config.classify(RiskLevelThreshold::None);
        let approval = config.classify(RiskLevelThreshold::Medium);
        let gate = config.classify(RiskLevelThreshold::Critical);
        assert!(matches!(auto, RiskTier::AutoApprove));
        assert!(matches!(approval, RiskTier::RequireApproval));
        assert!(matches!(gate, RiskTier::HardGate));
    }
}
