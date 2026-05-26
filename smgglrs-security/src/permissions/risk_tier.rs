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
        assert_eq!(config.classify(RiskLevelThreshold::None), RiskTier::AutoApprove);
        assert_eq!(config.classify(RiskLevelThreshold::Low), RiskTier::AutoApprove);
        assert_eq!(config.classify(RiskLevelThreshold::Medium), RiskTier::RequireApproval);
        assert_eq!(config.classify(RiskLevelThreshold::High), RiskTier::HardGate);
        assert_eq!(config.classify(RiskLevelThreshold::Critical), RiskTier::HardGate);
    }

    #[test]
    fn custom_config() {
        let config = RiskTierConfig {
            auto_approve_max: RiskLevelThreshold::Medium,
            require_approval_max: RiskLevelThreshold::High,
        };
        assert_eq!(config.classify(RiskLevelThreshold::Medium), RiskTier::AutoApprove);
        assert_eq!(config.classify(RiskLevelThreshold::High), RiskTier::RequireApproval);
        assert_eq!(config.classify(RiskLevelThreshold::Critical), RiskTier::HardGate);
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
