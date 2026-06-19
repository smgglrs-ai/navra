//! Execution ring model mapping trust state and risk tier to isolation level.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::permissions::risk_tier::RiskTier;
use crate::trust_score::TrustState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum ExecutionRing {
    SreWitnessed = 0,
    OpenShell = 1,
    Podman = 2,
    Direct = 3,
}

impl ExecutionRing {
    pub fn from_trust_and_risk(trust: TrustState, risk: RiskTier) -> Self {
        match (trust, risk) {
            (TrustState::Suspended, _) => ExecutionRing::OpenShell,
            (TrustState::Normal, RiskTier::HardGate) => ExecutionRing::SreWitnessed,
            (TrustState::ReadOnly, RiskTier::HardGate) => ExecutionRing::SreWitnessed,
            (TrustState::Normal, RiskTier::RequireApproval) => ExecutionRing::Podman,
            (TrustState::ReadOnly, RiskTier::RequireApproval) => ExecutionRing::OpenShell,
            (TrustState::Normal, RiskTier::AutoApprove) => ExecutionRing::Direct,
            (TrustState::ReadOnly, RiskTier::AutoApprove) => ExecutionRing::Direct,
        }
    }

    pub fn from_capability_ring(ring: u8) -> Self {
        match ring {
            0 => ExecutionRing::SreWitnessed,
            1 => ExecutionRing::OpenShell,
            2 => ExecutionRing::Podman,
            _ => ExecutionRing::Direct,
        }
    }

    pub fn effective(cap_ring: Option<Self>, trust_ring: Self) -> Self {
        match cap_ring {
            Some(c) => c.min(trust_ring),
            None => trust_ring,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for ExecutionRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (n, name) = match self {
            ExecutionRing::SreWitnessed => (0, "SreWitnessed"),
            ExecutionRing::OpenShell => (1, "OpenShell"),
            ExecutionRing::Podman => (2, "Podman"),
            ExecutionRing::Direct => (3, "Direct"),
        };
        write!(f, "Ring {n} ({name})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_risk_matrix_suspended() {
        assert_eq!(
            ExecutionRing::from_trust_and_risk(TrustState::Suspended, RiskTier::AutoApprove),
            ExecutionRing::OpenShell
        );
        assert_eq!(
            ExecutionRing::from_trust_and_risk(TrustState::Suspended, RiskTier::RequireApproval),
            ExecutionRing::OpenShell
        );
        assert_eq!(
            ExecutionRing::from_trust_and_risk(TrustState::Suspended, RiskTier::HardGate),
            ExecutionRing::OpenShell
        );
    }

    #[test]
    fn trust_risk_matrix_normal() {
        assert_eq!(
            ExecutionRing::from_trust_and_risk(TrustState::Normal, RiskTier::AutoApprove),
            ExecutionRing::Direct
        );
        assert_eq!(
            ExecutionRing::from_trust_and_risk(TrustState::Normal, RiskTier::RequireApproval),
            ExecutionRing::Podman
        );
        assert_eq!(
            ExecutionRing::from_trust_and_risk(TrustState::Normal, RiskTier::HardGate),
            ExecutionRing::SreWitnessed
        );
    }

    #[test]
    fn trust_risk_matrix_read_only() {
        assert_eq!(
            ExecutionRing::from_trust_and_risk(TrustState::ReadOnly, RiskTier::AutoApprove),
            ExecutionRing::Direct
        );
        assert_eq!(
            ExecutionRing::from_trust_and_risk(TrustState::ReadOnly, RiskTier::RequireApproval),
            ExecutionRing::OpenShell
        );
        assert_eq!(
            ExecutionRing::from_trust_and_risk(TrustState::ReadOnly, RiskTier::HardGate),
            ExecutionRing::SreWitnessed
        );
    }

    #[test]
    fn from_capability_ring_known_values() {
        assert_eq!(
            ExecutionRing::from_capability_ring(0),
            ExecutionRing::SreWitnessed
        );
        assert_eq!(
            ExecutionRing::from_capability_ring(1),
            ExecutionRing::OpenShell
        );
        assert_eq!(
            ExecutionRing::from_capability_ring(2),
            ExecutionRing::Podman
        );
        assert_eq!(
            ExecutionRing::from_capability_ring(3),
            ExecutionRing::Direct
        );
    }

    #[test]
    fn from_capability_ring_overflow() {
        assert_eq!(
            ExecutionRing::from_capability_ring(255),
            ExecutionRing::Direct
        );
    }

    #[test]
    fn effective_returns_min() {
        assert_eq!(
            ExecutionRing::effective(Some(ExecutionRing::Podman), ExecutionRing::Direct),
            ExecutionRing::Podman
        );
        assert_eq!(
            ExecutionRing::effective(Some(ExecutionRing::Direct), ExecutionRing::OpenShell),
            ExecutionRing::OpenShell
        );
        assert_eq!(
            ExecutionRing::effective(
                Some(ExecutionRing::SreWitnessed),
                ExecutionRing::SreWitnessed
            ),
            ExecutionRing::SreWitnessed
        );
    }

    #[test]
    fn effective_none_returns_trust_ring() {
        assert_eq!(
            ExecutionRing::effective(None, ExecutionRing::Podman),
            ExecutionRing::Podman
        );
    }

    #[test]
    fn ordering() {
        assert!(ExecutionRing::SreWitnessed < ExecutionRing::OpenShell);
        assert!(ExecutionRing::OpenShell < ExecutionRing::Podman);
        assert!(ExecutionRing::Podman < ExecutionRing::Direct);
    }

    #[test]
    fn display_formatting() {
        assert_eq!(
            ExecutionRing::SreWitnessed.to_string(),
            "Ring 0 (SreWitnessed)"
        );
        assert_eq!(ExecutionRing::OpenShell.to_string(), "Ring 1 (OpenShell)");
        assert_eq!(ExecutionRing::Podman.to_string(), "Ring 2 (Podman)");
        assert_eq!(ExecutionRing::Direct.to_string(), "Ring 3 (Direct)");
    }

    #[test]
    fn as_u8_values() {
        assert_eq!(ExecutionRing::SreWitnessed.as_u8(), 0);
        assert_eq!(ExecutionRing::OpenShell.as_u8(), 1);
        assert_eq!(ExecutionRing::Podman.as_u8(), 2);
        assert_eq!(ExecutionRing::Direct.as_u8(), 3);
    }

    #[test]
    fn serde_roundtrip() {
        for ring in [
            ExecutionRing::SreWitnessed,
            ExecutionRing::OpenShell,
            ExecutionRing::Podman,
            ExecutionRing::Direct,
        ] {
            let json = serde_json::to_string(&ring).unwrap();
            let back: ExecutionRing = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ring);
        }
    }
}
