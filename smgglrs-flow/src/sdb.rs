//! Stochastic-Deterministic Boundary (SDB) formalization.
//!
//! Makes the boundary between LLM output (stochastic) and tool
//! execution (deterministic) a first-class architectural primitive.
//! Each DAG node transition has a four-part contract.

use serde::{Deserialize, Serialize};

/// The four-part SDB contract for a DAG node transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdbContract {
    pub proposer: ProposerType,
    pub verifier: VerifierType,
    pub commit_on: CommitCondition,
    pub reject_action: RejectAction,
}

/// What generates the action plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposerType {
    Llm,
    Deterministic,
}

/// How the proposal is validated before commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierType {
    None,
    SchemaCheck { schema_name: String },
    MandateValidator,
    SafetyHook,
    MinConfidence { threshold: f32 },
}

/// When the proposal becomes an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitCondition {
    Immediate,
    AfterVerification,
    AfterApproval,
}

/// What happens when verification fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectAction {
    Retry { max_attempts: u32 },
    Escalate,
    Abort,
    Skip,
}

impl Default for SdbContract {
    fn default() -> Self {
        Self {
            proposer: ProposerType::Llm,
            verifier: VerifierType::MandateValidator,
            commit_on: CommitCondition::AfterVerification,
            reject_action: RejectAction::Retry { max_attempts: 2 },
        }
    }
}

/// Validate a proposal against an SDB contract.
///
/// Returns true if the proposal passes the verifier, false if it
/// should be rejected.
pub fn validate_proposal(
    contract: &SdbContract,
    output: &str,
    validation_score: f32,
) -> bool {
    match &contract.verifier {
        VerifierType::None => true,
        VerifierType::MandateValidator => validation_score >= 50.0,
        VerifierType::MinConfidence { threshold } => validation_score >= *threshold,
        VerifierType::SchemaCheck { schema_name: _ } => {
            serde_json::from_str::<serde_json::Value>(output).is_ok()
        }
        VerifierType::SafetyHook => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_contract() {
        let c = SdbContract::default();
        assert!(matches!(c.proposer, ProposerType::Llm));
        assert!(matches!(c.verifier, VerifierType::MandateValidator));
        assert!(matches!(c.commit_on, CommitCondition::AfterVerification));
    }

    #[test]
    fn mandate_validator_passes_above_50() {
        let c = SdbContract::default();
        assert!(validate_proposal(&c, "output", 75.0));
        assert!(!validate_proposal(&c, "output", 30.0));
    }

    #[test]
    fn min_confidence_threshold() {
        let c = SdbContract {
            verifier: VerifierType::MinConfidence { threshold: 0.7 },
            ..Default::default()
        };
        assert!(validate_proposal(&c, "", 0.8));
        assert!(!validate_proposal(&c, "", 0.5));
    }

    #[test]
    fn schema_check_validates_json() {
        let c = SdbContract {
            verifier: VerifierType::SchemaCheck {
                schema_name: "test".into(),
            },
            ..Default::default()
        };
        assert!(validate_proposal(&c, r#"{"key": "value"}"#, 0.0));
        assert!(!validate_proposal(&c, "not json", 0.0));
    }

    #[test]
    fn none_verifier_always_passes() {
        let c = SdbContract {
            verifier: VerifierType::None,
            ..Default::default()
        };
        assert!(validate_proposal(&c, "", 0.0));
    }

    #[test]
    fn serialization_roundtrip() {
        let c = SdbContract::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: SdbContract = serde_json::from_str(&json).unwrap();
        assert!(matches!(back.reject_action, RejectAction::Retry { max_attempts: 2 }));
    }
}
