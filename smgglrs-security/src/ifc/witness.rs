//! Cryptographic witness for IFC declassification events.
//!
//! Every `declassify()` call produces a `DeclassificationWitness` that
//! records the label transition, authority, justification, and an
//! optional Ed25519 signature over the canonical JSON encoding.

use serde::{Deserialize, Serialize};

use crate::ifc::DataLabel;
use crate::identity::CapSigner;

/// Immutable record of a declassification event.
///
/// The witness captures the before/after labels, the authority that
/// performed the downgrade, a human-readable justification, and an
/// optional cryptographic signature for non-repudiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclassificationWitness {
    pub original_label: DataLabel,
    pub new_label: DataLabel,
    pub declassifier: String,
    pub timestamp: i64,
    pub justification: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

impl DeclassificationWitness {
    /// Canonical JSON payload for signing (excludes the signature field).
    fn canonical_payload(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "original_label": self.original_label,
            "new_label": self.new_label,
            "declassifier": self.declassifier,
            "timestamp": self.timestamp,
            "justification": self.justification,
        });
        serde_json::to_vec(&canonical).expect("canonical JSON serialization")
    }

    /// Sign this witness with the given signer.
    ///
    /// Serializes the non-signature fields to canonical JSON and signs
    /// the resulting bytes. Replaces any existing signature.
    pub fn sign(&mut self, signer: &dyn CapSigner) {
        let payload = self.canonical_payload();
        self.signature = Some(signer.sign(&payload));
    }

    /// Verify the witness signature against the given signer's public key.
    ///
    /// Returns `false` if unsigned or if the signature does not match.
    pub fn verify(&self, signer: &dyn CapSigner) -> bool {
        let Some(ref sig) = self.signature else {
            return false;
        };
        let payload = self.canonical_payload();
        signer.verify(&payload, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Ed25519Signer;
    use smgglrs_protocol::label::{Confidentiality, Integrity};

    fn sample_witness() -> DeclassificationWitness {
        DeclassificationWitness {
            original_label: DataLabel {
                integrity: Integrity::Trusted,
                confidentiality: Confidentiality::Pii,
            },
            new_label: DataLabel {
                integrity: Integrity::Trusted,
                confidentiality: Confidentiality::Public,
            },
            declassifier: "pii-filter".to_string(),
            timestamp: 1716900000,
            justification: "full PII redaction complete".to_string(),
            signature: None,
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate();
        let mut witness = sample_witness();
        witness.sign(&signer);
        assert!(witness.signature.is_some());
        assert!(witness.verify(&signer));
    }

    #[test]
    fn wrong_key_rejects() {
        let signer1 = Ed25519Signer::generate();
        let signer2 = Ed25519Signer::generate();
        let mut witness = sample_witness();
        witness.sign(&signer1);
        assert!(!witness.verify(&signer2));
    }

    #[test]
    fn unsigned_verify_returns_false() {
        let signer = Ed25519Signer::generate();
        let witness = sample_witness();
        assert!(!witness.verify(&signer));
    }

    #[test]
    fn tampered_witness_fails() {
        let signer = Ed25519Signer::generate();
        let mut witness = sample_witness();
        witness.sign(&signer);
        witness.justification = "tampered justification".to_string();
        assert!(!witness.verify(&signer));
    }
}
