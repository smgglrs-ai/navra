//! Cryptographic witness for IFC declassification events.
//!
//! Every `declassify()` call produces a `DeclassificationWitness` that
//! records the label transition, authority, justification, and an
//! Ed25519 signature over a deterministic CBOR encoding (RFC 7049 §3.9).

use serde::{Deserialize, Serialize};

use crate::identity::CapSigner;
use crate::ifc::DataLabel;

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

/// Canonical payload struct with fields in alphabetical order.
/// CBOR struct serialization preserves field declaration order,
/// so alphabetical declaration = deterministic encoding.
#[derive(Serialize)]
struct CanonicalPayload<'a> {
    declassifier: &'a str,
    justification: &'a str,
    new_label: &'a DataLabel,
    original_label: &'a DataLabel,
    timestamp: i64,
}

impl DeclassificationWitness {
    /// Deterministic CBOR payload for signing (excludes the signature field).
    fn canonical_payload(&self) -> Vec<u8> {
        let payload = CanonicalPayload {
            declassifier: &self.declassifier,
            justification: &self.justification,
            new_label: &self.new_label,
            original_label: &self.original_label,
            timestamp: self.timestamp,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).expect("CBOR serialization");
        buf
    }

    /// Legacy JSON payload for backward-compatible verification.
    fn legacy_json_payload(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "original_label": self.original_label,
            "new_label": self.new_label,
            "declassifier": self.declassifier,
            "timestamp": self.timestamp,
            "justification": self.justification,
        });
        serde_json::to_vec(&canonical).expect("JSON serialization")
    }

    /// Sign this witness with the given signer.
    ///
    /// Serializes the non-signature fields to deterministic CBOR and
    /// signs the resulting bytes. Replaces any existing signature.
    pub fn sign(&mut self, signer: &dyn CapSigner) {
        let payload = self.canonical_payload();
        self.signature = Some(signer.sign(&payload));
    }

    /// Verify the witness signature against the given signer's public key.
    ///
    /// Tries CBOR canonical encoding first, falls back to legacy JSON
    /// for backward compatibility with pre-CBOR witnesses.
    /// Returns `false` if unsigned or if the signature does not match.
    pub fn verify(&self, signer: &dyn CapSigner) -> bool {
        let Some(ref sig) = self.signature else {
            return false;
        };
        let cbor_payload = self.canonical_payload();
        if signer.verify(&cbor_payload, sig) {
            return true;
        }
        let json_payload = self.legacy_json_payload();
        signer.verify(&json_payload, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Ed25519Signer;
    use navra_protocol::label::{Confidentiality, Integrity};

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

    #[test]
    fn legacy_json_signed_witness_still_verifies() {
        let signer = Ed25519Signer::generate();
        let mut witness = sample_witness();
        // Sign with legacy JSON encoding
        let payload = witness.legacy_json_payload();
        witness.signature = Some(signer.sign(&payload));
        // verify() should fall back to JSON and succeed
        assert!(witness.verify(&signer));
    }

    #[test]
    fn canonical_payload_is_deterministic() {
        let witness = sample_witness();
        let p1 = witness.canonical_payload();
        let p2 = witness.canonical_payload();
        assert_eq!(p1, p2, "canonical encoding must be deterministic");
    }
}
