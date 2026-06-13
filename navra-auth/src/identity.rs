//! Cryptographic identity for navra agents and the server itself.
//!
//! Provides DID:key generation from Ed25519 public keys, algorithm-agile
//! signing via the [`CapSigner`] trait, and keypair lifecycle management.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::path::Path;

/// Multicodec prefix for Ed25519 public keys.
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid DID format: {0}")]
    InvalidDid(String),
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("unsupported multicodec: 0x{0:02x}{1:02x} (expected Ed25519 0xed01)")]
    UnsupportedCodec(u8, u8),
    #[error(transparent)]
    Crypto(#[from] ed25519_dalek::SignatureError),
    #[error(transparent)]
    Bs58(#[from] bs58::decode::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[cfg(feature = "desktop")]
    #[error(transparent)]
    Keyring(#[from] keyring::Error),
}

/// Algorithm-agile signer/verifier for capability tokens.
///
/// Implementations hide the specific key type (Ed25519 today,
/// hybrid Ed25519+ML-DSA in the future).
pub trait CapSigner: Send + Sync {
    /// Algorithm identifier: "ed25519", "ml-dsa-65", "hybrid".
    fn algorithm(&self) -> &str;

    /// DID:key identifier derived from the public key.
    fn did(&self) -> &str;

    /// Sign a payload, returning the raw signature bytes.
    fn sign(&self, payload: &[u8]) -> Vec<u8>;

    /// Verify a signature over a payload.
    fn verify(&self, payload: &[u8], sig: &[u8]) -> bool;

    /// Raw public key bytes (for embedding in AID records).
    fn public_key_bytes(&self) -> Vec<u8>;
}

/// Ed25519 implementation of [`CapSigner`].
pub struct Ed25519Signer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    did: String,
}

impl Ed25519Signer {
    /// Create from an existing 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        let did = did_from_pubkey(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            did,
        }
    }

    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let did = did_from_pubkey(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            did,
        }
    }

    /// Return the 32-byte seed for storage.
    pub fn seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl CapSigner for Ed25519Signer {
    fn algorithm(&self) -> &str {
        "ed25519"
    }

    fn did(&self) -> &str {
        &self.did
    }

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.signing_key.sign(payload).to_bytes().to_vec()
    }

    fn verify(&self, payload: &[u8], sig: &[u8]) -> bool {
        let Ok(sig_bytes): Result<[u8; 64], _> = sig.try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_bytes);
        self.verifying_key.verify(payload, &sig).is_ok()
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
}

/// Verifier-only: verify signatures from a known public key.
pub struct Ed25519Verifier {
    verifying_key: VerifyingKey,
    did: String,
}

impl Ed25519Verifier {
    /// Create from a DID:key string.
    pub fn from_did(did: &str) -> Result<Self, IdentityError> {
        let verifying_key = pubkey_from_did(did)?;
        Ok(Self {
            verifying_key,
            did: did.to_string(),
        })
    }

    /// Create from raw 32-byte public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        let verifying_key = VerifyingKey::from_bytes(bytes)?;
        let did = did_from_pubkey(&verifying_key);
        Ok(Self { verifying_key, did })
    }

    /// Verify a signature over a payload.
    pub fn verify(&self, payload: &[u8], sig: &[u8]) -> bool {
        let Ok(sig_bytes): Result<[u8; 64], _> = sig.try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_bytes);
        self.verifying_key.verify(payload, &sig).is_ok()
    }

    pub fn did(&self) -> &str {
        &self.did
    }
}

/// Blanket `CapSigner` impl for `Arc<T>` where T: CapSigner.
/// Enables sharing a signer between the authenticator and tool handlers.
impl<T: CapSigner> CapSigner for std::sync::Arc<T> {
    fn algorithm(&self) -> &str {
        (**self).algorithm()
    }
    fn did(&self) -> &str {
        (**self).did()
    }
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        (**self).sign(payload)
    }
    fn verify(&self, payload: &[u8], sig: &[u8]) -> bool {
        (**self).verify(payload, sig)
    }
    fn public_key_bytes(&self) -> Vec<u8> {
        (**self).public_key_bytes()
    }
}

// --- DID:key encoding/decoding ---

/// Derive a `did:key:z6Mk...` from an Ed25519 public key.
///
/// Format: `did:key:` + multibase('z' = base58btc) of
/// multicodec(0xed01) + 32-byte public key.
pub fn did_from_pubkey(pubkey: &VerifyingKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&ED25519_MULTICODEC);
    bytes.extend_from_slice(pubkey.as_bytes());
    format!("did:key:z{}", bs58::encode(&bytes).into_string())
}

/// Extract an Ed25519 public key from a `did:key:z6Mk...` string.
pub fn pubkey_from_did(did: &str) -> Result<VerifyingKey, IdentityError> {
    let multibase = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| IdentityError::InvalidDid(did.to_string()))?;

    let decoded = bs58::decode(multibase).into_vec()?;

    if decoded.len() != 34 {
        return Err(IdentityError::InvalidKeyLength {
            expected: 34,
            actual: decoded.len(),
        });
    }
    if decoded[0] != ED25519_MULTICODEC[0] || decoded[1] != ED25519_MULTICODEC[1] {
        return Err(IdentityError::UnsupportedCodec(decoded[0], decoded[1]));
    }

    let key_bytes: [u8; 32] =
        decoded[2..34]
            .try_into()
            .map_err(|_| IdentityError::InvalidKeyLength {
                expected: 32,
                actual: decoded.len() - 2,
            })?;
    Ok(VerifyingKey::from_bytes(&key_bytes)?)
}

/// Load identity seed from a file, or generate and save if absent.
pub fn load_or_create_file_identity(path: &Path) -> Result<Ed25519Signer, IdentityError> {
    if path.exists() {
        let seed_bytes = std::fs::read(path)?;
        if seed_bytes.len() != 32 {
            return Err(IdentityError::InvalidKeyLength {
                expected: 32,
                actual: seed_bytes.len(),
            });
        }
        let seed: [u8; 32] =
            seed_bytes
                .try_into()
                .map_err(|_| IdentityError::InvalidKeyLength {
                    expected: 32,
                    actual: 0,
                })?;
        Ok(Ed25519Signer::from_seed(&seed))
    } else {
        let signer = Ed25519Signer::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, signer.seed())?;
        // Best-effort: restrict permissions to owner-only on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(signer)
    }
}

#[cfg(feature = "desktop")]
/// Load identity seed from OS keyring, or generate and store if absent.
pub fn load_or_create_keyring_identity() -> Result<Ed25519Signer, IdentityError> {
    let entry = keyring::Entry::new("navra", "root-identity")?;

    match entry.get_secret() {
        Ok(seed_bytes) => {
            if seed_bytes.len() != 32 {
                return Err(IdentityError::InvalidKeyLength {
                    expected: 32,
                    actual: seed_bytes.len(),
                });
            }
            let seed: [u8; 32] =
                seed_bytes
                    .try_into()
                    .map_err(|_| IdentityError::InvalidKeyLength {
                        expected: 32,
                        actual: 0,
                    })?;
            Ok(Ed25519Signer::from_seed(&seed))
        }
        Err(keyring::Error::NoEntry) => {
            let signer = Ed25519Signer::generate();
            entry.set_secret(&signer.seed())?;
            Ok(signer)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign_verify() {
        let signer = Ed25519Signer::generate();
        let payload = b"hello navra";
        let sig = signer.sign(payload);
        assert!(signer.verify(payload, &sig));
    }

    #[test]
    fn tampered_payload_fails() {
        let signer = Ed25519Signer::generate();
        let sig = signer.sign(b"original");
        assert!(!signer.verify(b"tampered", &sig));
    }

    #[test]
    fn tampered_signature_fails() {
        let signer = Ed25519Signer::generate();
        let mut sig = signer.sign(b"payload");
        sig[0] ^= 0xff;
        assert!(!signer.verify(b"payload", &sig));
    }

    #[test]
    fn wrong_length_signature_fails() {
        let signer = Ed25519Signer::generate();
        assert!(!signer.verify(b"payload", &[0u8; 10]));
    }

    #[test]
    fn did_roundtrip() {
        let signer = Ed25519Signer::generate();
        let did = signer.did();
        assert!(did.starts_with("did:key:z6Mk"));

        let recovered = pubkey_from_did(did).unwrap();
        assert_eq!(recovered.as_bytes(), signer.verifying_key.as_bytes());
    }

    #[test]
    fn did_from_seed_is_deterministic() {
        let seed = [42u8; 32];
        let signer1 = Ed25519Signer::from_seed(&seed);
        let signer2 = Ed25519Signer::from_seed(&seed);
        assert_eq!(signer1.did(), signer2.did());
    }

    #[test]
    fn pubkey_from_invalid_did_fails() {
        assert!(pubkey_from_did("not-a-did").is_err());
        assert!(pubkey_from_did("did:key:z123").is_err());
        assert!(pubkey_from_did("did:key:zabc").is_err());
    }

    #[test]
    fn verifier_from_did() {
        let signer = Ed25519Signer::generate();
        let verifier = Ed25519Verifier::from_did(signer.did()).unwrap();

        let payload = b"test message";
        let sig = signer.sign(payload);
        assert!(verifier.verify(payload, &sig));
        assert!(!verifier.verify(b"wrong", &sig));
    }

    #[test]
    fn file_identity_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-identity.key");

        let signer1 = load_or_create_file_identity(&path).unwrap();
        let signer2 = load_or_create_file_identity(&path).unwrap();

        assert_eq!(signer1.did(), signer2.did());
        assert_eq!(signer1.seed(), signer2.seed());
    }

    #[test]
    fn algorithm_is_ed25519() {
        let signer = Ed25519Signer::generate();
        assert_eq!(signer.algorithm(), "ed25519");
    }

    #[test]
    fn public_key_bytes_is_32() {
        let signer = Ed25519Signer::generate();
        assert_eq!(signer.public_key_bytes().len(), 32);
    }
}
