//! Tool manifest signing and verification with TOFU key pinning.
//!
//! Signs upstream MCP server tool manifests using Ed25519 via the
//! [`CapSigner`] trait. This is a navra extension — not in the
//! MCP spec — providing supply-chain integrity for tool definitions.

use crate::identity::CapSigner;
use navra_protocol::ToolDefinition;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use vstd::prelude::*;

#[derive(Debug, Clone)]
pub struct ManifestSignature {
    pub signature: Vec<u8>,
    pub signer_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifest {
    pub tools: Vec<ToolDefinition>,
    pub server_name: String,
    pub timestamp: i64,
}

impl ToolManifest {
    /// Order-insensitive fingerprint of the signed tool set.
    ///
    /// Canonicalizes each tool definition (sorted by name) and hashes
    /// the concatenation. Used to check that the tools an upstream
    /// actually serves match the signed manifest — any drift (rug
    /// pull, description rewrite) fails the comparison.
    pub fn tools_fingerprint(&self) -> [u8; 32] {
        tools_fingerprint(&self.tools)
    }
}

/// Order-insensitive SHA-256 fingerprint over a set of tool
/// definitions (sorted by name, canonical JSON per tool).
pub fn tools_fingerprint(tools: &[ToolDefinition]) -> [u8; 32] {
    let mut tools = tools.to_vec();
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    let mut hasher = Sha256::new();
    for tool in &tools {
        hasher.update(tool.name.as_bytes());
        let value = serde_json::to_value(tool).unwrap_or(serde_json::Value::Null);
        hasher.update(canonical_json_bytes(&value));
    }
    hasher.finalize().into()
}

/// Wire format for a signed tool manifest (JSON, suitable for a file
/// or inline config).
///
/// Produced by signing a [`ToolManifest`] with an upstream's key:
///
/// ```
/// # use navra_auth::identity::Ed25519Signer;
/// # use navra_auth::manifest::{SignedManifest, ToolManifest};
/// # fn example(manifest: ToolManifest) {
/// let signer = Ed25519Signer::generate();
/// let signed = SignedManifest::sign(&manifest, &signer);
/// let json = serde_json::to_string_pretty(&signed).unwrap();
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    pub manifest: ToolManifest,
    /// Hex-encoded Ed25519 signature over the manifest canonical bytes.
    pub signature: String,
    /// DID:key of the signing key.
    pub signer_did: String,
}

impl SignedManifest {
    /// Sign a manifest with the given signer.
    pub fn sign(manifest: &ToolManifest, signer: &dyn CapSigner) -> Self {
        let sig = manifest.sign(signer);
        Self {
            manifest: manifest.clone(),
            signature: hex::encode(&sig.signature),
            signer_did: sig.signer_did,
        }
    }

    /// Decode the hex signature into the raw bytes.
    fn signature_bytes(&self) -> Result<Vec<u8>, String> {
        hex::decode(&self.signature)
            .map_err(|e| format!("manifest signature is not valid hex: {e}"))
    }
}

/// Outcome of verifying a signed manifest against a TOFU key store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestVerification {
    /// Signature valid and key pinned from a previous run.
    Trusted,
    /// Signature valid and key pinned now (first use).
    FirstUse,
    /// Signature valid but the signer differs from the pinned key.
    /// The pin is NOT updated — the caller must reject the upstream.
    KeyChanged { pinned: String, presented: String },
    /// Signature missing, malformed, or it does not match the manifest
    /// content (tampering). The key store is untouched.
    InvalidSignature,
}

/// Verify a signed manifest: signature over canonical bytes, then
/// TOFU key pinning.
///
/// Fail-closed semantics:
/// - tampered content or a bad signature → [`ManifestVerification::InvalidSignature`]
/// - key change after pinning → [`ManifestVerification::KeyChanged`]
///   without re-pinning
/// - first use → pins the key and returns [`ManifestVerification::FirstUse`]
pub fn verify_signed_manifest(
    signed: &SignedManifest,
    key_store: &mut ManifestKeyStore,
) -> ManifestVerification {
    let sig_bytes = match signed.signature_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(server = %signed.manifest.server_name, error = %e, "Invalid manifest signature encoding");
            return ManifestVerification::InvalidSignature;
        }
    };
    let verifier = match crate::identity::Ed25519Verifier::from_did(&signed.signer_did) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(server = %signed.manifest.server_name, did = %signed.signer_did, error = %e, "Manifest signer DID is not a usable Ed25519 key");
            return ManifestVerification::InvalidSignature;
        }
    };
    if !verifier.verify(&signed.manifest.canonical_bytes(), &sig_bytes) {
        return ManifestVerification::InvalidSignature;
    }
    match key_store.check(&signed.manifest.server_name, &signed.signer_did) {
        TofuResult::Trusted => ManifestVerification::Trusted,
        TofuResult::FirstUse => ManifestVerification::FirstUse,
        TofuResult::KeyChanged => ManifestVerification::KeyChanged {
            pinned: key_store
                .pinned_did(&signed.manifest.server_name)
                .unwrap_or_default()
                .to_string(),
            presented: signed.signer_did.clone(),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuResult {
    Trusted,
    FirstUse,
    KeyChanged,
}

#[derive(Debug)]
pub struct ManifestKeyStore {
    known_keys: HashMap<String, String>,
    path: Option<std::path::PathBuf>,
}

impl ManifestKeyStore {
    pub fn new() -> Self {
        Self {
            known_keys: HashMap::new(),
            path: None,
        }
    }

    /// Open a persistent key store, failing closed when the file is
    /// unreadable or corrupt.
    ///
    /// A missing file is normal (first run) and yields an empty store.
    /// Pins are written back on first use. Follows the same data-file
    /// convention as the tool scanner's `tool_hashes.json`.
    pub fn with_path(path: std::path::PathBuf) -> Result<Self, String> {
        let known_keys = match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).map_err(|e| {
                format!(
                    "corrupt manifest keystore {} (delete it to re-pin from scratch): {e}",
                    path.display()
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                return Err(format!(
                    "failed to read manifest keystore {}: {e}",
                    path.display()
                ));
            }
        };
        Ok(Self {
            known_keys,
            path: Some(path),
        })
    }

    /// The DID currently pinned for a server, if any.
    pub fn pinned_did(&self, server_name: &str) -> Option<&str> {
        self.known_keys.get(server_name).map(|s| s.as_str())
    }

    pub fn check(&mut self, server_name: &str, signer_did: &str) -> TofuResult {
        match self.known_keys.get(server_name) {
            None => {
                self.known_keys
                    .insert(server_name.to_string(), signer_did.to_string());
                self.persist();
                TofuResult::FirstUse
            }
            Some(pinned) if pinned == signer_did => TofuResult::Trusted,
            Some(_) => TofuResult::KeyChanged,
        }
    }

    /// Write pins back to disk (only when a path was configured).
    fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(&self.known_keys) {
            Ok(data) => {
                if let Err(e) = std::fs::write(path, data) {
                    tracing::warn!(path = %path.display(), error = %e, "Failed to persist manifest keystore");
                }
            }
            Err(e) => tracing::warn!(error = %e, "Failed to serialize manifest keystore"),
        }
    }
}

impl Default for ManifestKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Default keystore location, following the same data-file convention
/// as the tool scanner's hash store: `~/.local/share/navra/manifest_keys.json`.
pub fn default_keystore_path() -> Option<std::path::PathBuf> {
    dirs::data_dir().map(|d| d.join("navra").join("manifest_keys.json"))
}

impl ToolManifest {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let value = serde_json::to_value(self).expect("manifest serialization cannot fail");
        canonical_json_bytes(&value)
    }

    pub fn sign(&self, signer: &dyn CapSigner) -> ManifestSignature {
        let bytes = self.canonical_bytes();
        ManifestSignature {
            signature: signer.sign(&bytes),
            signer_did: signer.did().to_string(),
        }
    }

    pub fn verify(&self, sig: &ManifestSignature, signer: &dyn CapSigner) -> bool {
        if sig.signer_did != signer.did() {
            return false;
        }
        let bytes = self.canonical_bytes();
        signer.verify(&bytes, &sig.signature)
    }
}

fn canonical_json_bytes(value: &serde_json::Value) -> Vec<u8> {
    use serde_json::Value;
    let mut buf = Vec::new();
    match value {
        Value::Null => buf.extend_from_slice(b"null"),
        Value::Bool(b) => buf.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => buf.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => {
            buf.push(b'"');
            for ch in s.chars() {
                match ch {
                    '"' => buf.extend_from_slice(b"\\\""),
                    '\\' => buf.extend_from_slice(b"\\\\"),
                    '\n' => buf.extend_from_slice(b"\\n"),
                    '\r' => buf.extend_from_slice(b"\\r"),
                    '\t' => buf.extend_from_slice(b"\\t"),
                    c if c < '\x20' => {
                        buf.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
                    }
                    c => {
                        let mut tmp = [0u8; 4];
                        buf.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
                    }
                }
            }
            buf.push(b'"');
        }
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                buf.extend(canonical_json_bytes(v));
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            buf.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                buf.extend(canonical_json_bytes(&Value::String((*key).clone())));
                buf.push(b':');
                buf.extend(canonical_json_bytes(&map[*key]));
            }
            buf.push(b'}');
        }
    }
    buf
}

pub fn verify_manifest_option(
    manifest: &ToolManifest,
    signature: Option<&ManifestSignature>,
    key_store: &mut ManifestKeyStore,
    signer: &dyn CapSigner,
) -> Option<bool> {
    let sig = signature?;
    if !manifest.verify(sig, signer) {
        return Some(false);
    }
    match key_store.check(&manifest.server_name, &sig.signer_did) {
        TofuResult::Trusted | TofuResult::FirstUse => Some(true),
        TofuResult::KeyChanged => Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Ed25519Signer;
    use navra_protocol::compat::empty_input_schema;

    fn test_tools() -> Vec<ToolDefinition> {
        vec![
            ToolDefinition::new("file_read", "Read a file", empty_input_schema()),
            ToolDefinition::new("git_status", "Show git status", empty_input_schema()),
        ]
    }

    fn test_manifest() -> ToolManifest {
        ToolManifest {
            tools: test_tools(),
            server_name: "test-upstream".to_string(),
            timestamp: 1700000000,
        }
    }

    #[test]
    fn manifest_sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate();
        let manifest = test_manifest();
        let sig = manifest.sign(&signer);
        assert!(manifest.verify(&sig, &signer));
    }

    #[test]
    fn manifest_tampered_rejects() {
        let signer = Ed25519Signer::generate();
        let manifest = test_manifest();
        let sig = manifest.sign(&signer);

        let mut tampered = manifest.clone();
        tampered.tools[0].name = "file_write".into();
        assert!(!tampered.verify(&sig, &signer));
    }

    #[test]
    fn tofu_first_use_pins_key() {
        let mut store = ManifestKeyStore::new();
        let result = store.check("server-a", "did:key:z6MkTest1");
        assert_eq!(result, TofuResult::FirstUse);
        assert_eq!(
            store.known_keys.get("server-a").unwrap(),
            "did:key:z6MkTest1"
        );
    }

    #[test]
    fn tofu_same_key_trusted() {
        let mut store = ManifestKeyStore::new();
        store.check("server-a", "did:key:z6MkTest1");
        let result = store.check("server-a", "did:key:z6MkTest1");
        assert_eq!(result, TofuResult::Trusted);
    }

    #[test]
    fn tofu_key_changed_warns() {
        let mut store = ManifestKeyStore::new();
        store.check("server-a", "did:key:z6MkTest1");
        let result = store.check("server-a", "did:key:z6MkDifferent");
        assert_eq!(result, TofuResult::KeyChanged);
    }

    #[test]
    fn unsigned_manifest_returns_none() {
        let signer = Ed25519Signer::generate();
        let manifest = test_manifest();
        let result = verify_manifest_option(&manifest, None, &mut ManifestKeyStore::new(), &signer);
        assert!(result.is_none());
    }

    #[test]
    fn scan_result_includes_verification() {
        let signer = Ed25519Signer::generate();
        let manifest = test_manifest();
        let sig = manifest.sign(&signer);
        let mut store = ManifestKeyStore::new();
        let result = verify_manifest_option(&manifest, Some(&sig), &mut store, &signer);
        assert_eq!(result, Some(true));
    }

    #[test]
    fn wrong_signer_rejects() {
        let signer1 = Ed25519Signer::generate();
        let signer2 = Ed25519Signer::generate();
        let manifest = test_manifest();
        let sig = manifest.sign(&signer1);
        assert!(!manifest.verify(&sig, &signer2));
    }

    #[test]
    fn canonical_bytes_deterministic() {
        let m1 = test_manifest();
        let m2 = test_manifest();
        assert_eq!(m1.canonical_bytes(), m2.canonical_bytes());
    }

    #[test]
    fn verify_manifest_with_tofu_key_change() {
        let signer1 = Ed25519Signer::generate();
        let signer2 = Ed25519Signer::generate();
        let manifest = test_manifest();
        let mut store = ManifestKeyStore::new();

        // First use with signer1
        let sig1 = manifest.sign(&signer1);
        let r1 = verify_manifest_option(&manifest, Some(&sig1), &mut store, &signer1);
        assert_eq!(r1, Some(true));

        // Second use with different signer — key changed
        let sig2 = manifest.sign(&signer2);
        let r2 = verify_manifest_option(&manifest, Some(&sig2), &mut store, &signer2);
        assert_eq!(r2, Some(false));
    }

    // --- SignedManifest wire format + verify_signed_manifest ---

    fn test_signed_manifest() -> (SignedManifest, Ed25519Signer) {
        let signer = Ed25519Signer::generate();
        (SignedManifest::sign(&test_manifest(), &signer), signer)
    }

    #[test]
    fn signed_manifest_wire_roundtrip_first_use() {
        let (signed, _signer) = test_signed_manifest();
        let json = serde_json::to_string(&signed).unwrap();
        let back: SignedManifest = serde_json::from_str(&json).unwrap();

        let mut store = ManifestKeyStore::new();
        assert_eq!(
            verify_signed_manifest(&back, &mut store),
            ManifestVerification::FirstUse
        );
        // Pinned now; a second verification is Trusted.
        assert_eq!(
            verify_signed_manifest(&back, &mut store),
            ManifestVerification::Trusted
        );
    }

    #[test]
    fn signed_manifest_tampered_content_rejected() {
        let (mut signed, _signer) = test_signed_manifest();
        // Tamper with the signed content: change a tool description.
        signed.manifest.tools[0].description = Some("Read any file, no restrictions".into());
        let mut store = ManifestKeyStore::new();
        assert_eq!(
            verify_signed_manifest(&signed, &mut store),
            ManifestVerification::InvalidSignature
        );
        // The failed verification must not have pinned anything.
        assert_eq!(store.pinned_did("test-upstream"), None);
    }

    #[test]
    fn signed_manifest_key_changed_rejected_without_repin() {
        // Pin signer1's key, then present a manifest signed by signer2.
        let (signed1, signer1) = test_signed_manifest();
        let mut store = ManifestKeyStore::new();
        assert_eq!(
            verify_signed_manifest(&signed1, &mut store),
            ManifestVerification::FirstUse
        );

        let signer2 = Ed25519Signer::generate();
        let signed2 = SignedManifest::sign(&test_manifest(), &signer2);
        let result = verify_signed_manifest(&signed2, &mut store);
        match result {
            ManifestVerification::KeyChanged {
                ref pinned,
                ref presented,
            } => {
                assert_eq!(pinned, &signer1.did());
                assert_eq!(presented, &signer2.did());
            }
            other => panic!("expected KeyChanged, got {other:?}"),
        }
        // No silent re-pin: signer1's key must still be pinned.
        assert_eq!(store.pinned_did("test-upstream"), Some(signer1.did()));
        // And the original manifest still verifies as Trusted.
        assert_eq!(
            verify_signed_manifest(&signed1, &mut store),
            ManifestVerification::Trusted
        );
    }

    #[test]
    fn keystore_persists_pins_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest_keys.json");
        let signer = Ed25519Signer::generate();

        let mut store = ManifestKeyStore::with_path(path.clone()).unwrap();
        assert_eq!(store.check("server-a", signer.did()), TofuResult::FirstUse);
        assert!(path.exists(), "pin must be persisted on first use");

        let mut reopened = ManifestKeyStore::with_path(path).unwrap();
        assert_eq!(
            reopened.check("server-a", signer.did()),
            TofuResult::Trusted
        );
    }

    #[test]
    fn keystore_corrupt_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest_keys.json");
        std::fs::write(&path, b"{not json").unwrap();
        let result = ManifestKeyStore::with_path(path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("corrupt manifest keystore"));
    }

    #[test]
    fn tools_fingerprint_ignores_order_detects_changes() {
        let m1 = test_manifest();
        let mut m2 = test_manifest();
        m2.tools.reverse();
        assert_eq!(
            m1.tools_fingerprint(),
            m2.tools_fingerprint(),
            "same tools in a different order must share a fingerprint"
        );

        m2.tools[0].description = Some("Changed description".into());
        assert_ne!(
            m1.tools_fingerprint(),
            m2.tools_fingerprint(),
            "a changed tool definition must change the fingerprint"
        );
    }
}

verus! {

// TOFU (Trust On First Use) key pinning model:
// has_pinned_key: whether server has a previously pinned key
// key_matches: whether current key matches pinned key
// Result: Trusted=0, FirstUse=1, KeyChanged=2

spec fn spec_tofu_check(has_pinned_key: bool, key_matches: bool) -> nat {
    if !has_pinned_key { 1 }       // FirstUse
    else if key_matches { 0 }       // Trusted
    else { 2 }                      // KeyChanged
}

proof fn first_use_when_no_pin()
    ensures spec_tofu_check(false, false) == 1,
{}

proof fn trusted_when_key_matches()
    ensures spec_tofu_check(true, true) == 0,
{}

proof fn key_changed_when_mismatch()
    ensures spec_tofu_check(true, false) == 2,
{}

// verify_manifest_option fail-closed model:
// sig_valid: signature verification passed
// tofu_result: TOFU check result
// Result: true (trusted), false (rejected)

spec fn spec_verify_manifest(sig_valid: bool, tofu_result: nat) -> bool {
    sig_valid && tofu_result <= 1 // Trusted(0) or FirstUse(1) pass; KeyChanged(2) rejects
}

proof fn invalid_sig_always_rejects(tofu_result: nat)
    ensures !spec_verify_manifest(false, tofu_result),
{}

proof fn key_changed_always_rejects(sig_valid: bool)
    ensures !spec_verify_manifest(sig_valid, 2),
{}

proof fn valid_sig_trusted_passes()
    ensures spec_verify_manifest(true, 0),
{}

proof fn valid_sig_first_use_passes()
    ensures spec_verify_manifest(true, 1),
{}

} // verus!
