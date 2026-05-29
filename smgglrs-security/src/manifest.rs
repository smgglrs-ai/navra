//! Tool manifest signing and verification with TOFU key pinning.
//!
//! Signs upstream MCP server tool manifests using Ed25519 via the
//! [`CapSigner`] trait. This is a smgglrs extension — not in the
//! MCP spec — providing supply-chain integrity for tool definitions.

use crate::identity::CapSigner;
use serde::{Deserialize, Serialize};
use smgglrs_protocol::ToolDefinition;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifest {
    pub tools: Vec<ToolDefinition>,
    pub server_name: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone)]
pub struct ManifestSignature {
    pub signature: Vec<u8>,
    pub signer_did: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuResult {
    Trusted,
    FirstUse,
    KeyChanged,
}

pub struct ManifestKeyStore {
    known_keys: HashMap<String, String>,
}

impl ManifestKeyStore {
    pub fn new() -> Self {
        Self {
            known_keys: HashMap::new(),
        }
    }

    pub fn check(&mut self, server_name: &str, signer_did: &str) -> TofuResult {
        match self.known_keys.get(server_name) {
            None => {
                self.known_keys
                    .insert(server_name.to_string(), signer_did.to_string());
                TofuResult::FirstUse
            }
            Some(pinned) if pinned == signer_did => TofuResult::Trusted,
            Some(_) => TofuResult::KeyChanged,
        }
    }
}

impl Default for ManifestKeyStore {
    fn default() -> Self {
        Self::new()
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Ed25519Signer;
    use smgglrs_protocol::ToolInputSchema;

    fn test_tools() -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "file_read".to_string(),
                description: Some("Read a file".to_string()),
                input_schema: ToolInputSchema {
                    schema_type: "object".to_string(),
                    properties: None,
                    required: None,
                },
                annotations: None,
                ttl_ms: None,
                cache_scope: None,
            },
            ToolDefinition {
                name: "git_status".to_string(),
                description: Some("Show git status".to_string()),
                input_schema: ToolInputSchema {
                    schema_type: "object".to_string(),
                    properties: None,
                    required: None,
                },
                annotations: None,
                ttl_ms: None,
                cache_scope: None,
            },
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
        tampered.tools[0].name = "file_write".to_string();
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
        let result =
            verify_manifest_option(&manifest, Some(&sig), &mut store, &signer);
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
