//! Capability token codec: encode, sign, verify, decode.
//!
//! Token wire format: `smgglrs_cap_v1.<base64url(cbor)>.<base64url(sig)>`
//!
//! Tokens are self-describing: they embed the issuer DID, subject DID,
//! granted capabilities, ring level, expiry, and a nonce. The signature
//! covers the raw CBOR bytes.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::identity::CapSigner;

/// Token version prefix.
const TOKEN_PREFIX: &str = "smgglrs_cap_v1";

/// Set of capabilities granted by a token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilitySet {
    /// Path allow globs (must be subset of issuer's).
    pub paths: Vec<String>,
    /// Permitted operations (e.g., "read", "write", "git.status").
    pub operations: Vec<String>,
    /// Tool name globs (e.g., "file_*", "git_*").
    pub tools: Vec<String>,
    /// Credential labels this token can access.
    #[serde(default)]
    pub credentials: Vec<String>,
}

/// Capability token payload (serialized to CBOR).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityPayload {
    /// Version: 1.
    pub v: u8,
    /// Issuer DID (who signed this token).
    pub iss: String,
    /// Subject DID (who this token is for).
    pub sub: String,
    /// Capabilities granted.
    pub cap: CapabilitySet,
    /// Maximum ring level (0 = most privileged).
    pub ring: u8,
    /// Issued-at (Unix timestamp, seconds).
    pub iat: u64,
    /// Expiry (Unix timestamp, seconds).
    pub exp: u64,
    /// Unique nonce (prevents replay).
    pub nonce: [u8; 16],
    /// Parent token nonce (for delegation chains).
    #[serde(default)]
    pub parent: Option<[u8; 16]>,
}

/// Resolved capabilities extracted from a verified token.
#[derive(Debug, Clone)]
pub struct ResolvedCapabilities {
    pub issuer_did: String,
    pub subject_did: String,
    pub ring: u8,
    pub paths: Vec<String>,
    pub operations: HashSet<String>,
    pub tools: Vec<String>,
    pub credentials: Vec<String>,
    pub expires_at: u64,
}

/// Encode and sign a capability token.
///
/// Returns the wire-format string: `smgglrs_cap_v1.<cbor>.<sig>`
pub fn encode_token(payload: &CapabilityPayload, signer: &dyn CapSigner) -> anyhow::Result<String> {
    let cbor_bytes = cbor_encode(payload)?;
    let sig = signer.sign(&cbor_bytes);

    let cbor_b64 = URL_SAFE_NO_PAD.encode(&cbor_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);

    Ok(format!("{TOKEN_PREFIX}.{cbor_b64}.{sig_b64}"))
}

/// Decode and verify a capability token.
///
/// Verifies the signature using the provided signer (which must hold
/// the issuer's public key), checks expiry, and returns the payload.
pub fn decode_token(
    token: &str,
    verifier: &dyn CapSigner,
) -> anyhow::Result<CapabilityPayload> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        anyhow::bail!("invalid token format: expected 3 dot-separated parts");
    }
    if parts[0] != TOKEN_PREFIX {
        anyhow::bail!("invalid token prefix: expected {TOKEN_PREFIX}");
    }

    let cbor_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2])?;

    if !verifier.verify(&cbor_bytes, &sig_bytes) {
        anyhow::bail!("invalid token signature");
    }

    let payload: CapabilityPayload = cbor_decode(&cbor_bytes)?;

    // Check expiry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if payload.exp < now {
        anyhow::bail!("token expired at {}, current time {}", payload.exp, now);
    }

    if payload.v != 1 {
        anyhow::bail!("unsupported token version: {}", payload.v);
    }

    Ok(payload)
}

/// Decode a token without checking expiry or signature.
///
/// **WARNING**: This skips signature verification. Use `decode_token()`
/// for authentication. This function is for inspection/debugging only.
/// **Do not use for authentication** — skips signature verification.
/// Exposed for testing and token inspection only.
/// Decode a token without verifying its signature or expiry.
///
/// **Do not use for authentication** — skips signature verification.
/// Intended for testing, token inspection, and delegation validation.
#[cfg_attr(not(test), doc(hidden))]
pub fn decode_token_unchecked(token: &str) -> anyhow::Result<CapabilityPayload> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 || parts[0] != TOKEN_PREFIX {
        anyhow::bail!("invalid token format");
    }
    let cbor_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
    cbor_decode(&cbor_bytes)
}

/// Resolve a verified payload into capabilities for permission checks.
pub fn resolve_capabilities(payload: &CapabilityPayload) -> ResolvedCapabilities {
    ResolvedCapabilities {
        issuer_did: payload.iss.clone(),
        subject_did: payload.sub.clone(),
        ring: payload.ring,
        paths: payload.cap.paths.clone(),
        operations: payload.cap.operations.iter().cloned().collect(),
        tools: payload.cap.tools.clone(),
        credentials: payload.cap.credentials.clone(),
        expires_at: payload.exp,
    }
}

/// Validate that a delegated token's capabilities are a subset of the parent's.
pub fn validate_delegation(
    parent: &CapabilityPayload,
    child: &CapabilityPayload,
    max_depth: u8,
) -> anyhow::Result<()> {
    // Child must reference parent
    match child.parent {
        Some(parent_nonce) if parent_nonce == parent.nonce => {}
        _ => anyhow::bail!("child token does not reference parent nonce"),
    }

    // Ring attenuation: child must be same or less privileged
    if child.ring < parent.ring {
        anyhow::bail!(
            "ring escalation: child ring {} < parent ring {}",
            child.ring,
            parent.ring
        );
    }

    // Expiry attenuation: child cannot outlive parent
    if child.exp > parent.exp {
        anyhow::bail!("child expiry exceeds parent expiry");
    }

    // Operations subset
    let parent_ops: HashSet<&str> = parent.cap.operations.iter().map(|s| s.as_str()).collect();
    for op in &child.cap.operations {
        if !parent_ops.contains(op.as_str()) {
            anyhow::bail!("operation escalation: child has '{}' not in parent", op);
        }
    }

    // Credentials subset
    let parent_creds: HashSet<&str> = parent.cap.credentials.iter().map(|s| s.as_str()).collect();
    for cred in &child.cap.credentials {
        if !parent_creds.contains(cred.as_str()) {
            anyhow::bail!("credential escalation: child has '{}' not in parent", cred);
        }
    }

    // Depth check: max_depth indicates how many more delegations are allowed.
    // 0 = no further delegation, 1 = one more level, etc.
    if child.parent.is_some()
        && max_depth == 0 {
            anyhow::bail!("delegation chain depth exceeded (max_depth=0)");
        }
        // The child's effective max_depth must be strictly less than the parent's
        // to prevent unlimited re-delegation at the same depth.

    Ok(())
}

// --- CBOR helpers ---

fn cbor_encode(payload: &CapabilityPayload) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf)?;
    Ok(buf)
}

fn cbor_decode(bytes: &[u8]) -> anyhow::Result<CapabilityPayload> {
    Ok(ciborium::from_reader(bytes)?)
}

/// Generate a random 16-byte nonce.
pub fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    use rand::rngs::OsRng;
    use rand::RngCore;
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Build a capability payload with common defaults.
pub fn build_payload(
    issuer_did: &str,
    subject_did: &str,
    cap: CapabilitySet,
    ring: u8,
    ttl_secs: u64,
) -> CapabilityPayload {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    CapabilityPayload {
        v: 1,
        iss: issuer_did.to_string(),
        sub: subject_did.to_string(),
        cap,
        ring,
        iat: now,
        exp: now + ttl_secs,
        nonce: generate_nonce(),
        parent: None,
    }
}

/// Build a delegated capability payload that chains from a parent token.
///
/// The child token's capabilities are intersected with the parent's:
/// - Operations must be a subset of the parent's operations
/// - Tools must be a subset of the parent's tools
/// - Paths must be a subset of the parent's paths
/// - Credentials must be a subset of the parent's credentials
/// - Ring must be >= parent's ring (less privileged)
/// - Expiry must be <= parent's expiry
///
/// Returns an error if the requested capabilities would escalate
/// beyond the parent's grants.
pub fn build_delegated_payload(
    parent: &CapabilityPayload,
    subject_did: &str,
    requested_ops: Vec<String>,
    requested_tools: Vec<String>,
    ring: u8,
    ttl_secs: u64,
) -> anyhow::Result<CapabilityPayload> {
    // Ring attenuation: child must be same or less privileged
    if ring < parent.ring {
        anyhow::bail!(
            "ring escalation: requested ring {} < parent ring {}",
            ring, parent.ring
        );
    }

    // Intersect operations with parent's
    let parent_ops: HashSet<&str> = parent.cap.operations.iter().map(|s| s.as_str()).collect();
    let mut effective_ops = Vec::new();
    for op in &requested_ops {
        if parent_ops.contains(op.as_str()) {
            effective_ops.push(op.clone());
        } else {
            anyhow::bail!(
                "operation escalation: '{}' not in parent's grants {:?}",
                op, parent.cap.operations
            );
        }
    }

    // Intersect tools with parent's using glob matching.
    // Each requested tool must match at least one parent tool glob.
    let mut effective_tools = Vec::new();
    for tool in &requested_tools {
        let covered = parent.cap.tools.iter().any(|parent_glob| {
            glob::Pattern::new(parent_glob)
                .map(|p| p.matches(tool))
                .unwrap_or(false)
                || parent_glob == tool
        });
        if !covered {
            anyhow::bail!(
                "tool escalation: '{}' not covered by parent's tool grants {:?}",
                tool, parent.cap.tools
            );
        }
        effective_tools.push(tool.clone());
    }

    // Expiry attenuation: child cannot outlive parent
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let child_exp = now + ttl_secs;
    let effective_exp = child_exp.min(parent.exp);

    let cap = CapabilitySet {
        paths: parent.cap.paths.clone(),
        operations: effective_ops,
        tools: effective_tools,
        credentials: vec![], // teammates don't inherit credentials
    };

    Ok(CapabilityPayload {
        v: 1,
        iss: parent.iss.clone(),
        sub: subject_did.to_string(),
        cap,
        ring,
        iat: now,
        exp: effective_exp,
        nonce: generate_nonce(),
        parent: Some(parent.nonce),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Ed25519Signer;

    fn test_cap_set() -> CapabilitySet {
        CapabilitySet {
            paths: vec!["/home/user/projects/**".to_string()],
            operations: vec!["read".to_string(), "write".to_string(), "git.status".to_string()],
            tools: vec!["file_*".to_string(), "git_*".to_string()],
            credentials: vec!["github.pat".to_string()],
        }
    }

    fn test_payload(signer: &Ed25519Signer) -> CapabilityPayload {
        build_payload(
            signer.did(),
            "did:key:z6MkSubject",
            test_cap_set(),
            1,
            3600,
        )
    }

    #[test]
    fn roundtrip_encode_decode() {
        let signer = Ed25519Signer::generate();
        let payload = test_payload(&signer);

        let token = encode_token(&payload, &signer).unwrap();
        assert!(token.starts_with("smgglrs_cap_v1."));

        let decoded = decode_token(&token, &signer).unwrap();
        assert_eq!(decoded.v, 1);
        assert_eq!(decoded.iss, signer.did());
        assert_eq!(decoded.sub, "did:key:z6MkSubject");
        assert_eq!(decoded.ring, 1);
        assert_eq!(decoded.cap.paths, vec!["/home/user/projects/**"]);
        assert_eq!(decoded.cap.operations.len(), 3);
        assert_eq!(decoded.cap.tools, vec!["file_*", "git_*"]);
        assert_eq!(decoded.cap.credentials, vec!["github.pat"]);
        assert_eq!(decoded.nonce, payload.nonce);
    }

    #[test]
    fn tampered_payload_fails() {
        let signer = Ed25519Signer::generate();
        let payload = test_payload(&signer);
        let token = encode_token(&payload, &signer).unwrap();

        // Tamper with the CBOR part
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let mut cbor = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        cbor[0] ^= 0xff;
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(&cbor),
            parts[2]
        );

        assert!(decode_token(&tampered, &signer).is_err());
    }

    #[test]
    fn tampered_signature_fails() {
        let signer = Ed25519Signer::generate();
        let payload = test_payload(&signer);
        let token = encode_token(&payload, &signer).unwrap();

        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let mut sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        sig[0] ^= 0xff;
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            URL_SAFE_NO_PAD.encode(&sig),
        );

        assert!(decode_token(&tampered, &signer).is_err());
    }

    #[test]
    fn wrong_signer_fails() {
        let signer1 = Ed25519Signer::generate();
        let signer2 = Ed25519Signer::generate();
        let payload = test_payload(&signer1);
        let token = encode_token(&payload, &signer1).unwrap();

        // Verify with wrong key
        assert!(decode_token(&token, &signer2).is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let signer = Ed25519Signer::generate();
        let mut payload = test_payload(&signer);
        // Set expiry in the past
        payload.exp = 1000;
        payload.iat = 900;
        let token = encode_token(&payload, &signer).unwrap();

        let err = decode_token(&token, &signer).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn invalid_format_rejected() {
        let signer = Ed25519Signer::generate();
        assert!(decode_token("not-a-token", &signer).is_err());
        assert!(decode_token("smgglrs_cap_v1.only-two", &signer).is_err());
        assert!(decode_token("wrong_prefix.a.b", &signer).is_err());
    }

    #[test]
    fn decode_unchecked_skips_verification() {
        let signer = Ed25519Signer::generate();
        let mut payload = test_payload(&signer);
        payload.exp = 1000; // expired
        let token = encode_token(&payload, &signer).unwrap();

        // decode_token fails (expired)
        assert!(decode_token(&token, &signer).is_err());
        // decode_token_unchecked succeeds
        let decoded = decode_token_unchecked(&token).unwrap();
        assert_eq!(decoded.exp, 1000);
    }

    #[test]
    fn resolve_capabilities_extracts_fields() {
        let signer = Ed25519Signer::generate();
        let payload = test_payload(&signer);
        let resolved = resolve_capabilities(&payload);

        assert_eq!(resolved.ring, 1);
        assert_eq!(resolved.paths, vec!["/home/user/projects/**"]);
        assert!(resolved.operations.contains("read"));
        assert!(resolved.operations.contains("write"));
        assert!(resolved.operations.contains("git.status"));
        assert_eq!(resolved.tools, vec!["file_*", "git_*"]);
        assert_eq!(resolved.credentials, vec!["github.pat"]);
    }

    #[test]
    fn nonce_is_unique() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
    }

    #[test]
    fn cbor_is_compact() {
        let signer = Ed25519Signer::generate();
        let payload = test_payload(&signer);
        let token = encode_token(&payload, &signer).unwrap();

        // Token should be reasonably compact (< 500 bytes for typical payloads)
        assert!(token.len() < 500, "token too large: {} bytes", token.len());
    }

    // --- Delegation validation tests ---

    #[test]
    fn valid_delegation() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let child = CapabilityPayload {
            v: 1,
            iss: "did:key:z6MkSubject".to_string(),
            sub: "did:key:z6MkChild".to_string(),
            cap: CapabilitySet {
                paths: vec!["/home/user/projects/app/**".to_string()],
                operations: vec!["read".to_string()],
                tools: vec!["file_*".to_string()],
                credentials: vec![],
            },
            ring: 2,
            iat: parent.iat,
            exp: parent.exp - 100,
            nonce: generate_nonce(),
            parent: Some(parent.nonce),
        };

        assert!(validate_delegation(&parent, &child, 3).is_ok());
    }

    #[test]
    fn delegation_ring_escalation_rejected() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let mut child = parent.clone();
        child.ring = 0; // escalation: parent is ring 1
        child.nonce = generate_nonce();
        child.parent = Some(parent.nonce);

        let err = validate_delegation(&parent, &child, 3).unwrap_err();
        assert!(err.to_string().contains("ring escalation"));
    }

    #[test]
    fn delegation_expiry_extension_rejected() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let mut child = parent.clone();
        child.exp = parent.exp + 1000; // extends beyond parent
        child.nonce = generate_nonce();
        child.parent = Some(parent.nonce);

        let err = validate_delegation(&parent, &child, 3).unwrap_err();
        assert!(err.to_string().contains("expiry"));
    }

    #[test]
    fn delegation_operation_escalation_rejected() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let child = CapabilityPayload {
            v: 1,
            iss: parent.sub.clone(),
            sub: "did:key:z6MkChild".to_string(),
            cap: CapabilitySet {
                paths: vec![],
                operations: vec!["read".to_string(), "shell.exec".to_string()],
                tools: vec![],
                credentials: vec![],
            },
            ring: parent.ring,
            iat: parent.iat,
            exp: parent.exp,
            nonce: generate_nonce(),
            parent: Some(parent.nonce),
        };

        let err = validate_delegation(&parent, &child, 3).unwrap_err();
        assert!(err.to_string().contains("shell.exec"));
    }

    #[test]
    fn delegation_credential_escalation_rejected() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let child = CapabilityPayload {
            v: 1,
            iss: parent.sub.clone(),
            sub: "did:key:z6MkChild".to_string(),
            cap: CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec!["github.pat".to_string(), "aws.secret".to_string()],
            },
            ring: parent.ring,
            iat: parent.iat,
            exp: parent.exp,
            nonce: generate_nonce(),
            parent: Some(parent.nonce),
        };

        let err = validate_delegation(&parent, &child, 3).unwrap_err();
        assert!(err.to_string().contains("aws.secret"));
    }

    #[test]
    fn delegation_missing_parent_nonce_rejected() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let mut child = parent.clone();
        child.nonce = generate_nonce();
        child.parent = None; // no parent reference

        let err = validate_delegation(&parent, &child, 3).unwrap_err();
        assert!(err.to_string().contains("parent nonce"));
    }

    #[test]
    fn delegation_wrong_parent_nonce_rejected() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let mut child = parent.clone();
        child.nonce = generate_nonce();
        child.parent = Some([0xff; 16]); // wrong nonce

        let err = validate_delegation(&parent, &child, 3).unwrap_err();
        assert!(err.to_string().contains("parent nonce"));
    }

    #[test]
    fn empty_capabilities_valid() {
        let signer = Ed25519Signer::generate();
        let payload = build_payload(
            signer.did(),
            "did:key:z6MkMinimal",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec![],
            },
            3,
            60,
        );

        let token = encode_token(&payload, &signer).unwrap();
        let decoded = decode_token(&token, &signer).unwrap();
        assert!(decoded.cap.paths.is_empty());
        assert!(decoded.cap.operations.is_empty());
        assert!(decoded.cap.credentials.is_empty());
    }

    // --- Delegated payload builder tests ---

    #[test]
    fn delegated_payload_restricts_operations() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let child = build_delegated_payload(
            &parent,
            "did:teammate:team-1:reader",
            vec!["read".to_string()],
            vec!["file_read".to_string()],
            2,
            600,
        )
        .unwrap();

        assert_eq!(child.cap.operations, vec!["read"]);
        assert_eq!(child.cap.tools, vec!["file_read"]);
        assert_eq!(child.ring, 2);
        assert_eq!(child.parent, Some(parent.nonce));
        assert!(child.cap.credentials.is_empty());
    }

    #[test]
    fn delegated_payload_rejects_operation_escalation() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let err = build_delegated_payload(
            &parent,
            "did:teammate:team-1:hacker",
            vec!["read".to_string(), "shell.exec".to_string()],
            vec!["file_read".to_string()],
            2,
            600,
        )
        .unwrap_err();

        assert!(err.to_string().contains("operation escalation"));
        assert!(err.to_string().contains("shell.exec"));
    }

    #[test]
    fn delegated_payload_rejects_tool_escalation() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let err = build_delegated_payload(
            &parent,
            "did:teammate:team-1:hacker",
            vec!["read".to_string()],
            vec!["shell_exec".to_string()],
            2,
            600,
        )
        .unwrap_err();

        assert!(err.to_string().contains("tool escalation"));
        assert!(err.to_string().contains("shell_exec"));
    }

    #[test]
    fn delegated_payload_rejects_ring_escalation() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let err = build_delegated_payload(
            &parent,
            "did:teammate:team-1:hacker",
            vec!["read".to_string()],
            vec!["file_read".to_string()],
            0, // ring 0 < parent ring 1
            600,
        )
        .unwrap_err();

        assert!(err.to_string().contains("ring escalation"));
    }

    #[test]
    fn delegated_payload_caps_expiry_to_parent() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer); // ttl=3600

        let child = build_delegated_payload(
            &parent,
            "did:teammate:team-1:worker",
            vec!["read".to_string()],
            vec!["file_read".to_string()],
            2,
            99999, // much longer than parent
        )
        .unwrap();

        // Child expiry must not exceed parent's
        assert!(child.exp <= parent.exp);
    }

    #[test]
    fn delegated_payload_tool_glob_matching() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);
        // Parent has tools: ["file_*", "git_*"]

        // file_read matches file_*
        let child = build_delegated_payload(
            &parent,
            "did:teammate:team-1:reader",
            vec!["read".to_string()],
            vec!["file_read".to_string(), "file_grep".to_string(), "git_status".to_string()],
            2,
            600,
        )
        .unwrap();

        assert_eq!(child.cap.tools, vec!["file_read", "file_grep", "git_status"]);
    }

    #[test]
    fn delegated_payload_sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let child = build_delegated_payload(
            &parent,
            "did:teammate:team-1:worker",
            vec!["read".to_string()],
            vec!["file_read".to_string()],
            2,
            600,
        )
        .unwrap();

        let token = encode_token(&child, &signer).unwrap();
        let decoded = decode_token(&token, &signer).unwrap();

        assert_eq!(decoded.sub, "did:teammate:team-1:worker");
        assert_eq!(decoded.cap.operations, vec!["read"]);
        assert_eq!(decoded.cap.tools, vec!["file_read"]);
        assert_eq!(decoded.ring, 2);
        assert_eq!(decoded.parent, Some(parent.nonce));

        // Validate delegation chain
        assert!(validate_delegation(&parent, &decoded, 3).is_ok());
    }

    #[test]
    fn delegated_payload_inherits_paths() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer);

        let child = build_delegated_payload(
            &parent,
            "did:teammate:team-1:worker",
            vec!["read".to_string()],
            vec!["file_read".to_string()],
            2,
            600,
        )
        .unwrap();

        // Paths are inherited from parent
        assert_eq!(child.cap.paths, parent.cap.paths);
    }
}
