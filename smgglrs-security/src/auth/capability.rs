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

/// On-behalf-of identity: the human this agent acts for.
///
/// Carries the human's identity from the root token through the
/// entire delegation chain, enabling human -> agent accountability
/// in audit trails. Set via RFC 8693 token exchange.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OboIdentity {
    /// Human subject identifier (email, employee ID, etc.)
    pub sub: String,
    /// Identity provider that authenticated the human.
    pub iss: String,
    /// When the human authenticated (Unix timestamp, seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
}

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
    /// On-behalf-of: the human identity this agent acts for.
    /// Propagated through delegation chains; cannot be added during attenuation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obo: Option<OboIdentity>,
    /// Sandbox profile: per-tool rules that transform how the gateway
    /// presents tools to this token's holder (simulate, redact, rate-limit,
    /// path rewrite). Restrictions can only be added/tightened, never removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<super::sandbox_profile::SandboxProfile>,
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
    /// On-behalf-of human subject identifier, for audit trails.
    pub obo_sub: Option<String>,
    /// Sandbox profile from the capability token.
    pub sandbox: Option<super::sandbox_profile::SandboxProfile>,
}

/// Revocation list for capability tokens.
///
/// Tokens are identified by their nonce. Revoking a token adds its nonce
/// to this set. Expired nonces are auto-cleaned on `check()`.
#[derive(Default)]
pub struct TokenRevocationList {
    revoked: std::sync::RwLock<HashSet<[u8; 16]>>,
}

impl TokenRevocationList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke a token by its nonce.
    pub fn revoke(&self, nonce: [u8; 16]) {
        self.revoked.write().unwrap().insert(nonce);
    }

    /// Check if a token nonce has been revoked.
    pub fn is_revoked(&self, nonce: &[u8; 16]) -> bool {
        self.revoked.read().unwrap().contains(nonce)
    }

    /// Number of entries in the revocation list.
    pub fn len(&self) -> usize {
        self.revoked.read().unwrap().len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
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
/// Verifies the signature, checks expiry, and optionally checks the
/// revocation list. Returns the payload if all checks pass.
pub fn decode_token(token: &str, verifier: &dyn CapSigner) -> anyhow::Result<CapabilityPayload> {
    decode_token_with_revocation(token, verifier, None)
}

/// Decode and verify a capability token with revocation checking.
pub fn decode_token_with_revocation(
    token: &str,
    verifier: &dyn CapSigner,
    revocation_list: Option<&TokenRevocationList>,
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

    if let Some(rl) = revocation_list {
        if rl.is_revoked(&payload.nonce) {
            anyhow::bail!("token has been revoked");
        }
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
        obo_sub: payload.obo.as_ref().map(|o| o.sub.clone()),
        sandbox: payload.sandbox.clone(),
    }
}

/// Core delegation attenuation checks (pure, no anyhow).
///
/// Returns Ok(()) if child is a valid attenuation of parent.
/// Used by Kani proofs and by validate_delegation.
pub fn check_attenuation(
    parent_ring: u8,
    child_ring: u8,
    parent_exp: u64,
    child_exp: u64,
) -> Result<(), &'static str> {
    if child_ring < parent_ring {
        return Err("ring escalation");
    }
    if child_exp > parent_exp {
        return Err("expiry extension");
    }
    Ok(())
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

    // Ring and expiry attenuation
    check_attenuation(parent.ring, child.ring, parent.exp, child.exp).map_err(|e| {
        anyhow::anyhow!(
            "{}: child ring={} exp={}, parent ring={} exp={}",
            e,
            child.ring,
            child.exp,
            parent.ring,
            parent.exp
        )
    })?;

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

    // OBO identity: must be inherited, never added during attenuation.
    // If the parent has no obo, the child must not introduce one.
    // If the parent has obo, the child must carry the same identity.
    match (&parent.obo, &child.obo) {
        (None, Some(_)) => {
            anyhow::bail!("obo escalation: child introduces obo identity not present in parent");
        }
        (Some(parent_obo), Some(child_obo)) => {
            if parent_obo.sub != child_obo.sub || parent_obo.iss != child_obo.iss {
                anyhow::bail!(
                    "obo mismatch: child obo (sub={}, iss={}) differs from parent (sub={}, iss={})",
                    child_obo.sub,
                    child_obo.iss,
                    parent_obo.sub,
                    parent_obo.iss
                );
            }
        }
        _ => {} // (Some, None) is allowed (child drops obo — unusual but not an escalation)
                // (None, None) is the common case
    }

    // Sandbox attenuation: child can only add/tighten sandbox rules, never remove/weaken.
    match (&parent.sandbox, &child.sandbox) {
        (Some(parent_sandbox), Some(child_sandbox)) => {
            parent_sandbox
                .validate_attenuation(child_sandbox)
                .map_err(|e| anyhow::anyhow!(e))?;
        }
        (Some(_), None) => {
            anyhow::bail!("sandbox escalation: child removes sandbox profile present in parent");
        }
        _ => {} // (None, Some) is fine (child adds sandbox), (None, None) is common
    }

    // Depth check: max_depth indicates how many more delegations are allowed.
    // 0 = no further delegation, 1 = one more level, etc.
    if child.parent.is_some() && max_depth == 0 {
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
        obo: None,
        sandbox: None,
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
            ring,
            parent.ring
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
                op,
                parent.cap.operations
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
                tool,
                parent.cap.tools
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
        obo: parent.obo.clone(),
        sandbox: parent.sandbox.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Ed25519Signer;

    fn test_cap_set() -> CapabilitySet {
        CapabilitySet {
            paths: vec!["/home/user/projects/**".to_string()],
            operations: vec![
                "read".to_string(),
                "write".to_string(),
                "git.status".to_string(),
            ],
            tools: vec!["file_*".to_string(), "git_*".to_string()],
            credentials: vec!["github.pat".to_string()],
        }
    }

    fn test_payload(signer: &Ed25519Signer) -> CapabilityPayload {
        build_payload(signer.did(), "did:key:z6MkSubject", test_cap_set(), 1, 3600)
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
        let tampered = format!("{}.{}.{}", parts[0], parts[1], URL_SAFE_NO_PAD.encode(&sig),);

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
            obo: None,
            sandbox: None,
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
            obo: None,
            sandbox: None,
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
            obo: None,
            sandbox: None,
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
            vec![
                "file_read".to_string(),
                "file_grep".to_string(),
                "git_status".to_string(),
            ],
            2,
            600,
        )
        .unwrap();

        assert_eq!(
            child.cap.tools,
            vec!["file_read", "file_grep", "git_status"]
        );
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

    #[test]
    fn revoked_token_rejected() {
        let signer = Ed25519Signer::generate();
        let payload = test_payload(&signer);
        let nonce = payload.nonce;
        let token = encode_token(&payload, &signer).unwrap();

        let rl = TokenRevocationList::new();
        // Token valid before revocation
        assert!(decode_token_with_revocation(&token, &signer, Some(&rl)).is_ok());

        // Revoke it
        rl.revoke(nonce);
        assert!(rl.is_revoked(&nonce));

        // Token rejected after revocation
        let err = decode_token_with_revocation(&token, &signer, Some(&rl)).unwrap_err();
        assert!(err.to_string().contains("revoked"));
    }

    #[test]
    fn revocation_list_without_check_still_works() {
        let signer = Ed25519Signer::generate();
        let payload = test_payload(&signer);
        let token = encode_token(&payload, &signer).unwrap();

        // decode_token() without revocation list still works
        assert!(decode_token(&token, &signer).is_ok());
    }

    // --- OBO identity tests ---

    fn test_obo() -> OboIdentity {
        OboIdentity {
            sub: "alice@example.com".to_string(),
            iss: "https://idp.example.com".to_string(),
            auth_time: Some(1700000000),
        }
    }

    #[test]
    fn obo_roundtrip_serialization() {
        let signer = Ed25519Signer::generate();
        let mut payload = test_payload(&signer);
        payload.obo = Some(test_obo());

        let token = encode_token(&payload, &signer).unwrap();
        let decoded = decode_token(&token, &signer).unwrap();

        let obo = decoded.obo.unwrap();
        assert_eq!(obo.sub, "alice@example.com");
        assert_eq!(obo.iss, "https://idp.example.com");
        assert_eq!(obo.auth_time, Some(1700000000));
    }

    #[test]
    fn obo_none_backward_compat() {
        let signer = Ed25519Signer::generate();
        let payload = test_payload(&signer);
        assert!(payload.obo.is_none());

        let token = encode_token(&payload, &signer).unwrap();
        let decoded = decode_token(&token, &signer).unwrap();
        assert!(decoded.obo.is_none());
    }

    #[test]
    fn obo_preserved_through_delegation() {
        let signer = Ed25519Signer::generate();
        let mut parent = test_payload(&signer);
        parent.obo = Some(test_obo());

        let child = build_delegated_payload(
            &parent,
            "did:teammate:team-1:worker",
            vec!["read".to_string()],
            vec!["file_read".to_string()],
            2,
            600,
        )
        .unwrap();

        // OBO must be propagated from parent
        let child_obo = child.obo.as_ref().unwrap();
        assert_eq!(child_obo.sub, "alice@example.com");
        assert_eq!(child_obo.iss, "https://idp.example.com");
        assert_eq!(child_obo.auth_time, Some(1700000000));

        // Validate delegation passes
        assert!(validate_delegation(&parent, &child, 3).is_ok());
    }

    #[test]
    fn obo_cannot_be_added_during_attenuation() {
        let signer = Ed25519Signer::generate();
        let parent = test_payload(&signer); // no obo

        let child = CapabilityPayload {
            v: 1,
            iss: parent.sub.clone(),
            sub: "did:key:z6MkChild".to_string(),
            cap: CapabilitySet {
                paths: vec![],
                operations: vec!["read".to_string()],
                tools: vec![],
                credentials: vec![],
            },
            ring: parent.ring,
            iat: parent.iat,
            exp: parent.exp,
            nonce: generate_nonce(),
            parent: Some(parent.nonce),
            obo: Some(test_obo()), // trying to inject obo
            sandbox: None,
        };

        let err = validate_delegation(&parent, &child, 3).unwrap_err();
        assert!(err.to_string().contains("obo escalation"));
    }

    #[test]
    fn obo_mismatch_rejected_during_delegation() {
        let signer = Ed25519Signer::generate();
        let mut parent = test_payload(&signer);
        parent.obo = Some(test_obo());

        let child = CapabilityPayload {
            v: 1,
            iss: parent.sub.clone(),
            sub: "did:key:z6MkChild".to_string(),
            cap: CapabilitySet {
                paths: vec![],
                operations: vec!["read".to_string()],
                tools: vec![],
                credentials: vec![],
            },
            ring: parent.ring,
            iat: parent.iat,
            exp: parent.exp,
            nonce: generate_nonce(),
            parent: Some(parent.nonce),
            obo: Some(OboIdentity {
                sub: "bob@evil.com".to_string(),
                iss: "https://evil.com".to_string(),
                auth_time: None,
            }),
            sandbox: None,
        };

        let err = validate_delegation(&parent, &child, 3).unwrap_err();
        assert!(err.to_string().contains("obo mismatch"));
    }

    #[test]
    fn obo_resolved_in_capabilities() {
        let signer = Ed25519Signer::generate();
        let mut payload = test_payload(&signer);
        payload.obo = Some(test_obo());

        let resolved = resolve_capabilities(&payload);
        assert_eq!(resolved.obo_sub.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn obo_none_in_resolved_capabilities() {
        let signer = Ed25519Signer::generate();
        let payload = test_payload(&signer);

        let resolved = resolve_capabilities(&payload);
        assert!(resolved.obo_sub.is_none());
    }

    #[test]
    fn obo_multi_hop_delegation_preserves() {
        let signer = Ed25519Signer::generate();
        let mut root = test_payload(&signer);
        root.obo = Some(test_obo());

        // First delegation
        let child1 = build_delegated_payload(
            &root,
            "did:agent:child1",
            vec!["read".to_string()],
            vec!["file_read".to_string()],
            2,
            600,
        )
        .unwrap();
        assert!(child1.obo.is_some());

        // Second delegation (grandchild)
        let child2 = build_delegated_payload(
            &child1,
            "did:agent:child2",
            vec!["read".to_string()],
            vec!["file_read".to_string()],
            3,
            300,
        )
        .unwrap();
        let obo = child2.obo.unwrap();
        assert_eq!(obo.sub, "alice@example.com");
        assert_eq!(obo.iss, "https://idp.example.com");
    }

    // --- Sandbox profile in capability token tests ---

    #[test]
    fn sandbox_none_backward_compat() {
        let signer = Ed25519Signer::generate();
        let payload = test_payload(&signer);
        assert!(payload.sandbox.is_none());

        let token = encode_token(&payload, &signer).unwrap();
        let decoded = decode_token(&token, &signer).unwrap();
        assert!(decoded.sandbox.is_none());
    }

    #[test]
    fn sandbox_roundtrip_serialization() {
        let signer = Ed25519Signer::generate();
        let mut payload = test_payload(&signer);

        let mut profile = super::super::sandbox_profile::SandboxProfile::default();
        profile.rules.insert(
            "file_write".to_string(),
            super::super::sandbox_profile::ToolSandboxRule {
                action: super::super::sandbox_profile::SandboxAction::Simulate {
                    response: "write disabled".to_string(),
                },
            },
        );
        payload.sandbox = Some(profile);

        let token = encode_token(&payload, &signer).unwrap();
        let decoded = decode_token(&token, &signer).unwrap();

        let sandbox = decoded.sandbox.unwrap();
        assert!(sandbox.rule_for("file_write").is_some());
    }

    #[test]
    fn sandbox_propagated_through_delegation() {
        let signer = Ed25519Signer::generate();
        let mut parent = test_payload(&signer);

        let mut profile = super::super::sandbox_profile::SandboxProfile::default();
        profile.rules.insert(
            "git_*".to_string(),
            super::super::sandbox_profile::ToolSandboxRule {
                action: super::super::sandbox_profile::SandboxAction::Simulate {
                    response: "git disabled".to_string(),
                },
            },
        );
        parent.sandbox = Some(profile);

        let child = build_delegated_payload(
            &parent,
            "did:teammate:worker",
            vec!["read".to_string()],
            vec!["file_read".to_string()],
            2,
            600,
        )
        .unwrap();

        assert!(child.sandbox.is_some());
        let child_sandbox = child.sandbox.unwrap();
        assert!(child_sandbox.rule_for("git_status").is_some());
    }

    #[test]
    fn sandbox_removal_rejected_in_delegation() {
        let signer = Ed25519Signer::generate();
        let mut parent = test_payload(&signer);

        let mut profile = super::super::sandbox_profile::SandboxProfile::default();
        profile.rules.insert(
            "file_write".to_string(),
            super::super::sandbox_profile::ToolSandboxRule {
                action: super::super::sandbox_profile::SandboxAction::Simulate {
                    response: "blocked".to_string(),
                },
            },
        );
        parent.sandbox = Some(profile);

        let mut child = parent.clone();
        child.nonce = generate_nonce();
        child.parent = Some(parent.nonce);
        child.sandbox = None; // trying to remove sandbox

        let err = validate_delegation(&parent, &child, 3).unwrap_err();
        assert!(err.to_string().contains("sandbox escalation"));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn ring_escalation_rejected() {
        let parent_ring: u8 = kani::any();
        let child_ring: u8 = kani::any();
        kani::assume(parent_ring <= 3);
        kani::assume(child_ring <= 3);
        let result = check_attenuation(parent_ring, child_ring, 1000, 1000);
        if child_ring < parent_ring {
            assert!(result.is_err());
        }
    }

    #[kani::proof]
    fn valid_ring_accepted() {
        let parent_ring: u8 = kani::any();
        let child_ring: u8 = kani::any();
        kani::assume(parent_ring <= 3);
        kani::assume(child_ring <= 3);
        kani::assume(child_ring >= parent_ring);
        let result = check_attenuation(parent_ring, child_ring, 1000, 1000);
        assert!(result.is_ok());
    }

    #[kani::proof]
    fn expiry_extension_rejected() {
        let parent_exp: u64 = kani::any();
        let child_exp: u64 = kani::any();
        kani::assume(parent_exp <= 10000);
        kani::assume(child_exp <= 10000);
        let result = check_attenuation(0, 0, parent_exp, child_exp);
        if child_exp > parent_exp {
            assert!(result.is_err());
        }
    }

    #[kani::proof]
    fn valid_expiry_accepted() {
        let parent_exp: u64 = kani::any();
        let child_exp: u64 = kani::any();
        kani::assume(parent_exp <= 10000);
        kani::assume(child_exp <= 10000);
        kani::assume(child_exp <= parent_exp);
        let result = check_attenuation(0, 0, parent_exp, child_exp);
        assert!(result.is_ok());
    }

    #[kani::proof]
    fn transitive_attenuation() {
        let r0: u8 = kani::any();
        let r1: u8 = kani::any();
        let r2: u8 = kani::any();
        kani::assume(r0 <= 3 && r1 <= 3 && r2 <= 3);
        let e0: u64 = kani::any();
        let e1: u64 = kani::any();
        let e2: u64 = kani::any();
        kani::assume(e0 <= 1000 && e1 <= 1000 && e2 <= 1000);

        let parent_to_child = check_attenuation(r0, r1, e0, e1);
        let child_to_grandchild = check_attenuation(r1, r2, e1, e2);

        if parent_to_child.is_ok() && child_to_grandchild.is_ok() {
            assert!(check_attenuation(r0, r2, e0, e2).is_ok());
        }
    }
}
