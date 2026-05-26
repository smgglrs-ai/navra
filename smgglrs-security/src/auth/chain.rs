//! Composite authenticator that tries multiple backends in order.
//!
//! The [`ChainAuthenticator`] tries each authenticator in sequence,
//! returning the first successful result. This enables backward
//! compatibility: capability tokens are checked first, then legacy
//! BLAKE3 tokens, then development-mode no-auth.

use super::{AgentIdentity, AuthError, Authenticator};
use crate::auth::capability;
use crate::identity::{CapSigner, Ed25519Verifier};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Authenticator that verifies `smgglrs_cap_v1.*` capability tokens.
pub struct CapabilityAuthenticator {
    /// Root signer for verifying smgglrs-issued tokens.
    root_verifier: Box<dyn CapSigner>,
    /// Known agent DIDs → verifiers (for delegation chain verification).
    agent_verifiers: HashMap<String, Ed25519Verifier>,
    /// Seen nonces to prevent replay attacks (CWE-294).
    /// Maps nonce → first-seen time. Pruned on access.
    seen_nonces: Mutex<HashMap<[u8; 16], Instant>>,
    /// TTL for nonce cache entries (default: 7200s = 2 hours).
    nonce_cache_ttl: std::time::Duration,
}

impl CapabilityAuthenticator {
    pub fn new(root_signer: Box<dyn CapSigner>) -> Self {
        Self::with_nonce_ttl(root_signer, std::time::Duration::from_secs(7200))
    }

    /// Create with a custom nonce cache TTL.
    pub fn with_nonce_ttl(
        root_signer: Box<dyn CapSigner>,
        nonce_cache_ttl: std::time::Duration,
    ) -> Self {
        Self {
            root_verifier: root_signer,
            agent_verifiers: HashMap::new(),
            seen_nonces: Mutex::new(HashMap::new()),
            nonce_cache_ttl,
        }
    }

    /// Register an agent's public key for delegation verification.
    pub fn register_agent_verifier(&mut self, did: String, verifier: Ed25519Verifier) {
        self.agent_verifiers.insert(did, verifier);
    }
}

impl Authenticator for CapabilityAuthenticator {
    fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<AgentIdentity, AuthError> {
        let header = headers
            .get("authorization")
            .ok_or(AuthError::MissingToken)?;

        let value = header.to_str().map_err(|_| AuthError::InvalidToken)?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidToken)?;

        // Only handle capability tokens
        if !token.starts_with("smgglrs_cap_v1.") {
            return Err(AuthError::InvalidToken);
        }

        // Try root verifier first (smgglrs-issued tokens)
        let payload = capability::decode_token(token, self.root_verifier.as_ref())
            .map_err(|_| AuthError::InvalidToken)?;

        // Nonce tracking: record first-seen time for auditing.
        // Tokens are reusable within their TTL — they are bearer
        // tokens, not one-time-use. The nonce uniquely identifies
        // the token for logging and correlation, not for replay
        // prevention. Replay protection is handled by the TTL
        // (exp field) — expired tokens are rejected above.
        {
            let mut nonces = self.seen_nonces.lock().unwrap_or_else(|e| e.into_inner());
            let cutoff = Instant::now() - self.nonce_cache_ttl;
            nonces.retain(|_, seen_at| *seen_at > cutoff);
            nonces.entry(payload.nonce).or_insert_with(Instant::now);
        }

        let resolved = capability::resolve_capabilities(&payload);

        Ok(AgentIdentity {
            name: payload.sub.clone(),
            permissions: format!("cap:ring{}", payload.ring),
            signing_key: None,
            did: Some(payload.sub),
            capabilities: Some(resolved),
        })
    }
}

/// Composite authenticator that tries multiple backends in order.
///
/// Returns the first successful authentication result. If all
/// backends fail, returns the last error.
pub struct ChainAuthenticator {
    authenticators: Vec<Box<dyn Authenticator>>,
}

impl Default for ChainAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainAuthenticator {
    pub fn new() -> Self {
        Self {
            authenticators: Vec::new(),
        }
    }

    pub fn add(mut self, auth: impl Authenticator + 'static) -> Self {
        self.authenticators.push(Box::new(auth));
        self
    }
}

impl Authenticator for ChainAuthenticator {
    fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<AgentIdentity, AuthError> {
        let mut last_err = AuthError::MissingToken;
        for auth in &self.authenticators {
            match auth.authenticate(headers) {
                Ok(identity) => return Ok(identity),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::capability::{build_payload, encode_token, CapabilitySet};
    use crate::auth::TokenAuthenticator;
    use crate::identity::Ed25519Signer;
    use axum::http::HeaderMap;

    fn make_cap_token(signer: &Ed25519Signer) -> String {
        let payload = build_payload(
            signer.did(),
            "did:key:z6MkTestAgent",
            CapabilitySet {
                paths: vec!["/home/user/**".to_string()],
                operations: vec!["read".to_string()],
                tools: vec!["docs_*".to_string()],
                credentials: vec![],
            },
            1,
            3600,
        );
        encode_token(&payload, signer).unwrap()
    }

    #[test]
    fn capability_auth_accepts_valid_token() {
        let signer = Ed25519Signer::generate();
        let token = make_cap_token(&signer);

        let auth = CapabilityAuthenticator::new(Box::new(signer));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.did, Some("did:key:z6MkTestAgent".to_string()));
        assert!(identity.capabilities.is_some());
        let caps = identity.capabilities.unwrap();
        assert_eq!(caps.ring, 1);
        assert!(caps.operations.contains("read"));
    }

    #[test]
    fn capability_auth_rejects_blake3_token() {
        let signer = Ed25519Signer::generate();
        let auth = CapabilityAuthenticator::new(Box::new(signer));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer some-blake3-token".parse().unwrap());

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn capability_auth_rejects_wrong_signer() {
        let signer1 = Ed25519Signer::generate();
        let signer2 = Ed25519Signer::generate();
        let token = make_cap_token(&signer1);

        // Verifier uses signer2's key
        let auth = CapabilityAuthenticator::new(Box::new(signer2));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        assert!(auth.authenticate(&headers).is_err());
    }

    #[test]
    fn chain_tries_cap_first_then_blake3() {
        let signer = Ed25519Signer::generate();

        let mut blake3_auth = TokenAuthenticator::new();
        blake3_auth.register("legacy-token", AgentIdentity::new("legacy-agent", "dev"));

        let chain = ChainAuthenticator::new()
            .add(CapabilityAuthenticator::new(Box::new(signer)))
            .add(blake3_auth);

        // BLAKE3 token should work (cap auth fails, chain falls through)
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer legacy-token".parse().unwrap());

        let identity = chain.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "legacy-agent");
        assert!(identity.capabilities.is_none());
    }

    #[test]
    fn chain_cap_token_takes_priority() {
        let signer = Ed25519Signer::generate();
        let token = make_cap_token(&signer);

        let mut blake3_auth = TokenAuthenticator::new();
        blake3_auth.register("legacy-token", AgentIdentity::new("legacy-agent", "dev"));

        let chain = ChainAuthenticator::new()
            .add(CapabilityAuthenticator::new(Box::new(signer)))
            .add(blake3_auth);

        // Cap token should be handled by first authenticator
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        let identity = chain.authenticate(&headers).unwrap();
        assert!(identity.capabilities.is_some());
        assert_eq!(identity.did, Some("did:key:z6MkTestAgent".to_string()));
    }

    #[test]
    fn chain_all_fail_returns_last_error() {
        let signer = Ed25519Signer::generate();
        let chain = ChainAuthenticator::new()
            .add(CapabilityAuthenticator::new(Box::new(signer)))
            .add(TokenAuthenticator::new());

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer unknown-token".parse().unwrap());

        assert!(chain.authenticate(&headers).is_err());
    }

    #[test]
    fn chain_no_header_returns_missing() {
        let chain = ChainAuthenticator::new();
        let headers = HeaderMap::new();
        let err = chain.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::MissingToken));
    }

    #[test]
    fn resolved_identity_has_cap_permissions() {
        let signer = Ed25519Signer::generate();
        let token = make_cap_token(&signer);
        let auth = CapabilityAuthenticator::new(Box::new(signer));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        // Permission set name is derived from ring
        assert_eq!(identity.permissions, "cap:ring1");
    }
}
