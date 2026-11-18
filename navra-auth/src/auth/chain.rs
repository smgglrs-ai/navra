//! Composite authenticator that tries multiple backends in order.
//!
//! The [`ChainAuthenticator`] tries each authenticator in sequence,
//! returning the first successful result. This enables backward
//! compatibility: capability tokens are checked first, then legacy
//! BLAKE3 tokens, then development-mode no-auth.

use super::{AgentIdentity, AuthError, Authenticator, is_did_shaped};
use crate::auth::capability;
use crate::identity::{CapSigner, Ed25519Verifier};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Authenticator that verifies `navra_cap_v1.*` capability tokens.
pub struct CapabilityAuthenticator {
    /// Root signer for verifying navra-issued tokens.
    root_verifier: Box<dyn CapSigner>,
    /// Known agent DIDs → verifiers (for delegation chain verification).
    agent_verifiers: HashMap<String, Ed25519Verifier>,
    /// Seen nonces to prevent replay attacks (CWE-294).
    /// Maps nonce → first-seen time. Pruned on access.
    seen_nonces: Mutex<HashMap<[u8; 16], Instant>>,
    /// TTL for nonce cache entries (default: 7200s = 2 hours).
    nonce_cache_ttl: std::time::Duration,
    /// Permission set assigned to capability-authenticated agents.
    /// The token's `cap` field provides additional scoping (operations,
    /// tools); this is the base permission set for path ACLs.
    ///
    /// Defaults to the reserved name [`DEFAULT_CAP_PERMISSION_SET`]:
    /// it is never a registered permission set, so the token's own
    /// embedded capabilities are enforced (least privilege) with the
    /// deny-all "default" set's deny rules layered on top.
    default_permission_set: String,
    /// Shared revocation list consulted on every authentication.
    /// When set, tokens whose nonce appears in the list are rejected.
    revocation_list: Option<Arc<capability::TokenRevocationList>>,
    /// Expected audience (`aud` claim). When set, tokens that carry
    /// an `aud` claim must match it. Tokens without `aud` are still
    /// accepted for backwards compatibility.
    expected_audience: Option<String>,
}

/// Default permission set name for capability-token identities.
///
/// This is a reserved name that operators should never register as a
/// permission set: `PermissionEngine::check_with_capabilities` falls
/// back to the token's embedded capabilities when the named set is
/// absent, which is the least-privilege behavior for capability
/// tokens. Operators who want capability-token identities routed
/// through a registered ACL instead can override it with
/// [`CapabilityAuthenticator::with_permission_set`].
pub const DEFAULT_CAP_PERMISSION_SET: &str = "cap:token";

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
            default_permission_set: DEFAULT_CAP_PERMISSION_SET.to_string(),
            revocation_list: None,
            expected_audience: None,
        }
    }

    pub fn with_permission_set(mut self, perm_set: impl Into<String>) -> Self {
        self.default_permission_set = perm_set.into();
        self
    }

    /// Wire a shared revocation list into the authenticator.
    ///
    /// The caller keeps the [`Arc`] and can revoke tokens at runtime
    /// via [`capability::TokenRevocationList::revoke_token`];
    /// subsequent authentication attempts are rejected.
    pub fn with_revocation_list(
        mut self,
        revocation_list: Arc<capability::TokenRevocationList>,
    ) -> Self {
        self.revocation_list = Some(revocation_list);
        self
    }

    /// Require that tokens carrying an `aud` claim match this audience.
    ///
    /// Tokens without an `aud` claim remain accepted (backwards
    /// compatibility); tokens with a mismatched audience are rejected,
    /// preventing replay across servers.
    pub fn with_expected_audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audience = Some(audience.into());
        self
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
        if !token.starts_with("navra_cap_v1.") {
            return Err(AuthError::InvalidToken);
        }

        // Try root verifier first (navra-issued tokens), consulting
        // the shared revocation list when one is wired in.
        let payload = capability::decode_token_with_revocation(
            token,
            self.root_verifier.as_ref(),
            self.revocation_list.as_deref(),
        )
        .map_err(|_| AuthError::InvalidToken)?;

        // C-2 identity forge: the subject must be a DID-shaped,
        // namespaced identifier. `payload.sub` is caller-controlled
        // at delegation time — a token with a plain-name subject
        // like "ops-admin" would otherwise authenticate as
        // AgentIdentity { name: "ops-admin" } and pass name-based
        // gates (e.g. the config-API self-edit path) as a config
        // agent it is not.
        if !is_did_shaped(&payload.sub) {
            return Err(AuthError::InvalidToken);
        }

        // Audience validation: when the authenticator is configured
        // with an expected audience, tokens that declare an `aud`
        // claim must match it. Tokens without `aud` are accepted
        // for backwards compatibility.
        if let Some(ref expected) = self.expected_audience
            && let Some(ref aud) = payload.aud
            && aud != expected
        {
            return Err(AuthError::InvalidToken);
        }

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
            permissions: self.default_permission_set.clone(),
            signing_key: None,
            did: Some(payload.sub),
            capabilities: Some(resolved),
            model: None,
            allowed_upstreams: Vec::new(),
            max_concurrent: None,
            max_context: None,
            wimse: None,
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

    #[allow(clippy::should_implement_trait)]
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
    use crate::auth::TokenAuthenticator;
    use crate::auth::capability::{CapabilitySet, build_payload, encode_token};
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

    fn make_cap_payload(signer: &Ed25519Signer) -> crate::auth::capability::CapabilityPayload {
        build_payload(
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
        )
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
        // Legacy pre-entropy-policy token: registered via the
        // operator override since "legacy-token" fails the guard.
        blake3_auth.register_allow_weak("legacy-token", AgentIdentity::new("legacy-agent", "dev"));

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
        blake3_auth.register_allow_weak("legacy-token", AgentIdentity::new("legacy-agent", "dev"));

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
        // Default permission set for capability tokens is the reserved
        // least-privilege name, never a permissive set like "dev".
        assert_eq!(identity.permissions, DEFAULT_CAP_PERMISSION_SET);
    }

    #[test]
    fn capability_auth_custom_permission_set() {
        let signer = Ed25519Signer::generate();
        let token = make_cap_token(&signer);
        let auth = CapabilityAuthenticator::new(Box::new(signer)).with_permission_set("readonly");

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.permissions, "readonly");
    }

    #[test]
    fn capability_auth_rejects_revoked_token() {
        let signer = Ed25519Signer::generate();
        let token = make_cap_token(&signer);

        let revocation_list =
            std::sync::Arc::new(crate::auth::capability::TokenRevocationList::new());
        let auth = CapabilityAuthenticator::new(Box::new(signer))
            .with_revocation_list(std::sync::Arc::clone(&revocation_list));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        // Valid before revocation
        assert!(auth.authenticate(&headers).is_ok());

        // Revoke via the shared handle (the navra-server insertion API)
        revocation_list
            .revoke_token(&token, auth.root_verifier.as_ref())
            .unwrap();

        // Rejected after revocation
        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn capability_auth_without_revocation_list_still_works() {
        let signer = Ed25519Signer::generate();
        let token = make_cap_token(&signer);
        let auth = CapabilityAuthenticator::new(Box::new(signer));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        assert!(auth.authenticate(&headers).is_ok());
    }

    fn auth_headers_for(signer: &Ed25519Signer, subject: &str) -> HeaderMap {
        let cap = CapabilitySet {
            paths: vec!["/home/**".to_string()],
            operations: vec!["read".to_string()],
            tools: vec![],
            credentials: vec![],
        };
        let payload = build_payload(signer.did(), subject, cap, 2, 3600);
        let token = encode_token(&payload, signer).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers
    }

    #[test]
    fn capability_auth_rejects_plain_name_subject() {
        // C-2: a delegated token whose subject is a bare agent name
        // ("ops-admin") must not authenticate — it would forge
        // AgentIdentity.name and pass name-based gates.
        let signer = std::sync::Arc::new(Ed25519Signer::generate());
        for subject in ["ops-admin", "admin", "did:", "agent:", ""] {
            let headers = auth_headers_for(&signer, subject);
            let auth = CapabilityAuthenticator::new(Box::new(std::sync::Arc::clone(&signer)));
            assert!(
                auth.authenticate(&headers).is_err(),
                "subject {subject:?} must be rejected"
            );
        }
    }

    #[test]
    fn capability_auth_accepts_did_shaped_subjects() {
        let signer = std::sync::Arc::new(Ed25519Signer::generate());
        for subject in [
            "did:key:z6MkSubject",
            "did:teammate:team-1:researcher",
            "did:pool:navra-agents",
            "agent:worker-1",
        ] {
            let headers = auth_headers_for(&signer, subject);
            let auth = CapabilityAuthenticator::new(Box::new(std::sync::Arc::clone(&signer)));
            let identity = auth
                .authenticate(&headers)
                .unwrap_or_else(|e| panic!("subject {subject:?} must authenticate: {e}"));
            assert_eq!(identity.name, subject);
        }
    }

    #[test]
    fn capability_auth_audience_mismatch_rejected() {
        let signer = Ed25519Signer::generate();
        let mut payload = make_cap_payload(&signer);
        payload.aud = Some("https://server-a.example.com".to_string());
        let token = crate::auth::capability::encode_token(&payload, &signer).unwrap();

        let auth = CapabilityAuthenticator::new(Box::new(signer))
            .with_expected_audience("https://server-b.example.com");

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        assert!(auth.authenticate(&headers).is_err());
    }

    #[test]
    fn capability_auth_audience_match_accepted() {
        let signer = Ed25519Signer::generate();
        let mut payload = make_cap_payload(&signer);
        payload.aud = Some("https://server-a.example.com".to_string());
        let token = crate::auth::capability::encode_token(&payload, &signer).unwrap();

        let auth = CapabilityAuthenticator::new(Box::new(signer))
            .with_expected_audience("https://server-a.example.com");

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        assert!(auth.authenticate(&headers).is_ok());
    }

    #[test]
    fn capability_auth_audience_none_accepted_for_compat() {
        let signer = Ed25519Signer::generate();
        // Token without an aud claim
        let token = make_cap_token(&signer);
        let auth = CapabilityAuthenticator::new(Box::new(signer))
            .with_expected_audience("https://any-server.example.com");

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        // Backwards compat: no aud claim, no validation
        assert!(auth.authenticate(&headers).is_ok());
    }
}
