pub mod capability;
pub mod chain;
pub mod oauth;
pub mod openshell;
pub mod sandbox_profile;

use std::fmt;

/// Identity of an authenticated agent.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub name: String,
    pub permissions: String,
    /// Path to an Ed25519 private key for commit signing.
    pub signing_key: Option<String>,
    /// DID:key identifier (set when using capability tokens).
    pub did: Option<String>,
    /// Resolved capabilities from a verified capability token.
    /// When `Some`, these override the PermissionEngine path.
    pub capabilities: Option<capability::ResolvedCapabilities>,
}

impl fmt::Display for AgentIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name, self.permissions)
    }
}

/// Context available to tool handlers during a call.
#[derive(Debug, Clone)]
pub struct CallContext {
    pub agent: AgentIdentity,
    pub session_id: String,
    /// IFC taint tracker for this session. Accumulates the highest
    /// data label seen across tool calls. Taint only rises.
    pub taint: crate::ifc::TaintTracker,
    /// Remaining token budget for this call's response. When set,
    /// modules should self-compress tool output to fit within this
    /// limit. None = no budget constraint.
    pub remaining_tokens: Option<u32>,
    /// Sandbox profile from the agent's capability token.
    /// When `Some`, the `SandboxHook` applies per-tool transformations
    /// (simulate, redact, rate-limit, path rewrite).
    pub sandbox: Option<sandbox_profile::SandboxProfile>,
}

impl CallContext {
    /// Create a new call context with a clean taint tracker.
    pub fn new(agent: AgentIdentity, session_id: impl Into<String>) -> Self {
        Self {
            agent,
            session_id: session_id.into(),
            taint: crate::ifc::TaintTracker::new(),
            remaining_tokens: None,
            sandbox: None,
        }
    }
}

/// Error returned by authentication.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing authorization header")]
    MissingToken,
    #[error("invalid token")]
    InvalidToken,
    #[error("agent not found: {0}")]
    AgentNotFound(String),
}

/// Trait for pluggable authentication backends.
///
/// Implementations extract agent identity from HTTP request headers.
pub trait Authenticator: Send + Sync + 'static {
    fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<AgentIdentity, AuthError>;
}

/// Token-based authenticator using BLAKE3-hashed bearer tokens.
pub struct TokenAuthenticator {
    /// Map from BLAKE3 hash of token → AgentIdentity.
    agents: std::collections::HashMap<String, AgentIdentity>,
}

impl Default for TokenAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenAuthenticator {
    pub fn new() -> Self {
        Self {
            agents: std::collections::HashMap::new(),
        }
    }

    /// Register an agent by raw token. The token is hashed immediately.
    pub fn register(&mut self, token: &str, identity: AgentIdentity) {
        let hash = Self::hash_token(token);
        self.agents.insert(hash, identity);
    }

    /// Register an agent by pre-computed BLAKE3 hash (from config).
    pub fn register_hash(&mut self, hash: &str, identity: AgentIdentity) {
        self.agents.insert(hash.to_string(), identity);
    }

    /// Compute the BLAKE3 hash of a token, returned as a hex string.
    pub fn hash_token(token: &str) -> String {
        blake3::hash(token.as_bytes()).to_hex().to_string()
    }
}

impl Authenticator for TokenAuthenticator {
    fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<AgentIdentity, AuthError> {
        let header = headers
            .get("authorization")
            .ok_or(AuthError::MissingToken)?;

        let value = header.to_str().map_err(|_| AuthError::InvalidToken)?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidToken)?;

        let hash = Self::hash_token(token);
        // Iterate all entries for constant-time behavior — prevents
        // timing side-channel on hash prefix matching (CWE-208).
        let mut found: Option<&AgentIdentity> = None;
        // All BLAKE3 hashes are 64 hex chars — length check is safe but
        // removed to maintain strict constant-time contract.
        let hash_bytes = hash.as_bytes();
        for (stored_hash, identity) in &self.agents {
            let stored_bytes = stored_hash.as_bytes();
            // Constant-time comparison: XOR all bytes, OR into accumulator
            let equal = if stored_bytes.len() == hash_bytes.len() {
                stored_bytes
                    .iter()
                    .zip(hash_bytes)
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            } else {
                1u8 // different lengths — always mismatch
            };
            if equal == 0 {
                found = Some(identity);
            }
        }
        found.cloned().ok_or(AuthError::InvalidToken)
    }
}

/// No-op authenticator that always returns a default identity.
/// For development/testing only.
pub struct NoAuthenticator {
    pub default_identity: AgentIdentity,
}

impl AgentIdentity {
    /// Create an identity without optional fields (convenience for tests).
    pub fn new(name: impl Into<String>, permissions: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            permissions: permissions.into(),
            signing_key: None,
            did: None,
            capabilities: None,
        }
    }
}

// Manual PartialEq/Eq/Hash — only compare identity fields, not capabilities.
impl PartialEq for AgentIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.permissions == other.permissions
    }
}
impl Eq for AgentIdentity {}
impl std::hash::Hash for AgentIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.permissions.hash(state);
    }
}

impl Authenticator for NoAuthenticator {
    fn authenticate(&self, _headers: &axum::http::HeaderMap) -> Result<AgentIdentity, AuthError> {
        Ok(self.default_identity.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn test_identity() -> AgentIdentity {
        AgentIdentity::new("test-agent", "developer")
    }

    #[test]
    fn token_auth_register_and_authenticate() {
        let mut auth = TokenAuthenticator::new();
        auth.register("secret-token-123", test_identity());

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer secret-token-123".parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "test-agent");
        assert_eq!(identity.permissions, "developer");
    }

    #[test]
    fn token_auth_missing_header() {
        let auth = TokenAuthenticator::new();
        let headers = HeaderMap::new();
        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::MissingToken));
    }

    #[test]
    fn token_auth_invalid_token() {
        let mut auth = TokenAuthenticator::new();
        auth.register("correct-token", test_identity());

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer wrong-token".parse().unwrap());

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn token_auth_missing_bearer_prefix() {
        let auth = TokenAuthenticator::new();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Token abc".parse().unwrap());

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn no_auth_always_succeeds() {
        let auth = NoAuthenticator {
            default_identity: test_identity(),
        };
        let headers = HeaderMap::new();
        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "test-agent");
    }

    #[test]
    fn agent_identity_display() {
        let id = test_identity();
        assert_eq!(format!("{id}"), "test-agent(developer)");
    }

    #[test]
    fn hash_token_is_deterministic() {
        let hash1 = TokenAuthenticator::hash_token("my-secret-token");
        let hash2 = TokenAuthenticator::hash_token("my-secret-token");
        assert_eq!(hash1, hash2);
        // BLAKE3 hashes are 64 hex chars
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn hash_token_differs_for_different_tokens() {
        let hash1 = TokenAuthenticator::hash_token("token-a");
        let hash2 = TokenAuthenticator::hash_token("token-b");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn register_hash_authenticates() {
        let hash = TokenAuthenticator::hash_token("my-token");
        let mut auth = TokenAuthenticator::new();
        auth.register_hash(&hash, test_identity());

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer my-token".parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "test-agent");
    }
}
