pub mod capability;
pub mod chain;
pub mod idjag;
pub mod oauth;
pub mod oauth_client;
pub mod openshell;
pub mod sandbox_profile;
pub mod wimse;

use std::fmt;
use subtle::ConstantTimeEq;
use vstd::prelude::*;

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
    /// Resolved model name (agent override > permission set default).
    pub model: Option<String>,
    /// Upstream MCP servers visible to this agent. Empty = all.
    pub allowed_upstreams: Vec<String>,
    /// Maximum concurrent tool calls for this agent.
    pub max_concurrent: Option<u32>,
    /// Context window cap for this agent's model requests.
    pub max_context: Option<u32>,
    /// WIMSE/SPIFFE identity (set when authenticated via WIMSE provider).
    pub wimse: Option<wimse::WimseIdentity>,
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
    /// MRTR (SEP-2322) retry fields from the client's `tools/call`
    /// request: responses to a previous `input_required` round and the
    /// opaque request state to echo back. Forwarded verbatim to
    /// upstreams on follow-up rounds; local tools ignore them.
    pub mrtr_input_responses: Option<std::collections::BTreeMap<String, serde_json::Value>>,
    /// Opaque MRTR request state from the client's `tools/call`
    /// request. See [`Self::mrtr_input_responses`].
    pub mrtr_request_state: Option<String>,
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
            mrtr_input_responses: None,
            mrtr_request_state: None,
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

/// Error returned when a bearer token fails the entropy policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WeakTokenError {
    #[error(
        "bearer token too short: {len} chars, minimum {min} \
         (use a machine-generated 256-bit token; override with \
         register_allow_weak if you accept the risk)"
    )]
    TooShort { len: usize, min: usize },
    #[error(
        "bearer token matches a low-entropy pattern ('{pattern}'); \
         use a machine-generated random token (override with \
         register_allow_weak if you accept the risk)"
    )]
    LowEntropy { pattern: String },
}

/// Minimum bearer-token length accepted by [`TokenAuthenticator::register`].
///
/// Static bearer tokens are stored as unsalted BLAKE3 hashes (see
/// [`TokenAuthenticator::hash_token`]). BLAKE3 is a fast, unsalted
/// hash: it is only safe for high-entropy, machine-generated tokens
/// (≥ 32 chars, ≥ 128 bits of randomness) where offline brute-force
/// is infeasible. Human-chosen passwords must not be used.
pub const MIN_TOKEN_LENGTH: usize = 32;

/// Substrings that mark a token as low-entropy (human-chosen).
/// Short numeric/alpha runs like "1234" or "abcdef" are deliberately
/// excluded: they occur naturally in machine-generated hex tokens.
const LOW_ENTROPY_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api-key",
    "key",
    "admin",
    "root",
    "test",
    "dev",
    "development",
    "navra",
    "qwerty",
    "123456",
    "letmein",
    "welcome",
    "changeme",
    "example",
    "sample",
];

/// Check a raw bearer token against the entropy policy.
///
/// Policy: tokens must be at least [`MIN_TOKEN_LENGTH`] chars and must
/// not contain obvious low-entropy substrings, consist of a single
/// repeated character, or be all digits. This is a heuristic guard,
/// not a substitute for machine generation — use a CSPRNG.
fn check_token_entropy(token: &str) -> Result<(), WeakTokenError> {
    if token.chars().count() < MIN_TOKEN_LENGTH {
        return Err(WeakTokenError::TooShort {
            len: token.chars().count(),
            min: MIN_TOKEN_LENGTH,
        });
    }
    if token.chars().all(|c| c.is_ascii_digit()) {
        return Err(WeakTokenError::LowEntropy {
            pattern: "all digits".to_string(),
        });
    }
    let first = token.chars().next().unwrap();
    if token.chars().all(|c| c == first) {
        return Err(WeakTokenError::LowEntropy {
            pattern: "single repeated character".to_string(),
        });
    }
    let lower = token.to_lowercase();
    for pattern in LOW_ENTROPY_PATTERNS {
        if lower.contains(pattern) {
            return Err(WeakTokenError::LowEntropy {
                pattern: pattern.to_string(),
            });
        }
    }
    Ok(())
}

/// Error returned when a `token_hash` value passed to
/// [`TokenAuthenticator::register_hash`] is not a well-formed
/// BLAKE3 digest.
///
/// The most common cause is an operator pasting the raw bearer
/// token into the config's `token_hash` field: the agent then
/// silently never authenticates (its lookup key is the hash of the
/// token, not the token) and the plaintext secret sits in config.
/// BLAKE3 digests are exactly 64 lowercase hex characters — anything
/// else is rejected up front with a descriptive error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenHashError {
    #[error(
        "token_hash must be exactly 64 lowercase hex characters \
         (the BLAKE3 digest of the bearer token); got {len} \
         characters — if this is the raw token, run \
         `navra token generate` and store the printed Hash value"
    )]
    WrongLength { len: usize },
    #[error(
        "token_hash contains non-hexadecimal characters — this \
         looks like a raw bearer token pasted instead of its BLAKE3 \
         hash; run `navra token generate` and store the printed \
         Hash value in token_hash"
    )]
    NotHex,
    #[error(
        "token_hash must be lowercase hex (blake3 emits lowercase \
         digests); lowercase the value and retry"
    )]
    Uppercase,
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
    ///
    /// Enforces the entropy policy: tokens shorter than
    /// [`MIN_TOKEN_LENGTH`] or matching obvious low-entropy patterns
    /// are rejected, because the stored hash is an unsalted BLAKE3
    /// digest that offers no protection against offline brute-force
    /// of weak secrets.
    pub fn register(&mut self, token: &str, identity: AgentIdentity) -> Result<(), WeakTokenError> {
        check_token_entropy(token)?;
        let hash = Self::hash_token(token);
        self.agents.insert(hash, identity);
        Ok(())
    }

    /// Register an agent by raw token, skipping the entropy guard.
    ///
    /// Operator override for deployments that accept the risk of
    /// weak bearer tokens under unsalted BLAKE3 hashing. Prefer
    /// rotating to a machine-generated token instead.
    pub fn register_allow_weak(&mut self, token: &str, identity: AgentIdentity) {
        let hash = Self::hash_token(token);
        self.agents.insert(hash, identity);
    }

    /// Register an agent by pre-computed BLAKE3 hash (from config).
    ///
    /// The value must be exactly 64 lowercase hex characters — the
    /// output format of [`TokenAuthenticator::hash_token`]. Anything
    /// else (notably a raw bearer token pasted into the config's
    /// `token_hash` field) is rejected with
    /// [`TokenHashError`]: a malformed value would otherwise never
    /// match any incoming token, silently locking the agent out
    /// while leaving a plaintext secret in the config file.
    ///
    /// The entropy policy cannot be enforced here: a hash carries no
    /// recoverable entropy signal (every hash looks random). Operators
    /// supplying `token_hash` values from config are responsible for
    /// generating them from high-entropy tokens; use
    /// [`TokenAuthenticator::hash_token`] on a machine-generated
    /// 256-bit token.
    pub fn register_hash(
        &mut self,
        hash: &str,
        identity: AgentIdentity,
    ) -> Result<(), TokenHashError> {
        if hash.chars().count() != 64 {
            return Err(TokenHashError::WrongLength {
                len: hash.chars().count(),
            });
        }
        let bytes = hash.as_bytes();
        if !bytes
            .iter()
            .all(|&b| b.is_ascii_digit() || b.is_ascii_lowercase() && b.is_ascii_hexdigit())
        {
            if bytes.iter().all(|&b| b.is_ascii_hexdigit()) {
                // Right alphabet and length, but some characters are
                // uppercase: blake3 never emits uppercase hex.
                return Err(TokenHashError::Uppercase);
            }
            return Err(TokenHashError::NotHex);
        }
        self.agents.insert(hash.to_string(), identity);
        Ok(())
    }

    /// Compute the BLAKE3 hash of a token, returned as a hex string.
    ///
    /// **Why unsalted BLAKE3 is acceptable here**: this is a lookup
    /// key over machine-generated 256-bit bearer tokens, not a
    /// password-storage hash. Salting would break O(1) lookup, and
    /// the threat model is table lookup, not offline cracking — a
    /// random 256-bit token has ~2^128 collision-resistance worth of
    /// entropy, making brute-force infeasible even against a fast
    /// unsalted hash. This is ONLY safe for high-entropy tokens:
    /// human-chosen passwords would be trivially crackable, which is
    /// why [`TokenAuthenticator::register`] enforces an entropy guard.
    pub fn hash_token(token: &str) -> String {
        blake3::hash(token.as_bytes()).to_hex().to_string()
    }
}

/// Constant-time byte comparison via the `subtle` crate (CWE-208).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

impl Authenticator for TokenAuthenticator {
    fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<AgentIdentity, AuthError> {
        // Accept token from Authorization: Bearer or x-api-key header.
        // x-api-key is checked as fallback so Anthropic SDK clients
        // (Claude Code) can authenticate with ANTHROPIC_API_KEY.
        let token = if let Some(header) = headers.get("authorization") {
            let value = header.to_str().map_err(|_| AuthError::InvalidToken)?;
            value
                .strip_prefix("Bearer ")
                .ok_or(AuthError::InvalidToken)?
        } else if let Some(header) = headers.get("x-api-key") {
            header.to_str().map_err(|_| AuthError::InvalidToken)?
        } else {
            return Err(AuthError::MissingToken);
        };

        let hash = Self::hash_token(token);
        // Iterate all entries for constant-time behavior — prevents
        // timing side-channel on hash prefix matching (CWE-208).
        let mut found: Option<&AgentIdentity> = None;
        let hash_bytes = hash.as_bytes();
        for (stored_hash, identity) in &self.agents {
            let stored_bytes = stored_hash.as_bytes();
            if constant_time_eq(stored_bytes, hash_bytes) {
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
            model: None,
            allowed_upstreams: Vec::new(),
            max_concurrent: None,
            max_context: None,
            wimse: None,
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

    /// Machine-generated-looking 43-char token that passes the
    /// entropy guard (no common words, mixed alphanumerics).
    const STRONG_TOKEN: &str = "9f3k2m8q4v7w1z5x0b6n3c8d5g4h2j7l9r4t6y8u";

    #[test]
    fn token_auth_register_and_authenticate() {
        let mut auth = TokenAuthenticator::new();
        auth.register(STRONG_TOKEN, test_identity()).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {STRONG_TOKEN}").parse().unwrap(),
        );

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
        auth.register(STRONG_TOKEN, test_identity()).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer 0w9o8e7u6t5s4r3q2p1o0i9u8y7t6r5e4w3q2p1o"
                .parse()
                .unwrap(),
        );

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
    fn x_api_key_authenticates() {
        let mut auth = TokenAuthenticator::new();
        auth.register(STRONG_TOKEN, test_identity()).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", STRONG_TOKEN.parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "test-agent");
    }

    #[test]
    fn x_api_key_invalid_token() {
        let mut auth = TokenAuthenticator::new();
        auth.register(STRONG_TOKEN, test_identity()).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-api-key",
            "0w9o8e7u6t5s4r3q2p1o0i9u8y7t6r5e4w3q2p1o".parse().unwrap(),
        );

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn authorization_header_takes_precedence_over_x_api_key() {
        let mut auth = TokenAuthenticator::new();
        let id_a = AgentIdentity::new("agent-a", "dev");
        let id_b = AgentIdentity::new("agent-b", "dev");
        auth.register("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2", id_a)
            .unwrap();
        auth.register("z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0f9e8", id_b)
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "x-api-key",
            "z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0f9e8"
                .parse()
                .unwrap(),
        );

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "agent-a");
    }

    #[test]
    fn register_hash_authenticates() {
        let hash = TokenAuthenticator::hash_token(STRONG_TOKEN);
        let mut auth = TokenAuthenticator::new();
        auth.register_hash(&hash, test_identity()).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {STRONG_TOKEN}").parse().unwrap(),
        );

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "test-agent");
    }

    // --- register_hash format validation tests ---

    #[test]
    fn register_hash_accepts_valid_64_hex() {
        let mut auth = TokenAuthenticator::new();
        let hash = TokenAuthenticator::hash_token(STRONG_TOKEN);
        assert!(auth.register_hash(&hash, test_identity()).is_ok());

        // Hand-built 64-lowercase-hex value is accepted (any
        // well-formed digest shape is; matching a real token is the
        // operator's responsibility).
        let other = "0123456789abcdef".repeat(4);
        assert!(auth.register_hash(&other, test_identity()).is_ok());
    }

    #[test]
    fn register_hash_rejects_raw_token() {
        // An operator pasted the raw bearer token into token_hash:
        // 'mcd_' + 64 hex = 68 chars — the length check fires first,
        // with an error that names the raw-token mistake. Must be
        // rejected, not silently stored as a never-matching key.
        let mut auth = TokenAuthenticator::new();
        let raw = format!("mcd_{}", "0123456789abcdef".repeat(4));
        let err = auth.register_hash(&raw, test_identity()).unwrap_err();
        assert!(matches!(err, TokenHashError::WrongLength { len: 68 }));

        // A 64-char raw token (no mcd_ prefix) trips the hex check.
        let raw64 = format!("{}1", "z".repeat(63));
        assert_eq!(raw64.chars().count(), 64);
        let err = auth.register_hash(&raw64, test_identity()).unwrap_err();
        assert!(matches!(err, TokenHashError::NotHex));

        // Nothing was registered by the failed attempt.
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {raw}").parse().unwrap());
        assert!(auth.authenticate(&headers).is_err());
    }

    #[test]
    fn register_hash_rejects_wrong_length() {
        let mut auth = TokenAuthenticator::new();
        // 63 chars (one short)
        let short = "a".repeat(63);
        let err = auth.register_hash(&short, test_identity()).unwrap_err();
        assert!(matches!(err, TokenHashError::WrongLength { len: 63 }));

        // 65 chars (one long)
        let long = "a".repeat(65);
        let err = auth.register_hash(&long, test_identity()).unwrap_err();
        assert!(matches!(err, TokenHashError::WrongLength { len: 65 }));

        // Empty
        let err = auth.register_hash("", test_identity()).unwrap_err();
        assert!(matches!(err, TokenHashError::WrongLength { len: 0 }));
    }

    #[test]
    fn register_hash_rejects_uppercase_hex() {
        // Uppercase is rejected, not normalized: blake3 digests are
        // lowercase, and accepting both would double the stored-key
        // space. The operator lowercases the config value instead.
        let mut auth = TokenAuthenticator::new();
        let hash = TokenAuthenticator::hash_token(STRONG_TOKEN);
        let upper = hash.to_uppercase();
        let err = auth.register_hash(&upper, test_identity()).unwrap_err();
        assert!(matches!(err, TokenHashError::Uppercase));
    }

    #[test]
    fn register_hash_rejects_non_hex_chars() {
        // Right length, but 'g'-'z' are not hex digits.
        let mut auth = TokenAuthenticator::new();
        let bad = "g".repeat(64);
        let err = auth.register_hash(&bad, test_identity()).unwrap_err();
        assert!(matches!(err, TokenHashError::NotHex));

        // Mixed: mostly hex with one non-hex char.
        let mut mixed = "0123456789abcdef".repeat(4);
        mixed.replace_range(7..8, "z");
        let err = auth.register_hash(&mixed, test_identity()).unwrap_err();
        assert!(matches!(err, TokenHashError::NotHex));
    }

    // --- Entropy guard tests ---

    #[test]
    fn register_rejects_short_token() {
        let mut auth = TokenAuthenticator::new();
        let err = auth.register("short", test_identity()).unwrap_err();
        assert!(matches!(err, WeakTokenError::TooShort { len: 5, .. }));

        // Boundary: exactly MIN_TOKEN_LENGTH chars of a strong-looking
        // token is accepted.
        let ok_token = "q7w1e5r9t2u6i0o3p8a4s7d2f5g8hj5k";
        assert_eq!(ok_token.chars().count(), MIN_TOKEN_LENGTH);
        assert!(auth.register(ok_token, test_identity()).is_ok());
    }

    #[test]
    fn register_rejects_low_entropy_patterns() {
        let mut auth = TokenAuthenticator::new();
        // Long enough, but contains "password"
        let err = auth
            .register("passwordpasswordpasswordpassword12345", test_identity())
            .unwrap_err();
        assert!(matches!(err, WeakTokenError::LowEntropy { .. }));

        // All digits
        let err = auth
            .register("1234567890123456789012345678901234567890", test_identity())
            .unwrap_err();
        assert!(matches!(err, WeakTokenError::LowEntropy { .. }));

        // Single repeated character
        let err = auth
            .register("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", test_identity())
            .unwrap_err();
        assert!(matches!(err, WeakTokenError::LowEntropy { .. }));

        // Nothing registered by the failed attempts
        let headers = HeaderMap::new();
        assert!(auth.authenticate(&headers).is_err());
    }

    #[test]
    fn register_allow_weak_overrides_guard() {
        let mut auth = TokenAuthenticator::new();
        // Operator-accepted risk: weak token still registers
        auth.register_allow_weak("sekrit", test_identity());

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sekrit".parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "test-agent");
    }
}

verus! {

// Constant-time equality modeled as pure function.
// ct_eq(a, b) ≡ (a == b) for equal-length slices, false for different lengths.
spec fn spec_ct_eq(a_len: nat, b_len: nat, content_equal: bool) -> bool {
    a_len == b_len && content_equal
}

proof fn ct_eq_correct(a_len: nat, b_len: nat, content_equal: bool)
    requires a_len == b_len,
    ensures spec_ct_eq(a_len, b_len, content_equal) == content_equal,
{}

proof fn ct_eq_different_lengths_false(a_len: nat, b_len: nat, content_equal: bool)
    requires a_len != b_len,
    ensures !spec_ct_eq(a_len, b_len, content_equal),
{}

} // verus!

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn ct_eq_correct() {
        let a: [u8; 4] = kani::any();
        let b: [u8; 4] = kani::any();
        let result = constant_time_eq(&a, &b);
        let naive = a == b;
        assert_eq!(result, naive);
    }

    #[kani::proof]
    fn ct_eq_different_lengths_false() {
        let a: [u8; 4] = kani::any();
        let b: [u8; 3] = kani::any();
        assert!(!constant_time_eq(&a, &b));
    }
}
