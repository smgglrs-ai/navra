//! ID-JAG (Identity Assertion for Authorization Grant) authenticator.
//!
//! Verifies JWT assertions minted by agent providers (OpenAI, Anthropic,
//! Cursor, etc.) and maps them to [`AgentIdentity`] for gateway access.
//! Providers are trusted via pre-configured JWKS URIs; keys are cached
//! in-memory and can be pre-loaded for testing.
//!
//! The authenticator sits early in the [`ChainAuthenticator`] — JWT tokens
//! (starting with `eyJ`) are tried as ID-JAG first; plain BLAKE3 tokens
//! fall through.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{AgentIdentity, AuthError, Authenticator};

/// Configuration for the ID-JAG authenticator.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdJagConfig {
    pub enabled: bool,
    pub trusted_providers: Vec<TrustedProvider>,
}

/// A provider whose agent JWTs are trusted by this gateway.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedProvider {
    /// Short name: "openai", "anthropic", "cursor".
    pub name: String,
    /// Expected `iss` claim in the JWT.
    pub issuer: String,
    /// JWKS endpoint for key fetching (not used yet — keys are
    /// pre-registered or fetched externally).
    pub jwks_uri: String,
    /// Expected `aud` claim in the JWT.
    pub audience: String,
    /// Permission set assigned to agents from this provider.
    pub default_permissions: String,
}

/// A cached JWK public key (simplified).
#[derive(Debug, Clone)]
pub struct JwkKey {
    /// Key ID (`kid` header in the JWT).
    pub kid: String,
    /// Algorithm: "EdDSA", "RS256", etc.
    pub algorithm: String,
    /// For EdDSA keys: raw 32-byte public key.
    /// For other algorithms: unused (unsupported).
    pub public_key_bytes: Vec<u8>,
}

/// JWT header (minimal, for decoding).
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// JWT claims expected in an ID-JAG assertion.
#[derive(Debug, Deserialize)]
struct IdJagClaims {
    /// Issuer (must match a trusted provider).
    iss: String,
    /// Subject (agent identifier at the provider).
    sub: String,
    /// Audience (must match expected audience).
    aud: IdJagAudience,
    /// Expiry (Unix timestamp).
    exp: u64,
    /// Issued-at (Unix timestamp).
    #[serde(default)]
    #[allow(dead_code)] // deserialized from JWT, not read programmatically
    iat: Option<u64>,
}

/// JWT `aud` claim can be a single string or an array of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IdJagAudience {
    Single(String),
    Multiple(Vec<String>),
}

impl IdJagAudience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            IdJagAudience::Single(s) => s == expected,
            IdJagAudience::Multiple(v) => v.iter().any(|s| s == expected),
        }
    }
}

/// ID-JAG authenticator: verifies provider-minted JWT assertions.
///
/// Supports the MCP Enterprise-Managed Authorization extension
/// (`io.modelcontextprotocol/enterprise-managed-authorization`).
/// Validates ID-JAG JWTs from corporate IdPs against configurable
/// JWKS endpoints, mapping IdP claims to navra permission sets.
pub struct IdJagAuthenticator {
    config: IdJagConfig,
    /// Cached JWKS keys per issuer.
    cached_keys: RwLock<HashMap<String, Vec<JwkKey>>>,
    http_client: reqwest::Client,
}

impl IdJagAuthenticator {
    pub fn new(config: IdJagConfig) -> Self {
        Self {
            config,
            cached_keys: RwLock::new(HashMap::new()),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Register a provider's JWKS keys (for testing or pre-fetching).
    pub fn register_keys(&self, issuer: &str, keys: Vec<JwkKey>) {
        let mut cache = self.cached_keys.write().unwrap_or_else(|e| e.into_inner());
        cache.insert(issuer.to_string(), keys);
    }

    /// Fetch JWKS keys from a provider's endpoint and cache them.
    pub async fn fetch_jwks(&self, provider: &TrustedProvider) -> Result<(), AuthError> {
        let resp = self
            .http_client
            .get(&provider.jwks_uri)
            .send()
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        let body: serde_json::Value = resp.json().await.map_err(|_| AuthError::InvalidToken)?;

        let jwks_keys = body
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or(AuthError::InvalidToken)?;

        let mut keys = Vec::new();
        for key_json in jwks_keys {
            let kty = key_json.get("kty").and_then(|v| v.as_str()).unwrap_or("");
            let alg = key_json
                .get("alg")
                .and_then(|v| v.as_str())
                .unwrap_or("EdDSA");
            let kid = key_json
                .get("kid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if kty == "OKP" {
                // Ed25519 key: decode the "x" parameter (base64url, 32 bytes)
                if let Some(x) = key_json.get("x").and_then(|v| v.as_str()) {
                    if let Ok(pk_bytes) = URL_SAFE_NO_PAD.decode(x) {
                        keys.push(JwkKey {
                            kid,
                            algorithm: alg.to_string(),
                            public_key_bytes: pk_bytes,
                        });
                    }
                }
            }
        }

        if keys.is_empty() {
            return Err(AuthError::InvalidToken);
        }

        self.register_keys(&provider.issuer, keys);
        tracing::info!(
            provider = %provider.name,
            issuer = %provider.issuer,
            "Fetched JWKS keys"
        );
        Ok(())
    }

    /// Fetch JWKS keys for all configured providers.
    pub async fn fetch_all_jwks(&self) {
        for provider in &self.config.trusted_providers {
            if let Err(e) = self.fetch_jwks(provider).await {
                tracing::warn!(
                    provider = %provider.name,
                    jwks_uri = %provider.jwks_uri,
                    error = ?e,
                    "Failed to fetch JWKS"
                );
            }
        }
    }

    /// Verify an ID-JAG assertion token.
    ///
    /// 1. Decode JWT header to get `kid` + `alg`
    /// 2. Decode claims to find `iss`, match to a trusted provider
    /// 3. Look up the signing key by `kid` in cached JWKS
    /// 4. Verify signature (EdDSA only for now)
    /// 5. Validate `aud`, `exp`
    /// 6. Return `AgentIdentity` with provider-assigned permissions
    pub fn verify_assertion(&self, token: &str) -> Result<AgentIdentity, AuthError> {
        let (header, claims, signing_input, sig_bytes) = decode_jwt_parts(token)?;

        // Find the trusted provider by issuer
        let provider = self
            .config
            .trusted_providers
            .iter()
            .find(|p| p.issuer == claims.iss)
            .ok_or(AuthError::InvalidToken)?;

        // Check audience
        if !claims.aud.contains(&provider.audience) {
            return Err(AuthError::InvalidToken);
        }

        // Check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if claims.exp < now {
            return Err(AuthError::InvalidToken);
        }

        // Look up the signing key
        let cache = self.cached_keys.read().unwrap_or_else(|e| e.into_inner());
        let keys = cache.get(&claims.iss).ok_or(AuthError::InvalidToken)?;

        let key = match &header.kid {
            Some(kid) => keys.iter().find(|k| k.kid == *kid),
            // If no kid in header, try the first key for this provider
            None => keys.first(),
        }
        .ok_or(AuthError::InvalidToken)?;

        // Verify signature — only EdDSA (Ed25519) supported
        if header.alg != "EdDSA" || key.algorithm != "EdDSA" {
            return Err(AuthError::InvalidToken);
        }

        verify_eddsa_signature(&signing_input, &sig_bytes, &key.public_key_bytes)?;

        Ok(AgentIdentity {
            name: format!("{}:{}", provider.name, claims.sub),
            permissions: provider.default_permissions.clone(),
            signing_key: None,
            did: None,
            capabilities: None,
        })
    }
}

impl Authenticator for IdJagAuthenticator {
    fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<AgentIdentity, AuthError> {
        if !self.config.enabled {
            return Err(AuthError::InvalidToken);
        }

        let header = headers
            .get("authorization")
            .ok_or(AuthError::MissingToken)?;

        let value = header.to_str().map_err(|_| AuthError::InvalidToken)?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidToken)?;

        // Only handle JWT tokens (start with "eyJ" = base64url-encoded "{")
        // Skip capability tokens and plain BLAKE3 tokens.
        if !token.starts_with("eyJ") {
            return Err(AuthError::InvalidToken);
        }

        // Must have exactly 2 dots (three JWT segments)
        if token.matches('.').count() != 2 {
            return Err(AuthError::InvalidToken);
        }

        self.verify_assertion(token)
    }
}

/// Protected Resource Metadata per RFC 9728.
///
/// Advertised at `/.well-known/oauth-protected-resource` so that
/// agents can discover which authorization servers (ID-JAG providers)
/// this gateway trusts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// URI identifying this protected resource.
    pub resource: String,
    /// Authorization servers whose tokens are accepted.
    pub authorization_servers: Vec<String>,
    /// Supported bearer token presentation methods.
    pub bearer_methods_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    /// Build metadata from an ID-JAG config and server resource URI.
    pub fn from_config(resource: impl Into<String>, config: &IdJagConfig) -> Self {
        let authorization_servers = config
            .trusted_providers
            .iter()
            .map(|p| p.issuer.clone())
            .collect();

        Self {
            resource: resource.into(),
            authorization_servers,
            bearer_methods_supported: vec!["header".to_string()],
        }
    }
}

// --- JWT parsing helpers ---

/// Decode a JWT into its constituent parts without verifying the signature.
fn decode_jwt_parts(token: &str) -> Result<(JwtHeader, IdJagClaims, String, Vec<u8>), AuthError> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(AuthError::InvalidToken);
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AuthError::InvalidToken)?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| AuthError::InvalidToken)?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AuthError::InvalidToken)?;
    let claims: IdJagClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| AuthError::InvalidToken)?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| AuthError::InvalidToken)?;

    Ok((header, claims, signing_input, sig_bytes))
}

/// Verify an EdDSA (Ed25519) signature using raw public key bytes.
fn verify_eddsa_signature(
    signing_input: &str,
    sig_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<(), AuthError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key_bytes: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| AuthError::InvalidToken)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| AuthError::InvalidToken)?;

    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| AuthError::InvalidToken)?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| AuthError::InvalidToken)
}

/// Build a minimal JWT for testing. Signs with the given `CapSigner`.
#[cfg(test)]
fn build_test_jwt(header_json: &str, claims_json: &str, signer: &dyn crate::identity::CapSigner) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature = signer.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
    format!("{signing_input}.{sig_b64}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::chain::ChainAuthenticator;
    use crate::auth::TokenAuthenticator;
    use crate::identity::Ed25519Signer;
    use axum::http::HeaderMap;

    fn test_provider_config(issuer: &str, audience: &str) -> TrustedProvider {
        TrustedProvider {
            name: "test-provider".to_string(),
            issuer: issuer.to_string(),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
            audience: audience.to_string(),
            default_permissions: "agent-default".to_string(),
        }
    }

    fn test_config() -> IdJagConfig {
        IdJagConfig {
            enabled: true,
            trusted_providers: vec![test_provider_config("https://test.provider", "navra")],
        }
    }

    fn future_exp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    fn past_exp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600
    }

    #[test]
    fn idjag_verify_registered_key() {
        let signer = Ed25519Signer::generate();
        let auth = IdJagAuthenticator::new(test_config());

        // Register the signer's public key as a JWKS key for the provider
        auth.register_keys(
            "https://test.provider",
            vec![JwkKey {
                kid: "test-key".to_string(),
                algorithm: "EdDSA".to_string(),
                public_key_bytes: signer.public_key_bytes(),
            }],
        );

        let header = r#"{"alg":"EdDSA","kid":"test-key"}"#;
        let claims = format!(
            r#"{{"iss":"https://test.provider","sub":"agent-1","aud":"navra","exp":{}}}"#,
            future_exp()
        );
        let token = build_test_jwt(header, &claims, &signer);

        let identity = auth.verify_assertion(&token).unwrap();
        assert_eq!(identity.name, "test-provider:agent-1");
        assert_eq!(identity.permissions, "agent-default");
    }

    #[test]
    fn idjag_unknown_provider_rejects() {
        let signer = Ed25519Signer::generate();
        let auth = IdJagAuthenticator::new(test_config());

        auth.register_keys(
            "https://test.provider",
            vec![JwkKey {
                kid: "test-key".to_string(),
                algorithm: "EdDSA".to_string(),
                public_key_bytes: signer.public_key_bytes(),
            }],
        );

        // JWT from an unknown issuer
        let header = r#"{"alg":"EdDSA","kid":"test-key"}"#;
        let claims = format!(
            r#"{{"iss":"https://unknown.provider","sub":"agent-1","aud":"navra","exp":{}}}"#,
            future_exp()
        );
        let token = build_test_jwt(header, &claims, &signer);

        let err = auth.verify_assertion(&token).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn idjag_expired_token_rejects() {
        let signer = Ed25519Signer::generate();
        let auth = IdJagAuthenticator::new(test_config());

        auth.register_keys(
            "https://test.provider",
            vec![JwkKey {
                kid: "test-key".to_string(),
                algorithm: "EdDSA".to_string(),
                public_key_bytes: signer.public_key_bytes(),
            }],
        );

        let header = r#"{"alg":"EdDSA","kid":"test-key"}"#;
        let claims = format!(
            r#"{{"iss":"https://test.provider","sub":"agent-1","aud":"navra","exp":{}}}"#,
            past_exp()
        );
        let token = build_test_jwt(header, &claims, &signer);

        let err = auth.verify_assertion(&token).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn idjag_chain_fallthrough() {
        let signer = Ed25519Signer::generate();
        let idjag_auth = IdJagAuthenticator::new(test_config());

        idjag_auth.register_keys(
            "https://test.provider",
            vec![JwkKey {
                kid: "test-key".to_string(),
                algorithm: "EdDSA".to_string(),
                public_key_bytes: signer.public_key_bytes(),
            }],
        );

        let mut blake3_auth = TokenAuthenticator::new();
        blake3_auth.register("plain-token-abc", AgentIdentity::new("legacy-agent", "dev"));

        let chain = ChainAuthenticator::new().add(idjag_auth).add(blake3_auth);

        // Plain BLAKE3 token should fall through ID-JAG to TokenAuthenticator
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer plain-token-abc".parse().unwrap());
        let identity = chain.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "legacy-agent");
        assert_eq!(identity.permissions, "dev");

        // JWT token should be handled by ID-JAG authenticator
        let jwt_header = r#"{"alg":"EdDSA","kid":"test-key"}"#;
        let jwt_claims = format!(
            r#"{{"iss":"https://test.provider","sub":"agent-2","aud":"navra","exp":{}}}"#,
            future_exp()
        );
        let jwt_token = build_test_jwt(jwt_header, &jwt_claims, &signer);

        let mut headers2 = HeaderMap::new();
        headers2.insert(
            "authorization",
            format!("Bearer {jwt_token}").parse().unwrap(),
        );
        let identity2 = chain.authenticate(&headers2).unwrap();
        assert_eq!(identity2.name, "test-provider:agent-2");
    }

    #[test]
    fn idjag_authenticate_header() {
        let signer = Ed25519Signer::generate();
        let auth = IdJagAuthenticator::new(test_config());

        auth.register_keys(
            "https://test.provider",
            vec![JwkKey {
                kid: "test-key".to_string(),
                algorithm: "EdDSA".to_string(),
                public_key_bytes: signer.public_key_bytes(),
            }],
        );

        let header = r#"{"alg":"EdDSA","kid":"test-key"}"#;
        let claims = format!(
            r#"{{"iss":"https://test.provider","sub":"agent-3","aud":"navra","exp":{}}}"#,
            future_exp()
        );
        let token = build_test_jwt(header, &claims, &signer);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "test-provider:agent-3");
        assert_eq!(identity.permissions, "agent-default");
    }

    #[test]
    fn protected_resource_metadata_serializes() {
        let config = test_config();
        let meta = ProtectedResourceMetadata::from_config("https://my-gateway.local", &config);

        assert_eq!(meta.resource, "https://my-gateway.local");
        assert_eq!(meta.authorization_servers, vec!["https://test.provider"]);
        assert_eq!(meta.bearer_methods_supported, vec!["header"]);

        // Verify it serializes to valid JSON
        let json = serde_json::to_string_pretty(&meta).unwrap();
        assert!(json.contains("authorization_servers"));
        assert!(json.contains("https://test.provider"));

        // Verify it round-trips
        let deserialized: ProtectedResourceMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.resource, meta.resource);
        assert_eq!(
            deserialized.authorization_servers,
            meta.authorization_servers
        );
    }

    #[test]
    fn idjag_wrong_audience_rejects() {
        let signer = Ed25519Signer::generate();
        let auth = IdJagAuthenticator::new(test_config());

        auth.register_keys(
            "https://test.provider",
            vec![JwkKey {
                kid: "test-key".to_string(),
                algorithm: "EdDSA".to_string(),
                public_key_bytes: signer.public_key_bytes(),
            }],
        );

        let header = r#"{"alg":"EdDSA","kid":"test-key"}"#;
        let claims = format!(
            r#"{{"iss":"https://test.provider","sub":"agent-1","aud":"wrong-audience","exp":{}}}"#,
            future_exp()
        );
        let token = build_test_jwt(header, &claims, &signer);

        let err = auth.verify_assertion(&token).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn idjag_wrong_signature_rejects() {
        let signer = Ed25519Signer::generate();
        let wrong_signer = Ed25519Signer::generate();
        let auth = IdJagAuthenticator::new(test_config());

        // Register the first signer's key
        auth.register_keys(
            "https://test.provider",
            vec![JwkKey {
                kid: "test-key".to_string(),
                algorithm: "EdDSA".to_string(),
                public_key_bytes: signer.public_key_bytes(),
            }],
        );

        // Sign with a different key
        let header = r#"{"alg":"EdDSA","kid":"test-key"}"#;
        let claims = format!(
            r#"{{"iss":"https://test.provider","sub":"agent-1","aud":"navra","exp":{}}}"#,
            future_exp()
        );
        let token = build_test_jwt(header, &claims, &wrong_signer);

        let err = auth.verify_assertion(&token).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn idjag_no_cached_keys_rejects() {
        let signer = Ed25519Signer::generate();
        let auth = IdJagAuthenticator::new(test_config());
        // Don't register any keys

        let header = r#"{"alg":"EdDSA","kid":"test-key"}"#;
        let claims = format!(
            r#"{{"iss":"https://test.provider","sub":"agent-1","aud":"navra","exp":{}}}"#,
            future_exp()
        );
        let token = build_test_jwt(header, &claims, &signer);

        let err = auth.verify_assertion(&token).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn idjag_disabled_rejects() {
        let mut config = test_config();
        config.enabled = false;
        let auth = IdJagAuthenticator::new(config);

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp0cnVlfQ.AAAA"
                .parse()
                .unwrap(),
        );

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn idjag_audience_array_accepted() {
        let signer = Ed25519Signer::generate();
        let auth = IdJagAuthenticator::new(test_config());

        auth.register_keys(
            "https://test.provider",
            vec![JwkKey {
                kid: "test-key".to_string(),
                algorithm: "EdDSA".to_string(),
                public_key_bytes: signer.public_key_bytes(),
            }],
        );

        // aud as array containing the expected audience
        let header = r#"{"alg":"EdDSA","kid":"test-key"}"#;
        let claims = format!(
            r#"{{"iss":"https://test.provider","sub":"agent-1","aud":["navra","other"],"exp":{}}}"#,
            future_exp()
        );
        let token = build_test_jwt(header, &claims, &signer);

        let identity = auth.verify_assertion(&token).unwrap();
        assert_eq!(identity.name, "test-provider:agent-1");
    }

    #[tokio::test]
    async fn idjag_fetch_jwks_from_mock_idp() {
        let signer = Ed25519Signer::generate();
        let pk_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signer.public_key_bytes());

        let jwks_json = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "kid": "idp-key-1",
                "x": pk_b64,
                "use": "sig"
            }]
        });

        // Start mock JWKS endpoint using axum
        let jwks_body = serde_json::to_string(&jwks_json).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let body = jwks_body.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        // Give the server a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let config = IdJagConfig {
            enabled: true,
            trusted_providers: vec![TrustedProvider {
                name: "mock-idp".to_string(),
                issuer: "https://idp.example.com".to_string(),
                jwks_uri: format!("http://127.0.0.1:{port}/.well-known/jwks.json"),
                audience: "navra".to_string(),
                default_permissions: "enterprise-agent".to_string(),
            }],
        };

        let auth = IdJagAuthenticator::new(config);
        auth.fetch_jwks(&auth.config.trusted_providers[0])
            .await
            .unwrap();

        // Now verify a JWT signed by the mock IdP
        let header = r#"{"alg":"EdDSA","kid":"idp-key-1"}"#;
        let claims = format!(
            r#"{{"iss":"https://idp.example.com","sub":"employee@corp.com","aud":"navra","exp":{}}}"#,
            future_exp()
        );
        let token = build_test_jwt(header, &claims, &signer);

        let identity = auth.verify_assertion(&token).unwrap();
        assert_eq!(identity.name, "mock-idp:employee@corp.com");
        assert_eq!(identity.permissions, "enterprise-agent");
    }

    #[test]
    fn enterprise_auth_capabilities_extension() {
        let caps = navra_protocol::ServerCapabilities {
            extensions: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "io.modelcontextprotocol/enterprise-managed-authorization".to_string(),
                    serde_json::json!({}),
                );
                m
            },
            ..Default::default()
        };

        let json = serde_json::to_value(&caps).unwrap();
        assert!(json["extensions"]
            .get("io.modelcontextprotocol/enterprise-managed-authorization")
            .is_some());
    }

    #[test]
    fn idjag_multiple_providers() {
        let signer1 = Ed25519Signer::generate();
        let signer2 = Ed25519Signer::generate();

        let config = IdJagConfig {
            enabled: true,
            trusted_providers: vec![
                TrustedProvider {
                    name: "openai".to_string(),
                    issuer: "https://api.openai.com".to_string(),
                    jwks_uri: "https://api.openai.com/.well-known/jwks.json".to_string(),
                    audience: "navra".to_string(),
                    default_permissions: "openai-agent".to_string(),
                },
                TrustedProvider {
                    name: "anthropic".to_string(),
                    issuer: "https://api.anthropic.com".to_string(),
                    jwks_uri: "https://api.anthropic.com/.well-known/jwks.json".to_string(),
                    audience: "navra".to_string(),
                    default_permissions: "anthropic-agent".to_string(),
                },
            ],
        };

        let auth = IdJagAuthenticator::new(config);

        auth.register_keys(
            "https://api.openai.com",
            vec![JwkKey {
                kid: "oai-key".to_string(),
                algorithm: "EdDSA".to_string(),
                public_key_bytes: signer1.public_key_bytes(),
            }],
        );
        auth.register_keys(
            "https://api.anthropic.com",
            vec![JwkKey {
                kid: "anth-key".to_string(),
                algorithm: "EdDSA".to_string(),
                public_key_bytes: signer2.public_key_bytes(),
            }],
        );

        // Token from OpenAI
        let header1 = r#"{"alg":"EdDSA","kid":"oai-key"}"#;
        let claims1 = format!(
            r#"{{"iss":"https://api.openai.com","sub":"gpt-agent","aud":"navra","exp":{}}}"#,
            future_exp()
        );
        let token1 = build_test_jwt(header1, &claims1, &signer1);
        let id1 = auth.verify_assertion(&token1).unwrap();
        assert_eq!(id1.name, "openai:gpt-agent");
        assert_eq!(id1.permissions, "openai-agent");

        // Token from Anthropic
        let header2 = r#"{"alg":"EdDSA","kid":"anth-key"}"#;
        let claims2 = format!(
            r#"{{"iss":"https://api.anthropic.com","sub":"claude-agent","aud":"navra","exp":{}}}"#,
            future_exp()
        );
        let token2 = build_test_jwt(header2, &claims2, &signer2);
        let id2 = auth.verify_assertion(&token2).unwrap();
        assert_eq!(id2.name, "anthropic:claude-agent");
        assert_eq!(id2.permissions, "anthropic-agent");
    }
}
