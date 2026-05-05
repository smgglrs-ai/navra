//! OAuth 2.0 authorization framework for MCP.
//!
//! Implements the MCP OAuth 2.0 flow with smgglrs acting as its own
//! authorization server. Supports:
//! - Discovery: `GET /.well-known/oauth-authorization-server`
//! - Token issuance: `POST /oauth/token` (client_credentials grant)
//! - Dynamic client registration: `POST /oauth/register`
//! - Bearer token validation via Ed25519-signed JWTs

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{AgentIdentity, AuthError, Authenticator};
use crate::identity::CapSigner;

/// OAuth 2.0 server metadata per RFC 8414 / MCP spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// OAuth token response per RFC 6749 section 5.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

/// OAuth client registration request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationRequest {
    pub redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub client_name: Option<String>,
}

/// OAuth client registration response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistration {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub client_name: Option<String>,
}

/// Token request for client_credentials grant.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
}

/// JWT header (minimal, Ed25519).
#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

/// JWT claims for OAuth access tokens.
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    /// Issuer
    iss: String,
    /// Subject (client_id)
    sub: String,
    /// Issued at (Unix timestamp)
    iat: u64,
    /// Expiry (Unix timestamp)
    exp: u64,
    /// Scopes (space-separated)
    #[serde(default)]
    scope: String,
    /// JWT ID (unique token identifier)
    jti: String,
}

/// OAuth configuration for the server.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub issuer: String,
    pub token_ttl_secs: u64,
    pub scopes: Vec<String>,
}

/// Registered OAuth client (in-memory).
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RegisteredClient {
    client_id: String,
    client_secret: String,
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    /// Permission set name this client maps to.
    permissions: String,
}

/// OAuth provider: issues and validates tokens.
///
/// Acts as both the authorization server (issuing tokens) and the
/// resource server (validating Bearer tokens in incoming requests).
pub struct OAuthProvider {
    config: OAuthConfig,
    signer: Box<dyn CapSigner>,
    /// Registered clients: client_id -> client.
    clients: Mutex<HashMap<String, RegisteredClient>>,
    /// Scope-to-permission-set mapping.
    scope_permissions: HashMap<String, String>,
}

impl OAuthProvider {
    pub fn new(
        config: OAuthConfig,
        signer: Box<dyn CapSigner>,
    ) -> Self {
        Self {
            config,
            signer,
            clients: Mutex::new(HashMap::new()),
            scope_permissions: HashMap::new(),
        }
    }

    /// Register a scope-to-permission mapping.
    pub fn map_scope(&mut self, scope: &str, permissions: &str) {
        self.scope_permissions
            .insert(scope.to_string(), permissions.to_string());
    }

    /// Register an OAuth client with pre-shared credentials.
    pub fn register_client(
        &self,
        client_id: &str,
        client_secret: &str,
        client_name: Option<&str>,
        permissions: &str,
    ) {
        let client = RegisteredClient {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            client_name: client_name.map(|s| s.to_string()),
            redirect_uris: Vec::new(),
            permissions: permissions.to_string(),
        };
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(client_id.to_string(), client);
    }

    /// Dynamic client registration.
    pub fn register_dynamic(
        &self,
        request: &ClientRegistrationRequest,
    ) -> ClientRegistration {
        let client_id = format!("oauth_{}", uuid::Uuid::new_v4());
        let client_secret = generate_client_secret();

        let client = RegisteredClient {
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            client_name: request.client_name.clone(),
            redirect_uris: request.redirect_uris.clone(),
            permissions: "readonly".to_string(),
        };
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(client_id.clone(), client);

        ClientRegistration {
            client_id,
            client_secret: Some(client_secret),
            redirect_uris: request.redirect_uris.clone(),
            grant_types: request.grant_types.clone(),
            response_types: request.response_types.clone(),
            client_name: request.client_name.clone(),
        }
    }

    /// Build the OAuth server metadata document.
    pub fn metadata(&self) -> OAuthMetadata {
        OAuthMetadata {
            issuer: self.config.issuer.clone(),
            authorization_endpoint: format!("{}/oauth/authorize", self.config.issuer),
            token_endpoint: format!("{}/oauth/token", self.config.issuer),
            registration_endpoint: Some(format!("{}/oauth/register", self.config.issuer)),
            scopes_supported: Some(self.config.scopes.clone()),
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: Some(vec!["client_credentials".to_string()]),
            token_endpoint_auth_methods_supported: Some(vec![
                "client_secret_post".to_string(),
            ]),
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
        }
    }

    /// Issue an access token for a client_credentials grant.
    pub fn issue_token(&self, request: &TokenRequest) -> Result<TokenResponse, String> {
        if request.grant_type != "client_credentials" {
            return Err("unsupported_grant_type".to_string());
        }

        let client_id = request
            .client_id
            .as_deref()
            .ok_or_else(|| "invalid_client: missing client_id".to_string())?;
        let client_secret = request
            .client_secret
            .as_deref()
            .ok_or_else(|| "invalid_client: missing client_secret".to_string())?;

        // Validate client credentials
        let clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        let client = clients
            .get(client_id)
            .ok_or_else(|| "invalid_client: unknown client_id".to_string())?;

        // Constant-time comparison for client secret
        let secret_match = constant_time_eq(
            client.client_secret.as_bytes(),
            client_secret.as_bytes(),
        );
        if !secret_match {
            return Err("invalid_client: bad credentials".to_string());
        }

        // Validate requested scopes
        let scope = request.scope.clone().unwrap_or_default();
        if !scope.is_empty() {
            let supported: HashSet<&str> =
                self.config.scopes.iter().map(|s| s.as_str()).collect();
            for s in scope.split_whitespace() {
                if !supported.contains(s) {
                    return Err(format!("invalid_scope: unknown scope '{s}'"));
                }
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = JwtClaims {
            iss: self.config.issuer.clone(),
            sub: client_id.to_string(),
            iat: now,
            exp: now + self.config.token_ttl_secs,
            scope: scope.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let jwt = encode_jwt(&claims, self.signer.as_ref())?;

        Ok(TokenResponse {
            access_token: jwt,
            token_type: "Bearer".to_string(),
            expires_in: Some(self.config.token_ttl_secs),
            refresh_token: None,
            scope: if scope.is_empty() { None } else { Some(scope) },
        })
    }

    /// Validate a JWT access token and return the claims.
    pub fn validate_token(&self, token: &str) -> Result<(String, String, String), AuthError> {
        let claims = decode_jwt(token, self.signer.as_ref())
            .map_err(|_| AuthError::InvalidToken)?;

        // Check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if claims.exp < now {
            return Err(AuthError::InvalidToken);
        }

        // Check issuer
        if claims.iss != self.config.issuer {
            return Err(AuthError::InvalidToken);
        }

        // Resolve permissions from client registration
        let clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        let permissions = clients
            .get(&claims.sub)
            .map(|c| c.permissions.clone())
            .unwrap_or_else(|| {
                // Fall back to scope-based permission mapping
                self.resolve_permissions_from_scopes(&claims.scope)
            });

        Ok((claims.sub, permissions, claims.scope))
    }

    /// Map OAuth scopes to a smgglrs permission set name.
    fn resolve_permissions_from_scopes(&self, scope: &str) -> String {
        // Check each scope for a mapped permission set.
        // Use the first match (most specific wins).
        for s in scope.split_whitespace() {
            if let Some(perm) = self.scope_permissions.get(s) {
                return perm.clone();
            }
        }
        // Default: read-only for unknown scopes
        "readonly".to_string()
    }
}

/// Authenticator that validates OAuth Bearer JWT tokens.
pub struct OAuthAuthenticator {
    provider: std::sync::Arc<OAuthProvider>,
}

impl OAuthAuthenticator {
    pub fn new(provider: std::sync::Arc<OAuthProvider>) -> Self {
        Self { provider }
    }
}

impl Authenticator for OAuthAuthenticator {
    fn authenticate(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<AgentIdentity, AuthError> {
        let header = headers
            .get("authorization")
            .ok_or(AuthError::MissingToken)?;

        let value = header.to_str().map_err(|_| AuthError::InvalidToken)?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidToken)?;

        // Only handle JWT tokens (three dot-separated base64url parts,
        // not capability tokens which start with "smgglrs_cap_v1.")
        if token.starts_with("smgglrs_cap_v1.") {
            return Err(AuthError::InvalidToken);
        }
        // Quick structural check: JWTs have exactly 2 dots
        if token.matches('.').count() != 2 {
            return Err(AuthError::InvalidToken);
        }

        let (client_id, permissions, _scope) = self.provider.validate_token(token)?;

        Ok(AgentIdentity {
            name: client_id,
            permissions,
            signing_key: None,
            did: None,
            capabilities: None,
        })
    }
}

// --- JWT encode/decode using Ed25519 ---

fn encode_jwt(claims: &JwtClaims, signer: &dyn CapSigner) -> Result<String, String> {
    let header = JwtHeader {
        alg: "EdDSA".to_string(),
        typ: "JWT".to_string(),
    };

    let header_json =
        serde_json::to_vec(&header).map_err(|e| format!("header serialization: {e}"))?;
    let claims_json =
        serde_json::to_vec(claims).map_err(|e| format!("claims serialization: {e}"))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature = signer.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(format!("{signing_input}.{sig_b64}"))
}

fn decode_jwt(token: &str, verifier: &dyn CapSigner) -> Result<JwtClaims, String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format".to_string());
    }

    // Verify header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| format!("header decode: {e}"))?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("header parse: {e}"))?;
    if header.alg != "EdDSA" {
        return Err(format!("unsupported algorithm: {}", header.alg));
    }

    // Verify signature
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("signature decode: {e}"))?;
    if !verifier.verify(signing_input.as_bytes(), &sig_bytes) {
        return Err("invalid signature".to_string());
    }

    // Decode claims
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("claims decode: {e}"))?;
    let claims: JwtClaims =
        serde_json::from_slice(&claims_bytes).map_err(|e| format!("claims parse: {e}"))?;

    Ok(claims)
}

/// Constant-time byte comparison (CWE-208 mitigation).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Generate a random client secret (32 bytes, hex-encoded).
fn generate_client_secret() -> String {
    let mut bytes = [0u8; 32];
    use rand::rngs::OsRng;
    use rand::RngCore;
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Ed25519Signer;
    use std::sync::Arc;

    fn test_config() -> OAuthConfig {
        OAuthConfig {
            issuer: "http://localhost:9315".to_string(),
            token_ttl_secs: 3600,
            scopes: vec![
                "tools:read".to_string(),
                "tools:write".to_string(),
                "resources:read".to_string(),
            ],
        }
    }

    fn test_provider() -> Arc<OAuthProvider> {
        let signer = Ed25519Signer::generate();
        let mut provider = OAuthProvider::new(test_config(), Box::new(signer));
        provider.map_scope("tools:read", "readonly");
        provider.map_scope("tools:write", "developer");
        let provider = Arc::new(provider);
        provider.register_client("test-client", "test-secret", Some("Test App"), "developer");
        provider
    }

    #[test]
    fn metadata_returns_valid_json() {
        let provider = test_provider();
        let meta = provider.metadata();

        assert_eq!(meta.issuer, "http://localhost:9315");
        assert_eq!(
            meta.token_endpoint,
            "http://localhost:9315/oauth/token"
        );
        assert!(meta.registration_endpoint.is_some());
        assert_eq!(
            meta.grant_types_supported,
            Some(vec!["client_credentials".to_string()])
        );
        assert_eq!(
            meta.scopes_supported,
            Some(vec![
                "tools:read".to_string(),
                "tools:write".to_string(),
                "resources:read".to_string(),
            ])
        );
    }

    #[test]
    fn issue_token_succeeds() {
        let provider = test_provider();
        let request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: Some("test-client".to_string()),
            client_secret: Some("test-secret".to_string()),
            scope: Some("tools:read".to_string()),
        };

        let response = provider.issue_token(&request).unwrap();
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, Some(3600));
        assert_eq!(response.scope, Some("tools:read".to_string()));
        // JWT has three dot-separated parts
        assert_eq!(response.access_token.matches('.').count(), 2);
    }

    #[test]
    fn issue_token_invalid_grant_type() {
        let provider = test_provider();
        let request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            client_id: Some("test-client".to_string()),
            client_secret: Some("test-secret".to_string()),
            scope: None,
        };

        let err = provider.issue_token(&request).unwrap_err();
        assert!(err.contains("unsupported_grant_type"));
    }

    #[test]
    fn issue_token_unknown_client() {
        let provider = test_provider();
        let request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: Some("nonexistent".to_string()),
            client_secret: Some("whatever".to_string()),
            scope: None,
        };

        let err = provider.issue_token(&request).unwrap_err();
        assert!(err.contains("invalid_client"));
    }

    #[test]
    fn issue_token_bad_secret() {
        let provider = test_provider();
        let request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: Some("test-client".to_string()),
            client_secret: Some("wrong-secret".to_string()),
            scope: None,
        };

        let err = provider.issue_token(&request).unwrap_err();
        assert!(err.contains("invalid_client"));
    }

    #[test]
    fn issue_token_invalid_scope() {
        let provider = test_provider();
        let request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: Some("test-client".to_string()),
            client_secret: Some("test-secret".to_string()),
            scope: Some("admin:all".to_string()),
        };

        let err = provider.issue_token(&request).unwrap_err();
        assert!(err.contains("invalid_scope"));
    }

    #[test]
    fn validate_token_roundtrip() {
        let provider = test_provider();
        let request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: Some("test-client".to_string()),
            client_secret: Some("test-secret".to_string()),
            scope: Some("tools:read".to_string()),
        };

        let response = provider.issue_token(&request).unwrap();
        let (sub, perms, scope) = provider.validate_token(&response.access_token).unwrap();

        assert_eq!(sub, "test-client");
        assert_eq!(perms, "developer"); // from client registration
        assert_eq!(scope, "tools:read");
    }

    #[test]
    fn expired_token_rejected() {
        let signer = Ed25519Signer::generate();
        let config = OAuthConfig {
            issuer: "http://localhost:9315".to_string(),
            token_ttl_secs: 3600,
            scopes: vec!["tools:read".to_string()],
        };
        let provider = Arc::new(OAuthProvider::new(config, Box::new(signer)));
        provider.register_client("c", "s", None, "dev");

        // Manually create a JWT with an expired timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = JwtClaims {
            iss: "http://localhost:9315".to_string(),
            sub: "c".to_string(),
            iat: now - 7200,
            exp: now - 3600, // expired 1 hour ago
            scope: String::new(),
            jti: uuid::Uuid::new_v4().to_string(),
        };
        // Use encode_jwt directly with expired claims
        let expired_jwt = encode_jwt(&claims, provider.signer.as_ref()).unwrap();
        let result = provider.validate_token(&expired_jwt);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_jwt_rejected() {
        let provider = test_provider();
        let request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: Some("test-client".to_string()),
            client_secret: Some("test-secret".to_string()),
            scope: None,
        };

        let response = provider.issue_token(&request).unwrap();
        // Tamper with the claims portion
        let parts: Vec<&str> = response.access_token.splitn(3, '.').collect();
        let tampered = format!("{}.{}x.{}", parts[0], parts[1], parts[2]);
        assert!(provider.validate_token(&tampered).is_err());
    }

    #[test]
    fn wrong_signer_jwt_rejected() {
        let signer1 = Ed25519Signer::generate();
        let signer2 = Ed25519Signer::generate();

        let provider1 = Arc::new(OAuthProvider::new(test_config(), Box::new(signer1)));
        provider1.register_client("c", "s", None, "dev");

        let provider2 = Arc::new(OAuthProvider::new(test_config(), Box::new(signer2)));

        let request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: Some("c".to_string()),
            client_secret: Some("s".to_string()),
            scope: None,
        };

        let response = provider1.issue_token(&request).unwrap();
        assert!(provider2.validate_token(&response.access_token).is_err());
    }

    #[test]
    fn bearer_auth_works_in_chain() {
        let provider = test_provider();
        let request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: Some("test-client".to_string()),
            client_secret: Some("test-secret".to_string()),
            scope: Some("tools:write".to_string()),
        };

        let response = provider.issue_token(&request).unwrap();
        let auth = OAuthAuthenticator::new(provider);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {}", response.access_token).parse().unwrap(),
        );

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "test-client");
        assert_eq!(identity.permissions, "developer");
    }

    #[test]
    fn oauth_auth_skips_capability_tokens() {
        let provider = test_provider();
        let auth = OAuthAuthenticator::new(provider);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer smgglrs_cap_v1.abc.def".parse().unwrap(),
        );

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn oauth_auth_skips_non_jwt_tokens() {
        let provider = test_provider();
        let auth = OAuthAuthenticator::new(provider);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer not-a-jwt-token".parse().unwrap(),
        );

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn dynamic_registration() {
        let provider = test_provider();
        let request = ClientRegistrationRequest {
            redirect_uris: vec!["http://localhost:8080/callback".to_string()],
            grant_types: Some(vec!["client_credentials".to_string()]),
            response_types: None,
            client_name: Some("My Agent".to_string()),
        };

        let reg = provider.register_dynamic(&request);
        assert!(reg.client_id.starts_with("oauth_"));
        assert!(reg.client_secret.is_some());
        assert_eq!(reg.client_name, Some("My Agent".to_string()));

        // The dynamically registered client can issue tokens
        let token_req = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: Some(reg.client_id.clone()),
            client_secret: reg.client_secret.clone(),
            scope: None,
        };
        let response = provider.issue_token(&token_req).unwrap();
        let (sub, _, _) = provider.validate_token(&response.access_token).unwrap();
        assert_eq!(sub, reg.client_id);
    }

    #[test]
    fn scope_to_permission_mapping() {
        let signer = Ed25519Signer::generate();
        let mut provider = OAuthProvider::new(test_config(), Box::new(signer));
        provider.map_scope("tools:read", "readonly");
        provider.map_scope("tools:write", "developer");

        assert_eq!(
            provider.resolve_permissions_from_scopes("tools:read"),
            "readonly"
        );
        assert_eq!(
            provider.resolve_permissions_from_scopes("tools:write tools:read"),
            "developer"
        );
        // Unknown scope defaults to readonly
        assert_eq!(
            provider.resolve_permissions_from_scopes("unknown"),
            "readonly"
        );
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
