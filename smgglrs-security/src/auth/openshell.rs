//! OpenShell identity federation authenticator.
//!
//! Verifies identity tokens issued by the OpenShell supervisor,
//! supporting SPIFFE/SPIRE JWT-SVIDs, OIDC bearer tokens, static
//! Ed25519-signed JWTs, and local Unix socket peer credentials.
//!
//! See `docs/designs/openshell-sandbox.md` Section 2 for the full spec.

use super::{AgentIdentity, AuthError, Authenticator};
use jsonwebtoken::{decode, decode_header, jwk, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Instant;

/// Configuration for OpenShell identity verification.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct OpenShellAuthConfig {
    /// Verification mode.
    pub mode: OpenShellAuthMode,
    /// Maps OpenShell label expressions to smgglrs permission set names.
    /// Example: "role=worker" -> "restricted"
    #[serde(default)]
    pub label_mapping: HashMap<String, String>,
    /// Default permission set when no label matches.
    #[serde(default = "default_permissions")]
    pub default_permissions: String,
    /// JWKS cache TTL in seconds (default: 60).
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl_secs: u64,
    /// HTTP request timeout in seconds for JWKS fetches (default: 5).
    #[serde(default = "default_http_timeout_secs")]
    pub http_timeout_secs: u64,
}

fn default_permissions() -> String {
    "restricted".to_string()
}

fn default_jwks_cache_ttl() -> u64 {
    60
}

fn default_http_timeout_secs() -> u64 {
    5
}

/// Verification backend mode.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OpenShellAuthMode {
    /// Verify JWT-SVID against SPIRE trust bundle.
    Spiffe {
        /// Path to SPIRE agent trust bundle PEM.
        trust_bundle_path: PathBuf,
        /// Expected audience claim (if set, audience validation is enabled).
        #[serde(default)]
        audience: Option<String>,
    },
    /// Verify JWT against OIDC provider JWKS endpoint.
    Oidc {
        /// OIDC issuer URL (JWKS fetched from .well-known/openid-configuration).
        issuer: String,
        /// Expected audience claim.
        #[serde(default)]
        audience: Option<String>,
    },
    /// Trust Unix socket peer credentials.
    /// Returns InvalidToken to let the chain continue to other authenticators.
    Local,
    /// Verify JWT signed by OpenShell gateway's Ed25519 key.
    Static {
        /// Path to the gateway's Ed25519 public key PEM.
        public_key_path: PathBuf,
        /// Expected audience claim (if set, audience validation is enabled).
        #[serde(default)]
        audience: Option<String>,
    },
}

/// Claims extracted from a verified OpenShell JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenShellClaims {
    /// Subject (SPIFFE URI or agent name).
    pub sub: String,
    /// Issuer.
    #[serde(default)]
    pub iss: Option<String>,
    /// Audience.
    #[serde(default)]
    pub aud: Option<OneOrMany>,
    /// Expiry (Unix timestamp).
    #[serde(default)]
    pub exp: Option<u64>,
    /// Issued-at (Unix timestamp).
    #[serde(default)]
    pub iat: Option<u64>,
    /// SPIFFE ID (if present).
    #[serde(default)]
    pub spiffe_id: Option<String>,
    /// Sandbox labels (key=value pairs).
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// Sandbox role/ring.
    #[serde(default)]
    pub role: Option<String>,
}

/// JWT `aud` can be a single string or an array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OpenShellClaims {
    /// Check if the claims match a label expression like "role=worker".
    pub fn labels_match(&self, label_expr: &str) -> bool {
        if let Some((key, value)) = label_expr.split_once('=') {
            self.labels.get(key).map(|v| v == value).unwrap_or(false)
                || (key == "role" && self.role.as_deref() == Some(value))
        } else {
            // Bare label — check if any label key matches
            self.labels.contains_key(label_expr) || self.role.as_deref() == Some(label_expr)
        }
    }
}

/// Cached JWKS keys for OIDC/SPIFFE verification.
struct JwksCache {
    keys: jwk::JwkSet,
    fetched_at: Instant,
}

/// Authenticator that accepts OpenShell-provided identity tokens.
pub struct OpenShellAuthenticator {
    config: OpenShellAuthConfig,
    /// Cached JWKS keys (refreshed on verification failure).
    jwks_cache: RwLock<Option<JwksCache>>,
}

impl OpenShellAuthenticator {
    /// Create a new OpenShell authenticator with the given config.
    pub fn new(config: OpenShellAuthConfig) -> Self {
        Self {
            config,
            jwks_cache: RwLock::new(None),
        }
    }

    /// Verify a JWT against a SPIFFE trust bundle PEM file.
    fn verify_spiffe_jwt(
        &self,
        token: &str,
        trust_bundle_path: &PathBuf,
        audience: Option<&str>,
    ) -> Result<OpenShellClaims, AuthError> {
        let pem_data = std::fs::read(trust_bundle_path).map_err(|e| {
            tracing::error!(path = %trust_bundle_path.display(), error = %e, "Failed to read SPIFFE trust bundle");
            AuthError::InvalidToken
        })?;

        let header = decode_header(token).map_err(|_| AuthError::InvalidToken)?;
        let alg = header.alg;

        let key = decoding_key_from_pem(&pem_data, alg).map_err(|_| AuthError::InvalidToken)?;

        let mut validation = Validation::new(alg);
        validation.validate_exp = true;
        if let Some(aud) = audience {
            validation.set_audience(&[aud]);
        } else {
            tracing::warn!(
                "SPIFFE provider has no audience configured — JWT audience validation disabled"
            );
            validation.validate_aud = false;
        }

        let token_data = decode::<OpenShellClaims>(token, &key, &validation).map_err(|e| {
            tracing::debug!(error = %e, "SPIFFE JWT verification failed");
            AuthError::InvalidToken
        })?;

        Ok(token_data.claims)
    }

    /// Verify a JWT against an OIDC provider's JWKS endpoint.
    fn verify_oidc_jwt(
        &self,
        token: &str,
        issuer: &str,
        audience: Option<&str>,
    ) -> Result<OpenShellClaims, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::InvalidToken)?;
        let kid = header.kid.as_deref().ok_or(AuthError::InvalidToken)?;

        let jwks = self.get_or_fetch_jwks(issuer)?;

        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
            .ok_or_else(|| {
                tracing::debug!(kid = kid, "No matching JWK found for kid");
                AuthError::InvalidToken
            })?;

        let key = DecodingKey::from_jwk(jwk).map_err(|e| {
            tracing::debug!(error = %e, "Failed to create decoding key from JWK");
            AuthError::InvalidToken
        })?;

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = true;
        validation.set_issuer(&[issuer]);
        if let Some(aud) = audience {
            validation.set_audience(&[aud]);
        } else {
            tracing::warn!(
                "OIDC provider has no audience configured — JWT audience validation disabled"
            );
            validation.validate_aud = false;
        }

        let token_data = decode::<OpenShellClaims>(token, &key, &validation).map_err(|e| {
            tracing::debug!(error = %e, "OIDC JWT verification failed");
            AuthError::InvalidToken
        })?;

        Ok(token_data.claims)
    }

    /// Verify a JWT signed with the OpenShell gateway's Ed25519 key.
    fn verify_static_jwt(
        &self,
        token: &str,
        public_key_path: &PathBuf,
        audience: Option<&str>,
    ) -> Result<OpenShellClaims, AuthError> {
        let pem_data = std::fs::read(public_key_path).map_err(|e| {
            tracing::error!(path = %public_key_path.display(), error = %e, "Failed to read public key");
            AuthError::InvalidToken
        })?;

        let key = DecodingKey::from_ed_pem(&pem_data).map_err(|e| {
            tracing::debug!(error = %e, "Failed to parse Ed25519 public key PEM");
            AuthError::InvalidToken
        })?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = true;
        if let Some(aud) = audience {
            validation.set_audience(&[aud]);
        } else {
            tracing::warn!(
                "Static provider has no audience configured — JWT audience validation disabled"
            );
            validation.validate_aud = false;
        }

        let token_data = decode::<OpenShellClaims>(token, &key, &validation).map_err(|e| {
            tracing::debug!(error = %e, "Static JWT verification failed");
            AuthError::InvalidToken
        })?;

        Ok(token_data.claims)
    }

    /// Resolve OpenShell sandbox labels to a smgglrs permission set name.
    fn resolve_permissions(&self, claims: &OpenShellClaims) -> String {
        for (label_expr, perm_set) in &self.config.label_mapping {
            if claims.labels_match(label_expr) {
                return perm_set.clone();
            }
        }
        self.config.default_permissions.clone()
    }

    /// Get cached JWKS or fetch from the OIDC discovery endpoint.
    fn get_or_fetch_jwks(&self, issuer: &str) -> Result<jwk::JwkSet, AuthError> {
        let cache_ttl = self.config.jwks_cache_ttl_secs;

        // Check cache
        {
            let cache = self.jwks_cache.read().unwrap_or_else(|e| {
                tracing::warn!("JWKS cache RwLock poisoned (read), recovering");
                e.into_inner()
            });
            if let Some(ref cached) = *cache {
                if cached.fetched_at.elapsed().as_secs() < cache_ttl {
                    return Ok(cached.keys.clone());
                }
            }
        }

        let timeout = std::time::Duration::from_secs(self.config.http_timeout_secs);
        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_global(Some(timeout))
                .build(),
        );

        // Fetch JWKS synchronously (blocking context)
        let jwks_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );

        // Use a blocking HTTP client since Authenticator::authenticate is sync
        let oidc_config: serde_json::Value = agent
            .get(&jwks_url)
            .call()
            .map_err(|e| {
                tracing::error!(url = %jwks_url, error = %e, "Failed to fetch OIDC config");
                AuthError::InvalidToken
            })?
            .into_body()
            .read_json()
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to parse OIDC config");
                AuthError::InvalidToken
            })?;

        let jwks_uri = oidc_config["jwks_uri"].as_str().ok_or_else(|| {
            tracing::error!("OIDC config missing jwks_uri");
            AuthError::InvalidToken
        })?;

        let jwks: jwk::JwkSet = agent
            .get(jwks_uri)
            .call()
            .map_err(|e| {
                tracing::error!(url = %jwks_uri, error = %e, "Failed to fetch JWKS");
                AuthError::InvalidToken
            })?
            .into_body()
            .read_json()
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to parse JWKS");
                AuthError::InvalidToken
            })?;

        // Update cache
        {
            let mut cache = self.jwks_cache.write().unwrap_or_else(|e| {
                tracing::warn!("JWKS cache RwLock poisoned (write), recovering");
                e.into_inner()
            });
            *cache = Some(JwksCache {
                keys: jwks.clone(),
                fetched_at: Instant::now(),
            });
        }

        Ok(jwks)
    }
}

impl Authenticator for OpenShellAuthenticator {
    fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<AgentIdentity, AuthError> {
        let header = headers
            .get("authorization")
            .ok_or(AuthError::MissingToken)?;

        let value = header.to_str().map_err(|_| AuthError::InvalidToken)?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidToken)?;

        // Skip tokens that belong to other authenticators
        if token.starts_with("smgglrs_cap_v1.") {
            return Err(AuthError::InvalidToken);
        }

        let claims = match &self.config.mode {
            OpenShellAuthMode::Spiffe {
                trust_bundle_path,
                audience,
            } => self.verify_spiffe_jwt(token, trust_bundle_path, audience.as_deref())?,
            OpenShellAuthMode::Oidc { issuer, audience } => {
                self.verify_oidc_jwt(token, issuer, audience.as_deref())?
            }
            OpenShellAuthMode::Static {
                public_key_path,
                audience,
            } => self.verify_static_jwt(token, public_key_path, audience.as_deref())?,
            OpenShellAuthMode::Local => {
                // Local mode extracts identity from SO_PEERCRED,
                // not from Authorization header. Return InvalidToken
                // to let the chain continue.
                return Err(AuthError::InvalidToken);
            }
        };

        let permissions = self.resolve_permissions(&claims);

        Ok(AgentIdentity {
            name: claims.sub.clone(),
            permissions,
            signing_key: None,
            did: claims.spiffe_id.map(|s| format!("spiffe://{s}")),
            capabilities: None,
        })
    }
}

/// Parse a PEM file into a `DecodingKey` for the given algorithm.
fn decoding_key_from_pem(pem_data: &[u8], alg: Algorithm) -> Result<DecodingKey, AuthError> {
    match alg {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            DecodingKey::from_rsa_pem(pem_data).map_err(|_| AuthError::InvalidToken)
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            DecodingKey::from_ec_pem(pem_data).map_err(|_| AuthError::InvalidToken)
        }
        Algorithm::EdDSA => DecodingKey::from_ed_pem(pem_data).map_err(|_| AuthError::InvalidToken),
        _ => {
            tracing::debug!(alg = ?alg, "Unsupported algorithm in SPIFFE trust bundle");
            Err(AuthError::InvalidToken)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use base64::Engine;
    use jsonwebtoken::{encode, EncodingKey, Header};

    /// Generate an Ed25519 keypair and return (encoding_key, decoding_key_pem).
    fn generate_ed25519_keypair() -> (EncodingKey, Vec<u8>) {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Build PKCS8 DER for the private key
        let seed = signing_key.to_bytes();
        let mut pkcs8_der = Vec::new();
        let inner_octet = {
            let mut v = vec![0x04, 0x20];
            v.extend_from_slice(&seed);
            v
        };
        let outer_octet = {
            let mut v = vec![0x04];
            v.push(inner_octet.len() as u8);
            v.extend_from_slice(&inner_octet);
            v
        };
        let alg_id = vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        let version = vec![0x02, 0x01, 0x00];
        let inner_len = version.len() + alg_id.len() + outer_octet.len();
        pkcs8_der.push(0x30);
        pkcs8_der.push(inner_len as u8);
        pkcs8_der.extend_from_slice(&version);
        pkcs8_der.extend_from_slice(&alg_id);
        pkcs8_der.extend_from_slice(&outer_octet);

        let private_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&pkcs8_der)
        );

        let encoding_key = EncodingKey::from_ed_pem(private_pem.as_bytes())
            .expect("Failed to create encoding key");

        // Build SubjectPublicKeyInfo DER for the public key
        let pub_bytes = verifying_key.to_bytes();
        let mut spki_der = Vec::new();
        let alg_id_pub = vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        let bit_string = {
            let mut v = vec![0x03];
            v.push((pub_bytes.len() + 1) as u8);
            v.push(0x00);
            v.extend_from_slice(&pub_bytes);
            v
        };
        let pub_inner_len = alg_id_pub.len() + bit_string.len();
        spki_der.push(0x30);
        spki_der.push(pub_inner_len as u8);
        spki_der.extend_from_slice(&alg_id_pub);
        spki_der.extend_from_slice(&bit_string);

        let public_pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&spki_der)
        );

        (encoding_key, public_pem.into_bytes())
    }

    fn make_test_claims(sub: &str) -> OpenShellClaims {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        OpenShellClaims {
            sub: sub.to_string(),
            iss: Some("test-issuer".to_string()),
            aud: None,
            exp: Some(now + 3600),
            iat: Some(now),
            spiffe_id: None,
            labels: {
                let mut m = HashMap::new();
                m.insert("role".to_string(), "worker".to_string());
                m
            },
            role: Some("worker".to_string()),
        }
    }

    fn make_expired_claims(sub: &str) -> OpenShellClaims {
        OpenShellClaims {
            sub: sub.to_string(),
            iss: Some("test-issuer".to_string()),
            aud: None,
            exp: Some(1000),
            iat: Some(900),
            spiffe_id: None,
            labels: HashMap::new(),
            role: None,
        }
    }

    fn test_config(mode: OpenShellAuthMode) -> OpenShellAuthConfig {
        let mut label_mapping = HashMap::new();
        label_mapping.insert("role=worker".to_string(), "restricted".to_string());
        label_mapping.insert("role=lead".to_string(), "developer".to_string());
        label_mapping.insert("role=admin".to_string(), "admin".to_string());

        OpenShellAuthConfig {
            mode,
            label_mapping,
            default_permissions: "restricted".to_string(),
            jwks_cache_ttl_secs: default_jwks_cache_ttl(),
            http_timeout_secs: default_http_timeout_secs(),
        }
    }

    #[test]
    fn static_jwt_roundtrip() {
        let (encoding_key, public_pem) = generate_ed25519_keypair();
        let claims = make_test_claims("test-agent");

        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // Write public key to temp file
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("pub.pem");
        std::fs::write(&key_path, &public_pem).unwrap();

        let config = test_config(OpenShellAuthMode::Static {
            public_key_path: key_path,
            audience: None,
        });
        let auth = OpenShellAuthenticator::new(config);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(identity.name, "test-agent");
        assert_eq!(identity.permissions, "restricted");
    }

    #[test]
    fn label_to_permission_mapping() {
        let config = test_config(OpenShellAuthMode::Local);
        let auth = OpenShellAuthenticator::new(config);

        // Worker role
        let worker = make_test_claims("worker-agent");
        assert_eq!(auth.resolve_permissions(&worker), "restricted");

        // Lead role
        let mut lead = make_test_claims("lead-agent");
        lead.labels.insert("role".to_string(), "lead".to_string());
        lead.role = Some("lead".to_string());
        assert_eq!(auth.resolve_permissions(&lead), "developer");

        // Admin role
        let mut admin = make_test_claims("admin-agent");
        admin.labels.insert("role".to_string(), "admin".to_string());
        admin.role = Some("admin".to_string());
        assert_eq!(auth.resolve_permissions(&admin), "admin");
    }

    #[test]
    fn default_permission_when_no_label_matches() {
        let config = test_config(OpenShellAuthMode::Local);
        let auth = OpenShellAuthenticator::new(config);

        let mut claims = make_test_claims("unknown-agent");
        claims.labels.clear();
        claims.role = Some("unknown".to_string());

        assert_eq!(auth.resolve_permissions(&claims), "restricted");
    }

    #[test]
    fn chain_ordering_cap_tokens_take_priority() {
        use crate::auth::capability::{build_payload, encode_token, CapabilitySet};
        use crate::auth::chain::{CapabilityAuthenticator, ChainAuthenticator};
        use crate::identity::{CapSigner, Ed25519Signer};

        let signer = Ed25519Signer::generate();
        let payload = build_payload(
            signer.did(),
            "did:key:z6MkTestAgent",
            CapabilitySet {
                paths: vec!["/home/**".to_string()],
                operations: vec!["read".to_string()],
                tools: vec!["docs_*".to_string()],
                credentials: vec![],
            },
            1,
            3600,
        );
        let cap_token = encode_token(&payload, &signer).unwrap();

        let (_, public_pem) = generate_ed25519_keypair();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("pub.pem");
        std::fs::write(&key_path, &public_pem).unwrap();

        let os_config = test_config(OpenShellAuthMode::Static {
            public_key_path: key_path,
            audience: None,
        });

        let chain = ChainAuthenticator::new()
            .add(CapabilityAuthenticator::new(Box::new(signer)))
            .add(OpenShellAuthenticator::new(os_config));

        // Cap token is handled by CapabilityAuthenticator, not OpenShell
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {cap_token}").parse().unwrap(),
        );

        let identity = chain.authenticate(&headers).unwrap();
        assert!(identity.capabilities.is_some());
        assert_eq!(identity.did, Some("did:key:z6MkTestAgent".to_string()));
    }

    #[test]
    fn expired_token_rejected() {
        let (encoding_key, public_pem) = generate_ed25519_keypair();
        let claims = make_expired_claims("expired-agent");

        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("pub.pem");
        std::fs::write(&key_path, &public_pem).unwrap();

        let config = test_config(OpenShellAuthMode::Static {
            public_key_path: key_path,
            audience: None,
        });
        let auth = OpenShellAuthenticator::new(config);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn invalid_signature_rejected() {
        let (encoding_key, _) = generate_ed25519_keypair();
        let (_, wrong_public_pem) = generate_ed25519_keypair();

        let claims = make_test_claims("bad-sig-agent");
        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("wrong_pub.pem");
        std::fs::write(&key_path, &wrong_public_pem).unwrap();

        let config = test_config(OpenShellAuthMode::Static {
            public_key_path: key_path,
            audience: None,
        });
        let auth = OpenShellAuthenticator::new(config);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn cap_tokens_skipped_by_openshell() {
        let (_, public_pem) = generate_ed25519_keypair();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("pub.pem");
        std::fs::write(&key_path, &public_pem).unwrap();

        let config = test_config(OpenShellAuthMode::Static {
            public_key_path: key_path,
            audience: None,
        });
        let auth = OpenShellAuthenticator::new(config);

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer smgglrs_cap_v1.some.thing".parse().unwrap(),
        );

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn local_mode_returns_invalid_token() {
        let config = test_config(OpenShellAuthMode::Local);
        let auth = OpenShellAuthenticator::new(config);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer some-jwt-token".parse().unwrap());

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn labels_match_key_value() {
        let claims = make_test_claims("agent");
        assert!(claims.labels_match("role=worker"));
        assert!(!claims.labels_match("role=admin"));
    }

    #[test]
    fn labels_match_role_field() {
        let mut claims = make_test_claims("agent");
        claims.labels.clear();
        // role field is "worker"
        assert!(claims.labels_match("role=worker"));
    }

    #[test]
    fn spiffe_id_becomes_did() {
        let (encoding_key, public_pem) = generate_ed25519_keypair();
        let mut claims = make_test_claims("spiffe-agent");
        claims.spiffe_id = Some("trust-domain/workload".to_string());

        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("pub.pem");
        std::fs::write(&key_path, &public_pem).unwrap();

        let config = test_config(OpenShellAuthMode::Static {
            public_key_path: key_path,
            audience: None,
        });
        let auth = OpenShellAuthenticator::new(config);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        assert_eq!(
            identity.did,
            Some("spiffe://trust-domain/workload".to_string())
        );
    }
}
