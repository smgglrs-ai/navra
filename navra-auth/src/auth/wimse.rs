//! WIMSE/SPIFFE identity support (NAVRA-172).
//!
//! Provides native WIMSE/SPIFFE identifier support alongside DID:key,
//! following the AIMS draft (draft-klrc-aiagent-auth) dual-identity model:
//! agent identity (SPIFFE ID) + owner identity (human/org).
//!
//! Also provides SPIFFE → DID bridging for interoperability with the
//! existing capability token system.

use super::{AgentIdentity, AuthError, Authenticator};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

/// WIMSE identity binding an agent to its workload and (optionally) its owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WimseIdentity {
    /// SPIFFE ID (e.g., "spiffe://example.org/agent/analyst").
    pub spiffe_id: String,
    /// WIMSE workload identifier (may differ from SPIFFE ID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    /// Owner identity — the human or org this agent acts for (AIMS dual-identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<OwnerIdentity>,
}

/// Human or organizational owner of an agent (AIMS dual-identity model).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OwnerIdentity {
    /// Owner subject identifier (email, employee ID, etc.).
    pub sub: String,
    /// Identity provider that authenticated the owner.
    pub iss: String,
    /// Organization (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// Bridge a SPIFFE ID to a DID:web identifier.
///
/// `spiffe://example.org/agent/analyst` → `did:web:example.org:agent:analyst`
pub fn spiffe_to_did(spiffe_id: &str) -> String {
    format!(
        "did:web:{}",
        spiffe_id
            .strip_prefix("spiffe://")
            .unwrap_or(spiffe_id)
            .replace('/', ":")
    )
}

/// Configuration for a trusted WIMSE/SPIFFE identity provider.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WimseProviderConfig {
    /// Human-readable name.
    pub name: String,
    /// Expected `iss` claim value.
    pub issuer: String,
    /// JWKS URI for signature verification.
    pub jwks_uri: String,
    /// Expected `aud` claim value.
    pub audience: String,
    /// Permission set assigned to agents from this provider.
    #[serde(default = "default_permissions")]
    pub default_permissions: String,
}

fn default_permissions() -> String {
    "restricted".to_string()
}

/// Top-level WIMSE authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WimseAuthConfig {
    /// Whether WIMSE authentication is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Trusted WIMSE/SPIFFE identity providers.
    #[serde(default)]
    pub trusted_providers: Vec<WimseProviderConfig>,
    /// Also accept raw SPIFFE JWT-SVIDs (without WIMSE extensions).
    #[serde(default)]
    pub accept_spiffe_svid: bool,
}

/// JWT claims from a WIMSE/SPIFFE token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WimseClaims {
    /// Subject — must be a SPIFFE ID (`spiffe://...`).
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
    /// WIMSE workload identifier (optional extension).
    #[serde(default)]
    pub wimse_id: Option<String>,
    /// Owner identity (AIMS dual-identity extension).
    #[serde(default)]
    pub owner: Option<OwnerIdentity>,
}

/// JWT `aud` can be a single string or an array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

struct JwksCache {
    keys: jwk::JwkSet,
    fetched_at: Instant,
}

/// Authenticator that verifies WIMSE/SPIFFE JWT tokens.
pub struct WimseAuthenticator {
    config: WimseAuthConfig,
    jwks_caches: RwLock<HashMap<String, JwksCache>>,
}

impl WimseAuthenticator {
    pub fn new(config: WimseAuthConfig) -> Self {
        Self {
            config,
            jwks_caches: RwLock::new(HashMap::new()),
        }
    }

    fn verify_jwt(
        &self,
        token: &str,
        provider: &WimseProviderConfig,
    ) -> Result<WimseClaims, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::InvalidToken)?;
        let kid = header.kid.as_deref().ok_or(AuthError::InvalidToken)?;

        let jwks = self.get_or_fetch_jwks(&provider.jwks_uri)?;

        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
            .ok_or(AuthError::InvalidToken)?;

        let key = DecodingKey::from_jwk(jwk).map_err(|_| AuthError::InvalidToken)?;

        let alg = jwk
            .common
            .key_algorithm
            .and_then(|a| match a {
                jwk::KeyAlgorithm::RS256 => Some(Algorithm::RS256),
                jwk::KeyAlgorithm::RS384 => Some(Algorithm::RS384),
                jwk::KeyAlgorithm::RS512 => Some(Algorithm::RS512),
                jwk::KeyAlgorithm::ES256 => Some(Algorithm::ES256),
                jwk::KeyAlgorithm::ES384 => Some(Algorithm::ES384),
                jwk::KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
                _ => None,
            })
            .unwrap_or(header.alg);

        let mut validation = Validation::new(alg);
        validation.validate_exp = true;
        validation.set_audience(&[&provider.audience]);
        validation.set_issuer(&[&provider.issuer]);

        let token_data = decode::<WimseClaims>(token, &key, &validation).map_err(|e| {
            tracing::debug!(error = %e, provider = %provider.name, "WIMSE JWT verification failed");
            AuthError::InvalidToken
        })?;

        let claims = token_data.claims;

        if !claims.sub.starts_with("spiffe://") && !self.config.accept_spiffe_svid {
            tracing::debug!(sub = %claims.sub, "WIMSE subject is not a SPIFFE ID");
            return Err(AuthError::InvalidToken);
        }

        Ok(claims)
    }

    fn get_or_fetch_jwks(&self, jwks_uri: &str) -> Result<jwk::JwkSet, AuthError> {
        {
            let cache = self.jwks_caches.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = cache.get(jwks_uri)
                && entry.fetched_at.elapsed().as_secs() < 300 {
                    return Ok(entry.keys.clone());
                }
        }

        let jwks = fetch_jwks(jwks_uri)?;

        {
            let mut cache = self
                .jwks_caches
                .write()
                .unwrap_or_else(|e| e.into_inner());
            cache.insert(
                jwks_uri.to_string(),
                JwksCache {
                    keys: jwks.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }

        Ok(jwks)
    }
}

fn fetch_jwks(jwks_uri: &str) -> Result<jwk::JwkSet, AuthError> {
    let agent = ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(std::time::Duration::from_secs(5)))
            .build(),
    );

    agent
        .get(jwks_uri)
        .call()
        .map_err(|e| {
            tracing::error!(uri = %jwks_uri, error = %e, "Failed to fetch JWKS");
            AuthError::InvalidToken
        })?
        .into_body()
        .read_json::<jwk::JwkSet>()
        .map_err(|e| {
            tracing::error!(uri = %jwks_uri, error = %e, "Failed to parse JWKS");
            AuthError::InvalidToken
        })
}

impl Authenticator for WimseAuthenticator {
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

        // Skip tokens that belong to other authenticators
        if token.starts_with("navra_cap_v1.") {
            return Err(AuthError::InvalidToken);
        }

        let mut last_err = AuthError::InvalidToken;
        for provider in &self.config.trusted_providers {
            match self.verify_jwt(token, provider) {
                Ok(claims) => {
                    let wimse = WimseIdentity {
                        spiffe_id: claims.sub.clone(),
                        workload_id: claims.wimse_id,
                        owner: claims.owner,
                    };

                    let did = if claims.sub.starts_with("spiffe://") {
                        Some(spiffe_to_did(&claims.sub))
                    } else {
                        None
                    };

                    return Ok(AgentIdentity {
                        name: claims.sub,
                        permissions: provider.default_permissions.clone(),
                        signing_key: None,
                        did,
                        capabilities: None,
                        model: None,
                        allowed_upstreams: Vec::new(),
                        max_concurrent: None,
                        max_context: None,
                        wimse: Some(wimse),
                    });
                }
                Err(e) => last_err = e,
            }
        }

        Err(last_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spiffe_to_did_basic() {
        assert_eq!(
            spiffe_to_did("spiffe://example.org/agent/analyst"),
            "did:web:example.org:agent:analyst"
        );
    }

    #[test]
    fn spiffe_to_did_root() {
        assert_eq!(
            spiffe_to_did("spiffe://example.org"),
            "did:web:example.org"
        );
    }

    #[test]
    fn spiffe_to_did_deep_path() {
        assert_eq!(
            spiffe_to_did("spiffe://corp.example.com/ns/prod/sa/worker"),
            "did:web:corp.example.com:ns:prod:sa:worker"
        );
    }

    #[test]
    fn spiffe_to_did_no_prefix() {
        assert_eq!(
            spiffe_to_did("example.org/agent"),
            "did:web:example.org:agent"
        );
    }

    #[test]
    fn wimse_identity_serialization_roundtrip() {
        let wimse = WimseIdentity {
            spiffe_id: "spiffe://example.org/agent/test".to_string(),
            workload_id: Some("wl-001".to_string()),
            owner: Some(OwnerIdentity {
                sub: "alice@example.org".to_string(),
                iss: "https://idp.example.org".to_string(),
                org: Some("ACME Corp".to_string()),
            }),
        };

        let json = serde_json::to_string(&wimse).unwrap();
        let deserialized: WimseIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(wimse, deserialized);
    }

    #[test]
    fn wimse_identity_minimal() {
        let wimse = WimseIdentity {
            spiffe_id: "spiffe://example.org/agent".to_string(),
            workload_id: None,
            owner: None,
        };

        let json = serde_json::to_string(&wimse).unwrap();
        assert!(!json.contains("workload_id"));
        assert!(!json.contains("owner"));

        let deserialized: WimseIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(wimse, deserialized);
    }

    #[test]
    fn disabled_authenticator_rejects() {
        let config = WimseAuthConfig {
            enabled: false,
            trusted_providers: vec![],
            accept_spiffe_svid: false,
        };
        let auth = WimseAuthenticator::new(config);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer some-jwt".parse().unwrap());

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn cap_tokens_skipped_by_wimse() {
        let config = WimseAuthConfig {
            enabled: true,
            trusted_providers: vec![],
            accept_spiffe_svid: false,
        };
        let auth = WimseAuthenticator::new(config);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer navra_cap_v1.some.thing".parse().unwrap(),
        );

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn no_providers_rejects() {
        let config = WimseAuthConfig {
            enabled: true,
            trusted_providers: vec![],
            accept_spiffe_svid: false,
        };
        let auth = WimseAuthenticator::new(config);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer some-jwt-token".parse().unwrap());

        let err = auth.authenticate(&headers).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn owner_identity_full_fields() {
        let owner = OwnerIdentity {
            sub: "bob@corp.example".to_string(),
            iss: "https://auth.corp.example".to_string(),
            org: Some("Engineering".to_string()),
        };

        let json = serde_json::to_string(&owner).unwrap();
        let rt: OwnerIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(owner, rt);
    }

    #[test]
    fn owner_identity_without_org() {
        let owner = OwnerIdentity {
            sub: "carol@example.com".to_string(),
            iss: "https://idp.example.com".to_string(),
            org: None,
        };

        let json = serde_json::to_string(&owner).unwrap();
        assert!(!json.contains("org"));
    }
}
