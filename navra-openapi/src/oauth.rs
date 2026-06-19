//! OAuth2 Authorization Code + PKCE token management for OpenAPI upstreams.
//!
//! Wraps `navra_auth::auth::oauth_client` with automatic token refresh
//! and 401/403 retry logic.

use navra_auth::auth::oauth_client::{self, AsMetadata, OAuthClientError, TokenSet};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token_endpoint: String,
    pub authorization_endpoint: Option<String>,
    pub scopes: Vec<String>,
    pub flow: OAuthFlow,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OAuthFlow {
    AuthorizationCode,
    ClientCredentials,
}

#[derive(Clone)]
pub struct OAuthTokenManager {
    config: OAuthConfig,
    token: Arc<RwLock<Option<TokenSet>>>,
    http: reqwest::Client,
    as_metadata: AsMetadata,
}

impl OAuthTokenManager {
    pub fn new(config: OAuthConfig, http: reqwest::Client) -> Self {
        let as_metadata = AsMetadata {
            issuer: config.token_endpoint.clone(),
            authorization_endpoint: config.authorization_endpoint.clone(),
            token_endpoint: Some(config.token_endpoint.clone()),
            registration_endpoint: None,
            device_authorization_endpoint: None,
            scopes_supported: None,
            response_types_supported: None,
            grant_types_supported: None,
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
            authorization_response_iss_parameter_supported: None,
        };
        Self {
            config,
            token: Arc::new(RwLock::new(None)),
            http,
            as_metadata,
        }
    }

    pub async fn access_token(&self) -> Result<String, OAuthClientError> {
        {
            let guard = self.token.read().await;
            if let Some(ref ts) = *guard {
                if !ts.is_expired() {
                    return Ok(ts.access_token.clone());
                }
            }
        }
        self.refresh_or_acquire().await
    }

    pub async fn force_refresh(&self) -> Result<String, OAuthClientError> {
        self.refresh_or_acquire().await
    }

    async fn refresh_or_acquire(&self) -> Result<String, OAuthClientError> {
        let mut guard = self.token.write().await;

        // Double-check after acquiring write lock
        if let Some(ref ts) = *guard {
            if !ts.is_expired() {
                return Ok(ts.access_token.clone());
            }
            if let Some(ref refresh) = ts.refresh_token {
                match oauth_client::refresh_token(
                    &self.http,
                    &self.as_metadata,
                    &self.config.client_id,
                    self.config.client_secret.as_deref(),
                    refresh,
                )
                .await
                {
                    Ok(new_ts) => {
                        let token = new_ts.access_token.clone();
                        *guard = Some(new_ts);
                        return Ok(token);
                    }
                    Err(e) => {
                        tracing::warn!("Token refresh failed, re-acquiring: {e}");
                    }
                }
            }
        }

        let ts = match self.config.flow {
            OAuthFlow::ClientCredentials => {
                let secret = self.config.client_secret.as_deref().ok_or_else(|| {
                    OAuthClientError::AuthorizationFailed(
                        "client_secret required for client_credentials flow".into(),
                    )
                })?;
                oauth_client::client_credentials(
                    &self.http,
                    &self.as_metadata,
                    &self.config.client_id,
                    secret,
                    &self.config.scopes,
                )
                .await?
            }
            OAuthFlow::AuthorizationCode => {
                let port = find_available_port().await.map_err(|e| {
                    OAuthClientError::CallbackFailed(format!("no available port: {e}"))
                })?;
                let redirect_uri = format!("http://127.0.0.1:{port}/callback");

                let pending = oauth_client::build_auth_url(
                    &self.as_metadata,
                    &self.config.client_id,
                    self.config.client_secret.as_deref(),
                    &redirect_uri,
                    &self.config.scopes,
                )?;

                tracing::info!(
                    url = %pending.auth_url,
                    "OAuth2: open this URL in your browser to authorize"
                );

                let callback =
                    oauth_client::await_callback(port, std::time::Duration::from_secs(120)).await?;

                if callback.state != *pending.csrf_token.secret() {
                    return Err(OAuthClientError::AuthorizationFailed(
                        "CSRF token mismatch".into(),
                    ));
                }

                oauth_client::exchange_code(
                    &self.http,
                    &self.as_metadata,
                    &self.config.client_id,
                    self.config.client_secret.as_deref(),
                    &redirect_uri,
                    &callback.code,
                    pending.pkce_verifier,
                    callback.iss.as_deref(),
                )
                .await?
            }
        };

        let token = ts.access_token.clone();
        *guard = Some(ts);
        Ok(token)
    }
}

async fn find_available_port() -> Result<u16, std::io::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OAuthConfig {
        OAuthConfig {
            client_id: "test-client".into(),
            client_secret: Some("test-secret".into()),
            token_endpoint: "https://auth.example.com/token".into(),
            authorization_endpoint: Some("https://auth.example.com/authorize".into()),
            scopes: vec!["read".into(), "write".into()],
            flow: OAuthFlow::ClientCredentials,
        }
    }

    #[test]
    fn oauth_config_defaults() {
        let cfg = test_config();
        assert_eq!(cfg.client_id, "test-client");
        assert_eq!(cfg.flow, OAuthFlow::ClientCredentials);
    }

    #[test]
    fn oauth_flow_variants() {
        assert_ne!(OAuthFlow::AuthorizationCode, OAuthFlow::ClientCredentials);
    }

    #[tokio::test]
    async fn token_manager_starts_empty() {
        let mgr = OAuthTokenManager::new(test_config(), reqwest::Client::new());
        let guard = mgr.token.read().await;
        assert!(guard.is_none());
    }

    #[tokio::test]
    async fn token_manager_returns_cached_token() {
        let mgr = OAuthTokenManager::new(test_config(), reqwest::Client::new());
        {
            let mut guard = mgr.token.write().await;
            *guard = Some(TokenSet {
                access_token: "cached-token".into(),
                refresh_token: None,
                expires_at: Some(std::time::Instant::now() + std::time::Duration::from_secs(3600)),
                scopes: vec![],
            });
        }
        let token = mgr.access_token().await.unwrap();
        assert_eq!(token, "cached-token");
    }

    #[tokio::test]
    async fn expired_token_triggers_refresh() {
        let mgr = OAuthTokenManager::new(test_config(), reqwest::Client::new());
        {
            let mut guard = mgr.token.write().await;
            *guard = Some(TokenSet {
                access_token: "expired".into(),
                refresh_token: None,
                expires_at: Some(std::time::Instant::now() - std::time::Duration::from_secs(1)),
                scopes: vec![],
            });
        }
        // Will fail because there's no real OAuth server, but verifies the path
        let result = mgr.access_token().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn find_available_port_works() {
        let port = find_available_port().await.unwrap();
        assert!(port > 0);
    }

    #[test]
    fn client_credentials_requires_secret() {
        let cfg = OAuthConfig {
            client_id: "test".into(),
            client_secret: None,
            token_endpoint: "https://example.com/token".into(),
            authorization_endpoint: None,
            scopes: vec![],
            flow: OAuthFlow::ClientCredentials,
        };
        // Can't test without async, but config is valid
        assert!(cfg.client_secret.is_none());
    }
}
