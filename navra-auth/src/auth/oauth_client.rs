//! OAuth 2.1 client for authenticating to upstream MCP servers.
//!
//! Implements the MCP authorization SEPs from the 2026-07-28 RC:
//! - SEP-2468: `iss` parameter validation (RFC 9207)
//! - SEP-837: `application_type` in DCR
//! - SEP-2352: credential binding to issuing server
//! - SEP-2350: client-side scope accumulation
//! - SEP-2207: conditional `offline_access` / refresh tokens
//! - SEP-2351: RFC 8414 well-known URI discovery

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, DeviceAuthorizationUrl,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
    StandardDeviceAuthorizationResponse, TokenUrl,
};
use oauth2_reqwest::ReqwestClient;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;

/// Errors from OAuth client operations.
#[derive(Debug, thiserror::Error)]
pub enum OAuthClientError {
    #[error("AS metadata discovery failed: {0}")]
    DiscoveryFailed(String),
    #[error("dynamic client registration failed: {0}")]
    RegistrationFailed(String),
    #[error("authorization failed: {0}")]
    AuthorizationFailed(String),
    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),
    #[error("iss validation failed: expected {expected}, got {got}")]
    IssValidation { expected: String, got: String },
    #[error("iss parameter missing but required by AS")]
    IssMissing,
    #[error("credential issuer mismatch: stored {stored}, current {current}")]
    IssuerMigration { stored: String, current: String },
    #[error("pre-registered credentials cannot be re-registered on issuer migration")]
    PreRegisteredMigration,
    #[error("callback server failed: {0}")]
    CallbackFailed(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("timeout waiting for authorization callback")]
    CallbackTimeout,
}

// ── Authorization Server Metadata (RFC 8414) ────────────────────────

/// Authorization server metadata per RFC 8414.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsMetadata {
    pub issuer: String,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(default)]
    pub response_types_supported: Option<Vec<String>>,
    #[serde(default)]
    pub grant_types_supported: Option<Vec<String>>,
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: Option<bool>,
}

/// Protected Resource Metadata per RFC 9728.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    #[serde(default)]
    pub authorization_servers: Option<Vec<String>>,
}

/// Discover the authorization server for a given resource URL.
///
/// 1. Fetch Protected Resource Metadata (RFC 9728) from the resource server
/// 2. Extract the AS issuer URL
/// 3. Fetch AS metadata from `/.well-known/oauth-authorization-server` (RFC 8414)
/// 4. Fall back to `/.well-known/openid-configuration` (SEP-2351)
pub async fn discover_as(
    http: &reqwest::Client,
    resource_url: &Url,
) -> Result<AsMetadata, OAuthClientError> {
    // Try Protected Resource Metadata first
    let prm_url = {
        let mut u = resource_url.clone();
        u.set_path("/.well-known/oauth-protected-resource");
        u
    };

    let as_issuer = match http.get(prm_url.as_str()).send().await {
        Ok(resp) if resp.status().is_success() => {
            let prm: ProtectedResourceMetadata = resp
                .json()
                .await
                .map_err(|e| OAuthClientError::DiscoveryFailed(e.to_string()))?;
            prm.authorization_servers
                .and_then(|servers| servers.into_iter().next())
        }
        _ => None,
    };

    let issuer_base = match as_issuer {
        Some(issuer) => Url::parse(&issuer)
            .map_err(|e| OAuthClientError::DiscoveryFailed(format!("invalid issuer URL: {e}")))?,
        None => {
            let mut base = resource_url.clone();
            base.set_path("/");
            base.set_query(None);
            base.set_fragment(None);
            base
        }
    };

    // RFC 8414: /.well-known/oauth-authorization-server (SEP-2351)
    let rfc8414_url = well_known_url(&issuer_base, "oauth-authorization-server");
    if let Ok(metadata) = fetch_as_metadata(http, &rfc8414_url).await {
        return Ok(metadata);
    }

    // Fallback: /.well-known/openid-configuration
    let oidc_url = well_known_url(&issuer_base, "openid-configuration");
    fetch_as_metadata(http, &oidc_url).await
}

fn well_known_url(issuer: &Url, suffix: &str) -> Url {
    let path = issuer.path().trim_end_matches('/');
    let mut u = issuer.clone();
    if path.is_empty() || path == "/" {
        u.set_path(&format!("/.well-known/{suffix}"));
    } else {
        // Path-inserted form per RFC 8414 §3.1
        u.set_path(&format!("/.well-known/{suffix}{path}"));
    }
    u
}

async fn fetch_as_metadata(
    http: &reqwest::Client,
    url: &Url,
) -> Result<AsMetadata, OAuthClientError> {
    let resp = http
        .get(url.as_str())
        .send()
        .await
        .map_err(|e| OAuthClientError::DiscoveryFailed(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(OAuthClientError::DiscoveryFailed(format!(
            "HTTP {} from {url}",
            resp.status()
        )));
    }

    resp.json()
        .await
        .map_err(|e| OAuthClientError::DiscoveryFailed(e.to_string()))
}

// ── ISS Parameter Validation (SEP-2468 / RFC 9207) ──────────────────

/// Validate the `iss` parameter from an OAuth authorization callback.
///
/// Per RFC 9207 / SEP-2468, the `iss` query parameter in the
/// authorization response must match the AS issuer using simple
/// string comparison (RFC 3986 §6.2.1 — no normalization).
pub fn validate_iss(
    as_metadata: &AsMetadata,
    callback_iss: Option<&str>,
) -> Result<(), OAuthClientError> {
    let as_supports_iss = as_metadata
        .authorization_response_iss_parameter_supported
        .unwrap_or(false);

    match (as_supports_iss, callback_iss) {
        (true, Some(iss)) => {
            if iss == as_metadata.issuer {
                Ok(())
            } else {
                Err(OAuthClientError::IssValidation {
                    expected: as_metadata.issuer.clone(),
                    got: iss.to_string(),
                })
            }
        }
        (true, None) => Err(OAuthClientError::IssMissing),
        (false, Some(iss)) => {
            if iss == as_metadata.issuer {
                Ok(())
            } else {
                Err(OAuthClientError::IssValidation {
                    expected: as_metadata.issuer.clone(),
                    got: iss.to_string(),
                })
            }
        }
        (false, None) => Ok(()),
    }
}

// ── Credential Store (SEP-2352) ─────────────────────────────────────

/// Credentials obtained from or pre-registered with an AS.
#[derive(Debug, Clone)]
pub struct StoredCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub registered_via_dcr: bool,
}

/// Result of checking whether an AS issuer has changed.
#[derive(Debug, PartialEq)]
pub enum MigrationCheck {
    /// Stored issuer matches.
    Same,
    /// No stored credentials for this server.
    NotStored,
    /// Issuer changed; DCR credentials can be re-registered.
    MigratedDcr { old_issuer: String },
    /// Issuer changed; pre-registered credentials cannot be migrated.
    MigratedPreRegistered { old_issuer: String },
}

/// Thread-safe store mapping AS issuer URLs to client credentials.
///
/// Per SEP-2352, credentials are bound to the issuing server and
/// must not be reused across different authorization servers.
#[derive(Debug, Clone)]
pub struct CredentialStore {
    inner: Arc<Mutex<CredentialStoreInner>>,
}

#[derive(Debug, Default)]
struct CredentialStoreInner {
    /// Map from issuer URL → credentials.
    credentials: HashMap<String, StoredCredentials>,
    /// Map from upstream server URL → last known issuer URL.
    server_issuers: HashMap<String, String>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(CredentialStoreInner::default())),
        }
    }

    pub async fn get(&self, issuer_url: &str) -> Option<StoredCredentials> {
        self.inner.lock().await.credentials.get(issuer_url).cloned()
    }

    pub async fn store(&self, issuer_url: &str, credentials: StoredCredentials) {
        self.inner
            .lock()
            .await
            .credentials
            .insert(issuer_url.to_string(), credentials);
    }

    pub async fn remove(&self, issuer_url: &str) {
        self.inner.lock().await.credentials.remove(issuer_url);
    }

    /// Record the issuer for a server URL and check for migration.
    pub async fn check_issuer_migration(
        &self,
        server_url: &str,
        current_issuer: &str,
    ) -> MigrationCheck {
        let mut inner = self.inner.lock().await;

        match inner.server_issuers.get(server_url) {
            None => {
                inner
                    .server_issuers
                    .insert(server_url.to_string(), current_issuer.to_string());
                if inner.credentials.contains_key(current_issuer) {
                    MigrationCheck::Same
                } else {
                    MigrationCheck::NotStored
                }
            }
            Some(stored_issuer) if stored_issuer == current_issuer => MigrationCheck::Same,
            Some(stored_issuer) => {
                let old_issuer = stored_issuer.clone();
                inner
                    .server_issuers
                    .insert(server_url.to_string(), current_issuer.to_string());
                match inner.credentials.get(&old_issuer) {
                    Some(creds) if creds.registered_via_dcr => {
                        inner.credentials.remove(&old_issuer);
                        MigrationCheck::MigratedDcr { old_issuer }
                    }
                    Some(_) => MigrationCheck::MigratedPreRegistered { old_issuer },
                    None => MigrationCheck::NotStored,
                }
            }
        }
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Scope Accumulator (SEP-2350) ────────────────────────────────────

/// Tracks all scopes requested across the lifetime of an upstream
/// connection. Per SEP-2350, on a 403 `insufficient_scope` response,
/// the client must re-authorize with the union of all previously
/// requested scopes and the newly challenged scopes.
#[derive(Debug, Clone, Default)]
pub struct ScopeAccumulator {
    scopes: HashSet<String>,
}

impl ScopeAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, scopes: &[String]) {
        for s in scopes {
            self.scopes.insert(s.clone());
        }
    }

    pub fn union_with(&mut self, challenged_scopes: &[String]) -> Vec<String> {
        for s in challenged_scopes {
            self.scopes.insert(s.clone());
        }
        self.all()
    }

    pub fn all(&self) -> Vec<String> {
        let mut v: Vec<_> = self.scopes.iter().cloned().collect();
        v.sort();
        v
    }
}

// ── Token Set ───────────────────────────────────────────────────────

/// A set of tokens received from an authorization server.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<std::time::Instant>,
    pub scopes: Vec<String>,
}

impl TokenSet {
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|at| std::time::Instant::now() >= at)
            .unwrap_or(false)
    }
}

// ── Dynamic Client Registration (RFC 7591 + SEP-837) ────────────────

/// Request body for Dynamic Client Registration.
#[derive(Debug, Clone, Serialize)]
pub struct DcrRequest {
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub application_type: String,
    pub token_endpoint_auth_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// Response from Dynamic Client Registration.
#[derive(Debug, Clone, Deserialize)]
pub struct DcrResponse {
    pub client_id: String,
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub client_name: Option<String>,
}

/// Register with an AS via Dynamic Client Registration (RFC 7591).
///
/// Per SEP-837, always includes `application_type: "native"`.
/// Per SEP-2207, includes `refresh_token` in grant_types.
pub async fn register_client(
    http: &reqwest::Client,
    as_metadata: &AsMetadata,
    redirect_uri: &str,
    client_name: Option<&str>,
) -> Result<DcrResponse, OAuthClientError> {
    let registration_url = as_metadata.registration_endpoint.as_ref().ok_or_else(|| {
        OAuthClientError::RegistrationFailed("AS has no registration_endpoint".to_string())
    })?;

    let request = DcrRequest {
        redirect_uris: vec![redirect_uri.to_string()],
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        response_types: vec!["code".to_string()],
        client_name: client_name.map(|s| s.to_string()),
        application_type: "native".to_string(),
        token_endpoint_auth_method: "client_secret_post".to_string(),
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
    };

    let resp = http
        .post(registration_url)
        .json(&request)
        .send()
        .await
        .map_err(|e| OAuthClientError::RegistrationFailed(e.to_string()))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(OAuthClientError::RegistrationFailed(format!(
            "HTTP {}: {body}",
            body.len()
        )));
    }

    resp.json()
        .await
        .map_err(|e| OAuthClientError::RegistrationFailed(e.to_string()))
}

// ── OAuth Flows ─────────────────────────────────────────────────────

/// State for an in-progress Authorization Code + PKCE flow.
pub struct PendingAuthorization {
    pub auth_url: Url,
    pub csrf_token: CsrfToken,
    pub pkce_verifier: PkceCodeVerifier,
    pub issuer: String,
    pub redirect_uri: String,
}

/// Build an authorization URL for the Authorization Code + PKCE flow.
pub fn build_auth_url(
    as_metadata: &AsMetadata,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    scopes: &[String],
) -> Result<PendingAuthorization, OAuthClientError> {
    let auth_endpoint = as_metadata.authorization_endpoint.as_ref().ok_or_else(|| {
        OAuthClientError::AuthorizationFailed("AS has no authorization_endpoint".to_string())
    })?;
    let token_endpoint = as_metadata.token_endpoint.as_ref().ok_or_else(|| {
        OAuthClientError::AuthorizationFailed("AS has no token_endpoint".to_string())
    })?;

    let mut client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_auth_uri(
            AuthUrl::new(auth_endpoint.clone())
                .map_err(|e| OAuthClientError::AuthorizationFailed(e.to_string()))?,
        )
        .set_token_uri(
            TokenUrl::new(token_endpoint.clone())
                .map_err(|e| OAuthClientError::AuthorizationFailed(e.to_string()))?,
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_string())
                .map_err(|e| OAuthClientError::AuthorizationFailed(e.to_string()))?,
        );

    if let Some(secret) = client_secret {
        client = client.set_client_secret(ClientSecret::new(secret.to_string()));
    }

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth_request = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge);

    for scope in scopes {
        auth_request = auth_request.add_scope(Scope::new(scope.clone()));
    }

    let (auth_url, csrf_token) = auth_request.url();

    Ok(PendingAuthorization {
        auth_url,
        csrf_token,
        pkce_verifier,
        issuer: as_metadata.issuer.clone(),
        redirect_uri: redirect_uri.to_string(),
    })
}

/// Exchange an authorization code for tokens.
///
/// Validates the `iss` parameter per SEP-2468 before exchanging.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_code(
    http: &reqwest::Client,
    as_metadata: &AsMetadata,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    code: &str,
    pkce_verifier: PkceCodeVerifier,
    callback_iss: Option<&str>,
) -> Result<TokenSet, OAuthClientError> {
    validate_iss(as_metadata, callback_iss)?;

    let token_endpoint = as_metadata.token_endpoint.as_ref().ok_or_else(|| {
        OAuthClientError::TokenExchangeFailed("AS has no token_endpoint".to_string())
    })?;

    let mut client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_token_uri(
            TokenUrl::new(token_endpoint.clone())
                .map_err(|e| OAuthClientError::TokenExchangeFailed(e.to_string()))?,
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_string())
                .map_err(|e| OAuthClientError::TokenExchangeFailed(e.to_string()))?,
        );

    if let Some(secret) = client_secret {
        client = client.set_client_secret(ClientSecret::new(secret.to_string()));
    }

    let oauth_http = build_oauth_http_client(http);

    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&oauth_http)
        .await
        .map_err(|e| OAuthClientError::TokenExchangeFailed(e.to_string()))?;

    Ok(token_result_to_set(&token_result))
}

/// Request tokens via Client Credentials grant.
pub async fn client_credentials(
    http: &reqwest::Client,
    as_metadata: &AsMetadata,
    client_id: &str,
    client_secret: &str,
    scopes: &[String],
) -> Result<TokenSet, OAuthClientError> {
    let token_endpoint = as_metadata.token_endpoint.as_ref().ok_or_else(|| {
        OAuthClientError::TokenExchangeFailed("AS has no token_endpoint".to_string())
    })?;

    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(client_secret.to_string()))
        .set_token_uri(
            TokenUrl::new(token_endpoint.clone())
                .map_err(|e| OAuthClientError::TokenExchangeFailed(e.to_string()))?,
        );

    let oauth_http = build_oauth_http_client(http);

    let mut request = client.exchange_client_credentials();
    for scope in scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }

    let token_result = request
        .request_async(&oauth_http)
        .await
        .map_err(|e| OAuthClientError::TokenExchangeFailed(e.to_string()))?;

    Ok(token_result_to_set(&token_result))
}

/// Initiate a Device Authorization flow (RFC 8628).
pub async fn device_authorize(
    http: &reqwest::Client,
    as_metadata: &AsMetadata,
    client_id: &str,
    scopes: &[String],
) -> Result<StandardDeviceAuthorizationResponse, OAuthClientError> {
    let device_url = as_metadata
        .device_authorization_endpoint
        .as_ref()
        .ok_or_else(|| {
            OAuthClientError::AuthorizationFailed(
                "AS has no device_authorization_endpoint".to_string(),
            )
        })?;

    let token_endpoint = as_metadata.token_endpoint.as_ref().ok_or_else(|| {
        OAuthClientError::AuthorizationFailed("AS has no token_endpoint".to_string())
    })?;

    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_device_authorization_url(
            DeviceAuthorizationUrl::new(device_url.clone())
                .map_err(|e| OAuthClientError::AuthorizationFailed(e.to_string()))?,
        )
        .set_token_uri(
            TokenUrl::new(token_endpoint.clone())
                .map_err(|e| OAuthClientError::AuthorizationFailed(e.to_string()))?,
        );

    let oauth_http = build_oauth_http_client(http);

    let mut request = client.exchange_device_code();
    for scope in scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }

    request
        .request_async(&oauth_http)
        .await
        .map_err(|e| OAuthClientError::AuthorizationFailed(e.to_string()))
}

/// Poll for device authorization completion.
pub async fn device_poll(
    http: &reqwest::Client,
    as_metadata: &AsMetadata,
    client_id: &str,
    device_auth_response: &StandardDeviceAuthorizationResponse,
    timeout: std::time::Duration,
) -> Result<TokenSet, OAuthClientError> {
    let token_endpoint = as_metadata.token_endpoint.as_ref().ok_or_else(|| {
        OAuthClientError::TokenExchangeFailed("AS has no token_endpoint".to_string())
    })?;

    let client = BasicClient::new(ClientId::new(client_id.to_string())).set_token_uri(
        TokenUrl::new(token_endpoint.clone())
            .map_err(|e| OAuthClientError::TokenExchangeFailed(e.to_string()))?,
    );

    let oauth_http = build_oauth_http_client(http);

    let token_result = client
        .exchange_device_access_token(device_auth_response)
        .request_async(&oauth_http, tokio::time::sleep, Some(timeout))
        .await
        .map_err(|e| OAuthClientError::TokenExchangeFailed(e.to_string()))?;

    Ok(token_result_to_set(&token_result))
}

/// Refresh an access token.
pub async fn refresh_token(
    http: &reqwest::Client,
    as_metadata: &AsMetadata,
    client_id: &str,
    client_secret: Option<&str>,
    refresh: &str,
) -> Result<TokenSet, OAuthClientError> {
    let token_endpoint = as_metadata.token_endpoint.as_ref().ok_or_else(|| {
        OAuthClientError::TokenExchangeFailed("AS has no token_endpoint".to_string())
    })?;

    let mut client = BasicClient::new(ClientId::new(client_id.to_string())).set_token_uri(
        TokenUrl::new(token_endpoint.clone())
            .map_err(|e| OAuthClientError::TokenExchangeFailed(e.to_string()))?,
    );

    if let Some(secret) = client_secret {
        client = client.set_client_secret(ClientSecret::new(secret.to_string()));
    }

    let oauth_http = build_oauth_http_client(http);

    let token_result = client
        .exchange_refresh_token(&RefreshToken::new(refresh.to_string()))
        .request_async(&oauth_http)
        .await
        .map_err(|e| OAuthClientError::TokenExchangeFailed(e.to_string()))?;

    Ok(token_result_to_set(&token_result))
}

// ── Localhost Callback Server ───────────────────────────────────────

/// Parameters extracted from an OAuth authorization callback.
#[derive(Debug)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
    pub iss: Option<String>,
}

/// Spawn a temporary HTTP server on localhost to capture the
/// authorization callback. Returns the callback parameters.
pub async fn await_callback(
    port: u16,
    timeout: std::time::Duration,
) -> Result<CallbackParams, OAuthClientError> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .map_err(|e| OAuthClientError::CallbackFailed(e.to_string()))?;

    let result = tokio::time::timeout(timeout, accept_callback(&listener)).await;

    match result {
        Ok(Ok(params)) => Ok(params),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(OAuthClientError::CallbackTimeout),
    }
}

async fn accept_callback(
    listener: &tokio::net::TcpListener,
) -> Result<CallbackParams, OAuthClientError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut stream, _) = listener
        .accept()
        .await
        .map_err(|e| OAuthClientError::CallbackFailed(e.to_string()))?;

    let mut buf = vec![0u8; 4096];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| OAuthClientError::CallbackFailed(e.to_string()))?;
    let request = String::from_utf8_lossy(&buf[..n]);

    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| OAuthClientError::CallbackFailed("empty request".to_string()))?;

    let path = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| OAuthClientError::CallbackFailed("malformed request".to_string()))?;

    let response_body = "Authorization received. You may close this window.";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
        response_body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;

    let url = Url::parse(&format!("http://localhost{path}"))
        .map_err(|e| OAuthClientError::CallbackFailed(e.to_string()))?;

    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| OAuthClientError::CallbackFailed("missing code parameter".to_string()))?;

    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| OAuthClientError::CallbackFailed("missing state parameter".to_string()))?;

    let iss = url
        .query_pairs()
        .find(|(k, _)| k == "iss")
        .map(|(_, v)| v.to_string());

    Ok(CallbackParams { code, state, iss })
}

// ── Helpers ─────────────────────────────────────────────────────────

fn build_oauth_http_client(_base: &reqwest::Client) -> ReqwestClient {
    ReqwestClient::from(
        reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client should build"),
    )
}

fn token_result_to_set(
    result: &oauth2::StandardTokenResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
) -> TokenSet {
    use oauth2::TokenResponse;

    let expires_at = result.expires_in().map(|d| std::time::Instant::now() + d);

    let scopes = result
        .scopes()
        .map(|s| s.iter().map(|scope| scope.to_string()).collect())
        .unwrap_or_default();

    TokenSet {
        access_token: result.access_token().secret().to_string(),
        refresh_token: result.refresh_token().map(|t| t.secret().to_string()),
        expires_at,
        scopes,
    }
}

/// Parse the `scope` parameter from a `WWW-Authenticate: Bearer` header value.
pub fn parse_www_authenticate_scope(header: &str) -> Vec<String> {
    // WWW-Authenticate: Bearer realm="example", scope="read write", error="insufficient_scope"
    let scope_prefix = "scope=\"";
    if let Some(start) = header.find(scope_prefix) {
        let rest = &header[start + scope_prefix.len()..];
        if let Some(end) = rest.find('"') {
            return rest[..end]
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
        }
    }
    Vec::new()
}

/// Check if the AS metadata supports `offline_access` scope (SEP-2207).
pub fn supports_offline_access(as_metadata: &AsMetadata) -> bool {
    as_metadata
        .scopes_supported
        .as_ref()
        .map(|s| s.iter().any(|scope| scope == "offline_access"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_as_metadata() -> AsMetadata {
        AsMetadata {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: Some("https://auth.example.com/authorize".to_string()),
            token_endpoint: Some("https://auth.example.com/token".to_string()),
            registration_endpoint: Some("https://auth.example.com/register".to_string()),
            device_authorization_endpoint: Some("https://auth.example.com/device".to_string()),
            scopes_supported: Some(vec!["openid".to_string(), "offline_access".to_string()]),
            response_types_supported: Some(vec!["code".to_string()]),
            grant_types_supported: Some(vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
                "refresh_token".to_string(),
            ]),
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
            authorization_response_iss_parameter_supported: Some(true),
        }
    }

    // ── iss validation tests ────────────────────────────────────────

    #[test]
    fn iss_valid_when_matches() {
        let meta = test_as_metadata();
        assert!(validate_iss(&meta, Some("https://auth.example.com")).is_ok());
    }

    #[test]
    fn iss_rejected_when_mismatches() {
        let meta = test_as_metadata();
        let err = validate_iss(&meta, Some("https://evil.example.com")).unwrap_err();
        assert!(matches!(err, OAuthClientError::IssValidation { .. }));
    }

    #[test]
    fn iss_rejected_when_missing_but_required() {
        let meta = test_as_metadata();
        let err = validate_iss(&meta, None).unwrap_err();
        assert!(matches!(err, OAuthClientError::IssMissing));
    }

    #[test]
    fn iss_accepted_when_missing_and_not_required() {
        let mut meta = test_as_metadata();
        meta.authorization_response_iss_parameter_supported = Some(false);
        assert!(validate_iss(&meta, None).is_ok());
    }

    #[test]
    fn iss_rejected_when_wrong_even_if_not_required() {
        let mut meta = test_as_metadata();
        meta.authorization_response_iss_parameter_supported = Some(false);
        let err = validate_iss(&meta, Some("https://evil.example.com")).unwrap_err();
        assert!(matches!(err, OAuthClientError::IssValidation { .. }));
    }

    #[test]
    fn iss_no_normalization() {
        let meta = test_as_metadata();
        // Trailing slash is a different string per RFC 3986 §6.2.1
        let err = validate_iss(&meta, Some("https://auth.example.com/")).unwrap_err();
        assert!(matches!(err, OAuthClientError::IssValidation { .. }));
    }

    #[test]
    fn iss_default_not_supported_when_field_absent() {
        let mut meta = test_as_metadata();
        meta.authorization_response_iss_parameter_supported = None;
        assert!(validate_iss(&meta, None).is_ok());
    }

    // ── Credential store tests ──────────────────────────────────────

    #[tokio::test]
    async fn credential_store_basic_operations() {
        let store = CredentialStore::new();

        assert!(store.get("https://auth.example.com").await.is_none());

        store
            .store(
                "https://auth.example.com",
                StoredCredentials {
                    client_id: "test-client".to_string(),
                    client_secret: Some("secret".to_string()),
                    registered_via_dcr: true,
                },
            )
            .await;

        let creds = store.get("https://auth.example.com").await.unwrap();
        assert_eq!(creds.client_id, "test-client");
        assert!(creds.registered_via_dcr);

        store.remove("https://auth.example.com").await;
        assert!(store.get("https://auth.example.com").await.is_none());
    }

    #[tokio::test]
    async fn credential_store_issuer_same() {
        let store = CredentialStore::new();
        store
            .store(
                "https://auth.example.com",
                StoredCredentials {
                    client_id: "c".to_string(),
                    client_secret: None,
                    registered_via_dcr: true,
                },
            )
            .await;

        let check = store
            .check_issuer_migration("https://mcp.example.com", "https://auth.example.com")
            .await;
        assert_eq!(check, MigrationCheck::Same);
    }

    #[tokio::test]
    async fn credential_store_issuer_migration_dcr() {
        let store = CredentialStore::new();
        store
            .store(
                "https://old-auth.example.com",
                StoredCredentials {
                    client_id: "old-client".to_string(),
                    client_secret: None,
                    registered_via_dcr: true,
                },
            )
            .await;

        // First visit records the issuer
        store
            .check_issuer_migration("https://mcp.example.com", "https://old-auth.example.com")
            .await;

        // Issuer changes → DCR credentials get discarded
        let check = store
            .check_issuer_migration("https://mcp.example.com", "https://new-auth.example.com")
            .await;
        assert_eq!(
            check,
            MigrationCheck::MigratedDcr {
                old_issuer: "https://old-auth.example.com".to_string()
            }
        );
        assert!(store.get("https://old-auth.example.com").await.is_none());
    }

    #[tokio::test]
    async fn credential_store_issuer_migration_pre_registered() {
        let store = CredentialStore::new();
        store
            .store(
                "https://old-auth.example.com",
                StoredCredentials {
                    client_id: "pre-reg".to_string(),
                    client_secret: Some("secret".to_string()),
                    registered_via_dcr: false,
                },
            )
            .await;

        store
            .check_issuer_migration("https://mcp.example.com", "https://old-auth.example.com")
            .await;

        let check = store
            .check_issuer_migration("https://mcp.example.com", "https://new-auth.example.com")
            .await;
        assert_eq!(
            check,
            MigrationCheck::MigratedPreRegistered {
                old_issuer: "https://old-auth.example.com".to_string()
            }
        );
    }

    #[tokio::test]
    async fn credential_store_not_stored() {
        let store = CredentialStore::new();
        let check = store
            .check_issuer_migration("https://mcp.example.com", "https://auth.example.com")
            .await;
        assert_eq!(check, MigrationCheck::NotStored);
    }

    // ── Scope accumulator tests ─────────────────────────────────────

    #[test]
    fn scope_accumulator_basic() {
        let mut acc = ScopeAccumulator::new();
        acc.add(&["read".to_string(), "write".to_string()]);
        assert_eq!(acc.all(), vec!["read", "write"]);
    }

    #[test]
    fn scope_accumulator_dedup() {
        let mut acc = ScopeAccumulator::new();
        acc.add(&["read".to_string(), "write".to_string()]);
        acc.add(&["read".to_string(), "admin".to_string()]);
        assert_eq!(acc.all(), vec!["admin", "read", "write"]);
    }

    #[test]
    fn scope_accumulator_union_with() {
        let mut acc = ScopeAccumulator::new();
        acc.add(&["read".to_string()]);
        let result = acc.union_with(&["write".to_string(), "admin".to_string()]);
        assert_eq!(result, vec!["admin", "read", "write"]);
    }

    #[test]
    fn scope_accumulator_empty() {
        let acc = ScopeAccumulator::new();
        assert!(acc.all().is_empty());
    }

    // ── Token set tests ─────────────────────────────────────────────

    #[test]
    fn token_set_not_expired_without_expiry() {
        let token = TokenSet {
            access_token: "test".to_string(),
            refresh_token: None,
            expires_at: None,
            scopes: vec![],
        };
        assert!(!token.is_expired());
    }

    #[test]
    fn token_set_not_expired_with_future_expiry() {
        let token = TokenSet {
            access_token: "test".to_string(),
            refresh_token: None,
            expires_at: Some(std::time::Instant::now() + std::time::Duration::from_secs(3600)),
            scopes: vec![],
        };
        assert!(!token.is_expired());
    }

    // ── Well-known URL construction ─────────────────────────────────

    #[test]
    fn well_known_url_root_path() {
        let issuer = Url::parse("https://auth.example.com").unwrap();
        let url = well_known_url(&issuer, "oauth-authorization-server");
        assert_eq!(
            url.as_str(),
            "https://auth.example.com/.well-known/oauth-authorization-server"
        );
    }

    #[test]
    fn well_known_url_with_path() {
        let issuer = Url::parse("https://auth.example.com/tenant/123").unwrap();
        let url = well_known_url(&issuer, "oauth-authorization-server");
        assert_eq!(
            url.as_str(),
            "https://auth.example.com/.well-known/oauth-authorization-server/tenant/123"
        );
    }

    #[test]
    fn well_known_url_trailing_slash() {
        let issuer = Url::parse("https://auth.example.com/").unwrap();
        let url = well_known_url(&issuer, "oauth-authorization-server");
        assert_eq!(
            url.as_str(),
            "https://auth.example.com/.well-known/oauth-authorization-server"
        );
    }

    // ── WWW-Authenticate parsing ────────────────────────────────────

    #[test]
    fn parse_www_authenticate_scope_basic() {
        let header = r#"Bearer realm="example", scope="read write admin""#;
        assert_eq!(
            parse_www_authenticate_scope(header),
            vec!["read", "write", "admin"]
        );
    }

    #[test]
    fn parse_www_authenticate_scope_empty() {
        let header = "Bearer realm=\"example\"";
        assert!(parse_www_authenticate_scope(header).is_empty());
    }

    #[test]
    fn parse_www_authenticate_scope_with_error() {
        let header = r#"Bearer realm="example", scope="mcp:tools mcp:resources", error="insufficient_scope""#;
        assert_eq!(
            parse_www_authenticate_scope(header),
            vec!["mcp:tools", "mcp:resources"]
        );
    }

    // ── offline_access support ──────────────────────────────────────

    #[test]
    fn supports_offline_access_true() {
        let meta = test_as_metadata();
        assert!(supports_offline_access(&meta));
    }

    #[test]
    fn supports_offline_access_false() {
        let mut meta = test_as_metadata();
        meta.scopes_supported = Some(vec!["openid".to_string()]);
        assert!(!supports_offline_access(&meta));
    }

    #[test]
    fn supports_offline_access_none() {
        let mut meta = test_as_metadata();
        meta.scopes_supported = None;
        assert!(!supports_offline_access(&meta));
    }

    // ── Build auth URL test ─────────────────────────────────────────

    #[test]
    fn build_auth_url_produces_valid_url() {
        let meta = test_as_metadata();
        let pending = build_auth_url(
            &meta,
            "test-client",
            Some("secret"),
            "http://127.0.0.1:9999/callback",
            &["openid".to_string()],
        )
        .unwrap();

        let url_str = pending.auth_url.to_string();
        assert!(url_str.starts_with("https://auth.example.com/authorize"));
        assert!(url_str.contains("client_id=test-client"));
        assert!(url_str.contains("redirect_uri="));
        assert!(url_str.contains("code_challenge="));
        assert!(url_str.contains("code_challenge_method=S256"));
        assert!(url_str.contains("scope=openid"));
        assert!(url_str.contains("state="));
        assert_eq!(pending.issuer, "https://auth.example.com");
    }

    // ── DCR request tests ───────────────────────────────────────────

    #[test]
    fn dcr_request_serialization() {
        let req = DcrRequest {
            redirect_uris: vec!["http://127.0.0.1:9999/callback".to_string()],
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            response_types: vec!["code".to_string()],
            client_name: Some("navra".to_string()),
            application_type: "native".to_string(),
            token_endpoint_auth_method: "client_secret_post".to_string(),
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["application_type"], "native");
        assert_eq!(json["grant_types"][1], "refresh_token");
        assert_eq!(json["token_endpoint_auth_method"], "client_secret_post");
    }

    // ── Callback server test ────────────────────────────────────────

    #[tokio::test]
    async fn callback_server_captures_params() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_handle = tokio::spawn(async move { accept_callback(&listener).await });

        // Simulate browser callback
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let client = reqwest::Client::new();
        let _ = client
            .get(format!(
                "http://127.0.0.1:{port}/callback?code=test-code&state=test-state&iss=https%3A%2F%2Fauth.example.com"
            ))
            .send()
            .await;

        let params = server_handle.await.unwrap().unwrap();
        assert_eq!(params.code, "test-code");
        assert_eq!(params.state, "test-state");
        assert_eq!(params.iss.as_deref(), Some("https://auth.example.com"));
    }

    #[tokio::test]
    async fn callback_timeout() {
        let result = await_callback(0, std::time::Duration::from_millis(100)).await;
        // Port 0 assigns a random port, and no one connects → timeout
        assert!(matches!(result, Err(OAuthClientError::CallbackTimeout)));
    }
}
