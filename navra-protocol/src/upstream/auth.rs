//! Token providers for upstream HTTP authentication.
//!
//! The `TokenProvider` trait abstracts over static Bearer tokens and
//! dynamic OAuth flows. `HttpTransport` calls the provider before
//! each request and on 401/403 responses.

use super::UpstreamError;
use async_trait::async_trait;
use std::sync::Arc;

/// Provides Bearer tokens for upstream HTTP requests.
///
/// Implementations range from a static token string to a full OAuth 2.1
/// client that handles AS discovery, token refresh, and step-up authorization.
#[async_trait]
pub trait TokenProvider: Send + Sync + 'static {
    /// Get the current access token, if available.
    ///
    /// Called before each HTTP request. Returns `None` if no token
    /// is available (unauthenticated request).
    async fn get_token(&self) -> Result<Option<String>, UpstreamError>;

    /// Handle a 401 Unauthorized response.
    ///
    /// The `www_authenticate` parameter contains the value of the
    /// `WWW-Authenticate` response header, if present. Returns a new
    /// access token to retry with, or an error if authentication fails.
    async fn handle_401(
        &self,
        upstream_name: &str,
        www_authenticate: Option<&str>,
    ) -> Result<String, UpstreamError>;

    /// Handle a 403 Forbidden response with `insufficient_scope`.
    ///
    /// Per SEP-2350, the client must accumulate scopes and re-authorize
    /// with the union. Returns a new access token with the expanded scope.
    async fn handle_403(
        &self,
        upstream_name: &str,
        www_authenticate: Option<&str>,
    ) -> Result<String, UpstreamError>;
}

/// A token provider that returns a static Bearer token.
pub struct StaticTokenProvider {
    token: Option<String>,
}

impl StaticTokenProvider {
    pub fn new(token: Option<String>) -> Arc<Self> {
        Arc::new(Self { token })
    }
}

#[async_trait]
impl TokenProvider for StaticTokenProvider {
    async fn get_token(&self) -> Result<Option<String>, UpstreamError> {
        Ok(self.token.clone())
    }

    async fn handle_401(
        &self,
        upstream_name: &str,
        _www_authenticate: Option<&str>,
    ) -> Result<String, UpstreamError> {
        Err(UpstreamError::Protocol {
            name: upstream_name.to_string(),
            message: "HTTP 401: static token rejected".to_string(),
        })
    }

    async fn handle_403(
        &self,
        upstream_name: &str,
        _www_authenticate: Option<&str>,
    ) -> Result<String, UpstreamError> {
        Err(UpstreamError::Protocol {
            name: upstream_name.to_string(),
            message: "HTTP 403: insufficient scope (static token cannot step up)".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_provider_returns_token() {
        let provider = StaticTokenProvider::new(Some("my-token".to_string()));
        assert_eq!(
            provider.get_token().await.unwrap(),
            Some("my-token".to_string())
        );
    }

    #[tokio::test]
    async fn static_provider_returns_none_when_no_token() {
        let provider = StaticTokenProvider::new(None);
        assert_eq!(provider.get_token().await.unwrap(), None);
    }

    #[tokio::test]
    async fn static_provider_401_errors() {
        let provider = StaticTokenProvider::new(Some("bad-token".to_string()));
        let result = provider.handle_401("test", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn static_provider_403_errors() {
        let provider = StaticTokenProvider::new(Some("limited-token".to_string()));
        let result = provider.handle_403("test", None).await;
        assert!(result.is_err());
    }
}
