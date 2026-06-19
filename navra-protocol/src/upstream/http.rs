//! HTTP transport: JSON-RPC over HTTP POST (MCP streamable-http).
//!
//! Sends JSON-RPC requests as POST to the upstream URL and reads
//! JSON-RPC responses from the response body. Supports pluggable
//! token providers for OAuth 2.1 authentication with 401/403 handling.

use super::auth::{StaticTokenProvider, TokenProvider};
use super::tls::TlsConfig;
use super::transport::Transport;
use super::UpstreamError;
use async_trait::async_trait;
use std::sync::Arc;

/// HTTP transport backed by reqwest.
pub struct HttpTransport {
    name: String,
    url: String,
    client: reqwest::Client,
    session_id: Option<String>,
    token_provider: Arc<dyn TokenProvider>,
}

impl HttpTransport {
    /// Create a new HTTP transport pointing at the given URL.
    ///
    /// The URL should be the MCP endpoint (e.g., `http://localhost:8001/mcp`).
    pub fn new(name: &str, url: &str) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
            client: reqwest::Client::new(),
            session_id: None,
            token_provider: StaticTokenProvider::new(None),
        }
    }

    /// Create an HTTP transport with TLS configuration.
    ///
    /// Builds a reqwest client configured with the given TLS settings
    /// (custom CA, client certs, skip-verify).
    pub fn with_tls(name: &str, url: &str, tls: &TlsConfig) -> Result<Self, UpstreamError> {
        let client = tls.build_client(name)?;
        Ok(Self {
            name: name.to_string(),
            url: url.to_string(),
            client,
            session_id: None,
            token_provider: StaticTokenProvider::new(None),
        })
    }

    /// Set a static authentication token (sent as `Authorization: Bearer <token>`).
    pub fn with_auth(mut self, token: impl Into<String>) -> Self {
        self.token_provider = StaticTokenProvider::new(Some(token.into()));
        self
    }

    /// Set a dynamic token provider for OAuth 2.1 authentication.
    pub fn with_token_provider(mut self, provider: Arc<dyn TokenProvider>) -> Self {
        self.token_provider = provider;
        self
    }

    async fn send_request(
        &mut self,
        body: &serde_json::Value,
        token: Option<&str>,
    ) -> Result<reqwest::Response, UpstreamError> {
        let mut req = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .json(body);

        if let Some(ref sid) = self.session_id {
            req = req.header("mcp-session-id", sid);
        }

        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }

        req.send().await.map_err(|e| UpstreamError::Protocol {
            name: self.name.clone(),
            message: format!("HTTP request failed: {e}"),
        })
    }

    fn capture_session_id(&mut self, resp: &reqwest::Response) {
        if let Some(sid) = resp.headers().get("mcp-session-id") {
            if let Ok(s) = sid.to_str() {
                self.session_id = Some(s.to_string());
            }
        }
    }

    fn extract_www_authenticate(resp: &reqwest::Response) -> Option<String> {
        resp.headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn request(
        &mut self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        let token = self.token_provider.get_token().await?;
        let resp = self.send_request(&body, token.as_deref()).await?;

        self.capture_session_id(&resp);
        let status = resp.status();

        // 401 Unauthorized — attempt token acquisition and retry once
        if status == reqwest::StatusCode::UNAUTHORIZED {
            let www_auth = Self::extract_www_authenticate(&resp);
            match self
                .token_provider
                .handle_401(&self.name, www_auth.as_deref())
                .await
            {
                Ok(new_token) => {
                    let retry_resp = self.send_request(&body, Some(&new_token)).await?;
                    self.capture_session_id(&retry_resp);
                    let retry_status = retry_resp.status();
                    if !retry_status.is_success() {
                        let body_text = retry_resp.text().await.unwrap_or_default();
                        return Err(UpstreamError::Protocol {
                            name: self.name.clone(),
                            message: format!("HTTP {retry_status} (after auth): {body_text}"),
                        });
                    }
                    return retry_resp.json::<serde_json::Value>().await.map_err(|e| {
                        UpstreamError::Protocol {
                            name: self.name.clone(),
                            message: format!("failed to parse response JSON: {e}"),
                        }
                    });
                }
                Err(e) => return Err(e),
            }
        }

        // 403 Forbidden — attempt scope step-up and retry once
        if status == reqwest::StatusCode::FORBIDDEN {
            let www_auth = Self::extract_www_authenticate(&resp);
            if let Some(ref auth_header) = www_auth {
                if auth_header.contains("insufficient_scope") {
                    match self
                        .token_provider
                        .handle_403(&self.name, www_auth.as_deref())
                        .await
                    {
                        Ok(new_token) => {
                            let retry_resp = self.send_request(&body, Some(&new_token)).await?;
                            self.capture_session_id(&retry_resp);
                            let retry_status = retry_resp.status();
                            if !retry_status.is_success() {
                                let body_text = retry_resp.text().await.unwrap_or_default();
                                return Err(UpstreamError::Protocol {
                                    name: self.name.clone(),
                                    message: format!(
                                        "HTTP {retry_status} (after step-up): {body_text}"
                                    ),
                                });
                            }
                            return retry_resp.json::<serde_json::Value>().await.map_err(|e| {
                                UpstreamError::Protocol {
                                    name: self.name.clone(),
                                    message: format!("failed to parse response JSON: {e}"),
                                }
                            });
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }

        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(UpstreamError::Protocol {
                name: self.name.clone(),
                message: format!("HTTP {status}: {body_text}"),
            });
        }

        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| UpstreamError::Protocol {
                name: self.name.clone(),
                message: format!("failed to parse response JSON: {e}"),
            })
    }

    fn shutdown(&mut self) {
        // HTTP is stateless; nothing to shut down.
    }
}
