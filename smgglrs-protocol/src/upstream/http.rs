//! HTTP transport: JSON-RPC over HTTP POST (MCP streamable-http).
//!
//! Sends JSON-RPC requests as POST to the upstream URL and reads
//! JSON-RPC responses from the response body.

use super::transport::Transport;
use super::UpstreamError;
use async_trait::async_trait;

/// HTTP transport backed by reqwest.
pub struct HttpTransport {
    name: String,
    url: String,
    client: reqwest::Client,
    session_id: Option<String>,
    auth_token: Option<String>,
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
            auth_token: None,
        }
    }

    /// Set an authentication token (sent as `Authorization: Bearer <token>`).
    pub fn with_auth(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn request(
        &mut self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        let mut req = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .json(&body);

        // Include session header if we have one (from a previous initialize)
        if let Some(ref sid) = self.session_id {
            req = req.header("mcp-session-id", sid);
        }

        // Include auth token if set
        if let Some(ref token) = self.auth_token {
            req = req.header("authorization", format!("Bearer {token}"));
        }

        let resp = req.send().await.map_err(|e| UpstreamError::Protocol {
            name: self.name.clone(),
            message: format!("HTTP request failed: {e}"),
        })?;

        // Capture session ID from response headers
        if let Some(sid) = resp.headers().get("mcp-session-id") {
            if let Ok(s) = sid.to_str() {
                self.session_id = Some(s.to_string());
            }
        }

        let status = resp.status();
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
