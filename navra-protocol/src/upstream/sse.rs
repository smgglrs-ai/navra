//! SSE transport: JSON-RPC over Server-Sent Events.
//!
//! Connects to the upstream's SSE endpoint (GET) to receive a message
//! endpoint URL, then sends JSON-RPC requests via POST to that endpoint
//! and reads responses from the SSE stream.
//!
//! SSE protocol flow:
//! 1. Client opens GET to the SSE URL
//! 2. Server sends an `endpoint` event with a POST URL
//! 3. Client sends JSON-RPC requests via POST to that URL
//! 4. Server sends responses as `message` events on the SSE stream

use super::tls::TlsConfig;
use super::transport::Transport;
use super::UpstreamError;
use async_trait::async_trait;

/// SSE transport backed by reqwest.
///
/// Connects to the upstream's SSE endpoint to discover the POST URL,
/// then sends JSON-RPC requests via POST and parses responses
/// (either plain JSON or SSE-formatted).
pub struct SseTransport {
    name: String,
    /// The base URL (e.g., `http://localhost:8001/sse`)
    base_url: String,
    /// The POST endpoint discovered from the SSE stream
    post_url: Option<String>,
    client: reqwest::Client,
}

impl SseTransport {
    /// Create a new SSE transport.
    ///
    /// The URL should be the SSE endpoint (e.g., `http://localhost:8001/sse`).
    /// The transport will connect and discover the POST endpoint on first use.
    pub fn new(name: &str, url: &str) -> Self {
        Self {
            name: name.to_string(),
            base_url: url.to_string(),
            post_url: None,
            client: reqwest::Client::new(),
        }
    }

    /// Create an SSE transport with TLS configuration.
    pub fn with_tls(name: &str, url: &str, tls: &TlsConfig) -> Result<Self, UpstreamError> {
        let client = tls.build_client(name)?;
        Ok(Self {
            name: name.to_string(),
            base_url: url.to_string(),
            post_url: None,
            client,
        })
    }

    /// Discover the POST endpoint by connecting to the SSE stream.
    async fn discover_endpoint(&mut self) -> Result<String, UpstreamError> {
        if let Some(ref url) = self.post_url {
            return Ok(url.clone());
        }

        let resp = self
            .client
            .get(&self.base_url)
            .header("Accept", "text/event-stream")
            .send()
            .await
            .map_err(|e| UpstreamError::Protocol {
                name: self.name.clone(),
                message: format!("SSE connection failed: {e}"),
            })?;

        if !resp.status().is_success() {
            return Err(UpstreamError::Protocol {
                name: self.name.clone(),
                message: format!("SSE endpoint returned {}", resp.status()),
            });
        }

        // Read SSE events to find the endpoint event.
        // SSE format: "event: endpoint\ndata: /mcp\n\n"
        let body = resp.text().await.map_err(|e| UpstreamError::Protocol {
            name: self.name.clone(),
            message: format!("failed to read SSE body: {e}"),
        })?;

        // Parse SSE events looking for "endpoint" event
        let mut event_type = String::new();
        for line in body.lines() {
            if let Some(et) = line.strip_prefix("event: ") {
                event_type = et.trim().to_string();
            } else if let Some(data) = line.strip_prefix("data: ") {
                if event_type == "endpoint" {
                    // The data is the relative or absolute URL for POST
                    let post_url = if data.starts_with("http") {
                        data.trim().to_string()
                    } else {
                        // Relative URL — resolve against base
                        let base = self
                            .base_url
                            .rfind('/')
                            .map(|i| &self.base_url[..i])
                            .unwrap_or(&self.base_url);
                        format!("{}{}", base, data.trim())
                    };
                    self.post_url = Some(post_url.clone());
                    return Ok(post_url);
                }
            }
        }

        Err(UpstreamError::Protocol {
            name: self.name.clone(),
            message: "SSE stream did not provide an endpoint event".to_string(),
        })
    }
}

#[async_trait]
impl Transport for SseTransport {
    async fn request(
        &mut self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        let post_url = self.discover_endpoint().await?;

        let resp = self
            .client
            .post(&post_url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| UpstreamError::Protocol {
                name: self.name.clone(),
                message: format!("SSE POST failed: {e}"),
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(UpstreamError::Protocol {
                name: self.name.clone(),
                message: format!("SSE POST {status}: {body_text}"),
            });
        }

        // The response may be plain JSON or SSE-formatted.
        // Check Content-Type to decide how to parse.
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let body_text = resp.text().await.map_err(|e| UpstreamError::Protocol {
            name: self.name.clone(),
            message: format!("failed to read response: {e}"),
        })?;

        if content_type.contains("text/event-stream") {
            // Parse SSE: extract the last "data:" line from "message" events
            let mut last_data = None;
            for line in body_text.lines() {
                if let Some(data) = line.strip_prefix("data: ") {
                    last_data = Some(data.trim().to_string());
                }
            }
            let data = last_data.ok_or_else(|| UpstreamError::Protocol {
                name: self.name.clone(),
                message: "SSE response contained no data".to_string(),
            })?;
            serde_json::from_str(&data).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })
        } else {
            // Plain JSON response
            serde_json::from_str(&body_text).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })
        }
    }

    fn shutdown(&mut self) {
        // Drop the POST URL so the next request re-discovers
        self.post_url = None;
    }
}
