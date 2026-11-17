//! TLS-aware HTTP client construction (NAVRA-199).
//!
//! Agents connect to a gateway that may serve HTTPS with an
//! internal (chart-issued) CA. Both the direct HTTP calls (task
//! fetch, result publish, model traffic) and the rmcp MCP transport
//! honor:
//!
//! - `NAVRA_TLS_CA_FILE` — CA bundle (PEM) trusted in addition to
//!   the system roots.
//!
//! Agents do not present client certificates: they authenticate
//! with delegated capability tokens at the application layer; TLS
//! is transport encryption only.

/// Build a reqwest client with the cluster TLS environment applied.
pub fn http_client_with_timeout(timeout: std::time::Duration) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Ok(ca_path) = std::env::var("NAVRA_TLS_CA_FILE")
        && !ca_path.is_empty()
    {
        match std::fs::read(&ca_path)
            .map_err(|e| e.to_string())
            .and_then(|pem| reqwest::Certificate::from_pem(&pem).map_err(|e| e.to_string()))
        {
            Ok(cert) => builder = builder.add_root_certificate(cert),
            Err(e) => {
                tracing::warn!(path = ca_path, error = %e, "NAVRA_TLS_CA_FILE unreadable — using system roots only");
            }
        }
    }
    builder.build().unwrap_or_default()
}

/// Default-timeout variant for convenience.
pub fn http_client() -> reqwest::Client {
    http_client_with_timeout(std::time::Duration::from_secs(120))
}
