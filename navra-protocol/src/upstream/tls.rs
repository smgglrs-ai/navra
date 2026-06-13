//! TLS configuration for upstream HTTP/SSE connections.
//!
//! Supports custom CA bundles, mutual TLS (client certificate + key),
//! and skip-verify for development environments.

use super::UpstreamError;
use serde::{Deserialize, Serialize};

/// TLS configuration for an upstream MCP server connection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to CA certificate bundle (PEM). When set, only CAs in this
    /// bundle are trusted.
    pub ca_cert: Option<String>,
    /// Path to client certificate (PEM) for mutual TLS.
    pub client_cert: Option<String>,
    /// Path to client private key (PEM) for mutual TLS.
    pub client_key: Option<String>,
    /// Skip TLS certificate verification (DANGEROUS — only for development).
    #[serde(default)]
    pub danger_skip_verify: bool,
}

impl TlsConfig {
    /// Build a `reqwest::Client` configured with this TLS config.
    ///
    /// Certificate files are read at call time, not at config parse time,
    /// so missing files produce errors only when a connection is attempted.
    pub fn build_client(&self, upstream_name: &str) -> Result<reqwest::Client, UpstreamError> {
        let mut builder = reqwest::Client::builder();

        if self.danger_skip_verify {
            tracing::warn!(
                upstream = %upstream_name,
                "TLS certificate verification is DISABLED — do not use in production"
            );
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ref ca_path) = self.ca_cert {
            let pem = std::fs::read(ca_path).map_err(|e| UpstreamError::Protocol {
                name: upstream_name.to_string(),
                message: format!("failed to read CA cert '{}': {}", ca_path, e),
            })?;
            let cert =
                reqwest::Certificate::from_pem(&pem).map_err(|e| UpstreamError::Protocol {
                    name: upstream_name.to_string(),
                    message: format!("invalid CA cert '{}': {}", ca_path, e),
                })?;
            builder = builder.add_root_certificate(cert);
        }

        if let Some(ref cert_path) = self.client_cert {
            let key_path = self
                .client_key
                .as_deref()
                .ok_or_else(|| UpstreamError::Protocol {
                    name: upstream_name.to_string(),
                    message: "client_cert is set but client_key is missing".to_string(),
                })?;

            let cert_pem = std::fs::read(cert_path).map_err(|e| UpstreamError::Protocol {
                name: upstream_name.to_string(),
                message: format!("failed to read client cert '{}': {}", cert_path, e),
            })?;
            let key_pem = std::fs::read(key_path).map_err(|e| UpstreamError::Protocol {
                name: upstream_name.to_string(),
                message: format!("failed to read client key '{}': {}", key_path, e),
            })?;

            #[cfg(feature = "rustls")]
            let identity = {
                let mut combined_pem = cert_pem;
                combined_pem.push(b'\n');
                combined_pem.extend_from_slice(&key_pem);
                reqwest::Identity::from_pem(&combined_pem)
            };
            #[cfg(not(feature = "rustls"))]
            let identity = reqwest::Identity::from_pkcs8_pem(&cert_pem, &key_pem);
            let identity = identity.map_err(|e| UpstreamError::Protocol {
                name: upstream_name.to_string(),
                message: format!("invalid client identity: {}", e),
            })?;
            builder = builder.identity(identity);
        }

        builder.build().map_err(|e| UpstreamError::Protocol {
            name: upstream_name.to_string(),
            message: format!("failed to build TLS client: {}", e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tls_config() {
        let cfg = TlsConfig::default();
        assert!(cfg.ca_cert.is_none());
        assert!(cfg.client_cert.is_none());
        assert!(cfg.client_key.is_none());
        assert!(!cfg.danger_skip_verify);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let cfg = TlsConfig {
            ca_cert: Some("/etc/navra/ca-bundle.pem".to_string()),
            client_cert: Some("/etc/navra/client.pem".to_string()),
            client_key: Some("/etc/navra/client-key.pem".to_string()),
            danger_skip_verify: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: TlsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ca_cert.as_deref(), Some("/etc/navra/ca-bundle.pem"));
        assert_eq!(parsed.client_cert.as_deref(), Some("/etc/navra/client.pem"));
        assert_eq!(
            parsed.client_key.as_deref(),
            Some("/etc/navra/client-key.pem")
        );
        assert!(!parsed.danger_skip_verify);
    }

    #[test]
    fn deserialize_minimal() {
        let json = "{}";
        let cfg: TlsConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.ca_cert.is_none());
        assert!(!cfg.danger_skip_verify);
    }

    #[test]
    fn deserialize_skip_verify_only() {
        let json = r#"{"danger_skip_verify": true}"#;
        let cfg: TlsConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.danger_skip_verify);
        assert!(cfg.ca_cert.is_none());
    }

    #[test]
    fn default_config_builds_client() {
        let cfg = TlsConfig::default();
        let client = cfg.build_client("test");
        assert!(client.is_ok());
    }

    #[test]
    fn skip_verify_builds_client() {
        let cfg = TlsConfig {
            danger_skip_verify: true,
            ..Default::default()
        };
        let client = cfg.build_client("test");
        assert!(client.is_ok());
    }

    #[test]
    fn missing_ca_cert_file_errors() {
        let cfg = TlsConfig {
            ca_cert: Some("/nonexistent/ca.pem".to_string()),
            ..Default::default()
        };
        let err = cfg.build_client("test").unwrap_err();
        assert!(err.to_string().contains("failed to read CA cert"));
    }

    #[test]
    fn client_cert_without_key_errors() {
        let cfg = TlsConfig {
            client_cert: Some("/some/cert.pem".to_string()),
            client_key: None,
            ..Default::default()
        };
        let err = cfg.build_client("test").unwrap_err();
        assert!(err.to_string().contains("client_key is missing"));
    }

    #[test]
    fn missing_client_cert_file_errors() {
        let cfg = TlsConfig {
            client_cert: Some("/nonexistent/cert.pem".to_string()),
            client_key: Some("/nonexistent/key.pem".to_string()),
            ..Default::default()
        };
        let err = cfg.build_client("test").unwrap_err();
        assert!(err.to_string().contains("failed to read client cert"));
    }
}
