//! TLS listener support (NAVRA-199).
//!
//! When `[server] tls_cert_path` and `tls_key_path` are set, the TCP
//! listener serves HTTPS via rustls. With `tls_client_ca_path` set,
//! client certificates are verified when presented (optional mutual
//! TLS): worker replicas authenticate at the transport layer with a
//! client certificate, while agents — which authenticate with
//! delegated capability tokens — connect without one. The Unix
//! socket listener is unaffected (node-local, filesystem-permission
//! protected).

use std::sync::Arc;

use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Build a TLS acceptor from config. `Ok(None)` when TLS is not
/// configured. Errors on a half-configured or unreadable setup —
/// startup fails rather than silently serving plaintext.
pub(crate) fn build_tls_acceptor(
    cfg: &crate::config::Config,
) -> anyhow::Result<Option<TlsAcceptor>> {
    let cert_path = &cfg.server.tls_cert_path;
    let key_path = &cfg.server.tls_key_path;
    match (cert_path, key_path) {
        (None, None) => Ok(None),
        (Some(_), None) => {
            anyhow::bail!("tls_cert_path is set but tls_key_path is not — configure both")
        }
        (None, Some(_)) => {
            anyhow::bail!("tls_key_path is set but tls_cert_path is not — configure both")
        }
        (Some(cert), Some(key)) => {
            let certs = load_certs(cert)?;
            if certs.is_empty() {
                anyhow::bail!("no certificates found in {cert}");
            }
            let private_key =
                load_key(key)?.ok_or_else(|| anyhow::anyhow!("no private key found in {key}"))?;

            // Install the ring provider as the process default if
            // none is installed — reqwest's rustls clients need it
            // too, and feature unification may leave both ring and
            // aws-lc-rs enabled (making auto-detection ambiguous).
            let provider = match tokio_rustls::rustls::crypto::CryptoProvider::get_default() {
                Some(p) => p.clone(),
                None => {
                    let _ = tokio_rustls::rustls::crypto::CryptoProvider::install_default(
                        tokio_rustls::rustls::crypto::ring::default_provider(),
                    );
                    tokio_rustls::rustls::crypto::CryptoProvider::get_default()
                        .expect("just installed")
                        .clone()
                }
            };

            let builder = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?;

            let config = match &cfg.server.tls_client_ca_path {
                Some(ca_path) => {
                    // Optional client auth: verify presented client
                    // certificates against the CA, but allow
                    // connections without one.
                    let ca_certs = load_certs(ca_path)?;
                    if ca_certs.is_empty() {
                        anyhow::bail!("no certificates found in {ca_path}");
                    }
                    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
                    for c in ca_certs {
                        roots
                            .add(c)
                            .map_err(|e| anyhow::anyhow!("invalid CA certificate: {e}"))?;
                    }
                    let verifier = tokio_rustls::rustls::server::WebPkiClientVerifier::builder(
                        Arc::new(roots),
                    )
                    .allow_unauthenticated()
                    .build()?;
                    builder
                        .with_client_cert_verifier(verifier)
                        .with_single_cert(certs, private_key)?
                }
                None => builder
                    .with_no_client_auth()
                    .with_single_cert(certs, private_key)?,
            };
            Ok(Some(TlsAcceptor::from(Arc::new(config))))
        }
    }
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("cannot open certificate file {path}: {e}"))?;
    let mut reader = std::io::BufReader::new(file);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    Ok(certs?)
}

fn load_key(path: &str) -> anyhow::Result<Option<PrivateKeyDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("cannot open key file {path}: {e}"))?;
    let mut reader = std::io::BufReader::new(file);
    Ok(rustls_pemfile::private_key(&mut reader)?)
}

/// An axum [`Listener`](axum::serve::Listener) serving TLS over a
/// TCP listener. Failed handshakes are logged and dropped — the
/// accept loop keeps serving.
pub(crate) struct TlsListener {
    tcp: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    pub(crate) fn new(tcp: tokio::net::TcpListener, acceptor: TlsAcceptor) -> Self {
        Self { tcp, acceptor }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.tcp.accept().await {
                Ok((stream, addr)) => match self.acceptor.accept(stream).await {
                    Ok(tls) => return (tls, addr),
                    Err(e) => {
                        tracing::warn!(peer = %addr, error = %e, "TLS handshake failed");
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "TCP accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed CA + server certificate and serve a
    /// minimal router over TLS; verify a rustls client with the CA
    /// trusted connects, one without does not, and a client with a
    /// signed client certificate is accepted under optional client
    /// auth.
    #[tokio::test]
    async fn tls_listener_serves_https_with_optional_client_auth() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params =
            rcgen::CertificateParams::new(vec!["navra-test-ca".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.clone().self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate().unwrap();
        let mut server_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        server_params.subject_alt_names = vec![
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("localhost").unwrap()),
            rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])),
        ];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("srv.pem");
        let key_path = dir.path().join("srv.key");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, server_cert.pem().as_bytes()).unwrap();
        std::fs::write(&key_path, server_key.serialize_pem().as_bytes()).unwrap();
        std::fs::write(&ca_path, ca_cert.pem().as_bytes()).unwrap();

        // Optional client auth via the same CA.
        let client_key = rcgen::KeyPair::generate().unwrap();
        let client_cert = rcgen::CertificateParams::new(vec!["worker".to_string()])
            .unwrap()
            .signed_by(&client_key, &ca_cert, &ca_key)
            .unwrap();
        let client_pem = format!("{}{}", client_cert.pem(), client_key.serialize_pem());

        let mut cfg = crate::config::Config::default();
        cfg.server.tls_cert_path = Some(cert_path.to_string_lossy().to_string());
        cfg.server.tls_key_path = Some(key_path.to_string_lossy().to_string());
        cfg.server.tls_client_ca_path = Some(ca_path.to_string_lossy().to_string());
        let acceptor = build_tls_acceptor(&cfg).unwrap().expect("acceptor built");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls_listener = TlsListener::new(listener, acceptor);

        let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
        tokio::spawn(async move {
            let _ = axum::serve(tls_listener, app).await;
        });

        // 1. Client with the CA trusted (no client cert) succeeds.
        let ca_cert = reqwest::Certificate::from_pem(ca_cert.pem().as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(ca_cert.clone())
            .build()
            .unwrap();
        let resp = client
            .get(format!("https://{addr}/healthz"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);

        // 2. Client without the CA fails the handshake.
        let plain = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        // Even with danger-accept the connection serves TLS; without
        // trust the normal client errors:
        let untrusting = reqwest::Client::builder().build().unwrap();
        assert!(
            untrusting
                .get(format!("https://{addr}/healthz"))
                .send()
                .await
                .is_err()
        );

        // 3. Client WITH a signed client certificate is accepted
        //    (optional client auth does not require it).
        let identity = reqwest::Identity::from_pem(client_pem.as_bytes()).unwrap();
        let mtls_client = reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .identity(identity)
            .build()
            .unwrap();
        let resp = mtls_client
            .get(format!("https://{addr}/healthz"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
    }

    #[test]
    fn half_configured_tls_fails() {
        let mut cfg = crate::config::Config::default();
        cfg.server.tls_cert_path = Some("/nonexistent.pem".into());
        assert!(build_tls_acceptor(&cfg).is_err());
        let mut cfg2 = crate::config::Config::default();
        assert!(build_tls_acceptor(&cfg2).unwrap().is_none());
    }
}
