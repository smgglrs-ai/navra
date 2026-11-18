//! navra-model-server: Standalone model inference server.
//!
//! Manages multiple model backends behind an OpenAI-compatible HTTP API.
//! Supports two usage modes:
//!
//! - **Standalone**: `navra model serve` — starts an HTTP server on a
//!   configurable port, auto-detects hardware, manages GPU budget.
//! - **Embedded**: the gateway (`navra serve`) creates a [`ModelServer`]
//!   in-process and accesses the [`ModelRegistry`] directly without HTTP.
//!
//! The registry is the single source of truth for loaded models. In remote
//! mode, the gateway connects to the model server's HTTP API, which
//! exposes the same lookup and inference interface.

pub mod api;
pub mod config;
pub mod hardware;
pub mod registry;
pub mod router;

pub use config::ModelServerConfig;
pub use registry::ModelRegistry;
pub use router::{RoutingConfig, RoutingDecision, RoutingRule, SessionRouter};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Top-level model server.
pub struct ModelServer {
    registry: Arc<RwLock<ModelRegistry>>,
    config: ModelServerConfig,
    session_router: Arc<SessionRouter>,
}

impl ModelServer {
    /// Create a new model server, loading all configured models.
    pub async fn new(config: ModelServerConfig) -> anyhow::Result<Self> {
        let registry = ModelRegistry::from_config(&config.models).await?;
        let session_router = Arc::new(SessionRouter::new(config.routing.clone()));
        Ok(Self {
            registry: Arc::new(RwLock::new(registry)),
            config,
            session_router,
        })
    }

    /// Start the HTTP server (standalone mode).
    ///
    /// Auth token is read from the `NAVRA_MODEL_TOKEN` environment
    /// variable. See [`Self::serve_with_token`] for the auth policy.
    pub async fn serve(self, bind: &str) -> anyhow::Result<()> {
        let token = std::env::var("NAVRA_MODEL_TOKEN")
            .ok()
            .filter(|t| !t.trim().is_empty());
        self.serve_with_token(bind, token).await
    }

    /// Start the HTTP server with an explicit auth token.
    ///
    /// When `token` is set, every inference route requires
    /// `Authorization: Bearer <token>` (`/health` stays open for
    /// probes). When the bind address is non-loopback, a token is
    /// **required** — the server refuses to start rather than
    /// exposing unauthenticated inference on the network.
    pub async fn serve_with_token(self, bind: &str, token: Option<String>) -> anyhow::Result<()> {
        let token = resolve_auth_token(bind, token)?;
        let state = api::ServerState {
            registry: self.registry,
            router: self.session_router,
        };
        let app = match &token {
            Some(t) => {
                tracing::info!(bind = %bind, "Model server listening (token auth enabled)");
                api::router_with_auth(state, t)
            }
            None => {
                tracing::info!(bind = %bind, "Model server listening (loopback, no auth)");
                api::router(state)
            }
        };

        let listener = tokio::net::TcpListener::bind(bind).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }

    /// Return the axum Router (for embedding in another server).
    ///
    /// # Embedder contract
    ///
    /// The returned router is **unauthenticated** — every inference
    /// route (`/v1/*`, `/hardware`) is open. This is safe only when
    /// the embedding server binds a loopback interface or layers its
    /// own authentication in front. Embedders binding a
    /// non-loopback address MUST either wrap these routes with an
    /// authenticating middleware or use
    /// [`api::router_with_auth`] / [`Self::serve_with_token`]
    /// instead. (Standalone mode enforces this: `serve_with_token`
    /// refuses to start unauthenticated on a non-loopback bind.)
    pub fn router(&self) -> axum::Router {
        let state = api::ServerState {
            registry: Arc::clone(&self.registry),
            router: Arc::clone(&self.session_router),
        };
        api::router(state)
    }

    /// Direct access to the model registry (embedded mode).
    pub fn registry(&self) -> &Arc<RwLock<ModelRegistry>> {
        &self.registry
    }

    /// Direct access to the within-session cost router (embedded mode).
    pub fn session_router(&self) -> &SessionRouter {
        &self.session_router
    }

    /// The bind address from config (default: 127.0.0.1:9316).
    pub fn default_bind(&self) -> &str {
        &self.config.bind
    }
}

/// Whether a `host:port` bind string targets a loopback interface.
///
/// Accepts `localhost`, IPv4 `127.0.0.0/8`, IPv6 `::1` (bracketed or
/// bare), and plain hostnames without a port. Anything else
/// (`0.0.0.0`, a LAN IP, a public hostname) is non-loopback.
pub fn is_loopback_bind(bind: &str) -> bool {
    let bind = bind.trim();
    // Bracketed IPv6 form: "[::1]:9316".
    if let Some(rest) = bind.strip_prefix('[')
        && let Some((host, _)) = rest.split_once(']')
    {
        return host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    }
    // Exactly one ':' means host:port; anything else is treated as a
    // bare host (covers unbracketed IPv6 like "::1").
    let host = if bind.matches(':').count() == 1 {
        bind.rsplit_once(':').map(|(host, _)| host).unwrap_or(bind)
    } else {
        bind
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Auth policy for the standalone model server:
/// - loopback bind: token optional (default posture)
/// - non-loopback bind: token required, fail closed
pub(crate) fn resolve_auth_token(
    bind: &str,
    token: Option<String>,
) -> anyhow::Result<Option<String>> {
    let token = token.filter(|t| !t.trim().is_empty());
    if is_loopback_bind(bind) || token.is_some() {
        Ok(token)
    } else {
        anyhow::bail!(
            "refusing to serve the model API on non-loopback {bind} without a token: \
             set NAVRA_MODEL_TOKEN (or pass a token to serve_with_token)"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_binds_detected() {
        for bind in [
            "127.0.0.1:9316",
            "localhost:9316",
            "localhost",
            "[::1]:9316",
            "::1",
            "127.0.0.1",
        ] {
            assert!(is_loopback_bind(bind), "expected loopback: {bind}");
        }
    }

    #[test]
    fn non_loopback_binds_detected() {
        for bind in [
            "0.0.0.0:9316",
            "192.168.1.10:9316",
            "example.com:9316",
            "[::]:9316",
            "10.0.0.5",
        ] {
            assert!(!is_loopback_bind(bind), "expected non-loopback: {bind}");
        }
    }

    #[test]
    fn non_loopback_without_token_fails_closed() {
        assert!(resolve_auth_token("0.0.0.0:9316", None).is_err());
        assert!(resolve_auth_token("0.0.0.0:9316", Some("".to_string())).is_err());
    }

    #[test]
    fn non_loopback_with_token_is_allowed() {
        assert_eq!(
            resolve_auth_token("0.0.0.0:9316", Some("sekrit".to_string())).unwrap(),
            Some("sekrit".to_string())
        );
    }

    #[test]
    fn loopback_token_is_optional() {
        assert_eq!(resolve_auth_token("127.0.0.1:9316", None).unwrap(), None);
        assert_eq!(
            resolve_auth_token("127.0.0.1:9316", Some("sekrit".to_string())).unwrap(),
            Some("sekrit".to_string())
        );
        // Blank tokens are treated as unset.
        assert_eq!(
            resolve_auth_token("127.0.0.1:9316", Some("  ".to_string())).unwrap(),
            None
        );
    }
}
