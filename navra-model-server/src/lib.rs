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
    pub async fn serve(self, bind: &str) -> anyhow::Result<()> {
        let state = api::ServerState {
            registry: self.registry,
            router: self.session_router,
        };
        let app = api::router(state);

        let listener = tokio::net::TcpListener::bind(bind).await?;
        tracing::info!(bind = %bind, "Model server listening");
        axum::serve(listener, app).await?;
        Ok(())
    }

    /// Return the axum Router (for embedding in another server).
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
