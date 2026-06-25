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
//! mode, the gateway connects via [`RemoteRegistry`] which implements the
//! same lookup interface over HTTP.

pub mod api;
pub mod config;
pub mod hardware;
pub mod registry;

pub use config::ModelServerConfig;
pub use registry::ModelRegistry;

use std::sync::Arc;
use tokio::sync::RwLock;

/// Top-level model server.
pub struct ModelServer {
    registry: Arc<RwLock<ModelRegistry>>,
    config: ModelServerConfig,
}

impl ModelServer {
    /// Create a new model server, loading all configured models.
    pub async fn new(config: ModelServerConfig) -> anyhow::Result<Self> {
        let registry = ModelRegistry::from_config(&config.models).await?;
        Ok(Self {
            registry: Arc::new(RwLock::new(registry)),
            config,
        })
    }

    /// Start the HTTP server (standalone mode).
    pub async fn serve(self, bind: &str) -> anyhow::Result<()> {
        let state = api::ServerState {
            registry: self.registry.clone(),
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
            registry: self.registry.clone(),
        };
        api::router(state)
    }

    /// Direct access to the model registry (embedded mode).
    pub fn registry(&self) -> &Arc<RwLock<ModelRegistry>> {
        &self.registry
    }

    /// The bind address from config (default: 127.0.0.1:9316).
    pub fn default_bind(&self) -> &str {
        &self.config.bind
    }
}
