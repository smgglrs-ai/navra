//! smgglrs-model-runtime: Serve AI models with pluggable isolation.
//!
//! Provides the [`ModelRuntime`] trait for starting, stopping, and
//! health-checking model inference servers. Configured via
//! [`ServeConfig`], returns an [`Endpoint`] with an OpenAI-compatible
//! API URL. Isolation levels:
//!
//! - `direct` — spawn `llama-server` as a child process (no isolation)
//! - `podman` — run inference in a rootless Podman container
//! - `libkrun` — run inference in a libkrun microVM (future)
//!
//! [`auto_runtime()`] picks the best available backend. GPU detection
//! is provided by [`detect_gpus()`].

mod error;
mod gpu;

#[cfg(feature = "direct")]
pub mod direct;
#[cfg(feature = "podman")]
pub mod podman;

pub use error::RuntimeError;
pub use gpu::{GpuDevice, GpuKind, detect_gpus};

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

/// A running model endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// URL of the OpenAI-compatible API.
    pub url: String,
    /// Identifier for stopping this endpoint.
    pub id: String,
    /// How the model is being served.
    pub backend: RuntimeBackend,
}

/// Which runtime backend is serving the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeBackend {
    /// Direct child process.
    Direct,
    /// Podman container.
    Podman,
    /// libkrun microVM.
    Libkrun,
}

/// Configuration for serving a model.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// Path to the model file (GGUF, safetensors, etc.).
    pub model_path: PathBuf,
    /// Host address to bind to.
    pub host: String,
    /// Port to serve on (0 = auto-select).
    pub port: u16,
    /// GPU devices to use (empty = CPU only).
    pub gpus: Vec<GpuDevice>,
    /// Number of context tokens.
    pub context_size: u32,
    /// Number of parallel request slots.
    pub parallel: u32,
    /// Additional backend-specific arguments.
    pub extra_args: Vec<String>,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            model_path: PathBuf::new(),
            host: "127.0.0.1".to_string(),
            port: 0,
            gpus: Vec::new(),
            context_size: 4096,
            parallel: 1,
            extra_args: Vec::new(),
        }
    }
}

/// Trait for model serving backends.
pub trait ModelRuntime: Send + Sync {
    /// Start serving a model, returning an endpoint with an OpenAI-compatible API.
    fn serve(
        &self,
        config: &ServeConfig,
    ) -> Pin<Box<dyn Future<Output = Result<Endpoint, RuntimeError>> + Send + '_>>;

    /// Stop a running model endpoint.
    fn stop(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + '_>>;

    /// Check if an endpoint is healthy.
    fn health(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RuntimeError>> + Send + '_>>;

    /// Which backend this runtime uses.
    fn backend(&self) -> RuntimeBackend;
}

/// Auto-detect the best available runtime.
///
/// Prefers Podman (if available) for isolation, falls back to direct execution.
pub async fn auto_runtime() -> Result<Box<dyn ModelRuntime>, RuntimeError> {
    #[cfg(feature = "podman")]
    {
        if podman::PodmanRuntime::is_available().await {
            tracing::info!("Using Podman runtime");
            return Ok(Box::new(podman::PodmanRuntime::new()));
        }
    }

    #[cfg(feature = "direct")]
    {
        if direct::DirectRuntime::is_available().await {
            tracing::info!("Using direct runtime (no isolation)");
            return Ok(Box::new(direct::DirectRuntime::new()));
        }
    }

    Err(RuntimeError::NoRuntime(
        "no suitable runtime found (need Podman or llama-server)".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_serve_config() {
        let cfg = ServeConfig::default();
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 0);
        assert_eq!(cfg.context_size, 4096);
        assert_eq!(cfg.parallel, 1);
        assert!(cfg.gpus.is_empty());
    }

    #[test]
    fn endpoint_debug() {
        let ep = Endpoint {
            url: "http://127.0.0.1:8080".to_string(),
            id: "test-123".to_string(),
            backend: RuntimeBackend::Direct,
        };
        let debug = format!("{ep:?}");
        assert!(debug.contains("127.0.0.1:8080"));
    }
}
