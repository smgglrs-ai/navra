//! smgglrs-model-runtime: Serve AI models with pluggable isolation.
//!
//! Provides the [`ModelRuntime`] trait for starting, stopping, and
//! health-checking model inference servers. Configured via
//! [`ServeConfig`], returns an [`Endpoint`] with an OpenAI-compatible
//! API URL. Isolation levels:
//!
//! - `direct` — spawn `llama-server` as a child process (no isolation)
//! - `podman` — run inference in a rootless Podman container
//! - `openshell` — delegate to OpenShell compute driver via gRPC
//!
//! [`auto_runtime()`] picks the best available backend. GPU detection
//! is provided by [`detect_gpus()`].

mod error;
mod gpu;
mod npu;

#[cfg(feature = "direct")]
pub mod direct;
#[cfg(feature = "podman")]
pub mod podman;
#[cfg(feature = "openshell")]
pub mod openshell;

pub use error::RuntimeError;
pub use gpu::{GpuDevice, GpuKind, detect_gpus};
pub use npu::{NpuDevice, detect_npus};

use serde::{Deserialize, Serialize};
use std::fmt;
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
    /// OpenShell sandbox (gRPC delegation).
    OpenShell,
}

/// KV cache quantization type for llama-server.
///
/// Controls the `--cache-type-k` and `--cache-type-v` flags.
/// Lower precision reduces VRAM usage at the cost of quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KvCacheType {
    /// Full 16-bit precision (llama-server default).
    F16,
    /// 8-bit quantized KV cache.
    Q8_0,
    /// 4-bit quantized KV cache.
    Q4_0,
}

impl KvCacheType {
    /// Return the llama-server CLI argument value.
    pub fn as_llama_arg(&self) -> &str {
        match self {
            Self::F16 => "f16",
            Self::Q8_0 => "q8_0",
            Self::Q4_0 => "q4_0",
        }
    }
}

impl fmt::Display for KvCacheType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_llama_arg())
    }
}

impl std::str::FromStr for KvCacheType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "f16" => Ok(Self::F16),
            "q8_0" => Ok(Self::Q8_0),
            "q4_0" => Ok(Self::Q4_0),
            other => Err(format!("unknown KV cache type: {other} (expected f16, q8_0, or q4_0)")),
        }
    }
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
    /// KV cache quantization type. When set, passes `--cache-type-k`
    /// and `--cache-type-v` to llama-server. None = llama-server default (f16).
    pub cache_type: Option<KvCacheType>,
    /// Speculative decoding: use a draft model for faster generation.
    pub speculative: Option<SpeculativeConfig>,
    /// Additional backend-specific arguments.
    pub extra_args: Vec<String>,
}

/// Speculative decoding configuration.
#[derive(Debug, Clone)]
pub struct SpeculativeConfig {
    /// Path to the draft model (smaller, faster).
    pub draft_model: PathBuf,
    /// Number of draft tokens per verification step (default: 5).
    pub draft_tokens: u32,
    /// Minimum probability for draft acceptance (0.0 = accept all).
    pub draft_min_p: f32,
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
            cache_type: None,
            speculative: None,
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
/// Prefers OpenShell (strongest isolation), then Podman, then direct execution.
pub async fn auto_runtime() -> Result<Box<dyn ModelRuntime>, RuntimeError> {
    #[cfg(feature = "openshell")]
    {
        // OpenShell gateway socket is at a well-known path
        let gateway = "unix:///run/openshell/gateway.sock";
        if openshell::OpenShellRuntime::is_available(gateway).await {
            tracing::info!("Using OpenShell runtime");
            return Ok(Box::new(openshell::OpenShellRuntime::new(gateway).await?));
        }
    }

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
        "no suitable runtime found (need OpenShell, Podman, or llama-server)".to_string(),
    ))
}

/// Bind to port 0 to let the OS pick a free port, then return it.
///
/// Note: there is a small TOCTOU window between releasing the socket
/// and the caller binding the returned port. This is acceptable for
/// dev/local use; production deployments should use fixed ports.
pub fn pick_free_port() -> Result<u16, RuntimeError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| RuntimeError::Start(format!("no free port: {e}")))?;
    let port = listener.local_addr().unwrap().port();
    Ok(port)
}

/// Detected runtime isolation environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationLevel {
    /// Bare metal or VM — no container isolation detected.
    BareMetal,
    /// Running inside a Podman/Docker container.
    Container,
    /// Running inside an OpenShell sandbox (libkrun microVM).
    OpenShellSandbox,
}

/// Runtime isolation context — detected once, cached for process lifetime.
#[derive(Debug, Clone)]
pub struct IsolationContext {
    pub level: IsolationLevel,
    pub container_id: Option<String>,
    pub sandbox_id: Option<String>,
}

static ISOLATION_CONTEXT: std::sync::OnceLock<IsolationContext> = std::sync::OnceLock::new();

impl IsolationContext {
    /// Detect the current isolation environment.
    ///
    /// Checks (in order):
    /// 1. `OPENSHELL_SANDBOX_ID` env var → OpenShellSandbox
    /// 2. `/.containerenv` or `/.dockerenv` file → Container
    /// 3. `/run/.containerenv` file → Container
    /// 4. Otherwise → BareMetal
    pub fn detect() -> &'static IsolationContext {
        ISOLATION_CONTEXT.get_or_init(|| {
            if let Ok(sandbox_id) = std::env::var("OPENSHELL_SANDBOX_ID") {
                return IsolationContext {
                    level: IsolationLevel::OpenShellSandbox,
                    container_id: None,
                    sandbox_id: Some(sandbox_id),
                };
            }

            let container_id = std::fs::read_to_string("/proc/self/cgroup")
                .ok()
                .and_then(|cg| {
                    cg.lines()
                        .find(|l| l.contains("libpod") || l.contains("docker") || l.contains("containerd"))
                        .and_then(|l| l.rsplit('/').next())
                        .map(String::from)
                });

            let in_container = container_id.is_some()
                || std::path::Path::new("/.containerenv").exists()
                || std::path::Path::new("/.dockerenv").exists()
                || std::path::Path::new("/run/.containerenv").exists();

            if in_container {
                IsolationContext {
                    level: IsolationLevel::Container,
                    container_id,
                    sandbox_id: None,
                }
            } else {
                IsolationContext {
                    level: IsolationLevel::BareMetal,
                    container_id: None,
                    sandbox_id: None,
                }
            }
        })
    }
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
        assert!(cfg.cache_type.is_none());
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

    #[test]
    fn isolation_context_detect_returns_consistent() {
        let ctx1 = IsolationContext::detect();
        let ctx2 = IsolationContext::detect();
        assert_eq!(ctx1.level, ctx2.level);
        assert!(std::ptr::eq(ctx1, ctx2));
    }

    #[test]
    fn kv_cache_type_as_llama_arg() {
        assert_eq!(KvCacheType::F16.as_llama_arg(), "f16");
        assert_eq!(KvCacheType::Q8_0.as_llama_arg(), "q8_0");
        assert_eq!(KvCacheType::Q4_0.as_llama_arg(), "q4_0");
    }

    #[test]
    fn kv_cache_type_display() {
        assert_eq!(KvCacheType::F16.to_string(), "f16");
        assert_eq!(KvCacheType::Q8_0.to_string(), "q8_0");
        assert_eq!(KvCacheType::Q4_0.to_string(), "q4_0");
    }

    #[test]
    fn kv_cache_type_from_str() {
        assert_eq!("f16".parse::<KvCacheType>().unwrap(), KvCacheType::F16);
        assert_eq!("q8_0".parse::<KvCacheType>().unwrap(), KvCacheType::Q8_0);
        assert_eq!("q4_0".parse::<KvCacheType>().unwrap(), KvCacheType::Q4_0);
        assert!("invalid".parse::<KvCacheType>().is_err());
    }

    #[test]
    fn kv_cache_type_serde_roundtrip() {
        let json = serde_json::to_string(&KvCacheType::Q8_0).unwrap();
        assert_eq!(json, "\"q8_0\"");
        let parsed: KvCacheType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, KvCacheType::Q8_0);

        // All variants
        for variant in [KvCacheType::F16, KvCacheType::Q8_0, KvCacheType::Q4_0] {
            let s = serde_json::to_string(&variant).unwrap();
            let back: KvCacheType = serde_json::from_str(&s).unwrap();
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn kv_cache_type_deserialize_optional() {
        #[derive(Deserialize)]
        struct Wrapper {
            cache_type: Option<KvCacheType>,
        }
        let with: Wrapper = serde_json::from_str(r#"{"cache_type":"q4_0"}"#).unwrap();
        assert_eq!(with.cache_type, Some(KvCacheType::Q4_0));

        let without: Wrapper = serde_json::from_str(r#"{}"#).unwrap();
        assert!(without.cache_type.is_none());
    }

    #[test]
    fn isolation_level_debug() {
        assert_eq!(format!("{:?}", IsolationLevel::BareMetal), "BareMetal");
        assert_eq!(format!("{:?}", IsolationLevel::Container), "Container");
        assert_eq!(format!("{:?}", IsolationLevel::OpenShellSandbox), "OpenShellSandbox");
    }
}
