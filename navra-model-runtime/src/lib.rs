//! navra-model-runtime: Serve AI models with pluggable isolation.
//!
//! Two orthogonal axes:
//!
//! **Engine** (what serves the model):
//! - `LlamaCpp` — llama.cpp (`llama-server`), CPU or GPU, GGUF format
//! - `Vllm` — vLLM (`vllm serve`), GPU required, safetensors/GGUF/AWQ/GPTQ
//!
//! **Isolation** (how the engine is launched):
//! - `direct` — spawn as a child process (no isolation)
//! - `podman` — run in a rootless Podman container
//! - `openshell` — delegate to OpenShell compute driver via gRPC
//!
//! [`auto_runtime()`] picks the best available combination.
//! GPU detection is provided by [`detect_gpus()`].

pub mod engine;
mod error;
pub mod format;
pub mod gpu;
pub mod hardware;
mod npu;

#[cfg(feature = "direct")]
pub mod direct;
#[cfg(feature = "embedded")]
pub mod embedded;
#[cfg(feature = "kubernetes")]
pub mod kubernetes;
#[cfg(feature = "openshell")]
pub mod openshell;
#[cfg(feature = "podman")]
pub mod podman;

pub use engine::Engine;
pub use error::RuntimeError;
pub use format::ModelFormat;
pub use gpu::{GpuDevice, GpuKind, detect_gpus};
pub use hardware::HardwareTarget;
pub use npu::{NpuDevice, detect_npus};

use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

/// How a model executes: loaded in-process (ONNX) or served via a
/// runtime backend (llama.cpp, vLLM). Decouples model *purpose*
/// (embedding, classification, chat) from *how it runs*.
///
/// Default: `from_task()` preserves current behavior — embedding and
/// classification run in-process, chat/generate run served. Operators
/// can override in config: `execution_mode = "served"` on an embedding
/// model to serve it via vLLM instead of loading it in-process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    /// Load model directly into the navra process (ONNX Runtime).
    InProcess,
    /// Spawn a dedicated inference server (llama.cpp, vLLM).
    Served,
}

impl ExecutionMode {
    /// Derive execution mode from model task string.
    ///
    /// Preserves current defaults:
    /// - `"embedding"` / `"classification"` → `InProcess`
    /// - `"chat"` / `"generate"` → `Served`
    pub fn from_task(task: &str) -> Self {
        match task {
            "embedding" | "classification" => Self::InProcess,
            _ => Self::Served,
        }
    }
}

impl fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InProcess => f.write_str("in_process"),
            Self::Served => f.write_str("served"),
        }
    }
}

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

/// Isolation mode — how the inference engine is launched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// Spawn as a child process (no isolation).
    Direct,
    /// Run in a rootless Podman container.
    Podman,
    /// Delegate to OpenShell compute driver via gRPC.
    OpenShell,
    /// Run in a Kubernetes Agent Sandbox (CRD-based).
    Kubernetes,
}

impl fmt::Display for Isolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("direct"),
            Self::Podman => f.write_str("podman"),
            Self::OpenShell => f.write_str("openshell"),
            Self::Kubernetes => f.write_str("kubernetes"),
        }
    }
}

/// Which runtime backend is serving the model (engine × isolation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackend {
    pub engine: Engine,
    pub isolation: Isolation,
}

impl RuntimeBackend {
    pub fn new(engine: Engine, isolation: Isolation) -> Self {
        Self { engine, isolation }
    }
}

impl fmt::Display for RuntimeBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.isolation {
            Isolation::Direct => write!(f, "{}", self.engine),
            other => write!(f, "{}-{other}", self.engine),
        }
    }
}

/// KV cache quantization type.
///
/// For llama-server: controls `--cache-type-k` and `--cache-type-v`.
/// For vLLM: maps to `--kv-cache-dtype` (fp8).
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
            other => Err(format!(
                "unknown KV cache type: {other} (expected f16, q8_0, or q4_0)"
            )),
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
    /// Hardware target (derived from `gpus` if not set explicitly).
    pub target: HardwareTarget,
    /// Model serialization format (auto-detected from path if not set).
    pub format: Option<ModelFormat>,
    /// Number of context tokens.
    pub context_size: u32,
    /// Number of parallel request slots.
    pub parallel: u32,
    /// KV cache quantization type.
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
            target: HardwareTarget::Cpu,
            format: None,
            context_size: 4096,
            parallel: 1,
            cache_type: None,
            speculative: None,
            extra_args: Vec::new(),
        }
    }
}

/// Capability flags for a model runtime.
#[derive(Debug, Clone, Default)]
pub struct RuntimeCapabilities {
    /// Whether the runtime supports saving/loading KV cache state.
    pub supports_kv_checkpoint: bool,
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

    /// Runtime capability flags.
    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::default()
    }
}

/// Auto-detect the best available runtime.
///
/// Picks the best isolation mode first, then the best engine within it.
/// Preference: OpenShell > Podman > Direct.
/// Within each mode: vLLM (if GPU available) > llama.cpp.
pub async fn auto_runtime() -> Result<Box<dyn ModelRuntime>, RuntimeError> {
    #[cfg(feature = "openshell")]
    {
        let gateway = "unix:///run/openshell/gateway.sock";
        if openshell::OpenShellRuntime::is_available(gateway).await {
            tracing::info!("Using OpenShell runtime (llama.cpp)");
            return Ok(Box::new(
                openshell::OpenShellRuntime::new(gateway, Engine::LlamaCpp).await?,
            ));
        }
    }

    #[cfg(feature = "podman")]
    {
        if podman::PodmanRuntime::is_available(&Engine::Vllm).await {
            tracing::info!("Using Podman runtime (vLLM)");
            return Ok(Box::new(podman::PodmanRuntime::new(Engine::Vllm)));
        }
        if podman::PodmanRuntime::is_available(&Engine::LlamaCpp).await {
            tracing::info!("Using Podman runtime (llama.cpp)");
            return Ok(Box::new(podman::PodmanRuntime::new(Engine::LlamaCpp)));
        }
    }

    #[cfg(feature = "direct")]
    {
        if direct::DirectRuntime::is_available(&Engine::Vllm).await {
            tracing::info!("Using vLLM runtime (no isolation)");
            return Ok(Box::new(direct::DirectRuntime::new(Engine::Vllm)));
        }
        if direct::DirectRuntime::is_available(&Engine::LlamaCpp).await {
            tracing::info!("Using llama.cpp runtime (no isolation)");
            return Ok(Box::new(direct::DirectRuntime::new(Engine::LlamaCpp)));
        }
    }

    #[cfg(feature = "embedded")]
    {
        tracing::info!("Using embedded llama.cpp runtime (in-process)");
        return Ok(Box::new(embedded::EmbeddedRuntime::new()));
    }

    #[cfg(not(feature = "embedded"))]
    Err(RuntimeError::NoRuntime(
        "no suitable runtime found (need OpenShell, Podman, vLLM, or llama-server)".to_string(),
    ))
}

/// Bind to port 0 to let the OS pick a free port, then return it.
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
                        .find(|l| {
                            l.contains("libpod") || l.contains("docker") || l.contains("containerd")
                        })
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
            backend: RuntimeBackend::new(Engine::LlamaCpp, Isolation::Direct),
        };
        let debug = format!("{ep:?}");
        assert!(debug.contains("127.0.0.1:8080"));
    }

    #[test]
    fn runtime_backend_display() {
        assert_eq!(
            RuntimeBackend::new(Engine::LlamaCpp, Isolation::Direct).to_string(),
            "llama-cpp"
        );
        assert_eq!(
            RuntimeBackend::new(Engine::LlamaCpp, Isolation::Podman).to_string(),
            "llama-cpp-podman"
        );
        assert_eq!(
            RuntimeBackend::new(Engine::LlamaCpp, Isolation::OpenShell).to_string(),
            "llama-cpp-openshell"
        );
        assert_eq!(
            RuntimeBackend::new(Engine::Vllm, Isolation::Direct).to_string(),
            "vllm"
        );
        assert_eq!(
            RuntimeBackend::new(Engine::Vllm, Isolation::Podman).to_string(),
            "vllm-podman"
        );
        assert_eq!(
            RuntimeBackend::new(Engine::Vllm, Isolation::OpenShell).to_string(),
            "vllm-openshell"
        );
    }

    #[test]
    fn runtime_backend_composed() {
        let backend = RuntimeBackend::new(Engine::LlamaCpp, Isolation::Podman);
        assert_eq!(backend.engine, Engine::LlamaCpp);
        assert_eq!(backend.isolation, Isolation::Podman);
    }

    #[test]
    fn isolation_display() {
        assert_eq!(Isolation::Direct.to_string(), "direct");
        assert_eq!(Isolation::Podman.to_string(), "podman");
        assert_eq!(Isolation::OpenShell.to_string(), "openshell");
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
    fn execution_mode_from_task() {
        assert_eq!(
            ExecutionMode::from_task("embedding"),
            ExecutionMode::InProcess
        );
        assert_eq!(
            ExecutionMode::from_task("classification"),
            ExecutionMode::InProcess
        );
        assert_eq!(ExecutionMode::from_task("chat"), ExecutionMode::Served);
        assert_eq!(ExecutionMode::from_task("generate"), ExecutionMode::Served);
        assert_eq!(ExecutionMode::from_task("unknown"), ExecutionMode::Served);
    }

    #[test]
    fn execution_mode_display() {
        assert_eq!(ExecutionMode::InProcess.to_string(), "in_process");
        assert_eq!(ExecutionMode::Served.to_string(), "served");
    }

    #[test]
    fn execution_mode_serde_roundtrip() {
        for variant in [ExecutionMode::InProcess, ExecutionMode::Served] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: ExecutionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn execution_mode_deserialize_snake_case() {
        let ip: ExecutionMode = serde_json::from_str(r#""in_process""#).unwrap();
        assert_eq!(ip, ExecutionMode::InProcess);
        let served: ExecutionMode = serde_json::from_str(r#""served""#).unwrap();
        assert_eq!(served, ExecutionMode::Served);
    }

    #[test]
    fn isolation_level_debug() {
        assert_eq!(format!("{:?}", IsolationLevel::BareMetal), "BareMetal");
        assert_eq!(format!("{:?}", IsolationLevel::Container), "Container");
        assert_eq!(
            format!("{:?}", IsolationLevel::OpenShellSandbox),
            "OpenShellSandbox"
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    impl kani::Arbitrary for ExecutionMode {
        fn any_array<const N: usize>() -> [Self; N] {
            [Self::InProcess; N]
        }

        fn any() -> Self {
            if kani::any::<bool>() {
                ExecutionMode::InProcess
            } else {
                ExecutionMode::Served
            }
        }
    }

    #[kani::proof]
    fn execution_mode_from_task_is_total() {
        let tasks = ["embedding", "classification", "chat", "generate", "other"];
        for task in tasks {
            let mode = ExecutionMode::from_task(task);
            assert!(mode == ExecutionMode::InProcess || mode == ExecutionMode::Served);
        }
    }

    impl kani::Arbitrary for KvCacheType {
        fn any_array<const N: usize>() -> [Self; N] {
            [Self::F16; N]
        }

        fn any() -> Self {
            match kani::any::<u8>() % 3 {
                0 => KvCacheType::F16,
                1 => KvCacheType::Q8_0,
                _ => KvCacheType::Q4_0,
            }
        }
    }

    #[kani::proof]
    fn kv_cache_type_roundtrip() {
        let t: KvCacheType = kani::any();
        let s = t.as_llama_arg();
        let back: KvCacheType = s.parse().unwrap();
        assert_eq!(t, back);
    }

    #[kani::proof]
    fn kv_cache_all_variants_have_llama_arg() {
        let t: KvCacheType = kani::any();
        let s = t.as_llama_arg();
        assert!(!s.is_empty());
    }
}
