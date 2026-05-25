//! OpenShell runtime — delegate sandbox creation to the OpenShell compute driver.
//!
//! Communicates with the OpenShell supervisor via gRPC to create, destroy,
//! and monitor sandboxed model inference environments. OpenShell handles
//! the actual isolation (Podman, libkrun, K8s, etc.) based on labels.

use crate::{Endpoint, ModelRuntime, RuntimeBackend, RuntimeError, ServeConfig};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

/// Generated protobuf types for the OpenShell compute driver.
pub mod proto {
    tonic::include_proto!("openshell.compute.v1");
}

pub use proto::compute_driver_client::ComputeDriverClient;
pub use proto::{
    CreateSandboxRequest, DestroySandboxRequest, ExecCommandRequest,
    ExecCommandResponse, Mount, SandboxState, SandboxStatusRequest,
    SupervisorConfig,
};
use tonic::transport::Channel;

/// Model runtime that delegates sandbox creation to OpenShell.
///
/// smgglrs requests a sandbox with labels (GPU requirements,
/// isolation level). OpenShell's compute driver handles
/// provisioning (Podman, libkrun, K8s, etc.).
pub struct OpenShellRuntime {
    /// gRPC endpoint of the OpenShell gateway.
    gateway: String,
    /// gRPC client (tonic).
    client: ComputeDriverClient<Channel>,
}

impl OpenShellRuntime {
    /// Connect to the OpenShell compute driver at the given gRPC endpoint.
    pub async fn new(gateway: &str) -> Result<Self, RuntimeError> {
        let channel = Channel::from_shared(gateway.to_string())
            .map_err(|e| RuntimeError::Connection(e.to_string()))?
            .connect()
            .await
            .map_err(|e| RuntimeError::Connection(e.to_string()))?;

        Ok(Self {
            gateway: gateway.to_string(),
            client: ComputeDriverClient::new(channel),
        })
    }

    /// Check if an OpenShell compute driver is reachable at the given endpoint.
    pub async fn is_available(gateway: &str) -> bool {
        let channel = match Channel::from_shared(gateway.to_string()) {
            Ok(c) => c,
            Err(_) => return false,
        };
        channel.connect().await.is_ok()
    }

    /// The gateway URL this runtime is connected to.
    pub fn gateway(&self) -> &str {
        &self.gateway
    }

    /// Get a clone of the gRPC client for use by other components.
    pub fn client(&self) -> ComputeDriverClient<Channel> {
        self.client.clone()
    }

    /// Execute a command inside a running sandbox.
    pub async fn exec_command(
        &self,
        sandbox_id: &str,
        command: Vec<String>,
        working_dir: &str,
        env: std::collections::HashMap<String, String>,
        timeout_secs: u32,
    ) -> Result<ExecCommandResponse, RuntimeError> {
        let resp = self
            .client
            .clone()
            .exec_command(ExecCommandRequest {
                sandbox_id: sandbox_id.to_string(),
                command,
                working_dir: working_dir.to_string(),
                env,
                timeout_secs,
            })
            .await
            .map_err(|e| RuntimeError::Start(format!("OpenShell ExecCommand: {e}")))?
            .into_inner();

        Ok(resp)
    }
}

/// Build a `CreateSandboxRequest` from a `ServeConfig`.
///
/// Maps ServeConfig fields to sandbox labels and supervisor config
/// that OpenShell's compute driver understands.
pub fn build_create_request(config: &ServeConfig) -> CreateSandboxRequest {
    let mut labels = HashMap::new();

    if !config.gpus.is_empty() {
        labels.insert("gpu".to_string(), "required".to_string());
        labels.insert("gpu_count".to_string(), config.gpus.len().to_string());
    }

    labels.insert("isolation".to_string(), "microvm".to_string());

    let mut args = vec![
        "-m".to_string(),
        config.model_path.to_string_lossy().to_string(),
        "--host".to_string(),
        "0.0.0.0".to_string(),
        "--port".to_string(),
        "8080".to_string(),
        "-c".to_string(),
        config.context_size.to_string(),
        "-np".to_string(),
        config.parallel.to_string(),
    ];

    // GPU layers
    if !config.gpus.is_empty() {
        args.push("--n-gpu-layers".to_string());
        args.push("999".to_string());
    }

    // KV cache quantization
    if let Some(cache_type) = &config.cache_type {
        args.push("--cache-type-k".to_string());
        args.push(cache_type.as_llama_arg().to_string());
        args.push("--cache-type-v".to_string());
        args.push(cache_type.as_llama_arg().to_string());
    }

    for arg in &config.extra_args {
        args.push(arg.clone());
    }

    CreateSandboxRequest {
        labels,
        supervisor: Some(SupervisorConfig {
            entrypoint: "llama-server".to_string(),
            args,
            env: HashMap::new(),
            mounts: vec![Mount {
                source: config.model_path.to_string_lossy().to_string(),
                target: config.model_path.to_string_lossy().to_string(),
                read_only: true,
            }],
        }),
    }
}

impl ModelRuntime for OpenShellRuntime {
    fn serve(
        &self,
        config: &ServeConfig,
    ) -> Pin<Box<dyn Future<Output = Result<Endpoint, RuntimeError>> + Send + '_>> {
        let request = build_create_request(config);
        Box::pin(async move {
            let resp = self
                .client
                .clone()
                .create_sandbox(request)
                .await
                .map_err(|e| RuntimeError::Start(format!("OpenShell CreateSandbox: {e}")))?
                .into_inner();

            Ok(Endpoint {
                url: resp.endpoint_url,
                id: resp.sandbox_id,
                backend: RuntimeBackend::OpenShell,
            })
        })
    }

    fn stop(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + '_>> {
        let sandbox_id = endpoint.id.clone();
        Box::pin(async move {
            self.client
                .clone()
                .destroy_sandbox(DestroySandboxRequest { sandbox_id })
                .await
                .map_err(|e| RuntimeError::Stop(format!("OpenShell DestroySandbox: {e}")))?;
            Ok(())
        })
    }

    fn health(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RuntimeError>> + Send + '_>> {
        let sandbox_id = endpoint.id.clone();
        Box::pin(async move {
            let resp = self
                .client
                .clone()
                .sandbox_status(SandboxStatusRequest { sandbox_id })
                .await
                .map_err(|e| RuntimeError::Health(format!("OpenShell SandboxStatus: {e}")))?
                .into_inner();
            Ok(resp.state == SandboxState::Running as i32)
        })
    }

    fn backend(&self) -> RuntimeBackend {
        RuntimeBackend::OpenShell
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn build_request_cpu_only() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/granite.gguf"),
            host: "127.0.0.1".to_string(),
            port: 0,
            gpus: vec![],
            context_size: 4096,
            parallel: 2,
            cache_type: None,
            speculative: None,
            extra_args: vec![],
        };

        let req = build_create_request(&config);

        assert!(!req.labels.contains_key("gpu"));
        assert!(!req.labels.contains_key("gpu_count"));
        assert_eq!(req.labels.get("isolation").unwrap(), "microvm");

        let sup = req.supervisor.unwrap();
        assert_eq!(sup.entrypoint, "llama-server");
        assert!(sup.args.contains(&"-m".to_string()));
        assert!(sup.args.contains(&"/models/granite.gguf".to_string()));
        assert!(sup.args.contains(&"-c".to_string()));
        assert!(sup.args.contains(&"4096".to_string()));
        assert!(sup.args.contains(&"-np".to_string()));
        assert!(sup.args.contains(&"2".to_string()));
        // No GPU layers arg
        assert!(!sup.args.contains(&"--n-gpu-layers".to_string()));

        assert_eq!(sup.mounts.len(), 1);
        assert!(sup.mounts[0].read_only);
    }

    #[test]
    fn build_request_with_gpus() {
        use crate::gpu::{GpuDevice, GpuKind};

        let config = ServeConfig {
            model_path: PathBuf::from("/models/llama.gguf"),
            host: "0.0.0.0".to_string(),
            port: 8080,
            gpus: vec![
                GpuDevice {
                    index: 0,
                    name: "RTX 4090".to_string(),
                    vram: Some(24576 * 1024 * 1024),
                    kind: GpuKind::Nvidia,
                },
                GpuDevice {
                    index: 1,
                    name: "RTX 4090".to_string(),
                    vram: Some(24576 * 1024 * 1024),
                    kind: GpuKind::Nvidia,
                },
            ],
            context_size: 8192,
            parallel: 4,
            cache_type: None,
            speculative: None,
            extra_args: vec!["--flash-attn".to_string()],
        };

        let req = build_create_request(&config);

        assert_eq!(req.labels.get("gpu").unwrap(), "required");
        assert_eq!(req.labels.get("gpu_count").unwrap(), "2");

        let sup = req.supervisor.unwrap();
        assert!(sup.args.contains(&"--n-gpu-layers".to_string()));
        assert!(sup.args.contains(&"999".to_string()));
        assert!(sup.args.contains(&"--flash-attn".to_string()));
        assert!(sup.args.contains(&"8192".to_string()));
    }

    #[test]
    fn build_request_with_extra_args() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test.gguf"),
            extra_args: vec![
                "--threads".to_string(),
                "8".to_string(),
            ],
            ..ServeConfig::default()
        };

        let req = build_create_request(&config);
        let sup = req.supervisor.unwrap();
        assert!(sup.args.contains(&"--threads".to_string()));
        assert!(sup.args.contains(&"8".to_string()));
    }

    #[test]
    fn build_request_with_cache_type() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test.gguf"),
            cache_type: Some(crate::KvCacheType::Q8_0),
            ..ServeConfig::default()
        };

        let req = build_create_request(&config);
        let sup = req.supervisor.unwrap();
        assert!(sup.args.contains(&"--cache-type-k".to_string()));
        assert!(sup.args.contains(&"--cache-type-v".to_string()));
        assert!(sup.args.contains(&"q8_0".to_string()));
    }

    #[test]
    fn build_request_without_cache_type() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test.gguf"),
            cache_type: None,
            ..ServeConfig::default()
        };

        let req = build_create_request(&config);
        let sup = req.supervisor.unwrap();
        assert!(!sup.args.contains(&"--cache-type-k".to_string()));
        assert!(!sup.args.contains(&"--cache-type-v".to_string()));
    }

    #[test]
    fn sandbox_state_running_value() {
        // Verify the enum int value we compare against in health()
        assert_eq!(SandboxState::Running as i32, 2);
        assert_eq!(SandboxState::Creating as i32, 1);
        assert_eq!(SandboxState::Stopped as i32, 3);
        assert_eq!(SandboxState::Failed as i32, 4);
    }
}
