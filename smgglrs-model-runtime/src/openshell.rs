//! OpenShell runtime — delegate sandbox creation to the OpenShell compute driver.
//!
//! Communicates with the OpenShell supervisor via gRPC to create, destroy,
//! and monitor sandboxed model inference environments. OpenShell handles
//! the actual isolation (Podman, libkrun, K8s, etc.) based on labels.
//! The engine determines which entrypoint and args are passed to the sandbox.

use crate::engine::Engine;
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
    CreateSandboxRequest, DestroySandboxRequest, ExecCommandRequest, ExecCommandResponse, Mount,
    SandboxState, SandboxStatusRequest, SupervisorConfig,
};
use tonic::transport::Channel;

/// Model runtime that delegates sandbox creation to OpenShell.
///
/// smgglrs requests a sandbox with labels (GPU requirements,
/// isolation level). OpenShell's compute driver handles
/// provisioning (Podman, libkrun, K8s, etc.).
pub struct OpenShellRuntime {
    engine: Engine,
    gateway: String,
    client: ComputeDriverClient<Channel>,
}

impl OpenShellRuntime {
    /// Connect to the OpenShell compute driver at the given gRPC endpoint.
    pub async fn new(gateway: &str, engine: Engine) -> Result<Self, RuntimeError> {
        let channel = Channel::from_shared(gateway.to_string())
            .map_err(|e| RuntimeError::Connection(e.to_string()))?
            .connect()
            .await
            .map_err(|e| RuntimeError::Connection(e.to_string()))?;

        Ok(Self {
            engine,
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

/// Build a `CreateSandboxRequest` from a `ServeConfig` and `Engine`.
pub fn build_create_request(engine: &Engine, config: &ServeConfig) -> CreateSandboxRequest {
    let mut labels = HashMap::new();

    if !config.gpus.is_empty() {
        labels.insert("gpu".to_string(), "required".to_string());
        labels.insert("gpu_count".to_string(), config.gpus.len().to_string());
    }

    labels.insert("isolation".to_string(), "microvm".to_string());

    let args = engine.build_container_args(config);

    CreateSandboxRequest {
        labels,
        supervisor: Some(SupervisorConfig {
            entrypoint: engine.binary().to_string(),
            args,
            env: HashMap::new(),
            mounts: vec![Mount {
                source: config.model_path.to_string_lossy().to_string(),
                target: "/model".to_string(),
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
        let request = build_create_request(&self.engine, config);
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
                backend: RuntimeBackend::from_engine_openshell(&self.engine),
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
        RuntimeBackend::from_engine_openshell(&self.engine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn build_request_llamacpp_cpu() {
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

        let req = build_create_request(&Engine::LlamaCpp, &config);

        assert!(!req.labels.contains_key("gpu"));
        assert_eq!(req.labels.get("isolation").unwrap(), "microvm");

        let sup = req.supervisor.unwrap();
        assert_eq!(sup.entrypoint, "llama-server");
        assert!(sup.args.contains(&"--model".to_string()));
        assert!(sup.args.contains(&"/model".to_string()));
        assert!(sup.args.contains(&"--ctx-size".to_string()));
        assert!(!sup.args.contains(&"--n-gpu-layers".to_string()));

        assert_eq!(sup.mounts.len(), 1);
        assert_eq!(sup.mounts[0].target, "/model");
        assert!(sup.mounts[0].read_only);
    }

    #[test]
    fn build_request_llamacpp_with_gpus() {
        use crate::gpu::{GpuDevice, GpuKind};

        let config = ServeConfig {
            model_path: PathBuf::from("/models/llama.gguf"),
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
            extra_args: vec!["--flash-attn".to_string()],
            ..ServeConfig::default()
        };

        let req = build_create_request(&Engine::LlamaCpp, &config);

        assert_eq!(req.labels.get("gpu").unwrap(), "required");
        assert_eq!(req.labels.get("gpu_count").unwrap(), "2");

        let sup = req.supervisor.unwrap();
        assert_eq!(sup.entrypoint, "llama-server");
        assert!(sup.args.contains(&"--n-gpu-layers".to_string()));
        assert!(sup.args.contains(&"999".to_string()));
        assert!(sup.args.contains(&"--flash-attn".to_string()));
    }

    #[test]
    fn build_request_vllm() {
        use crate::gpu::{GpuDevice, GpuKind};

        let config = ServeConfig {
            model_path: PathBuf::from("/models/llama-3-70b"),
            gpus: vec![
                GpuDevice { index: 0, name: "A100".into(), vram: None, kind: GpuKind::Nvidia },
                GpuDevice { index: 1, name: "A100".into(), vram: None, kind: GpuKind::Nvidia },
            ],
            context_size: 8192,
            parallel: 8,
            ..ServeConfig::default()
        };

        let req = build_create_request(&Engine::Vllm, &config);

        assert_eq!(req.labels.get("gpu").unwrap(), "required");
        assert_eq!(req.labels.get("gpu_count").unwrap(), "2");

        let sup = req.supervisor.unwrap();
        assert_eq!(sup.entrypoint, "vllm");
        assert!(sup.args.contains(&"--model".to_string()));
        assert!(sup.args.contains(&"/model".to_string()));
        assert!(sup.args.contains(&"--max-model-len".to_string()));
        assert!(sup.args.contains(&"--tensor-parallel-size".to_string()));
        assert!(sup.args.contains(&"2".to_string()));
    }

    #[test]
    fn build_request_with_extra_args() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test.gguf"),
            extra_args: vec!["--threads".to_string(), "8".to_string()],
            ..ServeConfig::default()
        };

        let req = build_create_request(&Engine::LlamaCpp, &config);
        let sup = req.supervisor.unwrap();
        assert!(sup.args.contains(&"--threads".to_string()));
        assert!(sup.args.contains(&"8".to_string()));
    }

    #[test]
    fn build_request_llamacpp_cache_type() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test.gguf"),
            cache_type: Some(crate::KvCacheType::Q8_0),
            ..ServeConfig::default()
        };

        let req = build_create_request(&Engine::LlamaCpp, &config);
        let sup = req.supervisor.unwrap();
        assert!(sup.args.contains(&"--cache-type-k".to_string()));
        assert!(sup.args.contains(&"--cache-type-v".to_string()));
        assert!(sup.args.contains(&"q8_0".to_string()));
    }

    #[test]
    fn build_request_vllm_cache_type() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test"),
            cache_type: Some(crate::KvCacheType::Q4_0),
            ..ServeConfig::default()
        };

        let req = build_create_request(&Engine::Vllm, &config);
        let sup = req.supervisor.unwrap();
        assert!(sup.args.contains(&"--kv-cache-dtype".to_string()));
        assert!(sup.args.contains(&"fp8".to_string()));
    }

    #[test]
    fn build_request_without_cache_type() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test.gguf"),
            cache_type: None,
            ..ServeConfig::default()
        };

        let req = build_create_request(&Engine::LlamaCpp, &config);
        let sup = req.supervisor.unwrap();
        assert!(!sup.args.contains(&"--cache-type-k".to_string()));
    }

    #[test]
    fn sandbox_state_running_value() {
        assert_eq!(SandboxState::Running as i32, 2);
        assert_eq!(SandboxState::Creating as i32, 1);
        assert_eq!(SandboxState::Stopped as i32, 3);
        assert_eq!(SandboxState::Failed as i32, 4);
    }
}
