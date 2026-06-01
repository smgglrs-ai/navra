//! Podman runtime — run inference in rootless containers.
//!
//! Each model gets its own container with:
//! - Read-only model mount
//! - `--network=none` (no data exfiltration)
//! - `--no-new-privileges`
//! - GPU passthrough via CDI (NVIDIA) or device bind (AMD/Intel)
//! - `--ipc=host` when the engine requires it (vLLM NCCL)

use crate::engine::Engine;
use crate::gpu::GpuKind;
use crate::{Endpoint, ModelRuntime, RuntimeBackend, RuntimeCapabilities, RuntimeError, ServeConfig};
use std::future::Future;
use std::pin::Pin;

const HEALTH_POLL_INTERVAL_MS: u64 = 500;

pub struct PodmanRuntime {
    engine: Engine,
}

impl PodmanRuntime {
    pub fn new(engine: Engine) -> Self {
        Self { engine }
    }

    /// Check if Podman is available and (for GPU-only engines) GPUs are present.
    pub async fn is_available(engine: &Engine) -> bool {
        // SAFETY: getuid() is always safe — no preconditions, cannot cause UB.
        let uid = unsafe { libc::getuid() };
        let socket = format!("/run/user/{uid}/podman/podman.sock");
        if !std::path::Path::new(&socket).exists() {
            return false;
        }
        if engine.requires_gpu() && crate::detect_gpus().is_empty() {
            return false;
        }
        true
    }
}

impl ModelRuntime for PodmanRuntime {
    fn serve(
        &self,
        config: &ServeConfig,
    ) -> Pin<Box<dyn Future<Output = Result<Endpoint, RuntimeError>> + Send + '_>> {
        let config = config.clone();
        Box::pin(async move {
            let port = if config.port == 0 {
                crate::pick_free_port()?
            } else {
                config.port
            };

            let image = self.engine.select_image(&config)?;
            let container_name = format!("navra-{}-{port}", self.engine.name());
            let model_path = config
                .model_path
                .to_str()
                .ok_or_else(|| RuntimeError::Start("invalid model path".to_string()))?;

            let container_args = self.engine.build_container_args(&config);
            let serve_port = self.engine.default_serve_port();

            let mut podman_args = vec![
                "run".to_string(),
                "--detach".to_string(),
                "--name".to_string(),
                container_name.clone(),
                "--rm".to_string(),
                "--network=none".to_string(),
                "--no-new-privileges".to_string(),
                "--read-only".to_string(),
            ];

            if self.engine.needs_ipc_host() {
                podman_args.push("--ipc=host".to_string());
            }

            podman_args.extend_from_slice(&[
                "-v".to_string(),
                format!("{model_path}:/model:ro"),
                "-p".to_string(),
                format!("{}:{port}:{serve_port}", config.host),
            ]);

            for gpu in &config.gpus {
                match gpu.kind {
                    GpuKind::Nvidia => {
                        podman_args.push("--device".to_string());
                        podman_args.push(format!("nvidia.com/gpu={}", gpu.index));
                    }
                    GpuKind::Amd => {
                        podman_args.push("--device".to_string());
                        podman_args.push("/dev/kfd".to_string());
                        podman_args.push("--device".to_string());
                        podman_args.push(format!("/dev/dri/renderD{}", 128 + gpu.index));
                    }
                    GpuKind::Intel => {
                        podman_args.push("--device".to_string());
                        podman_args.push(format!("/dev/dri/renderD{}", 128 + gpu.index));
                    }
                }
            }

            podman_args.push(image.to_string());
            podman_args.extend(container_args);

            tracing::info!(
                image = image,
                engine = %self.engine,
                name = %container_name,
                port = port,
                "Creating model container"
            );

            let output = tokio::process::Command::new("podman")
                .args(&podman_args)
                .output()
                .await
                .map_err(|e| RuntimeError::Container(format!("podman run failed: {e}")))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(RuntimeError::Container(format!(
                    "podman run failed: {stderr}"
                )));
            }

            let url = format!("http://{}:{port}", config.host);

            let client = reqwest::Client::new();
            let health_url = format!("{url}/health");
            let max_attempts = self.engine.health_poll_attempts();
            for attempt in 0..max_attempts {
                tokio::time::sleep(std::time::Duration::from_millis(HEALTH_POLL_INTERVAL_MS)).await;
                if let Ok(resp) = client.get(&health_url).send().await {
                    if resp.status().is_success() {
                        tracing::info!(
                            name = %container_name,
                            port = port,
                            engine = %self.engine,
                            "Model container is ready"
                        );
                        break;
                    }
                }
                if attempt == max_attempts - 1 {
                    let _ = tokio::process::Command::new("podman")
                        .args(["rm", "-f", &container_name])
                        .output()
                        .await;
                    let timeout_secs = max_attempts as u64 * HEALTH_POLL_INTERVAL_MS / 1000;
                    return Err(RuntimeError::Health(format!(
                        "model container did not become healthy within {timeout_secs}s"
                    )));
                }
            }

            Ok(Endpoint {
                url,
                id: container_name,
                backend: RuntimeBackend::from_engine_podman(&self.engine),
            })
        })
    }

    fn stop(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + '_>> {
        let name = endpoint.id.clone();
        Box::pin(async move {
            let output = tokio::process::Command::new("podman")
                .args(["stop", &name])
                .output()
                .await
                .map_err(|e| RuntimeError::Stop(format!("podman stop failed: {e}")))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(RuntimeError::Stop(format!(
                    "podman stop {name} failed: {stderr}"
                )));
            }
            tracing::info!(name = %name, "Stopped model container");
            Ok(())
        })
    }

    fn health(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RuntimeError>> + Send + '_>> {
        let url = format!("{}/health", endpoint.url);
        Box::pin(async move {
            let client = reqwest::Client::new();
            match client.get(&url).send().await {
                Ok(resp) => Ok(resp.status().is_success()),
                Err(_) => Ok(false),
            }
        })
    }

    fn backend(&self) -> RuntimeBackend {
        RuntimeBackend::from_engine_podman(&self.engine)
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            supports_kv_checkpoint: self.engine.supports_kv_checkpoint(),
        }
    }
}
