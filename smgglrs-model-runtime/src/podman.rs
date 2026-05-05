//! Podman runtime — run inference in rootless containers.
//!
//! Uses the Podman REST API (Unix socket) to manage containers.
//! Each model gets its own container with:
//! - Read-only model mount
//! - `--network=none` (no data exfiltration)
//! - `--no-new-privileges`
//! - GPU passthrough via CDI (NVIDIA) or device bind (AMD/Intel)

use crate::{Endpoint, ModelRuntime, RuntimeBackend, RuntimeError, ServeConfig};
use crate::gpu::GpuKind;
use std::pin::Pin;
use std::future::Future;

/// Default container images per GPU type.
const IMAGE_CPU: &str = "ghcr.io/ggml-org/llama.cpp:server";
const IMAGE_CUDA: &str = "ghcr.io/ggml-org/llama.cpp:server-cuda";
const IMAGE_ROCM: &str = "ghcr.io/ggml-org/llama.cpp:server-rocm";

const HEALTH_MAX_ATTEMPTS: usize = 120;

/// Runtime that manages llama.cpp containers via Podman.
#[derive(Default)]
pub struct PodmanRuntime;

impl PodmanRuntime {
    pub fn new() -> Self {
        Self
    }

    /// Check if the Podman socket is available.
    pub async fn is_available() -> bool {
        // SAFETY: getuid() is always safe — no preconditions, cannot cause UB.
        let uid = unsafe { libc::getuid() };
        let socket = format!("/run/user/{uid}/podman/podman.sock");
        std::path::Path::new(&socket).exists()
    }

    /// Select container image based on GPU.
    fn select_image(config: &ServeConfig) -> &'static str {
        match config.gpus.first().map(|g| &g.kind) {
            Some(GpuKind::Nvidia) => IMAGE_CUDA,
            Some(GpuKind::Amd) => IMAGE_ROCM,
            _ => IMAGE_CPU,
        }
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

            let image = Self::select_image(&config);
            let container_name = format!("smgglrs-model-{port}");
            let model_path = config
                .model_path
                .to_str()
                .ok_or_else(|| RuntimeError::Start("invalid model path".to_string()))?;

            // Build container create request
            let mut cmd = vec![
                "--model".to_string(),
                "/model".to_string(),
                "--host".to_string(),
                "0.0.0.0".to_string(),
                "--port".to_string(),
                "8080".to_string(),
                "--ctx-size".to_string(),
                config.context_size.to_string(),
                "--parallel".to_string(),
                config.parallel.to_string(),
            ];

            if !config.gpus.is_empty() {
                cmd.extend_from_slice(&["--n-gpu-layers".to_string(), "999".to_string()]);
            }

            cmd.extend(config.extra_args.iter().cloned());

            let mut devices = Vec::new();
            for gpu in &config.gpus {
                match gpu.kind {
                    GpuKind::Nvidia => {
                        // CDI device for NVIDIA
                        devices.push(format!("nvidia.com/gpu={}", gpu.index));
                    }
                    GpuKind::Amd => {
                        devices.push(format!("/dev/dri/renderD{}", 128 + gpu.index));
                    }
                    GpuKind::Intel => {
                        devices.push(format!("/dev/dri/renderD{}", 128 + gpu.index));
                    }
                }
            }

            // Create container via Podman CLI
            tracing::info!(
                image = image,
                name = %container_name,
                port = port,
                "Creating model container"
            );

            // Note: actual HTTP-over-Unix-socket requires hyper with
            // unix connector. For now, fall back to podman CLI.
            let output = tokio::process::Command::new("podman")
                .arg("run")
                .arg("--detach")
                .arg("--name")
                .arg(&container_name)
                .arg("--rm")
                .arg("--network=none")
                .arg("--no-new-privileges")
                .arg("--read-only")
                .arg("-v")
                .arg(format!("{model_path}:/model:ro"))
                .arg("-p")
                .arg(format!("{}:{port}:8080", config.host))
                .arg(image)
                .args(&cmd)
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

            // Wait for health
            let client = reqwest::Client::new();
            let health_url = format!("{url}/health");
            for attempt in 0..HEALTH_MAX_ATTEMPTS {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if let Ok(resp) = client.get(&health_url).send().await {
                    if resp.status().is_success() {
                        tracing::info!(
                            name = %container_name,
                            port = port,
                            "Model container is ready"
                        );
                        break;
                    }
                }
                if attempt == HEALTH_MAX_ATTEMPTS - 1 {
                    let _ = tokio::process::Command::new("podman")
                        .args(["rm", "-f", &container_name])
                        .output()
                        .await;
                    return Err(RuntimeError::Health(
                        "model container did not become healthy within 60s".to_string(),
                    ));
                }
            }

            Ok(Endpoint {
                url,
                id: container_name,
                backend: RuntimeBackend::Podman,
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
        RuntimeBackend::Podman
    }
}

