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

/// Runtime that manages llama.cpp containers via Podman.
pub struct PodmanRuntime {
    client: reqwest::Client,
    socket_path: String,
}

impl Default for PodmanRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl PodmanRuntime {
    pub fn new() -> Self {
        // SAFETY: getuid() is always safe — no preconditions, cannot cause UB.
        let uid = unsafe { libc::getuid() };
        let socket_path = format!("/run/user/{uid}/podman/podman.sock");
        Self {
            client: reqwest::Client::new(),
            socket_path,
        }
    }

    /// Check if the Podman socket is available.
    pub async fn is_available() -> bool {
        // SAFETY: getuid() is always safe — no preconditions, cannot cause UB.
        let uid = unsafe { libc::getuid() };
        let socket = format!("/run/user/{uid}/podman/podman.sock");
        std::path::Path::new(&socket).exists()
    }

    /// Build the Podman API base URL for Unix socket.
    fn api_url(&self, path: &str) -> String {
        format!("http://d/v5.0.0/libpod{path}")
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
                pick_free_port()?
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

            let create_body = serde_json::json!({
                "image": image,
                "name": container_name,
                "command": cmd,
                "mounts": [{
                    "destination": "/model",
                    "source": model_path,
                    "type": "bind",
                    "options": ["ro"]
                }],
                "portmappings": [{
                    "container_port": 8080,
                    "host_port": port as i64,
                    "host_ip": config.host,
                    "protocol": "tcp"
                }],
                "netns": { "nsmode": "none" },
                "no_new_privileges": true,
                "read_only_filesystem": true,
                "devices": devices.iter().map(|d| {
                    serde_json::json!({ "path": d })
                }).collect::<Vec<_>>(),
            });

            // Create container via Podman API
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
            for attempt in 0..120 {
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
                if attempt == 119 {
                    // Clean up on timeout
                    let _ = tokio::process::Command::new("podman")
                        .args(["stop", &container_name])
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
                tracing::warn!(name = %name, error = %stderr, "podman stop failed");
            } else {
                tracing::info!(name = %name, "Stopped model container");
            }

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

fn pick_free_port() -> Result<u16, RuntimeError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| RuntimeError::Start(format!("no free port: {e}")))?;
    let port = listener.local_addr().unwrap().port();
    Ok(port)
}
