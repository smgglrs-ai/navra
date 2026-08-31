//! Podman runtime — run inference in rootless containers.
//!
//! Each model gets its own container with:
//! - Read-only model mount
//! - `--network=none` (no data exfiltration)
//! - `--no-new-privileges`
//! - GPU passthrough via CDI (NVIDIA) or device bind (AMD/Intel)
//! - `--ipc=host` when the engine requires it (vLLM NCCL)

use crate::engine::Engine;
use crate::{
    Endpoint, Isolation, ModelRuntime, RuntimeBackend, RuntimeCapabilities, RuntimeError,
    ServeConfig,
};
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

    /// Build the `podman run` argument list.
    ///
    /// Extracted from [`serve()`] so the security-critical flags can be
    /// unit-tested without spawning a real container.
    pub(crate) fn build_podman_args(
        &self,
        config: &ServeConfig,
        port: u16,
        image: &str,
        container_name: &str,
        model_path: &str,
    ) -> Vec<String> {
        let container_args = self.engine.build_container_args(config);
        let serve_port = self.engine.default_serve_port();

        let mut podman_args = vec![
            "run".to_string(),
            "--detach".to_string(),
            "--name".to_string(),
            container_name.to_string(),
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
            podman_args.extend(config.target.podman_device_args(gpu.index));
        }

        podman_args.push(image.to_string());
        podman_args.extend(container_args);

        podman_args
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

            let podman_args =
                self.build_podman_args(&config, port, image, &container_name, model_path);

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
                if let Ok(resp) = client.get(&health_url).send().await
                    && resp.status().is_success()
                {
                    tracing::info!(
                        name = %container_name,
                        port = port,
                        engine = %self.engine,
                        "Model container is ready"
                    );
                    break;
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
                backend: RuntimeBackend::new(self.engine, Isolation::Podman),
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
        let endpoint = endpoint.clone();
        Box::pin(async move { crate::http_health_check(&endpoint).await })
    }

    fn backend(&self) -> RuntimeBackend {
        RuntimeBackend::new(self.engine, Isolation::Podman)
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            supports_kv_checkpoint: self.engine.supports_kv_checkpoint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HardwareTarget;
    use std::path::PathBuf;

    fn default_config() -> ServeConfig {
        ServeConfig {
            model_path: PathBuf::from("/models/test.gguf"),
            host: "127.0.0.1".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn podman_new_stores_engine() {
        let rt = PodmanRuntime::new(Engine::LlamaCpp);
        assert_eq!(rt.engine, Engine::LlamaCpp);

        let rt2 = PodmanRuntime::new(Engine::Vllm);
        assert_eq!(rt2.engine, Engine::Vllm);
    }

    #[test]
    fn podman_backend_returns_podman_isolation() {
        let rt = PodmanRuntime::new(Engine::LlamaCpp);
        let backend = rt.backend();
        assert_eq!(backend.engine, Engine::LlamaCpp);
        assert_eq!(backend.isolation, Isolation::Podman);

        let rt2 = PodmanRuntime::new(Engine::Vllm);
        let backend2 = rt2.backend();
        assert_eq!(backend2.engine, Engine::Vllm);
        assert_eq!(backend2.isolation, Isolation::Podman);
    }

    #[test]
    fn podman_capabilities_reflect_engine() {
        let llama_rt = PodmanRuntime::new(Engine::LlamaCpp);
        assert!(llama_rt.capabilities().supports_kv_checkpoint);

        let vllm_rt = PodmanRuntime::new(Engine::Vllm);
        assert!(!vllm_rt.capabilities().supports_kv_checkpoint);
    }

    #[tokio::test]
    async fn podman_is_available_no_socket() {
        // In CI there's typically no Podman socket.
        // If Podman happens to be running, this test still passes
        // — it just returns true instead of false.
        let result = PodmanRuntime::is_available(&Engine::LlamaCpp).await;
        // Can't assert false (Podman might be running), but assert no panic.
        let _ = result;
    }

    #[test]
    fn podman_serve_includes_security_flags() {
        let rt = PodmanRuntime::new(Engine::LlamaCpp);
        let config = default_config();
        let args = rt.build_podman_args(
            &config,
            8080,
            "ghcr.io/ggml-org/llama.cpp:server",
            "navra-llama-cpp-8080",
            "/models/test.gguf",
        );

        assert!(args.contains(&"--network=none".to_string()));
        assert!(args.contains(&"--no-new-privileges".to_string()));
        assert!(args.contains(&"--read-only".to_string()));
    }

    #[test]
    fn podman_serve_adds_ipc_host_when_needed() {
        // vLLM needs --ipc=host for NCCL shared memory
        let rt = PodmanRuntime::new(Engine::Vllm);
        let config = default_config();
        let args = rt.build_podman_args(
            &config,
            8000,
            "vllm/vllm-openai:latest",
            "navra-vllm-8000",
            "/models/test",
        );
        assert!(args.contains(&"--ipc=host".to_string()));

        // llama.cpp does not need --ipc=host
        let rt2 = PodmanRuntime::new(Engine::LlamaCpp);
        let args2 = rt2.build_podman_args(
            &config,
            8080,
            "ghcr.io/ggml-org/llama.cpp:server",
            "navra-llama-cpp-8080",
            "/models/test.gguf",
        );
        assert!(!args2.contains(&"--ipc=host".to_string()));
    }

    #[test]
    fn podman_serve_mounts_model_readonly() {
        let rt = PodmanRuntime::new(Engine::LlamaCpp);
        let config = default_config();
        let args = rt.build_podman_args(
            &config,
            8080,
            "ghcr.io/ggml-org/llama.cpp:server",
            "navra-llama-cpp-8080",
            "/models/test.gguf",
        );

        // Find the -v flag and check its value includes :ro
        let v_idx = args.iter().position(|a| a == "-v").unwrap();
        assert_eq!(args[v_idx + 1], "/models/test.gguf:/model:ro");
    }

    #[tokio::test]
    async fn podman_serve_fails_on_podman_error() {
        // Attempting to serve when Podman isn't available (or with
        // an invalid config) should produce a container error.
        // On CI without Podman, `podman run` itself fails to spawn.
        let rt = PodmanRuntime::new(Engine::LlamaCpp);
        let config = ServeConfig {
            model_path: PathBuf::from("/nonexistent/model.gguf"),
            target: HardwareTarget::Cpu,
            ..Default::default()
        };
        let result = rt.serve(&config).await;
        // Should fail — either Container (podman not found or exit 1)
        // or Health (container started but model didn't load).
        assert!(
            result.is_err(),
            "serve should fail without a valid model and container setup"
        );
    }
}
