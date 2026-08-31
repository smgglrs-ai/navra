//! Direct runtime — spawn an inference server as a child process.
//!
//! No isolation. The engine determines which binary is spawned
//! (llama-server for LlamaCpp, vllm for Vllm).

use crate::engine::Engine;
use crate::{
    Endpoint, Isolation, ModelRuntime, RuntimeBackend, RuntimeCapabilities, RuntimeError,
    ServeConfig,
};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use tokio::process::{Child, Command};

const HEALTH_POLL_INTERVAL_MS: u64 = 500;

pub struct DirectRuntime {
    engine: Engine,
    children: Mutex<HashMap<String, Child>>,
}

impl DirectRuntime {
    pub fn new(engine: Engine) -> Self {
        Self {
            engine,
            children: Mutex::new(HashMap::new()),
        }
    }

    pub async fn is_available(engine: &Engine) -> bool {
        engine.is_available().await
    }
}

impl ModelRuntime for DirectRuntime {
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

            let args = self.engine.build_serve_args(&config, port);

            let mut cmd = Command::new(self.engine.binary());
            cmd.args(&args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped());

            let child = cmd.spawn().map_err(|e| {
                RuntimeError::Start(format!("failed to spawn {}: {e}", self.engine.binary()))
            })?;

            let id = format!("{}-{port}", self.engine.name());
            let url = format!("http://{}:{port}", config.host);

            let client = reqwest::Client::new();
            let health_url = format!("{url}/health");
            let max_attempts = self.engine.health_poll_attempts();
            for attempt in 0..max_attempts {
                tokio::time::sleep(std::time::Duration::from_millis(HEALTH_POLL_INTERVAL_MS)).await;
                if let Ok(resp) = client.get(&health_url).send().await
                    && resp.status().is_success()
                {
                    tracing::info!(port = port, engine = %self.engine, "Server is ready");
                    break;
                }
                if attempt == max_attempts - 1 {
                    let timeout_secs = max_attempts as u64 * HEALTH_POLL_INTERVAL_MS / 1000;
                    return Err(RuntimeError::Health(format!(
                        "{} did not become healthy within {timeout_secs}s",
                        self.engine.binary()
                    )));
                }
            }

            self.children.lock().unwrap().insert(id.clone(), child);

            Ok(Endpoint {
                url,
                id,
                backend: RuntimeBackend::new(self.engine, Isolation::Direct),
            })
        })
    }

    fn stop(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + '_>> {
        let id = endpoint.id.clone();
        let engine_name = self.engine.binary();
        Box::pin(async move {
            let child = self.children.lock().unwrap().remove(&id);
            if let Some(mut child) = child {
                child.kill().await.map_err(|e| {
                    RuntimeError::Stop(format!("failed to kill {engine_name}: {e}"))
                })?;
                let _ = child.wait().await;
                tracing::info!(id = %id, "Stopped {engine_name}");
            }
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
        RuntimeBackend::new(self.engine, Isolation::Direct)
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
    use std::path::PathBuf;

    #[test]
    fn direct_new_stores_engine() {
        let rt = DirectRuntime::new(Engine::LlamaCpp);
        assert_eq!(rt.engine, Engine::LlamaCpp);

        let rt2 = DirectRuntime::new(Engine::Vllm);
        assert_eq!(rt2.engine, Engine::Vllm);
    }

    #[test]
    fn direct_backend_returns_direct_isolation() {
        let rt = DirectRuntime::new(Engine::LlamaCpp);
        let backend = rt.backend();
        assert_eq!(backend.engine, Engine::LlamaCpp);
        assert_eq!(backend.isolation, Isolation::Direct);

        let rt2 = DirectRuntime::new(Engine::Vllm);
        let backend2 = rt2.backend();
        assert_eq!(backend2.engine, Engine::Vllm);
        assert_eq!(backend2.isolation, Isolation::Direct);
    }

    #[test]
    fn direct_capabilities_reflect_engine() {
        let llama_rt = DirectRuntime::new(Engine::LlamaCpp);
        assert!(llama_rt.capabilities().supports_kv_checkpoint);

        let vllm_rt = DirectRuntime::new(Engine::Vllm);
        assert!(!vllm_rt.capabilities().supports_kv_checkpoint);
    }

    #[test]
    fn direct_serve_assigns_random_port_when_zero() {
        // pick_free_port is the mechanism used when port=0.
        // Verify it returns a valid nonzero port.
        let port = crate::pick_free_port().unwrap();
        assert!(port > 0);
    }

    #[test]
    fn direct_serve_uses_configured_port() {
        // When config.port != 0, the engine receives that exact port.
        // Verify via build_serve_args (the port is passed through).
        let config = ServeConfig {
            model_path: PathBuf::from("/tmp/test.gguf"),
            host: "127.0.0.1".to_string(),
            port: 8080,
            ..Default::default()
        };
        let args = Engine::LlamaCpp.build_serve_args(&config, 8080);
        let port_idx = args.iter().position(|a| a == "--port").unwrap();
        assert_eq!(args[port_idx + 1], "8080");
    }

    #[tokio::test]
    async fn direct_serve_fails_on_missing_binary() {
        // Neither llama-server nor vllm is typically on PATH in CI.
        // If either happens to be present, skip rather than fail.
        let rt = DirectRuntime::new(Engine::LlamaCpp);
        let config = ServeConfig {
            model_path: PathBuf::from("/nonexistent/model.gguf"),
            port: 0,
            ..Default::default()
        };
        let result = rt.serve(&config).await;
        match result {
            Err(RuntimeError::Start(msg)) => {
                assert!(
                    msg.contains("llama-server"),
                    "error should mention the binary: {msg}"
                );
            }
            Ok(_) => {
                // llama-server is actually installed — skip assertion
            }
            Err(other) => {
                // Health timeout is acceptable if the binary exists
                // but the model doesn't
                assert!(
                    matches!(other, RuntimeError::Health(_)),
                    "unexpected error variant: {other:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn direct_stop_unknown_endpoint_is_ok() {
        let rt = DirectRuntime::new(Engine::LlamaCpp);
        let endpoint = Endpoint {
            url: "http://127.0.0.1:9999".to_string(),
            id: "nonexistent-endpoint".to_string(),
            backend: RuntimeBackend::new(Engine::LlamaCpp, Isolation::Direct),
        };
        // Stopping an endpoint that was never started should succeed (no-op).
        let result = rt.stop(&endpoint).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn direct_health_poll_timeout_error() {
        // health() on an endpoint where nothing is listening returns Ok(false),
        // not an error — connection refused is mapped to false.
        let rt = DirectRuntime::new(Engine::LlamaCpp);
        let endpoint = Endpoint {
            url: "http://127.0.0.1:1".to_string(),
            id: "dead-endpoint".to_string(),
            backend: RuntimeBackend::new(Engine::LlamaCpp, Isolation::Direct),
        };
        let result = rt.health(&endpoint).await;
        // Connection refused → Ok(false)
        assert_eq!(result.unwrap(), false);
    }
}
