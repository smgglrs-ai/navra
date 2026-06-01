//! Direct runtime — spawn an inference server as a child process.
//!
//! No isolation. The engine determines which binary is spawned
//! (llama-server for LlamaCpp, vllm for Vllm).

use crate::engine::Engine;
use crate::{Endpoint, Isolation, ModelRuntime, RuntimeBackend, RuntimeCapabilities, RuntimeError, ServeConfig};
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
                if let Ok(resp) = client.get(&health_url).send().await {
                    if resp.status().is_success() {
                        tracing::info!(port = port, engine = %self.engine, "Server is ready");
                        break;
                    }
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
                child
                    .kill()
                    .await
                    .map_err(|e| RuntimeError::Stop(format!("failed to kill {engine_name}: {e}")))?;
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
        RuntimeBackend::new(self.engine, Isolation::Direct)
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            supports_kv_checkpoint: self.engine.supports_kv_checkpoint(),
        }
    }
}
