//! Direct runtime — spawn llama-server as a child process.
//!
//! No isolation. Suitable for development and trusted models.
//! Requires `llama-server` (from llama.cpp) on PATH.

use crate::{Endpoint, ModelRuntime, RuntimeBackend, RuntimeError, ServeConfig};
use std::pin::Pin;
use std::future::Future;
use std::sync::Mutex;
use std::collections::HashMap;
use tokio::process::{Child, Command};

/// Runtime that spawns llama-server directly.
pub struct DirectRuntime {
    children: Mutex<HashMap<String, Child>>,
}

impl Default for DirectRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectRuntime {
    pub fn new() -> Self {
        Self {
            children: Mutex::new(HashMap::new()),
        }
    }

    /// Check if llama-server is available on PATH.
    pub async fn is_available() -> bool {
        Command::new("llama-server")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
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

            let mut cmd = Command::new("llama-server");
            cmd.arg("--model")
                .arg(&config.model_path)
                .arg("--host")
                .arg(&config.host)
                .arg("--port")
                .arg(port.to_string())
                .arg("--ctx-size")
                .arg(config.context_size.to_string())
                .arg("--parallel")
                .arg(config.parallel.to_string());

            // GPU layers
            if !config.gpus.is_empty() {
                cmd.arg("--n-gpu-layers").arg("999");
            }

            for arg in &config.extra_args {
                cmd.arg(arg);
            }

            cmd.stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped());

            let child = cmd.spawn().map_err(|e| {
                RuntimeError::Start(format!("failed to spawn llama-server: {e}"))
            })?;

            let id = format!("direct-{port}");
            let url = format!("http://{}:{port}", config.host);

            // Wait for health
            let client = reqwest::Client::new();
            let health_url = format!("{url}/health");
            for attempt in 0..60 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if let Ok(resp) = client.get(&health_url).send().await {
                    if resp.status().is_success() {
                        tracing::info!(port = port, "llama-server is ready");
                        break;
                    }
                }
                if attempt == 59 {
                    return Err(RuntimeError::Health(
                        "llama-server did not become healthy within 30s".to_string(),
                    ));
                }
            }

            self.children.lock().unwrap().insert(id.clone(), child);

            Ok(Endpoint {
                url,
                id,
                backend: RuntimeBackend::Direct,
            })
        })
    }

    fn stop(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + '_>> {
        let id = endpoint.id.clone();
        Box::pin(async move {
            let child = self.children.lock().unwrap().remove(&id);
            if let Some(mut child) = child {
                child.kill().await.map_err(|e| {
                    RuntimeError::Stop(format!("failed to kill llama-server: {e}"))
                })?;
                let _ = child.wait().await;
                tracing::info!(id = %id, "Stopped llama-server");
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
        RuntimeBackend::Direct
    }
}

