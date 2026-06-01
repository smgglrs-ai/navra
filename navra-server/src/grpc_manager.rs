//! Manages lifecycle of out-of-process gRPC modules.
//!
//! `GrpcModuleManager` spawns module processes, connects to them via
//! gRPC, runs periodic health checks, and restarts crashed modules.

#![allow(dead_code)]

use serde::Deserialize;
use navra_core::grpc_module::{GrpcModule, GrpcModuleError};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Child;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Configuration for a single gRPC module.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct GrpcModuleConfig {
    /// Module name (used in logging and tool registration).
    pub name: String,
    /// Command to spawn the module process (first element is binary,
    /// rest are arguments). Empty if the module is externally managed.
    #[serde(default)]
    pub command: Vec<String>,
    /// Unix socket path for the module endpoint.
    #[serde(default)]
    pub socket: Option<PathBuf>,
    /// TCP address for remote modules (e.g., "gpu-host:50051").
    #[serde(default)]
    pub address: Option<String>,
    /// Health check interval in seconds (default: 10).
    #[serde(default = "default_health_interval")]
    pub health_interval_secs: u64,
    /// Whether to restart the module on failure (default: true).
    #[serde(default = "default_true")]
    pub restart_on_failure: bool,
    /// Maximum number of restarts before giving up (default: 3).
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,
}

fn default_health_interval() -> u64 {
    10
}

fn default_true() -> bool {
    true
}

fn default_max_restarts() -> u32 {
    3
}

impl GrpcModuleConfig {
    /// Build the gRPC endpoint URI from socket or address.
    pub fn endpoint(&self) -> Option<String> {
        if let Some(ref socket) = self.socket {
            Some(format!("unix://{}", socket.display()))
        } else if let Some(ref addr) = self.address {
            if addr.starts_with("http") {
                Some(addr.clone())
            } else {
                Some(format!("http://{addr}"))
            }
        } else {
            None
        }
    }
}

/// State for a single managed module.
struct ManagedModule {
    config: GrpcModuleConfig,
    process: Option<Child>,
    restarts: u32,
}

/// Manages lifecycle of gRPC module processes.
pub struct GrpcModuleManager {
    modules: HashMap<String, ManagedModule>,
}

impl GrpcModuleManager {
    /// Create a new manager from a list of module configurations.
    pub fn new(configs: Vec<GrpcModuleConfig>) -> Self {
        let modules = configs
            .into_iter()
            .map(|cfg| {
                let name = cfg.name.clone();
                (
                    name,
                    ManagedModule {
                        config: cfg,
                        process: None,
                        restarts: 0,
                    },
                )
            })
            .collect();

        Self { modules }
    }

    /// Spawn all module processes and connect to them.
    ///
    /// Returns the successfully connected GrpcModule instances.
    /// Modules that fail to start or connect are logged and skipped.
    pub async fn start_all(&mut self) -> Vec<GrpcModule> {
        let mut connected = Vec::new();

        let names: Vec<String> = self.modules.keys().cloned().collect();
        for name in names {
            match self.start_one(&name).await {
                Ok(module) => connected.push(module),
                Err(e) => {
                    tracing::error!(
                        module = %name,
                        error = %e,
                        "Failed to start gRPC module"
                    );
                }
            }
        }

        connected
    }

    /// Start a single module: spawn process (if configured) and connect.
    async fn start_one(&mut self, name: &str) -> Result<GrpcModule, GrpcModuleError> {
        let managed = self
            .modules
            .get_mut(name)
            .ok_or_else(|| GrpcModuleError::Connection(format!("unknown module: {name}")))?;

        // Spawn the process if a command is configured
        if !managed.config.command.is_empty() {
            let binary = &managed.config.command[0];
            let args = &managed.config.command[1..];

            let child = std::process::Command::new(binary)
                .args(args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| {
                    GrpcModuleError::Connection(format!("failed to spawn {binary}: {e}"))
                })?;

            tracing::info!(
                module = %name,
                pid = child.id(),
                "Spawned gRPC module process"
            );

            managed.process = Some(child);

            // Give the process a moment to start its gRPC server.
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let endpoint = managed.config.endpoint().ok_or_else(|| {
            GrpcModuleError::Connection(format!("module {name}: no socket or address configured"))
        })?;

        GrpcModule::connect(name, &endpoint).await
    }

    /// Run periodic health checks until cancelled.
    ///
    /// Checks each module at its configured interval. If a module
    /// fails its health check and `restart_on_failure` is true,
    /// attempts to restart it up to `max_restarts` times.
    pub async fn health_loop(&mut self, cancel: CancellationToken) {
        // Use the minimum health interval across all modules.
        let interval = self
            .modules
            .values()
            .map(|m| m.config.health_interval_secs)
            .min()
            .unwrap_or(10);

        let mut ticker = tokio::time::interval(Duration::from_secs(interval));

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("gRPC module health loop shutting down");
                    break;
                }
                _ = ticker.tick() => {
                    self.check_all().await;
                }
            }
        }
    }

    /// Check health of all modules.
    async fn check_all(&mut self) {
        let names: Vec<String> = self.modules.keys().cloned().collect();
        for name in names {
            let managed = match self.modules.get_mut(&name) {
                Some(m) => m,
                None => continue,
            };

            // Check if the process is still alive
            if let Some(ref mut child) = managed.process {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        tracing::warn!(
                            module = %name,
                            exit_status = %status,
                            "gRPC module process exited"
                        );
                        managed.process = None;

                        if managed.config.restart_on_failure
                            && managed.restarts < managed.config.max_restarts
                        {
                            managed.restarts += 1;
                            tracing::info!(
                                module = %name,
                                attempt = managed.restarts,
                                max = managed.config.max_restarts,
                                "Restarting gRPC module"
                            );
                            match self.start_one(&name).await {
                                Ok(_module) => {
                                    tracing::info!(
                                        module = %name,
                                        "gRPC module restarted"
                                    );
                                }
                                Err(e) => {
                                    tracing::error!(
                                        module = %name,
                                        error = %e,
                                        "Failed to restart gRPC module"
                                    );
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        // Process still running, all good.
                    }
                    Err(e) => {
                        tracing::warn!(
                            module = %name,
                            error = %e,
                            "Failed to check gRPC module process status"
                        );
                    }
                }
            }
        }
    }

    /// Stop all managed module processes.
    pub fn stop_all(&mut self) {
        for (name, managed) in &mut self.modules {
            if let Some(ref mut child) = managed.process {
                tracing::info!(module = %name, "Stopping gRPC module process");
                let _ = child.kill();
                let _ = child.wait();
                managed.process = None;
            }
        }
    }
}

impl Drop for GrpcModuleManager {
    fn drop(&mut self) {
        self.stop_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_endpoint_from_socket() {
        let cfg = GrpcModuleConfig {
            name: "test".to_string(),
            command: vec![],
            socket: Some(PathBuf::from("/run/navra/modules/test.sock")),
            address: None,
            health_interval_secs: 10,
            restart_on_failure: true,
            max_restarts: 3,
        };
        assert_eq!(
            cfg.endpoint(),
            Some("unix:///run/navra/modules/test.sock".to_string())
        );
    }

    #[test]
    fn config_endpoint_from_address() {
        let cfg = GrpcModuleConfig {
            name: "test".to_string(),
            command: vec![],
            socket: None,
            address: Some("gpu-host:50051".to_string()),
            health_interval_secs: 10,
            restart_on_failure: true,
            max_restarts: 3,
        };
        assert_eq!(cfg.endpoint(), Some("http://gpu-host:50051".to_string()));
    }

    #[test]
    fn config_endpoint_from_http_address() {
        let cfg = GrpcModuleConfig {
            name: "test".to_string(),
            command: vec![],
            socket: None,
            address: Some("http://localhost:50051".to_string()),
            health_interval_secs: 10,
            restart_on_failure: true,
            max_restarts: 3,
        };
        assert_eq!(cfg.endpoint(), Some("http://localhost:50051".to_string()));
    }

    #[test]
    fn config_endpoint_none_when_empty() {
        let cfg = GrpcModuleConfig {
            name: "test".to_string(),
            command: vec![],
            socket: None,
            address: None,
            health_interval_secs: 10,
            restart_on_failure: true,
            max_restarts: 3,
        };
        assert_eq!(cfg.endpoint(), None);
    }

    #[test]
    fn config_socket_preferred_over_address() {
        let cfg = GrpcModuleConfig {
            name: "test".to_string(),
            command: vec![],
            socket: Some(PathBuf::from("/run/test.sock")),
            address: Some("host:50051".to_string()),
            health_interval_secs: 10,
            restart_on_failure: true,
            max_restarts: 3,
        };
        // Socket takes priority
        assert_eq!(cfg.endpoint(), Some("unix:///run/test.sock".to_string()));
    }

    #[test]
    fn manager_new_tracks_all_configs() {
        let configs = vec![
            GrpcModuleConfig {
                name: "mod_a".to_string(),
                command: vec![],
                socket: None,
                address: Some("host:50051".to_string()),
                health_interval_secs: 10,
                restart_on_failure: true,
                max_restarts: 3,
            },
            GrpcModuleConfig {
                name: "mod_b".to_string(),
                command: vec![],
                socket: None,
                address: Some("host:50052".to_string()),
                health_interval_secs: 30,
                restart_on_failure: false,
                max_restarts: 0,
            },
        ];

        let manager = GrpcModuleManager::new(configs);
        assert_eq!(manager.modules.len(), 2);
        assert!(manager.modules.contains_key("mod_a"));
        assert!(manager.modules.contains_key("mod_b"));
    }

    #[test]
    fn config_deserialization() {
        let toml = r#"
name = "custom_tool"
command = ["/usr/libexec/navra/modules/custom-tool"]
socket = "/run/navra/modules/custom-tool.sock"
health_interval_secs = 10
restart_on_failure = true
max_restarts = 3
"#;

        let cfg: GrpcModuleConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.name, "custom_tool");
        assert_eq!(
            cfg.command,
            vec!["/usr/libexec/navra/modules/custom-tool"]
        );
        assert_eq!(
            cfg.socket,
            Some(PathBuf::from("/run/navra/modules/custom-tool.sock"))
        );
        assert_eq!(cfg.health_interval_secs, 10);
        assert!(cfg.restart_on_failure);
        assert_eq!(cfg.max_restarts, 3);
    }

    #[test]
    fn config_deserialization_defaults() {
        let toml = r#"
name = "remote_vision"
address = "gpu-host:50051"
"#;

        let cfg: GrpcModuleConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.name, "remote_vision");
        assert!(cfg.command.is_empty());
        assert!(cfg.socket.is_none());
        assert_eq!(cfg.address, Some("gpu-host:50051".to_string()));
        assert_eq!(cfg.health_interval_secs, 10);
        assert!(cfg.restart_on_failure);
        assert_eq!(cfg.max_restarts, 3);
    }
}
