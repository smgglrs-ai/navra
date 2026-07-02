//! Kubernetes Agent Sandbox isolation backend.
//!
//! Uses the kubernetes-sigs/agent-sandbox CRDs (Sandbox, SandboxClaim,
//! SandboxTemplate) to provision isolated inference environments on a
//! Kubernetes cluster. Maps navra risk tiers to SandboxTemplate security
//! profiles.
//!
//! Interacts with the cluster via `kubectl` CLI to avoid adding a heavy
//! kube-rs dependency. Production use should migrate to kube-rs for
//! proper watch/retry semantics.

use crate::{
    Endpoint, HardwareTarget, Isolation, ModelRuntime, RuntimeBackend, RuntimeError, ServeConfig,
    engine::Engine,
};
use std::future::Future;
use std::pin::Pin;

/// Configuration for the Kubernetes Agent Sandbox backend.
#[derive(Debug, Clone)]
pub struct KubernetesConfig {
    /// Kubernetes namespace for sandbox resources.
    pub namespace: String,
    /// SandboxTemplate name to use.
    pub template: String,
    /// Optional SandboxWarmPool name for sub-second provisioning.
    pub warm_pool: Option<String>,
    /// kubectl context to use (None = current context).
    pub context: Option<String>,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            namespace: "navra".into(),
            template: "inference-default".into(),
            warm_pool: None,
            context: None,
        }
    }
}

/// Runtime that provisions model inference in Kubernetes Agent Sandbox pods.
pub struct KubernetesRuntime {
    engine: Engine,
    config: KubernetesConfig,
}

impl KubernetesRuntime {
    pub fn new(engine: Engine, config: KubernetesConfig) -> Self {
        Self { engine, config }
    }

    pub async fn is_available(config: &KubernetesConfig) -> bool {
        let mut cmd = tokio::process::Command::new("kubectl");
        if let Some(ref ctx) = config.context {
            cmd.arg("--context").arg(ctx);
        }
        cmd.args(["api-resources", "--api-group=agents.x-k8s.io", "-o", "name"]);
        match cmd.output().await {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                stdout.contains("sandboxes")
            }
            Err(_) => false,
        }
    }

    fn kubectl_base(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new("kubectl");
        if let Some(ref ctx) = self.config.context {
            cmd.arg("--context").arg(ctx);
        }
        cmd.args(["-n", &self.config.namespace]);
        cmd
    }

    fn sandbox_name(config: &ServeConfig) -> String {
        let model_name = config
            .model_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("model")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .take(40)
            .collect::<String>()
            .to_lowercase();
        format!("navra-{model_name}")
    }

    fn sandbox_labels(config: &ServeConfig) -> Vec<(String, String)> {
        let mut labels = vec![
            ("app.kubernetes.io/managed-by".into(), "navra".into()),
            ("app.kubernetes.io/component".into(), "inference".into()),
        ];
        let hw = match config.target {
            HardwareTarget::Cpu => "cpu",
            HardwareTarget::Nvidia => "nvidia",
            HardwareTarget::Amd => "amd",
            HardwareTarget::Intel => "intel",
        };
        labels.push(("navra.io/hardware".into(), hw.into()));
        labels
    }

    fn build_sandbox_manifest(
        &self,
        config: &ServeConfig,
        name: &str,
        port: u16,
    ) -> serde_json::Value {
        let labels: serde_json::Map<String, serde_json::Value> = Self::sandbox_labels(config)
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();

        serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1alpha1",
            "kind": "Sandbox",
            "metadata": {
                "name": name,
                "namespace": self.config.namespace,
                "labels": labels
            },
            "spec": {
                "templateRef": {
                    "name": self.config.template
                },
                "resources": {
                    "limits": self.resource_limits(config)
                },
                "env": [
                    {"name": "MODEL_PATH", "value": config.model_path.to_string_lossy()},
                    {"name": "PORT", "value": port.to_string()},
                    {"name": "HOST", "value": "0.0.0.0"},
                    {"name": "CONTEXT_SIZE", "value": config.context_size.to_string()},
                    {"name": "PARALLEL", "value": config.parallel.to_string()}
                ]
            }
        })
    }

    fn resource_limits(&self, config: &ServeConfig) -> serde_json::Value {
        match config.target {
            HardwareTarget::Nvidia | HardwareTarget::Amd => serde_json::json!({
                "nvidia.com/gpu": config.gpus.len().max(1).to_string(),
                "memory": "16Gi",
                "cpu": "4"
            }),
            HardwareTarget::Intel => serde_json::json!({
                "gpu.intel.com/i915": config.gpus.len().max(1).to_string(),
                "memory": "8Gi",
                "cpu": "4"
            }),
            HardwareTarget::Cpu => serde_json::json!({
                "memory": "4Gi",
                "cpu": "2"
            }),
        }
    }
}

impl ModelRuntime for KubernetesRuntime {
    fn serve(
        &self,
        config: &ServeConfig,
    ) -> Pin<Box<dyn Future<Output = Result<Endpoint, RuntimeError>> + Send + '_>> {
        let config = config.clone();
        Box::pin(async move {
            let name = Self::sandbox_name(&config);
            let port = if config.port == 0 { 8080 } else { config.port };
            let manifest = self.build_sandbox_manifest(&config, &name, port);

            let manifest_json = serde_json::to_string(&manifest)
                .map_err(|e| RuntimeError::Start(format!("manifest serialization: {e}")))?;

            let mut cmd = self.kubectl_base();
            cmd.args(["apply", "-f", "-"]);
            cmd.stdin(std::process::Stdio::piped());
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());

            let mut child = cmd
                .spawn()
                .map_err(|e| RuntimeError::Start(format!("kubectl spawn: {e}")))?;

            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin
                    .write_all(manifest_json.as_bytes())
                    .await
                    .map_err(|e| RuntimeError::Start(format!("kubectl stdin: {e}")))?;
            }

            let output = child
                .wait_with_output()
                .await
                .map_err(|e| RuntimeError::Start(format!("kubectl wait: {e}")))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(RuntimeError::Start(format!(
                    "kubectl apply failed: {stderr}"
                )));
            }

            // Wait for sandbox to be ready
            let mut cmd = self.kubectl_base();
            cmd.args([
                "wait",
                "--for=condition=Ready",
                &format!("sandbox/{name}"),
                "--timeout=120s",
            ]);
            let wait_output = cmd
                .output()
                .await
                .map_err(|e| RuntimeError::Start(format!("kubectl wait: {e}")))?;

            if !wait_output.status.success() {
                let stderr = String::from_utf8_lossy(&wait_output.stderr);
                return Err(RuntimeError::Start(format!("sandbox not ready: {stderr}")));
            }

            // Get the sandbox endpoint
            let mut cmd = self.kubectl_base();
            cmd.args([
                "get",
                &format!("sandbox/{name}"),
                "-o",
                "jsonpath={.status.endpoint}",
            ]);
            let ep_output = cmd
                .output()
                .await
                .map_err(|e| RuntimeError::Start(format!("kubectl get endpoint: {e}")))?;

            let endpoint_url = String::from_utf8_lossy(&ep_output.stdout).to_string();
            let url = if endpoint_url.is_empty() {
                format!(
                    "http://{name}.{}.svc.cluster.local:{port}",
                    self.config.namespace
                )
            } else {
                endpoint_url
            };

            tracing::info!(
                sandbox = %name,
                url = %url,
                "Kubernetes sandbox started"
            );

            Ok(Endpoint {
                url,
                id: name,
                backend: RuntimeBackend::new(self.engine.clone(), Isolation::Kubernetes),
            })
        })
    }

    fn stop(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + '_>> {
        let name = endpoint.id.clone();
        Box::pin(async move {
            let mut cmd = self.kubectl_base();
            cmd.args(["delete", "sandbox", &name, "--ignore-not-found"]);
            let output = cmd
                .output()
                .await
                .map_err(|e| RuntimeError::Stop(format!("kubectl delete: {e}")))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!(sandbox = %name, error = %stderr, "Failed to delete sandbox");
            } else {
                tracing::info!(sandbox = %name, "Kubernetes sandbox deleted");
            }

            Ok(())
        })
    }

    fn health(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RuntimeError>> + Send + '_>> {
        let url = endpoint.url.clone();
        Box::pin(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default();
            match client.get(format!("{url}/health")).send().await {
                Ok(resp) => Ok(resp.status().is_success()),
                Err(_) => Ok(false),
            }
        })
    }

    fn backend(&self) -> RuntimeBackend {
        RuntimeBackend::new(self.engine.clone(), Isolation::Kubernetes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_config() -> ServeConfig {
        ServeConfig {
            model_path: PathBuf::from("/models/granite-3b.gguf"),
            host: "0.0.0.0".into(),
            port: 0,
            gpus: vec![],
            target: HardwareTarget::Cpu,
            format: None,
            context_size: 4096,
            parallel: 1,
            cache_type: None,
            speculative: None,
            extra_args: vec![],
        }
    }

    #[test]
    fn sandbox_name_from_model_path() {
        let config = test_config();
        let name = KubernetesRuntime::sandbox_name(&config);
        assert_eq!(name, "navra-granite-3b");
    }

    #[test]
    fn sandbox_name_sanitizes_special_chars() {
        let mut config = test_config();
        config.model_path = PathBuf::from("/models/my_model@v2.1.gguf");
        let name = KubernetesRuntime::sandbox_name(&config);
        assert!(!name.contains('@'));
        assert!(!name.contains('.'));
        assert!(name.starts_with("navra-"));
    }

    #[test]
    fn sandbox_labels_cpu() {
        let config = test_config();
        let labels = KubernetesRuntime::sandbox_labels(&config);
        assert!(
            labels
                .iter()
                .any(|(k, v)| k == "navra.io/hardware" && v == "cpu")
        );
    }

    #[test]
    fn sandbox_labels_gpu() {
        let mut config = test_config();
        config.target = HardwareTarget::Nvidia;
        let labels = KubernetesRuntime::sandbox_labels(&config);
        assert!(
            labels
                .iter()
                .any(|(k, v)| k == "navra.io/hardware" && v == "nvidia")
        );
    }

    #[test]
    fn kubernetes_config_defaults() {
        let cfg = KubernetesConfig::default();
        assert_eq!(cfg.namespace, "navra");
        assert_eq!(cfg.template, "inference-default");
        assert!(cfg.warm_pool.is_none());
        assert!(cfg.context.is_none());
    }

    #[test]
    fn manifest_structure() {
        let rt = KubernetesRuntime::new(Engine::LlamaCpp, KubernetesConfig::default());
        let config = test_config();
        let manifest = rt.build_sandbox_manifest(&config, "test-sandbox", 8080);

        assert_eq!(manifest["apiVersion"], "agents.x-k8s.io/v1alpha1");
        assert_eq!(manifest["kind"], "Sandbox");
        assert_eq!(manifest["metadata"]["name"], "test-sandbox");
        assert_eq!(manifest["metadata"]["namespace"], "navra");
        assert_eq!(manifest["spec"]["templateRef"]["name"], "inference-default");

        let env = manifest["spec"]["env"].as_array().unwrap();
        assert!(
            env.iter()
                .any(|e| e["name"] == "PORT" && e["value"] == "8080")
        );
        assert!(
            env.iter()
                .any(|e| e["name"] == "CONTEXT_SIZE" && e["value"] == "4096")
        );
    }

    #[test]
    fn resource_limits_cpu() {
        let rt = KubernetesRuntime::new(Engine::LlamaCpp, KubernetesConfig::default());
        let config = test_config();
        let limits = rt.resource_limits(&config);
        assert_eq!(limits["cpu"], "2");
        assert_eq!(limits["memory"], "4Gi");
        assert!(limits.get("nvidia.com/gpu").is_none());
    }

    #[test]
    fn resource_limits_gpu() {
        let rt = KubernetesRuntime::new(Engine::Vllm, KubernetesConfig::default());
        let mut config = test_config();
        config.target = HardwareTarget::Nvidia;
        let limits = rt.resource_limits(&config);
        assert_eq!(limits["nvidia.com/gpu"], "1");
        assert_eq!(limits["memory"], "16Gi");
    }

    #[test]
    fn backend_reports_kubernetes() {
        let rt = KubernetesRuntime::new(Engine::LlamaCpp, KubernetesConfig::default());
        let backend = rt.backend();
        assert_eq!(backend.isolation, Isolation::Kubernetes);
        assert_eq!(backend.engine, Engine::LlamaCpp);
    }
}
