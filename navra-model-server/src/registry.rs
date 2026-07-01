use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use navra_model::ModelBackend;

use crate::config::ModelEntry;

/// Manages loaded model backends keyed by name.
pub struct ModelRegistry {
    models: HashMap<String, Arc<dyn ModelBackend>>,
    running_endpoints: Vec<RunningEndpoint>,
}

struct RunningEndpoint {
    #[allow(dead_code)] // held to keep the runtime process alive
    runtime: Box<dyn navra_model_runtime::ModelRuntime>,
    endpoint: navra_model_runtime::Endpoint,
}

impl ModelRegistry {
    /// Build a registry from config, loading all models.
    pub async fn from_config(models: &HashMap<String, ModelEntry>) -> anyhow::Result<Self> {
        let mut registry = Self {
            models: HashMap::new(),
            running_endpoints: Vec::new(),
        };

        let hub = navra_model_hub::ModelHub::new().ok();

        for (name, entry) in models {
            if let Err(e) = registry.load_entry(name, entry, &hub).await {
                tracing::error!(model = %name, error = %e, "Failed to load model, skipping");
            }
        }

        tracing::info!(count = registry.models.len(), "Model registry ready");
        Ok(registry)
    }

    /// Load a single model entry into the registry.
    async fn load_entry(
        &mut self,
        name: &str,
        entry: &ModelEntry,
        hub: &Option<navra_model_hub::ModelHub>,
    ) -> anyhow::Result<()> {
        let resolved_path = resolve_model_path(name, entry, hub).await?;

        if !resolved_path.exists() {
            anyhow::bail!("model file not found: {}", resolved_path.display());
        }

        let execution_mode = entry
            .execution_mode
            .unwrap_or_else(|| navra_model_runtime::ExecutionMode::from_task(&entry.task));

        let backend: Arc<dyn ModelBackend> = match execution_mode {
            navra_model_runtime::ExecutionMode::InProcess => {
                self.load_in_process(name, entry, &resolved_path)?
            }
            navra_model_runtime::ExecutionMode::Served => {
                self.load_served(name, entry, &resolved_path).await?
            }
        };

        tracing::info!(model = %name, task = %entry.task, "Model loaded");
        self.models.insert(name.to_string(), backend);
        Ok(())
    }

    #[cfg(feature = "onnx")]
    fn load_in_process(
        &self,
        name: &str,
        entry: &ModelEntry,
        path: &std::path::Path,
    ) -> anyhow::Result<Arc<dyn ModelBackend>> {
        let device = entry
            .device
            .as_deref()
            .map(navra_model::Device::parse)
            .unwrap_or_default();

        let (task, tokenizer_path) = match entry.task.as_str() {
            "embedding" => {
                let dims = entry.dimensions.unwrap_or(768);
                (
                    navra_model::ModelTask::Embedding { dimensions: dims },
                    entry
                        .tokenizer_path
                        .as_ref()
                        .map(|p| PathBuf::from(expand_tilde(p))),
                )
            }
            "classification" => {
                let labels = if entry.labels.is_empty() {
                    vec!["safe".to_string(), "unsafe".to_string()]
                } else {
                    entry.labels.clone()
                };
                (
                    navra_model::ModelTask::Classification { labels },
                    entry
                        .tokenizer_path
                        .as_ref()
                        .map(|p| PathBuf::from(expand_tilde(p))),
                )
            }
            other => {
                anyhow::bail!(
                    "execution_mode=in_process but task is {other}, not embedding/classification"
                );
            }
        };

        let model =
            navra_model::OnnxBackend::load(name, path, tokenizer_path.as_deref(), task, device)?;
        Ok(Arc::new(model))
    }

    #[cfg(not(feature = "onnx"))]
    fn load_in_process(
        &self,
        _name: &str,
        _entry: &ModelEntry,
        _path: &PathBuf,
    ) -> anyhow::Result<Arc<dyn ModelBackend>> {
        anyhow::bail!("in-process models require the 'onnx' feature")
    }

    async fn load_served(
        &mut self,
        name: &str,
        entry: &ModelEntry,
        resolved_path: &std::path::Path,
    ) -> anyhow::Result<Arc<dyn ModelBackend>> {
        let runtime_kind = entry.runtime.as_deref().unwrap_or("auto");

        match runtime_kind {
            "ollama" => {
                let model_id = entry
                    .model_name
                    .clone()
                    .or_else(|| {
                        entry
                            .source
                            .as_ref()
                            .and_then(|s| s.strip_prefix("ollama://").map(String::from))
                    })
                    .unwrap_or_else(|| name.to_string());
                let backend = Arc::new(navra_model::OpenAiBackend::new(
                    "http://localhost:11434/v1",
                    &model_id,
                    None,
                    navra_model::Locality::Local,
                ));
                tracing::info!(model = %name, model_id = %model_id, "Model served via Ollama");
                return Ok(backend);
            }
            "ogx" => {
                let model_id = entry.model_name.clone().unwrap_or_else(|| name.to_string());
                let base_url = entry
                    .base_url
                    .as_deref()
                    .unwrap_or(navra_model::DEFAULT_OGX_URL);
                let locality = if entry.locality.as_deref() == Some("remote") {
                    navra_model::Locality::Remote
                } else {
                    navra_model::Locality::Local
                };
                let backend: Arc<dyn ModelBackend> = if entry.task == "classification" {
                    Arc::new(navra_model::OgxBackend::new(
                        base_url,
                        &model_id,
                        entry.api_key.clone(),
                        locality,
                    ))
                } else {
                    Arc::new(navra_model::OpenAiBackend::new(
                        base_url,
                        &model_id,
                        entry.api_key.clone(),
                        locality,
                    ))
                };
                tracing::info!(model = %name, model_id = %model_id, "Model served via OGX");
                return Ok(backend);
            }
            "none" => {
                anyhow::bail!("runtime=none, skipping");
            }
            _ => {}
        }

        let runtime: Box<dyn navra_model_runtime::ModelRuntime> = match runtime_kind {
            "auto" => navra_model_runtime::auto_runtime().await?,
            "llama-cpp" | "direct" => Box::new(navra_model_runtime::direct::DirectRuntime::new(
                navra_model_runtime::Engine::LlamaCpp,
            )),
            "llama-cpp-podman" | "podman" => {
                Box::new(navra_model_runtime::podman::PodmanRuntime::new(
                    navra_model_runtime::Engine::LlamaCpp,
                ))
            }
            "vllm" => Box::new(navra_model_runtime::direct::DirectRuntime::new(
                navra_model_runtime::Engine::Vllm,
            )),
            "vllm-podman" => Box::new(navra_model_runtime::podman::PodmanRuntime::new(
                navra_model_runtime::Engine::Vllm,
            )),
            #[cfg(feature = "embedded")]
            "embedded" => Box::new(navra_model_runtime::embedded::EmbeddedRuntime::new()),
            other => {
                anyhow::bail!("unknown runtime: {other}");
            }
        };

        let gpus = navra_model_runtime::detect_gpus();
        let target = navra_model_runtime::HardwareTarget::from_gpus(&gpus);
        let format = entry
            .format
            .as_deref()
            .and_then(|s| s.parse::<navra_model_runtime::ModelFormat>().ok())
            .or_else(|| navra_model_runtime::ModelFormat::detect(resolved_path));
        let speculative =
            entry
                .speculative
                .as_ref()
                .map(|s| navra_model_runtime::SpeculativeConfig {
                    draft_model: PathBuf::from(expand_tilde(&s.draft_model)),
                    draft_tokens: s.draft_tokens,
                    draft_min_p: s.draft_min_p,
                });
        let serve_cfg = navra_model_runtime::ServeConfig {
            model_path: resolved_path.to_path_buf(),
            port: entry.port.unwrap_or(0),
            gpus,
            target,
            format,
            context_size: entry.context_size.unwrap_or(4096),
            parallel: entry.parallel.unwrap_or(1),
            cache_type: entry.cache_type,
            speculative,
            ..Default::default()
        };

        let endpoint = runtime.serve(&serve_cfg).await?;
        tracing::info!(
            model = %name,
            url = %endpoint.url,
            backend = ?endpoint.backend,
            "Model served via runtime"
        );

        let model_id = entry.model_name.clone().unwrap_or_else(|| name.to_string());
        let backend: Arc<dyn ModelBackend> = Arc::new(navra_model::OpenAiBackend::new(
            &endpoint.url,
            &model_id,
            None,
            navra_model::Locality::Local,
        ));

        self.running_endpoints
            .push(RunningEndpoint { runtime, endpoint });
        Ok(backend)
    }

    /// Look up a model by name.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn ModelBackend>> {
        self.models.get(name)
    }

    /// List loaded model names.
    pub fn list(&self) -> Vec<String> {
        self.models.keys().cloned().collect()
    }

    /// Number of loaded models.
    pub fn len(&self) -> usize {
        self.models.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    /// Get the full model map (for backward compatibility with gateway).
    pub fn models(&self) -> &HashMap<String, Arc<dyn ModelBackend>> {
        &self.models
    }
}

impl Drop for ModelRegistry {
    fn drop(&mut self) {
        for ep in &self.running_endpoints {
            tracing::info!(
                id = %ep.endpoint.id,
                url = %ep.endpoint.url,
                "Stopping model endpoint"
            );
        }
    }
}

/// Resolve a model's path from hub source or local file.
async fn resolve_model_path(
    name: &str,
    entry: &ModelEntry,
    hub: &Option<navra_model_hub::ModelHub>,
) -> anyhow::Result<PathBuf> {
    if let Some(ref source) = entry.source {
        let hub = hub
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("model hub unavailable"))?;
        let uri = navra_model_hub::ModelUri::parse(source)?;
        let path = hub.pull(&uri).await?;
        tracing::info!(model = %name, source = %source, path = %path.display(), "Model pulled from hub");
        Ok(path)
    } else if let Some(ref path_str) = entry.model_path {
        Ok(PathBuf::from(expand_tilde(path_str)))
    } else {
        anyhow::bail!("no source or model_path configured");
    }
}

/// Expand `~/` to the user's home directory and `$VAR`/`${VAR}` to
/// environment variable values.
pub fn expand_tilde(path: &str) -> String {
    let mut result = path.to_string();
    if result.starts_with("~/")
        && let Some(home) = dirs::home_dir() {
            result = format!("{}{}", home.display(), &result[1..]);
        }
    let mut out = String::with_capacity(result.len());
    let mut chars = result.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            let braced = chars.peek() == Some(&'{');
            if braced {
                chars.next();
            }
            let mut var_name = String::new();
            while let Some(&ch) = chars.peek() {
                if braced {
                    if ch == '}' {
                        chars.next(); // consume closing brace
                        break;
                    }
                } else if !ch.is_alphanumeric() && ch != '_' {
                    break; // don't consume the delimiter
                }
                var_name.push(ch);
                chars.next();
            }
            if let Ok(val) = std::env::var(&var_name) {
                out.push_str(&val);
            } else {
                out.push('$');
                if braced {
                    out.push('{');
                }
                out.push_str(&var_name);
                if braced {
                    out.push('}');
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_tilde_home() {
        let expanded = expand_tilde("~/models/test.onnx");
        assert!(!expanded.starts_with("~/"));
        assert!(expanded.ends_with("/models/test.onnx"));
    }

    #[test]
    fn expand_tilde_no_tilde() {
        assert_eq!(expand_tilde("/absolute/path"), "/absolute/path");
    }

    #[test]
    fn expand_env_var() {
        unsafe { std::env::set_var("NAVRA_TEST_VAR", "hello") };
        assert_eq!(expand_tilde("$NAVRA_TEST_VAR/path"), "hello/path");
        assert_eq!(expand_tilde("${NAVRA_TEST_VAR}/path"), "hello/path");
        unsafe { std::env::remove_var("NAVRA_TEST_VAR") };
    }

    #[test]
    fn empty_registry() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let registry = ModelRegistry::from_config(&HashMap::new()).await.unwrap();
            assert!(registry.is_empty());
            assert_eq!(registry.len(), 0);
            assert!(registry.list().is_empty());
        });
    }
}
