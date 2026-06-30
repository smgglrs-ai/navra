//! Ollama registry transport.
//!
//! Pulls GGUF models from the Ollama registry API.
//! API: `GET https://registry.ollama.ai/v2/library/<model>/manifests/<tag>`
//! then fetch blob layers.
//!
//! Before hitting the network, checks the local Ollama model store
//! at `~/.ollama/models/` (or `$OLLAMA_MODELS`). If the model was
//! already pulled by `ollama pull`, it is read directly from disk.
//!
//! Metadata extraction: parses the manifest layers for model config,
//! parameters, and quantization info.

use super::ModelTransport;
use crate::card::VendorMeta;
use crate::error::HubError;
use crate::uri::ModelUri;
use std::path::PathBuf;

const OLLAMA_REGISTRY: &str = "https://registry.ollama.ai";

/// Transport for the Ollama model registry.
pub struct OllamaTransport {
    client: reqwest::Client,
    registry_url: String,
}

impl OllamaTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            registry_url: OLLAMA_REGISTRY.to_string(),
        }
    }
}

impl ModelTransport for OllamaTransport {
    fn pull<'a>(
        &'a self,
        uri: &'a ModelUri,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, HubError>> + Send + 'a>>
    {
        Box::pin(async move {
            // Parse "model:tag" — default tag is "latest"
            let (model, tag) = match uri.path.split_once(':') {
                Some((m, t)) => (m, t),
                None => (uri.path.as_str(), "latest"),
            };

            // Fetch manifest from registry (local manifest checked in ModelHub::pull)
            let manifest_url = format!("{}/v2/library/{model}/manifests/{tag}", self.registry_url);
            tracing::debug!(url = %manifest_url, "Fetching Ollama manifest");

            let resp = self
                .client
                .get(&manifest_url)
                .send()
                .await?
                .error_for_status()
                .map_err(|e| HubError::Registry(format!("manifest fetch failed: {e}")))?;

            let manifest: serde_json::Value = resp.json().await?;

            // Find the model layer (largest blob, typically the GGUF)
            let layers = manifest["layers"]
                .as_array()
                .ok_or_else(|| HubError::Registry("no layers in manifest".to_string()))?;

            let model_layer = layers
                .iter()
                .max_by_key(|l| l["size"].as_u64().unwrap_or(0))
                .ok_or_else(|| HubError::Registry("no model layer found".to_string()))?;

            let digest = model_layer["digest"]
                .as_str()
                .ok_or_else(|| HubError::Registry("layer missing digest".to_string()))?;

            // Fetch blob
            let blob_url = format!("{}/v2/library/{model}/blobs/{digest}", self.registry_url);
            tracing::info!(
                model = model,
                tag = tag,
                digest = digest,
                "Pulling Ollama model blob"
            );

            let blob = self
                .client
                .get(&blob_url)
                .send()
                .await?
                .error_for_status()
                .map_err(|e| HubError::Download(format!("blob fetch failed: {e}")))?
                .bytes()
                .await?;

            Ok(blob.to_vec())
        })
    }

    fn metadata<'a>(
        &'a self,
        uri: &'a ModelUri,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<VendorMeta, HubError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let (model, tag) = match uri.path.split_once(':') {
                Some((m, t)) => (m, t),
                None => (uri.path.as_str(), "latest"),
            };

            // Try local manifest first
            let manifest: serde_json::Value = if let Some(local) = read_local_manifest(model, tag) {
                local
            } else {
                let manifest_url =
                    format!("{}/v2/library/{model}/manifests/{tag}", self.registry_url);

                let resp = self
                    .client
                    .get(&manifest_url)
                    .send()
                    .await?
                    .error_for_status()
                    .map_err(|e| HubError::Registry(format!("manifest fetch failed: {e}")))?;

                resp.json().await?
            };

            let mut meta = VendorMeta {
                source: Some("ollama".into()),
                format: Some("gguf".into()),
                ..Default::default()
            };

            // Extract family from model name (e.g. "granite-code" → "granite")
            if let Some(family) = model.split('-').next() {
                meta.family = Some(family.to_string());
            }

            // Extract parameter count from tag (e.g. "3b", "8b-instruct")
            if let Some(params) = tag.split('-').next()
                && (params.ends_with('b') || params.ends_with('B')) {
                    meta.parameters = Some(params.to_uppercase());
                }

            // Parse layers for quantization info and context size
            if let Some(layers) = manifest["layers"].as_array() {
                for layer in layers {
                    let media_type = layer["mediaType"].as_str().unwrap_or("");
                    // The model config layer contains template and parameters
                    if media_type == "application/vnd.ollama.image.params" {
                        // Params layer may contain context window, stop tokens, etc.
                        // We'd need to fetch and parse it, but for now extract from mediaType
                    }
                    // Quantization is often in the model layer mediaType
                    if media_type.contains("model") {
                        // The digest or size can hint at quantization
                        if let Some(size) = layer["size"].as_u64() {
                            meta.quantization =
                                Some(estimate_quantization(size, meta.parameters.as_deref()));
                        }
                    }
                }
            }

            Ok(meta)
        })
    }
}

/// Resolve the local Ollama model store path.
///
/// Checks `$OLLAMA_MODELS` first, then `~/.ollama/models`.
fn ollama_models_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("OLLAMA_MODELS") {
        let p = PathBuf::from(dir);
        if p.is_dir() {
            return Some(p);
        }
    }
    dirs::home_dir().map(|h| h.join(".ollama/models")).filter(|p| p.is_dir())
}

/// Try to read a model blob from the local Ollama store.
///
/// Layout:
///   manifests/registry.ollama.ai/library/{model}/{tag} — JSON manifest
///   blobs/sha256-{hash} — raw model files
pub fn try_local_ollama(model: &str, tag: &str) -> Option<PathBuf> {
    let models_dir = ollama_models_dir()?;

    let manifest_path = models_dir
        .join("manifests/registry.ollama.ai/library")
        .join(model)
        .join(tag);

    let manifest_bytes = std::fs::read(&manifest_path).ok()?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).ok()?;

    let layers = manifest["layers"].as_array()?;

    let model_layer = layers
        .iter()
        .filter(|l| {
            l["mediaType"]
                .as_str()
                .is_some_and(|m| m.contains("model"))
        })
        .max_by_key(|l| l["size"].as_u64().unwrap_or(0))?;

    let digest = model_layer["digest"].as_str()?;
    let blob_name = digest.replace(':', "-");
    let blob_path = models_dir.join("blobs").join(&blob_name);

    if blob_path.is_file() {
        tracing::info!(
            model = model,
            tag = tag,
            path = %blob_path.display(),
            "Found model in local Ollama store"
        );
        Some(blob_path)
    } else {
        None
    }
}

/// Read the manifest JSON from the local Ollama store, if available.
fn read_local_manifest(model: &str, tag: &str) -> Option<serde_json::Value> {
    let models_dir = ollama_models_dir()?;
    let manifest_path = models_dir
        .join("manifests/registry.ollama.ai/library")
        .join(model)
        .join(tag);
    let bytes = std::fs::read(&manifest_path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Estimate quantization level from file size and parameter count.
fn estimate_quantization(size_bytes: u64, params: Option<&str>) -> String {
    let size_gb = size_bytes as f64 / 1_073_741_824.0;
    let param_b = match params {
        Some(p) => {
            let p = p.trim_end_matches(|c: char| c.is_ascii_alphabetic());
            p.parse::<f64>().unwrap_or(0.0)
        }
        None => return format!("{size_gb:.1}GB"),
    };
    if param_b == 0.0 {
        return format!("{size_gb:.1}GB");
    }
    // Rough: bytes_per_param = size / (params * 1e9)
    let bpp = size_bytes as f64 / (param_b * 1e9);
    match bpp {
        x if x < 0.6 => "Q4_0".to_string(),
        x if x < 0.7 => "Q4_K_M".to_string(),
        x if x < 0.85 => "Q5_K_M".to_string(),
        x if x < 1.1 => "Q8_0".to_string(),
        x if x < 2.5 => "fp16".to_string(),
        _ => "fp32".to_string(),
    }
}
