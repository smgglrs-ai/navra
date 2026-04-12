//! Ollama registry transport.
//!
//! Pulls GGUF models from the Ollama registry API.
//! API: `GET https://registry.ollama.ai/v2/library/<model>/manifests/<tag>`
//! then fetch blob layers.

use crate::error::HubError;
use crate::uri::ModelUri;
use super::ModelTransport;

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
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, HubError>> + Send + 'a>,
    > {
        Box::pin(async move {
            // Parse "model:tag" — default tag is "latest"
            let (model, tag) = match uri.path.split_once(':') {
                Some((m, t)) => (m, t),
                None => (uri.path.as_str(), "latest"),
            };

            // Fetch manifest
            let manifest_url = format!(
                "{}/v2/library/{model}/manifests/{tag}",
                self.registry_url
            );
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
            let blob_url = format!(
                "{}/v2/library/{model}/blobs/{digest}",
                self.registry_url
            );
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
}
