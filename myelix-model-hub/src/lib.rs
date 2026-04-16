//! Pull and cache AI models from OCI, HuggingFace, and Ollama registries.
//!
//! Models are addressed by URI:
//! - `ollama://granite-code:3b` — Ollama registry
//! - `hf://ibm-granite/granite-3.3-8b-instruct-GGUF` — HuggingFace Hub
//! - `oci://quay.io/myorg/mymodel:latest` — OCI container registry
//! - `file:///path/to/model.gguf` — local file (no pull needed)
//!
//! Models are cached in `$XDG_DATA_HOME/myelix/models/` (default
//! `~/.local/share/myelix/models/`), keyed by content hash.
//!
//! Each model has an associated **model card** (composite metadata)
//! stored in the `cards/` directory. Cards combine vendor metadata
//! (auto-populated on pull), operator-defined agentic capabilities
//! (from config), and runtime statistics (learned over time).

pub mod card;
mod cache;
mod error;
mod transport;
mod uri;

pub use cache::ModelCache;
pub use card::{AgenticMeta, ModelCard, RuntimeMeta, VendorMeta};
pub use error::HubError;
pub use transport::{ModelTransport, PullProgress};
pub use uri::{ModelUri, Registry};

#[cfg(test)]
mod tests;

use std::path::PathBuf;

/// Hub for pulling and caching models from registries.
pub struct ModelHub {
    cache: ModelCache,
    transports: TransportSet,
}

/// Registered transports, one per registry type.
struct TransportSet {
    ollama: transport::ollama::OllamaTransport,
    huggingface: transport::huggingface::HuggingFaceTransport,
    oci: transport::oci::OciTransport,
}

impl ModelHub {
    /// Create a hub with default cache directory.
    pub fn new() -> Result<Self, HubError> {
        let cache_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("~/.local/share"))
            .join("myelix")
            .join("models");
        Self::with_cache_dir(cache_dir)
    }

    /// Create a hub with a custom cache directory.
    pub fn with_cache_dir(cache_dir: PathBuf) -> Result<Self, HubError> {
        let cache = ModelCache::new(cache_dir)?;
        let transports = TransportSet {
            ollama: transport::ollama::OllamaTransport::new(),
            huggingface: transport::huggingface::HuggingFaceTransport::new(),
            oci: transport::oci::OciTransport::new(),
        };
        Ok(Self { cache, transports })
    }

    /// Pull a model to local cache, returning the path to the model file.
    ///
    /// If already cached (by content hash), returns immediately.
    /// On first pull, auto-populates a model card with vendor metadata.
    pub async fn pull(&self, uri: &ModelUri) -> Result<PathBuf, HubError> {
        // Local files need no pull
        if let Registry::File = uri.registry {
            let path = PathBuf::from(&uri.path);
            if path.exists() {
                // Ensure a card exists for local files too
                if self.cache.load_card(uri)?.is_none() {
                    let mut card = ModelCard::new(&uri.to_string());
                    card.vendor.source = Some("file".into());
                    self.cache.save_card(uri, &card)?;
                }
                return Ok(path);
            }
            return Err(HubError::NotFound(uri.to_string()));
        }

        // Check cache first
        if let Some(path) = self.cache.lookup(uri)? {
            tracing::info!(uri = %uri, path = %path.display(), "Model cache hit");
            return Ok(path);
        }

        // Pull via appropriate transport
        tracing::info!(uri = %uri, "Pulling model");
        let transport = self.transport_for(uri);

        let blob = transport.pull(uri).await?;
        let path = self.cache.store(uri, &blob)?;
        tracing::info!(uri = %uri, path = %path.display(), "Model cached");

        // Auto-populate model card from vendor metadata
        let vendor = match transport.metadata(uri).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(uri = %uri, error = %e, "Failed to fetch vendor metadata");
                VendorMeta {
                    source: Some(match uri.registry {
                        Registry::Ollama => "ollama",
                        Registry::HuggingFace => "huggingface",
                        Registry::Oci => "oci",
                        Registry::File => "file",
                    }.into()),
                    ..Default::default()
                }
            }
        };

        let mut card = ModelCard::new(&uri.to_string());
        card.vendor = vendor;
        self.cache.save_card(uri, &card)?;
        tracing::info!(uri = %uri, "Model card created");

        Ok(path)
    }

    /// Get the model card for a cached model.
    pub fn card(&self, uri: &ModelUri) -> Result<Option<ModelCard>, HubError> {
        self.cache.load_card(uri)
    }

    /// Update a model card (e.g. merge operator agentic metadata or record runtime stats).
    pub fn update_card(&self, uri: &ModelUri, card: &ModelCard) -> Result<(), HubError> {
        self.cache.save_card(uri, card)
    }

    /// Fetch vendor metadata from a registry without pulling the model.
    pub async fn fetch_metadata(&self, uri: &ModelUri) -> Result<VendorMeta, HubError> {
        if let Registry::File = uri.registry {
            return Ok(VendorMeta {
                source: Some("file".into()),
                ..Default::default()
            });
        }
        self.transport_for(uri).metadata(uri).await
    }

    /// List all cached models.
    pub fn list(&self) -> Result<Vec<CachedModel>, HubError> {
        self.cache.list()
    }

    /// List all model cards (including models not in cache, e.g. remote-only).
    pub fn list_cards(&self) -> Result<Vec<ModelCard>, HubError> {
        self.cache.list_cards()
    }

    /// Remove a model and its card from cache.
    pub fn remove(&self, uri: &ModelUri) -> Result<(), HubError> {
        self.cache.remove(uri)
    }

    /// Get the transport for a given URI.
    fn transport_for(&self, uri: &ModelUri) -> &dyn ModelTransport {
        match uri.registry {
            Registry::Ollama => &self.transports.ollama,
            Registry::HuggingFace => &self.transports.huggingface,
            Registry::Oci => &self.transports.oci,
            Registry::File => unreachable!("file URIs don't use transports"),
        }
    }
}

/// A model stored in the local cache.
#[derive(Debug, Clone)]
pub struct CachedModel {
    /// Original URI used to pull this model.
    pub uri: String,
    /// Path to the model file on disk.
    pub path: PathBuf,
    /// Size in bytes.
    pub size: u64,
}
