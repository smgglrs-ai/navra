//! Model transport trait and registry-specific implementations.

pub mod huggingface;
pub mod oci;
pub mod ollama;

use crate::error::HubError;
use crate::uri::ModelUri;

/// Progress callback for model downloads.
#[derive(Debug, Clone)]
pub struct PullProgress {
    /// Bytes downloaded so far.
    pub downloaded: u64,
    /// Total bytes (if known).
    pub total: Option<u64>,
}

/// Trait for pulling model data from a registry.
pub trait ModelTransport: Send + Sync {
    /// Pull model bytes from the registry.
    fn pull<'a>(
        &'a self,
        uri: &'a ModelUri,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, HubError>> + Send + 'a>,
    >;
}
