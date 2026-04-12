//! OCI registry transport.
//!
//! Pulls model artifacts from OCI-compliant container registries.
//! URI format: `oci://registry.example.com/org/repo:tag`
//!
//! Uses the OCI Distribution Spec v2 API:
//! - `GET /v2/<name>/manifests/<reference>`
//! - `GET /v2/<name>/blobs/<digest>`

use crate::error::HubError;
use crate::uri::ModelUri;
use super::ModelTransport;

/// Transport for OCI container registries.
pub struct OciTransport {
    client: reqwest::Client,
}

impl OciTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl ModelTransport for OciTransport {
    fn pull<'a>(
        &'a self,
        uri: &'a ModelUri,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, HubError>> + Send + 'a>,
    > {
        Box::pin(async move {
            // Parse "registry/org/repo:tag"
            let (name, reference) = parse_oci_ref(&uri.path)?;

            let manifest_url = format!("https://{name}/v2/{name}/manifests/{reference}");
            tracing::debug!(url = %manifest_url, "Fetching OCI manifest");

            let resp = self
                .client
                .get(&manifest_url)
                .header(
                    "Accept",
                    "application/vnd.oci.image.manifest.v1+json",
                )
                .send()
                .await?
                .error_for_status()
                .map_err(|e| {
                    HubError::Registry(format!("OCI manifest fetch failed: {e}"))
                })?;

            let manifest: serde_json::Value = resp.json().await?;

            // Find the model layer (largest blob)
            let layers = manifest["layers"]
                .as_array()
                .ok_or_else(|| HubError::Registry("no layers in OCI manifest".to_string()))?;

            let model_layer = layers
                .iter()
                .max_by_key(|l| l["size"].as_u64().unwrap_or(0))
                .ok_or_else(|| HubError::Registry("no model layer found".to_string()))?;

            let digest = model_layer["digest"]
                .as_str()
                .ok_or_else(|| HubError::Registry("layer missing digest".to_string()))?;

            // Fetch blob
            let registry = name
                .split('/')
                .next()
                .ok_or_else(|| HubError::InvalidUri("no registry host".to_string()))?;
            let repo = &name[registry.len() + 1..];
            let blob_url = format!("https://{registry}/v2/{repo}/blobs/{digest}");

            tracing::info!(name = %name, digest = digest, "Pulling OCI blob");

            let blob = self
                .client
                .get(&blob_url)
                .send()
                .await?
                .error_for_status()
                .map_err(|e| HubError::Download(format!("OCI blob fetch failed: {e}")))?
                .bytes()
                .await?;

            Ok(blob.to_vec())
        })
    }
}

/// Parse an OCI reference into (name, reference).
/// Input: `quay.io/org/repo:tag` → (`quay.io/org/repo`, `tag`)
fn parse_oci_ref(path: &str) -> Result<(String, String), HubError> {
    // Split off tag (default: latest)
    let (name, reference) = match path.rsplit_once(':') {
        Some((n, r)) if !n.is_empty() && !r.is_empty() => {
            (n.to_string(), r.to_string())
        }
        _ => (path.to_string(), "latest".to_string()),
    };

    // Must have at least registry/repo
    if !name.contains('/') {
        return Err(HubError::InvalidUri(format!(
            "OCI reference needs registry/repo: {path}"
        )));
    }

    Ok((name, reference))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_oci_ref_with_tag() {
        let (name, reference) =
            parse_oci_ref("quay.io/myorg/mymodel:v1").unwrap();
        assert_eq!(name, "quay.io/myorg/mymodel");
        assert_eq!(reference, "v1");
    }

    #[test]
    fn parse_oci_ref_default_tag() {
        let (name, reference) =
            parse_oci_ref("quay.io/myorg/mymodel").unwrap();
        assert_eq!(name, "quay.io/myorg/mymodel");
        assert_eq!(reference, "latest");
    }

    #[test]
    fn parse_oci_ref_no_slash_fails() {
        assert!(parse_oci_ref("justname").is_err());
    }
}
