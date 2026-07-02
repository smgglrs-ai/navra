//! OCI registry transport.
//!
//! Pulls model artifacts from OCI-compliant container registries.
//! URI format: `oci://registry.example.com/org/repo:tag`
//!
//! Uses the OCI Distribution Spec v2 API:
//! - `GET /v2/<name>/manifests/<reference>`
//! - `GET /v2/<name>/blobs/<digest>`
//!
//! Model card support via OCI Referrers API (distribution-spec 1.1):
//! - `GET /v2/<name>/referrers/<digest>?artifactType=application/vnd.navra.model-card.v1+json`

use super::ModelTransport;
use crate::card::VendorMeta;
use crate::error::HubError;
use crate::uri::ModelUri;

/// Media type for navra model card side artifacts.
pub const MODEL_CARD_ARTIFACT_TYPE: &str = "application/vnd.navra.model-card.v1+json";

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
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, HubError>> + Send + 'a>>
    {
        Box::pin(async move {
            // Parse "registry/org/repo:tag"
            let (name, reference) = parse_oci_ref(&uri.path)?;

            let manifest_url = format!("https://{name}/v2/{name}/manifests/{reference}");
            tracing::debug!(url = %manifest_url, "Fetching OCI manifest");

            let resp = self
                .client
                .get(&manifest_url)
                .header("Accept", "application/vnd.oci.image.manifest.v1+json")
                .send()
                .await?
                .error_for_status()
                .map_err(|e| HubError::Registry(format!("OCI manifest fetch failed: {e}")))?;

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

    fn metadata<'a>(
        &'a self,
        uri: &'a ModelUri,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<VendorMeta, HubError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let (name, reference) = parse_oci_ref(&uri.path)?;

            let meta = VendorMeta {
                source: Some("oci".into()),
                ..Default::default()
            };

            // Fetch manifest to get digest for referrers query
            let manifest_url = format!("https://{name}/v2/{name}/manifests/{reference}");
            let resp = self
                .client
                .get(&manifest_url)
                .header("Accept", "application/vnd.oci.image.manifest.v1+json")
                .send()
                .await?
                .error_for_status()
                .map_err(|e| HubError::Registry(format!("OCI manifest fetch failed: {e}")))?;

            // Get the manifest digest from Docker-Content-Digest header
            let manifest_digest = resp
                .headers()
                .get("docker-content-digest")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            // Try OCI Referrers API for model card side artifact
            if let Some(digest) = manifest_digest {
                let registry = name.split('/').next().unwrap_or(&name);
                let repo = if name.len() > registry.len() + 1 {
                    &name[registry.len() + 1..]
                } else {
                    &name
                };
                let referrers_url = format!(
                    "https://{registry}/v2/{repo}/referrers/{digest}?artifactType={MODEL_CARD_ARTIFACT_TYPE}"
                );

                // Best-effort: not all registries support the Referrers API
                if let Ok(resp) = self.client.get(&referrers_url).send().await
                    && resp.status().is_success()
                    && let Ok(index) = resp.json::<serde_json::Value>().await
                    && let Some(manifests) = index["manifests"].as_array()
                    && let Some(card_ref) = manifests.first()
                    && let Some(card_digest) = card_ref["digest"].as_str()
                {
                    // Fetch the card blob
                    let card_url = format!("https://{registry}/v2/{repo}/blobs/{card_digest}");
                    if let Ok(card_resp) = self.client.get(&card_url).send().await
                        && let Ok(card_meta) = card_resp.json::<VendorMeta>().await
                    {
                        return Ok(card_meta);
                    }
                }
                tracing::debug!(uri = %uri, "No model card referrer found, returning basic metadata");
            }

            Ok(meta)
        })
    }
}

/// Parse an OCI reference into (name, reference).
/// Input: `quay.io/org/repo:tag` → (`quay.io/org/repo`, `tag`)
fn parse_oci_ref(path: &str) -> Result<(String, String), HubError> {
    // Split off tag (default: latest)
    let (name, reference) = match path.rsplit_once(':') {
        Some((n, r)) if !n.is_empty() && !r.is_empty() => (n.to_string(), r.to_string()),
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
        let (name, reference) = parse_oci_ref("quay.io/myorg/mymodel:v1").unwrap();
        assert_eq!(name, "quay.io/myorg/mymodel");
        assert_eq!(reference, "v1");
    }

    #[test]
    fn parse_oci_ref_default_tag() {
        let (name, reference) = parse_oci_ref("quay.io/myorg/mymodel").unwrap();
        assert_eq!(name, "quay.io/myorg/mymodel");
        assert_eq!(reference, "latest");
    }

    #[test]
    fn parse_oci_ref_no_slash_fails() {
        assert!(parse_oci_ref("justname").is_err());
    }
}
