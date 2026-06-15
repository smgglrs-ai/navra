use super::manifest::{AgentManifest, AGENT_BUNDLE_ARTIFACT_TYPE};

pub async fn fetch_agent_manifest(
    client: &reqwest::Client,
    oci_ref: &str,
) -> anyhow::Result<Option<AgentManifest>> {
    let (name, reference) = parse_oci_ref(oci_ref)?;

    let manifest_url = format!("https://{name}/v2/{name}/manifests/{reference}");
    tracing::debug!(url = %manifest_url, "Fetching OCI manifest for agent bundle");

    let resp = client
        .get(&manifest_url)
        .header("Accept", "application/vnd.oci.image.manifest.v1+json")
        .send()
        .await?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("OCI manifest fetch failed: {e}"))?;

    let manifest_digest = resp
        .headers()
        .get("docker-content-digest")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let Some(digest) = manifest_digest else {
        tracing::debug!("No docker-content-digest header, cannot query referrers");
        return Ok(None);
    };

    let registry = name
        .split('/')
        .next()
        .ok_or_else(|| anyhow::anyhow!("no registry host in OCI ref"))?;
    let repo = &name[registry.len() + 1..];
    let referrers_url = format!(
        "https://{registry}/v2/{repo}/referrers/{digest}?artifactType={AGENT_BUNDLE_ARTIFACT_TYPE}"
    );

    let resp = match client.get(&referrers_url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => {
            tracing::debug!(
                oci_ref,
                "Referrers API not available or no agent bundle artifact"
            );
            return Ok(None);
        }
    };

    let index: serde_json::Value = resp.json().await?;
    let Some(manifests) = index["manifests"].as_array() else {
        return Ok(None);
    };
    let Some(bundle_ref) = manifests.first() else {
        return Ok(None);
    };
    let Some(bundle_digest) = bundle_ref["digest"].as_str() else {
        return Ok(None);
    };

    let bundle_url = format!("https://{registry}/v2/{repo}/blobs/{bundle_digest}");
    let bundle_resp = client
        .get(&bundle_url)
        .send()
        .await?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("agent bundle artifact fetch failed: {e}"))?;

    let manifest: AgentManifest = bundle_resp.json().await?;
    Ok(Some(manifest))
}

fn parse_oci_ref(path: &str) -> anyhow::Result<(String, String)> {
    let path = path.strip_prefix("oci://").unwrap_or(path);

    let (name, reference) = match path.rsplit_once(':') {
        Some((n, r)) if !n.is_empty() && !r.is_empty() => (n.to_string(), r.to_string()),
        _ => (path.to_string(), "latest".to_string()),
    };

    if !name.contains('/') {
        anyhow::bail!("OCI reference needs registry/repo: {path}");
    }

    Ok((name, reference))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_oci_ref_with_tag() {
        let (name, reference) = parse_oci_ref("quay.io/navra/agent:v1").unwrap();
        assert_eq!(name, "quay.io/navra/agent");
        assert_eq!(reference, "v1");
    }

    #[test]
    fn parse_oci_ref_default_tag() {
        let (name, reference) = parse_oci_ref("quay.io/navra/agent").unwrap();
        assert_eq!(name, "quay.io/navra/agent");
        assert_eq!(reference, "latest");
    }

    #[test]
    fn parse_oci_ref_strips_scheme() {
        let (name, reference) = parse_oci_ref("oci://quay.io/navra/agent:v2").unwrap();
        assert_eq!(name, "quay.io/navra/agent");
        assert_eq!(reference, "v2");
    }

    #[test]
    fn parse_oci_ref_no_slash_fails() {
        assert!(parse_oci_ref("justname").is_err());
    }
}
