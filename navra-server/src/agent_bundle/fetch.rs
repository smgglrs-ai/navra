use super::manifest::{AGENT_BUNDLE_ARTIFACT_TYPE, AgentManifest};

/// Fetch an agent bundle manifest from an OCI registry.
///
/// Discovery follows the OCI Distribution spec:
/// 1. Resolve the tag to a manifest digest.
/// 2. Query the Referrers API for artifacts with the navra
///    agent-bundle artifact type attached to that digest.
/// 3. Fetch the referrer's artifact manifest and locate the JSON
///    layer holding the bundle.
/// 4. Fetch that layer blob and parse it.
///
/// Anonymous Bearer token handling: registries such as ghcr.io
/// require a token even for public pulls. A 401 with a
/// `WWW-Authenticate: Bearer` challenge triggers the anonymous
/// token dance (realm + service + pull scope) and a retry.
pub async fn fetch_agent_manifest(
    client: &reqwest::Client,
    oci_ref: &str,
) -> anyhow::Result<Option<AgentManifest>> {
    let (name, reference) = parse_oci_ref(oci_ref)?;
    let (registry, repo) = split_registry_repo(&name)?;
    let mut auth = RegistryAuth::Anonymous;

    // 1. Resolve the tag to a manifest digest.
    let tag_manifest_url = manifest_url(&registry, &repo, &reference);
    let resp = match authed_get(client, &mut auth, &repo, &tag_manifest_url).await? {
        Resp::Ok(r) => r,
        Resp::NotFound => return Ok(None),
    };
    let resp = resp
        .error_for_status()
        .map_err(registry_err("OCI manifest fetch"))?;

    let Some(digest) = header_string(resp.headers(), "docker-content-digest") else {
        tracing::debug!("no docker-content-digest header, cannot query referrers");
        return Ok(None);
    };
    let tag_manifest: serde_json::Value = resp.json().await?;

    // 2a. Direct artifact: the tag itself points at a navra bundle
    // artifact (oras push --artifact-type). No referrer dance needed.
    if tag_manifest["artifactType"].as_str() == Some(AGENT_BUNDLE_ARTIFACT_TYPE)
        && let Some(layer_digest) = bundle_layer_digest(&tag_manifest)
    {
        let blob = blob_url(&registry, &repo, &layer_digest);
        let resp = match authed_get(client, &mut auth, &repo, &blob).await? {
            Resp::Ok(r) => r,
            Resp::NotFound => return Ok(None),
        };
        let resp = resp
            .error_for_status()
            .map_err(registry_err("agent bundle layer fetch"))?;
        let manifest: AgentManifest = resp.json().await?;
        return Ok(Some(manifest));
    }

    // 2b. Attached artifact: query the Referrers API for navra
    // bundle artifacts attached to the tag's digest.
    let referrers_url = referrers_url(&registry, &repo, &digest);
    let resp = match authed_get(client, &mut auth, &repo, &referrers_url).await? {
        Resp::Ok(r) => r,
        Resp::NotFound => {
            tracing::debug!(
                oci_ref,
                "referrers API unavailable or no agent bundle artifact"
            );
            return Ok(None);
        }
    };
    let resp = resp
        .error_for_status()
        .map_err(registry_err("referrers query"))?;

    let index: serde_json::Value = resp.json().await?;
    let Some(artifact_digest) = first_referrer_digest(&index) else {
        return Ok(None);
    };

    // 3. Fetch the artifact manifest and locate the bundle layer.
    let artifact_url = manifest_url(&registry, &repo, &artifact_digest);
    let resp = match authed_get(client, &mut auth, &repo, &artifact_url).await? {
        Resp::Ok(r) => r,
        Resp::NotFound => return Ok(None),
    };
    let resp = resp
        .error_for_status()
        .map_err(registry_err("bundle artifact fetch"))?;

    let artifact: serde_json::Value = resp.json().await?;
    let Some(layer_digest) = bundle_layer_digest(&artifact) else {
        anyhow::bail!("agent bundle artifact has no JSON layer");
    };

    // 4. Fetch the layer blob — the AgentManifest itself.
    let blob_url = blob_url(&registry, &repo, &layer_digest);
    let resp = match authed_get(client, &mut auth, &repo, &blob_url).await? {
        Resp::Ok(r) => r,
        Resp::NotFound => return Ok(None),
    };
    let resp = resp
        .error_for_status()
        .map_err(registry_err("agent bundle layer fetch"))?;

    let manifest: AgentManifest = resp.json().await?;
    Ok(Some(manifest))
}

// --- Pure helpers (unit-tested) ---

/// Split `registry/owner/repo` into (`registry`, `owner/repo`).
pub fn split_registry_repo(name: &str) -> anyhow::Result<(String, String)> {
    let (registry, repo) = name
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("OCI reference needs registry/repo: {name}"))?;
    anyhow::ensure!(!repo.is_empty(), "OCI reference has empty repo: {name}");
    Ok((registry.to_string(), repo.to_string()))
}

pub fn manifest_url(registry: &str, repo: &str, reference: &str) -> String {
    format!("https://{registry}/v2/{repo}/manifests/{reference}")
}

pub fn referrers_url(registry: &str, repo: &str, digest: &str) -> String {
    format!(
        "https://{registry}/v2/{repo}/referrers/{digest}?artifactType={AGENT_BUNDLE_ARTIFACT_TYPE}"
    )
}

pub fn blob_url(registry: &str, repo: &str, digest: &str) -> String {
    format!("https://{registry}/v2/{repo}/blobs/{digest}")
}

/// Digest of the first referrer in a Referrers API response.
pub fn first_referrer_digest(index: &serde_json::Value) -> Option<String> {
    index
        .get("manifests")?
        .as_array()?
        .first()?
        .get("digest")?
        .as_str()
        .map(String::from)
}

/// Digest of the layer holding the bundle JSON in an artifact
/// manifest: the first `application/json` layer, falling back to
/// the first layer.
pub fn bundle_layer_digest(artifact: &serde_json::Value) -> Option<String> {
    let layers = artifact["layers"].as_array()?;
    layers
        .iter()
        .find(|l| l["mediaType"].as_str() == Some("application/json"))
        .or_else(|| layers.first())?
        .get("digest")?
        .as_str()
        .map(String::from)
}

/// Parse a `WWW-Authenticate: Bearer realm="...",service="..."`
/// challenge into (realm, service).
pub fn parse_bearer_challenge(header: &str) -> Option<(String, String)> {
    let rest = header.strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = None;
    for part in rest.split(',') {
        let (key, value) = part.split_once('=')?;
        let value = value.trim_matches('"');
        match key.trim() {
            "realm" => realm = Some(value.to_string()),
            "service" => service = Some(value.to_string()),
            _ => {}
        }
    }
    Some((realm?, service.unwrap_or_default()))
}

/// Anonymous token URL for the pull scope of a repository.
pub fn token_url(realm: &str, service: &str, repo: &str) -> String {
    format!("{realm}?service={service}&scope=repository:{repo}:pull")
}

pub fn parse_oci_ref(path: &str) -> anyhow::Result<(String, String)> {
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

// --- Authenticated GET with anonymous Bearer retry ---

#[derive(Default)]
enum RegistryAuth {
    #[default]
    Anonymous,
    Token(String),
}

enum Resp {
    Ok(reqwest::Response),
    NotFound,
}

/// GET a registry URL, performing the anonymous Bearer token dance
/// on a 401 challenge and retrying once.
async fn authed_get(
    client: &reqwest::Client,
    auth: &mut RegistryAuth,
    repo: &str,
    url: &str,
) -> anyhow::Result<Resp> {
    let mut req = client
        .get(url)
        .header("Accept", "application/vnd.oci.image.manifest.v1+json");
    if let RegistryAuth::Token(token) = auth {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.map_err(registry_err("registry request"))?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        && let Some(challenge) = header_string(resp.headers(), "www-authenticate")
        && let RegistryAuth::Anonymous = auth
        && let Some((realm, service)) = parse_bearer_challenge(&challenge)
    {
        let token = fetch_anon_token(client, &token_url(&realm, &service, repo)).await?;
        *auth = RegistryAuth::Token(token);

        let mut req = client
            .get(url)
            .header("Accept", "application/vnd.oci.image.manifest.v1+json");
        if let RegistryAuth::Token(token) = auth {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await.map_err(registry_err("registry request"))?;
        return classify(resp);
    }

    classify(resp)
}

async fn fetch_anon_token(client: &reqwest::Client, token_url: &str) -> anyhow::Result<String> {
    #[derive(serde::Deserialize)]
    struct TokenResponse {
        token: Option<String>,
        #[serde(default)]
        access_token: Option<String>,
    }
    let resp = client.get(token_url).send().await?;
    let body: TokenResponse = resp.json().await?;
    body.token
        .or(body.access_token)
        .ok_or_else(|| anyhow::anyhow!("registry token endpoint returned no token"))
}

fn classify(resp: reqwest::Response) -> anyhow::Result<Resp> {
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        Ok(Resp::NotFound)
    } else {
        Ok(Resp::Ok(resp))
    }
}

fn header_string(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn registry_err(context: &'static str) -> impl Fn(reqwest::Error) -> anyhow::Error {
    move |e| anyhow::anyhow!("{context} failed: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_oci_ref_with_tag() {
        let (name, reference) = parse_oci_ref("ghcr.io/owner/agent:v1").unwrap();
        assert_eq!(name, "ghcr.io/owner/agent");
        assert_eq!(reference, "v1");
    }

    #[test]
    fn parse_oci_ref_default_tag() {
        let (name, reference) = parse_oci_ref("ghcr.io/owner/agent").unwrap();
        assert_eq!(name, "ghcr.io/owner/agent");
        assert_eq!(reference, "latest");
    }

    #[test]
    fn parse_oci_ref_strips_scheme() {
        let (name, reference) = parse_oci_ref("oci://ghcr.io/owner/agent:v2").unwrap();
        assert_eq!(name, "ghcr.io/owner/agent");
        assert_eq!(reference, "v2");
    }

    #[test]
    fn parse_oci_ref_no_slash_fails() {
        assert!(parse_oci_ref("justname").is_err());
    }

    #[test]
    fn split_registry_repo_ghcr_style() {
        let (registry, repo) = split_registry_repo("ghcr.io/smgglrs-ai/researcher").unwrap();
        assert_eq!(registry, "ghcr.io");
        assert_eq!(repo, "smgglrs-ai/researcher");
    }

    #[test]
    fn manifest_url_uses_registry_host_once() {
        // Regression: the URL must not embed the full registry/repo
        // as the host.
        let url = manifest_url("ghcr.io", "owner/agent", "latest");
        assert_eq!(url, "https://ghcr.io/v2/owner/agent/manifests/latest");
    }

    #[test]
    fn referrers_url_includes_artifact_type() {
        let url = referrers_url("ghcr.io", "owner/agent", "sha256:abc");
        assert_eq!(
            url,
            "https://ghcr.io/v2/owner/agent/referrers/sha256:abc\
             ?artifactType=application/vnd.navra.agent-bundle.v1+json"
        );
    }

    #[test]
    fn blob_url_shape() {
        assert_eq!(
            blob_url("ghcr.io", "owner/agent", "sha256:def"),
            "https://ghcr.io/v2/owner/agent/blobs/sha256:def"
        );
    }

    #[test]
    fn first_referrer_digest_extracts() {
        let index = json!({"manifests": [
            {"digest": "sha256:aaa", "mediaType": "application/vnd.oci.image.manifest.v1+json"},
            {"digest": "sha256:bbb"}
        ]});
        assert_eq!(first_referrer_digest(&index).as_deref(), Some("sha256:aaa"));
        assert_eq!(first_referrer_digest(&json!({})), None);
    }

    #[test]
    fn bundle_layer_prefers_json_layer() {
        let artifact = json!({"layers": [
            {"mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:empty"},
            {"mediaType": "application/json", "digest": "sha256:bundle"}
        ]});
        assert_eq!(
            bundle_layer_digest(&artifact).as_deref(),
            Some("sha256:bundle")
        );
    }

    #[test]
    fn bundle_layer_falls_back_to_first() {
        let artifact = json!({"layers": [
            {"mediaType": "application/octet-stream", "digest": "sha256:only"}
        ]});
        assert_eq!(
            bundle_layer_digest(&artifact).as_deref(),
            Some("sha256:only")
        );
    }

    #[test]
    fn parse_bearer_challenge_ghcr_shape() {
        let (realm, service) =
            parse_bearer_challenge("Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\"")
                .unwrap();
        assert_eq!(realm, "https://ghcr.io/token");
        assert_eq!(service, "ghcr.io");
    }

    #[test]
    fn parse_bearer_challenge_rejects_non_bearer() {
        assert!(parse_bearer_challenge("Basic realm=\"x\"").is_none());
    }

    #[test]
    fn token_url_carries_pull_scope() {
        assert_eq!(
            token_url("https://ghcr.io/token", "ghcr.io", "owner/agent"),
            "https://ghcr.io/token?service=ghcr.io&scope=repository:owner/agent:pull"
        );
    }

    #[test]
    fn direct_artifact_detection() {
        // A tag manifest pushed with --artifact-type matching the
        // bundle type is a direct artifact; its JSON layer holds
        // the bundle.
        let manifest = json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": AGENT_BUNDLE_ARTIFACT_TYPE,
            "layers": [{"mediaType": "application/json", "digest": "sha256:bundle"}]
        });
        assert_eq!(
            manifest["artifactType"].as_str(),
            Some(AGENT_BUNDLE_ARTIFACT_TYPE)
        );
        assert_eq!(
            bundle_layer_digest(&manifest).as_deref(),
            Some("sha256:bundle")
        );

        // A plain image manifest has no artifactType and no JSON
        // layer path.
        let image = json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json"},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]
        });
        assert_ne!(
            image["artifactType"].as_str(),
            Some(AGENT_BUNDLE_ARTIFACT_TYPE)
        );
    }
}
