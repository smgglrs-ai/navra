//! HuggingFace Hub transport.
//!
//! Pulls model files from the HuggingFace Hub API.
//! URI format: `hf://org/repo` or `hf://org/repo/specific-file.gguf`
//!
//! When no specific file is given, looks for the first GGUF file
//! in the repository.
//!
//! Metadata extraction: parses the HuggingFace model info API for
//! pipeline_tag, tags, license, languages, and model card content.
//!
//! Downloads are streamed to disk in 64KB chunks to avoid OOM on
//! multi-GB model files.

use super::{ModelTransport, PullProgress};
use crate::card::VendorMeta;
use crate::error::HubError;
use crate::uri::ModelUri;
use futures_util::StreamExt;
use std::path::Path;
use tokio::io::AsyncWriteExt;

const HF_API: &str = "https://huggingface.co";

/// Chunk size for streaming downloads (64 KB).
const CHUNK_SIZE: usize = 64 * 1024;

/// Transport for the HuggingFace Hub.
pub struct HuggingFaceTransport {
    client: reqwest::Client,
    api_url: String,
    token: Option<String>,
}

impl HuggingFaceTransport {
    /// Create a new transport using the default HuggingFace API URL.
    pub fn new() -> Self {
        let token = std::env::var("HF_TOKEN").ok();
        Self {
            client: reqwest::Client::new(),
            api_url: HF_API.to_string(),
            token,
        }
    }

    /// Create a transport pointing at a custom API URL (for testing).
    #[cfg(test)]
    fn with_api_url(api_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_url: api_url.to_string(),
            token: None,
        }
    }

    /// Resolve which file to download from a HuggingFace repo.
    ///
    /// If the URI includes a specific file path, returns it directly.
    /// Otherwise queries the HF API and returns the first GGUF file.
    async fn resolve_filename(
        &self,
        org: &str,
        repo: &str,
        specific_file: Option<&str>,
    ) -> Result<String, HubError> {
        match specific_file {
            Some(f) => Ok(f.to_string()),
            None => {
                let api_url = format!("{}/api/models/{org}/{repo}", self.api_url);
                let mut req = self.client.get(&api_url);
                if let Some(token) = &self.token {
                    req = req.bearer_auth(token);
                }

                let resp = req
                    .send()
                    .await?
                    .error_for_status()
                    .map_err(|e| HubError::Registry(format!("HF API error: {e}")))?;

                let info: serde_json::Value = resp.json().await?;
                let siblings = info["siblings"]
                    .as_array()
                    .ok_or_else(|| HubError::Registry("no files in HF repo".to_string()))?;

                siblings
                    .iter()
                    .filter_map(|s| s["rfilename"].as_str())
                    .find(|name| name.ends_with(".gguf"))
                    .map(|s| s.to_string())
                    .ok_or_else(|| HubError::NotFound(format!("no GGUF file in {org}/{repo}")))
            }
        }
    }

    /// Parse org/repo (and optional file) from a URI path.
    fn parse_parts(uri: &ModelUri) -> Result<(&str, &str, Option<&str>), HubError> {
        let parts: Vec<&str> = uri.path.splitn(3, '/').collect();
        if parts.len() < 2 {
            return Err(HubError::InvalidUri(format!(
                "HuggingFace URI needs org/repo: {}",
                uri
            )));
        }
        Ok((parts[0], parts[1], parts.get(2).copied()))
    }
}

impl ModelTransport for HuggingFaceTransport {
    fn pull<'a>(
        &'a self,
        uri: &'a ModelUri,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, HubError>> + Send + 'a>>
    {
        Box::pin(async move {
            // Stream to a temp file, then read back.
            // This keeps the in-memory pull() API but avoids holding
            // the entire response in reqwest's buffer.
            let tmp = tempfile::NamedTempFile::new().map_err(|e| HubError::Io(e))?;
            let tmp_path = tmp.path().to_path_buf();

            self.pull_to_file(uri, &tmp_path, None).await?;

            let data = tokio::fs::read(&tmp_path).await?;
            Ok(data)
        })
    }

    fn pull_to_file<'a>(
        &'a self,
        uri: &'a ModelUri,
        dest: &'a Path,
        on_progress: Option<&'a (dyn Fn(PullProgress) + Send + Sync)>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HubError>> + Send + 'a>>
    {
        Box::pin(async move {
            let (org, repo, specific_file) = Self::parse_parts(uri)?;
            let filename = self.resolve_filename(org, repo, specific_file).await?;

            // Ensure parent directory exists
            if let Some(parent) = dest.parent() {
                if !parent.exists() {
                    return Err(HubError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("parent directory does not exist: {}", parent.display()),
                    )));
                }
            }

            let download_url = format!("{}/{org}/{repo}/resolve/main/{filename}", self.api_url);
            tracing::info!(
                repo = format!("{org}/{repo}"),
                file = %filename,
                "Pulling from HuggingFace (streaming)"
            );

            let mut req = self.client.get(&download_url);
            if let Some(token) = &self.token {
                req = req.bearer_auth(token);
            }

            let resp = req
                .send()
                .await?
                .error_for_status()
                .map_err(|e| HubError::Download(format!("HF download failed: {e}")))?;

            // Read Content-Length for progress reporting
            let total_size = resp.content_length();

            // Stream response body to disk in chunks
            let file = tokio::fs::File::create(dest).await?;
            let mut writer = tokio::io::BufWriter::with_capacity(CHUNK_SIZE, file);
            let mut stream = resp.bytes_stream();
            let mut downloaded: u64 = 0;

            let result: Result<(), HubError> = async {
                while let Some(chunk_result) = stream.next().await {
                    let chunk = chunk_result?;
                    writer.write_all(&chunk).await?;
                    downloaded += chunk.len() as u64;

                    if let Some(cb) = on_progress {
                        cb(PullProgress {
                            downloaded,
                            total: total_size,
                        });
                    }
                }
                writer.flush().await?;
                writer.shutdown().await?;
                Ok(())
            }
            .await;

            // Clean up partial file on error
            if let Err(ref e) = result {
                tracing::warn!(
                    dest = %dest.display(),
                    error = %e,
                    "Download failed, removing partial file"
                );
                let _ = tokio::fs::remove_file(dest).await;
            }

            result
        })
    }

    fn metadata<'a>(
        &'a self,
        uri: &'a ModelUri,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<VendorMeta, HubError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let (org, repo, _) = Self::parse_parts(uri)?;

            let api_url = format!("{}/api/models/{org}/{repo}", self.api_url);
            let mut req = self.client.get(&api_url);
            if let Some(token) = &self.token {
                req = req.bearer_auth(token);
            }

            let resp = req
                .send()
                .await?
                .error_for_status()
                .map_err(|e| HubError::Registry(format!("HF API error: {e}")))?;

            let info: serde_json::Value = resp.json().await?;

            let mut meta = VendorMeta {
                source: Some("huggingface".into()),
                ..Default::default()
            };

            // Pipeline tag -> tasks
            if let Some(tag) = info["pipeline_tag"].as_str() {
                meta.tasks = vec![tag.to_string()];
            }

            // Tags array may contain model family, quantization, etc.
            if let Some(tags) = info["tags"].as_array() {
                for tag in tags {
                    if let Some(t) = tag.as_str() {
                        if t.starts_with("license:") {
                            meta.license = Some(t.strip_prefix("license:").unwrap().to_string());
                        } else if t == "gguf" || t == "safetensors" || t == "onnx" {
                            meta.format = Some(t.to_string());
                        }
                    }
                }
            }

            // License (direct field)
            if meta.license.is_none()
                && let Some(license) = info["cardData"]["license"].as_str()
            {
                meta.license = Some(license.to_string());
            }

            // Languages
            if let Some(langs) = info["cardData"]["language"].as_array() {
                meta.languages = langs
                    .iter()
                    .filter_map(|l| l.as_str().map(|s| s.to_string()))
                    .collect();
            }

            // Model family from org/repo name
            let name_lower = repo.to_lowercase();
            for family in [
                "granite", "llama", "mistral", "qwen", "gemma", "phi", "falcon",
            ] {
                if name_lower.contains(family) {
                    meta.family = Some(family.to_string());
                    break;
                }
            }

            // Parameter count from repo name (e.g. "granite-3.3-8b-instruct-GGUF")
            for part in repo.split('-') {
                let lower = part.to_lowercase();
                if lower.ends_with('b') {
                    let num = &lower[..lower.len() - 1];
                    if num.parse::<f64>().is_ok() {
                        meta.parameters = Some(part.to_uppercase());
                        break;
                    }
                }
            }

            Ok(meta)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper: create a transport pointing at a wiremock server.
    fn transport_for(server: &MockServer) -> HuggingFaceTransport {
        HuggingFaceTransport::with_api_url(&server.uri())
    }

    /// Helper: build a URI for testing with a specific file.
    fn test_uri(file: &str) -> ModelUri {
        ModelUri::parse(&format!("hf://testorg/testrepo/{file}")).unwrap()
    }

    /// Helper: build a URI without a specific file (triggers GGUF lookup).
    fn test_uri_bare() -> ModelUri {
        ModelUri::parse("hf://testorg/testrepo").unwrap()
    }

    // ── Streaming download tests ──────────────────────────────────

    #[tokio::test]
    async fn pull_streams_to_file_small() {
        let server = MockServer::start().await;
        let body = vec![0xABu8; 1024]; // 1KB

        Mock::given(method("GET"))
            .and(path("/testorg/testrepo/resolve/main/model.gguf"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let uri = test_uri("model.gguf");
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("model.gguf");

        transport.pull_to_file(&uri, &dest, None).await.unwrap();

        let written = tokio::fs::read(&dest).await.unwrap();
        assert_eq!(written, body);
    }

    #[tokio::test]
    async fn pull_streams_to_file_progress() {
        let server = MockServer::start().await;
        let body = vec![0x42u8; 4096];

        Mock::given(method("GET"))
            .and(path("/testorg/testrepo/resolve/main/model.gguf"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-length", "4096")
                    .set_body_bytes(body.clone()),
            )
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let uri = test_uri("model.gguf");
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("model.gguf");

        let progress_log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log_clone = progress_log.clone();
        let cb = move |p: PullProgress| {
            log_clone.lock().unwrap().push(p);
        };

        transport
            .pull_to_file(&uri, &dest, Some(&cb))
            .await
            .unwrap();

        let log = progress_log.lock().unwrap();
        assert!(!log.is_empty(), "progress callback should fire");
        // Last progress entry should have downloaded == total body size
        let last = log.last().unwrap();
        assert_eq!(last.downloaded, 4096);
        assert_eq!(last.total, Some(4096));
    }

    #[tokio::test]
    async fn pull_to_nonexistent_dir_fails() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/testorg/testrepo/resolve/main/model.gguf"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"data"))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let uri = test_uri("model.gguf");
        let dest = std::path::PathBuf::from("/tmp/nonexistent_navra_test_dir_xyz/model.gguf");

        let result = transport.pull_to_file(&uri, &dest, None).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, HubError::Io(_)),
            "expected Io error, got: {err}"
        );
    }

    #[tokio::test]
    async fn pull_handles_http_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/testorg/testrepo/resolve/main/model.gguf"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let uri = test_uri("model.gguf");
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("model.gguf");

        let result = transport.pull_to_file(&uri, &dest, None).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, HubError::Download(_)),
            "expected Download error, got: {err}"
        );
        // Partial file should not exist
        assert!(!dest.exists(), "partial file should be cleaned up");
    }

    #[tokio::test]
    async fn pull_handles_network_disconnect() {
        let server = MockServer::start().await;

        // Respond with a content-length header but drop the connection
        // after sending only part of the body.
        Mock::given(method("GET"))
            .and(path("/testorg/testrepo/resolve/main/model.gguf"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-length", "1048576") // claim 1MB
                    .set_body_bytes(vec![0u8; 128]), // send only 128 bytes
            )
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let uri = test_uri("model.gguf");
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("model.gguf");

        // The stream will end prematurely. The file will be written
        // but will be smaller than expected. This tests that the
        // write completes without panic. In a real scenario the
        // TCP connection would reset, producing an error. With
        // wiremock the short body is delivered cleanly, so we just
        // verify the file exists and is short.
        let result = transport.pull_to_file(&uri, &dest, None).await;
        // wiremock delivers the short body without error, so the
        // write succeeds but the file is only 128 bytes
        if result.is_ok() {
            let meta = tokio::fs::metadata(&dest).await.unwrap();
            assert_eq!(meta.len(), 128, "file should contain only partial data");
        } else {
            // If it did error (real disconnect), partial file must be cleaned up
            assert!(!dest.exists(), "partial file should be cleaned up on error");
        }
    }

    // ── Metadata tests ────────────────────────────────────────────

    fn hf_model_info_json(overrides: serde_json::Value) -> serde_json::Value {
        let mut base = serde_json::json!({
            "modelId": "testorg/testrepo",
            "tags": [],
            "siblings": [{"rfilename": "model.gguf"}],
        });
        if let serde_json::Value::Object(map) = overrides {
            for (k, v) in map {
                base[k] = v;
            }
        }
        base
    }

    #[tokio::test]
    async fn metadata_parses_pipeline_tag() {
        let server = MockServer::start().await;

        let info = hf_model_info_json(serde_json::json!({
            "pipeline_tag": "text-generation"
        }));

        Mock::given(method("GET"))
            .and(path("/api/models/testorg/testrepo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&info))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let uri = test_uri_bare();
        let meta = transport.metadata(&uri).await.unwrap();

        assert_eq!(meta.tasks, vec!["text-generation"]);
        assert_eq!(meta.source, Some("huggingface".into()));
    }

    #[tokio::test]
    async fn metadata_parses_license_from_tags() {
        let server = MockServer::start().await;

        let info = hf_model_info_json(serde_json::json!({
            "tags": ["gguf", "license:apache-2.0"]
        }));

        Mock::given(method("GET"))
            .and(path("/api/models/testorg/testrepo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&info))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let uri = test_uri_bare();
        let meta = transport.metadata(&uri).await.unwrap();

        assert_eq!(meta.license, Some("apache-2.0".into()));
        assert_eq!(meta.format, Some("gguf".into()));
    }

    #[tokio::test]
    async fn metadata_parses_license_from_card_data() {
        let server = MockServer::start().await;

        // No license: tag, but cardData.license is set
        let info = hf_model_info_json(serde_json::json!({
            "tags": ["gguf"],
            "cardData": {
                "license": "mit"
            }
        }));

        Mock::given(method("GET"))
            .and(path("/api/models/testorg/testrepo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&info))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let uri = test_uri_bare();
        let meta = transport.metadata(&uri).await.unwrap();

        assert_eq!(meta.license, Some("mit".into()));
    }

    #[tokio::test]
    async fn metadata_detects_model_family() {
        let server = MockServer::start().await;

        let info = hf_model_info_json(serde_json::json!({}));

        Mock::given(method("GET"))
            .and(path("/api/models/ibm-granite/granite-3.3-8b"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&info))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let uri = ModelUri::parse("hf://ibm-granite/granite-3.3-8b").unwrap();
        let meta = transport.metadata(&uri).await.unwrap();

        assert_eq!(meta.family, Some("granite".into()));
    }

    #[tokio::test]
    async fn metadata_extracts_parameter_count() {
        let server = MockServer::start().await;

        let info = hf_model_info_json(serde_json::json!({}));

        Mock::given(method("GET"))
            .and(path("/api/models/ibm-granite/granite-3.3-8b"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&info))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let uri = ModelUri::parse("hf://ibm-granite/granite-3.3-8b").unwrap();
        let meta = transport.metadata(&uri).await.unwrap();

        assert_eq!(meta.parameters, Some("8B".into()));
    }
}
