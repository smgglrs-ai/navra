//! HuggingFace Hub transport.
//!
//! Pulls model files from the HuggingFace Hub API.
//! URI format: `hf://org/repo` or `hf://org/repo/specific-file.gguf`
//!
//! When no specific file is given, looks for the first GGUF file
//! in the repository.

use crate::error::HubError;
use crate::uri::ModelUri;
use super::ModelTransport;

const HF_API: &str = "https://huggingface.co";

/// Transport for the HuggingFace Hub.
pub struct HuggingFaceTransport {
    client: reqwest::Client,
    api_url: String,
    token: Option<String>,
}

impl HuggingFaceTransport {
    pub fn new() -> Self {
        let token = std::env::var("HF_TOKEN").ok();
        Self {
            client: reqwest::Client::new(),
            api_url: HF_API.to_string(),
            token,
        }
    }
}

impl ModelTransport for HuggingFaceTransport {
    fn pull<'a>(
        &'a self,
        uri: &'a ModelUri,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, HubError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let parts: Vec<&str> = uri.path.splitn(3, '/').collect();
            if parts.len() < 2 {
                return Err(HubError::InvalidUri(format!(
                    "HuggingFace URI needs org/repo: {}",
                    uri
                )));
            }

            let org = parts[0];
            let repo = parts[1];
            let specific_file = parts.get(2).copied();

            let filename = match specific_file {
                Some(f) => f.to_string(),
                None => {
                    // List repo files, find first GGUF
                    let api_url = format!(
                        "{}/api/models/{org}/{repo}",
                        self.api_url
                    );
                    let mut req = self.client.get(&api_url);
                    if let Some(token) = &self.token {
                        req = req.bearer_auth(token);
                    }

                    let resp = req
                        .send()
                        .await?
                        .error_for_status()
                        .map_err(|e| {
                            HubError::Registry(format!("HF API error: {e}"))
                        })?;

                    let info: serde_json::Value = resp.json().await?;
                    let siblings = info["siblings"]
                        .as_array()
                        .ok_or_else(|| {
                            HubError::Registry("no files in HF repo".to_string())
                        })?;

                    siblings
                        .iter()
                        .filter_map(|s| s["rfilename"].as_str())
                        .find(|name| name.ends_with(".gguf"))
                        .map(|s| s.to_string())
                        .ok_or_else(|| {
                            HubError::NotFound(format!(
                                "no GGUF file in {org}/{repo}"
                            ))
                        })?
                }
            };

            // Download the file
            let download_url = format!(
                "{}/{org}/{repo}/resolve/main/{filename}",
                self.api_url
            );
            tracing::info!(
                repo = format!("{org}/{repo}"),
                file = %filename,
                "Pulling from HuggingFace"
            );

            let mut req = self.client.get(&download_url);
            if let Some(token) = &self.token {
                req = req.bearer_auth(token);
            }

            let blob = req
                .send()
                .await?
                .error_for_status()
                .map_err(|e| HubError::Download(format!("HF download failed: {e}")))?
                .bytes()
                .await?;

            Ok(blob.to_vec())
        })
    }
}
