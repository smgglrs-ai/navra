//! OpenAI-compatible API backend for external model inference.
//!
//! Connects to vLLM, ollama, or any OpenAI-compatible API server.
//! Supports generate, embed, and classify operations.

use mcpd_core::models::{
    ClassifyLabel, ClassifyRequest, ClassifyResponse, EmbedRequest, EmbedResponse,
    GenerateRequest, GenerateResponse, Locality, ModelBackend, ModelError,
};

/// External model backend using OpenAI-compatible HTTP APIs.
pub struct OpenAiBackend {
    client: reqwest::Client,
    base_url: String,
    model: String,
    api_key: Option<String>,
    locality: Locality,
}

impl OpenAiBackend {
    /// Create a new OpenAI-compatible backend.
    pub fn new(
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: Option<String>,
        locality: Locality,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            model: model.into(),
            api_key,
            locality,
        }
    }

    /// Returns the locality of this backend.
    pub fn locality(&self) -> &Locality {
        &self.locality
    }

    fn auth_header(&self) -> Option<(&str, String)> {
        self.api_key
            .as_ref()
            .map(|key| ("Authorization", format!("Bearer {key}")))
    }
}

impl ModelBackend for OpenAiBackend {
    fn generate(
        &self,
        request: &GenerateRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<GenerateResponse, ModelError>> + Send + '_>,
    > {
        let url = format!("{}/chat/completions", self.base_url);
        let mut messages = Vec::new();

        if let Some(ref system) = request.system {
            messages.push(serde_json::json!({"role": "system", "content": system}));
        }
        messages.push(serde_json::json!({"role": "user", "content": &request.prompt}));

        let mut body = serde_json::json!({
            "model": &self.model,
            "messages": messages,
        });

        if let Some(max_tokens) = request.max_tokens {
            body["max_tokens"] = serde_json::json!(max_tokens);
        }
        if let Some(temperature) = request.temperature {
            body["temperature"] = serde_json::json!(temperature);
        }

        let mut req = self.client.post(&url).json(&body);
        if let Some((header, value)) = self.auth_header() {
            req = req.header(header, value);
        }

        Box::pin(async move {
            let resp = req
                .send()
                .await
                .map_err(|e| ModelError::Api(format!("request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(ModelError::Api(format!("HTTP {status}: {text}")));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ModelError::Api(format!("invalid response: {e}")))?;

            let text = json["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or("")
                .to_string();

            let prompt_tokens = json["usage"]["prompt_tokens"].as_u64().map(|v| v as u32);
            let completion_tokens = json["usage"]["completion_tokens"]
                .as_u64()
                .map(|v| v as u32);

            Ok(GenerateResponse {
                text,
                prompt_tokens,
                completion_tokens,
            })
        })
    }

    fn embed(
        &self,
        request: &EmbedRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<EmbedResponse, ModelError>> + Send + '_>,
    > {
        let url = format!("{}/embeddings", self.base_url);
        let body = serde_json::json!({
            "model": &self.model,
            "input": &request.text,
        });

        let mut req = self.client.post(&url).json(&body);
        if let Some((header, value)) = self.auth_header() {
            req = req.header(header, value);
        }

        Box::pin(async move {
            let resp = req
                .send()
                .await
                .map_err(|e| ModelError::Api(format!("request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(ModelError::Api(format!("HTTP {status}: {text}")));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ModelError::Api(format!("invalid response: {e}")))?;

            let embedding: Vec<f32> = json["data"][0]["embedding"]
                .as_array()
                .ok_or_else(|| ModelError::Api("missing embedding in response".into()))?
                .iter()
                .filter_map(|v| v.as_f64().map(|f| f as f32))
                .collect();

            let dimensions = embedding.len();

            Ok(EmbedResponse {
                embedding,
                dimensions,
            })
        })
    }

    fn classify(
        &self,
        request: &ClassifyRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ClassifyResponse, ModelError>> + Send + '_>,
    > {
        // Use chat completions with a classification prompt.
        // Guardian models on vLLM support this via structured output.
        let url = format!("{}/chat/completions", self.base_url);
        let body = serde_json::json!({
            "model": &self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a content safety classifier. Respond with only a JSON object: {\"label\": \"safe\" or \"unsafe\", \"confidence\": 0.0-1.0}"
                },
                {
                    "role": "user",
                    "content": format!("Classify this content:\n\n{}", request.text)
                }
            ],
            "temperature": 0.0,
            "max_tokens": 50,
        });

        let mut req = self.client.post(&url).json(&body);
        if let Some((header, value)) = self.auth_header() {
            req = req.header(header, value);
        }

        Box::pin(async move {
            let resp = req
                .send()
                .await
                .map_err(|e| ModelError::Api(format!("request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(ModelError::Api(format!("HTTP {status}: {text}")));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ModelError::Api(format!("invalid response: {e}")))?;

            let content = json["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or("");

            // Parse the model's JSON response
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
                let label = parsed["label"].as_str().unwrap_or("safe").to_string();
                let confidence = parsed["confidence"].as_f64().unwrap_or(1.0) as f32;

                let labels = if label == "safe" {
                    vec![
                        ClassifyLabel {
                            label: "safe".to_string(),
                            score: confidence,
                        },
                        ClassifyLabel {
                            label: "unsafe".to_string(),
                            score: 1.0 - confidence,
                        },
                    ]
                } else {
                    vec![
                        ClassifyLabel {
                            label: label.clone(),
                            score: confidence,
                        },
                        ClassifyLabel {
                            label: "safe".to_string(),
                            score: 1.0 - confidence,
                        },
                    ]
                };

                Ok(ClassifyResponse { labels })
            } else {
                // Fallback: treat unparseable output as safe
                tracing::warn!(
                    response = content,
                    "Could not parse classification response, defaulting to safe"
                );
                Ok(ClassifyResponse {
                    labels: vec![ClassifyLabel {
                        label: "safe".to_string(),
                        score: 1.0,
                    }],
                })
            }
        })
    }
}
