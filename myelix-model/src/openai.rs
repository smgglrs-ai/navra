//! OpenAI-compatible API backend for external model inference.
//!
//! Connects to vLLM, ollama, or any OpenAI-compatible API server.
//! Supports generate, embed, classify, transcribe, and synthesize.

use crate::{
    ClassifyLabel, ClassifyRequest, ClassifyResponse, EmbedRequest, EmbedResponse,
    GenerateRequest, GenerateResponse, Locality, ModelBackend, ModelError, SynthesizeRequest,
    SynthesizeResponse, TranscribeRequest, TranscribeResponse,
};
use crate::chat::{
    ChatMessage, ChatRequest, ChatResponse, ChatRole, ChatToolDefinition,
    FinishReason, FunctionCall, ToolCall, ToolChoice,
};
use futures_util::StreamExt;

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

        // Build user message — multimodal if images are present
        if request.images.is_empty() {
            messages.push(serde_json::json!({"role": "user", "content": &request.prompt}));
        } else {
            let mut content_parts = vec![
                serde_json::json!({"type": "text", "text": &request.prompt}),
            ];
            for image in &request.images {
                content_parts.push(serde_json::json!({
                    "type": "image_url",
                    "image_url": {
                        "url": format!("data:{};base64,{}", image.mime_type, image.data),
                    },
                }));
            }
            messages.push(serde_json::json!({"role": "user", "content": content_parts}));
        }

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

    fn transcribe(
        &self,
        request: &TranscribeRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TranscribeResponse, ModelError>> + Send + '_>,
    > {
        let url = format!("{}/audio/transcriptions", self.base_url);
        let wav_data = pcm_to_wav(&request.audio, 16000);
        let language = request.language.clone();
        let model = self.model.clone();

        let part = reqwest::multipart::Part::bytes(wav_data)
            .file_name("audio.wav")
            .mime_str("audio/wav")
            .unwrap();

        let mut form = reqwest::multipart::Form::new()
            .part("file", part)
            .text("model", model)
            .text("response_format", "json");

        if let Some(ref lang) = language {
            form = form.text("language", lang.clone());
        }

        let mut req = self.client.post(&url).multipart(form);
        if let Some((header, value)) = self.auth_header() {
            req = req.header(header, value);
        }

        Box::pin(async move {
            let resp = req
                .send()
                .await
                .map_err(|e| ModelError::Api(format!("transcription request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(ModelError::Api(format!("HTTP {status}: {text}")));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ModelError::Api(format!("invalid response: {e}")))?;

            let text = json["text"].as_str().unwrap_or("").to_string();
            let detected_lang = json["language"].as_str().map(String::from);

            Ok(TranscribeResponse {
                text,
                language: detected_lang.or(language),
            })
        })
    }

    fn synthesize(
        &self,
        request: &SynthesizeRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<SynthesizeResponse, ModelError>> + Send + '_>,
    > {
        let url = format!("{}/audio/speech", self.base_url);
        let body = serde_json::json!({
            "model": &self.model,
            "input": &request.text,
            "voice": request.voice.as_deref().unwrap_or("alloy"),
            "response_format": "pcm",
        });

        let mut req = self.client.post(&url).json(&body);
        if let Some((header, value)) = self.auth_header() {
            req = req.header(header, value);
        }

        Box::pin(async move {
            let resp = req
                .send()
                .await
                .map_err(|e| ModelError::Api(format!("synthesis request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(ModelError::Api(format!("HTTP {status}: {text}")));
            }

            let bytes = resp
                .bytes()
                .await
                .map_err(|e| ModelError::Api(format!("failed to read audio: {e}")))?;

            // OpenAI PCM format: 24kHz mono 16-bit signed little-endian
            let samples: Vec<f32> = bytes
                .chunks_exact(2)
                .map(|chunk| {
                    let sample = i16::from_le_bytes([chunk[0], chunk[1]]);
                    sample as f32 / 32768.0
                })
                .collect();

            Ok(SynthesizeResponse {
                audio: samples,
                sample_rate: 24000,
            })
        })
    }

    fn respond(
        &self,
        request: &crate::CreateResponseRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<crate::ModelResponse, ModelError>> + Send + '_>,
    > {
        // Translate Open Responses → Chat Completions at the HTTP boundary
        let chat_req = crate::responses_to_chat(request);
        let url = format!("{}/chat/completions", self.base_url);
        let body = self.build_chat_body(&chat_req, false);
        let model_name = self.model.clone();

        Box::pin(async move {
            let max_retries = 3u32;
            let mut attempt = 0u32;
            let resp = loop {
                let try_req = self.client.post(&url).json(&body);
                let try_req = if let Some((header, value)) = self.auth_header() {
                    try_req.header(header, value)
                } else {
                    try_req
                };

                let r = try_req
                    .send()
                    .await
                    .map_err(|e| ModelError::Api(format!("request failed: {e}")))?;

                if r.status() == reqwest::StatusCode::TOO_MANY_REQUESTS && attempt < max_retries {
                    let retry_after = r
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok());
                    let delay = retry_after.unwrap_or(1u64 << attempt);
                    tracing::warn!(
                        attempt = attempt + 1,
                        delay_secs = delay,
                        "Rate limited (429), retrying"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                    attempt += 1;
                    continue;
                }
                break r;
            };

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(ModelError::Api(format!("HTTP {status}: {text}")));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ModelError::Api(format!("invalid response: {e}")))?;

            let chat_resp = Self::parse_chat_response(&json)?;
            Ok(crate::chat_to_responses(&model_name, &chat_resp))
        })
    }
}

// --- Chat completion helpers ---

/// Serialize a ChatMessage into the OpenAI messages array format.
fn serialize_message(msg: &ChatMessage) -> serde_json::Value {
    match msg.role {
        ChatRole::System => {
            serde_json::json!({"role": "system", "content": msg.content.as_deref().unwrap_or("")})
        }
        ChatRole::User if msg.images.is_empty() => {
            serde_json::json!({"role": "user", "content": msg.content.as_deref().unwrap_or("")})
        }
        ChatRole::User => {
            let mut parts = vec![
                serde_json::json!({"type": "text", "text": msg.content.as_deref().unwrap_or("")}),
            ];
            for image in &msg.images {
                parts.push(serde_json::json!({
                    "type": "image_url",
                    "image_url": {
                        "url": format!("data:{};base64,{}", image.mime_type, image.data),
                    },
                }));
            }
            serde_json::json!({"role": "user", "content": parts})
        }
        ChatRole::Assistant if msg.tool_calls.is_empty() => {
            serde_json::json!({"role": "assistant", "content": msg.content.as_deref().unwrap_or("")})
        }
        ChatRole::Assistant => {
            let tool_calls: Vec<serde_json::Value> = msg
                .tool_calls
                .iter()
                .map(|tc| {
                    serde_json::json!({
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        }
                    })
                })
                .collect();
            serde_json::json!({"role": "assistant", "content": serde_json::Value::Null, "tool_calls": tool_calls})
        }
        ChatRole::Tool => {
            serde_json::json!({
                "role": "tool",
                "tool_call_id": msg.tool_call_id.as_deref().unwrap_or(""),
                "content": msg.content.as_deref().unwrap_or(""),
            })
        }
    }
}

/// Serialize messages for the OpenAI API.
fn serialize_messages(messages: &[ChatMessage]) -> Vec<serde_json::Value> {
    messages.iter().map(serialize_message).collect()
}

impl OpenAiBackend {
    /// Build the chat completion request body.
    fn build_chat_body(&self, request: &ChatRequest, stream: bool) -> serde_json::Value {
        let mut body = serde_json::json!({
            "model": &self.model,
            "messages": serialize_messages(&request.messages),
        });

        if let Some(max_tokens) = request.max_tokens {
            body["max_tokens"] = serde_json::json!(max_tokens);
        }
        if let Some(temperature) = request.temperature {
            body["temperature"] = serde_json::json!(temperature);
        }

        if !request.tools.is_empty() {
            let tools: Vec<serde_json::Value> = request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.parameters,
                        }
                    })
                })
                .collect();
            body["tools"] = serde_json::json!(tools);

            if let Some(ref choice) = request.tool_choice {
                body["tool_choice"] = match choice {
                    ToolChoice::Auto => serde_json::json!("auto"),
                    ToolChoice::None => serde_json::json!("none"),
                    ToolChoice::Required => serde_json::json!("required"),
                };
            }
        }

        if stream {
            body["stream"] = serde_json::json!(true);
            body["stream_options"] = serde_json::json!({"include_usage": true});
        }

        body
    }

    /// Parse a non-streaming chat completion response.
    fn parse_chat_response(json: &serde_json::Value) -> Result<ChatResponse, ModelError> {
        let choice = &json["choices"][0];
        let message = &choice["message"];

        let content = message["content"].as_str().map(String::from);

        let tool_calls = message["tool_calls"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|tc| {
                        Some(ToolCall {
                            id: tc["id"].as_str()?.to_string(),
                            call_type: "function".to_string(),
                            function: FunctionCall {
                                name: tc["function"]["name"].as_str()?.to_string(),
                                arguments: tc["function"]["arguments"].as_str()?.to_string(),
                            },
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let finish_reason = choice["finish_reason"]
            .as_str()
            .map(FinishReason::from_str)
            .unwrap_or(FinishReason::Stop);

        let prompt_tokens = json["usage"]["prompt_tokens"].as_u64().map(|v| v as u32);
        let completion_tokens = json["usage"]["completion_tokens"].as_u64().map(|v| v as u32);

        Ok(ChatResponse {
            message: ChatMessage {
                role: ChatRole::Assistant,
                content,
                images: Vec::new(),
                tool_calls,
                tool_call_id: None,
            },
            finish_reason,
            prompt_tokens,
            completion_tokens,
        })
    }
}

/// Encode f32 PCM samples as a 16-bit WAV file in memory.
fn pcm_to_wav(samples: &[f32], sample_rate: u32) -> Vec<u8> {
    let num_samples = samples.len() as u32;
    let data_size = num_samples * 2; // 16-bit = 2 bytes per sample
    let file_size = 36 + data_size;

    let mut buf = Vec::with_capacity(file_size as usize + 8);

    // RIFF header
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&file_size.to_le_bytes());
    buf.extend_from_slice(b"WAVE");

    // fmt chunk
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&16u32.to_le_bytes()); // chunk size
    buf.extend_from_slice(&1u16.to_le_bytes()); // PCM format
    buf.extend_from_slice(&1u16.to_le_bytes()); // mono
    buf.extend_from_slice(&sample_rate.to_le_bytes());
    buf.extend_from_slice(&(sample_rate * 2).to_le_bytes()); // byte rate
    buf.extend_from_slice(&2u16.to_le_bytes()); // block align
    buf.extend_from_slice(&16u16.to_le_bytes()); // bits per sample

    // data chunk
    buf.extend_from_slice(b"data");
    buf.extend_from_slice(&data_size.to_le_bytes());
    for &sample in samples {
        let clamped = sample.clamp(-1.0, 1.0);
        let int_sample = (clamped * 32767.0) as i16;
        buf.extend_from_slice(&int_sample.to_le_bytes());
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcm_to_wav_valid_header() {
        let samples = vec![0.0f32; 16000]; // 1 second of silence
        let wav = pcm_to_wav(&samples, 16000);

        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[12..16], b"fmt ");
        // PCM format = 1
        assert_eq!(u16::from_le_bytes([wav[20], wav[21]]), 1);
        // Mono
        assert_eq!(u16::from_le_bytes([wav[22], wav[23]]), 1);
        // Sample rate
        assert_eq!(
            u32::from_le_bytes([wav[24], wav[25], wav[26], wav[27]]),
            16000
        );
        // Data chunk
        assert_eq!(&wav[36..40], b"data");
        // Data size = 16000 samples * 2 bytes
        assert_eq!(
            u32::from_le_bytes([wav[40], wav[41], wav[42], wav[43]]),
            32000
        );
    }

    #[test]
    fn pcm_to_wav_roundtrip() {
        let samples = vec![0.5, -0.5, 0.0, 1.0, -1.0];
        let wav = pcm_to_wav(&samples, 16000);

        // Read back the samples from the data section
        let data_start = 44;
        let decoded: Vec<f32> = wav[data_start..]
            .chunks_exact(2)
            .map(|chunk| {
                let s = i16::from_le_bytes([chunk[0], chunk[1]]);
                s as f32 / 32768.0
            })
            .collect();

        assert_eq!(decoded.len(), 5);
        // Check approximate roundtrip (16-bit quantization)
        assert!((decoded[0] - 0.5).abs() < 0.001);
        assert!((decoded[1] + 0.5).abs() < 0.001);
        assert!((decoded[2]).abs() < 0.001);
    }

    // --- Chat serialization tests ---

    #[test]
    fn serialize_messages_text_only() {
        let msgs = vec![
            ChatMessage::system("You are helpful"),
            ChatMessage::user("Hello"),
            ChatMessage::assistant("Hi there"),
        ];
        let json = serialize_messages(&msgs);
        assert_eq!(json.len(), 3);
        assert_eq!(json[0]["role"], "system");
        assert_eq!(json[0]["content"], "You are helpful");
        assert_eq!(json[1]["role"], "user");
        assert_eq!(json[2]["role"], "assistant");
    }

    #[test]
    fn serialize_messages_with_images() {
        let mut msg = ChatMessage::user("Describe this");
        msg.images.push(crate::ImageInput {
            data: "base64data".to_string(),
            mime_type: "image/png".to_string(),
        });
        let json = serialize_messages(&[msg]);
        let content = json[0]["content"].as_array().unwrap();
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[1]["type"], "image_url");
    }

    #[test]
    fn serialize_messages_tool_calls() {
        let msg = ChatMessage::assistant_tool_calls(vec![ToolCall {
            id: "call_1".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "get_weather".to_string(),
                arguments: r#"{"city":"Paris"}"#.to_string(),
            },
        }]);
        let json = serialize_messages(&[msg]);
        assert!(json[0]["content"].is_null());
        let tc = &json[0]["tool_calls"][0];
        assert_eq!(tc["id"], "call_1");
        assert_eq!(tc["function"]["name"], "get_weather");
    }

    #[test]
    fn serialize_messages_tool_result() {
        let msg = ChatMessage::tool_result("call_1", "Sunny, 22C");
        let json = serialize_messages(&[msg]);
        assert_eq!(json[0]["role"], "tool");
        assert_eq!(json[0]["tool_call_id"], "call_1");
        assert_eq!(json[0]["content"], "Sunny, 22C");
    }

    #[test]
    fn build_chat_body_with_tools() {
        let backend = OpenAiBackend::new("http://localhost", "test", None, Locality::Local);
        let request = ChatRequest {
            messages: vec![ChatMessage::user("Hello")],
            max_tokens: Some(100),
            temperature: None,
            tools: vec![ChatToolDefinition {
                name: "get_weather".to_string(),
                description: "Get weather".to_string(),
                parameters: serde_json::json!({"type": "object"}),
            }],
            tool_choice: Some(ToolChoice::Auto),
        };
        let body = backend.build_chat_body(&request, false);
        assert_eq!(body["tools"][0]["type"], "function");
        assert_eq!(body["tools"][0]["function"]["name"], "get_weather");
        assert_eq!(body["tool_choice"], "auto");
        assert!(body.get("stream").is_none());
    }

    #[test]
    fn build_chat_body_stream_flag() {
        let backend = OpenAiBackend::new("http://localhost", "test", None, Locality::Local);
        let request = ChatRequest {
            messages: vec![ChatMessage::user("Hello")],
            max_tokens: None,
            temperature: None,
            tools: vec![],
            tool_choice: None,
        };
        let body = backend.build_chat_body(&request, true);
        assert_eq!(body["stream"], true);
        assert_eq!(body["stream_options"]["include_usage"], true);
    }

    #[test]
    fn parse_chat_response_text() {
        let json = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Hello!"
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2}
        });
        let resp = OpenAiBackend::parse_chat_response(&json).unwrap();
        assert_eq!(resp.message.content, Some("Hello!".to_string()));
        assert_eq!(resp.finish_reason, FinishReason::Stop);
        assert_eq!(resp.prompt_tokens, Some(5));
    }

    #[test]
    fn parse_chat_response_tool_calls() {
        let json = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 15}
        });
        let resp = OpenAiBackend::parse_chat_response(&json).unwrap();
        assert!(resp.message.content.is_none());
        assert_eq!(resp.finish_reason, FinishReason::ToolCalls);
        assert_eq!(resp.message.tool_calls.len(), 1);
        assert_eq!(resp.message.tool_calls[0].function.name, "get_weather");
    }
}
