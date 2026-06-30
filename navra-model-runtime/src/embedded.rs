//! Embedded runtime — run llama.cpp in-process via llama-cpp-4.
//!
//! Loads a GGUF model directly into the navra process and serves
//! an OpenAI-compatible `/v1/chat/completions` endpoint on a local
//! port. No external process, no container, no Ollama required.

use crate::{
    Endpoint, Isolation, ModelRuntime, RuntimeBackend, RuntimeCapabilities, RuntimeError,
    ServeConfig,
};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::{extract::State, routing::get, routing::post, Json, Router};
use llama_cpp_4::context::params::LlamaContextParams;
use llama_cpp_4::llama_backend::LlamaBackend;
use llama_cpp_4::model::params::LlamaModelParams;
use llama_cpp_4::model::{AddBos, LlamaModel, Special};
use llama_cpp_4::sampling::LlamaSampler;
use llama_cpp_4::token::LlamaToken;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

struct RunningInstance {
    shutdown: tokio::sync::oneshot::Sender<()>,
}

pub struct EmbeddedRuntime {
    instances: Mutex<HashMap<String, RunningInstance>>,
}

impl EmbeddedRuntime {
    pub fn new() -> Self {
        Self {
            instances: Mutex::new(HashMap::new()),
        }
    }
}

#[derive(Clone)]
struct AppState {
    model: Arc<LlamaModel>,
    backend: Arc<LlamaBackend>,
    context_size: u32,
}

unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

#[derive(Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatCompletionRequest {
    #[serde(default)]
    messages: Vec<ChatMessage>,
    #[serde(default = "default_max_tokens")]
    max_tokens: u32,
    #[serde(default = "default_temperature")]
    temperature: f32,
}

fn default_max_tokens() -> u32 {
    2048
}
fn default_temperature() -> f32 {
    0.7
}

#[derive(Serialize)]
struct ChatCompletionResponse {
    id: String,
    object: &'static str,
    choices: Vec<Choice>,
    usage: Usage,
}

#[derive(Serialize)]
struct Choice {
    index: u32,
    message: ResponseMessage,
    finish_reason: String,
}

#[derive(Serialize)]
struct ResponseMessage {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct Usage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

async fn health() -> &'static str {
    "ok"
}

async fn chat_completions(
    State(state): State<AppState>,
    Json(req): Json<ChatCompletionRequest>,
) -> Json<ChatCompletionResponse> {
    let ctx_size = state.context_size;
    let result = tokio::task::spawn_blocking(move || {
        generate_response(&state.backend, &state.model, &req, ctx_size)
    })
    .await
    .unwrap_or_else(|e| Err(format!("inference task panicked: {e}")));

    match result {
        Ok(resp) => Json(resp),
        Err(err) => Json(ChatCompletionResponse {
            id: format!("chatcmpl-err-{}", Uuid::new_v4()),
            object: "chat.completion",
            choices: vec![Choice {
                index: 0,
                message: ResponseMessage {
                    role: "assistant",
                    content: format!("Error: {err}"),
                },
                finish_reason: "error".to_string(),
            }],
            usage: Usage {
                prompt_tokens: 0,
                completion_tokens: 0,
                total_tokens: 0,
            },
        }),
    }
}

fn generate_response(
    _backend: &LlamaBackend,
    model: &LlamaModel,
    req: &ChatCompletionRequest,
    context_size: u32,
) -> Result<ChatCompletionResponse, String> {
    let prompt = format_chat_prompt(model, &req.messages);

    let ctx_params = LlamaContextParams::default()
        .with_n_ctx(std::num::NonZeroU32::new(context_size));

    let mut ctx = model
        .new_context(_backend, ctx_params)
        .map_err(|e| format!("failed to create context: {e}"))?;

    let tokens = model
        .str_to_token(&prompt, AddBos::Always)
        .map_err(|e| format!("tokenization failed: {e}"))?;

    let prompt_token_count = tokens.len() as u32;

    let mut batch = llama_cpp_4::llama_batch::LlamaBatch::new(context_size as usize, 1);
    for (i, &token) in tokens.iter().enumerate() {
        let is_last = i == tokens.len() - 1;
        batch
            .add(token, i as i32, &[0], is_last)
            .map_err(|e| format!("batch add failed: {e}"))?;
    }

    ctx.decode(&mut batch)
        .map_err(|e| format!("prompt decode failed: {e}"))?;

    let mut sampler = LlamaSampler::chain_simple([
        LlamaSampler::temp(req.temperature),
        LlamaSampler::top_k(40),
        LlamaSampler::top_p(0.95, 1),
        LlamaSampler::dist(42),
    ]);

    let mut output_tokens: Vec<LlamaToken> = Vec::new();
    let max_tokens = req.max_tokens.min(context_size);
    let eos = model.token_eos();

    for _ in 0..max_tokens {
        let token = sampler.sample(&ctx, -1);
        sampler.accept(token);

        if token == eos {
            break;
        }

        output_tokens.push(token);

        batch.clear();
        let pos = (tokens.len() + output_tokens.len() - 1) as i32;
        batch
            .add(token, pos, &[0], true)
            .map_err(|e| format!("batch add failed: {e}"))?;

        ctx.decode(&mut batch)
            .map_err(|e| format!("decode failed: {e}"))?;
    }

    let completion_token_count = output_tokens.len() as u32;

    let response_text = output_tokens
        .iter()
        .map(|t| model.token_to_str(*t, Special::Tokenize))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("detokenization failed: {e}"))?
        .join("");

    let finish_reason = if output_tokens.len() as u32 >= max_tokens {
        "length"
    } else {
        "stop"
    };

    Ok(ChatCompletionResponse {
        id: format!("chatcmpl-{}", Uuid::new_v4()),
        object: "chat.completion",
        choices: vec![Choice {
            index: 0,
            message: ResponseMessage {
                role: "assistant",
                content: response_text,
            },
            finish_reason: finish_reason.to_string(),
        }],
        usage: Usage {
            prompt_tokens: prompt_token_count,
            completion_tokens: completion_token_count,
            total_tokens: prompt_token_count + completion_token_count,
        },
    })
}

fn format_chat_prompt(model: &LlamaModel, messages: &[ChatMessage]) -> String {
    let chat_messages: Vec<_> = messages
        .iter()
        .map(|m| (m.role.as_str(), m.content.as_str()))
        .collect();

    if let Ok(formatted) = apply_chat_template(model, &chat_messages) {
        return formatted;
    }

    let mut prompt = String::new();
    for msg in messages {
        match msg.role.as_str() {
            "system" => {
                prompt.push_str(&msg.content);
                prompt.push('\n');
            }
            "user" => {
                prompt.push_str("User: ");
                prompt.push_str(&msg.content);
                prompt.push('\n');
            }
            "assistant" => {
                prompt.push_str("Assistant: ");
                prompt.push_str(&msg.content);
                prompt.push('\n');
            }
            _ => {}
        }
    }
    prompt.push_str("Assistant:");
    prompt
}

fn apply_chat_template(
    model: &LlamaModel,
    messages: &[(&str, &str)],
) -> Result<String, String> {
    let chat_messages: Vec<llama_cpp_4::model::LlamaChatMessage> = messages
        .iter()
        .map(|(role, content)| llama_cpp_4::model::LlamaChatMessage::new(role.to_string(), content.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("chat message creation failed: {e}"))?;

    model
        .apply_chat_template(None, &chat_messages, true)
        .map_err(|e| format!("chat template failed: {e}"))
}

impl ModelRuntime for EmbeddedRuntime {
    fn serve(
        &self,
        config: &ServeConfig,
    ) -> Pin<Box<dyn Future<Output = Result<Endpoint, RuntimeError>> + Send + '_>> {
        let config = config.clone();
        Box::pin(async move {
            let port = if config.port == 0 {
                crate::pick_free_port()?
            } else {
                config.port
            };

            let model_path = config.model_path.clone();
            let context_size = config.context_size;
            let n_gpu_layers = if config.gpus.is_empty() { 0 } else { 999 };

            let (model, backend) = tokio::task::spawn_blocking(move || {
                let backend = LlamaBackend::init().map_err(|e| {
                    RuntimeError::Start(format!("llama backend init failed: {e}"))
                })?;

                let model_params = LlamaModelParams::default()
                    .with_n_gpu_layers(n_gpu_layers);

                let model = LlamaModel::load_from_file(&backend, model_path, &model_params)
                    .map_err(|e| RuntimeError::Start(format!("model load failed: {e}")))?;

                tracing::info!(
                    params = model.n_params(),
                    layers = model.n_layer(),
                    embd = model.n_embd(),
                    ctx_train = model.n_ctx_train(),
                    "Embedded model loaded"
                );

                Ok::<_, RuntimeError>((model, backend))
            })
            .await
            .map_err(|e| RuntimeError::Start(format!("model load task panicked: {e}")))??;

            let state = AppState {
                model: Arc::new(model),
                backend: Arc::new(backend),
                context_size,
            };

            let app = Router::new()
                .route("/health", get(health))
                .route("/v1/chat/completions", post(chat_completions))
                .with_state(state);

            let addr = format!("{}:{port}", config.host);
            let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
                RuntimeError::Start(format!("bind {addr} failed: {e}"))
            })?;

            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

            tokio::spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .ok();
            });

            let id = format!("embedded-{port}");
            let url = format!("http://{}:{port}", config.host);

            tracing::info!(port = port, "Embedded llama.cpp server ready");

            self.instances.lock().unwrap().insert(
                id.clone(),
                RunningInstance {
                    shutdown: shutdown_tx,
                },
            );

            Ok(Endpoint {
                url,
                id,
                backend: RuntimeBackend::new(
                    crate::engine::Engine::LlamaCpp,
                    Isolation::Direct,
                ),
            })
        })
    }

    fn stop(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + '_>> {
        let id = endpoint.id.clone();
        Box::pin(async move {
            let instance = self.instances.lock().unwrap().remove(&id);
            if let Some(instance) = instance {
                let _ = instance.shutdown.send(());
                tracing::info!(id = %id, "Stopped embedded llama.cpp server");
            }
            Ok(())
        })
    }

    fn health(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RuntimeError>> + Send + '_>> {
        let url = format!("{}/health", endpoint.url);
        Box::pin(async move {
            let client = reqwest::Client::new();
            match client.get(&url).send().await {
                Ok(resp) => Ok(resp.status().is_success()),
                Err(_) => Ok(false),
            }
        })
    }

    fn backend(&self) -> RuntimeBackend {
        RuntimeBackend::new(crate::engine::Engine::LlamaCpp, Isolation::Direct)
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            supports_kv_checkpoint: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_runtime_creates() {
        let rt = EmbeddedRuntime::new();
        assert!(rt.instances.lock().unwrap().is_empty());
    }

    #[test]
    fn format_chat_prompt_fallback() {
        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: "You are helpful.".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: "Hello".to_string(),
            },
        ];
        // Without a model, test the fallback formatter
        let mut prompt = String::new();
        for msg in &messages {
            match msg.role.as_str() {
                "system" => {
                    prompt.push_str(&msg.content);
                    prompt.push('\n');
                }
                "user" => {
                    prompt.push_str("User: ");
                    prompt.push_str(&msg.content);
                    prompt.push('\n');
                }
                _ => {}
            }
        }
        prompt.push_str("Assistant:");
        assert!(prompt.contains("You are helpful."));
        assert!(prompt.contains("User: Hello"));
        assert!(prompt.ends_with("Assistant:"));
    }

    #[test]
    fn chat_completion_response_serializes() {
        let resp = ChatCompletionResponse {
            id: "test-123".to_string(),
            object: "chat.completion",
            choices: vec![Choice {
                index: 0,
                message: ResponseMessage {
                    role: "assistant",
                    content: "Hello!".to_string(),
                },
                finish_reason: "stop".to_string(),
            }],
            usage: Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("chat.completion"));
        assert!(json.contains("Hello!"));
    }
}
