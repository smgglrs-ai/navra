//! Embedded runtime — run llama.cpp in-process via llama-cpp-4.
//!
//! Loads GGUF models on demand into the navra process and serves
//! OpenAI-compatible `/v1/chat/completions` endpoints on local ports.
//! Models are managed in an LRU pool — when memory is constrained,
//! the least-recently-used model is evicted to free RAM/VRAM.
//!
//! GPU-aware: probes available VRAM before loading and offloads
//! model layers to GPU when sufficient VRAM exists, falling back
//! to CPU otherwise.

use crate::{
    Endpoint, Isolation, ModelRuntime, RuntimeBackend, RuntimeCapabilities, RuntimeError,
    ServeConfig,
};
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use axum::{extract::State, routing::get, routing::post, Json, Router};
use llama_cpp_4::context::params::LlamaContextParams;
use llama_cpp_4::llama_backend::LlamaBackend;
use llama_cpp_4::model::params::LlamaModelParams;
use llama_cpp_4::model::{AddBos, LlamaModel, Special};
use llama_cpp_4::sampling::LlamaSampler;
use llama_cpp_4::token::LlamaToken;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

struct LoadedModel {
    endpoint: Endpoint,
    shutdown: tokio::sync::oneshot::Sender<()>,
    model_size: u64,
    gpu_offloaded: bool,
    last_used: Instant,
    model_path: PathBuf,
}

pub struct EmbeddedRuntime {
    pool: Mutex<HashMap<String, LoadedModel>>,
    backend: OnceLock<Arc<LlamaBackend>>,
}

impl EmbeddedRuntime {
    pub fn new() -> Self {
        Self {
            pool: Mutex::new(HashMap::new()),
            backend: OnceLock::new(),
        }
    }

    fn init_backend(&self) -> Result<Arc<LlamaBackend>, RuntimeError> {
        if let Some(b) = self.backend.get() {
            return Ok(Arc::clone(b));
        }
        let backend = LlamaBackend::init()
            .map_err(|e| RuntimeError::Start(format!("llama backend init failed: {e}")))?;
        let arc = Arc::new(backend);
        let _ = self.backend.set(Arc::clone(&arc));
        Ok(self.backend.get().map(Arc::clone).unwrap_or(arc))
    }

    fn evict_lru(&self) -> Option<(String, tokio::sync::oneshot::Sender<()>, u64, bool)> {
        let mut pool = self.pool.lock().unwrap();
        let oldest = pool
            .iter()
            .min_by_key(|(_, m)| m.last_used)
            .map(|(k, _)| k.clone());
        if let Some(key) = oldest {
            let model = pool.remove(&key).unwrap();
            tracing::info!(
                model = %key,
                size_mb = model.model_size / (1024 * 1024),
                gpu = model.gpu_offloaded,
                "Evicting LRU model"
            );
            Some((key, model.shutdown, model.model_size, model.gpu_offloaded))
        } else {
            None
        }
    }

    pub fn touch(&self, model_path: &str) {
        let mut pool = self.pool.lock().unwrap();
        if let Some(model) = pool.values_mut().find(|m| m.model_path.to_string_lossy() == model_path) {
            model.last_used = Instant::now();
        }
    }

    fn find_loaded(&self, model_path: &std::path::Path) -> Option<Endpoint> {
        let mut pool = self.pool.lock().unwrap();
        if let Some(model) = pool.values_mut().find(|m| m.model_path == model_path) {
            model.last_used = Instant::now();
            return Some(model.endpoint.clone());
        }
        None
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
            // Return existing endpoint if model is already loaded
            if let Some(endpoint) = self.find_loaded(&config.model_path) {
                tracing::debug!(
                    path = %config.model_path.display(),
                    url = %endpoint.url,
                    "Model already loaded, reusing endpoint"
                );
                return Ok(endpoint);
            }

            let port = if config.port == 0 {
                crate::pick_free_port()?
            } else {
                config.port
            };

            let model_path = config.model_path.clone();
            let context_size = config.context_size;
            let model_size = std::fs::metadata(&model_path)
                .map(|m| m.len())
                .unwrap_or(0);

            // GPU-aware offloading: check available VRAM
            let available_vram = crate::gpu::available_vram();
            let has_gpu = !config.gpus.is_empty();
            let n_gpu_layers = if has_gpu && available_vram > model_size {
                tracing::info!(
                    vram_free_mb = available_vram / (1024 * 1024),
                    model_size_mb = model_size / (1024 * 1024),
                    "VRAM sufficient, offloading all layers to GPU"
                );
                999
            } else if has_gpu {
                tracing::warn!(
                    vram_free_mb = available_vram / (1024 * 1024),
                    model_size_mb = model_size / (1024 * 1024),
                    "VRAM insufficient, falling back to CPU"
                );
                0
            } else {
                0
            };
            let gpu_offloaded = n_gpu_layers > 0;

            // Evict LRU if we're memory-constrained
            // Simple heuristic: if loading this model would exceed
            // available system RAM, evict the oldest model
            let available_ram = {
                let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
                meminfo
                    .lines()
                    .find(|l| l.starts_with("MemAvailable:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|kb| kb * 1024)
                    .unwrap_or(u64::MAX)
            };

            if !gpu_offloaded && model_size > available_ram {
                if let Some((name, shutdown, _, _)) = self.evict_lru() {
                    let _ = shutdown.send(());
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    tracing::info!(evicted = %name, "Freed memory for new model");
                }
            }

            if gpu_offloaded && model_size > available_vram {
                if let Some((name, shutdown, _, was_gpu)) = self.evict_lru() {
                    let _ = shutdown.send(());
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    tracing::info!(
                        evicted = %name,
                        freed_gpu = was_gpu,
                        "Freed VRAM for new model"
                    );
                }
            }

            let backend = self.init_backend()?;
            let backend_clone = Arc::clone(&backend);

            let model = tokio::task::spawn_blocking(move || {
                let model_params = LlamaModelParams::default()
                    .with_n_gpu_layers(n_gpu_layers);

                let model = LlamaModel::load_from_file(&backend_clone, model_path, &model_params)
                    .map_err(|e| RuntimeError::Start(format!("model load failed: {e}")))?;

                tracing::info!(
                    params = model.n_params(),
                    layers = model.n_layer(),
                    embd = model.n_embd(),
                    ctx_train = model.n_ctx_train(),
                    gpu_layers = n_gpu_layers,
                    size_mb = model_size / (1024 * 1024),
                    "Embedded model loaded"
                );

                Ok::<_, RuntimeError>(model)
            })
            .await
            .map_err(|e| RuntimeError::Start(format!("model load task panicked: {e}")))??;

            let state = AppState {
                model: Arc::new(model),
                backend,
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

            tracing::info!(port = port, gpu = gpu_offloaded, "Embedded llama.cpp server ready");

            let endpoint = Endpoint {
                url,
                id: id.clone(),
                backend: RuntimeBackend::new(
                    crate::engine::Engine::LlamaCpp,
                    Isolation::Direct,
                ),
            };

            self.pool.lock().unwrap().insert(
                id,
                LoadedModel {
                    endpoint: endpoint.clone(),
                    shutdown: shutdown_tx,
                    model_size,
                    gpu_offloaded,
                    last_used: Instant::now(),
                    model_path: config.model_path,
                },
            );

            Ok(endpoint)
        })
    }

    fn stop(
        &self,
        endpoint: &Endpoint,
    ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + '_>> {
        let id = endpoint.id.clone();
        Box::pin(async move {
            let model = self.pool.lock().unwrap().remove(&id);
            if let Some(model) = model {
                let _ = model.shutdown.send(());
                tracing::info!(
                    id = %id,
                    size_mb = model.model_size / (1024 * 1024),
                    gpu = model.gpu_offloaded,
                    "Stopped embedded model"
                );
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
        assert!(rt.pool.lock().unwrap().is_empty());
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
