//! Integration tests for navra-model public API.
//!
//! Tests the public types, constructors, and classification response
//! helpers without requiring running model backends.

use navra_model::responses::response::Usage;
use navra_model::{
    AnthropicBackend, ClassifyLabel, ClassifyRequest, ClassifyResponse, CliBackend,
    CreateResponseRequest, EmbedRequest, GenerateRequest, InputItem, Locality, MessageItem,
    ModelBackend, ModelError, ModelResponse, OpenAiBackend, OutputItem, ResponseStatus,
    safe_backend::{ModelSafetyFilter, SafeModelBackend},
};
#[cfg(feature = "onnx")]
use navra_model::{Device, ModelTask, OnnxBackend};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

// =====================================================================
// 1. ClassifyResponse helpers
// =====================================================================

#[test]
fn classify_response_top_label() {
    let resp = ClassifyResponse {
        labels: vec![
            ClassifyLabel {
                label: "safe".into(),
                score: 0.9,
            },
            ClassifyLabel {
                label: "hap".into(),
                score: 0.1,
            },
        ],
    };
    assert_eq!(resp.top_label().unwrap().label, "safe");
    assert_eq!(resp.top_label().unwrap().score, 0.9);
}

#[test]
fn classify_response_is_unsafe_above_threshold() {
    let resp = ClassifyResponse {
        labels: vec![
            ClassifyLabel {
                label: "hap".into(),
                score: 0.8,
            },
            ClassifyLabel {
                label: "safe".into(),
                score: 0.2,
            },
        ],
    };
    assert!(resp.is_unsafe(0.5));
    assert!(resp.is_unsafe(0.8));
    assert!(!resp.is_unsafe(0.9));
}

#[test]
fn classify_response_safe_not_unsafe() {
    let resp = ClassifyResponse {
        labels: vec![ClassifyLabel {
            label: "safe".into(),
            score: 0.99,
        }],
    };
    assert!(!resp.is_unsafe(0.5));
}

// =====================================================================
// 2. ModelError display
// =====================================================================

#[test]
fn model_error_display() {
    let e = ModelError::NotLoaded("whisper".into());
    assert_eq!(format!("{e}"), "model not loaded: whisper");

    let e = ModelError::Api("HTTP 429".into());
    assert_eq!(format!("{e}"), "API error: HTTP 429");

    let e = ModelError::Inference("OOM".into());
    assert_eq!(format!("{e}"), "inference failed: OOM");

    let e = ModelError::InvalidInput("empty prompt".into());
    assert_eq!(format!("{e}"), "invalid input: empty prompt");
}

// =====================================================================
// 3. Locality enum
// =====================================================================

#[test]
fn locality_equality() {
    assert_eq!(Locality::Local, Locality::Local);
    assert_eq!(Locality::Remote, Locality::Remote);
    assert_ne!(Locality::Local, Locality::Remote);
}

// =====================================================================
// 4. OpenAiBackend constructor
// =====================================================================

#[test]
fn openai_backend_constructor() {
    let backend = OpenAiBackend::new(
        "http://localhost:11434/v1",
        "granite3.3:8b",
        None,
        Locality::Local,
    );
    assert_eq!(backend.locality(), &Locality::Local);
}

#[test]
fn openai_backend_with_api_key() {
    let backend = OpenAiBackend::new(
        "https://api.openai.com/v1",
        "gpt-4o",
        Some("sk-test-key".into()),
        Locality::Remote,
    );
    assert_eq!(backend.locality(), &Locality::Remote);
}

// =====================================================================
// 5. AnthropicBackend constructor
// =====================================================================

#[test]
fn anthropic_backend_constructor() {
    let backend = AnthropicBackend::new(
        "https://api.anthropic.com",
        "claude-sonnet-4-20250514",
        None,
        Locality::Remote,
    );
    assert_eq!(backend.locality(), &Locality::Remote);
}

// =====================================================================
// 6. SafeModelBackend with mock
// =====================================================================

struct FakeBackend;

impl ModelBackend for FakeBackend {
    fn respond(
        &self,
        _req: &CreateResponseRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ModelResponse, ModelError>> + Send + '_>> {
        Box::pin(async {
            Ok(ModelResponse {
                id: "resp_test".into(),
                object: "response".into(),
                created_at: None,
                completed_at: None,
                status: ResponseStatus::Completed,
                model: Some("fake".into()),
                output: vec![OutputItem::Message(MessageItem::assistant("hello world"))],
                usage: Some(Usage {
                    input_tokens: 10,
                    output_tokens: 5,
                    total_tokens: 15,
                    input_tokens_details: None,
                    output_tokens_details: None,
                }),
                error: None,
                previous_response_id: None,
                instructions: None,
                tools: vec![],
                tool_choice: None,
                text: None,
                reasoning: None,
                truncation: None,
                temperature: None,
                max_output_tokens: None,
                metadata: Default::default(),
                incomplete_details: None,
                extra: Default::default(),
            })
        })
    }
}

struct CountingFilter {
    calls: AtomicU32,
}

impl ModelSafetyFilter for CountingFilter {
    fn filter_prompt(&self, _req: &CreateResponseRequest) -> Result<(), String> {
        Ok(())
    }
    fn filter_response(&self, _resp: &ModelResponse) -> Result<(), String> {
        Ok(())
    }
    fn record_call(&self, _model: &str, _in_tok: u32, _out_tok: u32, _blocked: bool) {
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}

struct BlockingFilter;

impl ModelSafetyFilter for BlockingFilter {
    fn filter_prompt(&self, _req: &CreateResponseRequest) -> Result<(), String> {
        Err("blocked: sensitive content".into())
    }
    fn filter_response(&self, _resp: &ModelResponse) -> Result<(), String> {
        Ok(())
    }
    fn record_call(&self, _model: &str, _in_tok: u32, _out_tok: u32, _blocked: bool) {}
}

#[tokio::test]
async fn safe_backend_passthrough() {
    let filter = Arc::new(CountingFilter {
        calls: AtomicU32::new(0),
    });
    let backend = SafeModelBackend::new(FakeBackend, filter.clone(), "test-model");

    let req = CreateResponseRequest::new(String::from("test"), vec![InputItem::user("hi")]);
    let resp = backend.respond(&req).await.unwrap();
    assert_eq!(resp.text().unwrap(), "hello world");
    assert_eq!(filter.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn safe_backend_blocks_sensitive_prompt() {
    let filter = Arc::new(BlockingFilter);
    let backend = SafeModelBackend::new(FakeBackend, filter, "test-model");

    let req =
        CreateResponseRequest::new(String::from("test"), vec![InputItem::user("secret data")]);
    let err = backend.respond(&req).await.unwrap_err();
    assert!(format!("{err}").contains("sensitive content"));
}

// =====================================================================
// 7. Default ModelBackend trait methods return NotLoaded
// =====================================================================

struct EmptyBackend;

impl ModelBackend for EmptyBackend {}

#[tokio::test]
async fn default_backend_methods_return_not_loaded() {
    let backend = EmptyBackend;

    let embed_err = backend
        .embed(&EmbedRequest {
            text: "hello".into(),
        })
        .await;
    assert!(matches!(embed_err, Err(ModelError::NotLoaded(_))));

    let classify_err = backend
        .classify(&ClassifyRequest {
            text: "hello".into(),
        })
        .await;
    assert!(matches!(classify_err, Err(ModelError::NotLoaded(_))));

    let gen_err = backend
        .generate(&GenerateRequest {
            prompt: "hello".into(),
            max_tokens: None,
            temperature: None,
            system: None,
            images: vec![],
        })
        .await;
    assert!(matches!(gen_err, Err(ModelError::NotLoaded(_))));

    let resp_err = backend
        .respond(&CreateResponseRequest::new(String::from("m"), vec![]))
        .await;
    assert!(matches!(resp_err, Err(ModelError::NotLoaded(_))));
}

// =====================================================================
// 8. CliBackend
// =====================================================================

#[test]
fn cli_backend_constructor() {
    let backend = CliBackend::new("claude", vec!["-p".into()]);
    assert_eq!(backend.locality(), &Locality::Local);
}

#[test]
fn cli_backend_builder() {
    let backend = CliBackend::builder("gemini")
        .args(vec!["--format".into(), "text".into()])
        .timeout_secs(120)
        .build();
    assert_eq!(backend.locality(), &Locality::Local);
}

#[tokio::test]
async fn cli_backend_generate_with_echo() {
    let backend = CliBackend::new("echo", vec!["test output".into()]);
    let req = GenerateRequest {
        prompt: "ignored".into(),
        max_tokens: None,
        temperature: None,
        system: None,
        images: vec![],
    };
    let resp = backend.generate(&req).await.unwrap();
    assert_eq!(resp.text, "test output");
}

#[tokio::test]
async fn cli_backend_generate_via_stdin() {
    let backend = CliBackend::new("cat", vec![]);
    let req = GenerateRequest {
        prompt: "stdin content".into(),
        max_tokens: None,
        temperature: None,
        system: None,
        images: vec![],
    };
    let resp = backend.generate(&req).await.unwrap();
    assert_eq!(resp.text, "stdin content");
}

#[tokio::test]
async fn cli_backend_respond() {
    let backend = CliBackend::new("echo", vec!["response text".into()]);
    let req = CreateResponseRequest::new(String::from("cli-model"), vec![InputItem::user("hello")]);
    let resp = backend.respond(&req).await.unwrap();
    assert_eq!(resp.status, ResponseStatus::Completed);
    assert_eq!(resp.text().unwrap(), "response text");
}

#[tokio::test]
async fn cli_backend_embed_unsupported() {
    let backend = CliBackend::new("echo", vec![]);
    let err = backend
        .embed(&navra_model::EmbedRequest { text: "hi".into() })
        .await;
    assert!(matches!(err, Err(ModelError::NotLoaded(_))));
}

#[tokio::test]
async fn cli_backend_classify_unsupported() {
    let backend = CliBackend::new("echo", vec![]);
    let err = backend
        .classify(&ClassifyRequest { text: "hi".into() })
        .await;
    assert!(matches!(err, Err(ModelError::NotLoaded(_))));
}

#[tokio::test]
async fn cli_backend_command_not_found() {
    let backend = CliBackend::new("nonexistent_cli_tool_xyz", vec![]);
    let req = GenerateRequest {
        prompt: "hello".into(),
        max_tokens: None,
        temperature: None,
        system: None,
        images: vec![],
    };
    let err = backend.generate(&req).await.unwrap_err();
    assert!(matches!(err, ModelError::Inference(_)));
    assert!(format!("{err}").contains("nonexistent_cli_tool_xyz"));
}

#[tokio::test]
async fn cli_backend_nonzero_exit() {
    let backend = CliBackend::new("false", vec![]);
    let req = GenerateRequest {
        prompt: "hello".into(),
        max_tokens: None,
        temperature: None,
        system: None,
        images: vec![],
    };
    let err = backend.generate(&req).await.unwrap_err();
    assert!(matches!(err, ModelError::Inference(_)));
}

// =====================================================================
// Real ONNX model tests (skip if model files not present)
// =====================================================================
#[cfg(feature = "onnx")]
mod onnx_tests {
    use super::*;
    use navra_model::{Device, ModelTask, OnnxBackend};

    fn guardian_hap_paths() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
        let home = std::env::var("HOME").ok()?;
        let model = std::path::PathBuf::from(&home)
            .join(".local/share/navra/models/granite-guardian-hap-38m-quantized.onnx");
        let tokenizer = std::path::PathBuf::from(&home)
            .join(".local/share/navra/models/granite-guardian-hap-38m/tokenizer.json");
        if model.exists() && tokenizer.exists() {
            Some((model, tokenizer))
        } else {
            None
        }
    }

    fn load_guardian_hap(device: Device) -> Option<OnnxBackend> {
        let (model_path, tokenizer_path) = guardian_hap_paths()?;
        let task = ModelTask::Classification {
            labels: vec!["non-toxic".to_string(), "toxic".to_string()],
        };
        Some(
            OnnxBackend::load(
                "guardian-hap-test",
                &model_path,
                Some(tokenizer_path.as_path()),
                task,
                device,
            )
            .expect("Failed to load Guardian HAP model"),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn guardian_hap_cpu_classifies_safe_text() {
        let Some(backend) = load_guardian_hap(Device::Cpu) else {
            eprintln!("Skipping: Guardian HAP model not found");
            return;
        };
        let req = ClassifyRequest {
            text: "The weather is nice today.".to_string(),
        };
        let result = backend.classify(&req).await.unwrap();
        assert_eq!(result.top_label().unwrap().label, "non-toxic");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn guardian_hap_cpu_classifies_toxic_text() {
        let Some(backend) = load_guardian_hap(Device::Cpu) else {
            eprintln!("Skipping: Guardian HAP model not found");
            return;
        };
        let req = ClassifyRequest {
            text: "I hate you, you stupid idiot!".to_string(),
        };
        let result = backend.classify(&req).await.unwrap();
        assert_eq!(result.top_label().unwrap().label, "toxic");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn guardian_hap_openvino_auto_classifies() {
        let Some(backend) = load_guardian_hap(Device::parse("openvino:AUTO")) else {
            eprintln!("Skipping: Guardian HAP model not found");
            return;
        };

        let safe_req = ClassifyRequest {
            text: "Hello, how are you?".to_string(),
        };
        let safe_result = backend.classify(&safe_req).await.unwrap();
        assert_eq!(safe_result.top_label().unwrap().label, "non-toxic");

        let toxic_req = ClassifyRequest {
            text: "I hate you, you stupid idiot!".to_string(),
        };
        let toxic_result = backend.classify(&toxic_req).await.unwrap();
        assert_eq!(toxic_result.top_label().unwrap().label, "toxic");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn guardian_hap_device_benchmark() {
        if guardian_hap_paths().is_none() {
            eprintln!("Skipping: Guardian HAP model not found");
            return;
        }

        let devices = vec![
            ("CPU", "cpu"),
            ("OpenVINO:AUTO", "openvino:AUTO"),
            ("OpenVINO:NPU", "openvino:NPU"),
            ("OpenVINO:GPU", "openvino:GPU"),
        ];

        let text = "The quick brown fox jumps over the lazy dog.";
        let iterations = 50;

        println!("\n--- Guardian HAP 38M benchmark ({iterations} iterations) ---");

        for (label, device_str) in &devices {
            let device = Device::parse(device_str);
            let backend = match load_guardian_hap(device) {
                Some(b) => b,
                None => {
                    println!("{label:16} SKIP (load failed)");
                    continue;
                }
            };

            let req = ClassifyRequest {
                text: text.to_string(),
            };

            // Warmup
            for _ in 0..5 {
                let _ = backend.classify(&req).await;
            }

            // Benchmark
            let start = std::time::Instant::now();
            for _ in 0..iterations {
                backend.classify(&req).await.unwrap();
            }
            let elapsed = start.elapsed();
            let per_call = elapsed / iterations;

            println!("{label:16} {per_call:>8.2?}/call ({elapsed:.2?} total)");
        }
    }

    // =====================================================================
    // Granite Embedding R2 149M tests
    // =====================================================================

    fn embedding_r2_paths() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
        let home = std::env::var("HOME").ok()?;
        let model = std::path::PathBuf::from(&home)
            .join(".local/share/navra/models/granite-embedding-r2-onnx/model_int8.onnx");
        let tokenizer = std::path::PathBuf::from(&home)
            .join(".local/share/navra/models/granite-embedding-r2-onnx/tokenizer.json");
        if model.exists() && tokenizer.exists() {
            Some((model, tokenizer))
        } else {
            None
        }
    }

    fn load_embedding_r2(device: Device) -> Option<OnnxBackend> {
        let (model_path, tokenizer_path) = embedding_r2_paths()?;
        let task = ModelTask::Embedding { dimensions: 768 };
        Some(
            OnnxBackend::load(
                "embedding-r2-test",
                &model_path,
                Some(tokenizer_path.as_path()),
                task,
                device,
            )
            .expect("Failed to load Granite Embedding R2 model"),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn embedding_r2_cpu_produces_vectors() {
        let Some(backend) = load_embedding_r2(Device::Cpu) else {
            eprintln!("Skipping: Embedding R2 model not found");
            return;
        };

        let req = EmbedRequest {
            text: "Secure MCP gateway for Linux desktops.".to_string(),
        };
        let result = backend.embed(&req).await.unwrap();
        assert_eq!(result.dimensions, 768);
        assert_eq!(result.embedding.len(), 768);

        // Embedding should be L2-normalized (norm ≈ 1.0)
        let norm: f32 = result.embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.01, "expected unit norm, got {norm}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn embedding_r2_similar_texts_closer() {
        let Some(backend) = load_embedding_r2(Device::Cpu) else {
            eprintln!("Skipping: Embedding R2 model not found");
            return;
        };

        let req_a = EmbedRequest {
            text: "The cat sat on the mat.".to_string(),
        };
        let req_b = EmbedRequest {
            text: "A kitten was sitting on a rug.".to_string(),
        };
        let req_c = EmbedRequest {
            text: "Quantum chromodynamics describes strong force interactions.".to_string(),
        };

        let emb_a = backend.embed(&req_a).await.unwrap().embedding;
        let emb_b = backend.embed(&req_b).await.unwrap().embedding;
        let emb_c = backend.embed(&req_c).await.unwrap().embedding;

        let sim_ab: f32 = emb_a.iter().zip(&emb_b).map(|(a, b)| a * b).sum();
        let sim_ac: f32 = emb_a.iter().zip(&emb_c).map(|(a, b)| a * b).sum();

        assert!(
            sim_ab > sim_ac,
            "similar texts should be closer: sim(a,b)={sim_ab:.4} vs sim(a,c)={sim_ac:.4}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn embedding_r2_device_benchmark() {
        if embedding_r2_paths().is_none() {
            eprintln!("Skipping: Embedding R2 model not found");
            return;
        }

        let devices = vec![
            ("CPU", "cpu"),
            ("OpenVINO:AUTO", "openvino:AUTO"),
            ("OpenVINO:NPU", "openvino:NPU"),
            ("OpenVINO:GPU", "openvino:GPU"),
        ];

        let text = "Secure MCP gateway for Linux desktops with deny-wins ACLs and safety filters.";
        let iterations = 20;

        println!("\n--- Granite Embedding R2 149M benchmark ({iterations} iterations) ---");

        for (label, device_str) in &devices {
            let device = Device::parse(device_str);
            let backend = match load_embedding_r2(device) {
                Some(b) => b,
                None => {
                    println!("{label:16} SKIP (load failed)");
                    continue;
                }
            };

            let req = EmbedRequest {
                text: text.to_string(),
            };

            // Warmup
            for _ in 0..3 {
                let _ = backend.embed(&req).await;
            }

            // Benchmark
            let start = std::time::Instant::now();
            for _ in 0..iterations {
                backend.embed(&req).await.unwrap();
            }
            let elapsed = start.elapsed();
            let per_call = elapsed / iterations as u32;

            println!("{label:16} {per_call:>8.2?}/call ({elapsed:.2?} total)");
        }
    }
} // mod onnx_tests
