//! Inference engine abstraction.
//!
//! An [`Engine`] knows how to build CLI arguments, select container
//! images, and check availability for a specific inference server
//! (llama.cpp or vLLM). Isolation modes ([`DirectRuntime`],
//! [`PodmanRuntime`], [`OpenShellRuntime`]) are generic over the engine.

use crate::gpu::GpuKind;
use crate::{RuntimeError, ServeConfig};
use tokio::process::Command;

/// Inference engine — the software that actually serves the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// llama.cpp (`llama-server`). Supports CPU and GPU. GGUF format.
    LlamaCpp,
    /// vLLM (`vllm serve`). GPU required. safetensors/GGUF/AWQ/GPTQ.
    Vllm,
}

impl Engine {
    /// Human-readable name for display and config values.
    pub fn name(&self) -> &'static str {
        match self {
            Self::LlamaCpp => "llama-cpp",
            Self::Vllm => "vllm",
        }
    }

    /// Binary to spawn.
    pub fn binary(&self) -> &'static str {
        match self {
            Self::LlamaCpp => "llama-server",
            Self::Vllm => "vllm",
        }
    }

    /// Default port the server listens on inside a container.
    pub fn default_serve_port(&self) -> u16 {
        match self {
            Self::LlamaCpp => 8080,
            Self::Vllm => 8000,
        }
    }

    /// Whether this engine requires a GPU to function.
    pub fn requires_gpu(&self) -> bool {
        match self {
            Self::LlamaCpp => false,
            Self::Vllm => true,
        }
    }

    /// Whether Podman needs `--ipc=host` (NCCL shared memory for tensor parallelism).
    pub fn needs_ipc_host(&self) -> bool {
        match self {
            Self::LlamaCpp => false,
            Self::Vllm => true,
        }
    }

    /// Whether the engine supports KV cache checkpointing for instant resume.
    pub fn supports_kv_checkpoint(&self) -> bool {
        match self {
            Self::LlamaCpp => true,
            Self::Vllm => false,
        }
    }

    /// Number of health poll attempts (at 500ms intervals) before giving up.
    pub fn health_poll_attempts(&self) -> usize {
        match self {
            Self::LlamaCpp => 60,  // 30s
            Self::Vllm => 240,    // 120s (vLLM compiles CUDA kernels on first start)
        }
    }

    /// Check if the engine binary is available on PATH.
    pub async fn is_available(&self) -> bool {
        let (bin, arg) = match self {
            Self::LlamaCpp => ("llama-server", "--version"),
            Self::Vllm => ("vllm", "version"),
        };
        Command::new(bin)
            .arg(arg)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Build the CLI arguments for serving a model.
    ///
    /// For llama-server: `--model {path} --host {host} --port {port} ...`
    /// For vllm: `serve {path} --host {host} --port {port} ...`
    pub fn build_serve_args(&self, config: &ServeConfig, port: u16) -> Vec<String> {
        match self {
            Self::LlamaCpp => Self::build_llamacpp_args(config, port),
            Self::Vllm => Self::build_vllm_args(config, port),
        }
    }

    /// Select the container image for this engine based on GPU type.
    pub fn select_image(&self, config: &ServeConfig) -> Result<&'static str, RuntimeError> {
        match self {
            Self::LlamaCpp => Ok(Self::select_llamacpp_image(config)),
            Self::Vllm => Self::select_vllm_image(config),
        }
    }

    // ── llama.cpp ───────────────────────────────────────────────────────

    fn build_llamacpp_args(config: &ServeConfig, port: u16) -> Vec<String> {
        let mut args = vec![
            "--model".to_string(),
            config.model_path.to_string_lossy().to_string(),
            "--host".to_string(),
            config.host.clone(),
            "--port".to_string(),
            port.to_string(),
            "--ctx-size".to_string(),
            config.context_size.to_string(),
            "--parallel".to_string(),
            config.parallel.to_string(),
        ];

        if !config.gpus.is_empty() {
            args.extend_from_slice(&["--n-gpu-layers".to_string(), "999".to_string()]);
        }

        if let Some(cache_type) = &config.cache_type {
            args.extend_from_slice(&[
                "--cache-type-k".to_string(),
                cache_type.as_llama_arg().to_string(),
                "--cache-type-v".to_string(),
                cache_type.as_llama_arg().to_string(),
            ]);
        }

        if let Some(ref spec) = config.speculative {
            args.extend_from_slice(&[
                "--model-draft".to_string(),
                spec.draft_model.to_string_lossy().to_string(),
                "--draft-max".to_string(),
                spec.draft_tokens.to_string(),
            ]);
            if spec.draft_min_p > 0.0 {
                args.extend_from_slice(&[
                    "--draft-min-p".to_string(),
                    spec.draft_min_p.to_string(),
                ]);
            }
        }

        args.extend(config.extra_args.iter().cloned());
        args
    }

    /// For containers: llama-server uses short flags and 0.0.0.0 bind.
    pub fn build_container_args(&self, config: &ServeConfig) -> Vec<String> {
        match self {
            Self::LlamaCpp => {
                let mut args = vec![
                    "--model".to_string(),
                    "/model".to_string(),
                    "--host".to_string(),
                    "0.0.0.0".to_string(),
                    "--port".to_string(),
                    self.default_serve_port().to_string(),
                    "--ctx-size".to_string(),
                    config.context_size.to_string(),
                    "--parallel".to_string(),
                    config.parallel.to_string(),
                ];

                if !config.gpus.is_empty() {
                    args.extend_from_slice(&["--n-gpu-layers".to_string(), "999".to_string()]);
                }

                if let Some(cache_type) = &config.cache_type {
                    args.extend_from_slice(&[
                        "--cache-type-k".to_string(),
                        cache_type.as_llama_arg().to_string(),
                        "--cache-type-v".to_string(),
                        cache_type.as_llama_arg().to_string(),
                    ]);
                }

                if let Some(ref spec) = config.speculative {
                    args.extend_from_slice(&[
                        "--model-draft".to_string(),
                        spec.draft_model.to_string_lossy().to_string(),
                        "--draft-max".to_string(),
                        spec.draft_tokens.to_string(),
                    ]);
                    if spec.draft_min_p > 0.0 {
                        args.extend_from_slice(&[
                            "--draft-min-p".to_string(),
                            spec.draft_min_p.to_string(),
                        ]);
                    }
                }

                args.extend(config.extra_args.iter().cloned());
                args
            }
            Self::Vllm => {
                let mut args = vec![
                    "--model".to_string(),
                    "/model".to_string(),
                    "--host".to_string(),
                    "0.0.0.0".to_string(),
                    "--port".to_string(),
                    self.default_serve_port().to_string(),
                    "--max-model-len".to_string(),
                    config.context_size.to_string(),
                    "--max-num-seqs".to_string(),
                    config.parallel.to_string(),
                ];

                let gpu_count = config.gpus.len();
                if gpu_count > 1 {
                    args.extend_from_slice(&[
                        "--tensor-parallel-size".to_string(),
                        gpu_count.to_string(),
                    ]);
                }

                if let Some(cache_type) = &config.cache_type {
                    let dtype = match cache_type {
                        crate::KvCacheType::F16 => "auto",
                        crate::KvCacheType::Q8_0 | crate::KvCacheType::Q4_0 => "fp8",
                    };
                    args.extend_from_slice(&["--kv-cache-dtype".to_string(), dtype.to_string()]);
                }

                if let Some(ref spec) = config.speculative {
                    args.extend_from_slice(&[
                        "--speculative-model".to_string(),
                        spec.draft_model.to_string_lossy().to_string(),
                        "--num-speculative-tokens".to_string(),
                        spec.draft_tokens.to_string(),
                    ]);
                }

                args.extend(config.extra_args.iter().cloned());
                args
            }
        }
    }

    fn select_llamacpp_image(config: &ServeConfig) -> &'static str {
        match config.gpus.first().map(|g| &g.kind) {
            Some(GpuKind::Nvidia) => "ghcr.io/ggml-org/llama.cpp:server-cuda",
            Some(GpuKind::Amd) => "ghcr.io/ggml-org/llama.cpp:server-rocm",
            _ => "ghcr.io/ggml-org/llama.cpp:server",
        }
    }

    // ── vLLM ────────────────────────────────────────────────────────────

    fn build_vllm_args(config: &ServeConfig, port: u16) -> Vec<String> {
        let mut args = vec![
            "serve".to_string(),
            config.model_path.to_string_lossy().to_string(),
            "--host".to_string(),
            config.host.clone(),
            "--port".to_string(),
            port.to_string(),
            "--max-model-len".to_string(),
            config.context_size.to_string(),
            "--max-num-seqs".to_string(),
            config.parallel.to_string(),
        ];

        let gpu_count = config.gpus.len();
        if gpu_count > 1 {
            args.extend_from_slice(&[
                "--tensor-parallel-size".to_string(),
                gpu_count.to_string(),
            ]);
        }

        if let Some(cache_type) = &config.cache_type {
            let dtype = match cache_type {
                crate::KvCacheType::F16 => "auto",
                crate::KvCacheType::Q8_0 | crate::KvCacheType::Q4_0 => "fp8",
            };
            args.extend_from_slice(&["--kv-cache-dtype".to_string(), dtype.to_string()]);
        }

        if let Some(ref spec) = config.speculative {
            args.extend_from_slice(&[
                "--speculative-model".to_string(),
                spec.draft_model.to_string_lossy().to_string(),
                "--num-speculative-tokens".to_string(),
                spec.draft_tokens.to_string(),
            ]);
        }

        args.extend(config.extra_args.iter().cloned());
        args
    }

    fn select_vllm_image(config: &ServeConfig) -> Result<&'static str, RuntimeError> {
        match config.gpus.first().map(|g| &g.kind) {
            Some(GpuKind::Nvidia) => Ok("vllm/vllm-openai:latest"),
            Some(GpuKind::Amd) => Ok("vllm/vllm-openai:latest-rocm"),
            Some(GpuKind::Intel) => Err(RuntimeError::Gpu(
                "vLLM does not support Intel GPUs".to_string(),
            )),
            None => Err(RuntimeError::Gpu(
                "vLLM requires a GPU — no GPU detected".to_string(),
            )),
        }
    }
}

impl std::fmt::Display for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GpuDevice, GpuKind, KvCacheType, SpeculativeConfig};
    use std::path::PathBuf;

    // ── llama.cpp args ──────────────────────────────────────────────────

    #[test]
    fn llamacpp_build_args_basic() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/granite.gguf"),
            host: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let args = Engine::LlamaCpp.build_serve_args(&config, 8080);
        assert_eq!(args[0], "--model");
        assert_eq!(args[1], "/models/granite.gguf");
        assert!(args.contains(&"--host".to_string()));
        assert!(args.contains(&"--ctx-size".to_string()));
        assert!(!args.contains(&"--n-gpu-layers".to_string()));
    }

    #[test]
    fn llamacpp_build_args_with_gpu() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test.gguf"),
            gpus: vec![GpuDevice {
                kind: GpuKind::Nvidia,
                index: 0,
                name: "4090".into(),
                vram: None,
            }],
            ..Default::default()
        };
        let args = Engine::LlamaCpp.build_serve_args(&config, 8080);
        assert!(args.contains(&"--n-gpu-layers".to_string()));
        assert!(args.contains(&"999".to_string()));
    }

    #[test]
    fn llamacpp_build_args_cache_type() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test.gguf"),
            cache_type: Some(KvCacheType::Q8_0),
            ..Default::default()
        };
        let args = Engine::LlamaCpp.build_serve_args(&config, 8080);
        assert!(args.contains(&"--cache-type-k".to_string()));
        assert!(args.contains(&"--cache-type-v".to_string()));
        assert!(args.contains(&"q8_0".to_string()));
    }

    #[test]
    fn llamacpp_build_args_speculative() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/main.gguf"),
            speculative: Some(SpeculativeConfig {
                draft_model: PathBuf::from("/models/draft.gguf"),
                draft_tokens: 5,
                draft_min_p: 0.1,
            }),
            ..Default::default()
        };
        let args = Engine::LlamaCpp.build_serve_args(&config, 8080);
        assert!(args.contains(&"--model-draft".to_string()));
        assert!(args.contains(&"--draft-max".to_string()));
        assert!(args.contains(&"--draft-min-p".to_string()));
    }

    // ── vLLM args ───────────────────────────────────────────────────────

    #[test]
    fn vllm_build_args_basic() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/llama-3"),
            host: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let args = Engine::Vllm.build_serve_args(&config, 8000);
        assert_eq!(args[0], "serve");
        assert_eq!(args[1], "/models/llama-3");
        assert!(args.contains(&"--max-model-len".to_string()));
        assert!(args.contains(&"--max-num-seqs".to_string()));
    }

    #[test]
    fn vllm_build_args_multi_gpu() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test"),
            gpus: vec![
                GpuDevice { kind: GpuKind::Nvidia, index: 0, name: "A100".into(), vram: None },
                GpuDevice { kind: GpuKind::Nvidia, index: 1, name: "A100".into(), vram: None },
            ],
            ..Default::default()
        };
        let args = Engine::Vllm.build_serve_args(&config, 8000);
        let tp_idx = args.iter().position(|a| a == "--tensor-parallel-size").unwrap();
        assert_eq!(args[tp_idx + 1], "2");
    }

    #[test]
    fn vllm_build_args_single_gpu_no_tp() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test"),
            gpus: vec![GpuDevice {
                kind: GpuKind::Nvidia,
                index: 0,
                name: "4090".into(),
                vram: None,
            }],
            ..Default::default()
        };
        let args = Engine::Vllm.build_serve_args(&config, 8000);
        assert!(!args.contains(&"--tensor-parallel-size".to_string()));
    }

    #[test]
    fn vllm_build_args_speculative() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/main"),
            speculative: Some(SpeculativeConfig {
                draft_model: PathBuf::from("/models/draft"),
                draft_tokens: 8,
                draft_min_p: 0.0,
            }),
            ..Default::default()
        };
        let args = Engine::Vllm.build_serve_args(&config, 8000);
        assert!(args.contains(&"--speculative-model".to_string()));
        assert!(args.contains(&"--num-speculative-tokens".to_string()));
        assert!(args.contains(&"8".to_string()));
    }

    #[test]
    fn vllm_build_args_kv_cache() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test"),
            cache_type: Some(KvCacheType::Q8_0),
            ..Default::default()
        };
        let args = Engine::Vllm.build_serve_args(&config, 8000);
        assert!(args.contains(&"--kv-cache-dtype".to_string()));
        assert!(args.contains(&"fp8".to_string()));
    }

    #[test]
    fn vllm_build_args_extra() {
        let config = ServeConfig {
            model_path: PathBuf::from("/models/test"),
            extra_args: vec!["--enforce-eager".to_string()],
            ..Default::default()
        };
        let args = Engine::Vllm.build_serve_args(&config, 8000);
        assert!(args.contains(&"--enforce-eager".to_string()));
    }

    // ── Image selection ─────────────────────────────────────────────────

    #[test]
    fn llamacpp_image_cpu() {
        let config = ServeConfig::default();
        assert_eq!(
            Engine::LlamaCpp.select_image(&config).unwrap(),
            "ghcr.io/ggml-org/llama.cpp:server"
        );
    }

    #[test]
    fn llamacpp_image_nvidia() {
        let config = ServeConfig {
            gpus: vec![GpuDevice {
                kind: GpuKind::Nvidia,
                index: 0,
                name: "4090".into(),
                vram: None,
            }],
            ..Default::default()
        };
        assert_eq!(
            Engine::LlamaCpp.select_image(&config).unwrap(),
            "ghcr.io/ggml-org/llama.cpp:server-cuda"
        );
    }

    #[test]
    fn vllm_image_nvidia() {
        let config = ServeConfig {
            gpus: vec![GpuDevice {
                kind: GpuKind::Nvidia,
                index: 0,
                name: "A100".into(),
                vram: None,
            }],
            ..Default::default()
        };
        assert_eq!(
            Engine::Vllm.select_image(&config).unwrap(),
            "vllm/vllm-openai:latest"
        );
    }

    #[test]
    fn vllm_image_amd() {
        let config = ServeConfig {
            gpus: vec![GpuDevice {
                kind: GpuKind::Amd,
                index: 0,
                name: "MI300X".into(),
                vram: None,
            }],
            ..Default::default()
        };
        assert_eq!(
            Engine::Vllm.select_image(&config).unwrap(),
            "vllm/vllm-openai:latest-rocm"
        );
    }

    #[test]
    fn vllm_image_no_gpu_errors() {
        let config = ServeConfig::default();
        assert!(Engine::Vllm.select_image(&config).is_err());
    }

    #[test]
    fn vllm_image_intel_errors() {
        let config = ServeConfig {
            gpus: vec![GpuDevice {
                kind: GpuKind::Intel,
                index: 0,
                name: "Arc".into(),
                vram: None,
            }],
            ..Default::default()
        };
        assert!(Engine::Vllm.select_image(&config).is_err());
    }

    // ── Properties ──────────────────────────────────────────────────────

    #[test]
    fn engine_properties() {
        assert_eq!(Engine::LlamaCpp.binary(), "llama-server");
        assert_eq!(Engine::Vllm.binary(), "vllm");
        assert_eq!(Engine::LlamaCpp.default_serve_port(), 8080);
        assert_eq!(Engine::Vllm.default_serve_port(), 8000);
        assert!(!Engine::LlamaCpp.requires_gpu());
        assert!(Engine::Vllm.requires_gpu());
        assert!(!Engine::LlamaCpp.needs_ipc_host());
        assert!(Engine::Vllm.needs_ipc_host());
        assert!(Engine::LlamaCpp.supports_kv_checkpoint());
        assert!(!Engine::Vllm.supports_kv_checkpoint());
    }

    #[test]
    fn engine_display() {
        assert_eq!(Engine::LlamaCpp.to_string(), "llama-cpp");
        assert_eq!(Engine::Vllm.to_string(), "vllm");
    }

    #[tokio::test]
    async fn is_available_does_not_panic() {
        let _ = Engine::LlamaCpp.is_available().await;
        let _ = Engine::Vllm.is_available().await;
    }
}
