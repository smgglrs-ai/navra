//! Hardware target abstraction.
//!
//! [`HardwareTarget`] represents the accelerator a model runs on.
//! It centralizes container image selection, Podman device passthrough,
//! and hardware compatibility checks that were previously scattered
//! across `Engine` methods and runtime implementations.

use crate::engine::Engine;
use crate::gpu::{GpuDevice, GpuKind};
use crate::RuntimeError;
use serde::{Deserialize, Serialize};

/// Hardware accelerator target for model inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HardwareTarget {
    /// CPU-only inference (no accelerator).
    Cpu,
    /// NVIDIA GPU (CUDA).
    Nvidia,
    /// AMD GPU (ROCm).
    Amd,
    /// Intel GPU (oneAPI / Level Zero).
    Intel,
}

impl HardwareTarget {
    /// Derive hardware target from detected GPUs.
    ///
    /// Uses the first GPU's vendor. Returns `Cpu` if the list is empty.
    pub fn from_gpus(gpus: &[GpuDevice]) -> Self {
        match gpus.first().map(|g| &g.kind) {
            Some(GpuKind::Nvidia) => Self::Nvidia,
            Some(GpuKind::Amd) => Self::Amd,
            Some(GpuKind::Intel) => Self::Intel,
            None => Self::Cpu,
        }
    }

    /// Whether this target is a GPU (not CPU-only).
    pub fn is_gpu(&self) -> bool {
        !matches!(self, Self::Cpu)
    }

    /// Select the container image for a given engine on this hardware.
    pub fn container_image(&self, engine: &Engine) -> Result<&'static str, RuntimeError> {
        match (engine, self) {
            // llama.cpp supports all targets
            (Engine::LlamaCpp, Self::Nvidia) => Ok("ghcr.io/ggml-org/llama.cpp:server-cuda"),
            (Engine::LlamaCpp, Self::Amd) => Ok("ghcr.io/ggml-org/llama.cpp:server-rocm"),
            (Engine::LlamaCpp, _) => Ok("ghcr.io/ggml-org/llama.cpp:server"),

            // vLLM requires a GPU
            (Engine::Vllm, Self::Nvidia) => Ok("vllm/vllm-openai:latest"),
            (Engine::Vllm, Self::Amd) => Ok("vllm/vllm-openai:latest-rocm"),
            (Engine::Vllm, Self::Intel) => Err(RuntimeError::Gpu(
                "vLLM does not support Intel GPUs".to_string(),
            )),
            (Engine::Vllm, Self::Cpu) => Err(RuntimeError::Gpu(
                "vLLM requires a GPU — no GPU detected".to_string(),
            )),
        }
    }

    /// Generate Podman `--device` arguments for GPU passthrough.
    pub fn podman_device_args(&self, index: u32) -> Vec<String> {
        match self {
            Self::Nvidia => {
                vec!["--device".to_string(), format!("nvidia.com/gpu={index}")]
            }
            Self::Amd => {
                vec![
                    "--device".to_string(),
                    "/dev/kfd".to_string(),
                    "--device".to_string(),
                    format!("/dev/dri/renderD{}", 128 + index),
                ]
            }
            Self::Intel => {
                vec![
                    "--device".to_string(),
                    format!("/dev/dri/renderD{}", 128 + index),
                ]
            }
            Self::Cpu => vec![],
        }
    }
}

impl std::fmt::Display for HardwareTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cpu => f.write_str("cpu"),
            Self::Nvidia => f.write_str("nvidia"),
            Self::Amd => f.write_str("amd"),
            Self::Intel => f.write_str("intel"),
        }
    }
}

impl std::str::FromStr for HardwareTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cpu" => Ok(Self::Cpu),
            "nvidia" | "cuda" => Ok(Self::Nvidia),
            "amd" | "rocm" => Ok(Self::Amd),
            "intel" => Ok(Self::Intel),
            other => Err(format!(
                "unknown hardware target: {other} (expected cpu, nvidia, amd, or intel)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::{GpuDevice, GpuKind};

    #[test]
    fn from_gpus_empty() {
        assert_eq!(HardwareTarget::from_gpus(&[]), HardwareTarget::Cpu);
    }

    #[test]
    fn from_gpus_nvidia() {
        let gpus = vec![GpuDevice {
            kind: GpuKind::Nvidia,
            index: 0,
            name: "RTX 4090".into(),
            vram: None,
        }];
        assert_eq!(HardwareTarget::from_gpus(&gpus), HardwareTarget::Nvidia);
    }

    #[test]
    fn from_gpus_amd() {
        let gpus = vec![GpuDevice {
            kind: GpuKind::Amd,
            index: 0,
            name: "MI300X".into(),
            vram: None,
        }];
        assert_eq!(HardwareTarget::from_gpus(&gpus), HardwareTarget::Amd);
    }

    #[test]
    fn from_gpus_intel() {
        let gpus = vec![GpuDevice {
            kind: GpuKind::Intel,
            index: 0,
            name: "Arc".into(),
            vram: None,
        }];
        assert_eq!(HardwareTarget::from_gpus(&gpus), HardwareTarget::Intel);
    }

    #[test]
    fn is_gpu() {
        assert!(!HardwareTarget::Cpu.is_gpu());
        assert!(HardwareTarget::Nvidia.is_gpu());
        assert!(HardwareTarget::Amd.is_gpu());
        assert!(HardwareTarget::Intel.is_gpu());
    }

    #[test]
    fn container_image_llamacpp() {
        assert_eq!(
            HardwareTarget::Cpu
                .container_image(&Engine::LlamaCpp)
                .unwrap(),
            "ghcr.io/ggml-org/llama.cpp:server"
        );
        assert_eq!(
            HardwareTarget::Nvidia
                .container_image(&Engine::LlamaCpp)
                .unwrap(),
            "ghcr.io/ggml-org/llama.cpp:server-cuda"
        );
        assert_eq!(
            HardwareTarget::Amd
                .container_image(&Engine::LlamaCpp)
                .unwrap(),
            "ghcr.io/ggml-org/llama.cpp:server-rocm"
        );
        assert_eq!(
            HardwareTarget::Intel
                .container_image(&Engine::LlamaCpp)
                .unwrap(),
            "ghcr.io/ggml-org/llama.cpp:server"
        );
    }

    #[test]
    fn container_image_vllm() {
        assert_eq!(
            HardwareTarget::Nvidia
                .container_image(&Engine::Vllm)
                .unwrap(),
            "vllm/vllm-openai:latest"
        );
        assert_eq!(
            HardwareTarget::Amd.container_image(&Engine::Vllm).unwrap(),
            "vllm/vllm-openai:latest-rocm"
        );
        assert!(HardwareTarget::Intel
            .container_image(&Engine::Vllm)
            .is_err());
        assert!(HardwareTarget::Cpu.container_image(&Engine::Vllm).is_err());
    }

    #[test]
    fn podman_device_args_nvidia() {
        let args = HardwareTarget::Nvidia.podman_device_args(0);
        assert_eq!(args, vec!["--device", "nvidia.com/gpu=0"]);
    }

    #[test]
    fn podman_device_args_amd() {
        let args = HardwareTarget::Amd.podman_device_args(0);
        assert_eq!(
            args,
            vec!["--device", "/dev/kfd", "--device", "/dev/dri/renderD128"]
        );
    }

    #[test]
    fn podman_device_args_intel() {
        let args = HardwareTarget::Intel.podman_device_args(1);
        assert_eq!(args, vec!["--device", "/dev/dri/renderD129"]);
    }

    #[test]
    fn podman_device_args_cpu() {
        assert!(HardwareTarget::Cpu.podman_device_args(0).is_empty());
    }

    #[test]
    fn display() {
        assert_eq!(HardwareTarget::Cpu.to_string(), "cpu");
        assert_eq!(HardwareTarget::Nvidia.to_string(), "nvidia");
        assert_eq!(HardwareTarget::Amd.to_string(), "amd");
        assert_eq!(HardwareTarget::Intel.to_string(), "intel");
    }

    #[test]
    fn from_str() {
        assert_eq!(
            "cpu".parse::<HardwareTarget>().unwrap(),
            HardwareTarget::Cpu
        );
        assert_eq!(
            "nvidia".parse::<HardwareTarget>().unwrap(),
            HardwareTarget::Nvidia
        );
        assert_eq!(
            "cuda".parse::<HardwareTarget>().unwrap(),
            HardwareTarget::Nvidia
        );
        assert_eq!(
            "amd".parse::<HardwareTarget>().unwrap(),
            HardwareTarget::Amd
        );
        assert_eq!(
            "rocm".parse::<HardwareTarget>().unwrap(),
            HardwareTarget::Amd
        );
        assert_eq!(
            "intel".parse::<HardwareTarget>().unwrap(),
            HardwareTarget::Intel
        );
        assert!("unknown".parse::<HardwareTarget>().is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let json = serde_json::to_string(&HardwareTarget::Nvidia).unwrap();
        assert_eq!(json, "\"nvidia\"");
        let back: HardwareTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(back, HardwareTarget::Nvidia);
    }
}
