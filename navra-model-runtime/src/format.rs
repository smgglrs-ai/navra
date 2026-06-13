//! Model format detection and compatibility.
//!
//! [`ModelFormat`] identifies the serialization format of a model
//! (GGUF, safetensors, AWQ, GPTQ). Format determines which engines
//! can serve it and influences runtime selection in `auto_runtime()`.

use crate::engine::Engine;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Model serialization format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelFormat {
    /// GGUF (llama.cpp native format). Single file, quantized.
    Gguf,
    /// Safetensors (HuggingFace format). Directory with model shards.
    Safetensors,
    /// AWQ quantized model (4-bit, activation-aware).
    Awq,
    /// GPTQ quantized model (4-bit, post-training).
    Gptq,
}

impl ModelFormat {
    /// Detect format from a model path.
    ///
    /// - `.gguf` extension → GGUF
    /// - Directory with `quantize_config.json` → GPTQ
    /// - Directory with `quant_config.json` → AWQ
    /// - Directory with `*.safetensors` files → Safetensors
    /// - Otherwise → None
    pub fn detect(path: &Path) -> Option<Self> {
        if path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("gguf"))
            .unwrap_or(false)
        {
            return Some(Self::Gguf);
        }

        if path.is_dir() {
            if path.join("quantize_config.json").exists() {
                return Some(Self::Gptq);
            }
            if path.join("quant_config.json").exists() {
                return Some(Self::Awq);
            }
            let has_safetensors = std::fs::read_dir(path)
                .ok()
                .map(|entries| {
                    entries.flatten().any(|e| {
                        e.path()
                            .extension()
                            .map(|ext| ext == "safetensors")
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            if has_safetensors {
                return Some(Self::Safetensors);
            }
        }

        None
    }

    /// Whether an engine supports this format.
    pub fn is_supported_by(&self, engine: &Engine) -> bool {
        match (self, engine) {
            (Self::Gguf, Engine::LlamaCpp) => true,
            (Self::Gguf, Engine::Vllm) => true,
            (Self::Safetensors, Engine::Vllm) => true,
            (Self::Awq, Engine::Vllm) => true,
            (Self::Gptq, Engine::Vllm) => true,
            (Self::Safetensors, Engine::LlamaCpp) => false,
            (Self::Awq, Engine::LlamaCpp) => false,
            (Self::Gptq, Engine::LlamaCpp) => false,
        }
    }
}

impl std::fmt::Display for ModelFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gguf => f.write_str("gguf"),
            Self::Safetensors => f.write_str("safetensors"),
            Self::Awq => f.write_str("awq"),
            Self::Gptq => f.write_str("gptq"),
        }
    }
}

impl std::str::FromStr for ModelFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gguf" => Ok(Self::Gguf),
            "safetensors" => Ok(Self::Safetensors),
            "awq" => Ok(Self::Awq),
            "gptq" => Ok(Self::Gptq),
            other => Err(format!(
                "unknown model format: {other} (expected gguf, safetensors, awq, or gptq)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detect_gguf() {
        assert_eq!(
            ModelFormat::detect(&PathBuf::from("/models/granite.gguf")),
            Some(ModelFormat::Gguf)
        );
        assert_eq!(
            ModelFormat::detect(&PathBuf::from("/models/model.GGUF")),
            Some(ModelFormat::Gguf)
        );
    }

    #[test]
    fn detect_unknown() {
        assert_eq!(
            ModelFormat::detect(&PathBuf::from("/models/unknown.bin")),
            None
        );
    }

    #[test]
    fn detect_safetensors_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("model-00001.safetensors"), b"").unwrap();
        assert_eq!(
            ModelFormat::detect(dir.path()),
            Some(ModelFormat::Safetensors)
        );
    }

    #[test]
    fn detect_gptq_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("quantize_config.json"), b"{}").unwrap();
        assert_eq!(ModelFormat::detect(dir.path()), Some(ModelFormat::Gptq));
    }

    #[test]
    fn detect_awq_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("quant_config.json"), b"{}").unwrap();
        assert_eq!(ModelFormat::detect(dir.path()), Some(ModelFormat::Awq));
    }

    #[test]
    fn compatibility_matrix() {
        assert!(ModelFormat::Gguf.is_supported_by(&Engine::LlamaCpp));
        assert!(ModelFormat::Gguf.is_supported_by(&Engine::Vllm));
        assert!(!ModelFormat::Safetensors.is_supported_by(&Engine::LlamaCpp));
        assert!(ModelFormat::Safetensors.is_supported_by(&Engine::Vllm));
        assert!(!ModelFormat::Awq.is_supported_by(&Engine::LlamaCpp));
        assert!(ModelFormat::Awq.is_supported_by(&Engine::Vllm));
        assert!(!ModelFormat::Gptq.is_supported_by(&Engine::LlamaCpp));
        assert!(ModelFormat::Gptq.is_supported_by(&Engine::Vllm));
    }

    #[test]
    fn display() {
        assert_eq!(ModelFormat::Gguf.to_string(), "gguf");
        assert_eq!(ModelFormat::Safetensors.to_string(), "safetensors");
        assert_eq!(ModelFormat::Awq.to_string(), "awq");
        assert_eq!(ModelFormat::Gptq.to_string(), "gptq");
    }

    #[test]
    fn from_str() {
        assert_eq!("gguf".parse::<ModelFormat>().unwrap(), ModelFormat::Gguf);
        assert_eq!(
            "safetensors".parse::<ModelFormat>().unwrap(),
            ModelFormat::Safetensors
        );
        assert_eq!("awq".parse::<ModelFormat>().unwrap(), ModelFormat::Awq);
        assert_eq!("gptq".parse::<ModelFormat>().unwrap(), ModelFormat::Gptq);
        assert!("unknown".parse::<ModelFormat>().is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let json = serde_json::to_string(&ModelFormat::Safetensors).unwrap();
        assert_eq!(json, "\"safetensors\"");
        let back: ModelFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ModelFormat::Safetensors);
    }
}
