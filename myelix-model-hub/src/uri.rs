//! Model URI parsing.
//!
//! Supports:
//! - `ollama://model:tag`
//! - `hf://org/repo` or `hf://org/repo/file.gguf`
//! - `oci://registry/org/repo:tag`
//! - `file:///absolute/path/to/model.gguf`

use crate::HubError;
use std::fmt;

/// Which registry a model comes from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Registry {
    /// Ollama model registry.
    Ollama,
    /// HuggingFace Hub.
    HuggingFace,
    /// OCI-compliant container registry.
    Oci,
    /// Local file path (no pull needed).
    File,
}

/// A parsed model URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelUri {
    /// Registry type.
    pub registry: Registry,
    /// Model path (meaning depends on registry).
    /// - Ollama: `model:tag`
    /// - HuggingFace: `org/repo` or `org/repo/file.gguf`
    /// - OCI: `registry/org/repo:tag`
    /// - File: `/absolute/path/to/model.gguf`
    pub path: String,
}

impl ModelUri {
    /// Parse a model URI string.
    pub fn parse(s: &str) -> Result<Self, HubError> {
        if let Some(path) = s.strip_prefix("ollama://") {
            if path.is_empty() {
                return Err(HubError::InvalidUri(s.to_string()));
            }
            Ok(Self {
                registry: Registry::Ollama,
                path: path.to_string(),
            })
        } else if let Some(path) = s.strip_prefix("hf://") {
            if path.is_empty() || !path.contains('/') {
                return Err(HubError::InvalidUri(s.to_string()));
            }
            Ok(Self {
                registry: Registry::HuggingFace,
                path: path.to_string(),
            })
        } else if let Some(path) = s.strip_prefix("oci://") {
            if path.is_empty() {
                return Err(HubError::InvalidUri(s.to_string()));
            }
            Ok(Self {
                registry: Registry::Oci,
                path: path.to_string(),
            })
        } else if let Some(path) = s.strip_prefix("file://") {
            if path.is_empty() {
                return Err(HubError::InvalidUri(s.to_string()));
            }
            Ok(Self {
                registry: Registry::File,
                path: path.to_string(),
            })
        } else {
            // Default: treat as Ollama shorthand (like ramalama does)
            Ok(Self {
                registry: Registry::Ollama,
                path: s.to_string(),
            })
        }
    }

    /// Returns a cache-safe key for this URI.
    pub fn cache_key(&self) -> String {
        let prefix = match self.registry {
            Registry::Ollama => "ollama",
            Registry::HuggingFace => "hf",
            Registry::Oci => "oci",
            Registry::File => "file",
        };
        let safe_path = self.path.replace('/', "_").replace(':', "_");
        format!("{prefix}_{safe_path}")
    }
}

impl fmt::Display for ModelUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.registry {
            Registry::Ollama => "ollama://",
            Registry::HuggingFace => "hf://",
            Registry::Oci => "oci://",
            Registry::File => "file://",
        };
        write!(f, "{scheme}{}", self.path)
    }
}

impl std::str::FromStr for ModelUri {
    type Err = HubError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ollama() {
        let uri = ModelUri::parse("ollama://granite-code:3b").unwrap();
        assert_eq!(uri.registry, Registry::Ollama);
        assert_eq!(uri.path, "granite-code:3b");
    }

    #[test]
    fn parse_huggingface() {
        let uri = ModelUri::parse("hf://ibm-granite/granite-3.3-8b-instruct-GGUF").unwrap();
        assert_eq!(uri.registry, Registry::HuggingFace);
        assert_eq!(uri.path, "ibm-granite/granite-3.3-8b-instruct-GGUF");
    }

    #[test]
    fn parse_oci() {
        let uri = ModelUri::parse("oci://quay.io/myorg/mymodel:latest").unwrap();
        assert_eq!(uri.registry, Registry::Oci);
        assert_eq!(uri.path, "quay.io/myorg/mymodel:latest");
    }

    #[test]
    fn parse_file() {
        let uri = ModelUri::parse("file:///tmp/model.gguf").unwrap();
        assert_eq!(uri.registry, Registry::File);
        assert_eq!(uri.path, "/tmp/model.gguf");
    }

    #[test]
    fn parse_bare_name_defaults_to_ollama() {
        let uri = ModelUri::parse("granite-code:3b").unwrap();
        assert_eq!(uri.registry, Registry::Ollama);
        assert_eq!(uri.path, "granite-code:3b");
    }

    #[test]
    fn parse_empty_ollama_fails() {
        assert!(ModelUri::parse("ollama://").is_err());
    }

    #[test]
    fn parse_hf_no_slash_fails() {
        assert!(ModelUri::parse("hf://justname").is_err());
    }

    #[test]
    fn display_roundtrip() {
        let cases = [
            "ollama://granite-code:3b",
            "hf://ibm-granite/granite-3.3-8b-instruct-GGUF",
            "oci://quay.io/myorg/mymodel:latest",
            "file:///tmp/model.gguf",
        ];
        for s in cases {
            let uri = ModelUri::parse(s).unwrap();
            assert_eq!(uri.to_string(), s);
        }
    }

    #[test]
    fn cache_key_is_safe() {
        let uri = ModelUri::parse("hf://ibm-granite/granite-3.3-8b-instruct-GGUF").unwrap();
        let key = uri.cache_key();
        assert!(!key.contains('/'));
        assert!(!key.contains(':'));
        assert!(key.starts_with("hf_"));
    }
}
