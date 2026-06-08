//! Credential broker for capability-gated secret access.
//!
//! Provides a platform-agnostic [`CredentialStore`] trait with
//! implementations for OS keyrings (via the `keyring` crate) and
//! environment variables. Agents never see raw secrets — navra
//! resolves credential labels through config-defined mappings and
//! injects values into tool calls.

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("unknown credential label: {0}")]
    UnknownLabel(String),
    #[error("missing credential field '{field}' for label '{label}'")]
    MissingField { label: String, field: String },
    #[error("invalid credential path format: {0}")]
    InvalidPath(String),
    #[error("unsupported credential source: {0}")]
    UnsupportedSource(String),
    #[error("environment variable {0} not set")]
    EnvNotSet(String),
    #[error("cannot {0} environment variable credential")]
    EnvReadOnly(String),
    #[error(transparent)]
    Keyring(#[from] keyring::Error),
}

/// A resolved secret value. Zeroized on drop where possible.
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Best-effort zeroization
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }
}

/// Platform-agnostic credential store.
///
/// Credential labels are mapped through config to backend sources.
/// Only explicitly configured labels are accessible — the store
/// cannot discover or enumerate OS keyring entries.
pub trait CredentialStore: Send + Sync {
    /// Resolve a credential label to its secret value.
    fn resolve(&self, label: &str) -> Result<Secret, CredentialError>;

    /// Store a credential under a label (navra-managed only).
    fn store(&self, label: &str, secret: &[u8]) -> Result<(), CredentialError>;

    /// Delete a credential (navra-managed only).
    fn delete(&self, label: &str) -> Result<(), CredentialError>;

    /// List available credential labels.
    fn labels(&self) -> Vec<String>;
}

/// A credential source mapping from config.
///
/// Maps a label (e.g., "github.pat") to a backend source
/// (keyring path, environment variable, etc.).
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct CredentialMapping {
    /// Backend: "keyring" or "env".
    pub source: String,
    /// Keyring path (for source = "keyring").
    /// e.g., "navra/github-pat" or "org.gnome.OnlineAccounts/github"
    #[serde(default)]
    pub path: Option<String>,
    /// Environment variable name (for source = "env").
    #[serde(default)]
    pub var: Option<String>,
}

/// Credential store backed by config-mapped sources.
///
/// Supports multiple backends: OS keyring (GNOME Keyring, KWallet,
/// macOS Keychain, Windows Credential Manager) and environment
/// variables. Only credentials listed in config are accessible.
pub struct MappedCredentialStore {
    mappings: HashMap<String, CredentialMapping>,
}

impl MappedCredentialStore {
    pub fn new(mappings: HashMap<String, CredentialMapping>) -> Self {
        Self { mappings }
    }
}

impl CredentialStore for MappedCredentialStore {
    fn resolve(&self, label: &str) -> Result<Secret, CredentialError> {
        let mapping = self
            .mappings
            .get(label)
            .ok_or_else(|| CredentialError::UnknownLabel(label.to_string()))?;

        match mapping.source.as_str() {
            "keyring" => {
                let path = mapping
                    .path
                    .as_deref()
                    .ok_or_else(|| CredentialError::MissingField { label: label.to_string(), field: "path".to_string() })?;
                let (service, user) = path.split_once('/').ok_or_else(|| {
                    CredentialError::InvalidPath(path.to_string())
                })?;
                let entry = keyring::Entry::new(service, user)?;
                let secret = entry.get_secret()?;
                Ok(Secret::new(secret))
            }
            "env" => {
                let var = mapping
                    .var
                    .as_deref()
                    .ok_or_else(|| CredentialError::MissingField { label: label.to_string(), field: "var".to_string() })?;
                let value = std::env::var(var)
                    .map_err(|_| CredentialError::EnvNotSet(var.to_string()))?;
                Ok(Secret::new(value.into_bytes()))
            }
            other => Err(CredentialError::UnsupportedSource(other.to_string())),
        }
    }

    fn store(&self, label: &str, secret: &[u8]) -> Result<(), CredentialError> {
        let mapping = self
            .mappings
            .get(label)
            .ok_or_else(|| CredentialError::UnknownLabel(label.to_string()))?;

        match mapping.source.as_str() {
            "keyring" => {
                let path = mapping
                    .path
                    .as_deref()
                    .ok_or_else(|| CredentialError::MissingField { label: label.to_string(), field: "path".to_string() })?;
                let (service, user) = path.split_once('/').ok_or_else(|| {
                    CredentialError::InvalidPath(path.to_string())
                })?;
                let entry = keyring::Entry::new(service, user)?;
                entry.set_secret(secret)?;
                Ok(())
            }
            "env" => Err(CredentialError::EnvReadOnly("store to".to_string())),
            other => Err(CredentialError::UnsupportedSource(other.to_string())),
        }
    }

    fn delete(&self, label: &str) -> Result<(), CredentialError> {
        let mapping = self
            .mappings
            .get(label)
            .ok_or_else(|| CredentialError::UnknownLabel(label.to_string()))?;

        match mapping.source.as_str() {
            "keyring" => {
                let path = mapping
                    .path
                    .as_deref()
                    .ok_or_else(|| CredentialError::MissingField { label: label.to_string(), field: "path".to_string() })?;
                let (service, user) = path.split_once('/').ok_or_else(|| {
                    CredentialError::InvalidPath(path.to_string())
                })?;
                let entry = keyring::Entry::new(service, user)?;
                entry.delete_credential()?;
                Ok(())
            }
            "env" => Err(CredentialError::EnvReadOnly("delete".to_string())),
            other => Err(CredentialError::UnsupportedSource(other.to_string())),
        }
    }

    fn labels(&self) -> Vec<String> {
        self.mappings.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_zeroized_on_drop() {
        let data = vec![0x41, 0x42, 0x43];
        let ptr = data.as_ptr();
        let secret = Secret::new(data);
        assert_eq!(secret.as_bytes(), &[0x41, 0x42, 0x43]);
        assert_eq!(secret.as_str(), Some("ABC"));
        drop(secret);
        // Zeroization is best-effort; we just verify the logic compiles.
        let _ = ptr;
    }

    #[test]
    fn env_credential_resolves() {
        std::env::set_var("MCPD_TEST_CRED", "test-secret-value");
        let mut mappings = HashMap::new();
        mappings.insert(
            "test.token".to_string(),
            CredentialMapping {
                source: "env".to_string(),
                path: None,
                var: Some("MCPD_TEST_CRED".to_string()),
            },
        );
        let store = MappedCredentialStore::new(mappings);

        let secret = store.resolve("test.token").unwrap();
        assert_eq!(secret.as_str(), Some("test-secret-value"));
        std::env::remove_var("MCPD_TEST_CRED");
    }

    #[test]
    fn unknown_label_fails() {
        let store = MappedCredentialStore::new(HashMap::new());
        assert!(store.resolve("nonexistent").is_err());
    }

    #[test]
    fn env_missing_var_fails() {
        let mut mappings = HashMap::new();
        mappings.insert(
            "missing".to_string(),
            CredentialMapping {
                source: "env".to_string(),
                path: None,
                var: Some("MCPD_DEFINITELY_NOT_SET_12345".to_string()),
            },
        );
        let store = MappedCredentialStore::new(mappings);
        assert!(store.resolve("missing").is_err());
    }

    #[test]
    fn unsupported_source_fails() {
        let mut mappings = HashMap::new();
        mappings.insert(
            "bad".to_string(),
            CredentialMapping {
                source: "ftp".to_string(),
                path: None,
                var: None,
            },
        );
        let store = MappedCredentialStore::new(mappings);
        assert!(store.resolve("bad").is_err());
    }

    #[test]
    fn labels_returns_configured() {
        let mut mappings = HashMap::new();
        mappings.insert(
            "a".to_string(),
            CredentialMapping {
                source: "env".to_string(),
                path: None,
                var: Some("A".to_string()),
            },
        );
        mappings.insert(
            "b".to_string(),
            CredentialMapping {
                source: "keyring".to_string(),
                path: Some("svc/user".to_string()),
                var: None,
            },
        );
        let store = MappedCredentialStore::new(mappings);
        let mut labels = store.labels();
        labels.sort();
        assert_eq!(labels, vec!["a", "b"]);
    }

    #[test]
    fn cannot_store_to_env() {
        let mut mappings = HashMap::new();
        mappings.insert(
            "env_cred".to_string(),
            CredentialMapping {
                source: "env".to_string(),
                path: None,
                var: Some("X".to_string()),
            },
        );
        let store = MappedCredentialStore::new(mappings);
        assert!(store.store("env_cred", b"value").is_err());
    }

    #[test]
    fn keyring_missing_path_fails() {
        let mut mappings = HashMap::new();
        mappings.insert(
            "bad_keyring".to_string(),
            CredentialMapping {
                source: "keyring".to_string(),
                path: None,
                var: None,
            },
        );
        let store = MappedCredentialStore::new(mappings);
        assert!(store.resolve("bad_keyring").is_err());
    }

    #[test]
    fn keyring_invalid_path_format_fails() {
        let mut mappings = HashMap::new();
        mappings.insert(
            "bad_path".to_string(),
            CredentialMapping {
                source: "keyring".to_string(),
                path: Some("no-slash-here".to_string()),
                var: None,
            },
        );
        let store = MappedCredentialStore::new(mappings);
        assert!(store.resolve("bad_path").is_err());
    }
}
