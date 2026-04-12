//! Local model cache using content-addressed storage.
//!
//! Layout:
//! ```text
//! ~/.local/share/myelix/models/
//! ├── blobs/
//! │   └── sha256-<hash>           # raw model files by content hash
//! └── refs/
//!     └── ollama_granite-code_3b  # symlink → ../blobs/sha256-<hash>
//! ```

use crate::error::HubError;
use crate::uri::ModelUri;
use crate::CachedModel;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Content-addressed model cache.
pub struct ModelCache {
    root: PathBuf,
    blobs: PathBuf,
    refs: PathBuf,
}

impl ModelCache {
    /// Create or open a cache at the given directory.
    pub fn new(root: PathBuf) -> Result<Self, HubError> {
        let blobs = root.join("blobs");
        let refs = root.join("refs");
        fs::create_dir_all(&blobs)?;
        fs::create_dir_all(&refs)?;
        Ok(Self { root, blobs, refs })
    }

    /// Look up a model by URI. Returns the blob path if cached.
    pub fn lookup(&self, uri: &ModelUri) -> Result<Option<PathBuf>, HubError> {
        let ref_path = self.refs.join(uri.cache_key());
        if ref_path.exists() {
            let target = fs::read_link(&ref_path)?;
            // Resolve relative symlink
            let blob_path = if target.is_relative() {
                self.refs.join(&target)
            } else {
                target
            };
            if blob_path.exists() {
                return Ok(Some(blob_path));
            }
            // Dangling symlink — clean it up
            tracing::warn!(uri = %uri, "Dangling cache ref, removing");
            let _ = fs::remove_file(&ref_path);
        }
        Ok(None)
    }

    /// Store model data in the cache, returning the blob path.
    pub fn store(&self, uri: &ModelUri, data: &[u8]) -> Result<PathBuf, HubError> {
        let hash = sha256_hex(data);
        let blob_name = format!("sha256-{hash}");
        let blob_path = self.blobs.join(&blob_name);

        if !blob_path.exists() {
            // Write to temp then rename for atomicity
            let tmp_path = self.blobs.join(format!(".tmp-{blob_name}"));
            fs::write(&tmp_path, data)?;
            fs::rename(&tmp_path, &blob_path)?;
            tracing::debug!(hash = %hash, size = data.len(), "Stored blob");
        }

        // Create/update ref symlink
        let ref_path = self.refs.join(uri.cache_key());
        let _ = fs::remove_file(&ref_path);
        let relative_target = PathBuf::from("..").join("blobs").join(&blob_name);
        std::os::unix::fs::symlink(&relative_target, &ref_path)?;

        Ok(blob_path)
    }

    /// List all cached models.
    pub fn list(&self) -> Result<Vec<CachedModel>, HubError> {
        let mut models = Vec::new();
        for entry in fs::read_dir(&self.refs)? {
            let entry = entry?;
            let ref_path = entry.path();
            if let Ok(target) = fs::read_link(&ref_path) {
                let blob_path = if target.is_relative() {
                    self.refs.join(&target)
                } else {
                    target
                };
                if let Ok(meta) = fs::metadata(&blob_path) {
                    models.push(CachedModel {
                        uri: entry.file_name().to_string_lossy().to_string(),
                        path: blob_path,
                        size: meta.len(),
                    });
                }
            }
        }
        Ok(models)
    }

    /// Remove a model from cache.
    pub fn remove(&self, uri: &ModelUri) -> Result<(), HubError> {
        let ref_path = self.refs.join(uri.cache_key());
        if ref_path.exists() {
            // Resolve blob before removing ref
            if let Ok(target) = fs::read_link(&ref_path) {
                let blob_path = if target.is_relative() {
                    self.refs.join(&target)
                } else {
                    target
                };
                // Only remove blob if no other refs point to it
                if self.ref_count(&blob_path)? <= 1 {
                    let _ = fs::remove_file(&blob_path);
                }
            }
            fs::remove_file(&ref_path)?;
        }
        Ok(())
    }

    /// Count how many refs point to a given blob.
    fn ref_count(&self, blob_path: &Path) -> Result<usize, HubError> {
        let canonical = fs::canonicalize(blob_path).unwrap_or_else(|_| blob_path.to_path_buf());
        let mut count = 0;
        for entry in fs::read_dir(&self.refs)? {
            let entry = entry?;
            if let Ok(target) = fs::read_link(entry.path()) {
                let resolved = if target.is_relative() {
                    self.refs.join(&target)
                } else {
                    target
                };
                if let Ok(resolved_canonical) = fs::canonicalize(&resolved) {
                    if resolved_canonical == canonical {
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    /// Returns the cache root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uri::{ModelUri, Registry};

    #[test]
    fn store_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ModelCache::new(dir.path().to_path_buf()).unwrap();
        let uri = ModelUri {
            registry: Registry::Ollama,
            path: "test:latest".to_string(),
        };

        // Not cached yet
        assert!(cache.lookup(&uri).unwrap().is_none());

        // Store
        let data = b"fake model data";
        let path = cache.store(&uri, data).unwrap();
        assert!(path.exists());

        // Now cached
        let found = cache.lookup(&uri).unwrap().unwrap();
        assert_eq!(fs::read(&found).unwrap(), data);
    }

    #[test]
    fn list_models() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ModelCache::new(dir.path().to_path_buf()).unwrap();

        let uri1 = ModelUri::parse("ollama://model-a:latest").unwrap();
        let uri2 = ModelUri::parse("hf://org/model-b").unwrap();
        cache.store(&uri1, b"data-a").unwrap();
        cache.store(&uri2, b"data-b").unwrap();

        let models = cache.list().unwrap();
        assert_eq!(models.len(), 2);
    }

    #[test]
    fn remove_model() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ModelCache::new(dir.path().to_path_buf()).unwrap();
        let uri = ModelUri::parse("ollama://removeme:latest").unwrap();

        cache.store(&uri, b"data").unwrap();
        assert!(cache.lookup(&uri).unwrap().is_some());

        cache.remove(&uri).unwrap();
        assert!(cache.lookup(&uri).unwrap().is_none());
    }

    #[test]
    fn dedup_same_content() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ModelCache::new(dir.path().to_path_buf()).unwrap();

        let uri1 = ModelUri::parse("ollama://model-a:latest").unwrap();
        let uri2 = ModelUri::parse("ollama://model-b:latest").unwrap();
        let data = b"identical content";

        let path1 = cache.store(&uri1, data).unwrap();
        let path2 = cache.store(&uri2, data).unwrap();

        // Same blob
        assert_eq!(path1, path2);

        // Remove one ref, blob stays
        cache.remove(&uri1).unwrap();
        assert!(path2.exists());

        // Remove last ref, blob goes
        cache.remove(&uri2).unwrap();
        assert!(!path2.exists());
    }
}
