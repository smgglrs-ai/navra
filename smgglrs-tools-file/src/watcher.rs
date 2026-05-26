//! File watcher for automatic document re-indexing.
//!
//! Watches configured directories for file changes using the `notify`
//! crate and automatically updates the SQLite FTS5 index when files
//! are created, modified, or deleted.

use crate::store::IndexStore;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use smgglrs_core::models::ModelBackend;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Start watching directories for file changes.
///
/// Returns a handle that keeps the watcher alive. Drop the handle to
/// stop watching. File changes are processed in a background tokio task.
/// If an embedding model is provided, generates embeddings for indexed files.
pub fn start_watcher(
    directories: Vec<PathBuf>,
    index: Arc<IndexStore>,
) -> Result<WatcherHandle, notify::Error> {
    start_watcher_with_embeddings(directories, index, None)
}

/// Start watching with optional embedding model.
pub fn start_watcher_with_embeddings(
    directories: Vec<PathBuf>,
    index: Arc<IndexStore>,
    embedding_model: Option<Arc<dyn ModelBackend>>,
) -> Result<WatcherHandle, notify::Error> {
    let (tx, rx) = std::sync::mpsc::channel();

    let mut watcher = RecommendedWatcher::new(
        move |result: Result<Event, notify::Error>| {
            if let Ok(event) = result {
                let _ = tx.send(event);
            }
        },
        notify::Config::default(),
    )?;

    for dir in &directories {
        if dir.exists() {
            watcher.watch(dir, RecursiveMode::Recursive)?;
            tracing::info!(path = %dir.display(), "Watching directory for changes");
        } else {
            tracing::warn!(path = %dir.display(), "Watch directory does not exist, skipping");
        }
    }

    // Spawn background task to process events.
    // Use spawn_blocking because std::sync::mpsc::Receiver::recv() blocks.
    let task = tokio::task::spawn_blocking(move || process_events(rx, index, embedding_model));

    Ok(WatcherHandle {
        _watcher: watcher,
        _task: task,
    })
}

/// Handle that keeps the file watcher alive. Drop to stop watching.
pub struct WatcherHandle {
    _watcher: RecommendedWatcher,
    _task: tokio::task::JoinHandle<()>, // spawn_blocking returns JoinHandle<T>
}

/// Process file system events and update the index.
fn process_events(
    rx: std::sync::mpsc::Receiver<Event>,
    index: Arc<IndexStore>,
    embedding_model: Option<Arc<dyn ModelBackend>>,
) {
    while let Ok(event) = rx.recv() {
        for path in &event.paths {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    // For create/modify, file must exist and be indexable
                    if !is_indexable(path) {
                        continue;
                    }
                    index_file(path, &index, embedding_model.as_ref());
                }
                EventKind::Remove(_) => {
                    // For remove, only check name (file no longer exists)
                    if !has_indexable_name(path) {
                        continue;
                    }
                    let path_str = path.to_string_lossy();
                    match index.delete(&path_str) {
                        Ok(true) => {
                            tracing::debug!(path = %path_str, "Removed from index (file deleted)");
                        }
                        Ok(false) => {} // wasn't indexed
                        Err(e) => {
                            tracing::warn!(path = %path_str, error = %e, "Failed to remove from index");
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Index a single file into the store, optionally generating an embedding.
fn index_file(path: &Path, index: &IndexStore, embedding_model: Option<&Arc<dyn ModelBackend>>) {
    let path_str = path.to_string_lossy().to_string();

    // Read file content
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return, // binary file or read error — skip
    };

    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };

    let size = metadata.len() as i64;
    let modified_at = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();

    let mime_type = mime_from_ext(path);
    let title = extract_title(path, &content);
    let checksum = blake3::hash(content.as_bytes()).to_hex().to_string();

    match index.upsert(
        &path_str,
        mime_type,
        size,
        &modified_at,
        &checksum,
        &title,
        &content,
    ) {
        Ok(doc_id) => {
            tracing::debug!(path = %path_str, "Indexed file (watcher)");

            // Generate embedding if model is available
            if let Some(model) = embedding_model {
                if index.has_vectors() {
                    let request = smgglrs_core::models::EmbedRequest {
                        text: content.clone(),
                    };
                    // We're in spawn_blocking, so use Handle::block_on for async
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        match handle.block_on(model.embed(&request)) {
                            Ok(response) => {
                                if let Err(e) = index.upsert_embedding(doc_id, &response.embedding)
                                {
                                    tracing::warn!(path = %path_str, error = %e, "Failed to store embedding");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(path = %path_str, error = %e, "Failed to generate embedding");
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(path = %path_str, error = %e, "Failed to index file");
        }
    }
}

/// Check if a path should be indexed (must exist as a file).
fn is_indexable(path: &Path) -> bool {
    path.is_file() && has_indexable_name(path)
}

/// Check if a path name/extension is indexable (no filesystem check).
fn has_indexable_name(path: &Path) -> bool {
    // Skip hidden files (filename starts with '.')
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.starts_with('.') {
            return false;
        }
    }

    // Only index text-like files
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some(
            "md" | "markdown"
                | "txt"
                | "html"
                | "htm"
                | "json"
                | "csv"
                | "rs"
                | "py"
                | "go"
                | "c"
                | "h"
                | "toml"
                | "yaml"
                | "yml"
                | "xml"
                | "sh"
                | "bash"
                | "zsh"
                | "js"
                | "ts"
                | "css"
                | "sql"
                | "rb"
                | "java"
                | "kt"
                | "swift"
                | "lua"
                | "r"
                | "tex"
                | "bib"
                | "ini"
                | "cfg"
                | "conf"
                | "env"
                | "dockerfile"
                | "makefile"
        ) | None // extensionless files (README, Makefile, etc.)
    )
}

fn mime_from_ext(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("md" | "markdown") => "text/markdown",
        Some("txt") => "text/plain",
        Some("html" | "htm") => "text/html",
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("rs") => "text/x-rust",
        Some("py") => "text/x-python",
        Some("go") => "text/x-go",
        Some("toml") => "application/toml",
        Some("yaml" | "yml") => "application/yaml",
        Some("xml") => "application/xml",
        _ => "text/plain",
    }
}

fn extract_title(path: &Path, content: &str) -> String {
    for line in content.lines().take(10) {
        let trimmed = line.trim();
        if let Some(heading) = trimmed.strip_prefix("# ") {
            return heading.trim().to_string();
        }
    }
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("untitled")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexable_markdown() {
        assert!(has_indexable_name(Path::new("/tmp/test.md")));
    }

    #[test]
    fn indexable_rust() {
        assert!(has_indexable_name(Path::new("/tmp/main.rs")));
    }

    #[test]
    fn not_indexable_hidden() {
        assert!(!has_indexable_name(Path::new("/tmp/docs/.gitignore")));
        assert!(!has_indexable_name(Path::new("/tmp/.env")));
    }

    #[test]
    fn not_indexable_binary() {
        assert!(!has_indexable_name(Path::new("/tmp/image.png")));
    }

    #[test]
    fn mime_from_ext_markdown() {
        assert_eq!(mime_from_ext(Path::new("test.md")), "text/markdown");
    }

    #[test]
    fn mime_from_ext_unknown() {
        assert_eq!(mime_from_ext(Path::new("test.xyz")), "text/plain");
    }

    #[test]
    fn extract_title_from_heading() {
        let title = extract_title(Path::new("test.md"), "# My Title\nContent");
        assert_eq!(title, "My Title");
    }

    #[test]
    fn extract_title_from_filename() {
        let title = extract_title(Path::new("README.md"), "No heading here");
        assert_eq!(title, "README");
    }

    #[test]
    fn notify_receives_events() {
        // Verify that notify works on this platform
        let (tx, rx) = std::sync::mpsc::channel();
        let tmp = tempfile::tempdir().unwrap();
        let mut w = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            notify::Config::default(),
        )
        .unwrap();
        w.watch(tmp.path(), RecursiveMode::Recursive).unwrap();
        std::fs::write(tmp.path().join("test.txt"), "hello").unwrap();
        let event = rx.recv_timeout(std::time::Duration::from_secs(5));
        assert!(
            event.is_ok(),
            "notify should fire an event for file creation"
        );
        drop(w);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watcher_indexes_new_file() {
        let tmp = tempfile::tempdir().unwrap();
        // Use a non-hidden subdirectory (tempdir may start with '.')
        let watch_dir = tmp.path().join("docs");
        std::fs::create_dir_all(&watch_dir).unwrap();

        let db_path = tmp.path().join("test.db");
        let index = Arc::new(IndexStore::open(db_path.to_str().unwrap()).unwrap());

        let handle = start_watcher(vec![watch_dir.clone()], index.clone()).unwrap();

        // Small delay to let the watcher initialize
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Create a file
        let file_path = watch_dir.join("test.md");
        std::fs::write(&file_path, "# Hello\nWorld").unwrap();

        // Poll until the file is indexed or timeout
        let path_str = file_path.to_string_lossy().to_string();
        let mut found = false;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if index.get_by_path(&path_str).ok().flatten().is_some() {
                found = true;
                break;
            }
        }
        assert!(found, "File should be indexed after creation");

        drop(handle);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watcher_removes_deleted_file() {
        let tmp = tempfile::tempdir().unwrap();
        let watch_dir = tmp.path().join("docs");
        std::fs::create_dir_all(&watch_dir).unwrap();

        let db_path = tmp.path().join("test.db");
        let index = Arc::new(IndexStore::open(db_path.to_str().unwrap()).unwrap());

        // Pre-index a file
        let file_path = watch_dir.join("delete_me.md");
        std::fs::write(&file_path, "# Will be deleted").unwrap();
        let path_str = file_path.to_string_lossy().to_string();
        index
            .upsert(
                &path_str,
                "text/markdown",
                17,
                "0",
                "hash",
                "Will be deleted",
                "# Will be deleted",
            )
            .unwrap();

        let handle = start_watcher(vec![watch_dir], index.clone()).unwrap();

        // Small delay to let the watcher initialize
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Delete the file
        std::fs::remove_file(&file_path).unwrap();

        // Poll until removed or timeout
        let mut removed = false;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if index.get_by_path(&path_str).ok().flatten().is_none() {
                removed = true;
                break;
            }
        }
        assert!(removed, "File should be removed from index after deletion");

        drop(handle);
    }
}
