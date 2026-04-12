//! Integration tests for ModelHub.

use super::*;

#[test]
fn hub_with_custom_cache_dir() {
    let dir = tempfile::tempdir().unwrap();
    let hub = ModelHub::with_cache_dir(dir.path().to_path_buf()).unwrap();
    assert!(hub.cache.root().exists());
}

#[test]
fn file_uri_existing_path() {
    let dir = tempfile::tempdir().unwrap();
    let model_file = dir.path().join("test.gguf");
    std::fs::write(&model_file, b"fake gguf").unwrap();

    let hub = ModelHub::with_cache_dir(dir.path().join("cache")).unwrap();
    let uri = ModelUri::parse(&format!("file://{}", model_file.display())).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let path = rt.block_on(hub.pull(&uri)).unwrap();
    assert_eq!(path, model_file);
}

#[test]
fn file_uri_missing_path() {
    let dir = tempfile::tempdir().unwrap();
    let hub = ModelHub::with_cache_dir(dir.path().join("cache")).unwrap();
    let uri = ModelUri::parse("file:///nonexistent/model.gguf").unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert!(rt.block_on(hub.pull(&uri)).is_err());
}
