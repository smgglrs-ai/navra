//! Hot config reload via filesystem watching.
//!
//! Watches the config file's parent directory for changes (supports
//! both regular file edits and Kubernetes ConfigMap symlink swaps).
//! Invalid configs are logged and discarded — the previous valid
//! config stays in effect.

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

use crate::config::Config;

pub struct ConfigWatcher {
    _watcher: RecommendedWatcher,
}

impl ConfigWatcher {
    pub fn new(
        config_path: PathBuf,
        debounce_ms: u64,
        tx: watch::Sender<Arc<Config>>,
    ) -> anyhow::Result<Self> {
        let parent = config_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Config path has no parent directory"))?
            .to_path_buf();
        let filename = config_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Config path has no filename"))?
            .to_os_string();

        let debounce = Duration::from_millis(debounce_ms);
        let (notify_tx, notify_rx) = std::sync::mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = notify_tx.send(event);
                }
            },
            notify::Config::default(),
        )?;

        watcher.watch(&parent, RecursiveMode::NonRecursive)?;

        let config_path_clone = config_path.clone();
        let filename_clone = filename.clone();
        tokio::task::spawn_blocking(move || {
            let mut last_reload = std::time::Instant::now();

            while let Ok(event) = notify_rx.recv() {
                if !matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                ) {
                    continue;
                }

                let is_our_file = event
                    .paths
                    .iter()
                    .any(|p| p.file_name().map(|f| f == filename_clone).unwrap_or(false));
                if !is_our_file {
                    continue;
                }

                if last_reload.elapsed() < debounce {
                    continue;
                }
                last_reload = std::time::Instant::now();

                // Small delay to let atomic rename complete
                std::thread::sleep(Duration::from_millis(10));

                match reload_config(&config_path_clone) {
                    Ok(new_config) => {
                        tracing::info!("Config reloaded successfully");
                        let _ = tx.send(Arc::new(new_config));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Config reload failed, keeping previous config");
                    }
                }
            }
        });

        tracing::info!(
            path = %config_path.display(),
            debounce_ms,
            "Config watcher started"
        );

        Ok(Self { _watcher: watcher })
    }
}

fn reload_config(path: &Path) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn minimal_config() -> &'static str {
        r#"
        [server]
        tcp = "127.0.0.1:0"
        "#
    }

    #[tokio::test]
    async fn reload_on_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, minimal_config()).unwrap();

        let initial = Config::default();
        let (tx, mut rx) = watch::channel(Arc::new(initial));

        let _watcher = ConfigWatcher::new(config_path.clone(), 10, tx).unwrap();

        // Modify the config
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(f, "[server]\ntcp = \"127.0.0.1:9999\"").unwrap();
        drop(f);

        // Wait for the watcher to pick it up
        tokio::time::timeout(Duration::from_secs(3), rx.changed())
            .await
            .expect("timed out waiting for config reload")
            .expect("watch channel closed");

        let new_cfg = rx.borrow();
        assert_eq!(new_cfg.server.tcp.as_deref(), Some("127.0.0.1:9999"));
    }

    #[tokio::test]
    async fn invalid_config_keeps_previous() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, minimal_config()).unwrap();

        let initial = Config::default();
        let (tx, mut rx) = watch::channel(Arc::new(initial));

        let _watcher = ConfigWatcher::new(config_path.clone(), 10, tx).unwrap();

        // Write invalid TOML
        tokio::time::sleep(Duration::from_millis(50)).await;
        std::fs::write(&config_path, "this is not valid toml [[[").unwrap();

        // Should NOT trigger a change (invalid config discarded)
        let result = tokio::time::timeout(Duration::from_millis(500), rx.changed()).await;
        assert!(
            result.is_err(),
            "should not have received a config update for invalid TOML"
        );
    }

    #[tokio::test]
    async fn symlink_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, minimal_config()).unwrap();

        let initial = Config::default();
        let (tx, mut rx) = watch::channel(Arc::new(initial));

        let _watcher = ConfigWatcher::new(config_path.clone(), 10, tx).unwrap();

        // Simulate atomic ConfigMap replacement: write to temp, rename over
        tokio::time::sleep(Duration::from_millis(50)).await;
        let tmp_path = dir.path().join("config.toml.tmp");
        std::fs::write(&tmp_path, "[server]\ntcp = \"0.0.0.0:8080\"").unwrap();
        std::fs::rename(&tmp_path, &config_path).unwrap();

        tokio::time::timeout(Duration::from_secs(3), rx.changed())
            .await
            .expect("timed out waiting for config reload after rename")
            .expect("watch channel closed");

        let new_cfg = rx.borrow();
        assert_eq!(new_cfg.server.tcp.as_deref(), Some("0.0.0.0:8080"));
    }

    #[test]
    fn reload_config_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        std::fs::write(&path, "[server]\ntcp = \"localhost:1234\"").unwrap();
        let cfg = reload_config(&path).unwrap();
        assert_eq!(cfg.server.tcp.as_deref(), Some("localhost:1234"));
    }

    #[test]
    fn reload_config_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "not valid").unwrap();
        assert!(reload_config(&path).is_err());
    }

    #[test]
    fn reload_config_missing() {
        assert!(reload_config(Path::new("/nonexistent/config.toml")).is_err());
    }
}
