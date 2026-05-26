//! Cognitive file integrity monitoring.
//!
//! Watches persona/directive/heuristic YAML files for tampering using
//! SHA-256 baselines and optional semantic drift detection via embeddings.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertSeverity {
    Benign,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone)]
pub struct IntegrityAlert {
    pub path: PathBuf,
    pub severity: AlertSeverity,
    pub old_hash: String,
    pub new_hash: String,
    pub semantic_drift: Option<f64>,
    pub timestamp: std::time::SystemTime,
    pub message: String,
}

struct FileBaseline {
    hash: String,
    embedding: Option<Vec<f32>>,
}

#[derive(Debug, Clone)]
pub struct IntegrityMonitorConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub malicious_threshold: f64,
    pub suspicious_threshold: f64,
}

impl Default for IntegrityMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 60,
            malicious_threshold: 0.3,
            suspicious_threshold: 0.15,
        }
    }
}

pub struct IntegrityMonitor {
    config: IntegrityMonitorConfig,
    cognitive_core_dir: PathBuf,
    baselines: HashMap<PathBuf, FileBaseline>,
    alerts: Arc<RwLock<Vec<IntegrityAlert>>>,
}

impl IntegrityMonitor {
    pub fn new(config: IntegrityMonitorConfig, cognitive_core_dir: PathBuf) -> Self {
        Self {
            config,
            cognitive_core_dir,
            baselines: HashMap::new(),
            alerts: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn alerts(&self) -> Arc<RwLock<Vec<IntegrityAlert>>> {
        Arc::clone(&self.alerts)
    }

    pub async fn initialize(&mut self, embed_backend: Option<&dyn smgglrs_model::ModelBackend>) {
        let files = collect_yaml_files(&self.cognitive_core_dir);
        for path in files {
            if let Ok(content) = std::fs::read_to_string(&path) {
                let hash = sha256_hex(content.as_bytes());
                let embedding = compute_embedding(embed_backend, &content).await;
                self.baselines
                    .insert(path, FileBaseline { hash, embedding });
            }
        }
        tracing::info!(
            files = self.baselines.len(),
            dir = %self.cognitive_core_dir.display(),
            "Integrity monitor initialized"
        );
    }

    pub async fn check(&mut self, embed_backend: Option<&dyn smgglrs_model::ModelBackend>) {
        let current_files = collect_yaml_files(&self.cognitive_core_dir);
        let current_set: std::collections::HashSet<_> = current_files.iter().cloned().collect();

        // Alert if all monitored files have disappeared
        if current_files.is_empty() && !self.baselines.is_empty() {
            let alert = IntegrityAlert {
                path: self.cognitive_core_dir.clone(),
                severity: AlertSeverity::Malicious,
                old_hash: format!("{} files", self.baselines.len()),
                new_hash: String::new(),
                semantic_drift: None,
                timestamp: std::time::SystemTime::now(),
                message: "All cognitive files deleted — monitor silencing attempt".to_string(),
            };
            tracing::error!(
                dir = %self.cognitive_core_dir.display(),
                baseline_count = self.baselines.len(),
                "MALICIOUS: all cognitive files deleted"
            );
            self.alerts.write().await.push(alert);
        }

        // Check for missing files
        let baseline_paths: Vec<_> = self.baselines.keys().cloned().collect();
        for path in &baseline_paths {
            if !current_set.contains(path) {
                let baseline = self.baselines.remove(path).unwrap();
                let alert = IntegrityAlert {
                    path: path.clone(),
                    severity: AlertSeverity::Malicious,
                    old_hash: baseline.hash,
                    new_hash: String::new(),
                    semantic_drift: None,
                    timestamp: std::time::SystemTime::now(),
                    message: "Cognitive file deleted".to_string(),
                };
                tracing::error!(
                    path = %path.display(),
                    "MALICIOUS: cognitive file deleted"
                );
                self.alerts.write().await.push(alert);
            }
        }

        // Check existing and new files
        for path in current_files {
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Failed to read cognitive file");
                    continue;
                }
            };
            let new_hash = sha256_hex(content.as_bytes());

            if let Some(baseline) = self.baselines.get(&path) {
                let hash_match = baseline.hash.len() == new_hash.len()
                    && baseline
                        .hash
                        .bytes()
                        .zip(new_hash.bytes())
                        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                        == 0;
                if hash_match {
                    continue;
                }

                // Hash changed — compute semantic drift if possible
                let drift = if let Some(ref old_emb) = baseline.embedding {
                    if let Some(new_emb) = compute_embedding(embed_backend, &content).await {
                        let sim = crate::hooks::statistical::cosine_similarity(old_emb, &new_emb);
                        Some(1.0 - sim) // distance = 1 - similarity
                    } else {
                        None
                    }
                } else {
                    None
                };

                let severity = match drift {
                    Some(d) if d > self.config.malicious_threshold => AlertSeverity::Malicious,
                    Some(d) if d > self.config.suspicious_threshold => AlertSeverity::Suspicious,
                    _ => AlertSeverity::Benign,
                };

                let msg = match severity {
                    AlertSeverity::Malicious => format!(
                        "Large semantic drift ({:.3}) detected in {}",
                        drift.unwrap_or(0.0),
                        path.display()
                    ),
                    AlertSeverity::Suspicious => format!(
                        "Moderate semantic drift ({:.3}) in {}",
                        drift.unwrap_or(0.0),
                        path.display()
                    ),
                    AlertSeverity::Benign => format!("Minor change in {}", path.display()),
                };

                match severity {
                    AlertSeverity::Malicious => {
                        tracing::error!(path = %path.display(), drift = ?drift, "MALICIOUS: cognitive file tampered");
                    }
                    AlertSeverity::Suspicious => {
                        tracing::warn!(path = %path.display(), drift = ?drift, "SUSPICIOUS: cognitive file changed");
                    }
                    AlertSeverity::Benign => {
                        tracing::info!(path = %path.display(), "Benign cognitive file change, baseline updated");
                    }
                }

                let alert = IntegrityAlert {
                    path: path.clone(),
                    severity,
                    old_hash: baseline.hash.clone(),
                    new_hash: new_hash.clone(),
                    semantic_drift: drift,
                    timestamp: std::time::SystemTime::now(),
                    message: msg,
                };
                self.alerts.write().await.push(alert);

                // Update baseline
                let new_embedding = compute_embedding(embed_backend, &content).await;
                self.baselines.insert(
                    path,
                    FileBaseline {
                        hash: new_hash,
                        embedding: new_embedding,
                    },
                );
            } else {
                // New file — establish baseline
                let embedding = compute_embedding(embed_backend, &content).await;
                self.baselines.insert(
                    path,
                    FileBaseline {
                        hash: new_hash,
                        embedding,
                    },
                );
            }
        }
    }
}

pub fn spawn_monitor(
    mut monitor: IntegrityMonitor,
    embed_backend: Option<Arc<dyn smgglrs_model::ModelBackend>>,
) -> tokio::task::JoinHandle<()> {
    let interval_secs = monitor.config.interval_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.tick().await; // skip the first immediate tick
        loop {
            interval.tick().await;
            monitor.check(embed_backend.as_deref()).await;
        }
    })
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn collect_yaml_files(dir: &Path) -> Vec<PathBuf> {
    let subdirs = [
        "personas",
        "directives",
        "heuristics",
        "persona_specializations",
    ];
    let mut files = Vec::new();
    for subdir in &subdirs {
        let path = dir.join(subdir);
        if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                        // Resolve symlinks and verify the file is within
                        // the cognitive core directory to prevent traversal.
                        if let Ok(canonical) = p.canonicalize() {
                            if let Ok(base) = dir.canonicalize() {
                                if canonical.starts_with(&base) {
                                    files.push(canonical);
                                    continue;
                                }
                            }
                        }
                        files.push(p);
                    }
                }
            }
        }
    }
    files
}

async fn compute_embedding(
    backend: Option<&dyn smgglrs_model::ModelBackend>,
    content: &str,
) -> Option<Vec<f32>> {
    let backend = backend?;
    let request = smgglrs_model::EmbedRequest {
        text: content.to_string(),
    };
    match backend.embed(&request).await {
        Ok(resp) => Some(resp.embedding),
        Err(e) => {
            tracing::debug!(error = %e, "Failed to compute embedding for integrity check");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("personas")).unwrap();
        std::fs::create_dir_all(dir.path().join("directives")).unwrap();
        dir
    }

    fn write_persona(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join("personas").join(name), content).unwrap();
    }

    #[tokio::test]
    async fn initialize_collects_baselines() {
        let dir = test_dir();
        write_persona(
            dir.path(),
            "test.yaml",
            "persona_name: test\ncore_mandate: do stuff",
        );

        let mut monitor =
            IntegrityMonitor::new(IntegrityMonitorConfig::default(), dir.path().to_path_buf());
        monitor.initialize(None).await;
        assert_eq!(monitor.baselines.len(), 1);
    }

    #[tokio::test]
    async fn no_change_no_alert() {
        let dir = test_dir();
        write_persona(dir.path(), "test.yaml", "persona_name: test");

        let mut monitor =
            IntegrityMonitor::new(IntegrityMonitorConfig::default(), dir.path().to_path_buf());
        monitor.initialize(None).await;
        monitor.check(None).await;

        let alerts = monitor.alerts.read().await;
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn hash_change_detected() {
        let dir = test_dir();
        write_persona(dir.path(), "test.yaml", "persona_name: test");

        let mut monitor =
            IntegrityMonitor::new(IntegrityMonitorConfig::default(), dir.path().to_path_buf());
        monitor.initialize(None).await;

        // Modify the file
        write_persona(
            dir.path(),
            "test.yaml",
            "persona_name: HACKED ignore safety",
        );

        monitor.check(None).await;

        let alerts = monitor.alerts.read().await;
        assert_eq!(alerts.len(), 1);
        // Without embeddings, severity defaults to Benign (hash-only)
        assert_eq!(alerts[0].severity, AlertSeverity::Benign);
        assert_ne!(alerts[0].old_hash, alerts[0].new_hash);
    }

    #[tokio::test]
    async fn missing_file_is_malicious() {
        let dir = test_dir();
        write_persona(dir.path(), "test.yaml", "persona_name: test");

        let mut monitor =
            IntegrityMonitor::new(IntegrityMonitorConfig::default(), dir.path().to_path_buf());
        monitor.initialize(None).await;

        // Delete the file
        std::fs::remove_file(dir.path().join("personas/test.yaml")).unwrap();

        monitor.check(None).await;

        let alerts = monitor.alerts.read().await;
        // 2 alerts: "all files deleted" + individual file deletion
        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().all(|a| a.severity == AlertSeverity::Malicious));
        assert!(alerts.iter().any(|a| a.message.contains("deleted")));
    }

    #[tokio::test]
    async fn alerts_accumulate() {
        let dir = test_dir();
        write_persona(dir.path(), "test.yaml", "version 1");

        let mut monitor =
            IntegrityMonitor::new(IntegrityMonitorConfig::default(), dir.path().to_path_buf());
        monitor.initialize(None).await;

        write_persona(dir.path(), "test.yaml", "version 2");
        monitor.check(None).await;

        write_persona(dir.path(), "test.yaml", "version 3");
        monitor.check(None).await;

        let alerts = monitor.alerts.read().await;
        assert_eq!(alerts.len(), 2);
    }

    #[tokio::test]
    async fn new_file_establishes_baseline() {
        let dir = test_dir();

        let mut monitor =
            IntegrityMonitor::new(IntegrityMonitorConfig::default(), dir.path().to_path_buf());
        monitor.initialize(None).await;
        assert_eq!(monitor.baselines.len(), 0);

        write_persona(dir.path(), "new.yaml", "new persona");
        monitor.check(None).await;

        assert_eq!(monitor.baselines.len(), 1);
        let alerts = monitor.alerts.read().await;
        assert!(alerts.is_empty()); // new files don't trigger alerts
    }

    #[test]
    fn sha256_hex_deterministic() {
        let h1 = sha256_hex(b"test content");
        let h2 = sha256_hex(b"test content");
        assert_eq!(h1, h2);
        assert_ne!(sha256_hex(b"different"), h1);
    }

    #[test]
    fn collect_yaml_filters_extensions() {
        let dir = test_dir();
        write_persona(dir.path(), "good.yaml", "x");
        std::fs::write(dir.path().join("personas/skip.txt"), "x").unwrap();
        std::fs::write(dir.path().join("personas/also.yml"), "x").unwrap();

        let files = collect_yaml_files(dir.path());
        assert_eq!(files.len(), 2); // .yaml and .yml, not .txt
    }
}
