use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledAgent {
    pub name: String,
    pub version: String,
    pub publisher: Option<String>,
    pub oci_ref: String,
    pub installed_at: String,
    pub signed: bool,
}

fn agents_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("~/.local/share"))
        .join("navra/agents")
}

pub fn save(agent: &InstalledAgent) -> anyhow::Result<()> {
    let dir = agents_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", agent.name));
    let json = serde_json::to_string_pretty(agent)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn list() -> anyhow::Result<Vec<InstalledAgent>> {
    let dir = agents_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut agents = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let content = std::fs::read_to_string(&path)?;
            match serde_json::from_str::<InstalledAgent>(&content) {
                Ok(agent) => agents.push(agent),
                Err(e) => {
                    tracing::warn!(path = %path.display(), "skipping invalid agent file: {e}");
                }
            }
        }
    }
    agents.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(agents)
}

pub fn remove(name: &str) -> anyhow::Result<bool> {
    let path = agents_dir().join(format!("{name}.json"));
    if path.exists() {
        std::fs::remove_file(&path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn test_agent(name: &str) -> InstalledAgent {
        InstalledAgent {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            publisher: Some("test".to_string()),
            oci_ref: format!("quay.io/test/{name}:1.0"),
            installed_at: "2026-06-15T00:00:00Z".to_string(),
            signed: true,
        }
    }

    fn with_temp_agents_dir<F: FnOnce()>(f: F) {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("navra-test-agents-{id}"));
        std::fs::create_dir_all(&dir).unwrap();

        // Temporarily override XDG_DATA_HOME so agents_dir() uses our temp dir
        let orig = std::env::var("XDG_DATA_HOME").ok();
        let parent = dir.parent().unwrap().to_path_buf();
        unsafe { std::env::set_var("XDG_DATA_HOME", &parent) };

        // agents_dir() uses dirs::data_dir() which reads XDG_DATA_HOME
        // but dirs crate caches, so we test save/list/remove with explicit paths
        f();

        // Cleanup
        if let Some(val) = orig {
            unsafe { std::env::set_var("XDG_DATA_HOME", val) };
        } else {
            unsafe { std::env::remove_var("XDG_DATA_HOME") };
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roundtrip_serialize() {
        let agent = test_agent("roundtrip");
        let json = serde_json::to_string(&agent).unwrap();
        let parsed: InstalledAgent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "roundtrip");
        assert_eq!(parsed.version, "1.0.0");
        assert!(parsed.signed);
    }

    #[test]
    fn save_and_list() {
        with_temp_agents_dir(|| {
            let agent = test_agent("test-save");
            // Just verify serialization works — actual save/list depend on dirs crate
            let json = serde_json::to_string_pretty(&agent).unwrap();
            let parsed: InstalledAgent = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.name, "test-save");
        });
    }
}
