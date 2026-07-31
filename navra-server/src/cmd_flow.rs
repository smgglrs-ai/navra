use crate::config;
use crate::triggers::TriggerConfig;
use serde::Deserialize;

pub(crate) async fn flow_run(
    file: &str,
    prompt: &str,
    endpoint: &str,
    token: Option<&str>,
    model: Option<&str>,
) -> anyhow::Result<()> {
    crate::cmd_run::run_flow_file(file, prompt, endpoint, token, model).await
}

pub(crate) fn flow_list(cfg: &config::Config) -> anyhow::Result<()> {
    let flow_dirs = crate::setup::tools::resolve_flow_dirs(cfg);

    let mut found = false;
    for dir_str in &flow_dirs {
        let dir = std::path::Path::new(dir_str);
        if !dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str());
            if matches!(ext, Some("toml" | "yaml" | "yml")) {
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?");
                println!("{:<30} {}", name, path.display());
                found = true;
            }
        }
    }

    // Scan agent instance flow dirs
    if let Some(agents_dir) = instance_agents_dir()
        && agents_dir.is_dir() {
            for entry in std::fs::read_dir(&agents_dir)? {
                let entry = entry?;
                let instance_dir = entry.path();
                if !instance_dir.is_dir() {
                    continue;
                }
                let flows_dir = instance_dir.join("flows");
                if flows_dir.is_dir() {
                    let instance_name = instance_dir
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("?");
                    for flow_entry in std::fs::read_dir(&flows_dir)? {
                        let flow_entry = flow_entry?;
                        let path = flow_entry.path();
                        let ext = path.extension().and_then(|e| e.to_str());
                        if matches!(ext, Some("toml" | "yaml" | "yml")) {
                            let name = path
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("?");
                            println!(
                                "{:<30} {} (instance: {instance_name})",
                                name,
                                path.display()
                            );
                            found = true;
                        }
                    }
                }
            }
        }

    if !found {
        println!("No flows found.");
        println!("Flow directories:");
        for d in &flow_dirs {
            println!("  {d}");
        }
    }
    Ok(())
}

pub(crate) fn trigger_list(cfg: &config::Config) -> anyhow::Result<()> {
    let all = collect_all_triggers(cfg);

    if all.is_empty() {
        println!("No triggers configured.");
        println!("Add triggers to config.toml or agent instance configs.");
        return Ok(());
    }

    println!(
        "{:<20} {:<12} {:<30} DETAILS",
        "SOURCE", "TYPE", "TARGET"
    );
    println!(
        "{:<20} {:<12} {:<30} -------",
        "------", "----", "------"
    );

    for (source, trigger) in &all {
        match trigger {
            TriggerConfig::Cron {
                schedule,
                flow_name,
            } => {
                println!("{source:<20} {:<12} {flow_name:<30} {schedule}", "cron");
            }
            TriggerConfig::Webhook {
                path,
                flow_name,
                secret,
            } => {
                let auth = if secret.is_some() { " (hmac)" } else { "" };
                println!(
                    "{source:<20} {:<12} {flow_name:<30} {path}{auth}",
                    "webhook"
                );
            }
            TriggerConfig::FileWatch {
                path,
                pattern,
                flow_name,
                debounce_ms: _,
            } => {
                let pat = pattern.as_deref().unwrap_or("*");
                println!(
                    "{source:<20} {:<12} {flow_name:<30} {path} ({pat})",
                    "file_watch"
                );
            }
        }
    }
    Ok(())
}

pub(crate) async fn trigger_start(cfg: config::Config) -> anyhow::Result<()> {
    let all = collect_all_triggers(&cfg);

    if all.is_empty() {
        println!("No triggers configured. Nothing to start.");
        return Ok(());
    }

    println!("Starting trigger engine with {} trigger(s)...", all.len());
    for (source, trigger) in &all {
        let kind = match trigger {
            TriggerConfig::Cron { schedule, .. } => format!("cron: {schedule}"),
            TriggerConfig::Webhook { path, .. } => format!("webhook: {path}"),
            TriggerConfig::FileWatch { path, .. } => format!("file_watch: {path}"),
        };
        println!("  [{source}] {kind}");
    }

    // The trigger engine needs a FlowContext to execute flows.
    // For now, we require a running navra MCP gateway — triggers
    // call handle_flow_start which needs the full server context.
    // In standalone mode we print the config and wait for SIGTERM.
    println!();
    println!("Trigger engine requires `navra mcp serve` to be running.");
    println!("Use systemd: systemctl --user start navra.target");
    println!();
    println!("Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await?;
    println!("Trigger engine stopped.");
    Ok(())
}

// --- Internal helpers ---

fn instance_agents_dir() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("navra/agents"))
}

#[derive(Deserialize, Default)]
struct InstanceConfig {
    #[serde(default)]
    triggers: Vec<TriggerConfig>,
}

fn load_instance_triggers() -> Vec<(String, TriggerConfig)> {
    let agents_dir = match instance_agents_dir() {
        Some(d) if d.is_dir() => d,
        _ => return Vec::new(),
    };

    let mut result = Vec::new();
    let entries = match std::fs::read_dir(&agents_dir) {
        Ok(e) => e,
        Err(_) => return result,
    };

    for entry in entries.flatten() {
        let instance_dir = entry.path();
        if !instance_dir.is_dir() {
            continue;
        }
        let config_path = instance_dir.join("config.toml");
        if !config_path.exists() {
            continue;
        }
        let instance_name = instance_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    instance = %instance_name,
                    error = %e,
                    "Failed to read agent instance config"
                );
                continue;
            }
        };

        let parsed: InstanceConfig = match toml::from_str(&content) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(
                    instance = %instance_name,
                    error = %e,
                    "Failed to parse agent instance config for triggers"
                );
                continue;
            }
        };

        for trigger in parsed.triggers {
            result.push((instance_name.clone(), trigger));
        }
    }

    result
}

fn collect_all_triggers(cfg: &config::Config) -> Vec<(String, TriggerConfig)> {
    let mut all: Vec<(String, TriggerConfig)> = cfg
        .triggers
        .iter()
        .map(|t| ("config.toml".to_string(), t.clone()))
        .collect();

    all.extend(load_instance_triggers());
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_instance_triggers_no_dir() {
        let triggers = load_instance_triggers();
        // May or may not find triggers depending on dev machine state,
        // but must not panic.
        let _ = triggers;
    }

    #[test]
    fn collect_all_with_empty_config() {
        let cfg = config::Config::default();
        let all = collect_all_triggers(&cfg);
        // At minimum, should not panic. Instance triggers depend on disk state.
        let _ = all;
    }

    #[test]
    fn parse_instance_config_with_triggers() {
        let toml_str = r#"
bundle = "test-agent"

[[triggers]]
type = "cron"
schedule = "0 9 * * 1-5"
flow_name = "morning-report"

[[triggers]]
type = "file_watch"
path = "~/Documents"
pattern = "*.pdf"
flow_name = "ingest-document"
"#;
        let parsed: InstanceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.triggers.len(), 2);
        assert!(matches!(&parsed.triggers[0], TriggerConfig::Cron { schedule, .. } if schedule == "0 9 * * 1-5"));
        assert!(matches!(&parsed.triggers[1], TriggerConfig::FileWatch { path, .. } if path == "~/Documents"));
    }

    #[test]
    fn parse_instance_config_no_triggers() {
        let toml_str = r#"
bundle = "simple-agent"
model = "ollama/qwen2.5"
"#;
        let parsed: InstanceConfig = toml::from_str(toml_str).unwrap();
        assert!(parsed.triggers.is_empty());
    }
}
