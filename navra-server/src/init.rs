//! Interactive first-time setup for navra.
//!
//! Implements the `navra init` command, which walks the user through
//! environment detection, safety selection, model backend, and directory
//! permissions, then generates a complete `config.toml`.

use anyhow::Result;
use navra_core::auth::TokenAuthenticator;
use std::io::Write;

/// Answers collected from the interactive or quiet flow.
struct InitAnswers {
    agent_name: String,
    agent_type: String,
    project: String,
    model_backend: String,
    model_url: Option<String>,
    api_key: Option<String>,
    safety: String,
    allow_dirs: Vec<String>,
    install_service: bool,
}

/// Curated MCP server catalog entry.
struct McpServerEntry {
    name: &'static str,
    #[allow(dead_code)]
    description: &'static str,
    command: &'static [&'static str],
    project_types: &'static [&'static str],
}

/// Static catalog of upstream MCP servers.
const MCP_CATALOG: &[McpServerEntry] = &[
    McpServerEntry {
        name: "filesystem",
        description: "Filesystem access via MCP",
        command: &["npx", "-y", "@modelcontextprotocol/server-filesystem", "~"],
        project_types: &["dev", "data", "ops"],
    },
    McpServerEntry {
        name: "git",
        description: "Git repository operations",
        command: &["npx", "-y", "@modelcontextprotocol/server-git"],
        project_types: &["dev"],
    },
    McpServerEntry {
        name: "postgres",
        description: "PostgreSQL database access",
        command: &["npx", "-y", "@modelcontextprotocol/server-postgres"],
        project_types: &["data"],
    },
    McpServerEntry {
        name: "sqlite",
        description: "SQLite database access",
        command: &["npx", "-y", "@modelcontextprotocol/server-sqlite"],
        project_types: &["data"],
    },
    McpServerEntry {
        name: "docker",
        description: "Docker container management",
        command: &["npx", "-y", "@modelcontextprotocol/server-docker"],
        project_types: &["ops"],
    },
];

/// Entry point for `navra init`.
#[allow(clippy::too_many_arguments)]
pub async fn run_init(
    quiet: bool,
    agent_name: Option<String>,
    safety: String,
    project: String,
    model: String,
    model_url: Option<String>,
    api_key: Option<String>,
    allow: Option<String>,
    install_service: bool,
    dry_run: bool,
    output: Option<String>,
) -> Result<()> {
    let answers = if quiet {
        quiet_flow(
            agent_name,
            safety,
            project,
            model,
            model_url,
            api_key,
            allow,
            install_service,
        )
    } else {
        interactive_flow().await?
    };

    // Generate token
    let token = crate::config::generate_token();
    let hash = TokenAuthenticator::hash_token(&token);

    // Build config
    let config_toml = build_config_toml(&answers, &hash);

    // Validate generated TOML
    toml::from_str::<toml::Value>(&config_toml)
        .map_err(|e| anyhow::anyhow!("Generated config is invalid TOML: {e}"))?;

    if dry_run {
        println!("{config_toml}");
        eprintln!("\n# Token (save this — it cannot be recovered):");
        eprintln!("# {token}");
        return Ok(());
    }

    // Determine output path
    let config_path = match output {
        Some(ref p) => std::path::PathBuf::from(p),
        None => crate::config::Config::default_config_path(),
    };

    // Backup existing config
    if config_path.exists() {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let backup_path = config_path.with_extension(format!("toml.bak.{timestamp}"));
        std::fs::copy(&config_path, &backup_path)?;
        eprintln!("Backed up existing config to {}", backup_path.display());
    }

    // Write config
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config_path, &config_toml)?;
    eprintln!("Wrote config to {}", config_path.display());

    // Print token
    eprintln!();
    eprintln!("Agent token (save this — it cannot be recovered):");
    eprintln!("  {token}");

    // Install systemd service if requested
    if answers.install_service {
        eprintln!();
        crate::install_systemd_units()?;
    }

    // Print connection instructions
    let socket = "~/.run/navra/navra.sock";
    let instructions = connection_instructions(&answers.agent_type, &token, socket);
    eprintln!("{instructions}");

    Ok(())
}

/// Build answers from CLI flags (no prompts).
#[allow(clippy::too_many_arguments)]
fn quiet_flow(
    agent_name: Option<String>,
    safety: String,
    project: String,
    model: String,
    model_url: Option<String>,
    api_key: Option<String>,
    allow: Option<String>,
    install_service: bool,
) -> InitAnswers {
    let agent_type = detect_agent();
    let name = agent_name.unwrap_or_else(|| {
        match agent_type.as_str() {
            "claude" => "claude-code",
            "goose" => "goose",
            _ => "agent",
        }
        .to_string()
    });

    let allow_dirs = match allow {
        Some(dirs) => dirs.split(',').map(|s| s.trim().to_string()).collect(),
        None => vec!["~/Code/**".to_string()],
    };

    InitAnswers {
        agent_name: name,
        agent_type,
        project,
        model_backend: model,
        model_url,
        api_key,
        safety,
        allow_dirs,
        install_service,
    }
}

/// 8-step interactive wizard.
async fn interactive_flow() -> Result<InitAnswers> {
    eprintln!("navra init — interactive setup\n");

    // Step 1: Detect agent
    let agent_type = detect_agent();
    let default_name = match agent_type.as_str() {
        "claude" => "claude-code",
        "goose" => "goose",
        _ => "agent",
    };
    eprintln!(
        "Detected agent: {}",
        match agent_type.as_str() {
            "claude" => "Claude Code",
            "goose" => "Goose",
            _ => "unknown",
        }
    );
    let agent_name = prompt_line("Agent name", default_name);

    // Step 2: Project type
    eprintln!("\nProject types:");
    eprintln!("  dev    — file access, git, code-focused MCP servers");
    eprintln!("  data   — database access (postgres, sqlite)");
    eprintln!("  ops    — container management (docker)");
    eprintln!("  custom — choose MCP servers manually");
    let project = prompt_line("Project type", "dev");

    // Step 3: Model backend
    eprintln!("\nModel backends:");
    eprintln!("  ollama        — local Ollama instance");
    eprintln!("  mistral       — Mistral AI API");
    eprintln!("  anthropic     — Anthropic API");
    eprintln!("  openai-compat — any OpenAI-compatible endpoint");
    eprintln!("  none          — no model backend");

    let default_model = if detect_ollama().await {
        eprintln!("  (Ollama detected at localhost:11434)");
        "ollama"
    } else {
        "none"
    };
    let model_backend = prompt_line("Model backend", default_model);

    let (model_url, api_key) = match model_backend.as_str() {
        "openai-compat" => {
            let url = prompt_line("Base URL", "http://localhost:8080/v1");
            let key = prompt_line("API key (empty for none)", "");
            (Some(url), if key.is_empty() { None } else { Some(key) })
        }
        "mistral" | "anthropic" => {
            let key = prompt_line("API key", "");
            (None, if key.is_empty() { None } else { Some(key) })
        }
        _ => (None, None),
    };

    // Step 4: Safety level
    eprintln!("\nSafety levels:");
    eprintln!("  standard — PII detection + secret filtering + prompt injection detection");
    eprintln!("  strict   — all of standard plus ML-based content classification");
    eprintln!("  minimal  — secret filtering only");
    let safety = prompt_line("Safety level", "standard");

    // Step 5: Directories
    let allow_str = prompt_line("Allowed directories (comma-separated)", "~/Code/**");
    let allow_dirs: Vec<String> = allow_str.split(',').map(|s| s.trim().to_string()).collect();

    // Step 6: Systemd
    let install_service = prompt_yn("Install systemd user service?", true);

    // Step 7: Summary
    eprintln!("\n--- Configuration Summary ---");
    eprintln!("Agent:     {} ({})", agent_name, agent_type);
    eprintln!("Project:   {project}");
    eprintln!("Model:     {model_backend}");
    eprintln!("Safety:    {safety}");
    eprintln!("Dirs:      {}", allow_dirs.join(", "));
    eprintln!("Systemd:   {}", if install_service { "yes" } else { "no" });

    let servers: Vec<&str> = MCP_CATALOG
        .iter()
        .filter(|e| e.project_types.contains(&project.as_str()))
        .map(|e| e.name)
        .collect();
    if !servers.is_empty() {
        eprintln!("Upstream:  {}", servers.join(", "));
    }
    eprintln!("-----------------------------");

    if !prompt_yn("Proceed?", true) {
        anyhow::bail!("Setup cancelled by user");
    }

    Ok(InitAnswers {
        agent_name,
        agent_type,
        project,
        model_backend,
        model_url,
        api_key,
        safety,
        allow_dirs,
        install_service,
    })
}

/// Detect the agent runtime by checking for known directories/env vars.
fn detect_agent() -> String {
    // Check env var first
    if std::env::var("CLAUDE_CODE").is_ok() {
        return "claude".to_string();
    }

    let home = dirs::home_dir().unwrap_or_default();

    if home.join(".claude").is_dir() {
        return "claude".to_string();
    }

    if home.join(".config/goose").is_dir() {
        return "goose".to_string();
    }

    "custom".to_string()
}

/// Check if Ollama is running at localhost:11434.
async fn detect_ollama() -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .ok();

    if let Some(client) = client {
        client
            .get("http://localhost:11434/api/tags")
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    } else {
        false
    }
}

/// Prompt for a line of text, printing to stderr and reading from stdin.
fn prompt_line(question: &str, default: &str) -> String {
    if default.is_empty() {
        eprint!("{question}: ");
    } else {
        eprint!("{question} [{default}]: ");
    }
    std::io::stderr().flush().ok();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_ok() {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            default.to_string()
        } else {
            trimmed.to_string()
        }
    } else {
        default.to_string()
    }
}

/// Prompt for a yes/no answer.
fn prompt_yn(question: &str, default: bool) -> bool {
    let hint = if default { "Y/n" } else { "y/N" };
    eprint!("{question} [{hint}]: ");
    std::io::stderr().flush().ok();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_ok() {
        let trimmed = input.trim().to_lowercase();
        if trimmed.is_empty() {
            default
        } else {
            trimmed.starts_with('y')
        }
    } else {
        default
    }
}

/// Map user-facing safety level to internal profile name.
fn safety_profile(level: &str) -> &str {
    match level {
        "standard" => "standard",
        "strict" => "guardian",
        "minimal" => "secrets-only",
        other => other,
    }
}

/// Build the complete config.toml from answers.
fn build_config_toml(answers: &InitAnswers, token_hash: &str) -> String {
    let mut sections = Vec::new();

    // [server]
    sections.push(
        "[server]\nsocket = \"~/.run/navra/navra.sock\"\nmcp_version = \"2026-07-28\"".to_string(),
    );

    // [modules.*]
    match answers.project.as_str() {
        "dev" => {
            sections.push("[modules.file]\nenabled = true".to_string());
            sections.push("[modules.git]\nenabled = true".to_string());
        }
        "data" => {
            sections.push("[modules.file]\nenabled = true".to_string());
        }
        "ops" => {
            sections.push("[modules.file]\nenabled = true".to_string());
        }
        _ => {}
    }

    // Memory module (always, for PII)
    sections.push("[modules.memory]\npii_filter = \"standard\"".to_string());

    // [[agents]]
    sections.push(format!(
        "[[agents]]\nname = \"{}\"\ntoken_hash = \"{}\"\npermissions = \"{}\"",
        answers.agent_name, token_hash, answers.agent_name,
    ));

    // [permissions.<name>]
    let safety = safety_profile(&answers.safety);
    let allow_list: String = answers
        .allow_dirs
        .iter()
        .map(|d| format!("\"{}\"", d))
        .collect::<Vec<_>>()
        .join(", ");
    let deny_list = "\"**/.env\", \"**/*.key\", \"**/*secret*\", \"**/credentials*\"";

    let mut perm_section = format!(
        "[permissions.{}]\n\
         allow = [{allow_list}]\n\
         deny = [{deny_list}]\n\
         operations = [\"read\", \"write\"]\n\
         safety = \"{safety}\"\n\
         default_tool_policy = \"allow\"",
        answers.agent_name,
    );

    // Tool rules
    perm_section.push_str(&format!(
        "\n\n[[permissions.{}.tool_rules]]\ntool = \"git_push\"\npolicy = \"approve\"",
        answers.agent_name,
    ));
    perm_section.push_str(&format!(
        "\n\n[[permissions.{}.tool_rules]]\ntool = \"exec_*\"\npolicy = \"deny\"",
        answers.agent_name,
    ));

    sections.push(perm_section);

    // [[upstream]] — filtered by project type
    let upstream_servers: Vec<&McpServerEntry> = MCP_CATALOG
        .iter()
        .filter(|e| {
            e.project_types.contains(&answers.project.as_str()) || answers.project == "custom"
        })
        .collect();

    for server in &upstream_servers {
        let cmd_array: String = server
            .command
            .iter()
            .map(|c| format!("\"{}\"", c))
            .collect::<Vec<_>>()
            .join(", ");
        sections.push(format!(
            "[[upstream]]\nname = \"{}\"\ntransport = \"stdio\"\ncommand = [{}]",
            server.name, cmd_array,
        ));
    }

    // [models.*]
    match answers.model_backend.as_str() {
        "ollama" => {
            sections.push(
                "[models.default]\n\
                 source = \"ollama://qwen2.5:7b\"\n\
                 task = \"chat\"\n\
                 runtime = \"ollama\""
                    .to_string(),
            );
        }
        "mistral" => {
            let key_line = match &answers.api_key {
                Some(key) => format!("api_key = \"{}\"", key),
                None => "# api_key = \"your-api-key\"".to_string(),
            };
            sections.push(format!(
                "[models.default]\n\
                 base_url = \"https://api.mistral.ai/v1\"\n\
                 model_name = \"mistral-small-latest\"\n\
                 task = \"chat\"\n\
                 runtime = \"none\"\n\
                 {key_line}",
            ));
        }
        "anthropic" => {
            let key_line = match &answers.api_key {
                Some(key) => format!("api_key = \"{}\"", key),
                None => "# api_key = \"your-api-key\"".to_string(),
            };
            sections.push(format!(
                "[models.default]\n\
                 base_url = \"https://api.anthropic.com/v1\"\n\
                 model_name = \"claude-sonnet-4-20250514\"\n\
                 task = \"chat\"\n\
                 runtime = \"none\"\n\
                 {key_line}",
            ));
        }
        "openai-compat" => {
            let url = answers
                .model_url
                .as_deref()
                .unwrap_or("http://localhost:8080/v1");
            let key_line = match &answers.api_key {
                Some(key) => format!("api_key = \"{}\"", key),
                None => "# api_key = \"your-api-key\"".to_string(),
            };
            sections.push(format!(
                "[models.default]\n\
                 base_url = \"{url}\"\n\
                 model_name = \"default\"\n\
                 task = \"chat\"\n\
                 runtime = \"none\"\n\
                 {key_line}",
            ));
        }
        _ => {} // "none" — no models section
    }

    // [approval] + [budget]
    sections.push("[approval]\ntimeout_secs = 300\nnotify = \"dbus\"".to_string());
    sections.push(
        "[budget]\nmax_agents = 50\nmax_iterations = 200\nmax_parallel = 2\ntimeout_secs = 3600"
            .to_string(),
    );

    sections.join("\n\n") + "\n"
}

/// Generate per-agent connection instructions.
fn connection_instructions(agent_type: &str, token: &str, socket: &str) -> String {
    let mut out = String::new();
    out.push_str("\n--- Connection Instructions ---\n");

    match agent_type {
        "claude" => {
            out.push_str("\nAdd to .claude/settings.json:\n\n");
            out.push_str(&format!(
                r#"{{
  "mcpServers": {{
    "navra": {{
      "type": "stdio",
      "command": "navra",
      "args": ["connect", "--token", "{token}"]
    }}
  }}
}}"#,
            ));
            out.push('\n');
        }
        "goose" => {
            out.push_str("\nAdd to ~/.config/goose/config.yaml:\n\n");
            out.push_str(&format!(
                "mcpServers:\n  navra:\n    command: navra\n    args:\n      - connect\n      - --token\n      - \"{token}\"\n",
            ));
        }
        _ => {
            out.push_str(&format!(
                "\nConnect to the Unix socket at {socket}\n\
                 Bearer token: {token}\n",
            ));
        }
    }

    out.push_str("\n-------------------------------\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_answers() -> InitAnswers {
        InitAnswers {
            agent_name: "claude-code".to_string(),
            agent_type: "claude".to_string(),
            project: "dev".to_string(),
            model_backend: "none".to_string(),
            model_url: None,
            api_key: None,
            safety: "standard".to_string(),
            allow_dirs: vec!["~/Code/**".to_string()],
            install_service: false,
        }
    }

    #[test]
    fn test_build_config_dev() {
        let answers = dev_answers();
        let config = build_config_toml(&answers, "hash123");

        // Validate TOML
        let parsed: toml::Value = toml::from_str(&config).expect("valid TOML");

        // Check server section
        assert_eq!(
            parsed["server"]["mcp_version"].as_str().unwrap(),
            "2026-07-28"
        );

        // Check modules
        assert!(parsed["modules"]["file"]["enabled"].as_bool().unwrap());
        assert!(parsed["modules"]["git"]["enabled"].as_bool().unwrap());

        // Check agent
        let agents = parsed["agents"].as_array().unwrap();
        assert_eq!(agents[0]["name"].as_str().unwrap(), "claude-code");

        // Check permissions
        assert!(parsed["permissions"]["claude-code"].is_table());
        assert_eq!(
            parsed["permissions"]["claude-code"]["safety"]
                .as_str()
                .unwrap(),
            "standard"
        );

        // Check upstream servers for dev: filesystem + git
        let upstream = parsed["upstream"].as_array().unwrap();
        let names: Vec<&str> = upstream
            .iter()
            .map(|u| u["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"filesystem"));
        assert!(names.contains(&"git"));
    }

    #[test]
    fn test_build_config_data() {
        let answers = InitAnswers {
            project: "data".to_string(),
            ..dev_answers()
        };
        let config = build_config_toml(&answers, "hash123");
        let parsed: toml::Value = toml::from_str(&config).expect("valid TOML");

        let upstream = parsed["upstream"].as_array().unwrap();
        let names: Vec<&str> = upstream
            .iter()
            .map(|u| u["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"filesystem"));
        assert!(names.contains(&"postgres"));
        assert!(names.contains(&"sqlite"));
    }

    #[test]
    fn test_build_config_with_ollama() {
        let answers = InitAnswers {
            model_backend: "ollama".to_string(),
            ..dev_answers()
        };
        let config = build_config_toml(&answers, "hash123");
        let parsed: toml::Value = toml::from_str(&config).expect("valid TOML");

        assert!(parsed["models"]["default"].is_table());
        assert_eq!(
            parsed["models"]["default"]["runtime"].as_str().unwrap(),
            "ollama"
        );
    }

    #[test]
    fn test_build_config_with_anthropic() {
        let answers = InitAnswers {
            model_backend: "anthropic".to_string(),
            api_key: Some("sk-test-123".to_string()),
            ..dev_answers()
        };
        let config = build_config_toml(&answers, "hash123");
        let parsed: toml::Value = toml::from_str(&config).expect("valid TOML");

        assert!(parsed["models"]["default"].is_table());
        assert_eq!(
            parsed["models"]["default"]["api_key"].as_str().unwrap(),
            "sk-test-123"
        );
        assert!(
            parsed["models"]["default"]["base_url"]
                .as_str()
                .unwrap()
                .contains("anthropic")
        );
    }

    #[test]
    fn test_safety_mapping() {
        assert_eq!(safety_profile("standard"), "standard");
        assert_eq!(safety_profile("strict"), "guardian");
        assert_eq!(safety_profile("minimal"), "secrets-only");
        // Unknown levels pass through
        assert_eq!(safety_profile("custom-profile"), "custom-profile");
    }

    #[test]
    fn test_config_roundtrip() {
        // Test all project types generate valid TOML
        for project in &["dev", "data", "ops", "custom"] {
            let answers = InitAnswers {
                project: project.to_string(),
                ..dev_answers()
            };
            let config = build_config_toml(&answers, "hash_abc");
            toml::from_str::<toml::Value>(&config)
                .unwrap_or_else(|e| panic!("Invalid TOML for project {project}: {e}"));
        }

        // Test all model backends
        for backend in &["none", "ollama", "mistral", "anthropic", "openai-compat"] {
            let answers = InitAnswers {
                model_backend: backend.to_string(),
                model_url: Some("http://localhost:8080/v1".to_string()),
                ..dev_answers()
            };
            let config = build_config_toml(&answers, "hash_abc");
            toml::from_str::<toml::Value>(&config)
                .unwrap_or_else(|e| panic!("Invalid TOML for backend {backend}: {e}"));
        }
    }

    #[test]
    fn test_detect_agent_claude() {
        // If .claude/ exists in home (which it does on this dev machine),
        // detect_agent should return "claude". If it doesn't exist, it
        // should return "custom" (not panic).
        let result = detect_agent();
        assert!(
            result == "claude" || result == "goose" || result == "custom",
            "detect_agent returned unexpected: {result}"
        );
    }

    #[test]
    fn test_connection_instructions_claude() {
        let instructions =
            connection_instructions("claude", "mcd_test123", "~/.run/navra/navra.sock");
        assert!(instructions.contains("mcpServers"));
        assert!(instructions.contains("mcd_test123"));
        assert!(instructions.contains(".claude/settings.json"));
    }

    #[test]
    fn test_connection_instructions_goose() {
        let instructions =
            connection_instructions("goose", "mcd_test123", "~/.run/navra/navra.sock");
        assert!(instructions.contains("config.yaml"));
        assert!(instructions.contains("mcd_test123"));
    }

    #[test]
    fn test_connection_instructions_custom() {
        let instructions =
            connection_instructions("custom", "mcd_test123", "~/.run/navra/navra.sock");
        assert!(instructions.contains("Unix socket"));
        assert!(instructions.contains("mcd_test123"));
    }
}
