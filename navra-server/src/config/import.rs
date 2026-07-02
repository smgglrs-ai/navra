use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

const SENSITIVE_PATTERNS: &[&str] = &["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH"];

#[derive(Debug, Clone)]
pub struct ImportedUpstream {
    pub name: String,
    pub transport: String,
    pub command: Vec<String>,
    pub env: HashMap<String, String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    ClaudeDesktop,
    VsCode,
    Codex,
}

impl std::fmt::Display for SourceFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceFormat::ClaudeDesktop => write!(f, "Claude Desktop"),
            SourceFormat::VsCode => write!(f, "VS Code"),
            SourceFormat::Codex => write!(f, "Codex"),
        }
    }
}

pub fn detect_and_parse(content: &str) -> anyhow::Result<(SourceFormat, Vec<ImportedUpstream>)> {
    let trimmed = content.trim();

    if trimmed.starts_with('{') {
        let json: Value = serde_json::from_str(trimmed)?;

        if json.get("mcpServers").is_some() {
            let servers = parse_mcp_servers_json(json.get("mcpServers").unwrap())?;
            return Ok((SourceFormat::ClaudeDesktop, servers));
        }

        if let Some(mcp) = json.get("mcp")
            && let Some(servers_val) = mcp.get("servers")
        {
            let servers = parse_mcp_servers_json(servers_val)?;
            return Ok((SourceFormat::VsCode, servers));
        }

        if json.get("servers").is_some() {
            let servers = parse_mcp_servers_json(json.get("servers").unwrap())?;
            return Ok((SourceFormat::VsCode, servers));
        }

        anyhow::bail!("JSON file does not contain mcpServers, mcp.servers, or servers key");
    }

    if let Ok(toml_val) = trimmed.parse::<toml::Value>() {
        if let Some(table) = toml_val.get("mcp_servers").and_then(|v| v.as_table()) {
            let servers = parse_codex_toml(table)?;
            return Ok((SourceFormat::Codex, servers));
        }
        anyhow::bail!("TOML file does not contain [mcp_servers] table");
    }

    anyhow::bail!("Could not detect format: not valid JSON or TOML")
}

fn parse_mcp_servers_json(servers: &Value) -> anyhow::Result<Vec<ImportedUpstream>> {
    let obj = servers
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("mcpServers/servers must be an object"))?;

    let mut result = Vec::new();
    for (name, server) in obj {
        let mut upstream = ImportedUpstream {
            name: name.clone(),
            transport: "stdio".to_string(),
            command: Vec::new(),
            env: HashMap::new(),
            url: None,
        };

        if let Some(url) = server.get("url").and_then(|v| v.as_str()) {
            upstream.transport = "http".to_string();
            upstream.url = Some(url.to_string());
        } else {
            if let Some(cmd) = server.get("command").and_then(|v| v.as_str()) {
                upstream.command.push(cmd.to_string());
            }
            if let Some(args) = server.get("args").and_then(|v| v.as_array()) {
                for arg in args {
                    if let Some(s) = arg.as_str() {
                        upstream.command.push(s.to_string());
                    }
                }
            }
        }

        if let Some(env) = server.get("env").and_then(|v| v.as_object()) {
            for (k, v) in env {
                if let Some(val) = v.as_str() {
                    upstream.env.insert(k.clone(), val.to_string());
                }
            }
        }

        result.push(upstream);
    }

    Ok(result)
}

fn parse_codex_toml(
    table: &toml::map::Map<String, toml::Value>,
) -> anyhow::Result<Vec<ImportedUpstream>> {
    let mut result = Vec::new();
    for (name, server) in table {
        let server = server
            .as_table()
            .ok_or_else(|| anyhow::anyhow!("[mcp_servers.{name}] must be a table"))?;

        let mut upstream = ImportedUpstream {
            name: name.clone(),
            transport: "stdio".to_string(),
            command: Vec::new(),
            env: HashMap::new(),
            url: None,
        };

        if let Some(cmd) = server.get("command").and_then(|v| v.as_str()) {
            upstream.command.push(cmd.to_string());
        }
        if let Some(args) = server.get("args").and_then(|v| v.as_array()) {
            for arg in args {
                if let Some(s) = arg.as_str() {
                    upstream.command.push(s.to_string());
                }
            }
        }
        if let Some(env) = server.get("env").and_then(|v| v.as_table()) {
            for (k, v) in env {
                if let Some(val) = v.as_str() {
                    upstream.env.insert(k.clone(), val.to_string());
                }
            }
        }

        result.push(upstream);
    }
    Ok(result)
}

fn is_sensitive_key(key: &str) -> bool {
    let upper = key.to_uppercase();
    SENSITIVE_PATTERNS.iter().any(|p| upper.contains(p))
}

pub fn to_toml(servers: &[ImportedUpstream], redact: bool) -> String {
    let mut out = String::new();
    for server in servers {
        out.push_str("[[upstream]]\n");
        out.push_str(&format!("name = {:?}\n", server.name));
        out.push_str(&format!("transport = {:?}\n", server.transport));
        if !server.command.is_empty() {
            let items: Vec<String> = server.command.iter().map(|s| format!("{s:?}")).collect();
            out.push_str(&format!("command = [{}]\n", items.join(", ")));
        }
        if let Some(url) = &server.url {
            out.push_str(&format!("url = {:?}\n", url));
        }
        if !server.env.is_empty() {
            out.push_str("[upstream.env]\n");
            let mut keys: Vec<&String> = server.env.keys().collect();
            keys.sort();
            for k in keys {
                let v = &server.env[k];
                let display_val = if redact && is_sensitive_key(k) {
                    "<REDACTED>".to_string()
                } else {
                    v.clone()
                };
                out.push_str(&format!("{k} = {:?}\n", display_val));
            }
        }
        out.push('\n');
    }
    out
}

pub fn discover_config_files() -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();

    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return found,
    };

    let candidates = [
        home.join(".claude.json"),
        home.join(".claude/claude_desktop_config.json"),
    ];

    for path in &candidates {
        if path.exists() {
            found.push(path.clone());
        }
    }

    let cwd_mcp = Path::new(".mcp.json");
    if cwd_mcp.exists() {
        found.push(cwd_mcp.to_path_buf());
    }

    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_claude_desktop() {
        let json = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {
                        "HOME": "/home/user",
                        "API_KEY": "sk-secret-123"
                    }
                },
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {
                        "GITHUB_TOKEN": "ghp_abc123"
                    }
                }
            }
        }"#;

        let (format, servers) = detect_and_parse(json).unwrap();
        assert_eq!(format, SourceFormat::ClaudeDesktop);
        assert_eq!(servers.len(), 2);

        let fs = servers.iter().find(|s| s.name == "filesystem").unwrap();
        assert_eq!(fs.transport, "stdio");
        assert_eq!(
            fs.command,
            vec![
                "npx",
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/tmp"
            ]
        );
        assert_eq!(fs.env.get("API_KEY").unwrap(), "sk-secret-123");
    }

    #[test]
    fn parse_vscode_mcp_servers() {
        let json = r#"{
            "mcp": {
                "servers": {
                    "my-server": {
                        "command": "node",
                        "args": ["server.js"],
                        "env": {
                            "PORT": "3000"
                        }
                    }
                }
            }
        }"#;

        let (format, servers) = detect_and_parse(json).unwrap();
        assert_eq!(format, SourceFormat::VsCode);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "my-server");
        assert_eq!(servers[0].command, vec!["node", "server.js"]);
    }

    #[test]
    fn parse_vscode_servers_key() {
        let json = r#"{
            "servers": {
                "test": {
                    "command": "python3",
                    "args": ["-m", "server"]
                }
            }
        }"#;

        let (format, servers) = detect_and_parse(json).unwrap();
        assert_eq!(format, SourceFormat::VsCode);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].command, vec!["python3", "-m", "server"]);
    }

    #[test]
    fn parse_codex_toml() {
        let toml = r#"
[mcp_servers.my-tool]
command = "npx"
args = ["-y", "my-tool-server"]

[mcp_servers.my-tool.env]
API_KEY = "test-key"
"#;

        let (format, servers) = detect_and_parse(toml).unwrap();
        assert_eq!(format, SourceFormat::Codex);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "my-tool");
        assert_eq!(servers[0].command, vec!["npx", "-y", "my-tool-server"]);
        assert_eq!(servers[0].env.get("API_KEY").unwrap(), "test-key");
    }

    #[test]
    fn parse_http_transport() {
        let json = r#"{
            "mcpServers": {
                "remote": {
                    "url": "http://localhost:8080/mcp"
                }
            }
        }"#;

        let (_, servers) = detect_and_parse(json).unwrap();
        assert_eq!(servers[0].transport, "http");
        assert_eq!(servers[0].url.as_deref(), Some("http://localhost:8080/mcp"));
        assert!(servers[0].command.is_empty());
    }

    #[test]
    fn redact_sensitive_env() {
        let servers = vec![ImportedUpstream {
            name: "test".to_string(),
            transport: "stdio".to_string(),
            command: vec!["cmd".to_string()],
            env: HashMap::from([
                ("API_KEY".to_string(), "secret-value".to_string()),
                ("GITHUB_TOKEN".to_string(), "ghp_abc".to_string()),
                ("HOME".to_string(), "/home/user".to_string()),
                ("DB_PASSWORD".to_string(), "hunter2".to_string()),
            ]),
            url: None,
        }];

        let output = to_toml(&servers, true);
        assert!(output.contains("<REDACTED>"));
        assert!(!output.contains("secret-value"));
        assert!(!output.contains("ghp_abc"));
        assert!(!output.contains("hunter2"));
        assert!(output.contains("/home/user"));
    }

    #[test]
    fn no_redact_when_disabled() {
        let servers = vec![ImportedUpstream {
            name: "test".to_string(),
            transport: "stdio".to_string(),
            command: vec!["cmd".to_string()],
            env: HashMap::from([("API_KEY".to_string(), "secret-value".to_string())]),
            url: None,
        }];

        let output = to_toml(&servers, false);
        assert!(output.contains("secret-value"));
        assert!(!output.contains("REDACTED"));
    }

    #[test]
    fn toml_output_format() {
        let servers = vec![ImportedUpstream {
            name: "filesystem".to_string(),
            transport: "stdio".to_string(),
            command: vec!["npx".to_string(), "-y".to_string(), "server".to_string()],
            env: HashMap::new(),
            url: None,
        }];

        let output = to_toml(&servers, true);
        assert!(output.contains("[[upstream]]"));
        assert!(output.contains(r#"name = "filesystem""#));
        assert!(output.contains(r#"transport = "stdio""#));
        assert!(output.contains(r#"command = ["npx", "-y", "server"]"#));
    }

    #[test]
    fn invalid_format_errors() {
        assert!(detect_and_parse("not json or toml {{{").is_err());
        assert!(detect_and_parse(r#"{"unknown": true}"#).is_err());
        assert!(detect_and_parse("[some_other_table]\nfoo = 1").is_err());
    }
}
