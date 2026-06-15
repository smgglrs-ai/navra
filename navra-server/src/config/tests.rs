use super::*;

#[test]
fn parse_minimal_config() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.server.tcp.as_deref(), Some("127.0.0.1:9315"));
    assert!(config.file_enabled());
}

#[test]
fn parse_modular_config() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[modules.file]
enabled = true
db = "/tmp/test.db"

[[agents]]
name = "claude"
token_hash = "abc123"
permissions = "developer"

[permissions.developer]
allow = ["~/Documents/**"]
deny = ["**/.env"]
operations = ["read", "write", "search", "list", "git.status"]
approve = ["write", "git.commit"]
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert!(config.file_enabled());
    assert_eq!(config.file_db_path(), "/tmp/test.db");
    assert_eq!(config.agents.len(), 1);
    let dev = &config.permissions["developer"];
    assert!(dev.operations.contains(&"git.status".to_string()));
    assert!(dev.approve.contains(&"git.commit".to_string()));
}

#[test]
fn disable_module() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[modules.file]
enabled = false
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert!(!config.file_enabled());
}

#[test]
fn default_config_is_valid() {
    let config = Config::default();
    assert!(config.agents.is_empty());
    assert!(config.file_enabled());
}

#[test]
fn parse_upstream_config() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[[upstream]]
name = "navra"
command = ["poetry", "run", "python", "-m", "navra.memory.mcp_server"]
cwd = "/home/user/navra"

[[upstream]]
name = "api-server"
transport = "http"
url = "http://localhost:8001/mcp"

[[upstream]]
name = "sse-server"
transport = "sse"
url = "http://localhost:8002/sse"

[[upstream]]
name = "disabled-server"
command = ["echo", "noop"]
enabled = false
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.upstream.len(), 4);

    // stdio (default transport)
    assert_eq!(config.upstream[0].name, "navra");
    assert_eq!(config.upstream[0].transport, "stdio");
    assert_eq!(config.upstream[0].command[0], "poetry");
    assert_eq!(config.upstream[0].cwd.as_deref(), Some("/home/user/navra"));

    // http
    assert_eq!(config.upstream[1].name, "api-server");
    assert_eq!(config.upstream[1].transport, "http");
    assert_eq!(
        config.upstream[1].url.as_deref(),
        Some("http://localhost:8001/mcp")
    );

    // sse
    assert_eq!(config.upstream[2].transport, "sse");

    // disabled
    assert_eq!(config.upstream[3].enabled, Some(false));
}

#[test]
fn generate_token_format() {
    let token = generate_token();
    assert!(token.starts_with("mcd_"));
    // 4 prefix chars + 64 hex chars = 68 total
    assert_eq!(token.len(), 68);
    // Verify uniqueness
    let token2 = generate_token();
    assert_ne!(token, token2);
}

#[test]
fn parse_permission_rings() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[permissions.admin]
ring = 0
allow = ["/home/user/**"]
deny = ["**/.env"]
operations = ["read", "write", "git.status", "git.commit", "shell.exec"]

[permissions.developer]
ring = 1
allow = ["/home/user/projects/**"]
operations = ["read", "write", "git.status", "git.commit"]
approve = ["git.commit"]

[permissions.readonly]
ring = 2
allow = ["/home/user/projects/public/**"]
operations = ["read", "search", "list"]
"#;
    let config: Config = toml::from_str(toml).unwrap();

    assert_eq!(config.permissions["admin"].ring, Some(0));
    assert_eq!(config.permissions["developer"].ring, Some(1));
    assert_eq!(config.permissions["readonly"].ring, Some(2));
}

#[test]
fn ring_defaults_to_none() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[permissions.custom]
allow = ["~/Documents/**"]
operations = ["read"]
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.permissions["custom"].ring, None);
}

#[test]
fn parse_compliance_tags() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[permissions.audited]
allow = ["~/Projects/**"]
operations = ["read", "write"]
compliance = ["SOC2-CC6.1", "EU-AI-Act-Art-14", "HIPAA-164.312"]

[permissions.internal]
allow = ["~/Internal/**"]
operations = ["read"]
"#;
    let config: Config = toml::from_str(toml).unwrap();

    let audited = &config.permissions["audited"];
    assert_eq!(audited.compliance.len(), 3);
    assert!(audited.compliance.contains(&"SOC2-CC6.1".to_string()));
    assert!(audited.compliance.contains(&"EU-AI-Act-Art-14".to_string()));
    assert!(audited.compliance.contains(&"HIPAA-164.312".to_string()));

    // Permission set without compliance tags defaults to empty
    let internal = &config.permissions["internal"];
    assert!(internal.compliance.is_empty());
}

#[test]
fn parse_identity_config() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[server.identity]
key_path = "/etc/navra/identity.key"
token_ttl = 1800
max_delegation_depth = 2
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let identity = config.server.identity.as_ref().unwrap();
    assert_eq!(
        identity.key_path.as_deref(),
        Some("/etc/navra/identity.key")
    );
    assert_eq!(identity.token_ttl, 1800);
    assert_eq!(identity.max_delegation_depth, 2);
}

#[test]
fn parse_credential_mappings() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[credentials]
"github.pat" = { source = "keyring", path = "navra/github-pat" }
"ci.token" = { source = "env", var = "GITHUB_TOKEN" }
"gnome.github" = { source = "keyring", path = "org.gnome.OnlineAccounts/github" }
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.credentials.len(), 3);

    let gh = &config.credentials["github.pat"];
    assert_eq!(gh.source, "keyring");
    assert_eq!(gh.path.as_deref(), Some("navra/github-pat"));

    let ci = &config.credentials["ci.token"];
    assert_eq!(ci.source, "env");
    assert_eq!(ci.var.as_deref(), Some("GITHUB_TOKEN"));
}

#[test]
fn parse_agent_capability_fields() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[[agents]]
name = "leader"
token_hash = "abc123"
permissions = "admin"
pubkey = "~/.config/navra/agents/leader.pub"
capability_token = true
token_ttl = 900
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let agent = &config.agents[0];
    assert_eq!(
        agent.pubkey.as_deref(),
        Some("~/.config/navra/agents/leader.pub")
    );
    assert!(agent.capability_token);
    assert_eq!(agent.token_ttl, Some(900));
}

#[test]
fn parse_permission_credentials() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[permissions.leader]
ring = 1
allow = ["~/Code/**"]
operations = ["read", "write"]
credentials = ["github.pat", "jira.token"]
can_delegate = true
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let leader = &config.permissions["leader"];
    assert_eq!(leader.credentials, vec!["github.pat", "jira.token"]);
    assert!(leader.can_delegate);
}

#[test]
fn parse_model_agentic_config() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[models.granite-code]
task = "chat"
source = "ollama://granite-code:3b"

[models.granite-code.agentic]
strengths = ["code generation", "fast inference"]
weaknesses = ["limited reasoning"]
recommended_tasks = ["code review"]
avoid_tasks = ["multi-step planning"]
tool_use = "basic"
cost_tier = "free"
speed_tier = "fast"
max_agents = 4
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let model = &config.models["granite-code"];
    let agentic = model.agentic.as_ref().unwrap();
    assert_eq!(agentic.strengths, vec!["code generation", "fast inference"]);
    assert_eq!(agentic.tool_use, Some("basic".to_string()));
    assert_eq!(agentic.max_agents, Some(4));
}

#[test]
fn agent_capability_defaults() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[[agents]]
name = "legacy"
token_hash = "xyz"
permissions = "dev"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let agent = &config.agents[0];
    assert!(agent.pubkey.is_none());
    assert!(agent.did.is_none());
    assert!(!agent.capability_token);
    assert!(agent.token_ttl.is_none());
}

#[test]
fn parse_pii_patterns() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[[pii_patterns]]
name = "employee-id"
regex = "\\bEMP-\\d{6}\\b"
category = "employee-id"

[[pii_patterns]]
name = "badge-number"
regex = "\\bBDG[A-Z]\\d{4}\\b"
category = "badge"

[[pii_patterns]]
name = "internal-project"
regex = "\\bPRJ-[A-Z]{3}-\\d{4}\\b"
category = "project-code"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.pii_patterns.len(), 3);

    assert_eq!(config.pii_patterns[0].name, "employee-id");
    assert_eq!(config.pii_patterns[0].regex, r"\bEMP-\d{6}\b");
    assert_eq!(config.pii_patterns[0].category, "employee-id");

    assert_eq!(config.pii_patterns[1].name, "badge-number");
    assert_eq!(config.pii_patterns[1].category, "badge");

    assert_eq!(config.pii_patterns[2].name, "internal-project");
    assert_eq!(config.pii_patterns[2].category, "project-code");
}

#[test]
fn pii_patterns_default_empty() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert!(config.pii_patterns.is_empty());
}

#[test]
fn parse_routing_config() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[routing]
enabled = true
default_tier = "medium"

[[routing.tiers]]
name = "small"
model = "qwen2.5:3b"
max_tokens = 500
patterns = ["file_read", "git_status", "git_log"]

[[routing.tiers]]
name = "medium"
model = "granite3:8b"
max_tokens = 2000
patterns = ["file_write", "git_commit", "github_*"]

[[routing.tiers]]
name = "large"
model = "llama3.3:70b"
max_tokens = 8000
patterns = ["*_create", "*_review"]
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert!(config.routing.enabled);
    assert_eq!(config.routing.default_tier, "medium");
    assert_eq!(config.routing.tiers.len(), 3);
    assert_eq!(config.routing.tiers[0].name, "small");
    assert_eq!(config.routing.tiers[0].model, "qwen2.5:3b");
    assert_eq!(config.routing.tiers[0].max_tokens, 500);
    assert_eq!(
        config.routing.tiers[1].patterns,
        vec!["file_write", "git_commit", "github_*"]
    );
    assert_eq!(config.routing.tiers[2].name, "large");
}

#[test]
fn routing_defaults_when_absent() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert!(!config.routing.enabled);
    assert_eq!(config.routing.default_tier, "medium");
    assert!(config.routing.tiers.is_empty());
}

#[test]
fn parse_trigger_config() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"

[[triggers]]
type = "webhook"
path = "/hook/deploy"
secret = "my-webhook-secret"
flow_name = "review"

[[triggers]]
type = "cron"
schedule = "0 9 * * 1-5"
flow_name = "daily-review"

[[triggers]]
type = "file_watch"
path = "~/Documents/inbox"
pattern = "*.pdf"
flow_name = "process-document"
debounce_ms = 1000
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.triggers.len(), 3);

    match &config.triggers[0] {
        crate::triggers::TriggerConfig::Webhook {
            path,
            secret,
            flow_name,
        } => {
            assert_eq!(path, "/hook/deploy");
            assert_eq!(secret.as_deref(), Some("my-webhook-secret"));
            assert_eq!(flow_name, "review");
        }
        _ => panic!("Expected Webhook trigger"),
    }

    match &config.triggers[1] {
        crate::triggers::TriggerConfig::Cron {
            schedule,
            flow_name,
        } => {
            assert_eq!(schedule, "0 9 * * 1-5");
            assert_eq!(flow_name, "daily-review");
        }
        _ => panic!("Expected Cron trigger"),
    }

    match &config.triggers[2] {
        crate::triggers::TriggerConfig::FileWatch {
            path,
            pattern,
            flow_name,
            debounce_ms,
        } => {
            assert_eq!(path, "~/Documents/inbox");
            assert_eq!(pattern.as_deref(), Some("*.pdf"));
            assert_eq!(flow_name, "process-document");
            assert_eq!(*debounce_ms, Some(1000));
        }
        _ => panic!("Expected FileWatch trigger"),
    }
}

#[test]
fn triggers_default_empty() {
    let toml = r#"
[server]
tcp = "127.0.0.1:9315"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert!(!config.routing.enabled);
    assert_eq!(config.routing.default_tier, "medium");
    assert!(config.routing.tiers.is_empty());
    assert!(config.triggers.is_empty());
}

#[test]
fn schema_all_fields_described() {
    let schema = schemars::schema_for!(super::Config);
    let json = serde_json::to_value(&schema).unwrap();
    if let Some(props) = json.pointer("/properties") {
        for (key, val) in props.as_object().unwrap() {
            assert!(
                val.get("description").is_some() || val.get("$ref").is_some(),
                "field '{key}' lacks a description in the JSON Schema"
            );
        }
    }
}
