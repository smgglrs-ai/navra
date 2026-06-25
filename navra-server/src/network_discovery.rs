//! Network requirement discovery for MCP upstream servers.
//!
//! Provides heuristic extraction of required network endpoints from
//! server names, commands, and tool descriptions. Used by `navra wrap
//! --discover` to suggest egress policies.

use navra_safety_hooks::hooks::egress::{extract_domain, extract_urls};

/// Result of network requirement discovery.
#[derive(Debug, Default)]
pub struct NetworkRequirements {
    /// Domains discovered from the known-server registry.
    pub known: Vec<String>,
    /// Domains extracted from tool descriptions.
    pub from_descriptions: Vec<String>,
    /// Tools whose input schema suggests they accept URLs.
    pub url_accepting_tools: Vec<String>,
}

impl NetworkRequirements {
    pub fn all_domains(&self) -> Vec<String> {
        let mut all: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        all.extend(self.known.iter().cloned());
        all.extend(self.from_descriptions.iter().cloned());
        all.into_iter().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
            && self.from_descriptions.is_empty()
            && self.url_accepting_tools.is_empty()
    }
}

/// Look up network requirements for well-known MCP servers.
///
/// Matches on server name and command binary. Returns `None` if the
/// server is not in the registry.
pub fn known_server_domains(name: &str, command: &[String]) -> Option<Vec<String>> {
    let name_lower = name.to_lowercase();
    let binary = command
        .first()
        .and_then(|c| {
            std::path::Path::new(c)
                .file_name()
                .and_then(|n| n.to_str())
        })
        .unwrap_or("")
        .to_lowercase();

    let cmd_joined = command.join(" ").to_lowercase();

    if name_lower.contains("google-workspace")
        || name_lower.contains("google_workspace")
        || cmd_joined.contains("google-workspace")
    {
        return Some(vec![
            "*.googleapis.com".into(),
            "accounts.google.com".into(),
            "oauth2.googleapis.com".into(),
        ]);
    }

    if name_lower.contains("github") || cmd_joined.contains("server-github") {
        return Some(vec![
            "api.github.com".into(),
            "github.com".into(),
            "*.githubusercontent.com".into(),
        ]);
    }

    if name_lower.contains("gitlab") || cmd_joined.contains("server-gitlab") {
        return Some(vec!["gitlab.com".into(), "*.gitlab.com".into()]);
    }

    if name_lower.contains("slack") || cmd_joined.contains("server-slack") {
        return Some(vec!["slack.com".into(), "*.slack.com".into()]);
    }

    if name_lower.contains("jira") || name_lower.contains("atlassian") {
        return Some(vec![
            "*.atlassian.net".into(),
            "*.atlassian.com".into(),
        ]);
    }

    if name_lower.contains("notion") || cmd_joined.contains("server-notion") {
        return Some(vec!["api.notion.com".into()]);
    }

    if name_lower.contains("linear") || cmd_joined.contains("server-linear") {
        return Some(vec!["api.linear.app".into()]);
    }

    if name_lower.contains("postgres")
        || name_lower.contains("mysql")
        || name_lower.contains("sqlite")
        || binary.contains("database")
    {
        return Some(vec![]);
    }

    if name_lower.contains("filesystem")
        || cmd_joined.contains("server-filesystem")
        || cmd_joined.contains("server-everything")
    {
        return Some(vec![]);
    }

    if name_lower.contains("puppeteer")
        || name_lower.contains("playwright")
        || name_lower.contains("browser")
    {
        return None;
    }

    None
}

/// Extract potential network endpoints from tool descriptions.
pub fn discover_from_tools(tools: &[rmcp::model::Tool]) -> NetworkRequirements {
    let mut reqs = NetworkRequirements::default();
    let mut seen = std::collections::BTreeSet::new();

    for tool in tools {
        if let Some(ref desc) = tool.description {
            let val = serde_json::Value::String(desc.to_string());
            for url in extract_urls(&val) {
                if let Some(domain) = extract_domain(&url) {
                    if seen.insert(domain.clone()) {
                        reqs.from_descriptions.push(domain);
                    }
                }
            }
        }

        if let Some(props) = tool.input_schema.get("properties").and_then(|v| v.as_object()) {
            for key in props.keys() {
                let k = key.to_lowercase();
                if k == "url" || k == "endpoint" || k == "uri" || k == "host" {
                    reqs.url_accepting_tools.push(tool.name.to_string());
                    break;
                }
            }
        }
    }

    reqs
}

/// Run all discovery heuristics and merge results.
pub fn discover_all(
    name: &str,
    command: &[String],
    tools: &[rmcp::model::Tool],
) -> NetworkRequirements {
    let mut reqs = discover_from_tools(tools);

    if let Some(known) = known_server_domains(name, command) {
        reqs.known = known;
    }

    reqs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_google_workspace() {
        let domains =
            known_server_domains("google-workspace", &["npx".into(), "server-google".into()])
                .unwrap();
        assert!(domains.iter().any(|d| d.contains("googleapis.com")));
        assert!(domains.iter().any(|d| d.contains("accounts.google.com")));
    }

    #[test]
    fn known_github() {
        let domains = known_server_domains(
            "my-github",
            &["npx".into(), "@modelcontextprotocol/server-github".into()],
        )
        .unwrap();
        assert!(domains.iter().any(|d| d == "api.github.com"));
    }

    #[test]
    fn known_filesystem_is_offline() {
        let domains = known_server_domains("fs", &["npx".into(), "server-filesystem".into()])
            .unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn unknown_server_returns_none() {
        assert!(known_server_domains("custom-tool", &["./my-server".into()]).is_none());
    }

    #[test]
    fn known_slack() {
        let domains = known_server_domains("slack", &["npx".into(), "server-slack".into()])
            .unwrap();
        assert!(domains.iter().any(|d| d.contains("slack.com")));
    }

    #[test]
    fn known_jira() {
        let domains =
            known_server_domains("jira-cloud", &["npx".into(), "server-jira".into()]).unwrap();
        assert!(domains.iter().any(|d| d.contains("atlassian")));
    }

    fn make_tool(name: &str, description: &str, schema_json: &str) -> rmcp::model::Tool {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "description": description,
            "inputSchema": serde_json::from_str::<serde_json::Value>(schema_json).unwrap(),
        }))
        .unwrap()
    }

    #[test]
    fn discover_from_tools_extracts_urls() {
        let tools = vec![make_tool(
            "fetch_page",
            "Fetch a page from https://docs.example.com/api for processing",
            r#"{"type":"object","properties":{"path":{"type":"string"}}}"#,
        )];
        let reqs = discover_from_tools(&tools);
        assert!(reqs.from_descriptions.iter().any(|d| d == "docs.example.com"));
    }

    #[test]
    fn discover_from_tools_detects_url_params() {
        let tools = vec![make_tool(
            "http_request",
            "Make an HTTP request",
            r#"{"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string"}}}"#,
        )];
        let reqs = discover_from_tools(&tools);
        assert!(reqs.url_accepting_tools.contains(&"http_request".to_string()));
    }

    #[test]
    fn all_domains_deduplicates() {
        let reqs = NetworkRequirements {
            known: vec!["api.github.com".into(), "github.com".into()],
            from_descriptions: vec!["api.github.com".into(), "docs.github.com".into()],
            url_accepting_tools: vec![],
        };
        let all = reqs.all_domains();
        assert_eq!(
            all.iter().filter(|d| *d == "api.github.com").count(),
            1
        );
    }
}
