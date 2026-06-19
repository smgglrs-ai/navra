//! Egress endpoint allowlist hook.
//!
//! Pre-call hook that blocks tool calls targeting external endpoints
//! not on an allowlist. Motivated by the Shadow Escape zero-click MCP
//! attack: a compromised tool can exfiltrate data by embedding URLs
//! in arguments that reach external services.

use super::{Hook, HookDecision};
use navra_auth::auth::CallContext;

/// Configuration for the egress endpoint allowlist.
#[derive(Debug, Clone)]
pub struct EgressConfig {
    /// Whether the hook is enabled.
    pub enabled: bool,
    /// Domains explicitly allowed (e.g. `"github.com"`, `"*.example.com"`).
    pub allowed_domains: Vec<String>,
    /// Domains explicitly denied (checked first — deny wins).
    pub blocked_domains: Vec<String>,
    /// When true, only `allowed_domains` are reachable.
    pub deny_all_external: bool,
    /// Block egress from sessions tainted as untrusted or sensitive.
    pub block_tainted_egress: bool,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_domains: Vec::new(),
            blocked_domains: Vec::new(),
            deny_all_external: false,
            block_tainted_egress: true,
        }
    }
}

/// Pre-call hook that enforces an egress endpoint allowlist.
///
/// Recursively walks tool arguments for URL-like strings, extracts
/// domains, and checks them against blocked/allowed lists.
pub struct EgressFilterHook {
    config: EgressConfig,
}

impl EgressFilterHook {
    /// Create a new egress filter hook with the given config.
    pub fn new(config: EgressConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl Hook for EgressFilterHook {
    fn name(&self) -> &str {
        "egress-filter"
    }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        ctx: &CallContext,
        _annotations: Option<&navra_protocol::ToolAnnotations>,
    ) -> HookDecision {
        if !self.config.enabled {
            return HookDecision::Continue;
        }

        let urls = extract_urls(arguments);
        if urls.is_empty() {
            return HookDecision::Continue;
        }

        let domains: Vec<String> = urls.iter().filter_map(|u| extract_domain(u)).collect();
        if domains.is_empty() {
            return HookDecision::Continue;
        }

        // Tainted session check
        if self.config.block_tainted_egress
            && (ctx.taint.is_untrusted() || ctx.taint.is_sensitive())
        {
            let joined = domains.join(", ");
            tracing::warn!(
                tool = %tool_name,
                session = %ctx.session_id,
                domains = %joined,
                "egress-filter: blocked tainted session from external egress"
            );
            return HookDecision::Block(format!(
                "egress-filter: tainted session cannot reach external endpoints [{joined}]"
            ));
        }

        for domain in &domains {
            // Blocked domains checked first (deny wins)
            if self
                .config
                .blocked_domains
                .iter()
                .any(|p| matches_pattern(domain, p))
            {
                tracing::warn!(
                    tool = %tool_name,
                    session = %ctx.session_id,
                    domain = %domain,
                    "egress-filter: blocked explicitly denied domain"
                );
                return HookDecision::Block(format!(
                    "egress-filter: domain '{domain}' is explicitly blocked"
                ));
            }

            if self.config.deny_all_external
                && !self
                    .config
                    .allowed_domains
                    .iter()
                    .any(|p| matches_pattern(domain, p))
            {
                tracing::warn!(
                    tool = %tool_name,
                    session = %ctx.session_id,
                    domain = %domain,
                    "egress-filter: blocked non-allowlisted domain"
                );
                return HookDecision::Block(format!(
                    "egress-filter: domain '{domain}' is not on the allowlist"
                ));
            }
        }

        HookDecision::Continue
    }
}

/// Recursively walk a JSON value and collect URL-like strings.
pub fn extract_urls(value: &serde_json::Value) -> Vec<String> {
    let mut urls = Vec::new();
    collect_urls(value, &mut urls);
    urls
}

fn collect_urls(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            for token in s.split_whitespace() {
                if token.starts_with("http://") || token.starts_with("https://") {
                    out.push(token.to_string());
                } else if looks_like_hostname(token) {
                    out.push(format!("http://{token}"));
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_urls(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_urls(v, out);
            }
        }
        _ => {}
    }
}

fn looks_like_hostname(s: &str) -> bool {
    if !s.contains('.') {
        return false;
    }
    // IPv4 pattern
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return true;
    }
    // Bare hostname heuristic: at least two segments, no spaces, no slashes
    if parts.len() >= 2
        && !s.contains(' ')
        && !s.starts_with('/')
        && !s.starts_with('.')
        && !s.ends_with('.')
    {
        let tld = parts.last().unwrap();
        if tld.len() >= 2 && tld.len() <= 10 && tld.chars().all(|c| c.is_ascii_alphabetic()) {
            return true;
        }
    }
    false
}

/// Extract the domain (host) from a URL string.
pub fn extract_domain(url: &str) -> Option<String> {
    let s = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host_port = s.split('/').next()?;
    let host = host_port.split(':').next()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_lowercase())
}

/// Match a domain against a pattern. Supports exact match and wildcard
/// prefix (`*.example.com` matches `sub.example.com` but not `example.com`).
pub fn matches_pattern(domain: &str, pattern: &str) -> bool {
    let domain = domain.to_lowercase();
    let pattern = pattern.to_lowercase();

    if let Some(suffix) = pattern.strip_prefix("*.") {
        domain.ends_with(&format!(".{suffix}")) && domain.len() > suffix.len() + 1
    } else {
        domain == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_auth::auth::AgentIdentity;
    use navra_auth::ifc::DataLabel;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
    }

    fn tainted_ctx() -> CallContext {
        let mut ctx = test_ctx();
        ctx.taint.absorb(DataLabel::UNTRUSTED_PUBLIC);
        ctx
    }

    fn deny_all_hook() -> EgressFilterHook {
        EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: Vec::new(),
            blocked_domains: Vec::new(),
            deny_all_external: true,
            block_tainted_egress: true,
        })
    }

    // 1. Blocks non-allowlisted URL when deny_all_external
    #[tokio::test]
    async fn blocks_non_allowlisted_url_when_deny_all() {
        let hook = deny_all_hook();
        let args = serde_json::json!({"url": "https://evil.com/exfil"});
        let decision = hook.pre_tool_use("http_request", &args, &test_ctx(), None).await;
        match decision {
            HookDecision::Block(reason) => {
                assert!(reason.contains("evil.com"));
                assert!(reason.contains("allowlist"));
            }
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    // 2. Allows allowlisted domain
    #[tokio::test]
    async fn allows_allowlisted_domain() {
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec!["github.com".to_string()],
            blocked_domains: Vec::new(),
            deny_all_external: true,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"url": "https://github.com/repo"});
        let decision = hook.pre_tool_use("http_request", &args, &test_ctx(), None).await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    // 3. Blocked domains wins over allowed
    #[tokio::test]
    async fn blocked_domains_wins_over_allowed() {
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec!["evil.com".to_string()],
            blocked_domains: vec!["evil.com".to_string()],
            deny_all_external: false,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"url": "https://evil.com/data"});
        let decision = hook.pre_tool_use("http_request", &args, &test_ctx(), None).await;
        match decision {
            HookDecision::Block(reason) => {
                assert!(reason.contains("evil.com"));
                assert!(reason.contains("blocked"));
            }
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    // 4. Wildcard matching works
    #[tokio::test]
    async fn wildcard_matching_works() {
        assert!(matches_pattern("sub.example.com", "*.example.com"));
        assert!(matches_pattern("deep.sub.example.com", "*.example.com"));
        assert!(!matches_pattern("example.com", "*.example.com"));

        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec!["*.example.com".to_string()],
            blocked_domains: Vec::new(),
            deny_all_external: true,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"url": "https://api.example.com/v1"});
        let decision = hook.pre_tool_use("http_request", &args, &test_ctx(), None).await;
        assert!(matches!(decision, HookDecision::Continue));

        // Bare domain should NOT match wildcard
        let args2 = serde_json::json!({"url": "https://example.com/v1"});
        let decision2 = hook.pre_tool_use("http_request", &args2, &test_ctx(), None).await;
        assert!(matches!(decision2, HookDecision::Block(_)));
    }

    // 5. Blocks tainted session egress
    #[tokio::test]
    async fn blocks_tainted_session_egress() {
        let hook = deny_all_hook();
        let args = serde_json::json!({"url": "https://anything.com/data"});
        let decision = hook
            .pre_tool_use("http_request", &args, &tainted_ctx(), None)
            .await;
        match decision {
            HookDecision::Block(reason) => {
                assert!(reason.contains("tainted"));
            }
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    // 6. Allows internal tool without URLs
    #[tokio::test]
    async fn allows_internal_tool_without_urls() {
        let hook = deny_all_hook();
        let args = serde_json::json!({"path": "/home/user/file.txt", "content": "hello"});
        let decision = hook.pre_tool_use("file_write", &args, &test_ctx(), None).await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    // 7. Finds URLs in nested JSON
    #[tokio::test]
    async fn finds_urls_in_nested_json() {
        let hook = deny_all_hook();
        let args = serde_json::json!({
            "headers": {"referer": "https://attacker.com/track"},
            "body": {"links": ["https://evil.org/exfil"]},
        });
        let decision = hook.pre_tool_use("http_request", &args, &test_ctx(), None).await;
        match decision {
            HookDecision::Block(reason) => {
                assert!(
                    reason.contains("attacker.com") || reason.contains("evil.org"),
                    "should block one of the nested domains: {reason}"
                );
            }
            other => panic!("Expected Block, got {other:?}"),
        }
    }

    // 8. Disabled hook passes everything
    #[tokio::test]
    async fn disabled_hook_passes_everything() {
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: false,
            ..Default::default()
        });
        let args = serde_json::json!({"url": "https://evil.com/exfil"});
        let decision = hook.pre_tool_use("http_request", &args, &test_ctx(), None).await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    // Helper unit tests
    #[test]
    fn extract_domain_from_urls() {
        assert_eq!(
            extract_domain("https://github.com/repo"),
            Some("github.com".to_string())
        );
        assert_eq!(
            extract_domain("http://evil.com:8080/path"),
            Some("evil.com".to_string())
        );
        assert_eq!(
            extract_domain("https://Sub.Example.COM/path"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(extract_domain("not-a-url"), None);
    }

    #[test]
    fn extract_urls_finds_bare_hostnames() {
        let val = serde_json::json!({"target": "evil.com"});
        let urls = extract_urls(&val);
        assert!(!urls.is_empty());
        assert_eq!(extract_domain(&urls[0]), Some("evil.com".to_string()));
    }

    #[test]
    fn extract_urls_finds_ip_addresses() {
        let val = serde_json::json!({"host": "192.168.1.1"});
        let urls = extract_urls(&val);
        assert!(!urls.is_empty());
    }

    #[test]
    fn matches_pattern_exact_and_case_insensitive() {
        assert!(matches_pattern("github.com", "github.com"));
        assert!(!matches_pattern("github.com", "gitlab.com"));
        assert!(matches_pattern("GitHub.COM", "github.com"));
        assert!(matches_pattern("Sub.Example.COM", "*.example.com"));
    }
}
