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

        // Degenerate/unresolvable URLs (e.g. "https:///" or
        // "https://:") produce no domain. Fail closed: they count as
        // a taint match for the tainted-session check, and as
        // non-allowlisted whenever any domain list (or
        // deny_all_external) is configured.
        let mut saw_unresolvable = false;
        let domains: Vec<String> = urls
            .iter()
            .filter_map(|u| match extract_domain(u) {
                Some(d) => Some(d),
                None => {
                    saw_unresolvable = true;
                    None
                }
            })
            .collect();
        if domains.is_empty() && !saw_unresolvable {
            return HookDecision::Continue;
        }

        // Any list configured at all (blocklist, allowlist, or
        // deny-all): unparseable authorities are treated as a taint
        // match and blocked rather than passed through unmatched.
        let lists_configured = self.config.deny_all_external
            || !self.config.blocked_domains.is_empty()
            || !self.config.allowed_domains.is_empty();

        // Tainted session check
        if self.config.block_tainted_egress
            && (ctx.taint.is_untrusted() || ctx.taint.is_sensitive())
        {
            let mut taint_domains = domains.clone();
            if saw_unresolvable {
                taint_domains.push("<unresolvable-url>".to_string());
            }
            let joined = taint_domains.join(", ");
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

        if saw_unresolvable && lists_configured {
            tracing::warn!(
                tool = %tool_name,
                session = %ctx.session_id,
                "egress-filter: blocked unresolvable egress URL (fail closed)"
            );
            return HookDecision::Block(
                "egress-filter: egress URL has no resolvable domain and is not on the allowlist"
                    .to_string(),
            );
        }

        for domain in &domains {
            // Punycode hosts (xn-- labels) are not decoded here:
            // without decoding, an allowlist/blocklist match against
            // the punycode form is unreliable (the same Unicode host
            // has many encodings). Fail closed whenever any list is
            // configured.
            if lists_configured && domain.split('.').any(|label| label.starts_with("xn--")) {
                tracing::warn!(
                    tool = %tool_name,
                    session = %ctx.session_id,
                    domain = %domain,
                    "egress-filter: blocked punycode host (fail closed, no punycode decoding)"
                );
                return HookDecision::Block(format!(
                    "egress-filter: punycode domain '{domain}' cannot be verified against the configured domain lists"
                ));
            }

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

/// Regex matching an http(s) URL anywhere in a string — catches URLs
/// embedded in prose or wrapped in markdown/parens/quotes, which
/// token-prefix matching misses.
fn http_url_regex() -> &'static regex_lite::Regex {
    static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex_lite::Regex::new(r#"https?://[^\s<>"')\]]+"#).expect("valid URL regex"))
}

/// Trailing punctuation commonly attached to URLs embedded in prose
/// or markdown links — not part of the URL itself.
fn trim_url_punctuation(url: &str) -> &str {
    url.trim_end_matches(['.', ',', ';', '!', '?', ':', ')', '\'', '"'])
}

fn collect_urls(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            // URLs anywhere in the string (markdown-wrapped, embedded
            // in prose, quoted, parenthesized).
            let re = http_url_regex();
            for m in re.find_iter(s) {
                let url = trim_url_punctuation(m.as_str());
                if !url.is_empty() {
                    out.push(url.to_string());
                }
            }
            // Bare-hostname heuristic on whitespace-split tokens that
            // are not already URLs.
            for token in s.split_whitespace() {
                let token = trim_url_punctuation(token);
                // Scheme detection is case-insensitive and treats
                // backslashes as slashes — the regex above is
                // case-sensitive, so push the token as a URL when it
                // carries a scheme in any casing.
                let lower = token.to_lowercase().replace('\\', "/");
                if lower.starts_with("http://") || lower.starts_with("https://") {
                    out.push(token.to_string());
                    continue;
                }
                // Protocol-relative tokens: //evil.com/path,
                // \\evil.com\path, \/evil.com — the host is the
                // authority following the two leading separators.
                let bytes = token.as_bytes();
                let is_protocol_relative = bytes.len() >= 2
                    && matches!(bytes[0], b'/' | b'\\')
                    && matches!(bytes[1], b'/' | b'\\');
                if is_protocol_relative {
                    let bare = token.trim_start_matches(['/', '\\']);
                    let authority = bare.split(['/', '\\']).next().unwrap_or(bare);
                    if looks_like_hostname(authority) {
                        out.push(format!("http://{authority}"));
                    }
                    continue;
                }
                if looks_like_hostname(token) {
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

/// Strip a single trailing `:port` suffix from a bare host token.
///
/// Returns `None` when the port is malformed (non-numeric, empty, or
/// more than one colon outside brackets) — such tokens are not
/// hostnames and must not be collected. Bracketed IPv6 literals
/// (`[::1]:8080`) keep their brackets; the port is what follows the
/// closing `]`.
fn strip_trailing_port(s: &str) -> Option<&str> {
    // Bracketed IPv6 literal: the port (if any) follows the `]`.
    if let Some(close) = s.find(']') {
        if s[..close].contains('[') {
            let rest = &s[close + 1..];
            if rest.is_empty() {
                return Some(s);
            }
            let port = rest.strip_prefix(':')?;
            if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            return Some(&s[..=close]);
        }
    }
    let mut colons = s.match_indices(':');
    match (colons.next(), colons.next()) {
        // No colon: the whole token is the host.
        (None, _) => Some(s),
        // Exactly one colon: numeric port or not a hostname.
        (Some((i, _)), None) => {
            let port = &s[i + 1..];
            if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
                None
            } else {
                Some(&s[..i])
            }
        }
        // Multiple colons outside brackets: bare IPv6-ish, not a
        // bare host:port token.
        (Some(_), Some(_)) => None,
    }
}

fn looks_like_hostname(s: &str) -> bool {
    // Split off a single trailing `:port` first — plain tool args
    // like `"evil.com:8443"` or `"10.0.0.5:6379"` carry no scheme,
    // and without this the dot-segment/TLD checks never fire and
    // the host is invisible to the filter.
    let s = match strip_trailing_port(s) {
        Some(host) => host,
        None => return false,
    };
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
///
/// Handles the common parser-evasion forms:
/// - mixed-case schemes (`HTTPS://EVIL.COM`),
/// - protocol-relative URLs (`//evil.com`),
/// - backslash separators (`https:\\evil.com`), which browsers
///   normalize to forward slashes,
/// - userinfo confusion (`https://good.com@evil.com/` — the host is
///   the part after the last `@`, i.e. `evil.com`, not `good.com`),
/// - bracketed IPv6 literals (`http://[::1]:8080/` — the host is the
///   bracketed content `::1`), including zone-ID forms
///   (`http://[::1%25eth0]/` — the `%zone` suffix is stripped so the
///   host matches its bare address),
/// - query/fragment terminators (`https://evil.com?x=@allowed.com` —
///   the authority ends at `?`/`#`, so query text cannot smuggle a
///   fake host past the lists),
/// - bare IPv6-ish authorities (multiple colons, no brackets) are
///   treated conservatively: no host is extracted, so callers fail
///   closed,
/// - homoglyph hosts (Cyrillic/Greek lookalikes, fullwidth forms),
///   folded with navra-safety's scan-time table so `еvil.com`
///   (Cyrillic е) resolves to `evil.com`.
pub fn extract_domain(url: &str) -> Option<String> {
    // Fold homoglyphs and lowercase before parsing so script and
    // case tricks cannot hide the host from the allowlist check.
    let folded: String = url
        .chars()
        .map(|c| crate::safety::normalize::fold_char(c).to_ascii_lowercase())
        .collect();
    // Browsers treat backslashes as forward slashes in the authority
    // section; normalize before splitting.
    let normalized = folded.replace('\\', "/");
    let s = normalized
        .strip_prefix("https://")
        .or_else(|| normalized.strip_prefix("http://"))
        // Protocol-relative URL: the authority follows the slashes.
        .or_else(|| normalized.strip_prefix("//"))?;
    // The authority ends at the first '/', '?', or '#' — everything
    // after is path/query/fragment, never host material. Splitting on
    // all three closes two bypasses:
    // - `https://evil.com?x=@allowed.com` used to extract
    //   `allowed.com` from the query (allowlist bypass);
    // - `https://evil.com?x` used to extract `evil.com?x`, which
    //   never matched a `evil.com` blocklist entry.
    let authority = s.split(['/', '?', '#']).next()?;
    // Strip userinfo before host extraction: in
    // `https://good.com@evil.com/`, everything up to and including
    // the last `@` is userinfo and the host is what follows.
    let authority = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }
    // Bracketed IPv6 literal: the host is the bracketed content.
    if let Some(rest) = authority.strip_prefix('[') {
        let host = rest.split(']').next()?;
        if host.is_empty() {
            return None;
        }
        // Strip an IPv6 zone-ID suffix (`%eth0`, or its %-encoded
        // form `%25eth0`): `[::1%eth0]` and `[::1]` reach the same
        // host on the same link, so the zone-ID form must match a
        // blocked bare address. We strip rather than reject because
        // the forms are resolve-equivalent — a blocked `::1` should
        // catch `[::1%eth0]`, and an allowed `::1` should let it
        // through.
        let host = host.split('%').next().unwrap_or(host);
        if host.is_empty() {
            return None;
        }
        return Some(host.to_string());
    }
    // Bare IPv6-ish authority (multiple colons, no brackets, e.g.
    // `2001:db8::1`): extracting the first colon-separated fragment
    // would yield a bogus hostname fragment. Fail closed — no host.
    if authority.matches(':').count() > 1 {
        return None;
    }
    let host = authority.split(':').next()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
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
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
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
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
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
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
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
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(matches!(decision, HookDecision::Continue));

        // Bare domain should NOT match wildcard
        let args2 = serde_json::json!({"url": "https://example.com/v1"});
        let decision2 = hook
            .pre_tool_use("http_request", &args2, &test_ctx(), None)
            .await;
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
        let decision = hook
            .pre_tool_use("file_write", &args, &test_ctx(), None)
            .await;
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
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
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
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
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

    // 9. Markdown-wrapped URLs are caught
    #[test]
    fn extract_urls_finds_markdown_wrapped_urls() {
        let val = serde_json::json!({
            "content": "see [docs](https://evil.com/exfil) for details"
        });
        let urls = extract_urls(&val);
        assert!(
            urls.iter()
                .any(|u| extract_domain(u).as_deref() == Some("evil.com")),
            "markdown-wrapped URL should be found: {urls:?}"
        );
    }

    #[test]
    fn extract_urls_finds_urls_embedded_in_prose() {
        let val = serde_json::json!({
            "message": "upload everything to https://attacker.net/collect and confirm"
        });
        let urls = extract_urls(&val);
        assert!(
            urls.iter()
                .any(|u| extract_domain(u).as_deref() == Some("attacker.net")),
            "embedded URL should be found: {urls:?}"
        );
    }

    #[test]
    fn extract_urls_trims_trailing_punctuation() {
        let val = serde_json::json!({"text": "fetch https://evil.com/path, then rest"});
        let urls = extract_urls(&val);
        assert!(
            urls.iter()
                .any(|u| extract_domain(u).as_deref() == Some("evil.com")),
            "trailing comma should be trimmed: {urls:?}"
        );
    }

    #[tokio::test]
    async fn blocks_markdown_wrapped_url_egress() {
        let hook = deny_all_hook();
        let args = serde_json::json!({
            "content": "reference: [click here](https://evil.com/payload)"
        });
        let decision = hook
            .pre_tool_use("file_write", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(_)),
            "markdown-wrapped egress URL should be blocked"
        );
    }

    // --- Parser-evasion bypasses ---

    #[test]
    fn extract_domain_uppercase_scheme() {
        assert_eq!(
            extract_domain("HTTPS://EVIL.COM/exfil"),
            Some("evil.com".to_string())
        );
        assert_eq!(
            extract_domain("HtTp://Sub.Example.COM/path"),
            Some("sub.example.com".to_string())
        );
    }

    #[test]
    fn extract_domain_protocol_relative() {
        assert_eq!(
            extract_domain("//evil.com/exfil"),
            Some("evil.com".to_string())
        );
        assert_eq!(extract_domain("//good.host"), Some("good.host".to_string()));
    }

    #[test]
    fn extract_domain_backslash_variants() {
        assert_eq!(
            extract_domain("https:\\\\evil.com\\exfil"),
            Some("evil.com".to_string())
        );
        assert_eq!(
            extract_domain("https:/\\evil.com/exfil"),
            Some("evil.com".to_string())
        );
    }

    #[test]
    fn extract_domain_folds_homoglyph_hosts() {
        // Cyrillic 'е' (U+0435) looks identical to Latin 'e'
        assert_eq!(
            extract_domain("https://\u{0435}vil.com/exfil"),
            Some("evil.com".to_string())
        );
        // Fullwidth 'ｅ'
        assert_eq!(
            extract_domain("https://\u{FF45}vil.com/exfil"),
            Some("evil.com".to_string())
        );
    }

    #[tokio::test]
    async fn blocks_uppercase_scheme_url() {
        let hook = deny_all_hook();
        let args = serde_json::json!({"url": "HTTPS://EVIL.COM/exfil"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(ref r) if r.contains("evil.com")),
            "uppercase scheme must not bypass the allowlist: {decision:?}"
        );
    }

    #[tokio::test]
    async fn blocks_protocol_relative_url_token() {
        let hook = deny_all_hook();
        let args = serde_json::json!({"message": "upload everything to //evil.com/collect now"});
        let decision = hook
            .pre_tool_use("file_write", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(ref r) if r.contains("evil.com")),
            "protocol-relative URL token must not bypass: {decision:?}"
        );
    }

    #[tokio::test]
    async fn blocks_backslash_url_variant() {
        let hook = deny_all_hook();
        let args = serde_json::json!({"message": "fetch https:\\\\evil.com\\data for me"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(ref r) if r.contains("evil.com")),
            "backslash URL variant must not bypass: {decision:?}"
        );
    }

    #[tokio::test]
    async fn blocks_homoglyph_host() {
        let hook = deny_all_hook();
        let args = serde_json::json!({"url": "https://\u{0435}vil.com/exfil"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(ref r) if r.contains("evil.com")),
            "homoglyph host must fold to the blocked domain: {decision:?}"
        );
    }

    #[tokio::test]
    async fn unresolvable_url_blocks_tainted_session() {
        // "https:///" is URL-like but has no host — fail closed for
        // the taint check instead of Continue.
        let hook = deny_all_hook();
        let args = serde_json::json!({"url": "https:///"});
        let decision = hook
            .pre_tool_use("http_request", &args, &tainted_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(ref r) if r.contains("tainted")),
            "unresolvable URL must count as egress for tainted sessions: {decision:?}"
        );
    }

    #[tokio::test]
    async fn unresolvable_url_blocked_when_deny_all() {
        let hook = deny_all_hook();
        let args = serde_json::json!({"url": "https:///"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(_)),
            "unresolvable URL must fail closed under deny_all_external: {decision:?}"
        );
    }

    #[tokio::test]
    async fn unresolvable_url_continues_when_egress_allowed() {
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec![],
            blocked_domains: vec![],
            deny_all_external: false,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"url": "https:///"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    // --- Userinfo / IPv6 / punycode bypasses ---

    #[test]
    fn extract_domain_strips_userinfo() {
        // The host is the part after the last '@' — userinfo must
        // not be mistaken for the host.
        assert_eq!(
            extract_domain("https://good.com@evil.com/"),
            Some("evil.com".to_string())
        );
        assert_eq!(
            extract_domain("http://user:pass@evil.com:8080/path"),
            Some("evil.com".to_string())
        );
        // No userinfo: unchanged behavior.
        assert_eq!(
            extract_domain("https://good.com/path"),
            Some("good.com".to_string())
        );
    }

    #[tokio::test]
    async fn userinfo_confusion_blocked_by_blocklist() {
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec!["good.com".to_string()],
            blocked_domains: vec!["evil.com".to_string()],
            deny_all_external: false,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"url": "https://good.com@evil.com/exfil"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(ref r) if r.contains("evil.com")),
            "userinfo confusion must resolve to the real host: {decision:?}"
        );
    }

    #[test]
    fn extract_domain_bracketed_ipv6() {
        assert_eq!(
            extract_domain("http://[::1]:8080/"),
            Some("::1".to_string())
        );
        assert_eq!(
            extract_domain("https://[2001:db8::1]/path"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn extract_domain_bare_ipv6_fails_closed() {
        // Bare (unbracketed) IPv6-ish authorities extract no host so
        // callers fail closed instead of matching a colon fragment.
        assert_eq!(extract_domain("http://::1:8080/"), None);
        assert_eq!(extract_domain("http://2001:db8::1/path"), None);
    }

    #[tokio::test]
    async fn bracketed_ipv6_handled_and_blocked_under_deny_all() {
        let hook = deny_all_hook();
        let args = serde_json::json!({"url": "http://[::1]:8080/"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(_)),
            "IPv6 literal must not bypass the allowlist: {decision:?}"
        );
    }

    #[tokio::test]
    async fn punycode_host_rejected_under_blocklist_mode() {
        // xn-- hosts are not punycode-decoded; with any list
        // configured they are rejected outright (fail closed).
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec![],
            blocked_domains: vec!["evil.com".to_string()],
            deny_all_external: false,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"url": "https://xn--e1afmkfd.xn--p1ai/"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(ref r) if r.contains("xn--")),
            "punycode host must be rejected when lists are configured: {decision:?}"
        );
    }

    #[tokio::test]
    async fn punycode_host_rejected_under_allowlist_mode() {
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec!["good.com".to_string()],
            blocked_domains: vec![],
            deny_all_external: true,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"url": "https://xn--e1afmkfd.xn--p1ai/"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(_)),
            "punycode host must not match an ASCII allowlist: {decision:?}"
        );
    }

    #[tokio::test]
    async fn unresolvable_url_blocked_when_blocklist_configured() {
        // With any list configured, an unparseable authority is
        // treated as a taint match (fail closed).
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec![],
            blocked_domains: vec!["evil.com".to_string()],
            deny_all_external: false,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"url": "http://::1:8080/"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(_)),
            "bare IPv6-ish authority must fail closed under a blocklist: {decision:?}"
        );
    }

    // --- Query/fragment authority terminators ---

    #[test]
    fn extract_domain_terminates_authority_at_query() {
        // The query is not host material: `?x=@allowed.com` used to
        // extract `allowed.com` (allowlist bypass).
        assert_eq!(
            extract_domain("https://evil.com?x=@allowed.com"),
            Some("evil.com".to_string())
        );
        // `?x` used to glue onto the host so it never matched a
        // blocklist entry for the bare host.
        assert_eq!(
            extract_domain("https://evil.com?x"),
            Some("evil.com".to_string())
        );
        assert_eq!(
            extract_domain("https://evil.com#fragment"),
            Some("evil.com".to_string())
        );
        // Userinfo inside the query must not be taken as the host.
        assert_eq!(
            extract_domain("https://allowed.com/path?next=https://evil.com"),
            Some("allowed.com".to_string())
        );
    }

    #[tokio::test]
    async fn query_userinfo_allowlist_bypass_blocked() {
        // Walkthrough from the finding: the query string carries
        // `@allowed.com`, which the old parser mistook for the host.
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec!["allowed.com".to_string()],
            blocked_domains: vec![],
            deny_all_external: true,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"url": "https://evil.com?x=@allowed.com"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(ref r) if r.contains("evil.com")),
            "query-embedded allowed.com must not bypass the allowlist: {decision:?}"
        );
    }

    #[tokio::test]
    async fn query_appended_host_matches_blocklist() {
        // Walkthrough from the finding: `https://evil.com?x` never
        // matched the `evil.com` blocklist entry.
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec![],
            blocked_domains: vec!["evil.com".to_string()],
            deny_all_external: false,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"url": "https://evil.com?x"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(ref r) if r.contains("evil.com")),
            "query-appended host must match the blocklist: {decision:?}"
        );
    }

    // --- Bare host:port tokens ---

    #[test]
    fn looks_like_hostname_accepts_bare_host_port() {
        assert!(looks_like_hostname("evil.com:8443"));
        assert!(looks_like_hostname("10.0.0.5:6379"));
        // Malformed or ambiguous ports are not hostnames.
        assert!(!looks_like_hostname("evil.com:https"));
        assert!(!looks_like_hostname("evil.com:"));
        assert!(!looks_like_hostname("evil.com:80:90"));
        // Plain hostnames unchanged.
        assert!(looks_like_hostname("evil.com"));
        assert!(looks_like_hostname("192.168.1.1"));
    }

    #[test]
    fn extract_urls_collects_bare_host_port() {
        let val = serde_json::json!({"host": "evil.com:8443"});
        let urls = extract_urls(&val);
        assert!(
            urls.iter()
                .any(|u| extract_domain(u).as_deref() == Some("evil.com")),
            "bare host:port must be collected: {urls:?}"
        );

        let val = serde_json::json!({"host": "10.0.0.5:6379"});
        let urls = extract_urls(&val);
        assert!(
            urls.iter()
                .any(|u| extract_domain(u).as_deref() == Some("10.0.0.5")),
            "bare IPv4:port must be collected: {urls:?}"
        );
    }

    #[tokio::test]
    async fn bare_host_port_blocked_under_blocklist() {
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec![],
            blocked_domains: vec!["evil.com".to_string()],
            deny_all_external: false,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"host": "evil.com:8443"});
        let decision = hook
            .pre_tool_use("redis_connect", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(ref r) if r.contains("evil.com")),
            "bare host:port must not be invisible to the blocklist: {decision:?}"
        );
    }

    // --- IPv6 zone-ID evasion ---

    #[test]
    fn extract_domain_strips_ipv6_zone_id() {
        // %-encoded zone form (as browsers send it: %25 is an encoded %)
        assert_eq!(
            extract_domain("http://[::1%25eth0]:8080/"),
            Some("::1".to_string())
        );
        // Raw zone form
        assert_eq!(
            extract_domain("https://[::1%eth0]/path"),
            Some("::1".to_string())
        );
        // Non-zone hosts are unchanged.
        assert_eq!(
            extract_domain("https://[2001:db8::1]/path"),
            Some("2001:db8::1".to_string())
        );
    }

    #[tokio::test]
    async fn ipv6_zone_id_form_of_blocked_address_blocked() {
        let hook = EgressFilterHook::new(EgressConfig {
            enabled: true,
            allowed_domains: vec![],
            blocked_domains: vec!["::1".to_string()],
            deny_all_external: false,
            block_tainted_egress: false,
        });
        let args = serde_json::json!({"url": "http://[::1%25eth0]:8080/"});
        let decision = hook
            .pre_tool_use("http_request", &args, &test_ctx(), None)
            .await;
        assert!(
            matches!(decision, HookDecision::Block(ref r) if r.contains("::1")),
            "zone-ID form of a blocked IPv6 must be blocked: {decision:?}"
        );
    }
}
