//! Bidirectional policy sync between navra and OpenShell.
//!
//! Maps upstream tools to their required network endpoints and
//! dynamically hides tools whose endpoints are no longer reachable
//! (e.g., after an OpenShell admin tightens network policy).

use navra_core::ToolFilter;
use navra_protocol::ToolDefinition;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// Maps upstream tool names to the network domains they require.
///
/// Built at startup from `UpstreamConfig.network.allowed_domains`
/// and `known_server_domains()`. When an upstream registers tools,
/// all its tools inherit its domain set.
pub struct ToolEndpointRegistry {
    tool_domains: RwLock<HashMap<String, HashSet<String>>>,
}

impl ToolEndpointRegistry {
    pub fn new() -> Self {
        Self {
            tool_domains: RwLock::new(HashMap::new()),
        }
    }

    /// Register all tools from an upstream with its required domains.
    pub fn register_upstream(&self, tool_names: &[String], domains: Vec<String>) {
        let domain_set: HashSet<String> = domains.into_iter().collect();
        let mut map = self.tool_domains.write().unwrap_or_else(|e| e.into_inner());
        for name in tool_names {
            map.insert(name.clone(), domain_set.clone());
        }
    }

    /// Get the required domains for a tool, if registered.
    pub fn domains_for(&self, tool_name: &str) -> Option<HashSet<String>> {
        let map = self.tool_domains.read().unwrap_or_else(|e| e.into_inner());
        map.get(tool_name).cloned()
    }

    /// Return tool names whose required domains are NOT covered by
    /// the given allowed set. A tool is blocked if any of its required
    /// domains is not matched by the allowed set (with wildcard support).
    pub fn blocked_tools(&self, allowed_domains: &[String]) -> HashSet<String> {
        let map = self.tool_domains.read().unwrap_or_else(|e| e.into_inner());
        let mut blocked = HashSet::new();

        for (tool, required) in map.iter() {
            for domain in required {
                if !domain_matches_any(domain, allowed_domains) {
                    blocked.insert(tool.clone());
                    break;
                }
            }
        }

        blocked
    }

    /// Check all tools against per-upstream network policies from config.
    /// Returns the set of tool names that should be blocked.
    pub fn evaluate_config(
        &self,
        upstreams: &[crate::config::UpstreamConfig],
    ) -> HashSet<String> {
        let map = self.tool_domains.read().unwrap_or_else(|e| e.into_inner());
        let mut blocked = HashSet::new();

        // Build a lookup: upstream name → allowed domains from config
        let mut upstream_domains: HashMap<String, Vec<String>> = HashMap::new();
        for u in upstreams {
            if let Some(ref net) = u.network {
                upstream_domains.insert(u.name.clone(), net.allowed_domains.clone());
            }
        }

        // For each registered tool, find its upstream (by prefix or
        // registry), then check if its domains are still allowed.
        for (tool_name, required_domains) in map.iter() {
            // Find which upstream this tool belongs to by checking
            // which upstream's tool set contains it.
            for u in upstreams {
                if let Some(ref net) = u.network {
                    let allowed = &net.allowed_domains;
                    for domain in required_domains {
                        if !domain_matches_any(domain, allowed)
                            && !net.blocked_domains.is_empty()
                        {
                            blocked.insert(tool_name.clone());
                            break;
                        }
                    }
                }
            }
        }

        blocked
    }
}

/// Check if a domain matches any entry in an allowlist.
/// Supports wildcard prefix matching (e.g., `*.googleapis.com`
/// matches `storage.googleapis.com`).
fn domain_matches_any(domain: &str, allowed: &[String]) -> bool {
    for pattern in allowed {
        if pattern == domain {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            if domain.ends_with(suffix)
                && domain.len() > suffix.len()
                && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
            {
                return true;
            }
        }
    }
    false
}

/// Dynamic tool filter that hides tools whose network endpoints
/// are no longer reachable due to policy changes.
pub struct PolicySyncFilter {
    blocked: Arc<RwLock<HashSet<String>>>,
}

impl PolicySyncFilter {
    pub fn new() -> (Self, PolicySyncHandle) {
        let blocked = Arc::new(RwLock::new(HashSet::new()));
        let handle = PolicySyncHandle {
            blocked: Arc::clone(&blocked),
        };
        (Self { blocked }, handle)
    }
}

impl ToolFilter for PolicySyncFilter {
    fn filter(
        &self,
        tools: Vec<ToolDefinition>,
        _ctx: &navra_core::auth::CallContext,
    ) -> Vec<ToolDefinition> {
        let blocked = self.blocked.read().unwrap_or_else(|e| e.into_inner());
        if blocked.is_empty() {
            return tools;
        }
        tools
            .into_iter()
            .filter(|t| !blocked.contains(t.name.as_ref()))
            .collect()
    }
}

/// Handle for updating the set of blocked tools from the policy
/// sync task. Separate from the filter to allow independent ownership.
pub struct PolicySyncHandle {
    blocked: Arc<RwLock<HashSet<String>>>,
}

impl PolicySyncHandle {
    /// Update the set of blocked tools. Returns the number of tools
    /// that changed state (newly blocked + newly unblocked).
    pub fn update_blocked(&self, new_blocked: HashSet<String>) -> usize {
        let mut current = self.blocked.write().unwrap_or_else(|e| e.into_inner());
        let newly_blocked: Vec<_> = new_blocked.difference(&current).cloned().collect();
        let newly_unblocked: Vec<_> = current.difference(&new_blocked).cloned().collect();
        let changed = newly_blocked.len() + newly_unblocked.len();

        for tool in &newly_blocked {
            tracing::warn!(tool, "policy sync: tool blocked (endpoint unreachable)");
        }
        for tool in &newly_unblocked {
            tracing::info!(tool, "policy sync: tool unblocked (endpoint restored)");
        }

        *current = new_blocked;
        changed
    }

    /// Get the current set of blocked tools.
    pub fn blocked(&self) -> HashSet<String> {
        self.blocked.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_matches_exact() {
        assert!(domain_matches_any("api.github.com", &["api.github.com".into()]));
        assert!(!domain_matches_any("api.github.com", &["github.com".into()]));
    }

    #[test]
    fn domain_matches_wildcard() {
        assert!(domain_matches_any(
            "storage.googleapis.com",
            &["*.googleapis.com".into()]
        ));
        assert!(domain_matches_any(
            "api.googleapis.com",
            &["*.googleapis.com".into()]
        ));
        assert!(!domain_matches_any(
            "googleapis.com",
            &["*.googleapis.com".into()]
        ));
    }

    #[test]
    fn registry_maps_tools_to_domains() {
        let reg = ToolEndpointRegistry::new();
        reg.register_upstream(
            &["github_pr_list".into(), "github_pr_create".into()],
            vec!["api.github.com".into(), "github.com".into()],
        );

        let domains = reg.domains_for("github_pr_list").unwrap();
        assert!(domains.contains("api.github.com"));
        assert!(domains.contains("github.com"));
        assert!(reg.domains_for("unknown_tool").is_none());
    }

    #[test]
    fn blocked_tools_detects_unreachable() {
        let reg = ToolEndpointRegistry::new();
        reg.register_upstream(
            &["github_pr_list".into()],
            vec!["api.github.com".into()],
        );
        reg.register_upstream(
            &["slack_post".into()],
            vec!["slack.com".into()],
        );

        // Only github allowed → slack tools blocked
        let blocked = reg.blocked_tools(&["api.github.com".into()]);
        assert!(blocked.contains("slack_post"));
        assert!(!blocked.contains("github_pr_list"));
    }

    #[test]
    fn blocked_tools_with_wildcard() {
        let reg = ToolEndpointRegistry::new();
        reg.register_upstream(
            &["gws_mail_list".into()],
            vec!["mail.googleapis.com".into()],
        );

        let blocked = reg.blocked_tools(&["*.googleapis.com".into()]);
        assert!(blocked.is_empty());

        let blocked = reg.blocked_tools(&["api.example.com".into()]);
        assert!(blocked.contains("gws_mail_list"));
    }

    fn test_tool(name: &'static str) -> ToolDefinition {
        ToolDefinition::new(name, "", navra_protocol::compat::empty_input_schema())
    }

    #[test]
    fn filter_hides_blocked_tools() {
        let (filter, handle) = PolicySyncFilter::new();

        let tools = vec![test_tool("github_pr_list"), test_tool("slack_post")];

        let ctx = navra_core::auth::CallContext::new(
            navra_core::auth::AgentIdentity::new("test", "dev"),
            "sess",
        );

        // No blocked tools → all visible
        let visible = filter.filter(tools.clone(), &ctx);
        assert_eq!(visible.len(), 2);

        // Block slack_post
        let mut blocked = HashSet::new();
        blocked.insert("slack_post".to_string());
        handle.update_blocked(blocked);

        let visible = filter.filter(tools.clone(), &ctx);
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name, "github_pr_list");

        // Unblock all
        handle.update_blocked(HashSet::new());
        let visible = filter.filter(tools, &ctx);
        assert_eq!(visible.len(), 2);
    }

    #[test]
    fn handle_reports_changes() {
        let (_filter, handle) = PolicySyncFilter::new();

        let mut blocked = HashSet::new();
        blocked.insert("tool_a".to_string());
        blocked.insert("tool_b".to_string());
        let changed = handle.update_blocked(blocked);
        assert_eq!(changed, 2);

        // Same set → no changes
        let mut same = HashSet::new();
        same.insert("tool_a".to_string());
        same.insert("tool_b".to_string());
        let changed = handle.update_blocked(same);
        assert_eq!(changed, 0);

        // Remove one, add one
        let mut new = HashSet::new();
        new.insert("tool_a".to_string());
        new.insert("tool_c".to_string());
        let changed = handle.update_blocked(new);
        assert_eq!(changed, 2); // tool_b removed, tool_c added
    }
}
