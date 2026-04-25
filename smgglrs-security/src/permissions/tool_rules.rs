//! Per-tool permission rules with glob pattern matching.
//!
//! Allows fine-grained control over which tools an agent can use,
//! independent of the path-based ACL system. Rules match tool names
//! using glob patterns and apply a policy (allow, deny, or require approval).

/// Policy to apply when a tool rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolPolicy {
    /// Tool is allowed without restriction.
    Allow,
    /// Tool is blocked entirely.
    Deny,
    /// Tool requires human approval before execution.
    Approve,
}

/// A single rule matching a tool name pattern to a policy.
#[derive(Debug, Clone)]
pub struct ToolRule {
    /// Glob pattern matching tool names (e.g., "git_*", "shell_exec").
    pub tool: String,
    /// Policy to apply when matched.
    pub policy: ToolPolicy,
}

/// Per-tool permission engine for a permission set.
///
/// Evaluates rules with deny-wins priority:
/// 1. Any matching `Deny` rule -> `Deny` (immediate)
/// 2. Any matching `Allow` rule -> `Allow`
/// 3. Any matching `Approve` rule -> `Approve`
/// 4. No match -> `default_policy`
#[derive(Debug, Clone)]
pub struct ToolPermissions {
    rules: Vec<ToolRule>,
    default_policy: ToolPolicy,
}

impl ToolPermissions {
    /// Create a new tool permissions engine with the given rules and default.
    pub fn new(rules: Vec<ToolRule>, default_policy: ToolPolicy) -> Self {
        Self {
            rules,
            default_policy,
        }
    }

    /// Check the policy for a given tool name.
    pub fn check(&self, tool_name: &str) -> ToolPolicy {
        let mut has_allow = false;
        let mut has_approve = false;

        for rule in &self.rules {
            if !Self::glob_matches(&rule.tool, tool_name) {
                continue;
            }
            match rule.policy {
                ToolPolicy::Deny => return ToolPolicy::Deny,
                ToolPolicy::Allow => has_allow = true,
                ToolPolicy::Approve => has_approve = true,
            }
        }

        if has_allow {
            ToolPolicy::Allow
        } else if has_approve {
            ToolPolicy::Approve
        } else {
            self.default_policy.clone()
        }
    }

    /// Match a glob pattern against a tool name.
    fn glob_matches(pattern: &str, name: &str) -> bool {
        glob::Pattern::new(pattern)
            .map(|p| p.matches(name))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_deny() {
        let perms = ToolPermissions::new(
            vec![ToolRule {
                tool: "git_push".to_string(),
                policy: ToolPolicy::Deny,
            }],
            ToolPolicy::Allow,
        );
        assert_eq!(perms.check("git_push"), ToolPolicy::Deny);
        assert_eq!(perms.check("git_commit"), ToolPolicy::Allow);
    }

    #[test]
    fn glob_pattern_deny() {
        let perms = ToolPermissions::new(
            vec![ToolRule {
                tool: "shell_*".to_string(),
                policy: ToolPolicy::Deny,
            }],
            ToolPolicy::Allow,
        );
        assert_eq!(perms.check("shell_exec"), ToolPolicy::Deny);
        assert_eq!(perms.check("shell_run"), ToolPolicy::Deny);
        assert_eq!(perms.check("file_read"), ToolPolicy::Allow);
    }

    #[test]
    fn deny_wins_over_allow() {
        let perms = ToolPermissions::new(
            vec![
                ToolRule {
                    tool: "git_*".to_string(),
                    policy: ToolPolicy::Allow,
                },
                ToolRule {
                    tool: "git_push".to_string(),
                    policy: ToolPolicy::Deny,
                },
            ],
            ToolPolicy::Allow,
        );
        assert_eq!(perms.check("git_commit"), ToolPolicy::Allow);
        assert_eq!(perms.check("git_push"), ToolPolicy::Deny);
    }

    #[test]
    fn deny_wins_over_approve() {
        let perms = ToolPermissions::new(
            vec![
                ToolRule {
                    tool: "git_push".to_string(),
                    policy: ToolPolicy::Approve,
                },
                ToolRule {
                    tool: "git_push".to_string(),
                    policy: ToolPolicy::Deny,
                },
            ],
            ToolPolicy::Allow,
        );
        assert_eq!(perms.check("git_push"), ToolPolicy::Deny);
    }

    #[test]
    fn allow_wins_over_approve() {
        let perms = ToolPermissions::new(
            vec![
                ToolRule {
                    tool: "file_*".to_string(),
                    policy: ToolPolicy::Approve,
                },
                ToolRule {
                    tool: "file_read".to_string(),
                    policy: ToolPolicy::Allow,
                },
            ],
            ToolPolicy::Deny,
        );
        assert_eq!(perms.check("file_read"), ToolPolicy::Allow);
        assert_eq!(perms.check("file_write"), ToolPolicy::Approve);
    }

    #[test]
    fn default_policy_when_no_match() {
        let perms = ToolPermissions::new(vec![], ToolPolicy::Deny);
        assert_eq!(perms.check("anything"), ToolPolicy::Deny);

        let perms = ToolPermissions::new(vec![], ToolPolicy::Allow);
        assert_eq!(perms.check("anything"), ToolPolicy::Allow);

        let perms = ToolPermissions::new(vec![], ToolPolicy::Approve);
        assert_eq!(perms.check("anything"), ToolPolicy::Approve);
    }

    #[test]
    fn approve_policy() {
        let perms = ToolPermissions::new(
            vec![ToolRule {
                tool: "git_commit".to_string(),
                policy: ToolPolicy::Approve,
            }],
            ToolPolicy::Allow,
        );
        assert_eq!(perms.check("git_commit"), ToolPolicy::Approve);
        assert_eq!(perms.check("git_status"), ToolPolicy::Allow);
    }

    #[test]
    fn multiple_glob_patterns() {
        let perms = ToolPermissions::new(
            vec![
                ToolRule {
                    tool: "git_*".to_string(),
                    policy: ToolPolicy::Approve,
                },
                ToolRule {
                    tool: "shell_*".to_string(),
                    policy: ToolPolicy::Deny,
                },
                ToolRule {
                    tool: "file_*".to_string(),
                    policy: ToolPolicy::Allow,
                },
            ],
            ToolPolicy::Deny,
        );
        assert_eq!(perms.check("git_commit"), ToolPolicy::Approve);
        assert_eq!(perms.check("shell_exec"), ToolPolicy::Deny);
        assert_eq!(perms.check("file_read"), ToolPolicy::Allow);
        assert_eq!(perms.check("unknown_tool"), ToolPolicy::Deny);
    }

    #[test]
    fn wildcard_matches_all() {
        let perms = ToolPermissions::new(
            vec![ToolRule {
                tool: "*".to_string(),
                policy: ToolPolicy::Approve,
            }],
            ToolPolicy::Allow,
        );
        assert_eq!(perms.check("anything"), ToolPolicy::Approve);
        assert_eq!(perms.check("file_read"), ToolPolicy::Approve);
    }
}
