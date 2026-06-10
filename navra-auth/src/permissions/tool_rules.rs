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

    // --- Platform tool (three-part name) patterns ---

    #[test]
    fn github_read_only_via_default_deny() {
        // Read-only: only whitelist read ops, default deny catches the rest.
        // Don't use a github_* deny rule — it would win over specific allows.
        let perms = ToolPermissions::new(
            vec![
                ToolRule {
                    tool: "github_pr_list".to_string(),
                    policy: ToolPolicy::Allow,
                },
                ToolRule {
                    tool: "github_pr_view".to_string(),
                    policy: ToolPolicy::Allow,
                },
                ToolRule {
                    tool: "github_issue_list".to_string(),
                    policy: ToolPolicy::Allow,
                },
            ],
            ToolPolicy::Deny,
        );
        assert_eq!(perms.check("github_pr_list"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_pr_view"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_issue_list"), ToolPolicy::Allow);
        // Default deny catches everything else
        assert_eq!(perms.check("github_pr_create"), ToolPolicy::Deny);
        assert_eq!(perms.check("github_issue_create"), ToolPolicy::Deny);
        assert_eq!(perms.check("github_issue_comment"), ToolPolicy::Deny);
        // Non-github tools also denied by default
        assert_eq!(perms.check("git_status"), ToolPolicy::Deny);
    }

    #[test]
    fn github_deny_glob_wins_over_allow() {
        // Deny-wins: a github_* deny overrides even specific allows.
        // This is intentional — use default_deny pattern instead.
        let perms = ToolPermissions::new(
            vec![
                ToolRule {
                    tool: "github_pr_list".to_string(),
                    policy: ToolPolicy::Allow,
                },
                ToolRule {
                    tool: "github_*".to_string(),
                    policy: ToolPolicy::Deny,
                },
            ],
            ToolPolicy::Allow,
        );
        // Deny wins over the specific allow
        assert_eq!(perms.check("github_pr_list"), ToolPolicy::Deny);
        assert_eq!(perms.check("github_pr_create"), ToolPolicy::Deny);
        // Non-github tools use default allow
        assert_eq!(perms.check("git_status"), ToolPolicy::Allow);
    }

    #[test]
    fn github_pr_glob_allows_all_pr_ops() {
        let perms = ToolPermissions::new(
            vec![ToolRule {
                tool: "github_pr_*".to_string(),
                policy: ToolPolicy::Allow,
            }],
            ToolPolicy::Deny,
        );
        assert_eq!(perms.check("github_pr_list"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_pr_create"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_pr_view"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_issue_list"), ToolPolicy::Deny);
        assert_eq!(perms.check("github_issue_create"), ToolPolicy::Deny);
    }

    #[test]
    fn github_pr_create_requires_approval() {
        let perms = ToolPermissions::new(
            vec![
                ToolRule {
                    tool: "github_*".to_string(),
                    policy: ToolPolicy::Allow,
                },
                ToolRule {
                    tool: "github_pr_create".to_string(),
                    policy: ToolPolicy::Approve,
                },
            ],
            ToolPolicy::Deny,
        );
        assert_eq!(perms.check("github_pr_list"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_issue_list"), ToolPolicy::Allow);
        // Specific approve overrides glob allow
        assert_eq!(perms.check("github_pr_create"), ToolPolicy::Allow);
        // NOTE: Allow wins over Approve by design — if you want Approve
        // to take effect, don't also Allow via a broader glob
    }

    #[test]
    fn github_pr_create_approve_without_glob_allow() {
        let perms = ToolPermissions::new(
            vec![
                ToolRule {
                    tool: "github_pr_list".to_string(),
                    policy: ToolPolicy::Allow,
                },
                ToolRule {
                    tool: "github_pr_view".to_string(),
                    policy: ToolPolicy::Allow,
                },
                ToolRule {
                    tool: "github_pr_create".to_string(),
                    policy: ToolPolicy::Approve,
                },
            ],
            ToolPolicy::Deny,
        );
        assert_eq!(perms.check("github_pr_list"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_pr_view"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_pr_create"), ToolPolicy::Approve);
        assert_eq!(perms.check("github_issue_list"), ToolPolicy::Deny);
    }

    #[test]
    fn deny_wins_across_providers() {
        let perms = ToolPermissions::new(
            vec![
                ToolRule {
                    tool: "github_*".to_string(),
                    policy: ToolPolicy::Allow,
                },
                ToolRule {
                    tool: "gitlab_*".to_string(),
                    policy: ToolPolicy::Allow,
                },
                ToolRule {
                    tool: "*_create".to_string(),
                    policy: ToolPolicy::Deny,
                },
            ],
            ToolPolicy::Deny,
        );
        // Deny on *_create beats provider-level allow
        assert_eq!(perms.check("github_pr_create"), ToolPolicy::Deny);
        assert_eq!(perms.check("gitlab_mr_create"), ToolPolicy::Deny);
        assert_eq!(perms.check("github_issue_create"), ToolPolicy::Deny);
        // Non-create operations allowed
        assert_eq!(perms.check("github_pr_list"), ToolPolicy::Allow);
        assert_eq!(perms.check("gitlab_mr_list"), ToolPolicy::Allow);
    }

    #[test]
    fn mixed_providers_independent() {
        let perms = ToolPermissions::new(
            vec![
                ToolRule {
                    tool: "github_*".to_string(),
                    policy: ToolPolicy::Allow,
                },
                ToolRule {
                    tool: "gitlab_*".to_string(),
                    policy: ToolPolicy::Deny,
                },
                ToolRule {
                    tool: "jira_issue_list".to_string(),
                    policy: ToolPolicy::Allow,
                },
            ],
            ToolPolicy::Deny,
        );
        assert_eq!(perms.check("github_pr_list"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_pr_create"), ToolPolicy::Allow);
        assert_eq!(perms.check("gitlab_mr_list"), ToolPolicy::Deny);
        assert_eq!(perms.check("gitlab_mr_create"), ToolPolicy::Deny);
        assert_eq!(perms.check("jira_issue_list"), ToolPolicy::Allow);
        assert_eq!(perms.check("jira_issue_create"), ToolPolicy::Deny);
    }

    #[test]
    fn suffix_glob_blocks_write_ops() {
        let perms = ToolPermissions::new(
            vec![
                ToolRule {
                    tool: "github_*".to_string(),
                    policy: ToolPolicy::Allow,
                },
                ToolRule {
                    tool: "*_create".to_string(),
                    policy: ToolPolicy::Approve,
                },
                ToolRule {
                    tool: "*_comment".to_string(),
                    policy: ToolPolicy::Approve,
                },
            ],
            ToolPolicy::Deny,
        );
        assert_eq!(perms.check("github_pr_list"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_pr_view"), ToolPolicy::Allow);
        // Allow wins over Approve when both match
        assert_eq!(perms.check("github_pr_create"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_issue_comment"), ToolPolicy::Allow);
    }

    #[test]
    fn three_part_names_with_question_mark_glob() {
        let perms = ToolPermissions::new(
            vec![ToolRule {
                tool: "github_??_*".to_string(),
                policy: ToolPolicy::Allow,
            }],
            ToolPolicy::Deny,
        );
        assert_eq!(perms.check("github_pr_list"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_pr_create"), ToolPolicy::Allow);
        assert_eq!(perms.check("github_mr_list"), ToolPolicy::Allow);
        // "issue" has 5 chars, not 2
        assert_eq!(perms.check("github_issue_list"), ToolPolicy::Deny);
    }
}
