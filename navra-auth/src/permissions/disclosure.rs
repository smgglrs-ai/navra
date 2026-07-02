//! Progressive tool disclosure.
//!
//! Filters the tools visible to an agent based on disclosure rules.
//! Tools not in the disclosure set are hidden from tools/list but
//! can still be called if the agent knows the name (disclosure is
//! UI-level, not security — use tool_rules for access control).

use vstd::prelude::*;

/// Tool disclosure rules for a permission set.
#[derive(Debug, Clone)]
pub struct ToolDisclosure {
    /// Glob patterns of tools to expose. Empty = show all.
    include: Vec<String>,
    /// Glob patterns of tools to hide. Applied after include.
    exclude: Vec<String>,
}

impl ToolDisclosure {
    pub fn new(include: Vec<String>, exclude: Vec<String>) -> Self {
        Self { include, exclude }
    }

    /// Returns true if the tool should be visible.
    pub fn is_visible(&self, tool_name: &str) -> bool {
        if !self.include.is_empty() {
            let included = self.include.iter().any(|pat| {
                glob::Pattern::new(pat)
                    .map(|p| p.matches(tool_name))
                    .unwrap_or(false)
            });
            if !included {
                return false;
            }
        }

        !self.exclude.iter().any(|pat| {
            glob::Pattern::new(pat)
                .map(|p| p.matches(tool_name))
                .unwrap_or(false)
        })
    }

    /// Filter a list of tool names, returning only visible ones.
    pub fn filter(
        &self,
        tools: &[navra_protocol::ToolDefinition],
    ) -> Vec<navra_protocol::ToolDefinition> {
        if self.include.is_empty() && self.exclude.is_empty() {
            return tools.to_vec();
        }
        tools
            .iter()
            .filter(|t| self.is_visible(&t.name))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rules_show_all() {
        let d = ToolDisclosure::new(vec![], vec![]);
        assert!(d.is_visible("anything"));
        assert!(d.is_visible("file_read"));
    }

    #[test]
    fn include_filters_to_matching() {
        let d = ToolDisclosure::new(vec!["file_*".to_string(), "git_status".to_string()], vec![]);
        assert!(d.is_visible("file_read"));
        assert!(d.is_visible("file_write"));
        assert!(d.is_visible("git_status"));
        assert!(!d.is_visible("git_commit"));
        assert!(!d.is_visible("github_pr_list"));
    }

    #[test]
    fn exclude_hides_matching() {
        let d = ToolDisclosure::new(vec![], vec!["shell_*".to_string()]);
        assert!(d.is_visible("file_read"));
        assert!(d.is_visible("git_status"));
        assert!(!d.is_visible("shell_exec"));
    }

    #[test]
    fn include_then_exclude() {
        let d = ToolDisclosure::new(
            vec!["github_*".to_string()],
            vec!["github_pr_create".to_string()],
        );
        assert!(d.is_visible("github_pr_list"));
        assert!(d.is_visible("github_pr_view"));
        assert!(!d.is_visible("github_pr_create"));
        assert!(!d.is_visible("file_read"));
    }

    #[test]
    fn progressive_disclosure_for_beginner() {
        let d = ToolDisclosure::new(
            vec![
                "file_read".to_string(),
                "file_tree".to_string(),
                "memory_search".to_string(),
            ],
            vec![],
        );
        assert!(d.is_visible("file_read"));
        assert!(d.is_visible("file_tree"));
        assert!(d.is_visible("memory_search"));
        assert!(!d.is_visible("file_write"));
        assert!(!d.is_visible("git_commit"));
        assert!(!d.is_visible("shell_exec"));
    }

    #[test]
    fn filter_tool_definitions() {
        let schema = navra_protocol::compat::empty_input_schema();
        let tools = vec![
            navra_protocol::ToolDefinition::new("file_read", "Read a file", schema.clone()),
            navra_protocol::ToolDefinition::new("shell_exec", "Execute command", schema),
        ];
        let d = ToolDisclosure::new(vec!["file_*".to_string()], vec![]);
        let filtered = d.filter(&tools);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "file_read");
    }
}

verus! {

// Disclosure logic: include-first, then exclude.
// has_include_rules: whether include list is non-empty
// included: whether tool matches any include pattern
// excluded: whether tool matches any exclude pattern
spec fn spec_is_visible(has_include_rules: bool, included: bool, excluded: bool) -> bool {
    if has_include_rules && !included { false }
    else { !excluded }
}

proof fn empty_rules_show_all()
    ensures spec_is_visible(false, false, false),
{}

proof fn exclude_always_hides(has_include: bool, included: bool)
    ensures !spec_is_visible(has_include, included, true),
{}

proof fn include_required_when_set(excluded: bool)
    requires !excluded,
    ensures !spec_is_visible(true, false, excluded),
{}

proof fn include_and_not_excluded_visible()
    ensures spec_is_visible(true, true, false),
{}

} // verus!
