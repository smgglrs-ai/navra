use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Path ACL rules for a permission set.
#[derive(Debug, Clone)]
pub struct PathAcl {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    /// Permitted operations as strings, e.g. "read", "write", "git.status".
    pub operations: HashSet<String>,
    /// Operations requiring human approval before execution.
    pub requires_approval: HashSet<String>,
}

/// Result of a permission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionResult {
    Allowed,
    NeedsApproval,
    DeniedPath,
    DeniedOperation,
    DeniedUnknown,
}

/// Central permission engine.
///
/// Operations are string-based to support module namespacing:
/// - `"read"`, `"write"`, `"search"`, `"list"` (docs module)
/// - `"git.status"`, `"git.commit"`, `"git.push"` (git module)
/// - `"shell.exec"` (shell module)
#[derive(Debug, Clone)]
pub struct PermissionEngine {
    permission_sets: HashMap<String, PathAcl>,
}

impl PermissionEngine {
    pub fn new() -> Self {
        Self {
            permission_sets: HashMap::new(),
        }
    }

    pub fn add_permission_set(&mut self, name: String, acl: PathAcl) {
        self.permission_sets.insert(name, acl);
    }

    /// Check if a permission set has a given operation enabled
    /// (without checking any specific path).
    pub fn has_operation(&self, permission_set: &str, operation: &str) -> bool {
        self.permission_sets
            .get(permission_set)
            .map(|acl| acl.operations.contains(operation))
            .unwrap_or(false)
    }

    /// Check if an agent with the given permission set can perform
    /// the operation on the given path.
    pub fn check(
        &self,
        permission_set: &str,
        operation: &str,
        path: &Path,
    ) -> PermissionResult {
        let acl = match self.permission_sets.get(permission_set) {
            Some(acl) => acl,
            None => return PermissionResult::DeniedUnknown,
        };

        // Check operation permission first (cheapest check).
        if !acl.operations.contains(operation) {
            return PermissionResult::DeniedOperation;
        }

        // Canonicalize path to prevent traversal.
        let canonical = Self::normalize_path(path);

        // Deny rules win — check first.
        for pattern in &acl.deny {
            let expanded = Self::expand_tilde(pattern);
            if Self::glob_matches(&expanded, &canonical) {
                return PermissionResult::DeniedPath;
            }
        }

        // Check allow rules.
        let allowed = acl.allow.iter().any(|pattern| {
            let expanded = Self::expand_tilde(pattern);
            Self::glob_matches(&expanded, &canonical)
        });

        if !allowed {
            return PermissionResult::DeniedPath;
        }

        // Check if approval is needed.
        if acl.requires_approval.contains(operation) {
            return PermissionResult::NeedsApproval;
        }

        PermissionResult::Allowed
    }

    /// Expand `~` to the user's home directory.
    fn expand_tilde(pattern: &str) -> String {
        if pattern.starts_with("~/") {
            if let Some(home) = dirs::home_dir() {
                return format!("{}{}", home.display(), &pattern[1..]);
            }
        }
        pattern.to_string()
    }

    /// Normalize a path: resolve `..` components without filesystem access.
    fn normalize_path(path: &Path) -> PathBuf {
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::ParentDir => {
                    components.pop();
                }
                std::path::Component::CurDir => {}
                other => components.push(other),
            }
        }
        components.iter().collect()
    }

    /// Glob matching supporting `*` and `**`.
    ///
    /// If a pattern ends with `/**`, the parent directory itself also
    /// matches. This is intuitive: allowing `~/Documents/**` should
    /// let you list `~/Documents`.
    fn glob_matches(pattern: &str, path: &PathBuf) -> bool {
        let path_str = path.to_string_lossy();
        if glob::Pattern::new(pattern)
            .map(|p| p.matches(&path_str))
            .unwrap_or(false)
        {
            return true;
        }
        // If pattern is "/dir/**", also match "/dir" itself
        if let Some(prefix) = pattern.strip_suffix("/**") {
            return path_str == prefix || path_str == format!("{prefix}/");
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> PermissionEngine {
        let mut engine = PermissionEngine::new();
        engine.add_permission_set(
            "developer".to_string(),
            PathAcl {
                allow: vec!["/home/user/Documents/**".to_string()],
                deny: vec![
                    "/home/user/Documents/private/**".to_string(),
                    "**/.env".to_string(),
                ],
                operations: ["read", "write", "search", "list", "git.status", "git.diff"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                requires_approval: ["write", "git.commit"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
        );
        engine.add_permission_set(
            "readonly".to_string(),
            PathAcl {
                allow: vec!["/home/user/Documents/shared/**".to_string()],
                deny: vec![],
                operations: ["read", "search", "list"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                requires_approval: HashSet::new(),
            },
        );
        engine
    }

    #[test]
    fn allow_read_in_permitted_path() {
        let engine = test_engine();
        let result = engine.check(
            "developer",
            "read",
            Path::new("/home/user/Documents/notes.md"),
        );
        assert_eq!(result, PermissionResult::Allowed);
    }

    #[test]
    fn deny_wins_over_allow() {
        let engine = test_engine();
        let result = engine.check(
            "developer",
            "read",
            Path::new("/home/user/Documents/private/secret.md"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn deny_dot_env() {
        let engine = test_engine();
        let result = engine.check(
            "developer",
            "read",
            Path::new("/home/user/Documents/project/.env"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn deny_outside_allowed_paths() {
        let engine = test_engine();
        let result = engine.check("developer", "read", Path::new("/etc/passwd"));
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn deny_unpermitted_operation() {
        let engine = test_engine();
        let result = engine.check(
            "readonly",
            "write",
            Path::new("/home/user/Documents/shared/file.md"),
        );
        assert_eq!(result, PermissionResult::DeniedOperation);
    }

    #[test]
    fn write_needs_approval() {
        let engine = test_engine();
        let result = engine.check(
            "developer",
            "write",
            Path::new("/home/user/Documents/notes.md"),
        );
        assert_eq!(result, PermissionResult::NeedsApproval);
    }

    #[test]
    fn unknown_permission_set() {
        let engine = test_engine();
        let result = engine.check("nonexistent", "read", Path::new("/anything"));
        assert_eq!(result, PermissionResult::DeniedUnknown);
    }

    #[test]
    fn path_traversal_blocked() {
        let engine = test_engine();
        let result = engine.check(
            "developer",
            "read",
            Path::new("/home/user/Documents/../../etc/passwd"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn readonly_can_read_shared() {
        let engine = test_engine();
        let result = engine.check(
            "readonly",
            "read",
            Path::new("/home/user/Documents/shared/report.pdf"),
        );
        assert_eq!(result, PermissionResult::Allowed);
    }

    #[test]
    fn readonly_cannot_read_outside_shared() {
        let engine = test_engine();
        let result = engine.check(
            "readonly",
            "read",
            Path::new("/home/user/Documents/notes.md"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn normalize_removes_parent_dir() {
        let path = Path::new("/home/user/Documents/../../../etc/passwd");
        let normalized = PermissionEngine::normalize_path(path);
        assert_eq!(normalized, PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn namespaced_operations() {
        let engine = test_engine();
        // developer has git.status
        assert!(engine.has_operation("developer", "git.status"));
        assert!(engine.has_operation("developer", "git.diff"));
        // developer does NOT have git.push
        assert!(!engine.has_operation("developer", "git.push"));
        // readonly has no git ops
        assert!(!engine.has_operation("readonly", "git.status"));
    }

    #[test]
    fn namespaced_approval() {
        let engine = test_engine();
        // git.commit requires approval for developer
        let result = engine.check(
            "developer",
            "git.commit",
            Path::new("/home/user/Documents/repo"),
        );
        assert_eq!(result, PermissionResult::DeniedOperation);
        // Add git.commit to operations
        let mut engine = test_engine();
        if let Some(acl) = engine.permission_sets.get_mut("developer") {
            acl.operations.insert("git.commit".to_string());
        }
        let result = engine.check(
            "developer",
            "git.commit",
            Path::new("/home/user/Documents/repo"),
        );
        assert_eq!(result, PermissionResult::NeedsApproval);
    }

    #[test]
    fn directory_matches_glob_parent() {
        let engine = test_engine();
        // /home/user/Documents itself should match Documents/**
        let result = engine.check(
            "developer",
            "list",
            Path::new("/home/user/Documents"),
        );
        assert_eq!(result, PermissionResult::Allowed);
    }

    #[test]
    fn has_operation_unknown_set() {
        let engine = test_engine();
        assert!(!engine.has_operation("nonexistent", "read"));
    }
}
