use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Operations an agent can perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    Read,
    Write,
    Search,
    List,
    Index,
}

impl Operation {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "search" => Some(Self::Search),
            "list" => Some(Self::List),
            "index" => Some(Self::Index),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Search => "search",
            Self::List => "list",
            Self::Index => "index",
        }
    }
}

/// Path ACL rules for a permission set.
#[derive(Debug, Clone)]
pub struct PathAcl {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub operations: HashSet<Operation>,
    pub requires_approval: HashSet<Operation>,
}

/// Result of a permission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionResult {
    /// Access granted.
    Allowed,
    /// Access granted but requires human approval first.
    NeedsApproval,
    /// Access denied — path not in allow list or in deny list.
    DeniedPath,
    /// Access denied — operation not permitted.
    DeniedOperation,
    /// Access denied — unknown permission set.
    DeniedUnknown,
}

/// Central permission engine.
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

    /// Check if an agent with the given permission set can perform
    /// the operation on the given path.
    pub fn check(
        &self,
        permission_set: &str,
        operation: Operation,
        path: &Path,
    ) -> PermissionResult {
        let acl = match self.permission_sets.get(permission_set) {
            Some(acl) => acl,
            None => return PermissionResult::DeniedUnknown,
        };

        // Check operation permission first (cheapest check).
        if !acl.operations.contains(&operation) {
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
        if acl.requires_approval.contains(&operation) {
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

    /// Simple glob matching supporting `*` and `**`.
    fn glob_matches(pattern: &str, path: &PathBuf) -> bool {
        let path_str = path.to_string_lossy();
        glob::Pattern::new(pattern)
            .map(|p| p.matches(&path_str))
            .unwrap_or(false)
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
                operations: [Operation::Read, Operation::Write, Operation::Search, Operation::List]
                    .into_iter()
                    .collect(),
                requires_approval: [Operation::Write].into_iter().collect(),
            },
        );
        engine.add_permission_set(
            "readonly".to_string(),
            PathAcl {
                allow: vec!["/home/user/Documents/shared/**".to_string()],
                deny: vec![],
                operations: [Operation::Read, Operation::Search, Operation::List]
                    .into_iter()
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
            Operation::Read,
            Path::new("/home/user/Documents/notes.md"),
        );
        assert_eq!(result, PermissionResult::Allowed);
    }

    #[test]
    fn deny_wins_over_allow() {
        let engine = test_engine();
        let result = engine.check(
            "developer",
            Operation::Read,
            Path::new("/home/user/Documents/private/secret.md"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn deny_dot_env() {
        let engine = test_engine();
        let result = engine.check(
            "developer",
            Operation::Read,
            Path::new("/home/user/Documents/project/.env"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn deny_outside_allowed_paths() {
        let engine = test_engine();
        let result = engine.check(
            "developer",
            Operation::Read,
            Path::new("/etc/passwd"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn deny_unpermitted_operation() {
        let engine = test_engine();
        let result = engine.check(
            "readonly",
            Operation::Write,
            Path::new("/home/user/Documents/shared/file.md"),
        );
        assert_eq!(result, PermissionResult::DeniedOperation);
    }

    #[test]
    fn write_needs_approval() {
        let engine = test_engine();
        let result = engine.check(
            "developer",
            Operation::Write,
            Path::new("/home/user/Documents/notes.md"),
        );
        assert_eq!(result, PermissionResult::NeedsApproval);
    }

    #[test]
    fn unknown_permission_set() {
        let engine = test_engine();
        let result = engine.check(
            "nonexistent",
            Operation::Read,
            Path::new("/anything"),
        );
        assert_eq!(result, PermissionResult::DeniedUnknown);
    }

    #[test]
    fn path_traversal_blocked() {
        let engine = test_engine();
        // Attempt to escape via ..
        let result = engine.check(
            "developer",
            Operation::Read,
            Path::new("/home/user/Documents/../../etc/passwd"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn readonly_can_read_shared() {
        let engine = test_engine();
        let result = engine.check(
            "readonly",
            Operation::Read,
            Path::new("/home/user/Documents/shared/report.pdf"),
        );
        assert_eq!(result, PermissionResult::Allowed);
    }

    #[test]
    fn readonly_cannot_read_outside_shared() {
        let engine = test_engine();
        let result = engine.check(
            "readonly",
            Operation::Read,
            Path::new("/home/user/Documents/notes.md"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn operation_roundtrip() {
        for op in [Operation::Read, Operation::Write, Operation::Search, Operation::List, Operation::Index] {
            assert_eq!(Operation::from_str(op.as_str()), Some(op));
        }
    }

    #[test]
    fn normalize_removes_parent_dir() {
        let path = Path::new("/home/user/Documents/../../../etc/passwd");
        let normalized = PermissionEngine::normalize_path(path);
        assert_eq!(normalized, PathBuf::from("/etc/passwd"));
    }
}
