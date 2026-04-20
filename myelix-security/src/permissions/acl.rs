use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Path ACL rules for a permission set.
#[derive(Debug, Clone)]
pub struct PathAcl {
    /// Privilege ring level (0 = most privileged). When set,
    /// ring inheritance applies via `apply_ring_inheritance()`.
    pub ring: Option<u8>,
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
///
/// Supports graduated permission rings (0 = most privileged,
/// 3 = most restricted). When rings are assigned, higher-numbered
/// rings inherit deny rules and approval requirements from all
/// lower-numbered rings, and their operations are intersected.
#[derive(Debug, Clone)]
pub struct PermissionEngine {
    permission_sets: HashMap<String, PathAcl>,
}

impl Default for PermissionEngine {
    fn default() -> Self {
        Self::new()
    }
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

    /// Apply ring inheritance across all permission sets.
    ///
    /// For each ring N > 0, accumulate deny rules and approval
    /// requirements from all rings 0..N, and intersect operations
    /// so that higher rings can only narrow privileges.
    pub fn apply_ring_inheritance(&mut self) {
        // Collect ring assignments: (ring, name)
        let mut ringed: Vec<(u8, String)> = self
            .permission_sets
            .iter()
            .filter_map(|(name, acl)| acl.ring.map(|r| (r, name.clone())))
            .collect();

        if ringed.is_empty() {
            return;
        }

        // Sort by ring level (lowest = most privileged first)
        ringed.sort_by_key(|(ring, _)| *ring);

        // Accumulate deny rules and approval requirements from lower rings.
        // Track the running intersection of operations.
        let mut accumulated_deny: Vec<String> = Vec::new();
        let mut accumulated_approval: HashSet<String> = HashSet::new();
        let mut accumulated_ops: Option<HashSet<String>> = None;

        for (_, name) in &ringed {
            let acl = self.permission_sets.get(name).unwrap();

            // First ring sets the baseline operations; subsequent rings intersect.
            match &accumulated_ops {
                None => {
                    accumulated_ops = Some(acl.operations.clone());
                }
                Some(prev_ops) => {
                    // This ring's effective operations = intersection of
                    // its declared operations with accumulated operations.
                    let intersected: HashSet<String> = acl
                        .operations
                        .intersection(prev_ops)
                        .cloned()
                        .collect();
                    accumulated_ops = Some(intersected.clone());

                    // Merge inherited deny rules and approval requirements.
                    let acl = self.permission_sets.get_mut(name).unwrap();
                    for d in &accumulated_deny {
                        if !acl.deny.contains(d) {
                            acl.deny.push(d.clone());
                        }
                    }
                    for a in &accumulated_approval {
                        acl.requires_approval.insert(a.clone());
                    }
                    acl.operations = intersected;
                }
            }

            // Add this ring's deny rules and approvals to the accumulator.
            let acl = self.permission_sets.get(name).unwrap();
            accumulated_deny.extend(acl.deny.clone());
            for a in &acl.requires_approval {
                accumulated_approval.insert(a.clone());
            }
        }
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

        // Defense-in-depth: warn if caller forgot to canonicalize.
        // The ACL engine still normalizes the path, but callers should
        // canonicalize first to resolve symlinks.
        if !path.is_absolute() {
            tracing::warn!(
                path = %path.display(),
                "ACL check received non-absolute path — callers should canonicalize"
            );
        }
        if path.components().any(|c| c == std::path::Component::ParentDir) {
            tracing::warn!(
                path = %path.display(),
                "ACL check received path with '..' — callers should canonicalize to resolve symlinks"
            );
        }

        // Normalize path for glob matching (lexical only).
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

    /// Normalize a path: resolve `..` and `.` components without filesystem access.
    ///
    /// This is a **lexical-only** normalization. It does not follow symlinks
    /// or verify that the path exists. Callers must canonicalize the path
    /// (e.g., via `Path::canonicalize()`) before passing it to ACL checks
    /// if symlink resolution is needed.
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
                ring: None,
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
                ring: None,
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

    // --- Ring inheritance tests ---

    fn ring_engine() -> PermissionEngine {
        let mut engine = PermissionEngine::new();
        engine.add_permission_set(
            "admin".to_string(),
            PathAcl {
                ring: Some(0),
                allow: vec!["/home/user/**".to_string()],
                deny: vec!["**/.env".to_string()],
                operations: ["read", "write", "search", "list", "git.status", "git.commit", "git.push", "shell.exec"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                requires_approval: HashSet::new(),
            },
        );
        engine.add_permission_set(
            "developer".to_string(),
            PathAcl {
                ring: Some(1),
                allow: vec!["/home/user/projects/**".to_string()],
                deny: vec!["/home/user/projects/secrets/**".to_string()],
                operations: ["read", "write", "search", "list", "git.status", "git.commit"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                requires_approval: ["git.commit"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
        );
        engine.add_permission_set(
            "readonly".to_string(),
            PathAcl {
                ring: Some(2),
                allow: vec!["/home/user/projects/public/**".to_string()],
                deny: vec![],
                operations: ["read", "search", "list"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                requires_approval: HashSet::new(),
            },
        );
        engine.apply_ring_inheritance();
        engine
    }

    #[test]
    fn ring0_unaffected_by_inheritance() {
        let engine = ring_engine();
        // Admin (ring 0) keeps its own rules unchanged
        let result = engine.check("admin", "shell.exec", Path::new("/home/user/bin/script"));
        assert_eq!(result, PermissionResult::Allowed);
    }

    #[test]
    fn ring1_inherits_deny_from_ring0() {
        let engine = ring_engine();
        // Developer (ring 1) inherits **/.env deny from admin (ring 0)
        let result = engine.check(
            "developer",
            "read",
            Path::new("/home/user/projects/app/.env"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn ring1_keeps_own_deny() {
        let engine = ring_engine();
        // Developer's own deny rule still works
        let result = engine.check(
            "developer",
            "read",
            Path::new("/home/user/projects/secrets/key.pem"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn ring1_operations_narrowed() {
        let engine = ring_engine();
        // Developer declared git.commit but not git.push or shell.exec.
        // Intersection with ring 0 keeps git.commit (both have it)
        // but git.push and shell.exec are gone (developer didn't declare them).
        assert!(!engine.has_operation("developer", "git.push"));
        assert!(!engine.has_operation("developer", "shell.exec"));
        assert!(engine.has_operation("developer", "git.commit"));
    }

    #[test]
    fn ring2_inherits_deny_from_both_rings() {
        let engine = ring_engine();
        // Readonly (ring 2) inherits **/.env from ring 0
        // and secrets/** from ring 1
        let result = engine.check(
            "readonly",
            "read",
            Path::new("/home/user/projects/public/.env"),
        );
        assert_eq!(result, PermissionResult::DeniedPath);
    }

    #[test]
    fn ring2_operations_intersected_through_chain() {
        let engine = ring_engine();
        // Readonly declared [read, search, list].
        // Ring 1 effective ops: [read, write, search, list, git.status, git.commit]
        // Intersection: [read, search, list] — readonly keeps only its own.
        assert!(engine.has_operation("readonly", "read"));
        assert!(engine.has_operation("readonly", "search"));
        assert!(!engine.has_operation("readonly", "write"));
        assert!(!engine.has_operation("readonly", "git.status"));
    }

    #[test]
    fn ring2_inherits_approval_from_ring1() {
        // Readonly doesn't have git.commit in its operations (intersected out),
        // but approval requirements still cascade. If we gave readonly
        // git.commit, it would need approval.
        // Test with a ring that has overlapping ops:
        let mut engine = PermissionEngine::new();
        engine.add_permission_set(
            "base".to_string(),
            PathAcl {
                ring: Some(0),
                allow: vec!["/data/**".to_string()],
                deny: vec![],
                operations: ["read", "write"].into_iter().map(String::from).collect(),
                requires_approval: ["write"].into_iter().map(String::from).collect(),
            },
        );
        engine.add_permission_set(
            "child".to_string(),
            PathAcl {
                ring: Some(1),
                allow: vec!["/data/**".to_string()],
                deny: vec![],
                operations: ["read", "write"].into_iter().map(String::from).collect(),
                requires_approval: HashSet::new(),
            },
        );
        engine.apply_ring_inheritance();
        // Child inherits write-needs-approval from base
        let result = engine.check("child", "write", Path::new("/data/file.txt"));
        assert_eq!(result, PermissionResult::NeedsApproval);
    }

    #[test]
    fn no_ring_sets_unaffected() {
        // Permission sets without ring assignments are left unchanged
        let mut engine = PermissionEngine::new();
        engine.add_permission_set(
            "custom".to_string(),
            PathAcl {
                ring: None,
                allow: vec!["/tmp/**".to_string()],
                deny: vec![],
                operations: ["read"].into_iter().map(String::from).collect(),
                requires_approval: HashSet::new(),
            },
        );
        engine.add_permission_set(
            "ringed".to_string(),
            PathAcl {
                ring: Some(0),
                allow: vec!["/home/**".to_string()],
                deny: vec!["**/.secret".to_string()],
                operations: ["read", "write"].into_iter().map(String::from).collect(),
                requires_approval: HashSet::new(),
            },
        );
        engine.apply_ring_inheritance();
        // "custom" has no ring — should NOT inherit denies from "ringed"
        let result = engine.check("custom", "read", Path::new("/tmp/.secret"));
        assert_eq!(result, PermissionResult::Allowed);
    }
}
