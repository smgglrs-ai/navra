use smgglrs_protocol::permissions::{PermissionGrantEntry, PermissionScope};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// A dynamic permission grant for a session.
#[derive(Debug, Clone)]
struct DynamicGrant {
    request_id: String,
    scope: PermissionScope,
    expires_at: Option<u64>,
    granted_by: String,
}

/// Per-session dynamic permission grants.
///
/// These are granted at runtime via the `permissions/grant` MCP method
/// and are checked alongside static ACLs. Static deny rules always win
/// over dynamic grants (deny-wins invariant).
#[derive(Debug, Default)]
pub struct SessionPermissions {
    grants: Vec<DynamicGrant>,
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl SessionPermissions {
    /// Create an empty session permissions set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a dynamic grant.
    pub fn add_grant(
        &mut self,
        request_id: String,
        scope: PermissionScope,
        expires_at: Option<u64>,
        granted_by: String,
    ) {
        self.grants.push(DynamicGrant {
            request_id,
            scope,
            expires_at,
            granted_by,
        });
    }

    /// Remove expired grants.
    fn gc(&mut self) {
        let now = now_epoch();
        self.grants
            .retain(|g| g.expires_at.map_or(true, |exp| exp > now));
    }

    /// Check if a path operation is allowed by a dynamic grant.
    pub fn check_path(&mut self, path: &str, operation: &str) -> bool {
        self.gc();
        self.grants.iter().any(|g| match &g.scope {
            PermissionScope::PathAccess {
                path: granted_path,
                operations,
            } => {
                operations.iter().any(|op| op == operation)
                    && (path == granted_path || path.starts_with(&format!("{granted_path}/")))
            }
            _ => false,
        })
    }

    /// Check if a tool is allowed by a dynamic grant.
    pub fn check_tool(&mut self, tool_name: &str) -> bool {
        self.gc();
        self.grants.iter().any(|g| match &g.scope {
            PermissionScope::ToolAccess {
                tool_name: granted_tool,
            } => tool_name == granted_tool,
            _ => false,
        })
    }

    /// Check if a resource is allowed by a dynamic grant.
    pub fn check_resource(&mut self, uri: &str) -> bool {
        self.gc();
        self.grants.iter().any(|g| match &g.scope {
            PermissionScope::ResourceAccess { uri: granted_uri } => uri == granted_uri,
            _ => false,
        })
    }

    /// List all active grants.
    pub fn list(&mut self) -> Vec<PermissionGrantEntry> {
        self.gc();
        self.grants
            .iter()
            .map(|g| PermissionGrantEntry {
                request_id: g.request_id.clone(),
                scope: g.scope.clone(),
                expires_at: g.expires_at,
                granted_by: g.granted_by.clone(),
            })
            .collect()
    }

    /// Number of active grants (after GC).
    pub fn count(&mut self) -> usize {
        self.gc();
        self.grants.len()
    }

    /// Remove a specific grant by request ID.
    pub fn revoke(&mut self, request_id: &str) -> bool {
        let before = self.grants.len();
        self.grants.retain(|g| g.request_id != request_id);
        self.grants.len() < before
    }
}

/// Thread-safe store mapping session IDs to their dynamic permissions.
#[derive(Debug, Clone, Default)]
pub struct SessionPermissionStore {
    inner: Arc<RwLock<HashMap<String, SessionPermissions>>>,
}

impl SessionPermissionStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create the permissions for a session.
    fn with_session<F, R>(&self, session_id: &str, f: F) -> R
    where
        F: FnOnce(&mut SessionPermissions) -> R,
    {
        let mut map = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let perms = map
            .entry(session_id.to_string())
            .or_insert_with(SessionPermissions::new);
        f(perms)
    }

    /// Add a dynamic grant for a session.
    pub fn add_grant(
        &self,
        session_id: &str,
        request_id: String,
        scope: PermissionScope,
        expires_at: Option<u64>,
        granted_by: String,
    ) {
        self.with_session(session_id, |perms| {
            perms.add_grant(request_id, scope, expires_at, granted_by);
        });
    }

    /// Check if a path operation is dynamically granted.
    pub fn check_path(&self, session_id: &str, path: &str, operation: &str) -> bool {
        self.with_session(session_id, |perms| perms.check_path(path, operation))
    }

    /// Check if a tool is dynamically granted.
    pub fn check_tool(&self, session_id: &str, tool_name: &str) -> bool {
        self.with_session(session_id, |perms| perms.check_tool(tool_name))
    }

    /// Check if a resource is dynamically granted.
    pub fn check_resource(&self, session_id: &str, uri: &str) -> bool {
        self.with_session(session_id, |perms| perms.check_resource(uri))
    }

    /// List active grants for a session.
    pub fn list(&self, session_id: &str) -> Vec<PermissionGrantEntry> {
        self.with_session(session_id, |perms| perms.list())
    }

    /// Remove a session's permissions (on session close).
    pub fn remove_session(&self, session_id: &str) {
        let mut map = self.inner.write().unwrap_or_else(|e| e.into_inner());
        map.remove(session_id);
    }

    /// Revoke a specific grant.
    pub fn revoke(&self, session_id: &str, request_id: &str) -> bool {
        self.with_session(session_id, |perms| perms.revoke(request_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_path_access() {
        let mut perms = SessionPermissions::new();
        perms.add_grant(
            "req-1".to_string(),
            PermissionScope::PathAccess {
                path: "/home/user/data".to_string(),
                operations: vec!["read".to_string(), "write".to_string()],
            },
            None,
            "user".to_string(),
        );

        assert!(perms.check_path("/home/user/data", "read"));
        assert!(perms.check_path("/home/user/data", "write"));
        assert!(perms.check_path("/home/user/data/file.txt", "read"));
        assert!(!perms.check_path("/home/user/data", "exec"));
        assert!(!perms.check_path("/home/user/other", "read"));
    }

    #[test]
    fn grant_tool_access() {
        let mut perms = SessionPermissions::new();
        perms.add_grant(
            "req-2".to_string(),
            PermissionScope::ToolAccess {
                tool_name: "git_push".to_string(),
            },
            None,
            "user".to_string(),
        );

        assert!(perms.check_tool("git_push"));
        assert!(!perms.check_tool("git_commit"));
    }

    #[test]
    fn grant_resource_access() {
        let mut perms = SessionPermissions::new();
        perms.add_grant(
            "req-3".to_string(),
            PermissionScope::ResourceAccess {
                uri: "file:///doc.md".to_string(),
            },
            None,
            "user".to_string(),
        );

        assert!(perms.check_resource("file:///doc.md"));
        assert!(!perms.check_resource("file:///other.md"));
    }

    #[test]
    fn grant_expiry() {
        let mut perms = SessionPermissions::new();
        // Expired grant (epoch 0)
        perms.add_grant(
            "req-expired".to_string(),
            PermissionScope::ToolAccess {
                tool_name: "dangerous_tool".to_string(),
            },
            Some(0),
            "user".to_string(),
        );

        assert!(!perms.check_tool("dangerous_tool"));
        assert_eq!(perms.count(), 0);
    }

    #[test]
    fn grant_no_expiry_persists() {
        let mut perms = SessionPermissions::new();
        perms.add_grant(
            "req-forever".to_string(),
            PermissionScope::ToolAccess {
                tool_name: "safe_tool".to_string(),
            },
            None,
            "user".to_string(),
        );

        assert!(perms.check_tool("safe_tool"));
        assert_eq!(perms.count(), 1);
    }

    #[test]
    fn list_grants() {
        let mut perms = SessionPermissions::new();
        perms.add_grant(
            "req-a".to_string(),
            PermissionScope::ToolAccess {
                tool_name: "tool_a".to_string(),
            },
            None,
            "user".to_string(),
        );
        perms.add_grant(
            "req-b".to_string(),
            PermissionScope::PathAccess {
                path: "/tmp".to_string(),
                operations: vec!["read".to_string()],
            },
            None,
            "admin".to_string(),
        );

        let list = perms.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].request_id, "req-a");
        assert_eq!(list[1].request_id, "req-b");
    }

    #[test]
    fn revoke_grant() {
        let mut perms = SessionPermissions::new();
        perms.add_grant(
            "req-rev".to_string(),
            PermissionScope::ToolAccess {
                tool_name: "tool_x".to_string(),
            },
            None,
            "user".to_string(),
        );

        assert!(perms.check_tool("tool_x"));
        assert!(perms.revoke("req-rev"));
        assert!(!perms.check_tool("tool_x"));
        assert!(!perms.revoke("req-rev"));
    }

    #[test]
    fn store_multi_session() {
        let store = SessionPermissionStore::new();
        store.add_grant(
            "s1",
            "req-1".to_string(),
            PermissionScope::ToolAccess {
                tool_name: "tool_a".to_string(),
            },
            None,
            "user".to_string(),
        );
        store.add_grant(
            "s2",
            "req-2".to_string(),
            PermissionScope::ToolAccess {
                tool_name: "tool_b".to_string(),
            },
            None,
            "user".to_string(),
        );

        assert!(store.check_tool("s1", "tool_a"));
        assert!(!store.check_tool("s1", "tool_b"));
        assert!(store.check_tool("s2", "tool_b"));
        assert!(!store.check_tool("s2", "tool_a"));
    }

    #[test]
    fn store_remove_session() {
        let store = SessionPermissionStore::new();
        store.add_grant(
            "s1",
            "req-1".to_string(),
            PermissionScope::ToolAccess {
                tool_name: "tool_a".to_string(),
            },
            None,
            "user".to_string(),
        );

        assert!(store.check_tool("s1", "tool_a"));
        store.remove_session("s1");
        // After removal, a fresh SessionPermissions is created
        assert!(!store.check_tool("s1", "tool_a"));
    }
}
