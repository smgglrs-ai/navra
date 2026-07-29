/// Shared test helpers for navra-rag.
use navra_core::permissions::{PathAcl, PermissionEngine};
use std::collections::HashSet;

/// Build a `PermissionEngine` with a "dev" permission set allowing
/// read and search on all paths.
pub fn test_perm_engine() -> PermissionEngine {
    let mut engine = PermissionEngine::new();
    engine.add_permission_set(
        "dev".to_string(),
        PathAcl {
            ring: None,
            allow: vec!["/**".to_string()],
            deny: vec![],
            operations: ["read", "search"].into_iter().map(String::from).collect(),
            requires_approval: HashSet::new(),
        },
    );
    engine
}
