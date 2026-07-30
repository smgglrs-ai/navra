/// Shared test helpers for navra-safety-hooks.
use navra_auth::auth::CallContext;

/// Build a `CallContext` with full struct-literal fields for hook tests
/// that need the "full" permission level and explicit field values.
///
/// Hooks that only need a minimal context use `CallContext::new` directly
/// (e.g. routing.rs, memory_extraction.rs) — leave those alone.
pub(crate) fn test_ctx() -> CallContext {
    CallContext {
        agent: navra_auth::auth::AgentIdentity {
            name: "test".to_string(),
            permissions: "full".to_string(),
            signing_key: None,
            did: None,
            capabilities: None,
            model: None,
            allowed_upstreams: Vec::new(),
            max_concurrent: None,
            max_context: None,
            wimse: None,
        },
        session_id: "sess-1".to_string(),
        taint: navra_auth::ifc::TaintTracker::new(),
        remaining_tokens: None,
        sandbox: None,
    }
}
