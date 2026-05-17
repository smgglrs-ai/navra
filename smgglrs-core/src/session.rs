use crate::auth::AgentIdentity;
use crate::ifc::DataLabel;
use crate::protocol::ClientInfo;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A single MCP session, created on successful `initialize`.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub agent: AgentIdentity,
    pub client_info: ClientInfo,
    pub initialized: bool,
    /// Accumulated label of data the LLM has "seen" (returned to agent context).
    /// Persists across HTTP requests, unlike CallContext.taint.
    pub context_label: DataLabel,
    /// Unix timestamp when this session was created.
    pub created_at: i64,
    /// Unix timestamp of last activity.
    pub last_accessed: i64,
}

/// Trait for session storage backends.
///
/// The default implementation is in-memory (HashMap). A persistent
/// SQLite backend is provided by `smgglrs-memory` for production use.
pub trait SessionBackend: Send + Sync {
    fn create(&self, session: Session);
    fn get(&self, id: &str) -> Option<Session>;
    fn remove(&self, id: &str) -> Option<Session>;
    fn count(&self) -> usize;
    fn update_context_label(&self, id: &str, label: DataLabel);
    fn context_label(&self, id: &str) -> DataLabel;
    /// Touch last_accessed timestamp.
    fn touch(&self, id: &str);
    /// Remove sessions older than `max_age_secs`.
    fn expire(&self, max_age_secs: u64);
}

/// Thread-safe session store wrapping a pluggable backend.
#[derive(Clone)]
pub struct SessionStore {
    backend: Arc<dyn SessionBackend>,
}

impl std::fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStore").finish()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self {
            backend: Arc::new(InMemorySessionBackend::new()),
        }
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a store with a custom backend (e.g. SQLite).
    pub fn with_backend(backend: Arc<dyn SessionBackend>) -> Self {
        Self { backend }
    }

    pub fn create(&self, session: Session) {
        self.backend.create(session);
    }

    pub fn get(&self, id: &str) -> Option<Session> {
        self.backend.get(id)
    }

    pub fn remove(&self, id: &str) -> Option<Session> {
        self.backend.remove(id)
    }

    pub fn count(&self) -> usize {
        self.backend.count()
    }

    pub fn update_context_label(&self, id: &str, label: DataLabel) {
        self.backend.update_context_label(id, label);
    }

    pub fn context_label(&self, id: &str) -> DataLabel {
        self.backend.context_label(id)
    }

    pub fn touch(&self, id: &str) {
        self.backend.touch(id);
    }

    pub fn expire(&self, max_age_secs: u64) {
        self.backend.expire(max_age_secs);
    }
}

/// In-memory session backend (default). Sessions lost on restart.
#[derive(Debug, Default)]
pub struct InMemorySessionBackend {
    sessions: RwLock<HashMap<String, Session>>,
}

impl InMemorySessionBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionBackend for InMemorySessionBackend {
    fn create(&self, session: Session) {
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        sessions.insert(session.id.clone(), session);
    }

    fn get(&self, id: &str) -> Option<Session> {
        let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        sessions.get(id).cloned()
    }

    fn remove(&self, id: &str) -> Option<Session> {
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        sessions.remove(id)
    }

    fn count(&self) -> usize {
        let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        sessions.len()
    }

    fn update_context_label(&self, id: &str, label: DataLabel) {
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        if let Some(session) = sessions.get_mut(id) {
            session.context_label = session.context_label.join(label);
        }
    }

    fn context_label(&self, id: &str) -> DataLabel {
        let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        sessions
            .get(id)
            .map(|s| s.context_label)
            .unwrap_or(DataLabel::TRUSTED_PUBLIC)
    }

    fn touch(&self, id: &str) {
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        if let Some(session) = sessions.get_mut(id) {
            session.last_accessed = now_epoch();
        }
    }

    fn expire(&self, max_age_secs: u64) {
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        let cutoff = now_epoch() - max_age_secs as i64;
        sessions.retain(|_, s| s.last_accessed > cutoff);
    }
}

/// DashMap-based session backend for lock-free concurrent access.
///
/// Uses sharded concurrent hashmap instead of a global RwLock.
/// Better performance under high concurrency (many concurrent sessions).
#[derive(Debug, Default)]
pub struct DashMapSessionBackend {
    sessions: dashmap::DashMap<String, Session>,
}

impl DashMapSessionBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionBackend for DashMapSessionBackend {
    fn create(&self, session: Session) {
        self.sessions.insert(session.id.clone(), session);
    }

    fn get(&self, id: &str) -> Option<Session> {
        self.sessions.get(id).map(|s| s.clone())
    }

    fn remove(&self, id: &str) -> Option<Session> {
        self.sessions.remove(id).map(|(_, s)| s)
    }

    fn count(&self) -> usize {
        self.sessions.len()
    }

    fn update_context_label(&self, id: &str, label: DataLabel) {
        if let Some(mut session) = self.sessions.get_mut(id) {
            session.context_label = session.context_label.join(label);
        }
    }

    fn context_label(&self, id: &str) -> DataLabel {
        self.sessions
            .get(id)
            .map(|s| s.context_label)
            .unwrap_or(DataLabel::TRUSTED_PUBLIC)
    }

    fn touch(&self, id: &str) {
        if let Some(mut session) = self.sessions.get_mut(id) {
            session.last_accessed = now_epoch();
        }
    }

    fn expire(&self, max_age_secs: u64) {
        let cutoff = now_epoch() - max_age_secs as i64;
        self.sessions.retain(|_, s| s.last_accessed > cutoff);
    }
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(id: &str) -> Session {
        let now = now_epoch();
        Session {
            id: id.to_string(),
            agent: AgentIdentity::new("agent", "dev"),
            client_info: ClientInfo {
                name: "test".to_string(),
                version: None,
            },
            initialized: true,
            context_label: DataLabel::TRUSTED_PUBLIC,
            created_at: now,
            last_accessed: now,
        }
    }

    #[test]
    fn create_and_get() {
        let store = SessionStore::new();
        store.create(test_session("s1"));
        let s = store.get("s1").unwrap();
        assert_eq!(s.id, "s1");
        assert!(s.initialized);
    }

    #[test]
    fn get_missing() {
        let store = SessionStore::new();
        assert!(store.get("nope").is_none());
    }

    #[test]
    fn remove() {
        let store = SessionStore::new();
        store.create(test_session("s1"));
        assert_eq!(store.count(), 1);
        let removed = store.remove("s1").unwrap();
        assert_eq!(removed.id, "s1");
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn count() {
        let store = SessionStore::new();
        store.create(test_session("a"));
        store.create(test_session("b"));
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn expire_old_sessions() {
        let store = SessionStore::new();
        let mut old = test_session("old");
        old.last_accessed = now_epoch() - 7200; // 2 hours ago
        store.create(old);
        store.create(test_session("fresh"));
        assert_eq!(store.count(), 2);
        store.expire(3600); // expire older than 1 hour
        assert_eq!(store.count(), 1);
        assert!(store.get("fresh").is_some());
        assert!(store.get("old").is_none());
    }

    // --- DashMap backend tests ---

    fn dashmap_store() -> SessionStore {
        SessionStore::with_backend(Arc::new(DashMapSessionBackend::new()))
    }

    #[test]
    fn dashmap_create_and_get() {
        let store = dashmap_store();
        store.create(test_session("d1"));
        let s = store.get("d1").unwrap();
        assert_eq!(s.id, "d1");
    }

    #[test]
    fn dashmap_remove() {
        let store = dashmap_store();
        store.create(test_session("d1"));
        assert_eq!(store.count(), 1);
        store.remove("d1");
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn dashmap_expire() {
        let store = dashmap_store();
        let mut old = test_session("old");
        old.last_accessed = now_epoch() - 7200;
        store.create(old);
        store.create(test_session("fresh"));
        store.expire(3600);
        assert_eq!(store.count(), 1);
        assert!(store.get("fresh").is_some());
    }

    #[test]
    fn dashmap_concurrent_access() {
        let store = Arc::new(dashmap_store());
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let store = store.clone();
                std::thread::spawn(move || {
                    let id = format!("session-{i}");
                    store.create(test_session(&id));
                    assert!(store.get(&id).is_some());
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(store.count(), 10);
    }

    #[test]
    fn dashmap_context_label() {
        let store = dashmap_store();
        store.create(test_session("d1"));
        assert_eq!(store.context_label("d1"), DataLabel::TRUSTED_PUBLIC);
        let tainted = DataLabel {
            integrity: crate::ifc::Integrity::Untrusted,
            confidentiality: crate::ifc::Confidentiality::Public,
        };
        store.update_context_label("d1", tainted);
        assert_eq!(store.context_label("d1").integrity, crate::ifc::Integrity::Untrusted);
    }
}
