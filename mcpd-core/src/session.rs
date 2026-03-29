use crate::auth::AgentIdentity;
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
}

/// Thread-safe session store.
#[derive(Debug, Clone, Default)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&self, session: Session) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session.id.clone(), session);
    }

    pub fn get(&self, id: &str) -> Option<Session> {
        let sessions = self.sessions.read().unwrap();
        sessions.get(id).cloned()
    }

    pub fn remove(&self, id: &str) -> Option<Session> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(id)
    }

    pub fn count(&self) -> usize {
        let sessions = self.sessions.read().unwrap();
        sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(id: &str) -> Session {
        Session {
            id: id.to_string(),
            agent: AgentIdentity {
                name: "agent".to_string(),
                permissions: "dev".to_string(),
            },
            client_info: ClientInfo {
                name: "test".to_string(),
                version: None,
            },
            initialized: true,
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
}
