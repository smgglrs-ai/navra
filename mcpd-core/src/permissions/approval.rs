use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Status of an approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// A pending approval request.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub id: String,
    pub agent_name: String,
    pub operation: String,
    pub path: String,
    pub status: ApprovalStatus,
    pub created_at: Instant,
    pub timeout: Duration,
}

impl ApprovalRequest {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.timeout
    }

    pub fn effective_status(&self) -> ApprovalStatus {
        if self.status == ApprovalStatus::Pending && self.is_expired() {
            ApprovalStatus::Expired
        } else {
            self.status.clone()
        }
    }
}

/// Thread-safe store for pending approvals.
#[derive(Debug, Clone)]
pub struct ApprovalStore {
    requests: Arc<RwLock<HashMap<String, ApprovalRequest>>>,
    timeout: Duration,
}

impl ApprovalStore {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Create a new pending approval request. Returns the request ID.
    pub fn create(
        &self,
        agent_name: &str,
        operation: &str,
        path: &str,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let request = ApprovalRequest {
            id: id.clone(),
            agent_name: agent_name.to_string(),
            operation: operation.to_string(),
            path: path.to_string(),
            status: ApprovalStatus::Pending,
            created_at: Instant::now(),
            timeout: self.timeout,
        };
        let mut requests = self.requests.write().unwrap();
        requests.insert(id.clone(), request);
        id
    }

    /// Get the effective status of a request.
    pub fn status(&self, id: &str) -> Option<ApprovalStatus> {
        let requests = self.requests.read().unwrap();
        requests.get(id).map(|r| r.effective_status())
    }

    /// Approve a request.
    pub fn approve(&self, id: &str) -> bool {
        let mut requests = self.requests.write().unwrap();
        if let Some(req) = requests.get_mut(id) {
            if req.effective_status() == ApprovalStatus::Pending {
                req.status = ApprovalStatus::Approved;
                return true;
            }
        }
        false
    }

    /// Deny a request.
    pub fn deny(&self, id: &str) -> bool {
        let mut requests = self.requests.write().unwrap();
        if let Some(req) = requests.get_mut(id) {
            if req.effective_status() == ApprovalStatus::Pending {
                req.status = ApprovalStatus::Denied;
                return true;
            }
        }
        false
    }

    /// Remove expired requests.
    pub fn cleanup(&self) {
        let mut requests = self.requests.write().unwrap();
        requests.retain(|_, req| !req.is_expired());
    }

    pub fn pending_count(&self) -> usize {
        let requests = self.requests.read().unwrap();
        requests
            .values()
            .filter(|r| r.effective_status() == ApprovalStatus::Pending)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_query() {
        let store = ApprovalStore::new(300);
        let id = store.create("agent", "write", "/home/user/doc.md");
        assert_eq!(store.status(&id), Some(ApprovalStatus::Pending));
        assert_eq!(store.pending_count(), 1);
    }

    #[test]
    fn approve_request() {
        let store = ApprovalStore::new(300);
        let id = store.create("agent", "write", "/path");
        assert!(store.approve(&id));
        assert_eq!(store.status(&id), Some(ApprovalStatus::Approved));
        assert_eq!(store.pending_count(), 0);
    }

    #[test]
    fn deny_request() {
        let store = ApprovalStore::new(300);
        let id = store.create("agent", "write", "/path");
        assert!(store.deny(&id));
        assert_eq!(store.status(&id), Some(ApprovalStatus::Denied));
    }

    #[test]
    fn cannot_approve_twice() {
        let store = ApprovalStore::new(300);
        let id = store.create("agent", "write", "/path");
        assert!(store.approve(&id));
        assert!(!store.approve(&id));
    }

    #[test]
    fn cannot_approve_denied() {
        let store = ApprovalStore::new(300);
        let id = store.create("agent", "write", "/path");
        assert!(store.deny(&id));
        assert!(!store.approve(&id));
    }

    #[test]
    fn expired_request() {
        let store = ApprovalStore::new(0);
        let id = store.create("agent", "write", "/path");
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(store.status(&id), Some(ApprovalStatus::Expired));
        assert!(!store.approve(&id));
    }

    #[test]
    fn cleanup_removes_expired() {
        let store = ApprovalStore::new(0);
        store.create("agent", "write", "/path");
        std::thread::sleep(Duration::from_millis(10));
        store.cleanup();
        assert_eq!(store.pending_count(), 0);
    }

    #[test]
    fn unknown_id() {
        let store = ApprovalStore::new(300);
        assert_eq!(store.status("nonexistent"), None);
        assert!(!store.approve("nonexistent"));
    }
}
