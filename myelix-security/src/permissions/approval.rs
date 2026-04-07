use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Status of an approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Metadata for a pending approval request.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub id: String,
    pub agent_name: String,
    pub operation: String,
    pub path: String,
}

/// Internal state for a pending request.
struct PendingRequest {
    meta: ApprovalRequest,
    sender: Option<oneshot::Sender<ApprovalStatus>>,
}

/// A cached approval grant — allows a retry to pass through.
struct Grant {
    agent_name: String,
    operation: String,
    path: String,
    expires: Instant,
}

/// Thread-safe store for pending approvals and cached grants.
///
/// Supports two resolution channels:
/// 1. MCP-native: agent calls `docs_approve` tool → `approve()` → grant cached
/// 2. D-Bus: user clicks notification action → `approve()` → grant cached
///
/// After approval, the agent retries the original operation.
/// `check_grant()` finds the cached grant and consumes it.
pub struct ApprovalStore {
    pending: Arc<Mutex<HashMap<String, PendingRequest>>>,
    grants: Arc<Mutex<Vec<Grant>>>,
    timeout: Duration,
    grant_ttl: Duration,
}

impl ApprovalStore {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            grants: Arc::new(Mutex::new(Vec::new())),
            timeout: Duration::from_secs(timeout_secs),
            grant_ttl: Duration::from_secs(300), // 5 min to retry
        }
    }

    /// Create an approval request. Returns the request metadata and a
    /// receiver that resolves when the user approves, denies, or the
    /// request times out.
    pub fn request(
        &self,
        agent_name: &str,
        operation: &str,
        path: &str,
    ) -> (ApprovalRequest, oneshot::Receiver<ApprovalStatus>) {
        let id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        let meta = ApprovalRequest {
            id: id.clone(),
            agent_name: agent_name.to_string(),
            operation: operation.to_string(),
            path: path.to_string(),
        };
        let mut pending = self.pending.lock().unwrap();
        pending.insert(
            id,
            PendingRequest {
                meta: meta.clone(),
                sender: Some(tx),
            },
        );
        (meta, rx)
    }

    /// Resolve a pending request. If approved, caches a grant for the retry.
    pub fn resolve(&self, id: &str, status: ApprovalStatus) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if let Some(mut req) = pending.remove(id) {
            if status == ApprovalStatus::Approved {
                let mut grants = self.grants.lock().unwrap();
                grants.push(Grant {
                    agent_name: req.meta.agent_name.clone(),
                    operation: req.meta.operation.clone(),
                    path: req.meta.path.clone(),
                    expires: Instant::now() + self.grant_ttl,
                });
            }
            if let Some(tx) = req.sender.take() {
                let _ = tx.send(status);
            }
            return true;
        }
        false
    }

    /// Convenience: approve a request.
    pub fn approve(&self, id: &str) -> bool {
        self.resolve(id, ApprovalStatus::Approved)
    }

    /// Convenience: deny a request.
    pub fn deny(&self, id: &str) -> bool {
        self.resolve(id, ApprovalStatus::Denied)
    }

    /// Check if there's a cached grant for this (agent, operation, path).
    /// Consumes the grant if found (single-use).
    pub fn check_grant(&self, agent_name: &str, operation: &str, path: &str) -> bool {
        let mut grants = self.grants.lock().unwrap();
        let now = Instant::now();

        // Clean expired grants
        grants.retain(|g| g.expires > now);

        // Find and consume matching grant
        if let Some(pos) = grants.iter().position(|g| {
            g.agent_name == agent_name && g.operation == operation && g.path == path
        }) {
            grants.remove(pos);
            true
        } else {
            false
        }
    }

    /// Wait for approval with timeout. Returns the final status.
    pub async fn wait(&self, rx: oneshot::Receiver<ApprovalStatus>) -> ApprovalStatus {
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => ApprovalStatus::Expired,
            Err(_) => ApprovalStatus::Expired,
        }
    }

    /// Get metadata for a pending request (for docs_approve to validate).
    pub fn get_pending(&self, id: &str) -> Option<ApprovalRequest> {
        let pending = self.pending.lock().unwrap();
        pending.get(id).map(|r| r.meta.clone())
    }

    /// Number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// List all pending requests.
    pub fn pending_requests(&self) -> Vec<ApprovalRequest> {
        let pending = self.pending.lock().unwrap();
        pending.values().map(|r| r.meta.clone()).collect()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_and_approve() {
        let store = ApprovalStore::new(300);
        let (req, rx) = store.request("agent", "write", "/path");
        assert_eq!(store.pending_count(), 1);

        assert!(store.approve(&req.id));
        assert_eq!(store.pending_count(), 0);

        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn request_and_deny() {
        let store = ApprovalStore::new(300);
        let (req, rx) = store.request("agent", "write", "/path");

        assert!(store.deny(&req.id));

        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Denied);
    }

    #[tokio::test]
    async fn request_timeout() {
        let store = ApprovalStore::new(0);
        let (_req, rx) = store.request("agent", "write", "/path");

        let status = store.wait(rx).await;
        assert_eq!(status, ApprovalStatus::Expired);
    }

    #[tokio::test]
    async fn wait_returns_approved() {
        let store = Arc::new(ApprovalStore::new(5));
        let (req, rx) = store.request("agent", "write", "/path");

        let store2 = store.clone();
        let id = req.id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            store2.approve(&id);
        });

        let status = store.wait(rx).await;
        assert_eq!(status, ApprovalStatus::Approved);
    }

    #[test]
    fn resolve_unknown_id() {
        let store = ApprovalStore::new(300);
        assert!(!store.approve("nonexistent"));
    }

    #[test]
    fn pending_requests_list() {
        let store = ApprovalStore::new(300);
        store.request("a1", "write", "/path1");
        store.request("a2", "read", "/path2");
        let pending = store.pending_requests();
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn cannot_resolve_twice() {
        let store = ApprovalStore::new(300);
        let (req, _rx) = store.request("agent", "write", "/path");
        assert!(store.approve(&req.id));
        assert!(!store.approve(&req.id));
    }

    // --- grant cache tests ---

    #[test]
    fn approve_creates_grant() {
        let store = ApprovalStore::new(300);
        let (req, _rx) = store.request("agent", "write", "/home/user/doc.md");
        store.approve(&req.id);

        assert!(store.check_grant("agent", "write", "/home/user/doc.md"));
    }

    #[test]
    fn grant_is_single_use() {
        let store = ApprovalStore::new(300);
        let (req, _rx) = store.request("agent", "write", "/path");
        store.approve(&req.id);

        assert!(store.check_grant("agent", "write", "/path"));
        assert!(!store.check_grant("agent", "write", "/path"));
    }

    #[test]
    fn deny_does_not_create_grant() {
        let store = ApprovalStore::new(300);
        let (req, _rx) = store.request("agent", "write", "/path");
        store.deny(&req.id);

        assert!(!store.check_grant("agent", "write", "/path"));
    }

    #[test]
    fn grant_requires_exact_match() {
        let store = ApprovalStore::new(300);
        let (req, _rx) = store.request("agent", "write", "/path");
        store.approve(&req.id);

        assert!(!store.check_grant("other_agent", "write", "/path"));
        assert!(!store.check_grant("agent", "read", "/path"));
        assert!(!store.check_grant("agent", "write", "/other"));
    }

    #[test]
    fn get_pending_returns_metadata() {
        let store = ApprovalStore::new(300);
        let (req, _rx) = store.request("agent", "write", "/path");
        let meta = store.get_pending(&req.id).unwrap();
        assert_eq!(meta.agent_name, "agent");
        assert_eq!(meta.operation, "write");
    }

    #[test]
    fn get_pending_returns_none_after_resolve() {
        let store = ApprovalStore::new(300);
        let (req, _rx) = store.request("agent", "write", "/path");
        store.approve(&req.id);
        assert!(store.get_pending(&req.id).is_none());
    }
}
