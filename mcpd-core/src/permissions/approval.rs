use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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

/// Thread-safe store for pending approvals.
///
/// When a tool needs approval, `request()` creates an entry and returns
/// a `oneshot::Receiver` the caller can `.await`. The D-Bus notifier or
/// CLI resolves it via `resolve()`.
pub struct ApprovalStore {
    pending: Arc<Mutex<HashMap<String, PendingRequest>>>,
    timeout: Duration,
}

impl ApprovalStore {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            timeout: Duration::from_secs(timeout_secs),
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

    /// Resolve a pending request (from D-Bus action or CLI).
    /// Returns true if the request was found and resolved.
    pub fn resolve(&self, id: &str, status: ApprovalStatus) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if let Some(mut req) = pending.remove(id) {
            if let Some(tx) = req.sender.take() {
                let _ = tx.send(status);
                return true;
            }
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

    /// Wait for approval with timeout. Returns the final status.
    pub async fn wait(&self, rx: oneshot::Receiver<ApprovalStatus>) -> ApprovalStatus {
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => ApprovalStatus::Expired, // sender dropped
            Err(_) => {
                // Timeout — clean up is handled by the caller
                ApprovalStatus::Expired
            }
        }
    }

    /// Number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// List all pending requests (for tray icon / status display).
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
        let store = ApprovalStore::new(0); // 0 second timeout
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
}
