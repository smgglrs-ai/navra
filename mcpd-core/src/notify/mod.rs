mod dbus;

pub use dbus::DbusNotifier;

use crate::permissions::{ApprovalRequest, ApprovalStore};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait for approval notification backends.
///
/// Implementations send user-visible notifications and wire up
/// callbacks to resolve approval requests.
pub trait Notifier: Send + Sync + 'static {
    /// Send an approval notification for the given request.
    fn notify(
        &self,
        request: &ApprovalRequest,
        store: Arc<ApprovalStore>,
    ) -> BoxFuture<'_, Result<(), NotifyError>>;

    /// Dismiss a notification (e.g. after timeout or resolution).
    fn dismiss(&self, request_id: &str) -> BoxFuture<'_, Result<(), NotifyError>>;
}

/// No-op notifier for testing or headless environments.
/// Approvals must be resolved via CLI.
pub struct NoopNotifier;

impl Notifier for NoopNotifier {
    fn notify(
        &self,
        request: &ApprovalRequest,
        _store: Arc<ApprovalStore>,
    ) -> BoxFuture<'_, Result<(), NotifyError>> {
        let id = request.id.clone();
        let agent = request.agent_name.clone();
        let op = request.operation.clone();
        let path = request.path.clone();
        Box::pin(async move {
            tracing::info!(
                id = %id,
                agent = %agent,
                op = %op,
                path = %path,
                "Approval required (no notifier — use CLI: mcpd approve {id})",
            );
            Ok(())
        })
    }

    fn dismiss(&self, _request_id: &str) -> BoxFuture<'_, Result<(), NotifyError>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),
    #[error("Notification failed: {0}")]
    Other(String),
}
