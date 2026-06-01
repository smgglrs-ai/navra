use super::NotifyError;
use crate::permissions::{ApprovalRequest, ApprovalStore};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zbus::zvariant::Value;
use zbus::Connection;

/// D-Bus notification IDs mapped to approval request IDs.
type NotificationMap = Arc<Mutex<HashMap<u32, NotificationEntry>>>;

struct NotificationEntry {
    request_id: String,
    store: Arc<ApprovalStore>,
}

/// Desktop notification sender using org.freedesktop.Notifications.
///
/// Sends notifications with "Approve" and "Deny" action buttons.
/// Listens for ActionInvoked and NotificationClosed signals to
/// resolve the corresponding approval request.
pub struct DbusNotifier {
    connection: Connection,
    notifications: NotificationMap,
}

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    fn close_notification(&self, id: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

impl DbusNotifier {
    /// Connect to the session D-Bus and start listening for signals.
    pub async fn new() -> Result<Self, NotifyError> {
        let connection = Connection::session().await?;
        let notifications: NotificationMap = Arc::new(Mutex::new(HashMap::new()));

        // Spawn signal listener
        let conn = connection.clone();
        let notifs = notifications.clone();
        tokio::spawn(async move {
            if let Err(e) = listen_signals(conn, notifs).await {
                tracing::error!("D-Bus signal listener failed: {e}");
            }
        });

        Ok(Self {
            connection,
            notifications,
        })
    }

    async fn proxy(&self) -> Result<NotificationsProxy<'_>, NotifyError> {
        Ok(NotificationsProxy::new(&self.connection).await?)
    }
}

impl super::Notifier for DbusNotifier {
    fn notify(
        &self,
        request: &ApprovalRequest,
        store: Arc<ApprovalStore>,
    ) -> super::BoxFuture<'_, Result<(), NotifyError>> {
        let request_id = request.id.clone();
        let agent = request.agent_name.clone();
        let op = request.operation.clone();
        let path = request.path.clone();

        Box::pin(async move {
            let proxy = self.proxy().await?;

            let summary = format!("navra: {op} approval");
            let body = format!("Agent <b>{agent}</b> wants to <b>{op}</b>\n{path}",);

            let approve_key = format!("approve:{request_id}");
            let deny_key = format!("deny:{request_id}");
            let actions: Vec<&str> = vec![&approve_key, "Approve", &deny_key, "Deny"];

            let hints = HashMap::from([("urgency", Value::U8(2))]);

            let notif_id = proxy
                .notify(
                    "navra",
                    0,
                    "dialog-password",
                    &summary,
                    &body,
                    &actions,
                    hints,
                    0,
                )
                .await?;

            tracing::info!(
                notif_id,
                request_id = %request_id,
                agent = %agent,
                op = %op,
                path = %path,
                "Sent approval notification"
            );

            let mut map = self.notifications.lock().unwrap_or_else(|e| e.into_inner());
            map.insert(notif_id, NotificationEntry { request_id, store });

            Ok(())
        })
    }

    fn dismiss(&self, request_id: &str) -> super::BoxFuture<'_, Result<(), NotifyError>> {
        let request_id = request_id.to_string();
        Box::pin(async move {
            let notif_id = {
                let map = self.notifications.lock().unwrap_or_else(|e| e.into_inner());
                map.iter()
                    .find(|(_, e)| e.request_id == request_id)
                    .map(|(id, _)| *id)
            };

            if let Some(notif_id) = notif_id {
                let proxy = self.proxy().await?;
                proxy.close_notification(notif_id).await?;
                let mut map = self.notifications.lock().unwrap_or_else(|e| e.into_inner());
                map.remove(&notif_id);
            }

            Ok(())
        })
    }
}

async fn listen_signals(
    connection: Connection,
    notifications: NotificationMap,
) -> Result<(), NotifyError> {
    use futures_util::StreamExt;

    let proxy = NotificationsProxy::new(&connection).await?;

    let mut action_stream = proxy.receive_action_invoked().await?;
    let mut close_stream = proxy.receive_notification_closed().await?;

    loop {
        tokio::select! {
            Some(signal) = action_stream.next() => {
                if let Ok(args) = signal.args() {
                    handle_action(&notifications, args.id, args.action_key);
                }
            }
            Some(signal) = close_stream.next() => {
                if let Ok(args) = signal.args() {
                    // reason: 1=expired, 2=dismissed, 3=closed programmatically
                    if args.reason == 2 {
                        handle_dismissed(&notifications, args.id);
                    }
                    let mut map = notifications.lock().unwrap_or_else(|e| e.into_inner());
                    map.remove(&args.id);
                }
            }
        }
    }
}

fn handle_action(notifications: &NotificationMap, notif_id: u32, action_key: &str) {
    let entry = {
        let mut map = notifications.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(&notif_id)
    };

    if let Some(entry) = entry {
        if action_key.starts_with("approve:") {
            tracing::info!(request_id = %entry.request_id, "User approved");
            entry.store.approve(&entry.request_id);
        } else if action_key.starts_with("deny:") {
            tracing::info!(request_id = %entry.request_id, "User denied");
            entry.store.deny(&entry.request_id);
        }
    }
}

fn handle_dismissed(notifications: &NotificationMap, notif_id: u32) {
    let entry = {
        let map = notifications.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&notif_id)
            .map(|e| (e.request_id.clone(), e.store.clone()))
    };

    if let Some((request_id, store)) = entry {
        tracing::info!(request_id = %request_id, "Notification dismissed — denying");
        store.deny(&request_id);
    }
}
