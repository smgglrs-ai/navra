use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct UiBroadcaster {
    tx: broadcast::Sender<String>,
}

impl UiBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn send(&self, event: &serde_json::Value) {
        let _ = self.tx.send(event.to_string());
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }
}

pub fn start_polling_bridge(broadcaster: Arc<UiBroadcaster>, server: Arc<navra_core::McpServer>) {
    tokio::spawn(async move {
        let mut prev_process_count = 0usize;
        let mut prev_bb_count = 0u64;

        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            let snapshots = server.process_table().snapshot();
            if snapshots.len() != prev_process_count {
                broadcaster.send(&serde_json::json!({
                    "type": "process_update",
                    "data": {
                        "count": snapshots.len(),
                        "processes": snapshots,
                    }
                }));
                prev_process_count = snapshots.len();
            }

            if let Some(bb) = server.blackbox() {
                let count = bb.count();
                if count > prev_bb_count && prev_bb_count > 0 {
                    let new_entries = bb.recent((count - prev_bb_count) as usize);
                    for entry in &new_entries {
                        broadcaster.send(&serde_json::json!({
                            "type": "tool_call_end",
                            "data": {
                                "agent": entry.agent_name,
                                "tool": entry.tool_name,
                                "outcome": entry.outcome,
                                "duration_us": entry.duration_us,
                                "ifc_label": entry.ifc_label,
                            }
                        }));
                    }
                }
                prev_bb_count = count;
            }
        }
    });
}
