//! IFC-gated agent mailboxes for lateral message passing.
//!
//! Each agent in a flow gets an mpsc-backed mailbox. Every `post()`
//! is checked against Bell-LaPadula no-write-down policy: a sender
//! tainted with Sensitive data cannot write to a Public-clearance
//! receiver. All delivered messages are recorded in an audit log.

use crate::error::FlowError;
use navra_protocol::label::{Confidentiality, DataLabel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;

/// Body of a mailbox message: complete or incremental.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageBody {
    /// A complete message (current default).
    Complete(String),
    /// An incremental reasoning step for streaming delivery.
    /// The mpsc channels already support this — receivers can
    /// process steps as they arrive without waiting for `is_final`.
    Step {
        index: u32,
        content: String,
        is_final: bool,
    },
}

impl MessageBody {
    pub fn text(&self) -> &str {
        match self {
            MessageBody::Complete(s) => s,
            MessageBody::Step { content, .. } => content,
        }
    }
}

/// A labeled message between agents with provenance tracking.
#[derive(Debug, Clone)]
pub struct MailboxMessage {
    pub sender: String,
    pub body: MessageBody,
    pub label: DataLabel,
    pub timestamp: Instant,
    /// Provenance chain: ordered list of (agent_id, timestamp) pairs
    /// tracking all agents that contributed to this message's content.
    pub provenance: Vec<(String, Instant)>,
    /// Optional causal graph node ID linking this message to the provenance graph.
    pub causal_node_id: Option<String>,
}

/// Per-agent mailbox backed by tokio mpsc.
struct AgentMailbox {
    tx: mpsc::Sender<MailboxMessage>,
    rx: Mutex<mpsc::Receiver<MailboxMessage>>,
    agent_id: String,
    clearance: Confidentiality,
    send_count: std::sync::atomic::AtomicU64,
}

/// Flow-level mailbox registry. Shared across all agents in a flow.
pub struct MailboxRegistry {
    mailboxes: HashMap<String, AgentMailbox>,
    audit_log: Arc<Mutex<Vec<MailboxMessage>>>,
    rate_limit: u64,
}

impl MailboxRegistry {
    /// Create a registry with one mpsc channel per agent.
    ///
    /// All agents start with `Confidentiality::Public` clearance.
    /// `rate_limit` is the max messages per agent (0 = unlimited).
    pub fn new(agent_ids: &[String], capacity: usize) -> Self {
        Self::with_rate_limit(agent_ids, capacity, 0)
    }

    /// Create a registry with a per-agent message rate limit.
    pub fn with_rate_limit(agent_ids: &[String], capacity: usize, rate_limit: u64) -> Self {
        let mut mailboxes = HashMap::new();
        for id in agent_ids {
            let (tx, rx) = mpsc::channel(capacity);
            mailboxes.insert(
                id.clone(),
                AgentMailbox {
                    tx,
                    rx: Mutex::new(rx),
                    agent_id: id.clone(),
                    clearance: Confidentiality::Public,
                    send_count: std::sync::atomic::AtomicU64::new(0),
                },
            );
        }
        Self {
            mailboxes,
            audit_log: Arc::new(Mutex::new(Vec::new())),
            rate_limit,
        }
    }

    /// Post a labeled message from one agent to another.
    ///
    /// Includes provenance tracking and optional rate limiting.
    /// Returns `FlowError::IfcViolation` if the sender's label
    /// confidentiality exceeds the target's clearance (no write-down).
    /// Returns `FlowError::UnknownAgent` if the target does not exist.
    /// Returns `FlowError::MailboxFull` if the target's channel is full.
    pub fn post(
        &self,
        sender_id: &str,
        sender_label: DataLabel,
        target_id: &str,
        body: String,
    ) -> Result<(), FlowError> {
        self.post_with_provenance(
            sender_id,
            sender_label,
            target_id,
            MessageBody::Complete(body),
            Vec::new(),
        )
    }

    /// Post a message with an inherited provenance chain.
    ///
    /// When an agent forwards content from another agent's message,
    /// pass the original message's provenance chain here. The sender
    /// is appended to the chain. Circular provenance is detected and
    /// logged.
    pub fn post_with_provenance(
        &self,
        sender_id: &str,
        sender_label: DataLabel,
        target_id: &str,
        body: MessageBody,
        inherited_provenance: Vec<(String, Instant)>,
    ) -> Result<(), FlowError> {
        // Rate limit check
        if self.rate_limit > 0
            && let Some(sender_mailbox) = self.mailboxes.get(sender_id)
        {
            let count = sender_mailbox
                .send_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if count >= self.rate_limit {
                tracing::warn!(
                    sender = sender_id,
                    count,
                    limit = self.rate_limit,
                    "Agent rate limited — quarantine triggered"
                );
                return Err(FlowError::Other(anyhow::anyhow!(
                    "agent '{}' exceeded message rate limit ({} messages)",
                    sender_id,
                    self.rate_limit,
                )));
            }
        }

        let target = self
            .mailboxes
            .get(target_id)
            .ok_or_else(|| FlowError::UnknownAgent(target_id.to_string()))?;

        if !sender_label.can_write_to(target.clearance) {
            return Err(FlowError::IfcViolation {
                sender: sender_id.to_string(),
                target: target_id.to_string(),
                reason: format!(
                    "sender label {:?} exceeds target clearance {:?}",
                    sender_label.confidentiality, target.clearance,
                ),
            });
        }

        let mut provenance = inherited_provenance;
        let now = Instant::now();

        // Circular provenance detection
        if provenance.iter().any(|(id, _)| id == sender_id) {
            tracing::warn!(
                sender = sender_id,
                target = target_id,
                chain_len = provenance.len(),
                "Circular provenance detected in message chain"
            );
        }

        provenance.push((sender_id.to_string(), now));

        let msg = MailboxMessage {
            sender: sender_id.to_string(),
            body,
            label: sender_label,
            timestamp: now,
            provenance,
            causal_node_id: None,
        };

        target
            .tx
            .try_send(msg.clone())
            .map_err(|_| FlowError::MailboxFull(target.agent_id.clone()))?;

        let mut log = self.audit_log.lock().unwrap_or_else(|e| e.into_inner());
        log.push(msg);

        Ok(())
    }

    /// Non-blocking receive of the next pending message for an agent.
    pub fn recv(&self, agent_id: &str) -> Option<MailboxMessage> {
        let mailbox = self.mailboxes.get(agent_id)?;
        let mut rx = mailbox.rx.lock().unwrap_or_else(|e| e.into_inner());
        rx.try_recv().ok()
    }

    /// Drain all pending messages for an agent.
    pub fn recv_all(&self, agent_id: &str) -> Vec<MailboxMessage> {
        let Some(mailbox) = self.mailboxes.get(agent_id) else {
            return Vec::new();
        };
        let mut rx = mailbox.rx.lock().unwrap_or_else(|e| e.into_inner());
        let mut msgs = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            msgs.push(msg);
        }
        msgs
    }

    /// Update an agent's clearance level.
    pub fn set_clearance(&mut self, agent_id: &str, level: Confidentiality) {
        if let Some(mailbox) = self.mailboxes.get_mut(agent_id) {
            mailbox.clearance = level;
        }
    }

    /// Clone the audit log for inspection.
    pub fn audit_log(&self) -> Vec<MailboxMessage> {
        let log = self.audit_log.lock().unwrap_or_else(|e| e.into_inner());
        log.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_ids(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn post_and_recv_round_trip() {
        let ids = agent_ids(&["alice", "bob"]);
        let reg = MailboxRegistry::new(&ids, 16);

        reg.post("alice", DataLabel::TRUSTED_PUBLIC, "bob", "hello".into())
            .unwrap();

        let msg = reg.recv("bob").expect("should have a message");
        assert_eq!(msg.sender, "alice");
        assert_eq!(msg.body.text(), "hello");
        assert_eq!(msg.label, DataLabel::TRUSTED_PUBLIC);
    }

    #[test]
    fn post_ifc_violation_secret_to_public() {
        let ids = agent_ids(&["alice", "bob"]);
        let reg = MailboxRegistry::new(&ids, 16);

        let err = reg
            .post(
                "alice",
                DataLabel::UNTRUSTED_SENSITIVE,
                "bob",
                "secret stuff".into(),
            )
            .unwrap_err();

        match err {
            FlowError::IfcViolation { sender, target, .. } => {
                assert_eq!(sender, "alice");
                assert_eq!(target, "bob");
            }
            other => panic!("expected IfcViolation, got: {other}"),
        }
    }

    #[test]
    fn post_ifc_compatible_sensitive_to_sensitive() {
        let ids = agent_ids(&["alice", "bob"]);
        let mut reg = MailboxRegistry::new(&ids, 16);

        reg.set_clearance("bob", Confidentiality::Sensitive);

        reg.post(
            "alice",
            DataLabel::UNTRUSTED_SENSITIVE,
            "bob",
            "sensitive data".into(),
        )
        .unwrap();

        let msg = reg.recv("bob").expect("should have a message");
        assert_eq!(msg.body.text(), "sensitive data");
    }

    #[test]
    fn recv_empty_returns_none() {
        let ids = agent_ids(&["alice"]);
        let reg = MailboxRegistry::new(&ids, 16);

        assert!(reg.recv("alice").is_none());
    }

    #[test]
    fn recv_all_drains_messages() {
        let ids = agent_ids(&["alice", "bob"]);
        let reg = MailboxRegistry::new(&ids, 16);

        for i in 0..3 {
            reg.post(
                "alice",
                DataLabel::TRUSTED_PUBLIC,
                "bob",
                format!("msg {i}"),
            )
            .unwrap();
        }

        let msgs = reg.recv_all("bob");
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].body.text(), "msg 0");
        assert_eq!(msgs[1].body.text(), "msg 1");
        assert_eq!(msgs[2].body.text(), "msg 2");

        assert!(reg.recv("bob").is_none());
    }

    #[test]
    fn audit_log_records_deliveries() {
        let ids = agent_ids(&["alice", "bob"]);
        let reg = MailboxRegistry::new(&ids, 16);

        reg.post("alice", DataLabel::TRUSTED_PUBLIC, "bob", "one".into())
            .unwrap();
        reg.post("bob", DataLabel::TRUSTED_PUBLIC, "alice", "two".into())
            .unwrap();

        let log = reg.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].sender, "alice");
        assert_eq!(log[1].sender, "bob");
    }

    #[test]
    fn unknown_agent_returns_error() {
        let ids = agent_ids(&["alice"]);
        let reg = MailboxRegistry::new(&ids, 16);

        let err = reg
            .post("alice", DataLabel::TRUSTED_PUBLIC, "nobody", "hi".into())
            .unwrap_err();

        match err {
            FlowError::UnknownAgent(name) => assert_eq!(name, "nobody"),
            other => panic!("expected UnknownAgent, got: {other}"),
        }
    }

    #[test]
    fn mailbox_full() {
        let ids = agent_ids(&["alice", "bob"]);
        let reg = MailboxRegistry::new(&ids, 1);

        reg.post("alice", DataLabel::TRUSTED_PUBLIC, "bob", "first".into())
            .unwrap();

        let err = reg
            .post("alice", DataLabel::TRUSTED_PUBLIC, "bob", "second".into())
            .unwrap_err();

        match err {
            FlowError::MailboxFull(name) => assert_eq!(name, "bob"),
            other => panic!("expected MailboxFull, got: {other}"),
        }
    }

    #[test]
    fn step_messages_delivered_incrementally() {
        let ids = agent_ids(&["alice", "bob"]);
        let reg = MailboxRegistry::new(&ids, 16);

        for i in 0..3 {
            reg.post_with_provenance(
                "alice",
                DataLabel::TRUSTED_PUBLIC,
                "bob",
                MessageBody::Step {
                    index: i,
                    content: format!("step {i}"),
                    is_final: i == 2,
                },
                Vec::new(),
            )
            .unwrap();
        }

        let msgs = reg.recv_all("bob");
        assert_eq!(msgs.len(), 3);

        match &msgs[0].body {
            MessageBody::Step {
                index,
                content,
                is_final,
            } => {
                assert_eq!(*index, 0);
                assert_eq!(content, "step 0");
                assert!(!is_final);
            }
            _ => panic!("expected Step"),
        }

        match &msgs[2].body {
            MessageBody::Step { is_final, .. } => assert!(is_final),
            _ => panic!("expected Step"),
        }
    }

    #[test]
    fn message_body_text_accessor() {
        let complete = MessageBody::Complete("hello".into());
        assert_eq!(complete.text(), "hello");

        let step = MessageBody::Step {
            index: 0,
            content: "step content".into(),
            is_final: false,
        };
        assert_eq!(step.text(), "step content");
    }
}
