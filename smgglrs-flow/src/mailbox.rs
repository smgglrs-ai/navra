//! IFC-gated agent mailboxes for lateral message passing.
//!
//! Each agent in a flow gets an mpsc-backed mailbox. Every `post()`
//! is checked against Bell-LaPadula no-write-down policy: a sender
//! tainted with Sensitive data cannot write to a Public-clearance
//! receiver. All delivered messages are recorded in an audit log.

use crate::error::FlowError;
use smgglrs_protocol::label::{Confidentiality, DataLabel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;

/// A labeled message between agents.
#[derive(Debug, Clone)]
pub struct MailboxMessage {
    pub sender: String,
    pub body: String,
    pub label: DataLabel,
    pub timestamp: Instant,
}

/// Per-agent mailbox backed by tokio mpsc.
struct AgentMailbox {
    tx: mpsc::Sender<MailboxMessage>,
    rx: Mutex<mpsc::Receiver<MailboxMessage>>,
    agent_id: String,
    clearance: Confidentiality,
}

/// Flow-level mailbox registry. Shared across all agents in a flow.
pub struct MailboxRegistry {
    mailboxes: HashMap<String, AgentMailbox>,
    audit_log: Arc<Mutex<Vec<MailboxMessage>>>,
}

impl MailboxRegistry {
    /// Create a registry with one mpsc channel per agent.
    ///
    /// All agents start with `Confidentiality::Public` clearance.
    pub fn new(agent_ids: &[String], capacity: usize) -> Self {
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
                },
            );
        }
        Self {
            mailboxes,
            audit_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Post a labeled message from one agent to another.
    ///
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

        let msg = MailboxMessage {
            sender: sender_id.to_string(),
            body,
            label: sender_label,
            timestamp: Instant::now(),
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
        assert_eq!(msg.body, "hello");
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
            FlowError::IfcViolation {
                sender, target, ..
            } => {
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
        assert_eq!(msg.body, "sensitive data");
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
        assert_eq!(msgs[0].body, "msg 0");
        assert_eq!(msgs[1].body, "msg 1");
        assert_eq!(msgs[2].body, "msg 2");

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
}
