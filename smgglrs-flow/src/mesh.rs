//! Teammate mesh routing: in-process and remote A2A communication.
//!
//! The [`MeshRouter`] dispatches messages between teammates based on
//! their [`TeammateLocation`]. In-process teammates communicate via
//! the existing mailbox channels. Remote teammates use [`A2aClient`]
//! to send tasks over the A2A protocol.
//!
//! All messages are subject to Bell-LaPadula no-write-down IFC checks
//! before delivery, regardless of location.

use crate::error::FlowError;
use crate::mailbox::MailboxMessage;
use smgglrs_protocol::a2a::{AgentCard, Message, MessageKind, MessageRole, Part};
use smgglrs_protocol::a2a_client::A2aClient;
use smgglrs_protocol::label::{Confidentiality, DataLabel};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::sync::mpsc;

/// Where a teammate lives and how to reach it.
#[derive(Debug, Clone)]
pub enum TeammateLocation {
    /// Same process, communicate via tokio mpsc channels.
    InProcess,
    /// Remote sandbox, communicate via A2A protocol.
    Remote {
        /// A2A endpoint URL.
        url: String,
        /// Bearer token for authentication.
        token: String,
    },
}

/// In-memory directory of teammate Agent Cards.
///
/// Thread-safe via `Arc<RwLock<>>`. Used to discover teammate
/// capabilities without querying external registries.
#[derive(Clone)]
pub struct AgentCardDirectory {
    cards: Arc<RwLock<HashMap<String, AgentCard>>>,
}

impl AgentCardDirectory {
    /// Create an empty directory.
    pub fn new() -> Self {
        Self {
            cards: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a teammate's Agent Card.
    pub fn register(&self, name: &str, card: AgentCard) {
        let mut cards = self.cards.write().unwrap_or_else(|e| e.into_inner());
        cards.insert(name.to_string(), card);
    }

    /// Look up a teammate's Agent Card.
    pub fn lookup(&self, name: &str) -> Option<AgentCard> {
        let cards = self.cards.read().unwrap_or_else(|e| e.into_inner());
        cards.get(name).cloned()
    }

    /// List all registered teammates with their cards.
    pub fn list(&self) -> Vec<(String, AgentCard)> {
        let cards = self.cards.read().unwrap_or_else(|e| e.into_inner());
        cards.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Remove a teammate's Agent Card.
    pub fn remove(&self, name: &str) -> Option<AgentCard> {
        let mut cards = self.cards.write().unwrap_or_else(|e| e.into_inner());
        cards.remove(name)
    }

    /// Returns the number of registered cards.
    pub fn len(&self) -> usize {
        let cards = self.cards.read().unwrap_or_else(|e| e.into_inner());
        cards.len()
    }

    /// Returns true if no cards are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for AgentCardDirectory {
    fn default() -> Self {
        Self::new()
    }
}

/// Routes messages between teammates based on location.
///
/// Applies IFC enforcement on all messages: Bell-LaPadula no-write-down
/// prevents a sender tainted with Sensitive data from writing to a
/// Public-clearance receiver.
pub struct MeshRouter {
    /// Teammate locations, keyed by name.
    teammates: HashMap<String, TeammateLocation>,
    /// Per-teammate confidentiality clearance for IFC checks.
    clearances: HashMap<String, Confidentiality>,
    /// In-process mailbox senders (only for InProcess teammates).
    mailbox_senders: HashMap<String, mpsc::Sender<MailboxMessage>>,
    /// A2A clients for remote teammates (lazily created).
    a2a_clients: HashMap<String, A2aClient>,
}

impl MeshRouter {
    /// Create a new mesh router.
    pub fn new() -> Self {
        Self {
            teammates: HashMap::new(),
            clearances: HashMap::new(),
            mailbox_senders: HashMap::new(),
            a2a_clients: HashMap::new(),
        }
    }

    /// Register an in-process teammate with a mailbox sender.
    pub fn add_in_process(
        &mut self,
        name: &str,
        sender: mpsc::Sender<MailboxMessage>,
        clearance: Confidentiality,
    ) {
        self.teammates
            .insert(name.to_string(), TeammateLocation::InProcess);
        self.mailbox_senders.insert(name.to_string(), sender);
        self.clearances.insert(name.to_string(), clearance);
    }

    /// Register a remote teammate.
    pub fn add_remote(&mut self, name: &str, url: &str, token: &str, clearance: Confidentiality) {
        self.teammates.insert(
            name.to_string(),
            TeammateLocation::Remote {
                url: url.to_string(),
                token: token.to_string(),
            },
        );
        self.a2a_clients
            .insert(name.to_string(), A2aClient::new(url, token));
        self.clearances.insert(name.to_string(), clearance);
    }

    /// Get the location of a teammate.
    pub fn location(&self, name: &str) -> Option<&TeammateLocation> {
        self.teammates.get(name)
    }

    /// List all registered teammate names.
    pub fn teammate_names(&self) -> Vec<String> {
        self.teammates.keys().cloned().collect()
    }

    /// Resolve the effective clearance for a teammate.
    /// Unknown teammates default to Public (maximally restrictive).
    /// Extracted for Kani verification.
    fn resolve_clearance(&self, name: &str) -> Confidentiality {
        self.clearances
            .get(name)
            .copied()
            .unwrap_or(Confidentiality::Public)
    }

    /// Route a message to a teammate, enforcing IFC.
    ///
    /// Bell-LaPadula no-write-down: the sender's data label
    /// confidentiality must not exceed the target's clearance.
    pub async fn send(
        &self,
        from: &str,
        to: &str,
        body: String,
        data_label: DataLabel,
    ) -> Result<(), FlowError> {
        // IFC check: no-write-down
        let target_clearance = self.resolve_clearance(to);

        if !data_label.can_write_to(target_clearance) {
            return Err(FlowError::IfcViolation {
                sender: from.to_string(),
                target: to.to_string(),
                reason: format!(
                    "sender label {:?} exceeds target clearance {:?}",
                    data_label.confidentiality, target_clearance,
                ),
            });
        }

        match self.teammates.get(to) {
            Some(TeammateLocation::InProcess) => {
                let sender = self.mailbox_senders.get(to).ok_or_else(|| {
                    FlowError::TeammateNotFound(format!("{to} (no mailbox sender)"))
                })?;

                let now = Instant::now();
                let msg = MailboxMessage {
                    sender: from.to_string(),
                    body,
                    label: data_label,
                    timestamp: now,
                    provenance: vec![(from.to_string(), now)],
                    causal_node_id: None,
                };

                sender
                    .try_send(msg)
                    .map_err(|_| FlowError::MailboxFull(to.to_string()))?;

                Ok(())
            }
            Some(TeammateLocation::Remote { .. }) => {
                let client = self
                    .a2a_clients
                    .get(to)
                    .ok_or_else(|| FlowError::TeammateNotFound(format!("{to} (no A2A client)")))?;

                let a2a_msg = Message {
                    role: MessageRole::User,
                    parts: vec![Part::text(&body)],
                    message_id: format!("mesh-{from}-{to}-{}", uuid_v4_simple()),
                    task_id: None,
                    context_id: None,
                    metadata: None,
                    extensions: vec![],
                    reference_task_ids: vec![],
                    kind: MessageKind::Message,
                };

                let label_str = format!("{data_label}");
                client
                    .send_message(a2a_msg, Some(&label_str))
                    .await
                    .map_err(|e| FlowError::A2aError {
                        teammate: to.to_string(),
                        message: e.to_string(),
                    })?;

                Ok(())
            }
            None => Err(FlowError::TeammateNotFound(to.to_string())),
        }
    }

    /// Update a teammate's clearance level.
    pub fn set_clearance(&mut self, name: &str, level: Confidentiality) {
        self.clearances.insert(name.to_string(), level);
    }

    /// Check if a teammate is registered.
    pub fn has_teammate(&self, name: &str) -> bool {
        self.teammates.contains_key(name)
    }

    /// Check if a teammate is remote.
    pub fn is_remote(&self, name: &str) -> bool {
        matches!(
            self.teammates.get(name),
            Some(TeammateLocation::Remote { .. })
        )
    }

    /// Check if a teammate is in-process.
    pub fn is_in_process(&self, name: &str) -> bool {
        matches!(self.teammates.get(name), Some(TeammateLocation::InProcess))
    }
}

impl Default for MeshRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple UUID v4-like identifier without external dependency.
fn uuid_v4_simple() -> String {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}", nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use smgglrs_protocol::a2a::{AgentCapabilities, AgentCard, AgentSkill, A2A_PROTOCOL_VERSION};

    // --- AgentCardDirectory tests ---

    fn test_card(name: &str) -> AgentCard {
        AgentCard {
            name: name.to_string(),
            description: format!("Test agent {name}"),
            url: format!("http://localhost:9315/a2a/{name}"),
            version: "0.1.0".to_string(),
            provider: None,
            did: None,
            capabilities: AgentCapabilities {
                streaming: None,
                push_notifications: None,
                state_transition_history: None,
            },
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            skills: vec![AgentSkill {
                id: "test".to_string(),
                name: "test".to_string(),
                description: "Test skill".to_string(),
                tags: vec![],
                examples: vec![],
                input_modes: None,
                output_modes: None,
            }],
            documentation_url: None,
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        }
    }

    #[test]
    fn directory_register_and_lookup() {
        let dir = AgentCardDirectory::new();
        assert!(dir.is_empty());

        let card = test_card("analyst");
        dir.register("analyst", card.clone());

        assert_eq!(dir.len(), 1);
        let found = dir.lookup("analyst").unwrap();
        assert_eq!(found.name, "analyst");
        assert_eq!(found.url, "http://localhost:9315/a2a/analyst");
    }

    #[test]
    fn directory_lookup_missing() {
        let dir = AgentCardDirectory::new();
        assert!(dir.lookup("nonexistent").is_none());
    }

    #[test]
    fn directory_list() {
        let dir = AgentCardDirectory::new();
        dir.register("a", test_card("a"));
        dir.register("b", test_card("b"));

        let mut list = dir.list();
        list.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, "a");
        assert_eq!(list[1].0, "b");
    }

    #[test]
    fn directory_remove() {
        let dir = AgentCardDirectory::new();
        dir.register("x", test_card("x"));
        assert_eq!(dir.len(), 1);

        let removed = dir.remove("x");
        assert!(removed.is_some());
        assert_eq!(dir.len(), 0);
        assert!(dir.lookup("x").is_none());
    }

    #[test]
    fn directory_overwrite() {
        let dir = AgentCardDirectory::new();
        let card1 = test_card("agent");
        let mut card2 = test_card("agent");
        card2.description = "Updated description".to_string();

        dir.register("agent", card1);
        dir.register("agent", card2);

        assert_eq!(dir.len(), 1);
        let found = dir.lookup("agent").unwrap();
        assert_eq!(found.description, "Updated description");
    }

    // --- TeammateLocation tests ---

    #[test]
    fn teammate_location_in_process() {
        let loc = TeammateLocation::InProcess;
        assert!(matches!(loc, TeammateLocation::InProcess));
    }

    #[test]
    fn teammate_location_remote() {
        let loc = TeammateLocation::Remote {
            url: "http://example.com/a2a".to_string(),
            token: "tok_123".to_string(),
        };
        match loc {
            TeammateLocation::Remote { url, token } => {
                assert_eq!(url, "http://example.com/a2a");
                assert_eq!(token, "tok_123");
            }
            _ => panic!("expected Remote"),
        }
    }

    // --- MeshRouter tests ---

    #[test]
    fn router_add_in_process() {
        let (tx, _rx) = mpsc::channel(16);
        let mut router = MeshRouter::new();
        router.add_in_process("alice", tx, Confidentiality::Public);

        assert!(router.has_teammate("alice"));
        assert!(router.is_in_process("alice"));
        assert!(!router.is_remote("alice"));
    }

    #[test]
    fn router_add_remote() {
        let mut router = MeshRouter::new();
        router.add_remote(
            "bob",
            "http://localhost:9315/a2a/bob",
            "token",
            Confidentiality::Sensitive,
        );

        assert!(router.has_teammate("bob"));
        assert!(router.is_remote("bob"));
        assert!(!router.is_in_process("bob"));
    }

    #[test]
    fn router_teammate_not_found() {
        let router = MeshRouter::new();
        assert!(!router.has_teammate("nobody"));
        assert!(router.location("nobody").is_none());
    }

    #[test]
    fn router_teammate_names() {
        let (tx1, _rx1) = mpsc::channel(16);
        let mut router = MeshRouter::new();
        router.add_in_process("alice", tx1, Confidentiality::Public);
        router.add_remote("bob", "http://a2a/bob", "tok", Confidentiality::Public);

        let mut names = router.teammate_names();
        names.sort();
        assert_eq!(names, vec!["alice", "bob"]);
    }

    #[tokio::test]
    async fn router_send_in_process() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut router = MeshRouter::new();
        router.add_in_process("bob", tx, Confidentiality::Public);

        router
            .send("alice", "bob", "hello".into(), DataLabel::TRUSTED_PUBLIC)
            .await
            .unwrap();

        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.sender, "alice");
        assert_eq!(msg.body, "hello");
        assert_eq!(msg.label, DataLabel::TRUSTED_PUBLIC);
    }

    #[tokio::test]
    async fn router_ifc_blocks_write_down() {
        let (tx, _rx) = mpsc::channel(16);
        let mut router = MeshRouter::new();
        router.add_in_process("bob", tx, Confidentiality::Public);

        // Sender has Sensitive data, target has Public clearance => blocked
        let err = router
            .send(
                "alice",
                "bob",
                "secret stuff".into(),
                DataLabel::UNTRUSTED_SENSITIVE,
            )
            .await
            .unwrap_err();

        match err {
            FlowError::IfcViolation { sender, target, .. } => {
                assert_eq!(sender, "alice");
                assert_eq!(target, "bob");
            }
            other => panic!("expected IfcViolation, got: {other}"),
        }
    }

    #[tokio::test]
    async fn router_ifc_allows_write_up() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut router = MeshRouter::new();
        router.add_in_process("bob", tx, Confidentiality::Sensitive);

        // Sender has Public data, target has Sensitive clearance => allowed
        router
            .send(
                "alice",
                "bob",
                "public data".into(),
                DataLabel::TRUSTED_PUBLIC,
            )
            .await
            .unwrap();

        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.body, "public data");
    }

    #[tokio::test]
    async fn router_ifc_allows_same_level() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut router = MeshRouter::new();
        router.add_in_process("bob", tx, Confidentiality::Sensitive);

        // Sender has Sensitive data, target has Sensitive clearance => allowed
        router
            .send(
                "alice",
                "bob",
                "sensitive data".into(),
                DataLabel::UNTRUSTED_SENSITIVE,
            )
            .await
            .unwrap();

        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.body, "sensitive data");
    }

    #[tokio::test]
    async fn router_send_to_unknown_teammate() {
        let router = MeshRouter::new();

        let err = router
            .send("alice", "nobody", "hello".into(), DataLabel::TRUSTED_PUBLIC)
            .await
            .unwrap_err();

        match err {
            FlowError::TeammateNotFound(name) => assert_eq!(name, "nobody"),
            other => panic!("expected TeammateNotFound, got: {other}"),
        }
    }

    #[tokio::test]
    async fn router_mailbox_full() {
        let (tx, _rx) = mpsc::channel(1);
        let mut router = MeshRouter::new();
        router.add_in_process("bob", tx, Confidentiality::Public);

        // First message succeeds
        router
            .send("alice", "bob", "first".into(), DataLabel::TRUSTED_PUBLIC)
            .await
            .unwrap();

        // Second message fails (channel full)
        let err = router
            .send("alice", "bob", "second".into(), DataLabel::TRUSTED_PUBLIC)
            .await
            .unwrap_err();

        match err {
            FlowError::MailboxFull(name) => assert_eq!(name, "bob"),
            other => panic!("expected MailboxFull, got: {other}"),
        }
    }

    #[test]
    fn router_set_clearance() {
        let (tx, _rx) = mpsc::channel(16);
        let mut router = MeshRouter::new();
        router.add_in_process("bob", tx, Confidentiality::Public);

        // Initially Public
        assert_eq!(router.clearances.get("bob"), Some(&Confidentiality::Public));

        router.set_clearance("bob", Confidentiality::Sensitive);
        assert_eq!(
            router.clearances.get("bob"),
            Some(&Confidentiality::Sensitive)
        );
    }

    #[test]
    fn router_routing_decision() {
        let (tx, _rx) = mpsc::channel(16);
        let mut router = MeshRouter::new();
        router.add_in_process("local_agent", tx, Confidentiality::Public);
        router.add_remote(
            "remote_agent",
            "http://a2a/remote",
            "tok",
            Confidentiality::Public,
        );

        // Verify routing decisions
        assert!(router.is_in_process("local_agent"));
        assert!(!router.is_remote("local_agent"));
        assert!(router.is_remote("remote_agent"));
        assert!(!router.is_in_process("remote_agent"));
        assert!(!router.has_teammate("nonexistent"));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use smgglrs_protocol::label::{Confidentiality, DataLabel, Integrity};

    fn arbitrary_confidentiality() -> Confidentiality {
        match kani::any::<u8>() % 4 {
            0 => Confidentiality::Public,
            1 => Confidentiality::Sensitive,
            2 => Confidentiality::Pii,
            _ => Confidentiality::Secret,
        }
    }

    fn arbitrary_label() -> DataLabel {
        DataLabel {
            integrity: if kani::any::<bool>() {
                Integrity::Trusted
            } else {
                Integrity::Untrusted
            },
            confidentiality: arbitrary_confidentiality(),
        }
    }

    #[kani::proof]
    fn default_clearance_is_maximally_restrictive() {
        let router = MeshRouter::new();
        let clearance = router.resolve_clearance("unknown_agent");
        assert_eq!(clearance, Confidentiality::Public);
        // Public is the lowest level — Sensitive/PII/Secret data cannot write down to it
        let sensitive_label = DataLabel {
            integrity: Integrity::Trusted,
            confidentiality: Confidentiality::Sensitive,
        };
        assert!(!sensitive_label.can_write_to(clearance));
    }

    #[kani::proof]
    fn ifc_check_consistent_with_can_write_to() {
        let label = arbitrary_label();
        let clearance = arbitrary_confidentiality();
        let allowed = label.can_write_to(clearance);
        // The mesh send() blocks iff can_write_to returns false
        // This proves the IFC gate is exactly the BLP *-property
        assert_eq!(allowed, label.confidentiality <= clearance);
    }
}
