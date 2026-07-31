//! Shared types for agent memory.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Message role in a conversation turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

impl Role {
    pub fn as_str(&self) -> &str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "system" => Self::System,
            "user" => Self::User,
            "assistant" => Self::Assistant,
            "tool" => Self::Tool,
            _ => Self::User,
        }
    }
}

/// A single message in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
    pub timestamp: i64,
    pub metadata: Option<String>,
}

/// A conversation turn (user request + agent response + tool calls).
#[derive(Debug, Clone)]
pub struct Turn {
    pub turn_id: String,
    pub session_id: String,
    pub agent: String,
    pub messages: Vec<Message>,
    pub created_at: i64,
    /// Fork this turn belongs to (None = main timeline).
    pub fork_id: Option<String>,
    /// The fork this was branched from (None = root/main).
    pub parent_fork: Option<String>,
}

/// Strategy for merging a fork back into the main timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeStrategy {
    /// Add all fork turns after current main timeline turns.
    Append,
    /// Replace main timeline turns from the fork point onward.
    Replace,
    /// Summarize the fork into a single turn and append it.
    Summarize,
}

/// Category of a knowledge memory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryType {
    Fact,
    Event,
    Instruction,
    Insight,
    User,
    Project,
}

impl MemoryType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Fact => "fact",
            Self::Event => "event",
            Self::Instruction => "instruction",
            Self::Insight => "insight",
            Self::User => "user",
            Self::Project => "project",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, crate::error::MemoryError> {
        match s {
            "fact" => Ok(Self::Fact),
            "event" => Ok(Self::Event),
            "instruction" => Ok(Self::Instruction),
            "insight" => Ok(Self::Insight),
            "user" => Ok(Self::User),
            "project" => Ok(Self::Project),
            // Backward compatibility: old variant names map to new ones
            "reference" => Ok(Self::Fact),
            "feedback" => Ok(Self::Insight),
            _ => Err(crate::error::MemoryError::InvalidType(s.into())),
        }
    }
}

/// Scoping dimensions for memory isolation.
///
/// When all fields are `None`, the operation targets global (unscoped) memory.
/// Each non-`None` field narrows the scope: entity_id restricts to a specific
/// user/identity, process_id to a workflow execution, session_id to a session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryScope {
    /// Scope to a specific user or human identity.
    pub entity_id: Option<String>,
    /// Scope to a flow or workflow execution.
    pub process_id: Option<String>,
    /// Scope to a session.
    pub session_id: Option<String>,
}

impl MemoryScope {
    /// Returns true if all scope fields are None (global scope).
    pub fn is_global(&self) -> bool {
        self.entity_id.is_none() && self.process_id.is_none() && self.session_id.is_none()
    }
}

/// A persistent knowledge memory entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub id: String,
    pub memory_type: MemoryType,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: Option<i64>,
}

/// A distilled memory entry produced by the distillation pipeline.
///
/// Content-addressed via `content_key` (SHA-256 of kind + title).
/// Entries with the same content_key supersede each other, incrementing
/// the version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistilledEntry {
    pub kind: MemoryType,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub confidence: f64,
    pub source_session: String,
    pub content_key: String,
    #[serde(default)]
    pub importance: f64,
}

impl DistilledEntry {
    /// Compute content_key as SHA-256 hex of (kind + "|" + title).
    pub fn compute_key(kind: &MemoryType, title: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(kind.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(title.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Heuristic importance based on memory type and confidence.
    ///
    /// Higher-value memory types (insights, instructions) get higher base
    /// importance so they decay slower. Confidence scales the result.
    pub fn importance_heuristic(kind: &MemoryType, confidence: f64) -> f64 {
        let base = match kind {
            MemoryType::Insight => 0.8,
            MemoryType::Instruction => 0.7,
            MemoryType::User | MemoryType::Project => 0.6,
            MemoryType::Fact => 0.5,
            MemoryType::Event => 0.3,
        };
        base * confidence.clamp(0.0, 1.0)
    }

    /// Create a new distilled entry, computing the content_key and
    /// importance automatically.
    pub fn new(
        kind: MemoryType,
        title: String,
        content: String,
        tags: Vec<String>,
        confidence: f64,
        source_session: String,
    ) -> Self {
        let content_key = Self::compute_key(&kind, &title);
        let importance = Self::importance_heuristic(&kind, confidence);
        Self {
            kind,
            title,
            content,
            tags,
            confidence,
            source_session,
            content_key,
            importance,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_type_backward_compat_reference() {
        let mt = MemoryType::from_str("reference").unwrap();
        assert_eq!(mt, MemoryType::Fact);
    }

    #[test]
    fn memory_type_backward_compat_feedback() {
        let mt = MemoryType::from_str("feedback").unwrap();
        assert_eq!(mt, MemoryType::Insight);
    }

    #[test]
    fn memory_type_new_variants_parse() {
        assert_eq!(MemoryType::from_str("fact").unwrap(), MemoryType::Fact);
        assert_eq!(MemoryType::from_str("event").unwrap(), MemoryType::Event);
        assert_eq!(
            MemoryType::from_str("instruction").unwrap(),
            MemoryType::Instruction
        );
        assert_eq!(
            MemoryType::from_str("insight").unwrap(),
            MemoryType::Insight
        );
        assert_eq!(MemoryType::from_str("user").unwrap(), MemoryType::User);
        assert_eq!(
            MemoryType::from_str("project").unwrap(),
            MemoryType::Project
        );
    }

    #[test]
    fn memory_type_invalid_returns_error() {
        assert!(MemoryType::from_str("unknown").is_err());
    }

    #[test]
    fn distilled_entry_serialization_roundtrip() {
        let entry = DistilledEntry::new(
            MemoryType::Insight,
            "Test insight".to_string(),
            "Some content".to_string(),
            vec!["tag1".to_string(), "tag2".to_string()],
            0.85,
            "session-abc".to_string(),
        );

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: DistilledEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.kind, entry.kind);
        assert_eq!(deserialized.title, entry.title);
        assert_eq!(deserialized.content, entry.content);
        assert_eq!(deserialized.tags, entry.tags);
        assert!((deserialized.confidence - entry.confidence).abs() < f64::EPSILON);
        assert_eq!(deserialized.source_session, entry.source_session);
        assert_eq!(deserialized.content_key, entry.content_key);
    }

    #[test]
    fn content_key_deterministic() {
        let key1 = DistilledEntry::compute_key(&MemoryType::Fact, "hello");
        let key2 = DistilledEntry::compute_key(&MemoryType::Fact, "hello");
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn content_key_differs_by_kind() {
        let key1 = DistilledEntry::compute_key(&MemoryType::Fact, "hello");
        let key2 = DistilledEntry::compute_key(&MemoryType::Event, "hello");
        assert_ne!(key1, key2);
    }

    #[test]
    fn importance_heuristic_bounded() {
        for kind in [
            MemoryType::Fact,
            MemoryType::Event,
            MemoryType::Instruction,
            MemoryType::Insight,
            MemoryType::User,
            MemoryType::Project,
        ] {
            for conf in [0.0, 0.5, 1.0, 1.5, -0.1] {
                let imp = DistilledEntry::importance_heuristic(&kind, conf);
                assert!((0.0..=1.0).contains(&imp), "{kind:?} conf={conf} → {imp}");
            }
        }
    }

    #[test]
    fn importance_heuristic_monotonic_in_confidence() {
        for kind in [
            MemoryType::Fact,
            MemoryType::Event,
            MemoryType::Instruction,
            MemoryType::Insight,
            MemoryType::User,
            MemoryType::Project,
        ] {
            let low = DistilledEntry::importance_heuristic(&kind, 0.3);
            let high = DistilledEntry::importance_heuristic(&kind, 0.9);
            assert!(high >= low, "{kind:?}: conf=0.9 ({high}) < conf=0.3 ({low})");
        }
    }

    #[test]
    fn importance_heuristic_type_ordering() {
        let conf = 1.0;
        let insight = DistilledEntry::importance_heuristic(&MemoryType::Insight, conf);
        let instruction = DistilledEntry::importance_heuristic(&MemoryType::Instruction, conf);
        let fact = DistilledEntry::importance_heuristic(&MemoryType::Fact, conf);
        let event = DistilledEntry::importance_heuristic(&MemoryType::Event, conf);
        assert!(insight > instruction, "insight > instruction");
        assert!(instruction > fact, "instruction > fact");
        assert!(fact > event, "fact > event");
    }

    #[test]
    fn new_auto_assigns_importance() {
        let entry = DistilledEntry::new(
            MemoryType::Insight,
            "test".to_string(),
            "content".to_string(),
            vec![],
            0.9,
            "s1".to_string(),
        );
        assert!(entry.importance > 0.0, "importance should be auto-assigned");
        assert!(
            (entry.importance - 0.8 * 0.9).abs() < f64::EPSILON,
            "Insight at 0.9 confidence should be 0.72, got {}",
            entry.importance
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn importance_heuristic_always_bounded() {
        let kind_idx: u8 = kani::any();
        kani::assume(kind_idx < 6);
        let kind = match kind_idx {
            0 => MemoryType::Fact,
            1 => MemoryType::Event,
            2 => MemoryType::Instruction,
            3 => MemoryType::Insight,
            4 => MemoryType::User,
            _ => MemoryType::Project,
        };
        let confidence: u16 = kani::any();
        kani::assume(confidence <= 1000);
        let conf = confidence as f64 / 1000.0;
        let result = DistilledEntry::importance_heuristic(&kind, conf);
        assert!(result >= 0.0, "importance must be non-negative");
        assert!(result <= 1.0, "importance must not exceed 1.0");
    }

    #[kani::proof]
    fn importance_heuristic_monotonic_confidence() {
        let kind_idx: u8 = kani::any();
        kani::assume(kind_idx < 6);
        let kind = match kind_idx {
            0 => MemoryType::Fact,
            1 => MemoryType::Event,
            2 => MemoryType::Instruction,
            3 => MemoryType::Insight,
            4 => MemoryType::User,
            _ => MemoryType::Project,
        };
        let c1: u16 = kani::any();
        let c2: u16 = kani::any();
        kani::assume(c1 <= 1000);
        kani::assume(c2 <= 1000);
        kani::assume(c2 >= c1);
        let r1 = DistilledEntry::importance_heuristic(&kind, c1 as f64 / 1000.0);
        let r2 = DistilledEntry::importance_heuristic(&kind, c2 as f64 / 1000.0);
        assert!(r2 >= r1, "higher confidence must yield >= importance");
    }
}
