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

    /// Create a new distilled entry, computing the content_key automatically.
    pub fn new(
        kind: MemoryType,
        title: String,
        content: String,
        tags: Vec<String>,
        confidence: f64,
        source_session: String,
    ) -> Self {
        let content_key = Self::compute_key(&kind, &title);
        Self {
            kind,
            title,
            content,
            tags,
            confidence,
            source_session,
            content_key,
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
}
