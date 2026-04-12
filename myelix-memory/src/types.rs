//! Shared types for agent memory.

use serde::{Deserialize, Serialize};

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
}

/// Category of a knowledge memory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryType {
    User,
    Project,
    Feedback,
    Reference,
}

impl MemoryType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::User => "user",
            Self::Project => "project",
            Self::Feedback => "feedback",
            Self::Reference => "reference",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, crate::error::MemoryError> {
        match s {
            "user" => Ok(Self::User),
            "project" => Ok(Self::Project),
            "feedback" => Ok(Self::Feedback),
            "reference" => Ok(Self::Reference),
            _ => Err(crate::error::MemoryError::InvalidType(s.into())),
        }
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
