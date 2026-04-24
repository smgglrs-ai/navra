//! MCP tools for persistent knowledge memory.
//!
//! Exposes the knowledge store to agents via three tools:
//! - `memory_store`: persist a knowledge entry
//! - `memory_query`: full-text search over stored knowledge
//! - `memory_forget`: archive (delete) an entry by ID

use smgglrs_core::protocol::{ToolDefinition, ToolInputSchema};
use std::collections::HashMap;

pub fn memory_store_def() -> ToolDefinition {
    ToolDefinition {
        name: "memory_store".to_string(),
        description: Some(
            "Store a knowledge entry in persistent memory. Entries are \
             categorized by kind and searchable by title, content, and tags. \
             If an entry with the same ID already exists, it is updated."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("kind".to_string(), serde_json::json!({
                    "type": "string",
                    "enum": ["fact", "event", "instruction", "insight"],
                    "description": "Category of knowledge entry"
                })),
                ("title".to_string(), serde_json::json!({
                    "type": "string",
                    "description": "Short title for the entry"
                })),
                ("content".to_string(), serde_json::json!({
                    "type": "string",
                    "description": "Full content of the knowledge entry"
                })),
                ("tags".to_string(), serde_json::json!({
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional tags for categorization"
                })),
            ])),
            required: Some(vec![
                "kind".to_string(),
                "title".to_string(),
                "content".to_string(),
            ]),
        },
    }
}

pub fn memory_query_def() -> ToolDefinition {
    ToolDefinition {
        name: "memory_query".to_string(),
        description: Some(
            "Search stored knowledge entries using full-text search. \
             Returns matching entries ranked by relevance. Optionally \
             filter by kind and limit the number of results."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("query".to_string(), serde_json::json!({
                    "type": "string",
                    "description": "Search query text"
                })),
                ("kind".to_string(), serde_json::json!({
                    "type": "string",
                    "enum": ["fact", "event", "instruction", "insight"],
                    "description": "Optional: filter results by kind"
                })),
                ("limit".to_string(), serde_json::json!({
                    "type": "integer",
                    "description": "Maximum number of results (default: 10)"
                })),
            ])),
            required: Some(vec!["query".to_string()]),
        },
    }
}

pub fn memory_forget_def() -> ToolDefinition {
    ToolDefinition {
        name: "memory_forget".to_string(),
        description: Some(
            "Delete a knowledge entry from persistent memory by its ID."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("id".to_string(), serde_json::json!({
                    "type": "string",
                    "description": "ID of the entry to delete"
                })),
            ])),
            required: Some(vec!["id".to_string()]),
        },
    }
}
