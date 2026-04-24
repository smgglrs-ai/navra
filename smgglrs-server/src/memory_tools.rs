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

// --- Handler functions ---

/// Handle memory_store tool call.
pub async fn handle_memory_store(
    args: serde_json::Value,
    ks: std::sync::Arc<std::sync::Mutex<smgglrs_memory::KnowledgeStore>>,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let kind_str = match args.get("kind").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return CallToolResult::error("Missing required parameter: kind"),
    };
    let title = match args.get("title").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return CallToolResult::error("Missing required parameter: title"),
    };
    let content = match args.get("content").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return CallToolResult::error("Missing required parameter: content"),
    };

    let memory_type = match smgglrs_memory::MemoryType::from_str(kind_str) {
        Ok(mt) => mt,
        Err(_) => return CallToolResult::error(
            format!("Invalid kind: {kind_str}. Use: fact, event, instruction, insight")
        ),
    };

    let tags: Vec<String> = args
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let id = uuid::Uuid::new_v4().to_string();
    let entry = smgglrs_memory::MemoryEntry {
        id: id.clone(),
        memory_type,
        title: title.to_string(),
        content: content.to_string(),
        tags,
        created_at: now,
        updated_at: None,
    };

    let store = ks.lock().unwrap_or_else(|e| e.into_inner());
    match store.store(&entry) {
        Ok(()) => CallToolResult::text(
            serde_json::json!({"id": id, "status": "stored"}).to_string()
        ),
        Err(e) => CallToolResult::error(format!("Failed to store entry: {e}")),
    }
}

/// Handle memory_query tool call.
pub async fn handle_memory_query(
    args: serde_json::Value,
    ks: std::sync::Arc<std::sync::Mutex<smgglrs_memory::KnowledgeStore>>,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) => q,
        None => return CallToolResult::error("Missing required parameter: query"),
    };

    let limit = args.get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10) as usize;

    let kind_filter = args.get("kind")
        .and_then(|v| v.as_str())
        .and_then(|k| smgglrs_memory::MemoryType::from_str(k).ok());

    let store = ks.lock().unwrap_or_else(|e| e.into_inner());
    match store.search(query) {
        Ok(entries) => {
            let mut results: Vec<&smgglrs_memory::MemoryEntry> = entries.iter()
                .filter(|e| {
                    kind_filter.as_ref().map_or(true, |k| e.memory_type == *k)
                })
                .collect();
            results.truncate(limit);

            let output: Vec<serde_json::Value> = results.iter().map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "kind": e.memory_type.as_str(),
                    "title": e.title,
                    "content": e.content,
                    "tags": e.tags,
                    "created_at": e.created_at,
                })
            }).collect();

            CallToolResult::text(
                serde_json::to_string_pretty(&output).unwrap_or_default()
            )
        }
        Err(e) => CallToolResult::error(format!("Search failed: {e}")),
    }
}

/// Handle memory_forget tool call.
pub async fn handle_memory_forget(
    args: serde_json::Value,
    ks: std::sync::Arc<std::sync::Mutex<smgglrs_memory::KnowledgeStore>>,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let id = match args.get("id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error("Missing required parameter: id"),
    };

    let store = ks.lock().unwrap_or_else(|e| e.into_inner());
    match store.delete(id) {
        Ok(true) => CallToolResult::text(
            serde_json::json!({"id": id, "status": "deleted"}).to_string()
        ),
        Ok(false) => CallToolResult::error(format!("No entry found with id: {id}")),
        Err(e) => CallToolResult::error(format!("Failed to delete entry: {e}")),
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
