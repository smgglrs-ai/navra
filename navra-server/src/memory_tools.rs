//! MCP tools for persistent knowledge memory.
//!
//! Exposes the knowledge store to agents via three tools:
//! - `memory_store`: persist a knowledge entry
//! - `memory_query`: full-text search over stored knowledge
//! - `memory_forget`: archive (delete) an entry by ID
//!
//! PII filtering is applied before storage using the safety filter
//! pipeline from navra-security. The filter profile is controlled
//! by `[modules.memory] pii_filter` in config (default: "standard").

use navra_core::protocol::ToolDefinition;
use navra_core::safety::{FilterContext, FilterPipeline, PiiMetrics};
use navra_protocol::compat::{CallToolResultExt, tool_input_schema};
use navra_rag::ChunkStore;
use std::collections::HashMap;
use std::sync::Arc;

/// Type alias for an optional, shared PII filter pipeline.
pub type PiiSanitizer = Option<Arc<FilterPipeline>>;

/// Sanitize content for storage by running it through the PII filter pipeline.
///
/// Returns the original content if no pipeline is configured.
pub async fn sanitize_for_storage(content: &str, sanitizer: &PiiSanitizer) -> String {
    let pipeline = match sanitizer {
        Some(p) => p,
        None => return content.to_string(),
    };

    let ctx = FilterContext {
        agent_name: "memory",
        operation: "store",
        path: None,
    };

    match pipeline.process_inbound(content, &ctx).await {
        Ok(sanitized) => sanitized,
        Err(reason) => {
            tracing::warn!(reason = %reason, "PII filter blocked memory content, storing redacted placeholder");
            "[content blocked by PII filter]".to_string()
        }
    }
}

/// Synchronous PII sanitization for contexts where async is not available.
///
/// Uses the sync-only filter path (regex filters, no model filters).
pub fn sanitize_for_storage_sync(content: &str, sanitizer: &PiiSanitizer) -> String {
    let pipeline = match sanitizer {
        Some(p) => p,
        None => return content.to_string(),
    };

    let ctx = FilterContext {
        agent_name: "memory",
        operation: "store",
        path: None,
    };

    match pipeline.process(content, &ctx) {
        Ok(sanitized) => sanitized,
        Err(reason) => {
            tracing::warn!(reason = %reason, "PII filter blocked content, using redacted placeholder");
            "[content blocked by PII filter]".to_string()
        }
    }
}

pub fn memory_store_def() -> ToolDefinition {
    ToolDefinition::new(
        "memory_store",
        "Store a knowledge entry in persistent memory. Entries are \
         categorized by kind and searchable by title, content, and tags. \
         If an entry with the same ID already exists, it is updated.",
        tool_input_schema(
            Some(HashMap::from([
                (
                    "kind".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "enum": ["fact", "event", "instruction", "insight"],
                        "description": "Category of knowledge entry"
                    }),
                ),
                (
                    "title".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Short title for the entry"
                    }),
                ),
                (
                    "content".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Full content of the knowledge entry"
                    }),
                ),
                (
                    "tags".to_string(),
                    serde_json::json!({
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional tags for categorization"
                    }),
                ),
                (
                    "entity_id".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Optional: scope to a specific user/entity identity"
                    }),
                ),
                (
                    "process_id".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Optional: scope to a flow/workflow execution"
                    }),
                ),
                (
                    "session_id".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Optional: scope to a session"
                    }),
                ),
                (
                    "ttl_secs".to_string(),
                    serde_json::json!({
                        "type": "integer",
                        "description": "Optional: time-to-live in seconds (entry expires after this duration)"
                    }),
                ),
            ])),
            Some(vec![
                "kind".to_string(),
                "title".to_string(),
                "content".to_string(),
            ]),
        ),
    )
}

pub fn memory_query_def() -> ToolDefinition {
    ToolDefinition::new(
        "memory_query",
        "Search stored knowledge entries using full-text search. \
         Returns matching entries ranked by relevance. Optionally \
         filter by kind and limit the number of results.",
        tool_input_schema(
            Some(HashMap::from([
                (
                    "query".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Search query text"
                    }),
                ),
                (
                    "kind".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "enum": ["fact", "event", "instruction", "insight"],
                        "description": "Optional: filter results by kind"
                    }),
                ),
                (
                    "limit".to_string(),
                    serde_json::json!({
                        "type": "integer",
                        "description": "Maximum number of results (default: 10)"
                    }),
                ),
                (
                    "entity_id".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Optional: filter to entries scoped to this user/entity"
                    }),
                ),
                (
                    "process_id".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Optional: filter to entries scoped to this flow/workflow"
                    }),
                ),
                (
                    "session_id".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Optional: filter to entries scoped to this session"
                    }),
                ),
            ])),
            Some(vec!["query".to_string()]),
        ),
    )
}

// --- Handler functions ---

/// Handle memory_store tool call.
///
/// When a PII sanitizer is provided, both the title and content are
/// filtered before being written to SQLite.
pub async fn handle_memory_store(
    args: serde_json::Value,
    ks: std::sync::Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>,
    sanitizer: PiiSanitizer,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let kind_str = match args.get("kind").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return CallToolResult::error_msg("Missing required parameter: kind"),
    };
    let title = match args.get("title").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return CallToolResult::error_msg("Missing required parameter: title"),
    };
    let content = match args.get("content").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return CallToolResult::error_msg("Missing required parameter: content"),
    };

    let memory_type = match navra_memory::MemoryType::from_str(kind_str) {
        Ok(mt) => mt,
        Err(_) => {
            return CallToolResult::error_msg(format!(
                "Invalid kind: {kind_str}. Use: fact, event, instruction, insight"
            ));
        }
    };

    let tags: Vec<String> = args
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Detect PII in original content before sanitization
    let has_pii = content_has_pii(content, &sanitizer) || content_has_pii(title, &sanitizer);

    // Sanitize title and content through PII filter before storage
    let sanitized_title = sanitize_for_storage(title, &sanitizer).await;
    let sanitized_content = sanitize_for_storage(content, &sanitizer).await;

    // Extract scope parameters
    let scope = navra_memory::MemoryScope {
        entity_id: args
            .get("entity_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        process_id: args
            .get("process_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        session_id: args
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(String::from),
    };
    let ttl_secs = args.get("ttl_secs").and_then(|v| v.as_u64());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let id = uuid::Uuid::new_v4().to_string();
    let entry = navra_memory::MemoryEntry {
        id: id.clone(),
        memory_type,
        title: sanitized_title,
        content: sanitized_content,
        tags,
        created_at: now,
        updated_at: None,
    };

    let store = ks.lock().unwrap_or_else(|e| e.into_inner());

    // Use scoped storage if any scope or TTL is provided, otherwise preserve
    // backward-compatible path with PII flagging.
    let result = if !scope.is_global() || ttl_secs.is_some() {
        let valid_until = ttl_secs.map(|ttl| now + ttl as i64);
        // Store with scope first, then set PII flag if needed
        store
            .store_scoped(&entry, &scope, valid_until)
            .and_then(|()| {
                if has_pii {
                    store.set_pii_flag(&id, true)?;
                }
                Ok(())
            })
    } else {
        store.store_with_pii(&entry, has_pii)
    };

    match result {
        Ok(()) => CallToolResult::text(
            serde_json::json!({"id": id, "status": "stored", "has_pii": has_pii}).to_string(),
        ),
        Err(e) => CallToolResult::error_msg(format!("Failed to store entry: {e}")),
    }
}

/// Handle memory_query tool call.
pub async fn handle_memory_query(
    args: serde_json::Value,
    ks: std::sync::Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) => q,
        None => return CallToolResult::error_msg("Missing required parameter: query"),
    };

    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;

    let kind_filter = args
        .get("kind")
        .and_then(|v| v.as_str())
        .and_then(|k| navra_memory::MemoryType::from_str(k).ok());

    // Extract scope parameters
    let scope = navra_memory::MemoryScope {
        entity_id: args
            .get("entity_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        process_id: args
            .get("process_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        session_id: args
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(String::from),
    };

    let store = ks.lock().unwrap_or_else(|e| e.into_inner());

    // Use scoped search if any scope is provided, otherwise use global search
    let search_result = if !scope.is_global() {
        store.search_scoped(query, &scope, 100)
    } else {
        store.search(query)
    };

    match search_result {
        Ok(entries) => {
            let mut results: Vec<&navra_memory::MemoryEntry> = entries
                .iter()
                .filter(|e| kind_filter.as_ref().is_none_or(|k| e.memory_type == *k))
                .collect();
            results.truncate(limit);

            let output: Vec<serde_json::Value> = results
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "kind": e.memory_type.as_str(),
                        "title": e.title,
                        "content": e.content,
                        "tags": e.tags,
                        "created_at": e.created_at,
                    })
                })
                .collect();

            CallToolResult::text(serde_json::to_string_pretty(&output).unwrap_or_default())
        }
        Err(e) => CallToolResult::error_msg(format!("Search failed: {e}")),
    }
}

/// Handle memory_forget tool call.
///
/// When a `ChunkStore` is provided, also deletes any embedding vectors
/// associated with the entry's ID to prevent PII leakage through
/// vector search.
pub async fn handle_memory_forget(
    args: serde_json::Value,
    ks: std::sync::Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>,
    chunk_store: Option<Arc<ChunkStore>>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let id = match args.get("id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing required parameter: id"),
    };

    let store = ks.lock().unwrap_or_else(|e| e.into_inner());
    match store.delete(id) {
        Ok(true) => {
            let chunks_deleted = cascade_delete_source(&chunk_store, id);
            CallToolResult::text(
                serde_json::json!({
                    "id": id,
                    "status": "deleted",
                    "chunks_deleted": chunks_deleted,
                })
                .to_string(),
            )
        }
        Ok(false) => CallToolResult::error_msg(format!("No entry found with id: {id}")),
        Err(e) => CallToolResult::error_msg(format!("Failed to delete entry: {e}")),
    }
}

/// Build a PII sanitizer from a config profile name.
///
/// Returns `None` for "none" (no filtering), wraps a `FilterPipeline`
/// in `Arc` for all other profiles.
pub fn build_pii_sanitizer(profile: &str) -> PiiSanitizer {
    match profile {
        "none" | "" => None,
        _ => Some(Arc::new(navra_core::safety::build_pipeline(profile))),
    }
}

/// Check whether content contains PII by scanning it through the filter pipeline.
///
/// Returns true if any PII findings are detected. Does not modify the content.
pub fn content_has_pii(content: &str, sanitizer: &PiiSanitizer) -> bool {
    let pipeline = match sanitizer {
        Some(p) => p,
        None => return false,
    };

    let ctx = FilterContext {
        agent_name: "memory",
        operation: "scan",
        path: None,
    };

    !pipeline.scan_sync(content, &ctx).is_empty()
}

pub fn memory_purge_pii_def() -> ToolDefinition {
    ToolDefinition::new(
        "memory_purge_pii",
        "Scan stored knowledge entries for PII and either redact or delete them. \
         Supports GDPR compliance by finding and removing personal data from \
         persistent memory. Use action 'redact' to replace PII in-place, or \
         'delete' to remove entries containing PII entirely.",
        tool_input_schema(
            Some(HashMap::from([
                (
                    "action".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "enum": ["redact", "delete"],
                        "description": "Action to take: 'redact' replaces PII in-place, 'delete' removes entries"
                    }),
                ),
                (
                    "kind".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "enum": ["fact", "event", "instruction", "insight"],
                        "description": "Optional: filter entries by kind"
                    }),
                ),
                (
                    "query".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Optional: scope the scan to entries matching this search query"
                    }),
                ),
            ])),
            Some(vec!["action".to_string()]),
        ),
    )
}

/// Handle memory_purge_pii tool call.
///
/// When `action` is `"delete"` and a `ChunkStore` is provided, also
/// deletes embedding vectors associated with each purged entry to
/// prevent PII leakage through vector search.
pub async fn handle_memory_purge_pii(
    args: serde_json::Value,
    ks: std::sync::Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>,
    sanitizer: PiiSanitizer,
    chunk_store: Option<Arc<ChunkStore>>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let action = match args.get("action").and_then(|v| v.as_str()) {
        Some(a @ ("redact" | "delete")) => a.to_string(),
        _ => {
            return CallToolResult::error_msg(
                "Missing or invalid parameter: action (must be 'redact' or 'delete')",
            );
        }
    };

    let kind_filter = args
        .get("kind")
        .and_then(|v| v.as_str())
        .and_then(|k| navra_memory::MemoryType::from_str(k).ok());

    let query_filter = args.get("query").and_then(|v| v.as_str()).map(String::from);

    let store = ks.lock().unwrap_or_else(|e| e.into_inner());

    // Get candidate entries
    let entries = if let Some(ref q) = query_filter {
        match store.search(q) {
            Ok(e) => e,
            Err(e) => return CallToolResult::error_msg(format!("Search failed: {e}")),
        }
    } else {
        match store.list(kind_filter.clone()) {
            Ok(e) => e,
            Err(e) => return CallToolResult::error_msg(format!("List failed: {e}")),
        }
    };

    // Apply kind filter if search was used (search doesn't filter by kind)
    let entries: Vec<_> = if query_filter.is_some() {
        entries
            .into_iter()
            .filter(|e| kind_filter.as_ref().is_none_or(|k| e.memory_type == *k))
            .collect()
    } else {
        entries
    };

    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(1000) as usize;

    let total_candidates = entries.len();
    let entries: Vec<_> = entries.into_iter().take(limit).collect();
    let scanned = entries.len();
    let mut affected = 0usize;
    let mut chunks_deleted = 0usize;

    for entry in &entries {
        let has_pii = content_has_pii(&entry.content, &sanitizer)
            || content_has_pii(&entry.title, &sanitizer);

        if !has_pii {
            continue;
        }

        affected += 1;

        match action.as_str() {
            "delete" => {
                let _ = store.delete(&entry.id);
                chunks_deleted += cascade_delete_source(&chunk_store, &entry.id);
            }
            "redact" => {
                let redacted_title = sanitize_for_storage_sync(&entry.title, &sanitizer);
                let redacted_content = sanitize_for_storage_sync(&entry.content, &sanitizer);
                let _ = store.update_content(&entry.id, &redacted_title, &redacted_content);
                let _ = store.set_pii_flag(&entry.id, false);
            }
            _ => unreachable!(),
        }
    }

    let mut result = serde_json::json!({
        "scanned": scanned,
        "affected": affected,
        "action": action,
        "chunks_deleted": chunks_deleted,
    });
    if total_candidates > limit {
        result["truncated"] = serde_json::json!(true);
        result["total_candidates"] = serde_json::json!(total_candidates);
    }
    CallToolResult::text(result.to_string())
}

pub fn memory_forget_by_content_def() -> ToolDefinition {
    ToolDefinition::new(
        "memory_forget_by_content",
        "Find and delete all knowledge entries containing specific content. \
         Enables GDPR Article 17 right-to-erasure: 'delete all data related \
         to Jean Dupont'. Set confirm=false for a dry-run preview.",
        tool_input_schema(
            Some(HashMap::from([
                (
                    "query".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Text to search for in stored entries"
                    }),
                ),
                (
                    "confirm".to_string(),
                    serde_json::json!({
                        "type": "boolean",
                        "description": "If true, actually delete matching entries. If false, return a preview (dry run)."
                    }),
                ),
            ])),
            Some(vec!["query".to_string(), "confirm".to_string()]),
        ),
    )
}

/// Handle memory_forget_by_content tool call.
///
/// When `confirm` is true and a `ChunkStore` is provided, also
/// deletes embedding vectors associated with deleted entries and
/// any chunks whose content matches the query string.
pub async fn handle_memory_forget_by_content(
    args: serde_json::Value,
    ks: std::sync::Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>,
    chunk_store: Option<Arc<ChunkStore>>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) => q,
        None => return CallToolResult::error_msg("Missing required parameter: query"),
    };

    let confirm = args
        .get("confirm")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let store = ks.lock().unwrap_or_else(|e| e.into_inner());

    let mut entries = match store.search(query) {
        Ok(e) => e,
        Err(e) => return CallToolResult::error_msg(format!("Search failed: {e}")),
    };
    let total_matches = entries.len();
    entries.truncate(1000);

    if !confirm {
        let preview: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "kind": e.memory_type.as_str(),
                    "title": e.title,
                    "created_at": e.created_at,
                })
            })
            .collect();

        let mut result = serde_json::json!({
            "mode": "dry_run",
            "would_delete": entries.len(),
            "entries": preview,
        });
        if total_matches > 1000 {
            result["truncated"] = serde_json::json!(true);
            result["total_matches"] = serde_json::json!(total_matches);
        }
        return CallToolResult::text(result.to_string());
    }

    // Actually delete
    let mut deleted = 0usize;
    let mut chunks_deleted = 0usize;
    for entry in &entries {
        if let Ok(true) = store.delete(&entry.id) {
            deleted += 1;
            chunks_deleted += cascade_delete_source(&chunk_store, &entry.id);
        }
    }

    // Also delete any chunks whose content matches the query string
    // (catches vectors that may not be linked by source ID).
    chunks_deleted += cascade_delete_content(&chunk_store, query);

    CallToolResult::text(
        serde_json::json!({
            "mode": "confirmed",
            "deleted": deleted,
            "chunks_deleted": chunks_deleted,
        })
        .to_string(),
    )
}

pub fn memory_forget_def() -> ToolDefinition {
    ToolDefinition::new(
        "memory_forget",
        "Delete a knowledge entry from persistent memory by its ID.",
        tool_input_schema(
            Some(HashMap::from([(
                "id".to_string(),
                serde_json::json!({
                    "type": "string",
                    "description": "ID of the entry to delete"
                }),
            )])),
            Some(vec!["id".to_string()]),
        ),
    )
}

/// Cascade-delete chunks by source ID from the chunk store.
///
/// Returns the number of chunks deleted, or 0 if no chunk store is available.
fn cascade_delete_source(chunk_store: &Option<Arc<ChunkStore>>, source_id: &str) -> usize {
    if let Some(cs) = chunk_store {
        match cs.delete_by_source(source_id) {
            Ok(n) => {
                if n > 0 {
                    tracing::debug!(
                        source_id,
                        chunks = n,
                        "Cascade-deleted chunks for forgotten entry"
                    );
                }
                n
            }
            Err(e) => {
                tracing::warn!(source_id, error = %e, "Failed to cascade-delete chunks");
                0
            }
        }
    } else {
        0
    }
}

/// Cascade-delete chunks by content match from the chunk store.
///
/// Returns the number of chunks deleted, or 0 if no chunk store is available.
fn cascade_delete_content(chunk_store: &Option<Arc<ChunkStore>>, query: &str) -> usize {
    if let Some(cs) = chunk_store {
        match cs.delete_by_content_match(query) {
            Ok(n) => {
                if n > 0 {
                    tracing::debug!(query, chunks = n, "Cascade-deleted chunks by content match");
                }
                n
            }
            Err(e) => {
                tracing::warn!(query, error = %e, "Failed to cascade-delete chunks by content");
                0
            }
        }
    } else {
        0
    }
}

// --- pii_report tool ---

pub fn pii_report_def() -> ToolDefinition {
    ToolDefinition::new(
        "pii_report",
        "Generate a GDPR compliance report showing PII detection metrics, \
         retention policies, and current state of PII-flagged entries. \
         Provides data needed for Data Protection Impact Assessments \
         (GDPR Article 35).",
        tool_input_schema(Some(HashMap::new()), None),
    )
}

/// Handle pii_report tool call.
pub async fn handle_pii_report(
    _args: serde_json::Value,
    ks: Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>,
    metrics: Option<Arc<PiiMetrics>>,
    retention_days: Option<u32>,
    pii_retention_days: Option<u32>,
    audit_retention_days: Option<u32>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let store = ks.lock().unwrap_or_else(|e| e.into_inner());

    let pii_entry_count = store.count_pii_entries().unwrap_or(0);

    let metrics_snapshot = metrics
        .as_ref()
        .map(|m| {
            let snap = m.snapshot();
            serde_json::json!({
                "total_scans": snap.total_scans,
                "pii_detected": snap.pii_detected,
                "pii_redacted": snap.pii_redacted,
                "pii_blocked": snap.pii_blocked,
                "by_category": snap.by_category,
            })
        })
        .unwrap_or(serde_json::json!("not_configured"));

    let report = serde_json::json!({
        "metrics": metrics_snapshot,
        "knowledge_store": {
            "entries_with_pii": pii_entry_count,
        },
        "retention_policy": {
            "general_ttl_days": retention_days,
            "pii_ttl_days": pii_retention_days.unwrap_or(30),
            "audit_ttl_days": audit_retention_days.unwrap_or(365),
        },
    });

    CallToolResult::text(serde_json::to_string_pretty(&report).unwrap_or_default())
}

// --- memory_consent tool ---

pub fn memory_consent_def() -> ToolDefinition {
    ToolDefinition::new(
        "memory_consent",
        "Set or query the GDPR consent basis for stored knowledge entries. \
         Valid bases: legitimate_interest, consent, legal_obligation, \
         vital_interest, public_task, not_set. Use mode 'set' to assign \
         a basis to an entry, 'get' to query an entry's basis, or 'list' \
         to find all entries with a given basis.",
        tool_input_schema(
            Some(HashMap::from([
                (
                    "mode".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "enum": ["set", "get", "list"],
                        "description": "Operation mode: 'set' assigns a basis, 'get' queries one entry, 'list' filters by basis"
                    }),
                ),
                (
                    "id".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Entry ID (required for 'set' and 'get' modes)"
                    }),
                ),
                (
                    "basis".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "enum": ["legitimate_interest", "consent", "legal_obligation", "vital_interest", "public_task", "not_set"],
                        "description": "Consent basis (required for 'set' mode, used as filter for 'list' mode)"
                    }),
                ),
            ])),
            Some(vec!["mode".to_string()]),
        ),
    )
}

/// Handle memory_consent tool call.
pub async fn handle_memory_consent(
    args: serde_json::Value,
    ks: Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let mode = match args.get("mode").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => return CallToolResult::error_msg("Missing required parameter: mode"),
    };

    let store = ks.lock().unwrap_or_else(|e| e.into_inner());

    match mode {
        "set" => {
            let id = match args.get("id").and_then(|v| v.as_str()) {
                Some(id) => id,
                None => {
                    return CallToolResult::error_msg(
                        "Missing required parameter: id (for 'set' mode)",
                    );
                }
            };
            let basis = match args.get("basis").and_then(|v| v.as_str()) {
                Some(
                    b @ ("legitimate_interest"
                    | "consent"
                    | "legal_obligation"
                    | "vital_interest"
                    | "public_task"
                    | "not_set"),
                ) => b,
                _ => {
                    return CallToolResult::error_msg(
                        "Missing or invalid parameter: basis (must be one of: legitimate_interest, consent, legal_obligation, vital_interest, public_task, not_set)",
                    );
                }
            };

            match store.set_consent_basis(id, basis) {
                Ok(true) => CallToolResult::text(
                    serde_json::json!({"id": id, "consent_basis": basis, "status": "updated"})
                        .to_string(),
                ),
                Ok(false) => CallToolResult::error_msg(format!("No entry found with id: {id}")),
                Err(e) => CallToolResult::error_msg(format!("Failed to set consent basis: {e}")),
            }
        }
        "get" => {
            let id = match args.get("id").and_then(|v| v.as_str()) {
                Some(id) => id,
                None => {
                    return CallToolResult::error_msg(
                        "Missing required parameter: id (for 'get' mode)",
                    );
                }
            };

            match store.get_consent_basis(id) {
                Ok(Some(basis)) => CallToolResult::text(
                    serde_json::json!({"id": id, "consent_basis": basis}).to_string(),
                ),
                Ok(None) => CallToolResult::error_msg(format!("No entry found with id: {id}")),
                Err(e) => CallToolResult::error_msg(format!("Failed to get consent basis: {e}")),
            }
        }
        "list" => {
            let basis = match args.get("basis").and_then(|v| v.as_str()) {
                Some(b) => b,
                None => {
                    return CallToolResult::error_msg(
                        "Missing required parameter: basis (for 'list' mode)",
                    );
                }
            };

            match store.list_by_consent(basis) {
                Ok(entries) => {
                    let output: Vec<serde_json::Value> = entries
                        .iter()
                        .map(|e| {
                            serde_json::json!({
                                "id": e.id,
                                "kind": e.memory_type.as_str(),
                                "title": e.title,
                                "created_at": e.created_at,
                            })
                        })
                        .collect();

                    CallToolResult::text(
                        serde_json::json!({
                            "basis": basis,
                            "count": entries.len(),
                            "entries": output,
                        })
                        .to_string(),
                    )
                }
                Err(e) => CallToolResult::error_msg(format!("Failed to list by consent: {e}")),
            }
        }
        _ => CallToolResult::error_msg(format!(
            "Invalid mode: {mode}. Use 'set', 'get', or 'list'."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_args(content: &str) -> serde_json::Value {
        serde_json::json!({
            "kind": "fact",
            "title": "Test entry",
            "content": content,
        })
    }

    #[tokio::test]
    async fn memory_store_redacts_pii() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        let sanitizer = build_pii_sanitizer("standard");
        let content = "Contact john.doe@example.com or call 555-123-4567";
        let result = handle_memory_store(store_args(content), ks.clone(), sanitizer).await;

        // Should succeed
        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["status"], "stored");

        // Verify stored content has PII redacted
        let store = ks.lock().unwrap();
        let entries = store.list(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].content.contains("[REDACTED:"),
            "Expected PII redaction in stored content, got: {}",
            entries[0].content
        );
        assert!(!entries[0].content.contains("john.doe@example.com"));
    }

    #[tokio::test]
    async fn memory_store_no_filter_preserves_content() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        let sanitizer = build_pii_sanitizer("none");
        let content = "Contact john.doe@example.com or call 555-123-4567";
        handle_memory_store(store_args(content), ks.clone(), sanitizer).await;

        let store = ks.lock().unwrap();
        let entries = store.list(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].content, content);
    }

    #[tokio::test]
    async fn sanitize_for_storage_with_none_passes_through() {
        let result = sanitize_for_storage("hello world", &None).await;
        assert_eq!(result, "hello world");
    }

    #[tokio::test]
    async fn sanitize_for_storage_redacts_email() {
        let sanitizer = build_pii_sanitizer("standard");
        let result = sanitize_for_storage("email: user@example.com", &sanitizer).await;
        assert!(result.contains("[REDACTED:"));
        assert!(!result.contains("user@example.com"));
    }

    #[test]
    fn sanitize_sync_redacts_email() {
        let sanitizer = build_pii_sanitizer("standard");
        let result = sanitize_for_storage_sync("email: user@example.com", &sanitizer);
        assert!(result.contains("[REDACTED:"));
        assert!(!result.contains("user@example.com"));
    }

    #[test]
    fn sanitize_sync_none_passes_through() {
        let result = sanitize_for_storage_sync("hello world", &None);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn build_pii_sanitizer_none_returns_none() {
        assert!(build_pii_sanitizer("none").is_none());
        assert!(build_pii_sanitizer("").is_none());
    }

    #[test]
    fn build_pii_sanitizer_standard_returns_some() {
        assert!(build_pii_sanitizer("standard").is_some());
    }

    #[test]
    fn content_has_pii_detects_email() {
        let sanitizer = build_pii_sanitizer("standard");
        assert!(content_has_pii("email: user@example.com", &sanitizer));
    }

    #[test]
    fn content_has_pii_clean_text() {
        let sanitizer = build_pii_sanitizer("standard");
        assert!(!content_has_pii("This is clean text", &sanitizer));
    }

    #[test]
    fn content_has_pii_none_sanitizer() {
        assert!(!content_has_pii("user@example.com", &None));
    }

    #[tokio::test]
    async fn memory_store_sets_has_pii_flag() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        let sanitizer = build_pii_sanitizer("standard");
        let content = "Contact john.doe@example.com";
        let result = handle_memory_store(store_args(content), ks.clone(), sanitizer).await;

        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["has_pii"], true);

        // Verify the has_pii flag is set in the store
        let store = ks.lock().unwrap();
        let pii_entries = store.list_pii_entries(None).unwrap();
        assert_eq!(pii_entries.len(), 1);
    }

    #[tokio::test]
    async fn memory_purge_pii_redact() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        // Store entry with PII directly (bypassing sanitizer to keep raw PII)
        {
            let store = ks.lock().unwrap();
            let entry = navra_memory::MemoryEntry {
                id: "pii1".to_string(),
                memory_type: navra_memory::MemoryType::Fact,
                title: "Contact info".to_string(),
                content: "Email: user@example.com, phone: 555-123-4567".to_string(),
                tags: vec![],
                created_at: 1000,
                updated_at: None,
            };
            store.store(&entry).unwrap();
        }

        let sanitizer = build_pii_sanitizer("standard");
        let args = serde_json::json!({"action": "redact"});
        let result = handle_memory_purge_pii(args, ks.clone(), sanitizer, None).await;

        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["scanned"], 1);
        assert_eq!(response["affected"], 1);
        assert_eq!(response["action"], "redact");

        // Verify content was redacted
        let store = ks.lock().unwrap();
        let entry = store.get("pii1").unwrap().unwrap();
        assert!(!entry.content.contains("user@example.com"));
        assert!(entry.content.contains("[REDACTED:"));
    }

    #[tokio::test]
    async fn memory_purge_pii_delete() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        // Store entries with and without PII
        {
            let store = ks.lock().unwrap();
            let pii = navra_memory::MemoryEntry {
                id: "pii1".to_string(),
                memory_type: navra_memory::MemoryType::Fact,
                title: "Contact".to_string(),
                content: "Email: user@example.com".to_string(),
                tags: vec![],
                created_at: 1000,
                updated_at: None,
            };
            store.store(&pii).unwrap();

            let clean = navra_memory::MemoryEntry {
                id: "clean1".to_string(),
                memory_type: navra_memory::MemoryType::Fact,
                title: "Clean".to_string(),
                content: "No PII here".to_string(),
                tags: vec![],
                created_at: 1000,
                updated_at: None,
            };
            store.store(&clean).unwrap();
        }

        let sanitizer = build_pii_sanitizer("standard");
        let args = serde_json::json!({"action": "delete"});
        let result = handle_memory_purge_pii(args, ks.clone(), sanitizer, None).await;

        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["scanned"], 2);
        assert_eq!(response["affected"], 1);
        assert_eq!(response["action"], "delete");

        let store = ks.lock().unwrap();
        assert!(store.get("pii1").unwrap().is_none());
        assert!(store.get("clean1").unwrap().is_some());
    }

    #[tokio::test]
    async fn memory_forget_by_content_dry_run() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        {
            let store = ks.lock().unwrap();
            let entry = navra_memory::MemoryEntry {
                id: "e1".to_string(),
                memory_type: navra_memory::MemoryType::Fact,
                title: "Jean info".to_string(),
                content: "Jean Dupont works at ACME".to_string(),
                tags: vec![],
                created_at: 1000,
                updated_at: None,
            };
            store.store(&entry).unwrap();
        }

        let args = serde_json::json!({"query": "Jean", "confirm": false});
        let result = handle_memory_forget_by_content(args, ks.clone(), None).await;

        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["mode"], "dry_run");
        assert_eq!(response["would_delete"], 1);

        // Entry should still exist
        let store = ks.lock().unwrap();
        assert!(store.get("e1").unwrap().is_some());
    }

    #[tokio::test]
    async fn memory_forget_by_content_confirmed() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        {
            let store = ks.lock().unwrap();
            let entry = navra_memory::MemoryEntry {
                id: "e1".to_string(),
                memory_type: navra_memory::MemoryType::Fact,
                title: "Jean info".to_string(),
                content: "Jean Dupont works at ACME".to_string(),
                tags: vec![],
                created_at: 1000,
                updated_at: None,
            };
            store.store(&entry).unwrap();
        }

        let args = serde_json::json!({"query": "Jean", "confirm": true});
        let result = handle_memory_forget_by_content(args, ks.clone(), None).await;

        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["mode"], "confirmed");
        assert_eq!(response["deleted"], 1);

        // Entry should be gone
        let store = ks.lock().unwrap();
        assert!(store.get("e1").unwrap().is_none());
    }

    // --- Cascade deletion tests ---

    use navra_rag::ChunkStore;

    fn test_chunk_store() -> Arc<ChunkStore> {
        Arc::new(ChunkStore::open_memory(4).unwrap())
    }

    fn index_chunks_for_entry(cs: &ChunkStore, entry_id: &str, content: &str) {
        let chunks = vec![navra_rag::chunk::Chunk {
            content: content.to_string(),
            start_byte: 0,
            end_byte: content.len(),
            index: 0,
            breadcrumb: None,
            section_start_byte: None,
            section_end_byte: None,
        }];
        let embeddings = vec![vec![1.0, 0.0, 0.0, 0.0]];
        cs.index_document(entry_id, &chunks, &embeddings).unwrap();
    }

    #[tokio::test]
    async fn memory_forget_cascades_to_chunk_store() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));
        let cs = test_chunk_store();

        // Store a knowledge entry and index chunks with the entry ID as source
        {
            let store = ks.lock().unwrap();
            let entry = navra_memory::MemoryEntry {
                id: "entry1".to_string(),
                memory_type: navra_memory::MemoryType::Fact,
                title: "Test".to_string(),
                content: "Some knowledge".to_string(),
                tags: vec![],
                created_at: 1000,
                updated_at: None,
            };
            store.store(&entry).unwrap();
        }
        index_chunks_for_entry(&cs, "entry1", "Some knowledge content");
        assert_eq!(cs.stats().unwrap().chunk_count, 1);

        // Forget the entry
        let args = serde_json::json!({"id": "entry1"});
        let result = handle_memory_forget(args, ks.clone(), Some(Arc::clone(&cs))).await;

        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["status"], "deleted");
        assert_eq!(response["chunks_deleted"], 1);

        // Chunks should be gone
        assert_eq!(cs.stats().unwrap().chunk_count, 0);
    }

    #[tokio::test]
    async fn memory_forget_no_chunk_store_still_works() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        {
            let store = ks.lock().unwrap();
            let entry = navra_memory::MemoryEntry {
                id: "entry1".to_string(),
                memory_type: navra_memory::MemoryType::Fact,
                title: "Test".to_string(),
                content: "Content".to_string(),
                tags: vec![],
                created_at: 1000,
                updated_at: None,
            };
            store.store(&entry).unwrap();
        }

        let args = serde_json::json!({"id": "entry1"});
        let result = handle_memory_forget(args, ks.clone(), None).await;

        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["status"], "deleted");
        assert_eq!(response["chunks_deleted"], 0);
    }

    #[tokio::test]
    async fn memory_purge_pii_delete_cascades_to_chunk_store() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));
        let cs = test_chunk_store();

        // Store entry with PII and index chunks
        {
            let store = ks.lock().unwrap();
            let pii = navra_memory::MemoryEntry {
                id: "pii1".to_string(),
                memory_type: navra_memory::MemoryType::Fact,
                title: "Contact".to_string(),
                content: "Email: user@example.com".to_string(),
                tags: vec![],
                created_at: 1000,
                updated_at: None,
            };
            store.store(&pii).unwrap();
        }
        index_chunks_for_entry(&cs, "pii1", "Email: user@example.com");
        assert_eq!(cs.stats().unwrap().chunk_count, 1);

        let sanitizer = build_pii_sanitizer("standard");
        let args = serde_json::json!({"action": "delete"});
        let result =
            handle_memory_purge_pii(args, ks.clone(), sanitizer, Some(Arc::clone(&cs))).await;

        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["affected"], 1);
        assert_eq!(response["chunks_deleted"], 1);

        // Chunks should be gone
        assert_eq!(cs.stats().unwrap().chunk_count, 0);
    }

    #[tokio::test]
    async fn memory_forget_by_content_cascades_to_chunk_store() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));
        let cs = test_chunk_store();

        // Store entry and index chunks
        {
            let store = ks.lock().unwrap();
            let entry = navra_memory::MemoryEntry {
                id: "e1".to_string(),
                memory_type: navra_memory::MemoryType::Fact,
                title: "Jean info".to_string(),
                content: "Jean Dupont works at ACME".to_string(),
                tags: vec![],
                created_at: 1000,
                updated_at: None,
            };
            store.store(&entry).unwrap();
        }
        index_chunks_for_entry(&cs, "e1", "Jean Dupont works at ACME");

        // Also index a chunk from a different source that mentions Jean
        index_chunks_for_entry(&cs, "other_doc", "Jean Dupont is a colleague");
        assert_eq!(cs.stats().unwrap().chunk_count, 2);

        let args = serde_json::json!({"query": "Jean", "confirm": true});
        let result = handle_memory_forget_by_content(args, ks.clone(), Some(Arc::clone(&cs))).await;

        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["mode"], "confirmed");
        assert_eq!(response["deleted"], 1);
        // Should delete chunks by source ID (e1) AND by content match ("Jean")
        assert_eq!(response["chunks_deleted"], 2);

        // All chunks containing "Jean" should be gone
        assert_eq!(cs.stats().unwrap().chunk_count, 0);
    }

    // --- pii_report tests ---

    #[tokio::test]
    async fn pii_report_returns_correct_format() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        // Store an entry with PII
        {
            let store = ks.lock().unwrap();
            let entry = navra_memory::MemoryEntry {
                id: "pii1".to_string(),
                memory_type: navra_memory::MemoryType::Fact,
                title: "Contact".to_string(),
                content: "Email: user@example.com".to_string(),
                tags: vec![],
                created_at: 1000,
                updated_at: None,
            };
            store.store_with_pii(&entry, true).unwrap();
        }

        let metrics = Arc::new(PiiMetrics::new());
        let result = handle_pii_report(
            serde_json::json!({}),
            ks,
            Some(metrics),
            Some(90),
            Some(30),
            Some(365),
        )
        .await;

        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let report: serde_json::Value = serde_json::from_str(text).unwrap();

        assert!(report.get("metrics").is_some());
        assert_eq!(report["knowledge_store"]["entries_with_pii"], 1);
        assert_eq!(report["retention_policy"]["general_ttl_days"], 90);
        assert_eq!(report["retention_policy"]["pii_ttl_days"], 30);
        assert_eq!(report["retention_policy"]["audit_ttl_days"], 365);
    }

    #[tokio::test]
    async fn pii_report_without_metrics() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        let result = handle_pii_report(serde_json::json!({}), ks, None, None, None, None).await;

        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let report: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(report["metrics"], "not_configured");
    }

    // --- memory_consent tests ---

    #[tokio::test]
    async fn memory_consent_set_and_get() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        // Store an entry
        {
            let store = ks.lock().unwrap();
            let entry = navra_memory::MemoryEntry {
                id: "e1".to_string(),
                memory_type: navra_memory::MemoryType::Fact,
                title: "Test".to_string(),
                content: "Test content".to_string(),
                tags: vec![],
                created_at: 1000,
                updated_at: None,
            };
            store.store(&entry).unwrap();
        }

        // Set consent basis
        let args = serde_json::json!({"mode": "set", "id": "e1", "basis": "consent"});
        let result = handle_memory_consent(args, ks.clone()).await;
        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["status"], "updated");
        assert_eq!(response["consent_basis"], "consent");

        // Get consent basis
        let args = serde_json::json!({"mode": "get", "id": "e1"});
        let result = handle_memory_consent(args, ks.clone()).await;
        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["consent_basis"], "consent");
    }

    #[tokio::test]
    async fn memory_consent_list() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        {
            let store = ks.lock().unwrap();
            for (id, title) in &[("e1", "A"), ("e2", "B"), ("e3", "C")] {
                let entry = navra_memory::MemoryEntry {
                    id: id.to_string(),
                    memory_type: navra_memory::MemoryType::Fact,
                    title: title.to_string(),
                    content: "content".to_string(),
                    tags: vec![],
                    created_at: 1000,
                    updated_at: None,
                };
                store.store(&entry).unwrap();
            }
            store.set_consent_basis("e1", "consent").unwrap();
            store.set_consent_basis("e2", "consent").unwrap();
        }

        let args = serde_json::json!({"mode": "list", "basis": "consent"});
        let result = handle_memory_consent(args, ks.clone()).await;
        let text = navra_protocol::compat::content_as_text(result.content.first().unwrap())
            .expect("expected text content");
        let response: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(response["count"], 2);
        assert_eq!(response["basis"], "consent");
    }

    #[tokio::test]
    async fn memory_consent_invalid_basis() {
        let ks = std::sync::Arc::new(std::sync::Mutex::new(
            navra_memory::KnowledgeStore::open_memory().unwrap(),
        ));

        let args = serde_json::json!({"mode": "set", "id": "e1", "basis": "invalid"});
        let result = handle_memory_consent(args, ks).await;
        assert!(result.is_err());
    }
}
