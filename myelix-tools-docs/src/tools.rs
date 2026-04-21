use crate::store::IndexStore;
use myelix_core::auth::CallContext;
use myelix_core::models::ModelBackend;
use myelix_core::notify::Notifier;
use myelix_core::permissions::{ApprovalStore, PermissionEngine, PermissionResult};
use myelix_core::protocol::{CallToolResult, ToolDefinition, ToolInputSchema};
use myelix_core::ToolHandler;
use myelix_core::Module;
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Document management module for mcpd.
pub struct DocsModule {
    state: Arc<DocsState>,
}

struct DocsState {
    perm_engine: Arc<PermissionEngine>,
    index: Arc<IndexStore>,
    approvals: Arc<ApprovalStore>,
    notifier: Arc<dyn Notifier>,
    embedding_model: Option<Arc<dyn ModelBackend>>,
    default_root: Option<String>,
}

impl DocsModule {
    pub fn new(
        perm_engine: Arc<PermissionEngine>,
        index: Arc<IndexStore>,
        approvals: Arc<ApprovalStore>,
        notifier: Arc<dyn Notifier>,
    ) -> Self {
        Self {
            state: Arc::new(DocsState {
                perm_engine,
                index,
                approvals,
                notifier,
                embedding_model: None,
                default_root: None,
            }),
        }
    }

    /// Create a docs module with an embedding model for semantic search.
    pub fn with_embeddings(
        perm_engine: Arc<PermissionEngine>,
        index: Arc<IndexStore>,
        approvals: Arc<ApprovalStore>,
        notifier: Arc<dyn Notifier>,
        embedding_model: Arc<dyn ModelBackend>,
    ) -> Self {
        Self {
            state: Arc::new(DocsState {
                perm_engine,
                index,
                approvals,
                notifier,
                embedding_model: Some(embedding_model),
                default_root: None,
            }),
        }
    }

    /// Set the default root path for docs_tree when no path is specified.
    pub fn set_default_root(&mut self, path: String) {
        // Replace the Arc entirely to avoid Arc::get_mut issues
        let old = &*self.state;
        self.state = Arc::new(DocsState {
            perm_engine: old.perm_engine.clone(),
            index: old.index.clone(),
            approvals: old.approvals.clone(),
            notifier: old.notifier.clone(),
            embedding_model: old.embedding_model.clone(),
            default_root: Some(path),
        });
    }
}

impl Module for DocsModule {
    fn name(&self) -> &str {
        "docs"
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        let s = self.state.clone();
        let mut tools = vec![
            make_tool(search_tool_def(), s.clone(), handle_search),
            make_tool(read_tool_def(), s.clone(), handle_read),
            make_tool(list_tool_def(), s.clone(), handle_list),
            make_tool(write_tool_def(), s.clone(), handle_write),
            make_tool(edit_tool_def(), s.clone(), handle_edit),
            make_tool(info_tool_def(), s.clone(), handle_info),
            make_tool(delete_tool_def(), s.clone(), handle_delete),
            make_tool(approve_tool_def(), s.clone(), handle_approve),
            make_tool(deny_tool_def(), s.clone(), handle_deny),
            make_tool(tree_tool_def(), s.clone(), handle_tree),
            make_tool(grep_tool_def(), s.clone(), handle_grep),
        ];

        // Add semantic search tool if embedding model is available
        if s.embedding_model.is_some() && s.index.has_vectors() {
            tools.push(make_tool(
                semantic_search_tool_def(),
                s.clone(),
                handle_semantic_search,
            ));
        }

        tools
    }
}

/// Helper to create a (ToolDefinition, ToolHandler) pair from an async handler.
fn make_tool<F>(
    def: ToolDefinition,
    state: Arc<DocsState>,
    handler: fn(serde_json::Value, CallContext, Arc<DocsState>) -> F,
) -> (ToolDefinition, ToolHandler)
where
    F: Future<Output = CallToolResult> + Send + 'static,
{
    let h: ToolHandler = Arc::new(move |args, ctx| {
        let s = state.clone();
        Box::pin(handler(args, ctx, s))
    });
    (def, h)
}

// --- Tool definitions ---

fn search_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_search".to_string(),
        description: Some("Full-text search across indexed documents".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "query".to_string(),
                    serde_json::json!({"type": "string", "description": "Search query"}),
                ),
                (
                    "limit".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max results (default 10)", "default": 10}),
                ),
            ])),
            required: Some(vec!["query".to_string()]),
        },
    }
}

fn read_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_read".to_string(),
        description: Some("Read a document by path. Supports partial reads with offset and limit (line-based).".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Absolute path to document"}),
                ),
                (
                    "offset".to_string(),
                    serde_json::json!({"type": "integer", "description": "Line number to start from (1-based, default 1)"}),
                ),
                (
                    "limit".to_string(),
                    serde_json::json!({"type": "integer", "description": "Number of lines to read (default: all)"}),
                ),
            ])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn list_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_list".to_string(),
        description: Some("List files and directories at a path".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!({"type": "string", "description": "Directory path"}),
            )])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn tree_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_tree".to_string(),
        description: Some(
            "Recursively list all files under a directory. Returns the full file \
             tree with relative paths and line counts. Use this to understand \
             project structure. Call with no arguments to list the project root."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Directory path (optional — defaults to project root)"}),
                ),
                (
                    "pattern".to_string(),
                    serde_json::json!({"type": "string", "description": "Optional file extension filter (e.g. 'rs', 'py'). Omit for all files."}),
                ),
            ])),
            required: None,
        },
    }
}

fn grep_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_grep".to_string(),
        description: Some(
            "Search for a text pattern across all files in a directory. Returns \
             matching lines with file paths and line numbers. Use this for \
             broad codebase searches like finding all .unwrap() calls, unsafe \
             blocks, or specific function names across the entire project."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Root directory to search"}),
                ),
                (
                    "pattern".to_string(),
                    serde_json::json!({"type": "string", "description": "Text pattern to search for (substring match, not regex)"}),
                ),
                (
                    "extension".to_string(),
                    serde_json::json!({"type": "string", "description": "Optional file extension filter (e.g. 'rs')"}),
                ),
                (
                    "max_results".to_string(),
                    serde_json::json!({"type": "integer", "description": "Maximum matches to return (default: 100)"}),
                ),
            ])),
            required: Some(vec!["path".to_string(), "pattern".to_string()]),
        },
    }
}

fn write_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_write".to_string(),
        description: Some("Create or overwrite a document".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Absolute path"}),
                ),
                (
                    "content".to_string(),
                    serde_json::json!({"type": "string", "description": "Document content"}),
                ),
            ])),
            required: Some(vec!["path".to_string(), "content".to_string()]),
        },
    }
}

fn edit_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_edit".to_string(),
        description: Some(
            "Edit a document by replacing a string. The old_string must be unique in the file. \
             Use enough surrounding context to ensure uniqueness."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Absolute path to file"}),
                ),
                (
                    "old_string".to_string(),
                    serde_json::json!({"type": "string", "description": "Exact string to find and replace"}),
                ),
                (
                    "new_string".to_string(),
                    serde_json::json!({"type": "string", "description": "Replacement string"}),
                ),
            ])),
            required: Some(vec![
                "path".to_string(),
                "old_string".to_string(),
                "new_string".to_string(),
            ]),
        },
    }
}

fn info_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_info".to_string(),
        description: Some("Get file metadata without reading content (size, type, line count, modified time)".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!({"type": "string", "description": "Absolute path to file"}),
            )])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn delete_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_delete".to_string(),
        description: Some("Delete a document. Requires write permission.".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!({"type": "string", "description": "Absolute path to file"}),
            )])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn approve_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_approve".to_string(),
        description: Some(
            "Approve a pending operation. Call this with the request_id \
             returned by a tool that requires approval."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "request_id".to_string(),
                serde_json::json!({"type": "string", "description": "Approval request ID"}),
            )])),
            required: Some(vec!["request_id".to_string()]),
        },
    }
}

fn deny_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_deny".to_string(),
        description: Some(
            "Deny a pending operation. Call this with the request_id \
             returned by a tool that requires approval."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "request_id".to_string(),
                serde_json::json!({"type": "string", "description": "Approval request ID"}),
            )])),
            required: Some(vec!["request_id".to_string()]),
        },
    }
}

fn semantic_search_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_semantic_search".to_string(),
        description: Some(
            "Semantic search across indexed documents using vector similarity. \
             Finds documents with similar meaning, even if they don't share exact words."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "query".to_string(),
                    serde_json::json!({"type": "string", "description": "Natural language search query"}),
                ),
                (
                    "limit".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max results (default 5)", "default": 5}),
                ),
            ])),
            required: Some(vec!["query".to_string()]),
        },
    }
}

// --- Path security ---

fn resolve_path(raw: &str, must_exist: bool) -> Result<PathBuf, String> {
    let expanded = if raw.starts_with("~/") {
        match dirs::home_dir() {
            Some(home) => home.join(&raw[2..]),
            None => return Err("Cannot resolve home directory".to_string()),
        }
    } else {
        PathBuf::from(raw)
    };

    if !expanded.is_absolute() {
        return Err(format!("Path must be absolute: {raw}"));
    }

    if must_exist {
        let canonical = expanded
            .canonicalize()
            .map_err(|_| "Path does not exist or cannot be resolved".to_string())?;
        // TOCTOU mitigation: verify canonical path has no symlink escape
        if let Some(parent) = expanded.parent() {
            let canon_parent = parent
                .canonicalize()
                .map_err(|_| "Cannot verify path safety: parent unresolvable".to_string())?;
            if !canonical.starts_with(&canon_parent) {
                return Err("Path resolves outside its parent directory".to_string());
            }
        }
        Ok(canonical)
    } else {
        match expanded.parent() {
            Some(parent) => {
                let canon_parent = parent
                    .canonicalize()
                    .map_err(|_| "Parent directory does not exist".to_string())?;
                match expanded.file_name() {
                    Some(name) => {
                        let name_str = name.to_string_lossy();
                        // Reject filenames containing path separators or traversal
                        if name_str.contains('/') || name_str.contains("..") {
                            return Err("Invalid filename".to_string());
                        }
                        let final_path = canon_parent.join(name);
                        // If the file already exists, verify it isn't a symlink
                        // that escapes the ACL boundary
                        if final_path.exists() {
                            let resolved = final_path.canonicalize()
                                .map_err(|_| "Cannot verify existing path safety".to_string())?;
                            if !resolved.starts_with(&canon_parent) {
                                return Err("Path resolves outside its parent directory".to_string());
                            }
                            return Ok(resolved);
                        }
                        Ok(final_path)
                    }
                    None => Err("Invalid path".to_string()),
                }
            }
            None => Err("Invalid path".to_string()),
        }
    }
}

/// Check permission, handling the approval flow if needed.
///
/// If the operation requires approval, creates an approval request,
/// sends a D-Bus notification, and blocks until the user responds
/// or the request times out.
async fn check_perm(
    state: &DocsState,
    ctx: &CallContext,
    op: &str,
    path: &Path,
) -> Result<(), CallToolResult> {
    match state.perm_engine.check(&ctx.agent.permissions, op, path) {
        PermissionResult::Allowed => Ok(()),
        PermissionResult::NeedsApproval => {
            let path_str = path.display().to_string();

            // Check for a cached grant from a previous approval
            if state.approvals.check_grant(&ctx.agent.name, op, &path_str) {
                tracing::info!(
                    agent = %ctx.agent.name, op, path = %path_str,
                    "Using cached approval grant"
                );
                return Ok(());
            }

            // No cached grant — create approval request and return to client
            let (req, _rx) = state.approvals.request(
                &ctx.agent.name,
                op,
                &path_str,
            );

            // Send D-Bus notification in parallel (if available)
            if let Err(e) = state.notifier.notify(&req, state.approvals.clone()).await {
                tracing::warn!("Failed to send D-Bus notification: {e}");
            }

            // Return approval-needed response to the MCP client
            Err(CallToolResult::success(vec![
                myelix_core::protocol::Content::text(format!(
                    "Approval required: {} on {}\n\n\
                     Request ID: {}\n\
                     Agent: {}\n\n\
                     Call docs_approve with this request_id to approve,\n\
                     or docs_deny to reject.",
                    op, path_str, req.id, ctx.agent.name,
                )),
            ]))
        }
        PermissionResult::DeniedPath => Err(CallToolResult::error(format!(
            "Access denied: {}",
            path.display()
        ))),
        PermissionResult::DeniedOperation => Err(CallToolResult::error(format!(
            "Operation '{op}' not permitted for agent '{}'",
            ctx.agent.name
        ))),
        PermissionResult::DeniedUnknown => Err(CallToolResult::error(format!(
            "Unknown permission set: {}",
            ctx.agent.permissions
        ))),
    }
}

fn mime_from_path(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("md" | "markdown") => "text/markdown",
        Some("txt") => "text/plain",
        Some("html" | "htm") => "text/html",
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("pdf") => "application/pdf",
        Some("rs") => "text/x-rust",
        Some("py") => "text/x-python",
        Some("go") => "text/x-go",
        Some("c" | "h") => "text/x-c",
        Some("toml") => "application/toml",
        Some("yaml" | "yml") => "application/yaml",
        Some("xml") => "application/xml",
        _ => "application/octet-stream",
    }
}

fn extract_title(path: &Path, content: &str) -> String {
    for line in content.lines().take(10) {
        let trimmed = line.trim();
        if let Some(heading) = trimmed.strip_prefix("# ") {
            return heading.trim().to_string();
        }
    }
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("untitled")
        .to_string()
}

/// Generate and store an embedding for a document, if an embedding model is available.
async fn maybe_embed(state: &DocsState, doc_id: i64, content: &str) {
    let model = match &state.embedding_model {
        Some(m) => m,
        None => return,
    };
    if !state.index.has_vectors() {
        return;
    }

    let request = myelix_core::models::EmbedRequest {
        text: content.to_string(),
    };
    match model.embed(&request).await {
        Ok(response) => {
            if let Err(e) = state.index.upsert_embedding(doc_id, &response.embedding) {
                tracing::warn!(doc_id, error = %e, "Failed to store embedding");
            }
        }
        Err(e) => {
            tracing::warn!(doc_id, error = %e, "Failed to generate embedding");
        }
    }
}

fn chrono_now() -> String {
    use std::time::{Duration, SystemTime};
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    format!("{}", since_epoch.as_secs())
}

fn simple_checksum(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

// --- Tool handlers ---

async fn handle_search(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) if !q.is_empty() => q,
        _ => return CallToolResult::error("Missing required parameter: query"),
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10) as usize;

    if !state.perm_engine.has_operation(&ctx.agent.permissions, "search") {
        return CallToolResult::error(format!(
            "Operation 'search' not permitted for agent '{}'",
            ctx.agent.name
        ));
    }

    let results = match state.index.search(query, limit) {
        Ok(r) => r,
        Err(e) => return CallToolResult::error(format!("Search failed: {e}")),
    };

    let filtered: Vec<_> = results
        .into_iter()
        .filter(|r| {
            state
                .perm_engine
                .check(&ctx.agent.permissions, "read", Path::new(&r.path))
                == PermissionResult::Allowed
        })
        .collect();

    if filtered.is_empty() {
        return CallToolResult::text("No results found.");
    }

    let mut output = format!("Found {} result(s):\n\n", filtered.len());
    for (i, r) in filtered.iter().enumerate() {
        output.push_str(&format!(
            "{}. **{}**\n   {}\n   _{}_\n\n",
            i + 1,
            r.title,
            r.snippet,
            r.path
        ));
    }
    CallToolResult::text(output)
}

async fn handle_read(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path(raw_path, true) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &path).await {
        return e;
    }

    if !path.is_file() {
        return CallToolResult::error(format!("Not a file: {}", path.display()));
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => return { tracing::warn!(path = %path.display(), error = %e, "File read failed"); CallToolResult::error("Read operation failed") },
    };

    let total_lines = content.lines().count();
    let offset = args
        .get("offset")
        .and_then(|v| v.as_u64())
        .map(|v| v.max(1) as usize)
        .unwrap_or(1);
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);

    // Full read if no offset/limit specified
    if offset == 1 && limit.is_none() {
        return CallToolResult::text(format!(
            "{} ({} lines)\n\n{}",
            path.display(),
            total_lines,
            content
        ));
    }

    // Partial read
    let lines: Vec<&str> = content.lines().collect();
    let start = (offset - 1).min(lines.len());
    let end = match limit {
        Some(l) => (start + l).min(lines.len()),
        None => lines.len(),
    };

    let selected: String = lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, line)| format!("{:>4}\t{}", start + i + 1, line))
        .collect::<Vec<_>>()
        .join("\n");

    CallToolResult::text(format!(
        "{} (lines {}-{} of {})\n\n{}",
        path.display(),
        start + 1,
        end,
        total_lines,
        selected
    ))
}

async fn handle_list(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path(raw_path, true) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "list", &path).await {
        return e;
    }

    if !path.is_dir() {
        return CallToolResult::error(format!("Not a directory: {}", path.display()));
    }

    let entries = match std::fs::read_dir(&path) {
        Ok(rd) => rd,
        Err(e) => {
            return { tracing::warn!(path = %path.display(), error = %e, "Directory list failed"); CallToolResult::error("List operation failed") }
        }
    };

    let mut dirs = Vec::new();
    let mut files = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let entry_path = entry.path();

        if state
            .perm_engine
            .check(&ctx.agent.permissions, "read", &entry_path)
            != PermissionResult::Allowed
        {
            continue;
        }

        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        if ft.is_dir() {
            dirs.push(format!("{name}/"));
        } else if ft.is_file() {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            files.push(format!("{name}  ({size} bytes)"));
        } else if ft.is_symlink() {
            files.push(format!("{name} -> (symlink)"));
        }
    }

    dirs.sort();
    files.sort();

    if dirs.is_empty() && files.is_empty() {
        return CallToolResult::text(format!(
            "{}: (empty or no accessible entries)",
            path.display()
        ));
    }

    let mut output = format!("{}:\n\n", path.display());
    for d in &dirs {
        output.push_str(&format!("  {d}\n"));
    }
    for f in &files {
        output.push_str(&format!("  {f}\n"));
    }
    CallToolResult::text(output)
}

async fn handle_write(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let content = match args.get("content").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return CallToolResult::error("Missing required parameter: content"),
    };

    let path = match resolve_path(raw_path, false) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "write", &path).await {
        return e;
    }

    if let Err(e) = std::fs::write(&path, content) {
        return { tracing::warn!(path = %path.display(), error = %e, "File write failed"); CallToolResult::error("Write operation failed") };
    }

    let size = content.len() as i64;
    let mime = mime_from_path(&path);
    let title = extract_title(&path, content);
    let path_str = path.to_string_lossy();
    let modified = chrono_now();
    let checksum = simple_checksum(content.as_bytes());

    match state
        .index
        .upsert(&path_str, mime, size, &modified, &checksum, &title, content)
    {
        Ok(doc_id) => {
            maybe_embed(&state, doc_id, content).await;
        }
        Err(e) => {
            tracing::warn!("Failed to index {}: {e}", path.display());
        }
    }

    CallToolResult::text(format!("Written {} bytes to {}", size, path.display()))
}

async fn handle_edit(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };
    let old_string = match args.get("old_string").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::error("Missing required parameter: old_string"),
    };
    let new_string = match args.get("new_string").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::error("Missing required parameter: new_string"),
    };

    let path = match resolve_path(raw_path, true) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "write", &path).await {
        return e;
    }

    if !path.is_file() {
        return CallToolResult::error(format!("Not a file: {}", path.display()));
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => return { tracing::warn!(path = %path.display(), error = %e, "File read failed"); CallToolResult::error("Read operation failed") },
    };

    let count = content.matches(old_string).count();
    if count == 0 {
        return CallToolResult::error(format!(
            "old_string not found in {}",
            path.display()
        ));
    }
    if count > 1 {
        return CallToolResult::error(format!(
            "old_string found {} times in {} — must be unique. Include more surrounding context.",
            count,
            path.display()
        ));
    }

    let new_content = content.replacen(old_string, new_string, 1);

    if let Err(e) = std::fs::write(&path, &new_content) {
        return { tracing::warn!(path = %path.display(), error = %e, "File write failed"); CallToolResult::error("Write operation failed") };
    }

    // Re-index
    let size = new_content.len() as i64;
    let mime = mime_from_path(&path);
    let title = extract_title(&path, &new_content);
    let path_str = path.to_string_lossy();
    let modified = chrono_now();
    let checksum = simple_checksum(new_content.as_bytes());

    match state.index.upsert(
        &path_str, mime, size, &modified, &checksum, &title, &new_content,
    ) {
        Ok(doc_id) => {
            maybe_embed(&state, doc_id, &new_content).await;
        }
        Err(e) => {
            tracing::warn!("Failed to index {}: {e}", path.display());
        }
    }

    CallToolResult::text(format!("Edited {}", path.display()))
}

async fn handle_info(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path(raw_path, true) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &path).await {
        return e;
    }

    let metadata = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "File stat failed");
            return CallToolResult::error("Metadata read failed");
        }
    };

    let mime = mime_from_path(&path);
    let size = metadata.len();
    let modified = metadata
        .modified()
        .ok()
        .and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    let line_count = if metadata.is_file() {
        std::fs::read_to_string(&path)
            .map(|c| c.lines().count())
            .unwrap_or(0)
    } else {
        0
    };

    let is_dir = metadata.is_dir();
    let indexed = state
        .index
        .get_by_path(&path.to_string_lossy())
        .ok()
        .flatten()
        .is_some();

    let output = format!(
        "path: {}\ntype: {}\nsize: {} bytes\nlines: {}\nmodified: {}\nmime: {}\nindexed: {}{}",
        path.display(),
        if is_dir { "directory" } else { "file" },
        size,
        line_count,
        modified,
        mime,
        indexed,
        if is_dir { "\n(use docs_list to see contents)" } else { "" }
    );

    CallToolResult::text(output)
}

async fn handle_delete(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path(raw_path, true) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "write", &path).await {
        return e;
    }

    if !path.is_file() {
        return CallToolResult::error(format!("Not a file: {}", path.display()));
    }

    if let Err(e) = std::fs::remove_file(&path) {
        return { tracing::warn!(path = %path.display(), error = %e, "File delete failed"); CallToolResult::error("Delete operation failed") };
    }

    // Remove from index
    let path_str = path.to_string_lossy();
    if let Err(e) = state.index.delete(&path_str) {
        tracing::warn!("Failed to remove {} from index: {e}", path.display());
    }

    CallToolResult::text(format!("Deleted {}", path.display()))
}

/// Recursively list all files under a directory with line counts.
async fn handle_tree(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = args.get("path")
        .and_then(|v| v.as_str())
        .filter(|p| !p.is_empty() && *p != "." && *p != "./")
        .or(state.default_root.as_deref())
        .unwrap_or("/");

    let root = match resolve_path(raw_path, true) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "list", &root).await {
        return e;
    }

    let extension_filter = args
        .get("pattern")
        .and_then(|v| v.as_str())
        .map(|s| s.trim_start_matches('.').to_string());

    let mut entries: Vec<(String, usize)> = Vec::new();
    collect_tree(&root, &root, &extension_filter, &mut entries);
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut output = format!("{} files found", entries.len());
    if let Some(ref ext) = extension_filter {
        output.push_str(&format!(" (*.{})", ext));
    }
    output.push('\n');
    for (rel_path, lines) in &entries {
        output.push_str(&format!("  {} ({} lines)\n", rel_path, lines));
    }

    CallToolResult::text(output)
}

fn collect_tree(
    dir: &Path,
    root: &Path,
    ext_filter: &Option<String>,
    entries: &mut Vec<(String, usize)>,
) {
    let Ok(read_dir) = std::fs::read_dir(dir) else { return };
    for entry in read_dir.flatten() {
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        // Skip symlinks to prevent escaping the ACL boundary
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
            // Skip hidden directories and common non-source dirs
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') || name_str == "target" || name_str == "node_modules" {
                continue;
            }
            collect_tree(&path, root, ext_filter, entries);
        } else if ft.is_file() {
            // Apply extension filter
            if let Some(ref ext) = ext_filter {
                if path.extension().map(|e| e.to_string_lossy().to_string()) != Some(ext.clone()) {
                    continue;
                }
            }
            let rel = match path.strip_prefix(root) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let lines = std::fs::read_to_string(&path)
                .map(|c| c.lines().count())
                .unwrap_or(0);
            entries.push((rel.display().to_string(), lines));
        }
    }
}

/// Search for a text pattern across all files in a directory.
async fn handle_grep(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let pattern = match args.get("pattern").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: pattern"),
    };

    let root = match resolve_path(raw_path, true) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "search", &root).await {
        return e;
    }

    let ext_filter = args
        .get("extension")
        .and_then(|v| v.as_str())
        .map(|s| s.trim_start_matches('.').to_string());

    let max_results = args
        .get("max_results")
        .and_then(|v| v.as_u64())
        .unwrap_or(100) as usize;

    let mut matches: Vec<String> = Vec::new();
    let mut files_searched = 0u32;
    let mut files_matched = 0u32;
    grep_recursive(&root, &root, pattern, &ext_filter, max_results, &mut matches, &mut files_searched, &mut files_matched);

    let mut output = format!(
        "{} matches in {} files (searched {} files)\n\n",
        matches.len(),
        files_matched,
        files_searched
    );
    for m in &matches {
        output.push_str(m);
        output.push('\n');
    }

    CallToolResult::text(output)
}

fn grep_recursive(
    dir: &Path,
    root: &Path,
    pattern: &str,
    ext_filter: &Option<String>,
    max_results: usize,
    matches: &mut Vec<String>,
    files_searched: &mut u32,
    files_matched: &mut u32,
) {
    let Ok(read_dir) = std::fs::read_dir(dir) else { return };
    for entry in read_dir.flatten() {
        if matches.len() >= max_results {
            return;
        }
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        // Skip symlinks to prevent escaping the ACL boundary
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') || name_str == "target" || name_str == "node_modules" {
                continue;
            }
            grep_recursive(&path, root, pattern, ext_filter, max_results, matches, files_searched, files_matched);
        } else if ft.is_file() {
            if let Some(ref ext) = ext_filter {
                if path.extension().map(|e| e.to_string_lossy().to_string()) != Some(ext.clone()) {
                    continue;
                }
            }
            let Ok(content) = std::fs::read_to_string(&path) else { continue };
            *files_searched += 1;
            let rel = match path.strip_prefix(root) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let rel_str = rel.display().to_string();
            let mut file_matched = false;
            for (line_num, line) in content.lines().enumerate() {
                if matches.len() >= max_results {
                    break;
                }
                if line.contains(pattern) {
                    if !file_matched {
                        *files_matched += 1;
                        file_matched = true;
                    }
                    matches.push(format!(
                        "{}:{}: {}",
                        rel_str,
                        line_num + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
}

async fn handle_approve(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let request_id = match args.get("request_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error("Missing required parameter: request_id"),
    };

    // Validate the request exists
    let meta = match state.approvals.get_pending(request_id) {
        Some(m) => m,
        None => {
            return CallToolResult::error(format!(
                "No pending approval request: {request_id}"
            ))
        }
    };

    // Security: prevent self-approval — the requesting agent cannot approve
    // its own request. Approval must come from a different agent or human.
    if ctx.agent.name == meta.agent_name {
        return CallToolResult::error(
            "Self-approval denied: a different agent or human must approve this request"
        );
    }

    state.approvals.approve(request_id);

    // Dismiss D-Bus notification
    let _ = state.notifier.dismiss(request_id).await;

    tracing::info!(
        request_id = request_id,
        approved_by = %ctx.agent.name,
        agent = %meta.agent_name,
        operation = %meta.operation,
        "Approval granted"
    );

    CallToolResult::text(format!(
        "Approved: {} on {}\n\nYou can now retry the operation.",
        meta.operation, meta.path,
    ))
}

async fn handle_deny(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let request_id = match args.get("request_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error("Missing required parameter: request_id"),
    };

    let meta = match state.approvals.get_pending(request_id) {
        Some(m) => m,
        None => {
            return CallToolResult::error(format!(
                "No pending approval request: {request_id}"
            ))
        }
    };

    // Security: prevent self-denial for audit trail integrity
    if ctx.agent.name == meta.agent_name {
        return CallToolResult::error(
            "Self-denial not allowed: a different agent or human must deny this request"
        );
    }

    state.approvals.deny(request_id);

    let _ = state.notifier.dismiss(request_id).await;

    tracing::info!(
        request_id = request_id,
        denied_by = %ctx.agent.name,
        agent = %meta.agent_name,
        operation = %meta.operation,
        "Approval denied"
    );

    CallToolResult::text(format!(
        "Denied: {} on {}",
        meta.operation, meta.path,
    ))
}

async fn handle_semantic_search(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) if !q.is_empty() => q,
        _ => return CallToolResult::error("Missing required parameter: query"),
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(5) as usize;

    // ACL is checked per-result below (not against "/" which is too permissive)

    let model = match &state.embedding_model {
        Some(m) => m,
        None => return CallToolResult::error("Embedding model not available"),
    };

    // Generate embedding for the query
    let embed_request = myelix_core::models::EmbedRequest {
        text: query.to_string(),
    };
    let embed_response = match model.embed(&embed_request).await {
        Ok(r) => r,
        Err(e) => return CallToolResult::error(format!("Embedding failed: {e}")),
    };

    // Search for similar documents
    match state
        .index
        .search_similar(&embed_response.embedding, limit)
    {
        Ok(results) => {
            // Filter results through per-path ACL check
            use myelix_core::permissions::PermissionResult;
            let filtered: Vec<_> = results.iter().filter(|r| {
                let path = std::path::Path::new(&r.path);
                matches!(
                    state.perm_engine.check(&ctx.agent.permissions, "search", path),
                    PermissionResult::Allowed | PermissionResult::NeedsApproval
                )
            }).collect();

            if filtered.is_empty() {
                return CallToolResult::text("No similar documents found.".to_string());
            }

            let mut output = format!("Found {} similar documents:\n\n", filtered.len());
            for (i, result) in filtered.iter().enumerate() {
                output.push_str(&format!(
                    "{}. {} (distance: {:.4})\n",
                    i + 1,
                    result.path,
                    result.distance
                ));
            }
            CallToolResult::text(output)
        }
        Err(e) => CallToolResult::error(format!("Search failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myelix_core::auth::AgentIdentity;
    use myelix_core::notify::NoopNotifier;
    use myelix_core::permissions::PathAcl;
    use std::collections::HashSet;
    use tempfile::TempDir;

    fn test_state(tmpdir: &TempDir) -> Arc<DocsState> {
        let mut engine = PermissionEngine::new();
        engine.add_permission_set(
            "dev".to_string(),
            PathAcl {
                ring: None,
                allow: vec![format!("{}/**", tmpdir.path().display())],
                deny: vec![format!("{}/.secret/**", tmpdir.path().display())],
                operations: ["read", "write", "search", "list"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                requires_approval: HashSet::new(),
            },
        );
        engine.add_permission_set(
            "readonly".to_string(),
            PathAcl {
                ring: None,
                allow: vec![format!("{}/**", tmpdir.path().display())],
                deny: vec![],
                operations: ["read", "search", "list"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                requires_approval: HashSet::new(),
            },
        );
        let index = IndexStore::open_memory().unwrap();
        Arc::new(DocsState {
            perm_engine: Arc::new(engine),
            index: Arc::new(index),
            approvals: Arc::new(ApprovalStore::new(300)),
            notifier: Arc::new(NoopNotifier),
            embedding_model: None,
            default_root: None,
        })
    }

    fn dev_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("test-agent", "dev"), "test")
    }

    fn readonly_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("reader", "readonly"), "test")
    }

    fn text_of(result: &CallToolResult) -> &str {
        match &result.content[0] {
            myelix_core::protocol::Content::Text(t) => &t.text,
        }
    }

    // --- resolve_path ---

    #[test]
    fn resolve_path_rejects_relative() {
        assert!(resolve_path("relative/path.txt", true).unwrap_err().contains("absolute"));
    }

    #[test]
    fn resolve_path_rejects_nonexistent() {
        assert!(resolve_path("/nonexistent/path/file.txt", true).is_err());
    }

    #[test]
    fn resolve_path_canonicalizes() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("test.txt");
        std::fs::write(&file, "hello").unwrap();
        let resolved = resolve_path(file.to_str().unwrap(), true).unwrap();
        assert!(resolved.is_absolute());
    }

    // --- read ---

    #[tokio::test]
    async fn read_full_file() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("hello.txt");
        std::fs::write(&file, "Hello, world!").unwrap();

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);
        assert!(text_of(&result).contains("Hello, world!"));
        assert!(text_of(&result).contains("1 lines"));
    }

    #[tokio::test]
    async fn read_partial_with_offset_and_limit() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("multi.txt");
        std::fs::write(&file, "line1\nline2\nline3\nline4\nline5\n").unwrap();

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap(), "offset": 2, "limit": 2}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);
        let text = text_of(&result);
        assert!(text.contains("lines 2-3 of"));
        assert!(text.contains("line2"));
        assert!(text.contains("line3"));
        assert!(!text.contains("line1"));
        assert!(!text.contains("line4"));
    }

    #[tokio::test]
    async fn read_denied_path() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let secret_dir = tmp.path().join(".secret");
        std::fs::create_dir(&secret_dir).unwrap();
        let file = secret_dir.join("key.pem");
        std::fs::write(&file, "private key").unwrap();

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(result.is_error);
        assert!(text_of(&result).contains("denied"));
    }

    // --- write ---

    #[tokio::test]
    async fn write_new_file() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("new.md");

        let result = handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "# Hello\n\nWorld"}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "# Hello\n\nWorld");
    }

    #[tokio::test]
    async fn write_denied_for_readonly() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("nope.txt");

        let result = handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "fail"}),
            readonly_ctx(),
            state.clone(),
        ).await;
        assert!(result.is_error);
        assert!(!file.exists());
    }

    // --- edit ---

    #[tokio::test]
    async fn edit_replaces_unique_string() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("doc.md");
        std::fs::write(&file, "Hello world, this is a test.").unwrap();

        let result = handle_edit(
            serde_json::json!({
                "path": file.to_str().unwrap(),
                "old_string": "Hello world",
                "new_string": "Goodbye world"
            }),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "Goodbye world, this is a test."
        );
    }

    #[tokio::test]
    async fn edit_fails_if_not_found() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("doc.md");
        std::fs::write(&file, "Hello world").unwrap();

        let result = handle_edit(
            serde_json::json!({
                "path": file.to_str().unwrap(),
                "old_string": "nonexistent",
                "new_string": "replacement"
            }),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(result.is_error);
        assert!(text_of(&result).contains("not found"));
    }

    #[tokio::test]
    async fn edit_fails_if_not_unique() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("doc.md");
        std::fs::write(&file, "foo bar foo baz").unwrap();

        let result = handle_edit(
            serde_json::json!({
                "path": file.to_str().unwrap(),
                "old_string": "foo",
                "new_string": "qux"
            }),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(result.is_error);
        assert!(text_of(&result).contains("2 times"));
        // File should be unchanged
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "foo bar foo baz");
    }

    #[tokio::test]
    async fn edit_denied_for_readonly() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("doc.md");
        std::fs::write(&file, "content").unwrap();

        let result = handle_edit(
            serde_json::json!({
                "path": file.to_str().unwrap(),
                "old_string": "content",
                "new_string": "modified"
            }),
            readonly_ctx(),
            state.clone(),
        ).await;
        assert!(result.is_error);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "content");
    }

    // --- info ---

    #[tokio::test]
    async fn info_returns_metadata() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("info.md");
        std::fs::write(&file, "line1\nline2\nline3\n").unwrap();

        let result = handle_info(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);
        let text = text_of(&result);
        assert!(text.contains("type: file"));
        assert!(text.contains("lines: 3"));
        assert!(text.contains("mime: text/markdown"));
        assert!(text.contains("indexed: false"));
    }

    // --- delete ---

    #[tokio::test]
    async fn delete_removes_file() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("doomed.txt");
        std::fs::write(&file, "goodbye").unwrap();

        let result = handle_delete(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);
        assert!(!file.exists());
    }

    #[tokio::test]
    async fn delete_denied_for_readonly() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("safe.txt");
        std::fs::write(&file, "safe").unwrap();

        let result = handle_delete(
            serde_json::json!({"path": file.to_str().unwrap()}),
            readonly_ctx(),
            state.clone(),
        ).await;
        assert!(result.is_error);
        assert!(file.exists());
    }

    // --- list ---

    #[tokio::test]
    async fn list_directory() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        std::fs::write(tmp.path().join("a.txt"), "aaa").unwrap();
        std::fs::create_dir(tmp.path().join("subdir")).unwrap();

        let result = handle_list(
            serde_json::json!({"path": tmp.path().to_str().unwrap()}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);
        let text = text_of(&result);
        assert!(text.contains("a.txt"));
        assert!(text.contains("subdir/"));
    }

    // --- search ---

    #[tokio::test]
    async fn search_returns_results() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let path = tmp.path().join("notes.md");
        std::fs::write(&path, "").unwrap();
        state.index.upsert(
            path.to_str().unwrap(), "text/markdown", 100, "t", "h",
            "Notes", "rust programming guide",
        ).unwrap();

        let result = handle_search(
            serde_json::json!({"query": "rust programming"}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);
        assert!(text_of(&result).contains("1 result"));
    }

    // --- module trait ---

    #[test]
    fn module_provides_all_tools() {
        let engine = Arc::new(PermissionEngine::new());
        let index = Arc::new(IndexStore::open_memory().unwrap());
        let approvals = Arc::new(ApprovalStore::new(300));
        let notifier: Arc<dyn Notifier> = Arc::new(NoopNotifier);
        let module = DocsModule::new(engine, index, approvals, notifier);

        assert_eq!(module.name(), "docs");
        let tools = module.tools();
        let names: Vec<_> = tools.iter().map(|(def, _)| def.name.as_str()).collect();
        assert!(names.contains(&"docs_search"));
        assert!(names.contains(&"docs_read"));
        assert!(names.contains(&"docs_list"));
        assert!(names.contains(&"docs_write"));
        assert!(names.contains(&"docs_edit"));
        assert!(names.contains(&"docs_info"));
        assert!(names.contains(&"docs_delete"));
        assert!(names.contains(&"docs_approve"));
        assert!(names.contains(&"docs_deny"));
        assert!(names.contains(&"docs_tree"));
        assert!(names.contains(&"docs_grep"));
        assert_eq!(tools.len(), 11);
    }

    // --- roundtrips ---

    #[tokio::test]
    async fn write_then_read_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("rt.md");

        handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "# RT\n\nContent."}),
            dev_ctx(),
            state.clone(),
        ).await;

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(text_of(&result).contains("# RT\n\nContent."));
    }

    #[tokio::test]
    async fn write_edit_read_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("edit_rt.md");

        handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "Hello world"}),
            dev_ctx(),
            state.clone(),
        ).await;

        handle_edit(
            serde_json::json!({
                "path": file.to_str().unwrap(),
                "old_string": "Hello world",
                "new_string": "Goodbye world"
            }),
            dev_ctx(),
            state.clone(),
        ).await;

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(text_of(&result).contains("Goodbye world"));
    }

    #[tokio::test]
    async fn write_then_search_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("searchable.md");

        handle_write(
            serde_json::json!({
                "path": file.to_str().unwrap(),
                "content": "# K8s Guide\n\nDeploy pods with kubectl."
            }),
            dev_ctx(),
            state.clone(),
        ).await;

        let result = handle_search(
            serde_json::json!({"query": "kubectl deploy"}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(text_of(&result).contains("1 result"));
    }

    #[tokio::test]
    async fn write_delete_read_fails() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("temp.txt");

        handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "temporary"}),
            dev_ctx(),
            state.clone(),
        ).await;

        handle_delete(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            state.clone(),
        ).await;

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            state.clone(),
        ).await;
        assert!(result.is_error);
    }

    // --- approval flow ---

    fn test_state_with_approval(tmpdir: &TempDir) -> Arc<DocsState> {
        let mut engine = PermissionEngine::new();
        engine.add_permission_set(
            "needs_approval".to_string(),
            PathAcl {
                ring: None,
                allow: vec![format!("{}/**", tmpdir.path().display())],
                deny: vec![],
                operations: ["read", "write", "search", "list"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                requires_approval: ["write"].into_iter().map(String::from).collect(),
            },
        );
        let index = IndexStore::open_memory().unwrap();
        Arc::new(DocsState {
            perm_engine: Arc::new(engine),
            index: Arc::new(index),
            approvals: Arc::new(ApprovalStore::new(5)),
            notifier: Arc::new(NoopNotifier),
            embedding_model: None,
            default_root: None,
        })
    }

    fn approval_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("approval-agent", "needs_approval"), "test")
    }

    fn admin_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("admin", "admin"), "test-admin")
    }

    #[tokio::test]
    async fn write_needs_approval_returns_request_id() {
        let tmp = TempDir::new().unwrap();
        let state = test_state_with_approval(&tmp);
        let file = tmp.path().join("needs_approval.md");

        // First attempt: returns approval-needed (non-blocking)
        let result = handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "content"}),
            approval_ctx(),
            state.clone(),
        ).await;

        // Not an error — it's a workflow step
        assert!(!result.is_error);
        let text = text_of(&result);
        assert!(text.contains("Approval required"));
        assert!(text.contains("Request ID:"));
        assert!(text.contains("docs_approve"));

        // File should NOT exist yet
        assert!(!file.exists());

        // There should be a pending request
        assert_eq!(state.approvals.pending_count(), 1);
    }

    #[tokio::test]
    async fn approve_then_retry_succeeds() {
        let tmp = TempDir::new().unwrap();
        let state = test_state_with_approval(&tmp);
        let file = tmp.path().join("approved.md");

        // Step 1: write returns approval-needed
        let result = handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "approved content"}),
            approval_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);

        // Step 2: admin calls docs_approve (different agent — self-approval blocked)
        let pending = state.approvals.pending_requests();
        let result = handle_approve(
            serde_json::json!({"request_id": pending[0].id}),
            admin_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);
        assert!(text_of(&result).contains("Approved"));

        // Step 3: agent retries the write — grant is cached
        let result = handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "approved content"}),
            approval_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);
        assert!(text_of(&result).contains("Written"));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "approved content");
    }

    #[tokio::test]
    async fn deny_then_retry_still_needs_approval() {
        let tmp = TempDir::new().unwrap();
        let state = test_state_with_approval(&tmp);
        let file = tmp.path().join("denied.md");

        // Step 1: write returns approval-needed
        handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "content"}),
            approval_ctx(),
            state.clone(),
        ).await;

        // Step 2: admin calls docs_deny (different agent — self-denial blocked)
        let pending = state.approvals.pending_requests();
        let result = handle_deny(
            serde_json::json!({"request_id": pending[0].id}),
            admin_ctx(),
            state.clone(),
        ).await;
        assert!(!result.is_error);
        assert!(text_of(&result).contains("Denied"));

        // Step 3: retry still needs approval (no grant cached)
        let result = handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "content"}),
            approval_ctx(),
            state.clone(),
        ).await;
        assert!(text_of(&result).contains("Approval required"));
        assert!(!file.exists());
    }

    #[tokio::test]
    async fn approve_unknown_request_fails() {
        let tmp = TempDir::new().unwrap();
        let state = test_state_with_approval(&tmp);

        let result = handle_approve(
            serde_json::json!({"request_id": "nonexistent"}),
            admin_ctx(),
            state,
        ).await;
        assert!(result.is_error);
        assert!(text_of(&result).contains("No pending"));
    }

    #[tokio::test]
    async fn grant_is_single_use() {
        let tmp = TempDir::new().unwrap();
        let state = test_state_with_approval(&tmp);
        let file = tmp.path().join("single_use.md");

        // Get approval
        handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "first"}),
            approval_ctx(),
            state.clone(),
        ).await;
        let pending = state.approvals.pending_requests();
        handle_approve(
            serde_json::json!({"request_id": pending[0].id}),
            admin_ctx(),
            state.clone(),
        ).await;

        // First retry succeeds (consumes grant)
        let result = handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "first"}),
            approval_ctx(),
            state.clone(),
        ).await;
        assert!(text_of(&result).contains("Written"));

        // Second retry needs approval again (grant consumed)
        let result = handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "second"}),
            approval_ctx(),
            state.clone(),
        ).await;
        assert!(text_of(&result).contains("Approval required"));
    }

    #[tokio::test]
    async fn read_without_approval_still_works() {
        let tmp = TempDir::new().unwrap();
        let state = test_state_with_approval(&tmp);
        let file = tmp.path().join("readable.txt");
        std::fs::write(&file, "no approval needed").unwrap();

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap()}),
            approval_ctx(),
            state,
        ).await;
        assert!(!result.is_error);
        assert!(text_of(&result).contains("no approval needed"));
    }

    #[tokio::test]
    async fn dbus_approval_also_creates_grant() {
        let tmp = TempDir::new().unwrap();
        let state = test_state_with_approval(&tmp);
        let file = tmp.path().join("dbus_approved.md");

        // Write returns approval-needed
        handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "content"}),
            approval_ctx(),
            state.clone(),
        ).await;

        // Simulate D-Bus approval (calls store.approve directly)
        let pending = state.approvals.pending_requests();
        state.approvals.approve(&pending[0].id);

        // Retry should succeed (grant cached by approve)
        let result = handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "content"}),
            approval_ctx(),
            state.clone(),
        ).await;
        assert!(text_of(&result).contains("Written"));
    }
}
