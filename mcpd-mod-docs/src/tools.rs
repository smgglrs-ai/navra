use crate::store::IndexStore;
use mcpd_core::auth::CallContext;
use mcpd_core::permissions::{PermissionEngine, PermissionResult};
use mcpd_core::protocol::{CallToolResult, ToolDefinition, ToolInputSchema};
use mcpd_core::ToolHandler;
use mcpd_core::Module;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Document management module for mcpd.
pub struct DocsModule {
    state: Arc<DocsState>,
}

struct DocsState {
    perm_engine: Arc<PermissionEngine>,
    index: Arc<IndexStore>,
}

impl DocsModule {
    pub fn new(perm_engine: Arc<PermissionEngine>, index: Arc<IndexStore>) -> Self {
        Self {
            state: Arc::new(DocsState { perm_engine, index }),
        }
    }
}

impl Module for DocsModule {
    fn name(&self) -> &str {
        "docs"
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        let s = self.state.clone();
        vec![
            make_tool(search_tool_def(), s.clone(), handle_search),
            make_tool(read_tool_def(), s.clone(), handle_read),
            make_tool(list_tool_def(), s.clone(), handle_list),
            make_tool(write_tool_def(), s.clone(), handle_write),
            make_tool(edit_tool_def(), s.clone(), handle_edit),
            make_tool(info_tool_def(), s.clone(), handle_info),
            make_tool(delete_tool_def(), s.clone(), handle_delete),
        ]
    }
}

/// Helper to create a (ToolDefinition, ToolHandler) pair from a sync handler function.
fn make_tool(
    def: ToolDefinition,
    state: Arc<DocsState>,
    handler: fn(serde_json::Value, CallContext, &DocsState) -> CallToolResult,
) -> (ToolDefinition, ToolHandler) {
    let h: ToolHandler = Arc::new(move |args, ctx| {
        let s = state.clone();
        Box::pin(async move { handler(args, ctx, &s) })
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
        expanded
            .canonicalize()
            .map_err(|e| format!("Cannot resolve path {raw}: {e}"))
    } else {
        match expanded.parent() {
            Some(parent) => {
                let canon_parent = parent
                    .canonicalize()
                    .map_err(|e| format!("Parent directory does not exist for {raw}: {e}"))?;
                match expanded.file_name() {
                    Some(name) => Ok(canon_parent.join(name)),
                    None => Err(format!("Invalid path: {raw}")),
                }
            }
            None => Err(format!("Invalid path: {raw}")),
        }
    }
}

fn check_perm(
    state: &DocsState,
    ctx: &CallContext,
    op: &str,
    path: &Path,
) -> Result<(), CallToolResult> {
    match state.perm_engine.check(&ctx.agent.permissions, op, path) {
        PermissionResult::Allowed => Ok(()),
        PermissionResult::NeedsApproval => Err(CallToolResult::error(format!(
            "{op} on {} requires approval",
            path.display()
        ))),
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

fn chrono_now() -> String {
    use std::time::SystemTime;
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    format!("{}", since_epoch.as_secs())
}

fn simple_checksum(data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// --- Tool handlers ---

fn handle_search(
    args: serde_json::Value,
    ctx: CallContext,
    state: &DocsState,
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

fn handle_read(
    args: serde_json::Value,
    ctx: CallContext,
    state: &DocsState,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path(raw_path, true) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(state, &ctx, "read", &path) {
        return e;
    }

    if !path.is_file() {
        return CallToolResult::error(format!("Not a file: {}", path.display()));
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => return CallToolResult::error(format!("Failed to read {}: {e}", path.display())),
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

fn handle_list(
    args: serde_json::Value,
    ctx: CallContext,
    state: &DocsState,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path(raw_path, true) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(state, &ctx, "list", &path) {
        return e;
    }

    if !path.is_dir() {
        return CallToolResult::error(format!("Not a directory: {}", path.display()));
    }

    let entries = match std::fs::read_dir(&path) {
        Ok(rd) => rd,
        Err(e) => {
            return CallToolResult::error(format!("Failed to list {}: {e}", path.display()))
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

fn handle_write(
    args: serde_json::Value,
    ctx: CallContext,
    state: &DocsState,
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

    if let Err(e) = check_perm(state, &ctx, "write", &path) {
        return e;
    }

    if let Err(e) = std::fs::write(&path, content) {
        return CallToolResult::error(format!("Failed to write {}: {e}", path.display()));
    }

    let size = content.len() as i64;
    let mime = mime_from_path(&path);
    let title = extract_title(&path, content);
    let path_str = path.to_string_lossy();
    let modified = chrono_now();
    let checksum = simple_checksum(content.as_bytes());

    if let Err(e) = state
        .index
        .upsert(&path_str, mime, size, &modified, &checksum, &title, content)
    {
        tracing::warn!("Failed to index {}: {e}", path.display());
    }

    CallToolResult::text(format!("Written {} bytes to {}", size, path.display()))
}

fn handle_edit(
    args: serde_json::Value,
    ctx: CallContext,
    state: &DocsState,
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

    if let Err(e) = check_perm(state, &ctx, "write", &path) {
        return e;
    }

    if !path.is_file() {
        return CallToolResult::error(format!("Not a file: {}", path.display()));
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => return CallToolResult::error(format!("Failed to read {}: {e}", path.display())),
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
        return CallToolResult::error(format!("Failed to write {}: {e}", path.display()));
    }

    // Re-index
    let size = new_content.len() as i64;
    let mime = mime_from_path(&path);
    let title = extract_title(&path, &new_content);
    let path_str = path.to_string_lossy();
    let modified = chrono_now();
    let checksum = simple_checksum(new_content.as_bytes());

    if let Err(e) = state.index.upsert(
        &path_str, mime, size, &modified, &checksum, &title, &new_content,
    ) {
        tracing::warn!("Failed to index {}: {e}", path.display());
    }

    CallToolResult::text(format!("Edited {}", path.display()))
}

fn handle_info(
    args: serde_json::Value,
    ctx: CallContext,
    state: &DocsState,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path(raw_path, true) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(state, &ctx, "read", &path) {
        return e;
    }

    let metadata = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => {
            return CallToolResult::error(format!(
                "Failed to stat {}: {e}",
                path.display()
            ))
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

fn handle_delete(
    args: serde_json::Value,
    ctx: CallContext,
    state: &DocsState,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path(raw_path, true) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(state, &ctx, "write", &path) {
        return e;
    }

    if !path.is_file() {
        return CallToolResult::error(format!("Not a file: {}", path.display()));
    }

    if let Err(e) = std::fs::remove_file(&path) {
        return CallToolResult::error(format!("Failed to delete {}: {e}", path.display()));
    }

    // Remove from index
    let path_str = path.to_string_lossy();
    if let Err(e) = state.index.delete(&path_str) {
        tracing::warn!("Failed to remove {} from index: {e}", path.display());
    }

    CallToolResult::text(format!("Deleted {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpd_core::auth::AgentIdentity;
    use mcpd_core::permissions::PathAcl;
    use std::collections::HashSet;
    use tempfile::TempDir;

    fn test_state(tmpdir: &TempDir) -> Arc<DocsState> {
        let mut engine = PermissionEngine::new();
        engine.add_permission_set(
            "dev".to_string(),
            PathAcl {
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
        })
    }

    fn dev_ctx() -> CallContext {
        CallContext {
            agent: AgentIdentity {
                name: "test-agent".to_string(),
                permissions: "dev".to_string(),
            },
            session_id: "test".to_string(),
        }
    }

    fn readonly_ctx() -> CallContext {
        CallContext {
            agent: AgentIdentity {
                name: "reader".to_string(),
                permissions: "readonly".to_string(),
            },
            session_id: "test".to_string(),
        }
    }

    fn text_of(result: &CallToolResult) -> &str {
        match &result.content[0] {
            mcpd_core::protocol::Content::Text(t) => &t.text,
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

    #[test]
    fn read_full_file() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("hello.txt");
        std::fs::write(&file, "Hello, world!").unwrap();

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            &state,
        );
        assert!(!result.is_error);
        assert!(text_of(&result).contains("Hello, world!"));
        assert!(text_of(&result).contains("1 lines"));
    }

    #[test]
    fn read_partial_with_offset_and_limit() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("multi.txt");
        std::fs::write(&file, "line1\nline2\nline3\nline4\nline5\n").unwrap();

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap(), "offset": 2, "limit": 2}),
            dev_ctx(),
            &state,
        );
        assert!(!result.is_error);
        let text = text_of(&result);
        assert!(text.contains("lines 2-3 of"));
        assert!(text.contains("line2"));
        assert!(text.contains("line3"));
        assert!(!text.contains("line1"));
        assert!(!text.contains("line4"));
    }

    #[test]
    fn read_denied_path() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let secret_dir = tmp.path().join(".secret");
        std::fs::create_dir(&secret_dir).unwrap();
        let file = secret_dir.join("key.pem");
        std::fs::write(&file, "private key").unwrap();

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            &state,
        );
        assert!(result.is_error);
        assert!(text_of(&result).contains("denied"));
    }

    // --- write ---

    #[test]
    fn write_new_file() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("new.md");

        let result = handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "# Hello\n\nWorld"}),
            dev_ctx(),
            &state,
        );
        assert!(!result.is_error);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "# Hello\n\nWorld");
    }

    #[test]
    fn write_denied_for_readonly() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("nope.txt");

        let result = handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "fail"}),
            readonly_ctx(),
            &state,
        );
        assert!(result.is_error);
        assert!(!file.exists());
    }

    // --- edit ---

    #[test]
    fn edit_replaces_unique_string() {
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
            &state,
        );
        assert!(!result.is_error);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "Goodbye world, this is a test."
        );
    }

    #[test]
    fn edit_fails_if_not_found() {
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
            &state,
        );
        assert!(result.is_error);
        assert!(text_of(&result).contains("not found"));
    }

    #[test]
    fn edit_fails_if_not_unique() {
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
            &state,
        );
        assert!(result.is_error);
        assert!(text_of(&result).contains("2 times"));
        // File should be unchanged
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "foo bar foo baz");
    }

    #[test]
    fn edit_denied_for_readonly() {
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
            &state,
        );
        assert!(result.is_error);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "content");
    }

    // --- info ---

    #[test]
    fn info_returns_metadata() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("info.md");
        std::fs::write(&file, "line1\nline2\nline3\n").unwrap();

        let result = handle_info(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            &state,
        );
        assert!(!result.is_error);
        let text = text_of(&result);
        assert!(text.contains("type: file"));
        assert!(text.contains("lines: 3"));
        assert!(text.contains("mime: text/markdown"));
        assert!(text.contains("indexed: false"));
    }

    // --- delete ---

    #[test]
    fn delete_removes_file() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("doomed.txt");
        std::fs::write(&file, "goodbye").unwrap();

        let result = handle_delete(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            &state,
        );
        assert!(!result.is_error);
        assert!(!file.exists());
    }

    #[test]
    fn delete_denied_for_readonly() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("safe.txt");
        std::fs::write(&file, "safe").unwrap();

        let result = handle_delete(
            serde_json::json!({"path": file.to_str().unwrap()}),
            readonly_ctx(),
            &state,
        );
        assert!(result.is_error);
        assert!(file.exists());
    }

    // --- list ---

    #[test]
    fn list_directory() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        std::fs::write(tmp.path().join("a.txt"), "aaa").unwrap();
        std::fs::create_dir(tmp.path().join("subdir")).unwrap();

        let result = handle_list(
            serde_json::json!({"path": tmp.path().to_str().unwrap()}),
            dev_ctx(),
            &state,
        );
        assert!(!result.is_error);
        let text = text_of(&result);
        assert!(text.contains("a.txt"));
        assert!(text.contains("subdir/"));
    }

    // --- search ---

    #[test]
    fn search_returns_results() {
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
            &state,
        );
        assert!(!result.is_error);
        assert!(text_of(&result).contains("1 result"));
    }

    // --- module trait ---

    #[test]
    fn module_provides_all_tools() {
        let engine = Arc::new(PermissionEngine::new());
        let index = Arc::new(IndexStore::open_memory().unwrap());
        let module = DocsModule::new(engine, index);

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
        assert_eq!(tools.len(), 7);
    }

    // --- roundtrips ---

    #[test]
    fn write_then_read_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("rt.md");

        handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "# RT\n\nContent."}),
            dev_ctx(),
            &state,
        );

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            &state,
        );
        assert!(text_of(&result).contains("# RT\n\nContent."));
    }

    #[test]
    fn write_edit_read_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("edit_rt.md");

        handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "Hello world"}),
            dev_ctx(),
            &state,
        );

        handle_edit(
            serde_json::json!({
                "path": file.to_str().unwrap(),
                "old_string": "Hello world",
                "new_string": "Goodbye world"
            }),
            dev_ctx(),
            &state,
        );

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            &state,
        );
        assert!(text_of(&result).contains("Goodbye world"));
    }

    #[test]
    fn write_then_search_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("searchable.md");

        handle_write(
            serde_json::json!({
                "path": file.to_str().unwrap(),
                "content": "# K8s Guide\n\nDeploy pods with kubectl."
            }),
            dev_ctx(),
            &state,
        );

        let result = handle_search(
            serde_json::json!({"query": "kubectl deploy"}),
            dev_ctx(),
            &state,
        );
        assert!(text_of(&result).contains("1 result"));
    }

    #[test]
    fn write_delete_read_fails() {
        let tmp = TempDir::new().unwrap();
        let state = test_state(&tmp);
        let file = tmp.path().join("temp.txt");

        handle_write(
            serde_json::json!({"path": file.to_str().unwrap(), "content": "temporary"}),
            dev_ctx(),
            &state,
        );

        handle_delete(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            &state,
        );

        let result = handle_read(
            serde_json::json!({"path": file.to_str().unwrap()}),
            dev_ctx(),
            &state,
        );
        assert!(result.is_error);
    }
}
