use smgglrs_core::auth::CallContext;
use smgglrs_core::permissions::PermissionResult;
use smgglrs_core::protocol::CallToolResult;
use std::path::Path;
use std::sync::Arc;

use super::path_security::*;
use super::state::DocsState;

pub(super) async fn handle_search(
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

    if !state.perm_engine.has_operation(&ctx.agent.permissions, "search")
        && !ctx.agent.capabilities.as_ref().map_or(false, |c| c.operations.contains("search"))
    {
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
                .check_with_capabilities(
                    &ctx.agent.permissions, "read", Path::new(&r.path),
                    ctx.agent.capabilities.as_ref(),
                )
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

pub(super) async fn handle_read(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path_with_root(raw_path, true, state.default_root.as_deref()) {
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

pub(super) async fn handle_list(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path_with_root(raw_path, true, state.default_root.as_deref()) {
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

pub(super) async fn handle_write(
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

    let path = match resolve_path_with_root(raw_path, false, state.default_root.as_deref()) {
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

pub(super) async fn handle_edit(
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

    let path = match resolve_path_with_root(raw_path, true, state.default_root.as_deref()) {
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

pub(super) async fn handle_info(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path_with_root(raw_path, true, state.default_root.as_deref()) {
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

pub(super) async fn handle_delete(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path_with_root(raw_path, true, state.default_root.as_deref()) {
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
pub(super) async fn handle_tree(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<DocsState>,
) -> CallToolResult {
    let raw_path = args.get("path")
        .and_then(|v| v.as_str())
        .filter(|p| !p.is_empty() && *p != "." && *p != "./")
        .or(state.default_root.as_deref())
        .unwrap_or("/");

    let root = match resolve_path_with_root(raw_path, true, state.default_root.as_deref()) {
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

    let max_depth = args.get("max_depth")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);

    let max_files = args.get("max_files")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(500);

    let mut entries: Vec<(String, usize)> = Vec::new();
    collect_tree(&root, &root, &extension_filter, max_depth, 0, &mut entries);
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let total = entries.len();
    let truncated = total > max_files;
    if truncated {
        entries.truncate(max_files);
    }

    let mut output = format!("{} files found", total);
    if let Some(ref ext) = extension_filter {
        output.push_str(&format!(" (*.{})", ext));
    }
    if truncated {
        output.push_str(&format!(" — showing first {max_files}, use max_depth or path to narrow"));
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
    max_depth: Option<usize>,
    current_depth: usize,
    entries: &mut Vec<(String, usize)>,
) {
    if let Some(max) = max_depth {
        if current_depth >= max {
            return;
        }
    }
    let Ok(read_dir) = std::fs::read_dir(dir) else { return };
    for entry in read_dir.flatten() {
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
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
            collect_tree(&path, root, ext_filter, max_depth, current_depth + 1, entries);
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
pub(super) async fn handle_grep(
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

    let root = match resolve_path_with_root(raw_path, true, state.default_root.as_deref()) {
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

pub(super) async fn handle_approve(
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

pub(super) async fn handle_deny(
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

pub(super) async fn handle_semantic_search(
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
    let embed_request = smgglrs_core::models::EmbedRequest {
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
            use smgglrs_core::permissions::PermissionResult;
            let filtered: Vec<_> = results.iter().filter(|r| {
                let path = std::path::Path::new(&r.path);
                matches!(
                    state.perm_engine.check_with_capabilities(
                        &ctx.agent.permissions, "search", path,
                        ctx.agent.capabilities.as_ref(),
                    ),
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
