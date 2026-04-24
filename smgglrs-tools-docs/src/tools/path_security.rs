use crate::store::IndexStore;
use smgglrs_core::auth::CallContext;
use smgglrs_core::models::ModelBackend;
use smgglrs_core::notify::Notifier;
use smgglrs_core::permissions::{ApprovalStore, PermissionEngine, PermissionResult};
use smgglrs_core::protocol::CallToolResult;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::state::DocsState;

pub(super) fn resolve_path(raw: &str, must_exist: bool) -> Result<PathBuf, String> {
    resolve_path_with_root(raw, must_exist, None)
}

pub(super) fn resolve_path_with_root(raw: &str, must_exist: bool, default_root: Option<&str>) -> Result<PathBuf, String> {
    let expanded = if raw.starts_with("~/") {
        match dirs::home_dir() {
            Some(home) => home.join(&raw[2..]),
            None => return Err("Cannot resolve home directory".to_string()),
        }
    } else {
        PathBuf::from(raw)
    };

    let expanded = if !expanded.is_absolute() {
        match default_root {
            Some(root) => PathBuf::from(root).join(&expanded),
            None => return Err(format!("Path must be absolute: {raw}")),
        }
    } else {
        expanded
    };

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
pub(super) async fn check_perm(
    state: &DocsState,
    ctx: &CallContext,
    op: &str,
    path: &Path,
) -> Result<(), CallToolResult> {
    match state.perm_engine.check_with_capabilities(
        &ctx.agent.permissions, op, path, ctx.agent.capabilities.as_ref(),
    ) {
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
                smgglrs_core::protocol::Content::text(format!(
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

pub(super) fn mime_from_path(path: &Path) -> &'static str {
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

pub(super) fn extract_title(path: &Path, content: &str) -> String {
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
pub(super) async fn maybe_embed(state: &DocsState, doc_id: i64, content: &str) {
    let model = match &state.embedding_model {
        Some(m) => m,
        None => return,
    };
    if !state.index.has_vectors() {
        return;
    }

    let request = smgglrs_core::models::EmbedRequest {
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

pub(super) fn chrono_now() -> String {
    use std::time::{Duration, SystemTime};
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    format!("{}", since_epoch.as_secs())
}

pub(super) fn simple_checksum(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}
