pub(crate) mod fd_resolve;
mod handlers;
mod path_security;
mod state;

use crate::store::IndexStore;
use navra_core::models::ModelBackend;
use navra_core::notify::Notifier;
use navra_core::permissions::{ApprovalStore, PermissionEngine};
use navra_core::protocol::{
    ReadResourceResult, ResourceContent, ResourceDefinition, ToolDefinition,
};
use navra_core::ToolHandler;
use navra_core::{Module, ResourceHandler};
use std::sync::Arc;

use handlers::*;
use state::DocsState;

/// File management module for navra.
pub struct FileModule {
    state: Arc<DocsState>,
}

impl FileModule {
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

    /// Set the default root path for file_tree when no path is specified.
    /// The path is canonicalized at construction time to prevent traversal attacks.
    pub fn set_default_root(&mut self, path: String) {
        let canonical = match std::path::Path::new(&path).canonicalize() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "Failed to canonicalize default_root, using as-is");
                path
            }
        };
        // Replace the Arc entirely to avoid Arc::get_mut issues
        let old = &*self.state;
        self.state = Arc::new(DocsState {
            perm_engine: old.perm_engine.clone(),
            index: old.index.clone(),
            approvals: old.approvals.clone(),
            notifier: old.notifier.clone(),
            embedding_model: old.embedding_model.clone(),
            default_root: Some(canonical),
        });
    }
}

impl Module for FileModule {
    fn name(&self) -> &str {
        "file"
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        let s = self.state.clone();
        let mut tools = vec![
            handle_search_handler(s.clone()),
            handle_read_handler(s.clone()),
            handle_list_handler(s.clone()),
            handle_write_handler(s.clone()),
            handle_edit_handler(s.clone()),
            handle_info_handler(s.clone()),
            handle_delete_handler(s.clone()),
            handle_approve_handler(s.clone()),
            handle_deny_handler(s.clone()),
            handle_tree_handler(s.clone()),
            handle_grep_handler(s.clone()),
        ];

        // Add semantic search tool if embedding model is available
        if s.embedding_model.is_some() && s.index.has_vectors() {
            tools.push(handle_semantic_search_handler(s.clone()));
        }

        tools
    }

    fn resources(&self) -> Vec<(ResourceDefinition, ResourceHandler)> {
        let s = self.state.clone();
        let root_resource = ResourceDefinition {
            uri: "file:///".to_string(),
            name: "File system".to_string(),
            description: Some(
                "Read files via file:// URIs. Applies the same ACL checks as file_read."
                    .to_string(),
            ),
            mime_type: None,
            size: None,
        };
        let handler: ResourceHandler = Arc::new(move |uri: String, _ctx| {
            let state = s.clone();
            Box::pin(async move { handle_resource_read(uri, state).await })
        });
        vec![(root_resource, handler)]
    }
}

/// Handle a resources/read request for a file:// URI.
///
/// This is a read-only path that applies the same ACL checks as
/// the file_read tool. No CallContext is available here (resource
/// reads are not tool calls), so we check path ACLs with the
/// "readonly" permission set as a baseline.
async fn handle_resource_read(uri: String, state: Arc<DocsState>) -> ReadResourceResult {
    let path_str = match uri.strip_prefix("file://") {
        Some(p) => p,
        None => {
            return ReadResourceResult {
                contents: vec![ResourceContent {
                    uri,
                    mime_type: Some("text/plain".to_string()),
                    text: Some("Invalid URI: must start with file://".to_string()),
                    blob: None,
                }],
            };
        }
    };

    let path = match path_security::resolve_path_with_root(
        path_str,
        true,
        state.default_root.as_deref(),
    ) {
        Ok(p) => p,
        Err(e) => {
            return ReadResourceResult {
                contents: vec![ResourceContent {
                    uri,
                    mime_type: Some("text/plain".to_string()),
                    text: Some(format!("Error: {e}")),
                    blob: None,
                }],
            };
        }
    };

    // ACL check: resources/read uses the "readonly" permission set
    // since there is no agent context available at the resource layer.
    use navra_core::permissions::PermissionResult;
    let perm = state
        .perm_engine
        .check(&"readonly".to_string(), "read", &path);
    if perm != PermissionResult::Allowed {
        return ReadResourceResult {
            contents: vec![ResourceContent {
                uri,
                mime_type: Some("text/plain".to_string()),
                text: Some("Access denied".to_string()),
                blob: None,
            }],
        };
    }

    if !path.is_file() {
        return ReadResourceResult {
            contents: vec![ResourceContent {
                uri,
                mime_type: Some("text/plain".to_string()),
                text: Some(format!("Not a file: {}", path.display())),
                blob: None,
            }],
        };
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "Resource read failed");
            return ReadResourceResult {
                contents: vec![ResourceContent {
                    uri,
                    mime_type: Some("text/plain".to_string()),
                    text: Some("Read failed".to_string()),
                    blob: None,
                }],
            };
        }
    };

    let mime = path_security::mime_from_path(&path);
    ReadResourceResult {
        contents: vec![ResourceContent {
            uri,
            mime_type: Some(mime.to_string()),
            text: Some(content),
            blob: None,
        }],
    }
}

#[cfg(test)]
mod tests;
