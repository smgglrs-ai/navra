mod definitions;
mod handlers;
mod path_security;
mod state;

use crate::store::IndexStore;
use smgglrs_core::auth::CallContext;
use smgglrs_core::models::ModelBackend;
use smgglrs_core::notify::Notifier;
use smgglrs_core::permissions::{ApprovalStore, PermissionEngine};
use smgglrs_core::protocol::{
    CallToolResult, ReadResourceResult, ResourceContent, ResourceDefinition, ToolDefinition,
};
use smgglrs_core::ToolHandler;
use smgglrs_core::{Module, ResourceHandler};
use std::future::Future;
use std::sync::Arc;

use definitions::*;
use handlers::*;
use state::DocsState;

/// Document management module for smgglrs.
pub struct DocsModule {
    state: Arc<DocsState>,
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

impl Module for DocsModule {
    fn name(&self) -> &str {
        "file"
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
        };
        let handler: ResourceHandler = Arc::new(move |uri: String| {
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
    use smgglrs_core::permissions::PermissionResult;
    let perm = state
        .perm_engine
        .check(&"readonly".to_string(), "read", &path);
    if perm != PermissionResult::Allowed {
        return ReadResourceResult {
            contents: vec![ResourceContent {
                uri,
                mime_type: Some("text/plain".to_string()),
                text: Some(format!("Access denied: {}", path.display())),
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

#[cfg(test)]
mod tests;
