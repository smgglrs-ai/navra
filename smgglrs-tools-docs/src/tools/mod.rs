mod definitions;
mod handlers;
mod path_security;
mod state;

use crate::store::IndexStore;
use smgglrs_core::auth::CallContext;
use smgglrs_core::models::ModelBackend;
use smgglrs_core::notify::Notifier;
use smgglrs_core::permissions::{ApprovalStore, PermissionEngine};
use smgglrs_core::protocol::{CallToolResult, ToolDefinition};
use smgglrs_core::ToolHandler;
use smgglrs_core::Module;
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

#[cfg(test)]
mod tests;
