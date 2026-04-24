mod builder;
mod cards;
mod handlers;
mod types;

use crate::a2a::TaskStore;
use crate::auth::Authenticator;
use crate::hooks::HookPipeline;
use crate::permissions::tool_rules::ToolPermissions;
use crate::process::ProcessTable;
use crate::quota::QuotaEngine;
use crate::safety::FilterPipeline;
use crate::session::SessionStore;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub use builder::McpServerBuilder;
pub use types::ToolHandler;

use types::{RegisteredPrompt, RegisteredResource, RegisteredTool};

/// The MCP server, holding all state and tool/prompt/resource registrations.
pub struct McpServer {
    pub(crate) name: String,
    pub(crate) version: String,
    tools: HashMap<String, RegisteredTool>,
    prompts: HashMap<String, RegisteredPrompt>,
    resources: HashMap<String, RegisteredResource>,
    pub(crate) sessions: SessionStore,
    pub(crate) authenticator: Arc<dyn Authenticator>,
    /// Safety filter pipelines keyed by permission set name (legacy, used when no hooks).
    safety_pipelines: HashMap<String, FilterPipeline>,
    /// Per-tool permission rules keyed by permission set name.
    tool_permissions: HashMap<String, ToolPermissions>,
    /// Hook pipeline for pre/post tool-call interception.
    hooks: HookPipeline,
    /// Shared pause flag — when true, tool calls are rejected.
    paused: Arc<AtomicBool>,
    /// A2A task store for tracking agent-to-agent tasks.
    task_store: TaskStore,
    /// Process table tracking active agent sessions.
    process_table: ProcessTable,
    /// Quota engine for rate limiting.
    quota_engine: QuotaEngine,
    /// IFC policies per permission set (tainted write handling).
    ifc_policies: HashMap<String, crate::ifc::TaintedWritePolicy>,
    /// Trusted path patterns per permission set (skip Untrusted labeling).
    trusted_paths: HashMap<String, Vec<String>>,
    /// Per-value variable store for IFC tracking.
    value_stores: crate::ifc::value_store::ValueStoreMap,
    /// Gateway-level audit blackbox — records every tool call.
    blackbox: Option<crate::blackbox::Blackbox>,
}

impl McpServer {
    pub fn builder() -> McpServerBuilder {
        McpServerBuilder::new()
    }
}

#[cfg(test)]
mod tests;
