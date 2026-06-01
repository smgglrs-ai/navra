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
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

pub use builder::McpServerBuilder;
pub use handlers::{IFCToolFilter, ToolFilter};
pub use types::ToolHandler;

use types::{RegisteredPrompt, RegisteredResource, RegisteredResourceTemplate, RegisteredTool};

/// The MCP server, holding all state and tool/prompt/resource registrations.
pub struct McpServer {
    pub(crate) name: String,
    pub(crate) version: String,
    tools: HashMap<String, RegisteredTool>,
    prompts: HashMap<String, RegisteredPrompt>,
    resources: HashMap<String, RegisteredResource>,
    resource_templates: Vec<RegisteredResourceTemplate>,
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
    /// IFC read clearance per permission set (no-read-up enforcement).
    ifc_read_clearances: HashMap<String, crate::ifc::ReadClearance>,
    /// Trusted path patterns per permission set (skip Untrusted labeling).
    trusted_paths: HashMap<String, Vec<String>>,
    /// Per-value variable store for IFC tracking.
    value_stores: crate::ifc::value_store::ValueStoreMap,
    /// Gateway-level audit blackbox — records every tool call.
    blackbox: Option<Arc<crate::blackbox::Blackbox>>,
    /// Per-session dynamic permission grants (MCP permission negotiation).
    session_permissions: crate::permissions::SessionPermissionStore,
    /// Pending permission requests awaiting grant/deny.
    pending_permission_requests: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, PendingPermissionRequest>>,
    >,
    /// SSE broadcaster for server-initiated notifications.
    broadcaster: Option<crate::transport::sse::SseBroadcaster>,
    /// Resource subscriptions: session_id → set of subscribed resource URIs.
    resource_subscriptions: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Per-session log level filter (MCP logging/setLevel).
    session_log_levels: Arc<RwLock<HashMap<String, navra_protocol::LoggingLevel>>>,
    /// Tool disclosure rules per permission set (progressive tool disclosure).
    tool_disclosure: HashMap<String, navra_security::permissions::ToolDisclosure>,
    /// Dynamic tool filters applied during `tools/list` (runtime context-aware).
    dynamic_filters: Vec<Box<dyn ToolFilter>>,
    /// Prometheus metrics counters.
    pub(crate) metrics: Arc<crate::metrics::Metrics>,
    /// Optional Cedar policy engine for conditional access control.
    #[cfg(feature = "cedar")]
    cedar_engine: Option<navra_security::permissions::CedarEngine>,
    /// MCP protocol version — "2025-03-26" (default) or "2026-07-28" (stateless).
    mcp_version: String,
}

/// A pending permission request awaiting grant or deny.
#[derive(Debug, Clone)]
pub(crate) struct PendingPermissionRequest {
    pub session_id: String,
    pub agent_name: String,
    pub scope: navra_protocol::permissions::PermissionScope,
    pub duration_secs: Option<u64>,
}

impl McpServer {
    pub fn builder() -> McpServerBuilder {
        McpServerBuilder::new()
    }

    /// Broadcast a notification to all active SSE sessions.
    pub fn notify(&self, method: &str, params: Option<serde_json::Value>) {
        if let Some(ref broadcaster) = self.broadcaster {
            let notification = crate::transport::sse::make_notification(method, params);
            broadcaster.broadcast(&notification);
        }
    }

    /// Send a notification to a specific session.
    pub fn notify_session(
        &self,
        session_id: &str,
        method: &str,
        params: Option<serde_json::Value>,
    ) {
        if let Some(ref broadcaster) = self.broadcaster {
            let notification = crate::transport::sse::make_notification(method, params);
            broadcaster.send_to_session(session_id, &notification);
        }
    }

    /// Get a reference to the broadcaster (for progress callbacks).
    pub fn broadcaster(&self) -> Option<&crate::transport::sse::SseBroadcaster> {
        self.broadcaster.as_ref()
    }

    /// Access the gateway metrics registry.
    pub fn metrics(&self) -> &Arc<crate::metrics::Metrics> {
        &self.metrics
    }
}

#[cfg(test)]
mod tests;
