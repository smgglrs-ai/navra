//! Lightweight MCP module API for navra tool crates.
//!
//! This crate provides the `Module` trait, handler type aliases,
//! and re-exports from `navra-protocol`, `navra-auth`, `navra-model`,
//! and `navra-safety-hooks`. Tool crates depend on this instead of
//! `navra-core` to avoid pulling in server infrastructure (McpServer,
//! Axum transport, metrics, blackbox, session store).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

// Re-export dependency crates for consumer convenience.
pub use navra_auth::auth;
pub use navra_auth::identity;
pub use navra_auth::ifc;
pub use navra_auth::permissions;
pub use navra_auth::process;
pub use navra_auth::quota;
pub use navra_safety_hooks::hooks;
pub use navra_safety_hooks::safety;

pub use navra_protocol as protocol;
pub use navra_protocol::RetryConfig;

pub use navra_model as models;

use navra_auth::auth::CallContext;
use navra_protocol::{
    CallToolResult, GetPromptResult, PromptDefinition, ReadResourceResult, ResourceDefinition,
    ToolDefinition,
};

/// Async tool handler function type.
pub type ToolHandler = Arc<
    dyn Fn(serde_json::Value, CallContext) -> Pin<Box<dyn Future<Output = CallToolResult> + Send>>
        + Send
        + Sync,
>;

/// Async prompt handler function type.
pub type PromptHandler = Arc<
    dyn Fn(
            HashMap<String, String>,
            CallContext,
        ) -> Pin<Box<dyn Future<Output = GetPromptResult> + Send>>
        + Send
        + Sync,
>;

/// Async resource handler function type.
pub type ResourceHandler = Arc<
    dyn Fn(String, CallContext) -> Pin<Box<dyn Future<Output = ReadResourceResult> + Send>>
        + Send
        + Sync,
>;

/// Classified operation type for a tool (used by upstream module).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOperation {
    Read,
    Write,
    Deny,
}

/// A feature module that contributes tools and prompts to the MCP server.
///
/// Modules are the unit of composition in navra. Each module provides
/// a set of tools and/or prompts with their handlers. The server collects
/// them from all enabled modules and presents them to agents.
///
/// # Naming convention
///
/// Tool names should be prefixed with the module name to avoid
/// collisions: `file_read`, `git_status`, `shell_exec`.
///
/// Operations for the permission engine follow the same pattern:
/// `"read"`, `"write"` (docs), `"git.status"`, `"git.commit"` (git).
pub trait Module: Send + Sync + 'static {
    /// Module name, used in config and logging.
    fn name(&self) -> &str;

    /// Return the tools this module provides.
    ///
    /// Called once at server startup. Each tool is a (definition, handler) pair.
    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)>;

    /// Return the prompts this module provides.
    ///
    /// Called once at server startup. Each prompt is a (definition, handler) pair.
    /// Default implementation returns no prompts.
    fn prompts(&self) -> Vec<(PromptDefinition, PromptHandler)> {
        Vec::new()
    }

    /// Return the resources this module provides.
    ///
    /// Called once at server startup. Each resource is a (definition, handler) pair.
    /// Default implementation returns no resources.
    fn resources(&self) -> Vec<(ResourceDefinition, ResourceHandler)> {
        Vec::new()
    }
}
