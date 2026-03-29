use crate::protocol::ToolDefinition;
use crate::server::ToolHandler;

/// A feature module that contributes tools to the MCP server.
///
/// Modules are the unit of composition in mcpd. Each module provides
/// a set of tools with their handlers. The server collects tools from
/// all enabled modules and presents them to agents.
///
/// # Naming convention
///
/// Tool names should be prefixed with the module name to avoid
/// collisions: `docs_read`, `git_status`, `shell_exec`.
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
}
