//! MCP server framework and module system for navra.
//!
//! This crate provides the `Module` trait, `McpServer` builder, session
//! management, transport layer, and re-exports from `navra-auth`,
//! `navra-safety`, `navra-protocol`, and `navra-model`. Downstream
//! module crates (tools-\*, rag, modal-\*, memory) depend only on
//! this crate.
pub use navra_auth::auth;
pub use navra_auth::credentials;
pub use navra_auth::identity;
pub use navra_auth::ifc;
pub use navra_auth::notify;
pub use navra_auth::permissions;
pub use navra_auth::process;
pub use navra_auth::quota;
pub use navra_safety::hooks;
pub use navra_safety::safety;

pub use navra_protocol as protocol;
pub use navra_protocol::upstream;

pub use navra_model as models;

// Core modules (owned by this crate)
pub mod a2a;
pub mod acp;
pub mod blackbox;
pub mod metrics;
pub mod transport;

pub mod grpc_module;
mod module;
mod server;
pub mod session;
mod upstream_module;

pub use grpc_module::GrpcModule;
pub use module::{serve_module, Module, PromptHandler, ResourceHandler};
pub use server::{
    McpServer, McpServerBuilder, ToolFilter, ToolHandler, ToolUsageTracker, UsagePruningFilter,
};
pub use session::Session;
pub use navra_protocol::{RetryConfig, Upstream};
pub use upstream_module::{ToolOperation, UpstreamModule};

/// Re-export dispatch for unit tests (not part of public API).
#[cfg(test)]
pub(crate) use transport::streamable::dispatch::dispatch as dispatch_for_test;
