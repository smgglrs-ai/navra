// Facade: downstream module crates (tools-*, rag, modal-*, memory, server)
// depend only on navra-core and reach security/protocol/model types
// through these re-exports.  Crates that already have a direct dependency
// on navra-security or navra-protocol (agent, flow, benchmarks) may
// import from those crates directly.
pub use navra_security::auth;
pub use navra_security::credentials;
pub use navra_security::hooks;
pub use navra_security::identity;
pub use navra_security::ifc;
pub use navra_security::notify;
pub use navra_security::permissions;
pub use navra_security::process;
pub use navra_security::quota;
pub use navra_security::safety;

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
pub use upstream_module::UpstreamModule;

/// Re-export dispatch for unit tests (not part of public API).
#[cfg(test)]
pub(crate) use transport::streamable::dispatch::dispatch as dispatch_for_test;
