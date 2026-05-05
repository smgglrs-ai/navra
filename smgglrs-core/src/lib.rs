// Facade: downstream module crates (tools-*, rag, modal-*, memory, server)
// depend only on smgglrs-core and reach security/protocol/model types
// through these re-exports.  Crates that already have a direct dependency
// on smgglrs-security or smgglrs-protocol (agent, flow, benchmarks) may
// import from those crates directly.
pub use smgglrs_security::auth;
pub use smgglrs_security::credentials;
pub use smgglrs_security::hooks;
pub use smgglrs_security::identity;
pub use smgglrs_security::ifc;
pub use smgglrs_security::notify;
pub use smgglrs_security::permissions;
pub use smgglrs_security::process;
pub use smgglrs_security::quota;
pub use smgglrs_security::safety;

pub use smgglrs_protocol as protocol;
pub use smgglrs_protocol::upstream;

pub use smgglrs_model as models;

// Core modules (owned by this crate)
pub mod a2a;
pub mod blackbox;
pub mod transport;

pub mod grpc_module;
mod module;
mod server;
pub mod session;
mod upstream_module;

pub use module::{Module, PromptHandler, ResourceHandler};
pub use server::{McpServer, McpServerBuilder, ToolHandler};
pub use session::Session;
pub use smgglrs_protocol::{RetryConfig, Upstream};
pub use grpc_module::GrpcModule;
pub use upstream_module::UpstreamModule;

/// Re-export dispatch for unit tests (not part of public API).
#[cfg(test)]
pub(crate) use transport::streamable::dispatch::dispatch as dispatch_for_test;
