// Re-export from myelix-security
pub use myelix_security::auth;
pub use myelix_security::credentials;
pub use myelix_security::hooks;
pub use myelix_security::identity;
pub use myelix_security::ifc;
pub use myelix_security::notify;
pub use myelix_security::permissions;
pub use myelix_security::process;
pub use myelix_security::quota;
pub use myelix_security::safety;

// Re-export from myelix-protocol
pub use myelix_protocol as protocol;
pub use myelix_protocol::upstream;

// Re-export from myelix-model
pub use myelix_model as models;

// Core modules (owned by this crate)
pub mod a2a;
pub mod transport;

mod module;
mod server;
mod session;
mod upstream_module;

pub use module::{Module, PromptHandler, ResourceHandler};
pub use server::{McpServer, McpServerBuilder, ToolHandler};
pub use session::Session;
pub use myelix_protocol::{RetryConfig, Upstream};
pub use upstream_module::UpstreamModule;
