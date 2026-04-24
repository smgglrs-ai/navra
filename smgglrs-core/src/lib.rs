// Re-export from smgglrs-security
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

// Re-export from smgglrs-protocol
pub use smgglrs_protocol as protocol;
pub use smgglrs_protocol::upstream;

// Re-export from smgglrs-model
pub use smgglrs_model as models;

// Core modules (owned by this crate)
pub mod a2a;
pub mod blackbox;
pub mod transport;

mod module;
mod server;
pub mod session;
mod upstream_module;

pub use module::{Module, PromptHandler, ResourceHandler};
pub use server::{McpServer, McpServerBuilder, ToolHandler};
pub use session::Session;
pub use smgglrs_protocol::{RetryConfig, Upstream};
pub use upstream_module::UpstreamModule;
