//! navra-security: Facade re-exporting navra-auth and navra-safety.
//!
//! New code should depend on `navra-auth` or `navra-safety` directly.

pub use navra_auth::auth;
pub use navra_auth::credentials;
pub use navra_auth::identity;
pub use navra_auth::ifc;
pub use navra_auth::manifest;
pub use navra_auth::notify;
pub use navra_auth::permissions;
pub use navra_auth::process;
pub use navra_auth::quota;
pub use navra_auth::tool_scanner;
pub use navra_auth::trust_score;

pub use navra_safety::hooks;
pub use navra_safety::integrity_monitor;
pub use navra_safety::safety;
