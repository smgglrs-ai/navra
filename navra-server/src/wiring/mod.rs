//! Wiring submodules extracted from `serve_inner()`.
//!
//! Each submodule handles a bounded section of server initialization:
//! authentication, safety pipelines, upstream MCP connections, hooks,
//! and transport setup.

pub(crate) mod auth;
pub(crate) mod hooks;
pub(crate) mod safety;
pub(crate) mod transport;
pub(crate) mod upstream;
