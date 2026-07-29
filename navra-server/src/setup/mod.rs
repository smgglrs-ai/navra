//! Wiring submodules extracted from `serve_inner()`.
//!
//! Each submodule handles a bounded section of server initialization:
//! authentication, safety pipelines, upstream MCP connections, hooks,
//! model loading, module registration, tool registration, resource
//! registration, and transport setup.

pub(crate) mod auth;
pub(crate) mod hooks;
pub(crate) mod models;
pub(crate) mod modules;
pub(crate) mod resources;
pub(crate) mod safety;
pub(crate) mod tools;
pub(crate) mod transport;
pub(crate) mod upstream;
