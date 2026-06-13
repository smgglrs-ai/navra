//! GitHub forge module for navra.
//!
//! **DEPRECATED**: This crate is slated for removal. GitHub access should go
//! through the official GitHub MCP server (or a similar upstream MCP server)
//! with token-scoped permissions and per-project policies. Navra's role is
//! gateway-level concerns (PII, IFC, audit), not service-specific access control.
//!
//! Provides tools for interacting with GitHub via the `gh` CLI:
//! PR and issue listing, creation, viewing, and commenting.

pub mod graphql;
mod tools;

pub use tools::GithubModule;
