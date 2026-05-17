//! GitHub forge module for smgglrs.
//!
//! Provides tools for interacting with GitHub via the `gh` CLI:
//! PR and issue listing, creation, viewing, and commenting.

pub mod graphql;
mod tools;

pub use tools::GithubModule;
