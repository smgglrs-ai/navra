//! GitLab forge module for smgglrs.
//!
//! Provides tools for interacting with GitLab via the `glab` CLI:
//! MR and issue listing, creation, viewing, and commenting.

mod tools;

pub use tools::GitlabModule;
