//! Command execution tools for navra.
//!
//! Provides the `exec_run` tool for running shell commands with
//! configurable timeouts, working directory, and environment.
//! Supports direct execution, Podman containers, and OpenShell sandboxes.

mod tools;

pub use tools::ExecModule;
