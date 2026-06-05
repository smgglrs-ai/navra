//! ACP v0.2.0 (Agent Communication Protocol) implementation.
//!
//! Provides types, run store, agent manifest builder, and dispatch
//! logic for the ACP RESTful API. The HTTP router lives in
//! `crate::transport::acp`.

pub mod agents;
pub mod dispatch;
pub mod store;
pub mod types;

pub use dispatch::{RunDispatcher, ToolDispatcher};
