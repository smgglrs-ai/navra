//! navra-auth: Authentication, authorization, and identity primitives.
//!
//! Provides the non-ML security layer for the MCP gateway:
//!
//! - **auth** — BLAKE3 token authentication, OAuth, capability tokens
//! - **permissions** — Deny-wins path ACLs, Cedar policies, tool-level rules
//! - **identity** — Ed25519 `did:key` signing (`CapSigner`, `Ed25519Signer`)
//! - **credentials** — Secret storage with `CredentialStore` trait
//! - **ifc** — Information flow control with `DataLabel` taint tracking
//! - **quota** — Per-agent rate limiting (`QuotaEngine`)
//! - **process** — Live call tracking (`ProcessTable`)
//! - **manifest** — Tool manifest signing and TOFU key pinning
//! - **notify** — D-Bus desktop notifications
//! - **tool_scanner** — Supply-chain threat scanning
//! - **trust_score** — Trust scoring

pub mod auth;
pub mod credentials;
pub mod identity;
pub mod ifc;
pub mod manifest;
pub mod notify;
pub mod permissions;
pub mod process;
pub mod quota;
pub mod tool_scanner;
pub mod trust_score;
