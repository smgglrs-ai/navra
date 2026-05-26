//! smgglrs-security: Security layer for the MCP gateway.
//!
//! Enforces authentication, authorization, and content safety between
//! AI agents and local resources. Key subsystems:
//!
//! - **auth** — BLAKE3 token authentication
//! - **permissions** — Deny-wins path ACLs and tool-level rules
//! - **hooks** — Pre/post tool-call pipeline (`HookPipeline`)
//! - **safety** — Regex and ML content filters (`MlFilter`, `Finding`)
//! - **ifc** — Information flow control with `DataLabel` taint tracking
//! - **identity** — Ed25519 `did:key` signing (`CapSigner`, `Ed25519Signer`)
//! - **credentials** — Secret storage with `CredentialStore` trait
//! - **quota** — Per-agent rate limiting (`QuotaEngine`)
//! - **process** — Live call tracking (`ProcessTable`)

pub mod auth;
pub mod credentials;
pub mod hooks;
pub mod identity;
pub mod ifc;
pub mod integrity_monitor;
pub mod notify;
pub mod permissions;
pub mod process;
pub mod quota;
pub mod safety;
pub mod tool_scanner;
pub mod trust_score;
