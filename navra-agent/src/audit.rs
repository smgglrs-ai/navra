//! Audit sink trait for recording tool and model calls.
//!
//! navra-agent cannot depend on navra-memory (which depends on
//! navra-core/server). Instead, this trait defines the audit interface
//! and the server provides an implementation backed by AuditLog.

use std::sync::Arc;

/// Sink for audit events emitted by the agent tool loop.
pub trait AuditSink: Send + Sync {
    /// Record a tool call.
    fn log_tool_call(
        &self,
        run_id: &str,
        agent_id: &str,
        iteration: u32,
        tool_name: &str,
        tool_args: &str,
        tool_result: &str,
        duration_ms: u64,
    );

    /// Record a model call.
    fn log_model_call(
        &self,
        run_id: &str,
        agent_id: &str,
        iteration: u32,
        model_name: &str,
        input_tokens: u32,
        output_tokens: u32,
        response_type: &str,
    );
}

/// Convenience type alias.
pub type SharedAuditSink = Arc<dyn AuditSink>;
