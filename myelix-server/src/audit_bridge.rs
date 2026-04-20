//! Bridge between myelix-agent's AuditCallback trait and
//! myelix-memory's AuditLog storage.

use myelix_agent::AuditCallback;
use myelix_memory::audit::{AuditLog, AuditModelCall, AuditToolCall};
use std::sync::Arc;

/// Wraps an AuditLog and implements AuditCallback so the agent's
/// tool loop can record entries directly to SQLite.
pub struct AuditBridge {
    log: Arc<AuditLog>,
    run_id: String,
    agent_id: String,
}

impl AuditBridge {
    pub fn new(log: Arc<AuditLog>, run_id: &str, agent_id: &str) -> Self {
        Self {
            log,
            run_id: run_id.to_string(),
            agent_id: agent_id.to_string(),
        }
    }
}

impl AuditCallback for AuditBridge {
    fn on_tool_call(
        &self,
        iteration: u32,
        tool_name: &str,
        args: &str,
        result: &str,
        duration_ms: u64,
    ) {
        let entry = AuditToolCall {
            run_id: self.run_id.clone(),
            agent_id: self.agent_id.clone(),
            iteration,
            timestamp_ms: now_ms(),
            tool_name: tool_name.to_string(),
            tool_args: args.to_string(),
            tool_result: result.to_string(),
            duration_ms,
            acl_decision: None,
            ifc_label: None,
        };
        if let Err(e) = self.log.log_tool_call(&entry) {
            tracing::warn!(error = %e, "Failed to write audit tool call");
        }
    }

    fn on_model_call(
        &self,
        iteration: u32,
        input_tokens: u32,
        output_tokens: u32,
        response_type: &str,
        reasoning: Option<&str>,
    ) {
        let entry = AuditModelCall {
            run_id: self.run_id.clone(),
            agent_id: self.agent_id.clone(),
            iteration,
            timestamp_ms: now_ms(),
            model_name: None,
            input_tokens,
            output_tokens,
            response_type: response_type.to_string(),
            reasoning_text: reasoning.map(String::from),
        };
        if let Err(e) = self.log.log_model_call(&entry) {
            tracing::warn!(error = %e, "Failed to write audit model call");
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
