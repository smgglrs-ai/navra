//! Causal provenance hook: records causal relationships between tool calls.
//!
//! An observation-only post-hook that creates causal graph nodes for each
//! tool call and its result. Never modifies results.

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use smgglrs_protocol::CallToolResult;
use std::sync::Arc;

/// Trait for causal graph storage, decoupling smgglrs-security from smgglrs-flow.
///
/// Same decoupling pattern as `ExtractionStore` in `memory_extraction.rs`.
/// The concrete implementation (`CausalGraphStore`) lives in smgglrs-flow;
/// the server wires it at startup.
pub trait CausalSink: Send + Sync + 'static {
    fn record_tool_call(
        &self,
        node_id: &str,
        tool_name: &str,
        agent_id: &str,
        session_id: &str,
        input_node_ids: &[String],
    );

    fn record_tool_result(&self, result_node_id: &str, tool_call_node_id: &str);
}

/// Post-hook that records causal provenance for every tool call.
pub struct ProvenanceHook {
    sink: Arc<dyn CausalSink>,
}

impl ProvenanceHook {
    pub fn new(sink: Arc<dyn CausalSink>) -> Self {
        Self { sink }
    }
}

#[async_trait::async_trait]
impl Hook for ProvenanceHook {
    fn name(&self) -> &str {
        "causal-provenance"
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        _result: &CallToolResult,
        ctx: &CallContext,
    ) -> HookDecision {
        let call_node_id = uuid::Uuid::new_v4().to_string();
        let result_node_id = uuid::Uuid::new_v4().to_string();

        self.sink.record_tool_call(
            &call_node_id,
            tool_name,
            &ctx.agent.name,
            &ctx.session_id,
            &[],
        );

        self.sink
            .record_tool_result(&result_node_id, &call_node_id);

        HookDecision::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AgentIdentity;
    use std::sync::Mutex;

    struct TestSink {
        tool_calls: Mutex<Vec<(String, String, String, String)>>,
        tool_results: Mutex<Vec<(String, String)>>,
    }

    impl TestSink {
        fn new() -> Self {
            Self {
                tool_calls: Mutex::new(Vec::new()),
                tool_results: Mutex::new(Vec::new()),
            }
        }
    }

    impl CausalSink for TestSink {
        fn record_tool_call(
            &self,
            node_id: &str,
            tool_name: &str,
            agent_id: &str,
            session_id: &str,
            _input_node_ids: &[String],
        ) {
            self.tool_calls.lock().unwrap().push((
                node_id.to_string(),
                tool_name.to_string(),
                agent_id.to_string(),
                session_id.to_string(),
            ));
        }

        fn record_tool_result(&self, result_node_id: &str, tool_call_node_id: &str) {
            self.tool_results
                .lock()
                .unwrap()
                .push((result_node_id.to_string(), tool_call_node_id.to_string()));
        }
    }

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("agent-a", "dev"), "session-1")
    }

    #[tokio::test]
    async fn hook_records_tool_call_on_post() {
        let sink = Arc::new(TestSink::new());
        let hook = ProvenanceHook::new(Arc::clone(&sink) as Arc<dyn CausalSink>);
        let result = CallToolResult::text("file contents here");
        let ctx = test_ctx();

        hook.post_tool_use(
            "file_read",
            &serde_json::json!({"path": "/etc/hosts"}),
            &result,
            &ctx,
        )
        .await;

        let calls = sink.tool_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, "file_read");
        assert_eq!(calls[0].2, "agent-a");
        assert_eq!(calls[0].3, "session-1");

        let results = sink.tool_results.lock().unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn hook_always_returns_continue() {
        let sink = Arc::new(TestSink::new());
        let hook = ProvenanceHook::new(Arc::clone(&sink) as Arc<dyn CausalSink>);
        let result = CallToolResult::text("ok");
        let ctx = test_ctx();

        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn hook_records_errors_too() {
        let sink = Arc::new(TestSink::new());
        let hook = ProvenanceHook::new(Arc::clone(&sink) as Arc<dyn CausalSink>);
        let result = CallToolResult::error("permission denied");
        let ctx = test_ctx();

        hook.post_tool_use("file_write", &serde_json::json!({}), &result, &ctx)
            .await;

        let calls = sink.tool_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
    }
}
