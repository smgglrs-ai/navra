//! Execution trace capture for non-deterministic flow analysis.
//!
//! Traces record the sequence of node executions during a flow run.
//! Multiple traces from the same flow definition can be compared
//! using the PTA and dominator modules to extract stable invariants.

use serde::{Deserialize, Serialize};

/// A single event in an execution trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Node (task) ID that produced this event.
    pub node_id: String,
    /// Status of the node: "started", "completed", "failed".
    pub status: String,
    /// Monotonic timestamp in milliseconds (relative to trace start).
    pub timestamp_ms: u64,
    /// Optional hash of the node's output for semantic comparison.
    pub output_hash: Option<String>,
}

/// A complete execution trace from a single flow run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Flow definition ID.
    pub flow_id: String,
    /// Ordered sequence of events captured during execution.
    pub events: Vec<TraceEvent>,
}

impl ExecutionTrace {
    /// Create a new empty trace for the given flow.
    pub fn new(flow_id: impl Into<String>) -> Self {
        Self {
            flow_id: flow_id.into(),
            events: Vec::new(),
        }
    }

    /// Record an event in the trace.
    pub fn record(&mut self, node_id: impl Into<String>, status: impl Into<String>, timestamp_ms: u64) {
        self.events.push(TraceEvent {
            node_id: node_id.into(),
            status: status.into(),
            timestamp_ms,
            output_hash: None,
        });
    }

    /// Return the ordered list of completed node IDs.
    pub fn node_sequence(&self) -> Vec<&str> {
        self.events
            .iter()
            .filter(|e| e.status == "completed")
            .map(|e| e.node_id.as_str())
            .collect()
    }

    /// Return the ordered list of all node IDs regardless of status.
    pub fn all_nodes(&self) -> Vec<&str> {
        self.events
            .iter()
            .map(|e| e.node_id.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trace() {
        let trace = ExecutionTrace::new("flow-1");
        assert_eq!(trace.flow_id, "flow-1");
        assert!(trace.events.is_empty());
        assert!(trace.node_sequence().is_empty());
    }

    #[test]
    fn record_events() {
        let mut trace = ExecutionTrace::new("flow-1");
        trace.record("a", "started", 0);
        trace.record("a", "completed", 10);
        trace.record("b", "started", 11);
        trace.record("b", "completed", 20);

        assert_eq!(trace.events.len(), 4);
        assert_eq!(trace.node_sequence(), vec!["a", "b"]);
    }

    #[test]
    fn node_sequence_filters_completed() {
        let mut trace = ExecutionTrace::new("flow-1");
        trace.record("a", "started", 0);
        trace.record("a", "completed", 10);
        trace.record("b", "started", 11);
        trace.record("b", "failed", 20);
        trace.record("c", "started", 21);
        trace.record("c", "completed", 30);

        assert_eq!(trace.node_sequence(), vec!["a", "c"]);
    }

    #[test]
    fn all_nodes_includes_everything() {
        let mut trace = ExecutionTrace::new("flow-1");
        trace.record("a", "started", 0);
        trace.record("a", "completed", 10);
        trace.record("b", "started", 11);
        trace.record("b", "failed", 20);

        assert_eq!(trace.all_nodes(), vec!["a", "a", "b", "b"]);
    }

    #[test]
    fn serialize_roundtrip() {
        let mut trace = ExecutionTrace::new("flow-1");
        trace.record("a", "completed", 10);
        trace.events[0].output_hash = Some("abc123".to_string());

        let json = serde_json::to_string(&trace).unwrap();
        let deserialized: ExecutionTrace = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.flow_id, "flow-1");
        assert_eq!(deserialized.events.len(), 1);
        assert_eq!(deserialized.events[0].output_hash.as_deref(), Some("abc123"));
    }
}
