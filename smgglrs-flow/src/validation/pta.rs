//! Prefix Tree Acceptor for generalizing execution traces.
//!
//! Merges multiple execution traces into a tree-shaped state machine.
//! Traces with the same node sequence merge into a single path;
//! different sequences create branches. The PTA can then check
//! whether a new trace matches any previously observed pattern.

use super::trace::ExecutionTrace;

/// A node in the prefix tree.
#[derive(Debug)]
struct PtaNode {
    /// The node_id this state represents, or "" for root.
    state: String,
    /// Child states reachable from this node.
    children: Vec<PtaNode>,
    /// How many traces pass through this node.
    count: usize,
    /// Whether this node is an accepting state (end of a trace).
    accepting: bool,
}

impl PtaNode {
    fn new(state: impl Into<String>) -> Self {
        Self {
            state: state.into(),
            children: Vec::new(),
            count: 0,
            accepting: false,
        }
    }

    /// Find or create a child with the given state, returning its index.
    fn find_or_create_child(&mut self, state: &str) -> usize {
        if let Some(idx) = self.children.iter().position(|c| c.state == state) {
            idx
        } else {
            self.children.push(PtaNode::new(state));
            self.children.len() - 1
        }
    }

    /// Count all nodes in this subtree (including self).
    fn subtree_count(&self) -> usize {
        1 + self.children.iter().map(|c| c.subtree_count()).sum::<usize>()
    }
}

/// A Prefix Tree Acceptor built from execution traces.
///
/// Accepts traces whose completed-node sequence matches any path
/// from root to an accepting state in the tree.
#[derive(Debug)]
pub struct PrefixTreeAcceptor {
    root: PtaNode,
}

impl PrefixTreeAcceptor {
    /// Create an empty PTA.
    pub fn new() -> Self {
        Self {
            root: PtaNode::new(""),
        }
    }

    /// Add a trace to the PTA, merging shared prefixes.
    pub fn add_trace(&mut self, trace: &ExecutionTrace) {
        let seq = trace.node_sequence();
        let mut current = &mut self.root;
        current.count += 1;

        for node_id in &seq {
            let idx = current.find_or_create_child(node_id);
            current = &mut current.children[idx];
            current.count += 1;
        }
        current.accepting = true;
    }

    /// Check whether a trace matches any path in the PTA.
    pub fn accepts(&self, trace: &ExecutionTrace) -> bool {
        let seq = trace.node_sequence();
        let mut current = &self.root;

        for node_id in &seq {
            match current.children.iter().find(|c| c.state == *node_id) {
                Some(child) => current = child,
                None => return false,
            }
        }
        current.accepting
    }

    /// Total number of nodes in the PTA (including root).
    pub fn node_count(&self) -> usize {
        self.root.subtree_count()
    }

    /// Number of traces that have been added.
    pub fn trace_count(&self) -> usize {
        self.root.count
    }
}

impl Default for PrefixTreeAcceptor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::trace::ExecutionTrace;

    fn trace_from_seq(nodes: &[&str]) -> ExecutionTrace {
        let mut trace = ExecutionTrace::new("test-flow");
        for (i, node) in nodes.iter().enumerate() {
            trace.record(*node, "completed", (i * 10) as u64);
        }
        trace
    }

    #[test]
    fn empty_pta_rejects_nonempty_trace() {
        let pta = PrefixTreeAcceptor::new();
        let trace = trace_from_seq(&["a", "b"]);
        assert!(!pta.accepts(&trace));
    }

    #[test]
    fn empty_pta_rejects_empty_trace() {
        let pta = PrefixTreeAcceptor::new();
        let trace = trace_from_seq(&[]);
        // Empty trace is not accepted because root is not an accepting state
        assert!(!pta.accepts(&trace));
    }

    #[test]
    fn identical_traces_single_path() {
        let mut pta = PrefixTreeAcceptor::new();
        let t1 = trace_from_seq(&["a", "b", "c"]);
        let t2 = trace_from_seq(&["a", "b", "c"]);

        pta.add_trace(&t1);
        pta.add_trace(&t2);

        // Two identical traces should produce root + 3 nodes = 4
        assert_eq!(pta.node_count(), 4);
        assert_eq!(pta.trace_count(), 2);
        assert!(pta.accepts(&t1));
    }

    #[test]
    fn divergent_traces_branch() {
        let mut pta = PrefixTreeAcceptor::new();
        let t1 = trace_from_seq(&["a", "b", "c"]);
        let t2 = trace_from_seq(&["a", "b", "d"]);

        pta.add_trace(&t1);
        pta.add_trace(&t2);

        // root -> a -> b -> {c, d} = 5 nodes
        assert_eq!(pta.node_count(), 5);
        assert!(pta.accepts(&t1));
        assert!(pta.accepts(&t2));
    }

    #[test]
    fn accepts_valid_rejects_unknown() {
        let mut pta = PrefixTreeAcceptor::new();
        pta.add_trace(&trace_from_seq(&["a", "b", "c"]));
        pta.add_trace(&trace_from_seq(&["a", "b", "d"]));

        assert!(pta.accepts(&trace_from_seq(&["a", "b", "c"])));
        assert!(pta.accepts(&trace_from_seq(&["a", "b", "d"])));
        assert!(!pta.accepts(&trace_from_seq(&["a", "b", "e"])));
        assert!(!pta.accepts(&trace_from_seq(&["a", "c"])));
        assert!(!pta.accepts(&trace_from_seq(&["x", "y"])));
    }

    #[test]
    fn prefix_not_accepted_unless_marked() {
        let mut pta = PrefixTreeAcceptor::new();
        pta.add_trace(&trace_from_seq(&["a", "b", "c"]));

        // Prefix "a, b" is not an accepting state
        assert!(!pta.accepts(&trace_from_seq(&["a", "b"])));
        assert!(!pta.accepts(&trace_from_seq(&["a"])));
    }

    #[test]
    fn completely_different_traces() {
        let mut pta = PrefixTreeAcceptor::new();
        pta.add_trace(&trace_from_seq(&["a", "b"]));
        pta.add_trace(&trace_from_seq(&["x", "y"]));

        // root -> {a -> b, x -> y} = 5 nodes
        assert_eq!(pta.node_count(), 5);
        assert!(pta.accepts(&trace_from_seq(&["a", "b"])));
        assert!(pta.accepts(&trace_from_seq(&["x", "y"])));
        assert!(!pta.accepts(&trace_from_seq(&["a", "y"])));
    }

    #[test]
    fn realistic_flow_pattern() {
        let mut pta = PrefixTreeAcceptor::new();

        // Run 1: scout -> planner -> specialist1 -> specialist2 -> synthesizer
        pta.add_trace(&trace_from_seq(&[
            "scout", "planner", "specialist1", "specialist2", "synthesizer",
        ]));
        // Run 2: scout -> planner -> specialist2 -> specialist1 -> synthesizer
        // (non-deterministic parallel order)
        pta.add_trace(&trace_from_seq(&[
            "scout", "planner", "specialist2", "specialist1", "synthesizer",
        ]));

        // Both orderings accepted
        assert!(pta.accepts(&trace_from_seq(&[
            "scout", "planner", "specialist1", "specialist2", "synthesizer",
        ])));
        assert!(pta.accepts(&trace_from_seq(&[
            "scout", "planner", "specialist2", "specialist1", "synthesizer",
        ])));
        // Different specialist ordering not seen before
        assert!(!pta.accepts(&trace_from_seq(&[
            "scout", "planner", "specialist1", "synthesizer",
        ])));
    }

    #[test]
    fn count_tracks_frequency() {
        let mut pta = PrefixTreeAcceptor::new();
        pta.add_trace(&trace_from_seq(&["a", "b"]));
        pta.add_trace(&trace_from_seq(&["a", "b"]));
        pta.add_trace(&trace_from_seq(&["a", "c"]));

        assert_eq!(pta.trace_count(), 3);
    }
}
