//! Dominator analysis for identifying mandatory milestones in flow execution.
//!
//! Applies compiler-theory dominator analysis to execution traces.
//! A node D dominates node N if every path from the start to N must
//! pass through D. Nodes that dominate ALL paths from start to end
//! are mandatory milestones — they must appear in every valid execution.
//!
//! Uses the iterative dominator algorithm (Cooper-Harvey-Kennedy style):
//! compute Dom(n) = {n} ∪ ∩{Dom(p) | p ∈ predecessors(n)} until stable.

use super::trace::ExecutionTrace;
use std::collections::{HashMap, HashSet};

/// A dominator tree computed from a flow graph.
#[derive(Debug)]
pub struct DominatorTree {
    /// Maps each node to its immediate dominator.
    pub dominators: HashMap<String, String>,
}

/// Build a graph from a set of execution traces.
///
/// The graph is the union of all edges observed across traces.
/// An edge (A, B) exists if B immediately follows A in any trace's
/// completed-node sequence.
fn build_graph(traces: &[ExecutionTrace]) -> (Vec<String>, HashMap<String, HashSet<String>>) {
    let mut nodes_set: HashSet<String> = HashSet::new();
    let mut predecessors: HashMap<String, HashSet<String>> = HashMap::new();

    for trace in traces {
        let seq = trace.node_sequence();
        for node in &seq {
            nodes_set.insert(node.to_string());
        }
        for window in seq.windows(2) {
            predecessors
                .entry(window[1].to_string())
                .or_default()
                .insert(window[0].to_string());
        }
    }

    // Deterministic node ordering: use first-seen order from traces
    let mut nodes = Vec::new();
    let mut seen = HashSet::new();
    for trace in traces {
        for node in trace.node_sequence() {
            if seen.insert(node.to_string()) {
                nodes.push(node.to_string());
            }
        }
    }

    (nodes, predecessors)
}

/// Extract nodes that dominate all paths from the start to the end node.
///
/// These are the mandatory milestones: every valid execution must pass
/// through each of these nodes.
///
/// Algorithm:
/// 1. Build a union graph from all traces
/// 2. Compute dominator sets using iterative intersection
/// 3. Find the end node (last in topological order)
/// 4. Return nodes in the dominator set of the end node
pub fn extract_dominators(traces: &[ExecutionTrace]) -> Vec<String> {
    if traces.is_empty() {
        return Vec::new();
    }

    let (nodes, predecessors) = build_graph(traces);
    if nodes.is_empty() {
        return Vec::new();
    }

    let start = &nodes[0];

    // Compute dominator sets: Dom(n) = {n} ∪ ∩{Dom(p) | p ∈ pred(n)}
    // Initialize: Dom(start) = {start}, Dom(n) = all_nodes for n != start
    let all_nodes: HashSet<String> = nodes.iter().cloned().collect();
    let mut dom: HashMap<String, HashSet<String>> = HashMap::new();

    for node in &nodes {
        if node == start {
            let mut s = HashSet::new();
            s.insert(start.clone());
            dom.insert(node.clone(), s);
        } else {
            dom.insert(node.clone(), all_nodes.clone());
        }
    }

    // Iterate until stable
    let mut changed = true;
    while changed {
        changed = false;
        for node in &nodes {
            if node == start {
                continue;
            }

            let preds = predecessors.get(node);
            let new_dom = if let Some(preds) = preds {
                // Intersect dominator sets of all predecessors
                let mut iter = preds.iter();
                let first = iter.next().unwrap();
                let mut intersection = dom.get(first).cloned().unwrap_or_default();
                for pred in iter {
                    let pred_dom = dom.get(pred).cloned().unwrap_or_default();
                    intersection = intersection.intersection(&pred_dom).cloned().collect();
                }
                // Union with {node}
                intersection.insert(node.clone());
                intersection
            } else {
                // No predecessors (unreachable from start in some sense)
                let mut s = HashSet::new();
                s.insert(node.clone());
                s
            };

            if new_dom != *dom.get(node).unwrap() {
                dom.insert(node.clone(), new_dom);
                changed = true;
            }
        }
    }

    // Find the end node: the last node that appears in the completed sequence
    // across all traces. Use the node that is last in topological order.
    let end = find_end_node(&nodes, &predecessors);

    // The dominators of the end node are the mandatory milestones
    let end_dom = dom.get(&end).cloned().unwrap_or_default();

    // Return in topological order (preserve ordering from nodes list)
    nodes.into_iter().filter(|n| end_dom.contains(n)).collect()
}

/// Find the end node: a node with no successors, or the last node
/// in the ordering if all nodes have successors.
fn find_end_node(nodes: &[String], predecessors: &HashMap<String, HashSet<String>>) -> String {
    // Build successors from predecessors
    let mut has_successor: HashSet<&str> = HashSet::new();
    for preds in predecessors.values() {
        for pred in preds {
            has_successor.insert(pred.as_str());
        }
    }

    // Find nodes that are NOT predecessors of anything (i.e., no outgoing edges)
    // A node has no successors if it never appears as a predecessor
    let sinks: Vec<&String> = nodes
        .iter()
        .filter(|n| !has_successor.contains(n.as_str()))
        .collect();

    if sinks.len() == 1 {
        return sinks[0].clone();
    }

    // If multiple sinks or no clear sink, use the last node in ordering
    nodes.last().cloned().unwrap_or_default()
}

/// Build the immediate dominator tree from dominator sets.
pub fn build_dominator_tree(traces: &[ExecutionTrace]) -> DominatorTree {
    if traces.is_empty() {
        return DominatorTree {
            dominators: HashMap::new(),
        };
    }

    let (nodes, predecessors) = build_graph(traces);
    if nodes.is_empty() {
        return DominatorTree {
            dominators: HashMap::new(),
        };
    }

    let start = &nodes[0];
    let all_nodes: HashSet<String> = nodes.iter().cloned().collect();
    let mut dom: HashMap<String, HashSet<String>> = HashMap::new();

    for node in &nodes {
        if node == start {
            let mut s = HashSet::new();
            s.insert(start.clone());
            dom.insert(node.clone(), s);
        } else {
            dom.insert(node.clone(), all_nodes.clone());
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for node in &nodes {
            if node == start {
                continue;
            }
            let preds = predecessors.get(node);
            let new_dom = if let Some(preds) = preds {
                let mut iter = preds.iter();
                let first = iter.next().unwrap();
                let mut intersection = dom.get(first).cloned().unwrap_or_default();
                for pred in iter {
                    let pred_dom = dom.get(pred).cloned().unwrap_or_default();
                    intersection = intersection.intersection(&pred_dom).cloned().collect();
                }
                intersection.insert(node.clone());
                intersection
            } else {
                let mut s = HashSet::new();
                s.insert(node.clone());
                s
            };

            if new_dom != *dom.get(node).unwrap() {
                dom.insert(node.clone(), new_dom);
                changed = true;
            }
        }
    }

    // Extract immediate dominators: idom(n) is the closest strict dominator
    let mut idom = HashMap::new();
    for node in &nodes {
        if node == start {
            continue;
        }
        let node_dom = dom.get(node).unwrap();
        // Strict dominators: dom(n) \ {n}
        let strict: HashSet<&String> = node_dom.iter().filter(|d| *d != node).collect();
        // idom is the strict dominator with the largest dominator set
        // (i.e., closest to n in the dominator tree)
        let mut best: Option<&String> = None;
        let mut best_size = 0;
        for d in &strict {
            let d_dom_size = dom.get(*d).map(|s| s.len()).unwrap_or(0);
            if d_dom_size > best_size {
                best_size = d_dom_size;
                best = Some(d);
            }
        }
        if let Some(idom_node) = best {
            idom.insert(node.clone(), idom_node.clone());
        }
    }

    DominatorTree { dominators: idom }
}

/// Validate that a trace contains all required dominator nodes
/// in topological order.
///
/// Returns `Ok(())` if all dominators are present and ordered correctly,
/// or `Err(missing_nodes)` listing the dominator nodes not found.
pub fn validate_against_dominators(
    trace: &ExecutionTrace,
    required_dominators: &[String],
) -> Result<(), Vec<String>> {
    let seq = trace.node_sequence();
    let mut missing = Vec::new();
    let mut last_pos: Option<usize> = None;
    let mut order_violated = false;

    for dom_node in required_dominators {
        match seq.iter().position(|n| n == dom_node) {
            Some(pos) => {
                if let Some(prev) = last_pos {
                    if pos <= prev {
                        order_violated = true;
                    }
                }
                last_pos = Some(pos);
            }
            None => {
                missing.push(dom_node.clone());
            }
        }
    }

    if order_violated && missing.is_empty() {
        return Err(vec!["dominator order violated".to_string()]);
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
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
    fn simple_linear_dominators() {
        // A -> B -> C: every node dominates all downstream nodes
        let traces = vec![trace_from_seq(&["a", "b", "c"])];
        let doms = extract_dominators(&traces);
        assert_eq!(doms, vec!["a", "b", "c"]);
    }

    #[test]
    fn diamond_dag_dominators() {
        // A -> B, A -> C, B -> D, C -> D
        // Only A and D are mandatory (B and C are alternatives)
        let traces = vec![
            trace_from_seq(&["a", "b", "d"]),
            trace_from_seq(&["a", "c", "d"]),
        ];
        let doms = extract_dominators(&traces);
        assert!(doms.contains(&"a".to_string()));
        assert!(doms.contains(&"d".to_string()));
        assert!(!doms.contains(&"b".to_string()));
        assert!(!doms.contains(&"c".to_string()));
    }

    #[test]
    fn empty_traces() {
        let doms = extract_dominators(&[]);
        assert!(doms.is_empty());
    }

    #[test]
    fn single_node() {
        let traces = vec![trace_from_seq(&["a"])];
        let doms = extract_dominators(&traces);
        assert_eq!(doms, vec!["a"]);
    }

    #[test]
    fn validation_passes_all_present() {
        let trace = trace_from_seq(&["a", "b", "c", "d"]);
        let required = vec!["a".to_string(), "d".to_string()];
        assert!(validate_against_dominators(&trace, &required).is_ok());
    }

    #[test]
    fn validation_fails_missing_dominator() {
        let trace = trace_from_seq(&["a", "b", "c"]);
        let required = vec!["a".to_string(), "d".to_string()];
        let err = validate_against_dominators(&trace, &required).unwrap_err();
        assert_eq!(err, vec!["d"]);
    }

    #[test]
    fn validation_fails_multiple_missing() {
        let trace = trace_from_seq(&["b", "c"]);
        let required = vec!["a".to_string(), "d".to_string()];
        let err = validate_against_dominators(&trace, &required).unwrap_err();
        assert!(err.contains(&"a".to_string()));
        assert!(err.contains(&"d".to_string()));
    }

    #[test]
    fn validation_checks_order() {
        let trace = trace_from_seq(&["d", "a"]);
        let required = vec!["a".to_string(), "d".to_string()];
        // d appears before a, violating required order
        let err = validate_against_dominators(&trace, &required).unwrap_err();
        assert_eq!(err, vec!["dominator order violated"]);
    }

    #[test]
    fn realistic_flow_dominators() {
        // scout -> planner -> [specialist1, specialist2] -> synthesizer
        // Two execution orderings for the parallel specialists
        let traces = vec![
            trace_from_seq(&[
                "scout",
                "planner",
                "specialist1",
                "specialist2",
                "synthesizer",
            ]),
            trace_from_seq(&[
                "scout",
                "planner",
                "specialist2",
                "specialist1",
                "synthesizer",
            ]),
        ];
        let doms = extract_dominators(&traces);

        // scout, planner, and synthesizer are mandatory milestones
        assert!(doms.contains(&"scout".to_string()));
        assert!(doms.contains(&"planner".to_string()));
        assert!(doms.contains(&"synthesizer".to_string()));

        // specialist1 and specialist2 are NOT mandatory (order varies)
        assert!(!doms.contains(&"specialist1".to_string()));
        assert!(!doms.contains(&"specialist2".to_string()));
    }

    #[test]
    fn validate_realistic_flow() {
        let traces = vec![
            trace_from_seq(&[
                "scout",
                "planner",
                "specialist1",
                "specialist2",
                "synthesizer",
            ]),
            trace_from_seq(&[
                "scout",
                "planner",
                "specialist2",
                "specialist1",
                "synthesizer",
            ]),
        ];
        let doms = extract_dominators(&traces);

        // Valid trace (different specialist order)
        let valid = trace_from_seq(&[
            "scout",
            "planner",
            "specialist2",
            "specialist1",
            "synthesizer",
        ]);
        assert!(validate_against_dominators(&valid, &doms).is_ok());

        // Invalid trace (missing synthesizer)
        let invalid = trace_from_seq(&["scout", "planner", "specialist1"]);
        let err = validate_against_dominators(&invalid, &doms).unwrap_err();
        assert!(err.contains(&"synthesizer".to_string()));
    }

    #[test]
    fn dominator_tree_linear() {
        let traces = vec![trace_from_seq(&["a", "b", "c"])];
        let tree = build_dominator_tree(&traces);

        assert_eq!(tree.dominators.get("b"), Some(&"a".to_string()));
        assert_eq!(tree.dominators.get("c"), Some(&"b".to_string()));
        assert!(tree.dominators.get("a").is_none()); // root has no idom
    }

    #[test]
    fn dominator_tree_diamond() {
        let traces = vec![
            trace_from_seq(&["a", "b", "d"]),
            trace_from_seq(&["a", "c", "d"]),
        ];
        let tree = build_dominator_tree(&traces);

        // b and c are immediately dominated by a
        assert_eq!(tree.dominators.get("b"), Some(&"a".to_string()));
        assert_eq!(tree.dominators.get("c"), Some(&"a".to_string()));
        // d is immediately dominated by a (since b and c are alternatives)
        assert_eq!(tree.dominators.get("d"), Some(&"a".to_string()));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Pure dominator-set intersection for Kani verification.
    /// Models: Dom(n) = {n} ∪ ∩{Dom(p) | p ∈ preds(n)}.
    /// Uses bitmask representation: bit i set means node i is in the set.
    fn dom_intersect_step(
        node_mask: u8,
        pred1_dom: u8,
        pred2_dom: u8,
        has_pred2: bool,
    ) -> u8 {
        let intersection = if has_pred2 {
            pred1_dom & pred2_dom
        } else {
            pred1_dom
        };
        intersection | node_mask
    }

    #[kani::proof]
    fn dominator_self_always_in_set() {
        let node_bit: u8 = kani::any();
        kani::assume(node_bit.count_ones() == 1);
        let p1: u8 = kani::any();
        let p2: u8 = kani::any();
        let has_p2: bool = kani::any();
        let result = dom_intersect_step(node_bit, p1, p2, has_p2);
        assert!(result & node_bit != 0, "node must dominate itself");
    }

    #[kani::proof]
    fn dominator_intersection_monotonic() {
        let node_bit: u8 = kani::any();
        kani::assume(node_bit.count_ones() == 1);
        let p1: u8 = kani::any();
        let p2: u8 = kani::any();
        // With one pred vs two: adding a pred can only shrink the set
        let with_one = dom_intersect_step(node_bit, p1, 0, false);
        let with_two = dom_intersect_step(node_bit, p1, p2, true);
        // with_two ⊆ with_one (intersection can only remove, not add)
        assert!(with_two & !with_one == 0 || with_two == with_one | node_bit);
    }

    /// Pure order-checking: verify that required positions are strictly increasing.
    fn check_order(positions: &[u8], len: usize) -> bool {
        if len <= 1 {
            return true;
        }
        for i in 1..len {
            if positions[i] <= positions[i - 1] {
                return false;
            }
        }
        true
    }

    #[kani::proof]
    fn order_check_empty_passes() {
        assert!(check_order(&[], 0));
    }

    #[kani::proof]
    fn order_check_single_passes() {
        let pos: u8 = kani::any();
        assert!(check_order(&[pos], 1));
    }
}
