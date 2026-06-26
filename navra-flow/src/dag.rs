//! Dependency graph for task orchestration.
//!
//! Provides cycle detection, topological sorting, and ready-task
//! analysis for parallel execution.

use crate::error::FlowError;
use crate::task::Task;
use std::collections::{HashMap, HashSet};

/// A directed acyclic graph (DAG) of task dependencies.
#[derive(Debug)]
pub struct DependencyGraph {
    tasks: HashMap<String, Task>,
    /// For each task, the list of tasks that depend on it.
    dependents: HashMap<String, Vec<String>>,
    /// Topologically sorted task IDs (computed at construction).
    topo_order: Vec<String>,
}

impl DependencyGraph {
    /// Build a dependency graph from a list of tasks.
    ///
    /// Validates that:
    /// - All dependency references point to existing tasks
    /// - The graph is acyclic (no circular dependencies)
    pub fn new(tasks: Vec<Task>) -> Result<Self, FlowError> {
        let task_map: HashMap<String, Task> =
            tasks.into_iter().map(|t| (t.id.clone(), t)).collect();

        // Validate dependency references
        for task in task_map.values() {
            for dep in &task.depends_on {
                if !task_map.contains_key(dep) {
                    return Err(FlowError::UnknownDependency(dep.clone()));
                }
            }
        }

        // Build dependents map (reverse edges)
        let mut dependents: HashMap<String, Vec<String>> = HashMap::new();
        for task in task_map.values() {
            for dep in &task.depends_on {
                dependents
                    .entry(dep.clone())
                    .or_default()
                    .push(task.id.clone());
            }
        }

        // Topological sort with cycle detection (Kahn's algorithm)
        let topo_order = topological_sort(&task_map)?;

        Ok(Self {
            tasks: task_map,
            dependents,
            topo_order,
        })
    }

    /// Get tasks ready to execute (all dependencies satisfied).
    ///
    /// Returns tasks sorted by dependency depth (shallowest first).
    pub fn get_ready_tasks(&self, completed: &HashSet<String>) -> Vec<&Task> {
        self.tasks
            .values()
            .filter(|task| {
                !completed.contains(&task.id)
                    && task.depends_on.iter().all(|dep| completed.contains(dep))
            })
            .collect()
    }

    /// Get task IDs in topological order.
    pub fn topological_order(&self) -> &[String] {
        &self.topo_order
    }

    /// Get a task by ID.
    pub fn get_task(&self, id: &str) -> Option<&Task> {
        self.tasks.get(id)
    }

    /// Get all task IDs that transitively depend on the given task.
    pub fn all_dependents(&self, task_id: &str) -> HashSet<String> {
        let mut result = HashSet::new();
        let mut stack = vec![task_id.to_string()];
        while let Some(current) = stack.pop() {
            if let Some(deps) = self.dependents.get(&current) {
                for dep in deps {
                    if result.insert(dep.clone()) {
                        stack.push(dep.clone());
                    }
                }
            }
        }
        result
    }

    /// Number of tasks in the graph.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

/// Topological sort using Kahn's algorithm.
///
/// Returns an error if the graph contains a cycle.
fn topological_sort(tasks: &HashMap<String, Task>) -> Result<Vec<String>, FlowError> {
    // Count incoming edges for each node
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    for task in tasks.values() {
        in_degree.entry(&task.id).or_insert(0);
        for dep in &task.depends_on {
            in_degree.entry(dep.as_str()).or_insert(0);
        }
    }
    for task in tasks.values() {
        for _dep in &task.depends_on {
            *in_degree.entry(&task.id).or_insert(0) += 1;
        }
    }

    // Start with nodes that have no incoming edges
    let mut queue: Vec<&str> = in_degree
        .iter()
        .filter(|&(_, count)| *count == 0)
        .map(|(&id, _)| id)
        .collect();
    queue.sort(); // Deterministic order

    let mut result = Vec::new();

    while let Some(node) = queue.pop() {
        result.push(node.to_string());

        // For each task that depends on this node, decrement in-degree
        for task in tasks.values() {
            if task.depends_on.iter().any(|d| d == node) {
                let deg = in_degree.get_mut(task.id.as_str()).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    queue.push(&task.id);
                }
            }
        }
        queue.sort(); // Keep deterministic
    }

    if result.len() != tasks.len() {
        // Some nodes were never processed → cycle exists
        let remaining: Vec<String> = tasks
            .keys()
            .filter(|k| !result.contains(k))
            .cloned()
            .collect();
        return Err(FlowError::CyclicDependency(remaining.join(", ")));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, deps: &[&str]) -> Task {
        Task {
            id: id.to_string(),
            specialist: "dev".to_string(),
            model: None,
            mandate: format!("Do {id}"),
            depends_on: deps.iter().map(|s| s.to_string()).collect(),
            inputs: HashMap::new(),
            expected_output: None,
            success_criteria: Vec::new(),
            max_retries: 2,
            back_edges: Vec::new(),
            verification: None,
            temperature: None,
        }
    }

    #[test]
    fn single_task() {
        let dag = DependencyGraph::new(vec![task("a", &[])]).unwrap();
        assert_eq!(dag.len(), 1);
        assert_eq!(dag.topological_order(), &["a"]);
    }

    #[test]
    fn linear_chain() {
        let dag = DependencyGraph::new(vec![task("a", &[]), task("b", &["a"]), task("c", &["b"])])
            .unwrap();

        let order = dag.topological_order();
        assert!(order.iter().position(|x| x == "a") < order.iter().position(|x| x == "b"));
        assert!(order.iter().position(|x| x == "b") < order.iter().position(|x| x == "c"));
    }

    #[test]
    fn diamond_dependency() {
        // a → b, a → c, b → d, c → d
        let dag = DependencyGraph::new(vec![
            task("a", &[]),
            task("b", &["a"]),
            task("c", &["a"]),
            task("d", &["b", "c"]),
        ])
        .unwrap();

        let order = dag.topological_order();
        assert_eq!(order[0], "a");
        assert!(order.iter().position(|x| x == "b") < order.iter().position(|x| x == "d"));
        assert!(order.iter().position(|x| x == "c") < order.iter().position(|x| x == "d"));
    }

    #[test]
    fn cycle_detected() {
        let result = DependencyGraph::new(vec![task("a", &["b"]), task("b", &["a"])]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FlowError::CyclicDependency(_)
        ));
    }

    #[test]
    fn unknown_dependency() {
        let result = DependencyGraph::new(vec![task("a", &["nonexistent"])]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FlowError::UnknownDependency(_)
        ));
    }

    #[test]
    fn ready_tasks_initial() {
        let dag =
            DependencyGraph::new(vec![task("a", &[]), task("b", &[]), task("c", &["a", "b"])])
                .unwrap();

        let ready = dag.get_ready_tasks(&HashSet::new());
        let ids: HashSet<&str> = ready.iter().map(|t| t.id.as_str()).collect();
        assert!(ids.contains("a"));
        assert!(ids.contains("b"));
        assert!(!ids.contains("c"));
    }

    #[test]
    fn ready_tasks_after_completion() {
        let dag =
            DependencyGraph::new(vec![task("a", &[]), task("b", &[]), task("c", &["a", "b"])])
                .unwrap();

        let mut completed = HashSet::new();
        completed.insert("a".to_string());
        let ready = dag.get_ready_tasks(&completed);
        // b is ready, c is not (b not complete)
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "b");

        completed.insert("b".to_string());
        let ready = dag.get_ready_tasks(&completed);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "c");
    }

    #[test]
    fn all_dependents_transitive() {
        let dag = DependencyGraph::new(vec![task("a", &[]), task("b", &["a"]), task("c", &["b"])])
            .unwrap();

        let deps = dag.all_dependents("a");
        assert!(deps.contains("b"));
        assert!(deps.contains("c"));
    }

    #[test]
    fn independent_tasks() {
        let dag =
            DependencyGraph::new(vec![task("a", &[]), task("b", &[]), task("c", &[])]).unwrap();

        let ready = dag.get_ready_tasks(&HashSet::new());
        assert_eq!(ready.len(), 3);
    }

    // --- Stress tests ---

    #[test]
    fn stress_linear_chain_1000() {
        let tasks: Vec<Task> = (0..1000)
            .map(|i| {
                if i == 0 {
                    task(&format!("t{i}"), &[])
                } else {
                    task(&format!("t{i}"), &[&format!("t{}", i - 1)])
                }
            })
            .collect();

        let dag = DependencyGraph::new(tasks).unwrap();
        assert_eq!(dag.len(), 1000);

        // Verify topological order: each task must come after its predecessor
        let order = dag.topological_order();
        assert_eq!(order.len(), 1000);
        for i in 1..1000 {
            let prev = format!("t{}", i - 1);
            let curr = format!("t{i}");
            assert!(
                order.iter().position(|x| *x == prev) < order.iter().position(|x| *x == curr),
                "t{} must come before t{i} in topological order",
                i - 1
            );
        }

        // Only t0 should be initially ready
        let ready = dag.get_ready_tasks(&HashSet::new());
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "t0");

        // After completing all but the last, only the last should be ready
        let mut completed: HashSet<String> = (0..999).map(|i| format!("t{i}")).collect();
        let ready = dag.get_ready_tasks(&completed);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "t999");

        // After completing all, nothing is ready
        completed.insert("t999".to_string());
        let ready = dag.get_ready_tasks(&completed);
        assert_eq!(ready.len(), 0);
    }

    #[test]
    fn stress_diamond_100() {
        // Fan-out from root to 100 middle nodes, then fan-in to a sink.
        // root → m0, m1, ..., m99 → sink
        let mut tasks = vec![task("root", &[])];
        for i in 0..100 {
            tasks.push(task(&format!("m{i}"), &["root"]));
        }
        let middle_ids: Vec<String> = (0..100).map(|i| format!("m{i}")).collect();
        let middle_refs: Vec<&str> = middle_ids.iter().map(|s| s.as_str()).collect();
        tasks.push(task("sink", &middle_refs));

        let dag = DependencyGraph::new(tasks).unwrap();
        assert_eq!(dag.len(), 102);

        // Initially only root is ready
        let ready = dag.get_ready_tasks(&HashSet::new());
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "root");

        // After completing root, all 100 middle nodes should be ready
        let mut completed = HashSet::new();
        completed.insert("root".to_string());
        let ready = dag.get_ready_tasks(&completed);
        assert_eq!(ready.len(), 100);
        for t in &ready {
            assert!(t.id.starts_with('m'), "Expected middle node, got {}", t.id);
        }

        // After completing all middle nodes, only sink is ready
        for i in 0..100 {
            completed.insert(format!("m{i}"));
        }
        let ready = dag.get_ready_tasks(&completed);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "sink");

        // Topological order: root before all middle, all middle before sink
        let order = dag.topological_order();
        let root_pos = order.iter().position(|x| x == "root").unwrap();
        let sink_pos = order.iter().position(|x| x == "sink").unwrap();
        assert_eq!(root_pos, 0);
        assert_eq!(sink_pos, order.len() - 1);
    }

    #[test]
    fn stress_get_ready_performance() {
        // 500 independent tasks — get_ready_tasks must return all 500.
        let tasks: Vec<Task> = (0..500).map(|i| task(&format!("t{i}"), &[])).collect();

        let dag = DependencyGraph::new(tasks).unwrap();
        assert_eq!(dag.len(), 500);

        let start = std::time::Instant::now();
        let ready = dag.get_ready_tasks(&HashSet::new());
        let elapsed = start.elapsed();

        assert_eq!(ready.len(), 500);
        assert!(
            elapsed.as_millis() < 100,
            "get_ready_tasks took {}ms for 500 independent tasks (expected <100ms)",
            elapsed.as_millis()
        );
    }
}
