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
        .filter(|(_, &count)| count == 0)
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
            mandate: format!("Do {id}"),
            depends_on: deps.iter().map(|s| s.to_string()).collect(),
            inputs: HashMap::new(),
            expected_output: None,
            success_criteria: Vec::new(),
            max_retries: 2,
            back_edges: Vec::new(),
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
        let dag = DependencyGraph::new(vec![
            task("a", &[]),
            task("b", &["a"]),
            task("c", &["b"]),
        ])
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
        let result = DependencyGraph::new(vec![
            task("a", &["b"]),
            task("b", &["a"]),
        ]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FlowError::CyclicDependency(_)));
    }

    #[test]
    fn unknown_dependency() {
        let result = DependencyGraph::new(vec![task("a", &["nonexistent"])]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FlowError::UnknownDependency(_)));
    }

    #[test]
    fn ready_tasks_initial() {
        let dag = DependencyGraph::new(vec![
            task("a", &[]),
            task("b", &[]),
            task("c", &["a", "b"]),
        ])
        .unwrap();

        let ready = dag.get_ready_tasks(&HashSet::new());
        let ids: HashSet<&str> = ready.iter().map(|t| t.id.as_str()).collect();
        assert!(ids.contains("a"));
        assert!(ids.contains("b"));
        assert!(!ids.contains("c"));
    }

    #[test]
    fn ready_tasks_after_completion() {
        let dag = DependencyGraph::new(vec![
            task("a", &[]),
            task("b", &[]),
            task("c", &["a", "b"]),
        ])
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
        let dag = DependencyGraph::new(vec![
            task("a", &[]),
            task("b", &["a"]),
            task("c", &["b"]),
        ])
        .unwrap();

        let deps = dag.all_dependents("a");
        assert!(deps.contains("b"));
        assert!(deps.contains("c"));
    }

    #[test]
    fn independent_tasks() {
        let dag = DependencyGraph::new(vec![
            task("a", &[]),
            task("b", &[]),
            task("c", &[]),
        ])
        .unwrap();

        let ready = dag.get_ready_tasks(&HashSet::new());
        assert_eq!(ready.len(), 3);
    }
}
