use crate::protocol::a2a::{Artifact, Task, TaskStatus};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Thread-safe in-memory store for A2A tasks.
#[derive(Debug, Clone, Default)]
pub struct TaskStore {
    tasks: Arc<RwLock<HashMap<String, Task>>>,
}

impl TaskStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&self, task: Task) {
        let mut tasks = self.tasks.write().unwrap_or_else(|e| {
            tracing::warn!("TaskStore RwLock poisoned (write), recovering");
            e.into_inner()
        });
        tasks.insert(task.id.clone(), task);
    }

    pub fn get(&self, id: &str) -> Option<Task> {
        let tasks = self.tasks.read().unwrap_or_else(|e| {
            tracing::warn!("TaskStore RwLock poisoned (read), recovering");
            e.into_inner()
        });
        tasks.get(id).cloned()
    }

    pub fn update_status(&self, id: &str, status: TaskStatus) -> Option<Task> {
        let mut tasks = self.tasks.write().unwrap_or_else(|e| {
            tracing::warn!("TaskStore RwLock poisoned (write), recovering");
            e.into_inner()
        });
        if let Some(task) = tasks.get_mut(id) {
            task.status = status;
            Some(task.clone())
        } else {
            None
        }
    }

    pub fn add_artifact(&self, id: &str, artifact: Artifact) -> Option<Task> {
        let mut tasks = self.tasks.write().unwrap_or_else(|e| {
            tracing::warn!("TaskStore RwLock poisoned (write), recovering");
            e.into_inner()
        });
        if let Some(task) = tasks.get_mut(id) {
            task.artifacts.push(artifact);
            Some(task.clone())
        } else {
            None
        }
    }

    pub fn count(&self) -> usize {
        self.tasks.read().unwrap_or_else(|e| {
            tracing::warn!("TaskStore RwLock poisoned (read), recovering");
            e.into_inner()
        }).len()
    }
}
