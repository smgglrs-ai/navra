//! In-memory store for ACP runs and events.

use super::types::{Event, Message, Run, RunStatus};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Default)]
pub struct RunStore {
    runs: Arc<RwLock<HashMap<String, Run>>>,
    events: Arc<RwLock<HashMap<String, Vec<Event>>>>,
    session_runs: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl RunStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&self, run: Run) {
        let id = run.run_id.clone();
        let session_id = run.session_id.clone();

        let mut runs = self.runs.write().unwrap_or_else(|e| {
            tracing::warn!("RunStore RwLock poisoned (write), recovering");
            e.into_inner()
        });
        runs.insert(id.clone(), run);

        let mut events = self.events.write().unwrap_or_else(|e| {
            tracing::warn!("RunStore events RwLock poisoned (write), recovering");
            e.into_inner()
        });
        events.entry(id.clone()).or_default();

        if let Some(sid) = session_id {
            let mut sr = self.session_runs.write().unwrap_or_else(|e| {
                tracing::warn!("RunStore session_runs poisoned (write), recovering");
                e.into_inner()
            });
            sr.entry(sid).or_default().push(id);
        }
    }

    pub fn runs_for_session(&self, session_id: &str) -> Vec<String> {
        let sr = self.session_runs.read().unwrap_or_else(|e| {
            tracing::warn!("RunStore session_runs poisoned (read), recovering");
            e.into_inner()
        });
        sr.get(session_id).cloned().unwrap_or_default()
    }

    pub fn get(&self, id: &str) -> Option<Run> {
        let runs = self.runs.read().unwrap_or_else(|e| {
            tracing::warn!("RunStore RwLock poisoned (read), recovering");
            e.into_inner()
        });
        runs.get(id).cloned()
    }

    pub fn update_status(&self, id: &str, status: RunStatus) -> Option<Run> {
        let mut runs = self.runs.write().unwrap_or_else(|e| {
            tracing::warn!("RunStore RwLock poisoned (write), recovering");
            e.into_inner()
        });
        if let Some(run) = runs.get_mut(id) {
            run.status = status;
            Some(run.clone())
        } else {
            None
        }
    }

    pub fn set_finished(&self, id: &str, status: RunStatus, finished_at: String) -> Option<Run> {
        let mut runs = self.runs.write().unwrap_or_else(|e| {
            tracing::warn!("RunStore RwLock poisoned (write), recovering");
            e.into_inner()
        });
        if let Some(run) = runs.get_mut(id) {
            run.status = status;
            run.finished_at = Some(finished_at);
            Some(run.clone())
        } else {
            None
        }
    }

    pub fn set_error(
        &self,
        id: &str,
        error: super::types::AcpError,
        finished_at: String,
    ) -> Option<Run> {
        let mut runs = self.runs.write().unwrap_or_else(|e| {
            tracing::warn!("RunStore RwLock poisoned (write), recovering");
            e.into_inner()
        });
        if let Some(run) = runs.get_mut(id) {
            run.status = RunStatus::Failed;
            run.error = Some(error);
            run.finished_at = Some(finished_at);
            Some(run.clone())
        } else {
            None
        }
    }

    pub fn add_output_message(&self, id: &str, message: Message) -> Option<Run> {
        let mut runs = self.runs.write().unwrap_or_else(|e| {
            tracing::warn!("RunStore RwLock poisoned (write), recovering");
            e.into_inner()
        });
        if let Some(run) = runs.get_mut(id) {
            run.output.push(message);
            Some(run.clone())
        } else {
            None
        }
    }

    pub fn add_event(&self, run_id: &str, event: Event) {
        let mut events = self.events.write().unwrap_or_else(|e| {
            tracing::warn!("RunStore events RwLock poisoned (write), recovering");
            e.into_inner()
        });
        events.entry(run_id.to_string()).or_default().push(event);
    }

    pub fn list_events(&self, run_id: &str) -> Vec<Event> {
        let events = self.events.read().unwrap_or_else(|e| {
            tracing::warn!("RunStore events RwLock poisoned (read), recovering");
            e.into_inner()
        });
        events.get(run_id).cloned().unwrap_or_default()
    }

    pub fn set_awaiting(&self, id: &str, request: serde_json::Value) -> Option<Run> {
        let mut runs = self.runs.write().unwrap_or_else(|e| {
            tracing::warn!("RunStore RwLock poisoned (write), recovering");
            e.into_inner()
        });
        if let Some(run) = runs.get_mut(id) {
            run.status = RunStatus::Awaiting;
            run.await_request = Some(request);
            Some(run.clone())
        } else {
            None
        }
    }

    pub fn clear_await(&self, id: &str) -> Option<Run> {
        let mut runs = self.runs.write().unwrap_or_else(|e| {
            tracing::warn!("RunStore RwLock poisoned (write), recovering");
            e.into_inner()
        });
        if let Some(run) = runs.get_mut(id) {
            run.await_request = None;
            Some(run.clone())
        } else {
            None
        }
    }
}
