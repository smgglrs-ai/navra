//! In-memory store for ACP runs and events.

use super::types::{Event, Message, Run, RunStatus};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default)]
pub struct RunMetrics {
    pub total_runs: u64,
    pub completed: u64,
    pub failed: u64,
    pub total_duration_secs: f64,
}

impl RunMetrics {
    pub fn success_rate(&self) -> f64 {
        if self.total_runs == 0 {
            0.0
        } else {
            (self.completed as f64 / self.total_runs as f64) * 100.0
        }
    }

    pub fn avg_run_time(&self) -> f64 {
        let finished = self.completed + self.failed;
        if finished == 0 {
            0.0
        } else {
            self.total_duration_secs / finished as f64
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RunStore {
    runs: Arc<RwLock<HashMap<String, Run>>>,
    events: Arc<RwLock<HashMap<String, Vec<Event>>>>,
    session_runs: Arc<RwLock<HashMap<String, Vec<String>>>>,
    metrics: Arc<RwLock<RunMetrics>>,
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
            run.status = status.clone();
            run.finished_at = Some(finished_at.clone());
            let duration = compute_duration(&run.created_at, &finished_at);
            drop(runs);
            self.record_finish(&status, duration);
            self.get(id)
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
            run.finished_at = Some(finished_at.clone());
            let duration = compute_duration(&run.created_at, &finished_at);
            drop(runs);
            self.record_finish(&RunStatus::Failed, duration);
            self.get(id)
        } else {
            None
        }
    }

    fn record_finish(&self, status: &RunStatus, duration: f64) {
        let mut m = self.metrics.write().unwrap_or_else(|e| e.into_inner());
        m.total_runs += 1;
        m.total_duration_secs += duration;
        match status {
            RunStatus::Completed => m.completed += 1,
            RunStatus::Failed => m.failed += 1,
            _ => {}
        }
    }

    pub fn metrics(&self) -> RunMetrics {
        self.metrics.read().unwrap_or_else(|e| e.into_inner()).clone()
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

    /// Remove finished runs older than `max_age`. Returns number removed.
    pub fn expire(&self, max_age: Duration) -> usize {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            - max_age.as_secs() as i64;

        let expired_ids: Vec<String> = {
            let runs = self.runs.read().unwrap_or_else(|e| e.into_inner());
            runs.values()
                .filter(|r| {
                    matches!(
                        r.status,
                        RunStatus::Completed | RunStatus::Failed | RunStatus::Cancelled
                    ) && r
                        .finished_at
                        .as_ref()
                        .and_then(|ts| parse_iso_epoch(ts))
                        .map(|epoch| epoch < cutoff)
                        .unwrap_or(false)
                })
                .map(|r| r.run_id.clone())
                .collect()
        };

        if expired_ids.is_empty() {
            return 0;
        }

        let mut runs = self.runs.write().unwrap_or_else(|e| e.into_inner());
        let mut events = self.events.write().unwrap_or_else(|e| e.into_inner());
        let mut sr = self.session_runs.write().unwrap_or_else(|e| e.into_inner());

        for id in &expired_ids {
            runs.remove(id);
            events.remove(id);
        }

        for run_ids in sr.values_mut() {
            run_ids.retain(|rid| !expired_ids.contains(rid));
        }
        sr.retain(|_, v| !v.is_empty());

        expired_ids.len()
    }

    pub fn count(&self) -> usize {
        self.runs.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

fn compute_duration(created_at: &str, finished_at: &str) -> f64 {
    match (parse_iso_epoch(created_at), parse_iso_epoch(finished_at)) {
        (Some(start), Some(end)) => (end - start) as f64,
        _ => 0.0,
    }
}

fn parse_iso_epoch(ts: &str) -> Option<i64> {
    let parts: Vec<&str> = ts.split('T').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<i64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    if date_parts.len() != 3 {
        return None;
    }
    let time_str = parts[1].trim_end_matches('Z');
    let time_parts: Vec<i64> = time_str.split(':').filter_map(|p| p.parse().ok()).collect();
    if time_parts.len() != 3 {
        return None;
    }
    let (y, m, d) = (date_parts[0], date_parts[1] as u32, date_parts[2] as u32);
    let (h, min, s) = (time_parts[0], time_parts[1], time_parts[2]);

    let days = date_to_epoch_days(y, m, d);
    Some(days * 86400 + h * 3600 + min * 60 + s)
}

fn date_to_epoch_days(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let m = if m <= 2 { m + 9 } else { m - 3 } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
