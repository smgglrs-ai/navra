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
            .as_millis() as i64
            - max_age.as_millis() as i64;

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
                        .and_then(|ts| parse_iso_epoch_ms(ts))
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
    match (parse_iso_epoch_ms(created_at), parse_iso_epoch_ms(finished_at)) {
        (Some(start), Some(end)) => (end - start) as f64 / 1000.0,
        _ => 0.0,
    }
}

fn parse_iso_epoch_ms(ts: &str) -> Option<i64> {
    let parts: Vec<&str> = ts.split('T').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<i64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    if date_parts.len() != 3 {
        return None;
    }
    let time_str = parts[1].trim_end_matches('Z');
    let time_parts: Vec<&str> = time_str.split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let h: i64 = time_parts[0].parse().ok()?;
    let min: i64 = time_parts[1].parse().ok()?;
    let (s, ms) = if let Some((sec_str, frac_str)) = time_parts[2].split_once('.') {
        let s: i64 = sec_str.parse().ok()?;
        let frac: i64 = frac_str.parse().ok()?;
        let ms = match frac_str.len() {
            1 => frac * 100,
            2 => frac * 10,
            3 => frac,
            _ => frac / 10_i64.pow(frac_str.len() as u32 - 3),
        };
        (s, ms)
    } else {
        (time_parts[2].parse().ok()?, 0)
    };
    let (y, m, d) = (date_parts[0], date_parts[1] as u32, date_parts[2] as u32);

    let days = date_to_epoch_days(y, m, d);
    Some((days * 86400 + h * 3600 + min * 60 + s) * 1000 + ms)
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::AcpError;

    fn make_run(id: &str, session: Option<&str>) -> Run {
        Run {
            agent_name: "test-agent".to_string(),
            run_id: id.to_string(),
            status: RunStatus::Created,
            output: vec![],
            created_at: "2026-06-05T10:00:00Z".to_string(),
            session_id: session.map(String::from),
            await_request: None,
            error: None,
            finished_at: None,
        }
    }

    #[test]
    fn create_and_get() {
        let store = RunStore::new();
        store.create(make_run("r1", None));
        assert!(store.get("r1").is_some());
        assert!(store.get("r2").is_none());
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn update_status() {
        let store = RunStore::new();
        store.create(make_run("r1", None));
        let run = store.update_status("r1", RunStatus::InProgress).unwrap();
        assert_eq!(run.status, RunStatus::InProgress);
    }

    #[test]
    fn set_finished_records_metrics() {
        let store = RunStore::new();
        store.create(make_run("r1", None));
        store.set_finished("r1", RunStatus::Completed, "2026-06-05T10:00:05Z".to_string());

        let m = store.metrics();
        assert_eq!(m.total_runs, 1);
        assert_eq!(m.completed, 1);
        assert_eq!(m.failed, 0);
        assert_eq!(m.success_rate(), 100.0);
        assert!(m.avg_run_time() > 0.0);
    }

    #[test]
    fn set_error_records_failure() {
        let store = RunStore::new();
        store.create(make_run("r1", None));
        store.set_error(
            "r1",
            AcpError::server_error("boom"),
            "2026-06-05T10:00:03Z".to_string(),
        );

        let run = store.get("r1").unwrap();
        assert_eq!(run.status, RunStatus::Failed);
        assert!(run.error.is_some());

        let m = store.metrics();
        assert_eq!(m.failed, 1);
        assert_eq!(m.success_rate(), 0.0);
    }

    #[test]
    fn metrics_accumulate() {
        let store = RunStore::new();
        store.create(make_run("r1", None));
        store.create(make_run("r2", None));
        store.create(make_run("r3", None));

        store.set_finished("r1", RunStatus::Completed, "2026-06-05T10:00:02Z".to_string());
        store.set_finished("r2", RunStatus::Completed, "2026-06-05T10:00:04Z".to_string());
        store.set_error("r3", AcpError::server_error("err"), "2026-06-05T10:00:01Z".to_string());

        let m = store.metrics();
        assert_eq!(m.total_runs, 3);
        assert_eq!(m.completed, 2);
        assert_eq!(m.failed, 1);
        let rate = m.success_rate();
        assert!(rate > 66.0 && rate < 67.0, "expected ~66.7%, got {}", rate);
    }

    #[test]
    fn set_awaiting_and_clear() {
        let store = RunStore::new();
        store.create(make_run("r1", None));

        let run = store
            .set_awaiting("r1", serde_json::json!({"request_id": "a-1"}))
            .unwrap();
        assert_eq!(run.status, RunStatus::Awaiting);
        assert!(run.await_request.is_some());

        let run = store.clear_await("r1").unwrap();
        assert!(run.await_request.is_none());
    }

    #[test]
    fn set_awaiting_nonexistent() {
        let store = RunStore::new();
        assert!(store.set_awaiting("nope", serde_json::json!({})).is_none());
    }

    #[test]
    fn session_run_tracking() {
        let store = RunStore::new();
        store.create(make_run("r1", Some("s1")));
        store.create(make_run("r2", Some("s1")));
        store.create(make_run("r3", Some("s2")));
        store.create(make_run("r4", None));

        let s1_runs = store.runs_for_session("s1");
        assert_eq!(s1_runs, vec!["r1", "r2"]);

        let s2_runs = store.runs_for_session("s2");
        assert_eq!(s2_runs, vec!["r3"]);

        assert!(store.runs_for_session("s3").is_empty());
    }

    #[test]
    fn expire_removes_old_finished_runs() {
        let store = RunStore::new();
        store.create(make_run("r1", Some("s1")));
        store.set_finished("r1", RunStatus::Completed, "2020-01-01T00:00:00Z".to_string());

        store.create(make_run("r2", Some("s1")));
        store.update_status("r2", RunStatus::InProgress);

        let expired = store.expire(Duration::from_secs(60));
        assert_eq!(expired, 1);
        assert!(store.get("r1").is_none());
        assert!(store.get("r2").is_some());

        let s1_runs = store.runs_for_session("s1");
        assert_eq!(s1_runs, vec!["r2"]);
    }

    #[test]
    fn expire_keeps_recent_runs() {
        let store = RunStore::new();
        store.create(make_run("r1", None));
        store.set_finished(
            "r1",
            RunStatus::Completed,
            super::super::dispatch::now_iso(),
        );

        let expired = store.expire(Duration::from_secs(3600));
        assert_eq!(expired, 0);
        assert!(store.get("r1").is_some());
    }

    #[test]
    fn expire_cleans_session_mappings() {
        let store = RunStore::new();
        store.create(make_run("r1", Some("s1")));
        store.set_finished("r1", RunStatus::Completed, "2020-01-01T00:00:00Z".to_string());

        store.expire(Duration::from_secs(60));
        assert!(store.runs_for_session("s1").is_empty());
    }

    #[test]
    fn add_output_message() {
        let store = RunStore::new();
        store.create(make_run("r1", None));

        let msg = Message {
            role: "agent".to_string(),
            parts: vec![super::super::types::MessagePart::text("hello")],
            created_at: None,
            completed_at: None,
        };
        let run = store.add_output_message("r1", msg).unwrap();
        assert_eq!(run.output.len(), 1);
    }

    #[test]
    fn events_lifecycle() {
        let store = RunStore::new();
        store.create(make_run("r1", None));

        store.add_event("r1", Event::RunCreated {
            run: store.get("r1").unwrap(),
        });
        store.add_event("r1", Event::RunInProgress {
            run: store.get("r1").unwrap(),
        });

        let events = store.list_events("r1");
        assert_eq!(events.len(), 2);
        assert!(store.list_events("r2").is_empty());
    }

    #[test]
    fn parse_iso_epoch_valid() {
        let epoch = parse_iso_epoch_ms("2026-06-05T10:30:00Z").unwrap();
        assert!(epoch > 0);
    }

    #[test]
    fn parse_iso_epoch_invalid() {
        assert!(parse_iso_epoch_ms("not-a-date").is_none());
        assert!(parse_iso_epoch_ms("").is_none());
        assert!(parse_iso_epoch_ms("2026-06-05").is_none());
    }

    #[test]
    fn compute_duration_works() {
        let d = compute_duration("2026-06-05T10:00:00Z", "2026-06-05T10:00:05Z");
        assert_eq!(d, 5.0);
    }

    #[test]
    fn compute_duration_invalid_returns_zero() {
        assert_eq!(compute_duration("bad", "bad"), 0.0);
    }
}
