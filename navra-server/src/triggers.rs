//! Event-driven trigger infrastructure for activating agent flows.
//!
//! Supports three trigger types:
//! - **Webhook**: HTTP POST endpoints with optional HMAC-SHA256 verification
//! - **Cron**: Periodic scheduling via standard cron expressions
//! - **FileWatch**: Filesystem monitoring with glob filtering and debounce

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use navra_protocol::compat::{content_as_text, CallToolResultExt};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// Configuration for a single trigger, deserialized from TOML.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type")]
pub enum TriggerConfig {
    #[serde(rename = "webhook")]
    Webhook {
        /// URL path suffix, e.g. "/hook/deploy" becomes POST /hook/deploy
        path: String,
        /// Optional HMAC-SHA256 secret for request verification
        secret: Option<String>,
        /// Name of the flow to start when triggered
        flow_name: String,
    },
    #[serde(rename = "cron")]
    Cron {
        /// Cron expression: "minute hour day-of-month month day-of-week"
        schedule: String,
        /// Name of the flow to start on schedule
        flow_name: String,
    },
    #[serde(rename = "file_watch")]
    FileWatch {
        /// Directory path to watch (supports ~ expansion)
        path: String,
        /// Optional glob pattern to filter events, e.g. "*.pdf"
        pattern: Option<String>,
        /// Name of the flow to start when a matching file changes
        flow_name: String,
        /// Debounce interval in milliseconds (default: 500)
        debounce_ms: Option<u64>,
    },
}

/// Registry of active triggers with their background task handles.
pub struct TriggerRegistry {
    triggers: Vec<ActiveTrigger>,
}

struct ActiveTrigger {
    #[allow(dead_code)]
    config: TriggerConfig,
    handle: tokio::task::JoinHandle<()>,
}

/// Shared state for webhook route handlers.
struct WebhookState {
    flow_ctx: Arc<crate::flow_tools::FlowContext>,
    /// Maps webhook path suffix to (flow_name, optional secret).
    routes: HashMap<String, (String, Option<String>)>,
}

impl TriggerRegistry {
    /// Start all configured triggers.
    ///
    /// Returns the registry (owns background task handles) and an axum
    /// Router containing webhook routes (must be merged into the main router).
    pub fn start(
        configs: &[TriggerConfig],
        flow_ctx: Arc<crate::flow_tools::FlowContext>,
    ) -> (Self, Router) {
        let mut triggers = Vec::new();
        let mut webhook_routes: HashMap<String, (String, Option<String>)> = HashMap::new();

        for config in configs {
            match config {
                TriggerConfig::Webhook {
                    path,
                    secret,
                    flow_name,
                } => {
                    // Normalize path: ensure it starts with /
                    let path = if path.starts_with('/') {
                        path.clone()
                    } else {
                        format!("/{path}")
                    };
                    // Extract the route name (last segment after /hook/)
                    let route_key = path
                        .strip_prefix("/hook/")
                        .unwrap_or(path.trim_start_matches('/'))
                        .to_string();
                    webhook_routes.insert(route_key, (flow_name.clone(), secret.clone()));
                    tracing::info!(
                        path = %path,
                        flow = %flow_name,
                        verified = secret.is_some(),
                        "Webhook trigger registered"
                    );
                    // Webhooks don't need a background task — they're
                    // served via the axum router. We still record them
                    // in the registry for listing purposes.
                    let cfg = config.clone();
                    let handle = tokio::spawn(async {});
                    triggers.push(ActiveTrigger {
                        config: cfg,
                        handle,
                    });
                }
                TriggerConfig::Cron {
                    schedule,
                    flow_name,
                } => {
                    let parsed = match CronSchedule::parse(schedule) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!(
                                schedule = %schedule,
                                error = %e,
                                "Invalid cron expression, skipping trigger"
                            );
                            continue;
                        }
                    };
                    let flow_name_owned = flow_name.clone();
                    let ctx = Arc::clone(&flow_ctx);
                    let schedule_str = schedule.clone();
                    tracing::info!(
                        schedule = %schedule,
                        flow = %flow_name,
                        "Cron trigger started"
                    );
                    let handle = tokio::spawn(async move {
                        run_cron_trigger(parsed, &flow_name_owned, &schedule_str, ctx).await;
                    });
                    triggers.push(ActiveTrigger {
                        config: config.clone(),
                        handle,
                    });
                }
                TriggerConfig::FileWatch {
                    path,
                    pattern,
                    flow_name,
                    debounce_ms,
                } => {
                    let watch_path = crate::expand_tilde(path);
                    let flow_name_owned = flow_name.clone();
                    let pattern_owned = pattern.clone();
                    let debounce = std::time::Duration::from_millis(debounce_ms.unwrap_or(500));
                    let ctx = Arc::clone(&flow_ctx);
                    tracing::info!(
                        path = %path,
                        pattern = pattern.as_deref().unwrap_or("*"),
                        flow = %flow_name,
                        debounce_ms = debounce_ms.unwrap_or(500),
                        "File watch trigger started"
                    );
                    let handle = tokio::spawn(async move {
                        if let Err(e) = run_file_watch_trigger(
                            &watch_path,
                            pattern_owned.as_deref(),
                            &flow_name_owned,
                            debounce,
                            ctx,
                        )
                        .await
                        {
                            tracing::error!(
                                path = %watch_path,
                                error = %e,
                                "File watch trigger failed"
                            );
                        }
                    });
                    triggers.push(ActiveTrigger {
                        config: config.clone(),
                        handle,
                    });
                }
            }
        }

        // Build webhook router
        let router = if webhook_routes.is_empty() {
            Router::new()
        } else {
            let state = Arc::new(WebhookState {
                flow_ctx,
                routes: webhook_routes,
            });
            Router::new()
                .route("/hook/{name}", post(handle_webhook))
                .with_state(state)
        };

        (Self { triggers }, router)
    }

    /// Shut down all trigger background tasks.
    #[allow(dead_code)]
    pub fn shutdown(&self) {
        for trigger in &self.triggers {
            trigger.handle.abort();
        }
    }
}

impl Drop for TriggerRegistry {
    fn drop(&mut self) {
        for trigger in &self.triggers {
            trigger.handle.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Webhook handler
// ---------------------------------------------------------------------------

async fn handle_webhook(
    State(state): State<Arc<WebhookState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let (flow_name, secret) = match state.routes.get(&name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "Unknown webhook".to_string()),
    };

    // Verify HMAC-SHA256 if a secret is configured
    if let Some(secret) = secret {
        let sig_header = headers
            .get("x-signature-256")
            .or_else(|| headers.get("x-hub-signature-256"))
            .and_then(|v| v.to_str().ok());

        match sig_header {
            Some(sig) => {
                if !verify_hmac_sha256(secret.as_bytes(), &body, sig) {
                    tracing::warn!(webhook = %name, "HMAC verification failed");
                    return (StatusCode::UNAUTHORIZED, "Invalid signature".to_string());
                }
            }
            None => {
                tracing::warn!(webhook = %name, "Missing signature header");
                return (StatusCode::UNAUTHORIZED, "Missing signature".to_string());
            }
        }
    }

    // Build flow_start args
    let args = serde_json::json!({
        "flow_name": flow_name,
        "prompt": format!("Triggered by webhook: {name}"),
        "parameters": {
            "webhook_name": name,
            "webhook_body": String::from_utf8_lossy(&body).to_string(),
        },
    });

    let ctx = Arc::clone(&state.flow_ctx);
    let result = crate::flow_tools::handle_flow_start(args, ctx, "webhook-trigger").await;

    let response_text = result
        .content
        .iter()
        .filter_map(|c| content_as_text(c))
        .collect::<Vec<_>>()
        .join("\n");

    if result.is_err() {
        (StatusCode::INTERNAL_SERVER_ERROR, response_text)
    } else {
        (StatusCode::OK, response_text)
    }
}

/// Verify HMAC-SHA256 signature.
///
/// The signature header is expected in the format `sha256=<hex>`.
pub(crate) fn verify_hmac_sha256(secret: &[u8], body: &[u8], signature: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let sig_hex = signature.strip_prefix("sha256=").unwrap_or(signature);

    let expected = match hex::decode(sig_hex) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let mut mac = match Hmac::<Sha256>::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);

    mac.verify_slice(&expected).is_ok()
}

// ---------------------------------------------------------------------------
// Cron trigger
// ---------------------------------------------------------------------------

/// Minimal cron expression: minute hour day-of-month month day-of-week.
///
/// Supports:
/// - Exact values: `5`, `14`
/// - Wildcards: `*`
/// - Ranges: `1-5`
/// - Lists: `1,3,5`
/// - Step: `*/5`
#[derive(Debug, Clone)]
pub(crate) struct CronSchedule {
    minute: CronField,
    hour: CronField,
    dom: CronField,
    month: CronField,
    dow: CronField,
}

#[derive(Debug, Clone)]
enum CronField {
    Any,
    Values(Vec<u32>),
}

impl CronField {
    fn parse(s: &str, min: u32, max: u32) -> Result<Self, String> {
        if s == "*" {
            return Ok(CronField::Any);
        }
        if let Some(step_str) = s.strip_prefix("*/") {
            let step: u32 = step_str.parse().map_err(|_| format!("Invalid step: {s}"))?;
            if step == 0 {
                return Err(format!("Step cannot be zero: {s}"));
            }
            let values: Vec<u32> = (min..=max).filter(|v| v % step == 0).collect();
            return Ok(CronField::Values(values));
        }
        let mut values = Vec::new();
        for part in s.split(',') {
            if let Some((start_str, end_str)) = part.split_once('-') {
                let start: u32 = start_str
                    .parse()
                    .map_err(|_| format!("Invalid range start: {part}"))?;
                let end: u32 = end_str
                    .parse()
                    .map_err(|_| format!("Invalid range end: {part}"))?;
                if start > end || start < min || end > max {
                    return Err(format!("Range out of bounds: {part} (valid: {min}-{max})"));
                }
                values.extend(start..=end);
            } else {
                let val: u32 = part.parse().map_err(|_| format!("Invalid value: {part}"))?;
                if val < min || val > max {
                    return Err(format!("Value out of bounds: {val} (valid: {min}-{max})"));
                }
                values.push(val);
            }
        }
        Ok(CronField::Values(values))
    }

    fn matches(&self, value: u32) -> bool {
        match self {
            CronField::Any => true,
            CronField::Values(vals) => vals.contains(&value),
        }
    }
}

impl CronSchedule {
    pub(crate) fn parse(expr: &str) -> Result<Self, String> {
        let parts: Vec<&str> = expr.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(format!(
                "Cron expression must have 5 fields (minute hour dom month dow), got {}",
                parts.len()
            ));
        }
        Ok(CronSchedule {
            minute: CronField::parse(parts[0], 0, 59)?,
            hour: CronField::parse(parts[1], 0, 23)?,
            dom: CronField::parse(parts[2], 1, 31)?,
            month: CronField::parse(parts[3], 1, 12)?,
            dow: CronField::parse(parts[4], 0, 6)?,
        })
    }

    /// Check if the given time matches this schedule.
    fn matches(&self, minute: u32, hour: u32, dom: u32, month: u32, dow: u32) -> bool {
        self.minute.matches(minute)
            && self.hour.matches(hour)
            && self.dom.matches(dom)
            && self.month.matches(month)
            && self.dow.matches(dow)
    }

    /// Compute seconds until the next matching time from `now`.
    fn seconds_until_next(&self, now: std::time::SystemTime) -> u64 {
        use std::time::UNIX_EPOCH;

        let secs_since_epoch = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        // Walk forward minute by minute, up to 8 days (enough to cover
        // any weekly pattern). Start from the next full minute.
        let start = secs_since_epoch - (secs_since_epoch % 60) + 60;
        let max_search = 8 * 24 * 60; // 8 days in minutes

        for i in 0..max_search {
            let candidate = start + i * 60;
            let (minute, hour, dom, month, dow) = epoch_to_fields(candidate);
            if self.matches(minute, hour, dom, month, dow) {
                return candidate - secs_since_epoch;
            }
        }

        // Fallback: 1 hour
        3600
    }
}

/// Convert Unix epoch seconds to (minute, hour, day-of-month, month, day-of-week).
fn epoch_to_fields(epoch_secs: u64) -> (u32, u32, u32, u32, u32) {
    // Simple calendar arithmetic (no leap second accuracy needed for cron).
    let days_since_epoch = (epoch_secs / 86400) as i64;
    let time_of_day = epoch_secs % 86400;
    let hour = (time_of_day / 3600) as u32;
    let minute = ((time_of_day % 3600) / 60) as u32;

    // Day of week: Jan 1 1970 was Thursday (4)
    let dow = ((days_since_epoch + 4) % 7) as u32; // 0=Sunday

    // Date from days since epoch
    let (year, month, day) = days_to_date(days_since_epoch);
    let _ = year; // unused

    (minute, hour, day as u32, month as u32, dow)
}

/// Convert days since Unix epoch to (year, month 1-12, day 1-31).
fn days_to_date(days: i64) -> (i64, i64, i64) {
    // Algorithm from Howard Hinnant's civil_from_days
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

async fn run_cron_trigger(
    schedule: CronSchedule,
    flow_name: &str,
    schedule_str: &str,
    ctx: Arc<crate::flow_tools::FlowContext>,
) {
    loop {
        let wait_secs = schedule.seconds_until_next(std::time::SystemTime::now());
        tracing::debug!(
            flow = %flow_name,
            schedule = %schedule_str,
            next_in_secs = wait_secs,
            "Cron trigger sleeping"
        );
        tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;

        tracing::info!(flow = %flow_name, schedule = %schedule_str, "Cron trigger fired");

        let args = serde_json::json!({
            "flow_name": flow_name,
            "prompt": format!("Scheduled execution: {schedule_str}"),
        });

        let ctx = Arc::clone(&ctx);
        let flow_owned = flow_name.to_string();
        // Spawn so the cron loop isn't blocked by flow execution
        tokio::spawn(async move {
            let result = crate::flow_tools::handle_flow_start(args, ctx, "cron-trigger").await;
            if result.is_err() {
                tracing::warn!(flow = %flow_owned, "Cron-triggered flow failed");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// File watch trigger
// ---------------------------------------------------------------------------

async fn run_file_watch_trigger(
    watch_path: &str,
    pattern: Option<&str>,
    flow_name: &str,
    debounce: std::time::Duration,
    ctx: Arc<crate::flow_tools::FlowContext>,
) -> anyhow::Result<()> {
    let path = std::path::Path::new(watch_path);
    if !path.exists() {
        anyhow::bail!("Watch path does not exist: {watch_path}");
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<std::path::PathBuf>>(64);

    // Compile glob pattern
    let glob_pattern = pattern
        .map(glob::Pattern::new)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid glob pattern: {e}"))?;

    let glob_for_watcher = glob_pattern.clone();
    let tx_watcher = tx.clone();

    // Start the notify watcher in a blocking context
    let watch_path_owned = watch_path.to_string();
    let debounce_ms = debounce.as_millis() as u64;

    let _watcher_task = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        let (notify_tx, notify_rx) = std::sync::mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |result: Result<Event, notify::Error>| {
                if let Ok(event) = result {
                    let _ = notify_tx.send(event);
                }
            },
            notify::Config::default(),
        )
        .expect("Failed to create file watcher");

        watcher
            .watch(
                std::path::Path::new(&watch_path_owned),
                RecursiveMode::Recursive,
            )
            .expect("Failed to start watching directory");

        let mut last_fire = std::time::Instant::now() - std::time::Duration::from_secs(10);
        let mut pending_paths: Vec<std::path::PathBuf> = Vec::new();

        loop {
            match notify_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(event) => {
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) => {
                            for path in &event.paths {
                                // Apply glob filter
                                if let Some(ref pat) = glob_for_watcher {
                                    let file_name =
                                        path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                                    if !pat.matches(file_name) {
                                        continue;
                                    }
                                }
                                if !pending_paths.contains(path) {
                                    pending_paths.push(path.clone());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }

            // Debounce: fire only after the debounce period has elapsed
            // since the last batch of events.
            if !pending_paths.is_empty()
                && last_fire.elapsed() >= std::time::Duration::from_millis(debounce_ms)
            {
                let paths = std::mem::take(&mut pending_paths);
                let tx = tx_watcher.clone();
                rt.spawn(async move {
                    let _ = tx.send(paths).await;
                });
                last_fire = std::time::Instant::now();
            }
        }
    });

    // Receive debounced file change batches and start flows
    let flow_name = flow_name.to_string();
    while let Some(changed_paths) = rx.recv().await {
        let paths_str: Vec<String> = changed_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();

        tracing::info!(
            flow = %flow_name,
            files = ?paths_str,
            "File watch trigger fired"
        );

        let args = serde_json::json!({
            "flow_name": &flow_name,
            "prompt": format!("File change detected: {}", paths_str.join(", ")),
            "parameters": {
                "changed_files": paths_str.join("\n"),
            },
        });

        let ctx = Arc::clone(&ctx);
        let flow = flow_name.clone();
        tokio::spawn(async move {
            let result =
                crate::flow_tools::handle_flow_start(args, ctx, "file-watch-trigger").await;
            if result.is_err() {
                tracing::warn!(flow = %flow, "File-watch-triggered flow failed");
            }
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- HMAC verification ---

    #[test]
    fn hmac_valid_signature() {
        let secret = b"test-secret";
        let body = b"hello world";

        // Compute expected HMAC
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(body);
        let result = mac.finalize();
        let hex_sig = hex::encode(result.into_bytes());

        assert!(verify_hmac_sha256(
            secret,
            body,
            &format!("sha256={hex_sig}")
        ));
    }

    #[test]
    fn hmac_invalid_signature() {
        let secret = b"test-secret";
        let body = b"hello world";
        assert!(!verify_hmac_sha256(secret, body, "sha256=deadbeef"));
    }

    #[test]
    fn hmac_missing_prefix() {
        let secret = b"test-secret";
        let body = b"hello world";

        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(body);
        let hex_sig = hex::encode(mac.finalize().into_bytes());

        // Should work even without sha256= prefix
        assert!(verify_hmac_sha256(secret, body, &hex_sig));
    }

    #[test]
    fn hmac_wrong_secret() {
        let body = b"payload";

        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(b"correct-secret").unwrap();
        mac.update(body);
        let hex_sig = hex::encode(mac.finalize().into_bytes());

        assert!(!verify_hmac_sha256(
            b"wrong-secret",
            body,
            &format!("sha256={hex_sig}")
        ));
    }

    // --- Cron parsing ---

    #[test]
    fn cron_parse_basic() {
        let schedule = CronSchedule::parse("0 9 * * 1-5").unwrap();
        assert!(matches!(schedule.minute, CronField::Values(ref v) if v == &[0]));
        assert!(matches!(schedule.hour, CronField::Values(ref v) if v == &[9]));
        assert!(matches!(schedule.dom, CronField::Any));
        assert!(matches!(schedule.month, CronField::Any));
        assert!(matches!(schedule.dow, CronField::Values(ref v) if v == &[1, 2, 3, 4, 5]));
    }

    #[test]
    fn cron_parse_every_5_minutes() {
        let schedule = CronSchedule::parse("*/5 * * * *").unwrap();
        if let CronField::Values(ref vals) = schedule.minute {
            assert!(vals.contains(&0));
            assert!(vals.contains(&5));
            assert!(vals.contains(&55));
            assert!(!vals.contains(&3));
        } else {
            panic!("Expected Values");
        }
    }

    #[test]
    fn cron_parse_list() {
        let schedule = CronSchedule::parse("0,30 8,17 * * *").unwrap();
        if let CronField::Values(ref vals) = schedule.minute {
            assert_eq!(vals, &[0, 30]);
        } else {
            panic!("Expected Values");
        }
        if let CronField::Values(ref vals) = schedule.hour {
            assert_eq!(vals, &[8, 17]);
        } else {
            panic!("Expected Values");
        }
    }

    #[test]
    fn cron_parse_invalid_field_count() {
        assert!(CronSchedule::parse("0 9 * *").is_err());
        assert!(CronSchedule::parse("0 9 * * * *").is_err());
    }

    #[test]
    fn cron_parse_out_of_range() {
        assert!(CronSchedule::parse("60 * * * *").is_err());
        assert!(CronSchedule::parse("* 24 * * *").is_err());
        assert!(CronSchedule::parse("* * 0 * *").is_err());
        assert!(CronSchedule::parse("* * * 13 *").is_err());
        assert!(CronSchedule::parse("* * * * 7").is_err());
    }

    #[test]
    fn cron_matches() {
        let schedule = CronSchedule::parse("30 14 * * 1-5").unwrap();
        // 14:30 on a Monday (dow=1)
        assert!(schedule.matches(30, 14, 15, 5, 1));
        // 14:30 on a Sunday (dow=0)
        assert!(!schedule.matches(30, 14, 15, 5, 0));
        // 15:30 on a Monday
        assert!(!schedule.matches(30, 15, 15, 5, 1));
    }

    #[test]
    fn cron_seconds_until_next_finds_match() {
        let schedule = CronSchedule::parse("* * * * *").unwrap();
        let wait = schedule.seconds_until_next(std::time::SystemTime::now());
        // Every minute: should be <= 60 seconds
        assert!(wait <= 60, "Expected <= 60, got {wait}");
    }

    #[test]
    fn cron_step_zero_rejected() {
        assert!(CronSchedule::parse("*/0 * * * *").is_err());
    }

    // --- Epoch to fields ---

    #[test]
    fn epoch_to_fields_known_date() {
        // 2024-01-15 09:50:00 UTC = 1705312200
        // Monday (dow=1), January (month=1), day=15
        let (minute, hour, dom, month, dow) = epoch_to_fields(1705312200);
        assert_eq!(minute, 50);
        assert_eq!(hour, 9);
        assert_eq!(dom, 15);
        assert_eq!(month, 1);
        assert_eq!(dow, 1); // Monday
    }

    #[test]
    fn epoch_unix_epoch_is_thursday() {
        let (minute, hour, dom, month, dow) = epoch_to_fields(0);
        assert_eq!(minute, 0);
        assert_eq!(hour, 0);
        assert_eq!(dom, 1);
        assert_eq!(month, 1);
        assert_eq!(dow, 4); // Thursday
    }

    // --- TriggerConfig deserialization ---

    #[test]
    fn deserialize_webhook_trigger() {
        let toml = r#"
[[triggers]]
type = "webhook"
path = "/hook/deploy"
secret = "my-secret"
flow_name = "review"
"#;
        #[derive(Deserialize)]
        struct Wrapper {
            triggers: Vec<TriggerConfig>,
        }
        let w: Wrapper = toml::from_str(toml).unwrap();
        assert_eq!(w.triggers.len(), 1);
        match &w.triggers[0] {
            TriggerConfig::Webhook {
                path,
                secret,
                flow_name,
            } => {
                assert_eq!(path, "/hook/deploy");
                assert_eq!(secret.as_deref(), Some("my-secret"));
                assert_eq!(flow_name, "review");
            }
            _ => panic!("Expected Webhook"),
        }
    }

    #[test]
    fn deserialize_cron_trigger() {
        let toml = r#"
[[triggers]]
type = "cron"
schedule = "0 9 * * 1-5"
flow_name = "daily-review"
"#;
        #[derive(Deserialize)]
        struct Wrapper {
            triggers: Vec<TriggerConfig>,
        }
        let w: Wrapper = toml::from_str(toml).unwrap();
        match &w.triggers[0] {
            TriggerConfig::Cron {
                schedule,
                flow_name,
            } => {
                assert_eq!(schedule, "0 9 * * 1-5");
                assert_eq!(flow_name, "daily-review");
            }
            _ => panic!("Expected Cron"),
        }
    }

    #[test]
    fn deserialize_file_watch_trigger() {
        let toml = r#"
[[triggers]]
type = "file_watch"
path = "~/Documents/inbox"
pattern = "*.pdf"
flow_name = "process-document"
debounce_ms = 1000
"#;
        #[derive(Deserialize)]
        struct Wrapper {
            triggers: Vec<TriggerConfig>,
        }
        let w: Wrapper = toml::from_str(toml).unwrap();
        match &w.triggers[0] {
            TriggerConfig::FileWatch {
                path,
                pattern,
                flow_name,
                debounce_ms,
            } => {
                assert_eq!(path, "~/Documents/inbox");
                assert_eq!(pattern.as_deref(), Some("*.pdf"));
                assert_eq!(flow_name, "process-document");
                assert_eq!(*debounce_ms, Some(1000));
            }
            _ => panic!("Expected FileWatch"),
        }
    }

    #[test]
    fn deserialize_mixed_triggers() {
        let toml = r#"
[[triggers]]
type = "webhook"
path = "/hook/deploy"
flow_name = "deploy"

[[triggers]]
type = "cron"
schedule = "*/30 * * * *"
flow_name = "health-check"

[[triggers]]
type = "file_watch"
path = "/tmp/inbox"
flow_name = "ingest"
"#;
        #[derive(Deserialize)]
        struct Wrapper {
            triggers: Vec<TriggerConfig>,
        }
        let w: Wrapper = toml::from_str(toml).unwrap();
        assert_eq!(w.triggers.len(), 3);
    }

    // --- File watch debounce (unit-level) ---

    #[test]
    fn glob_pattern_matches() {
        let pat = glob::Pattern::new("*.pdf").unwrap();
        assert!(pat.matches("report.pdf"));
        assert!(!pat.matches("report.txt"));
        assert!(!pat.matches("report.pdf.bak"));
    }
}
