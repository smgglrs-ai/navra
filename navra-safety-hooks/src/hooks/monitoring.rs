//! Tier 2 detect-only monitoring agent.
//!
//! Observes hook decisions and tool-call outcomes without modifying
//! the data path. When a Tier 1 hook blocks, escalates, or detects
//! anomalies, an `EscalationEvent` is sent to an async channel.
//! A background task consumes events, produces structured `Verdict`s,
//! and logs them to the blackbox audit trail.

use super::{Hook, HookDecision};
use navra_auth::auth::CallContext;
use navra_protocol::CallToolResult;

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Sink for recording monitoring verdicts to the audit trail.
///
/// Implemented by navra-server to bridge to the Blackbox without
/// creating a circular dependency.
pub trait VerdictSink: Send + Sync + 'static {
    fn record_verdict(&self, event: &EscalationEvent, verdict: &Verdict);
}

/// Severity of an escalated event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Source hook that produced the escalation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationSource {
    SafetyHook,
    StatisticalGuardrail,
    TemporalContract,
    EgressFilter,
    LeakageDetection,
    ToolGuard,
    IFCDenial,
    AclDenial,
    Other(String),
}

/// An event escalated from Tier 1 hooks to the monitoring agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationEvent {
    pub timestamp_ms: i64,
    pub session_id: String,
    pub agent_name: String,
    pub tool_name: String,
    pub source: EscalationSource,
    pub severity: Severity,
    pub reason: String,
    pub tool_args_summary: Option<String>,
}

/// Verdict produced by the monitoring agent after analyzing an escalation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub timestamp_ms: i64,
    pub event_session_id: String,
    pub event_tool_name: String,
    pub source: EscalationSource,
    pub severity: Severity,
    pub technique: Option<String>,
    pub evidence: Vec<String>,
    pub recommendation: String,
    pub is_confirmed_threat: bool,
}

/// Sender half of the escalation channel.
///
/// Cloned into each Tier 1 hook that needs to escalate events.
/// Sending is best-effort — if the channel is full, the event
/// is dropped with a warning (never blocks the hot path).
#[derive(Clone)]
pub struct EscalationSender {
    tx: mpsc::Sender<EscalationEvent>,
}

impl EscalationSender {
    pub fn send(&self, event: EscalationEvent) {
        if let Err(e) = self.tx.try_send(event) {
            tracing::warn!("Escalation channel full or closed, dropping event: {e}");
        }
    }
}

/// Create an escalation channel pair.
///
/// `buffer_size` controls backpressure — events beyond this count
/// are dropped (the monitoring path must never block the tool-call
/// hot path).
pub fn escalation_channel(
    buffer_size: usize,
) -> (EscalationSender, mpsc::Receiver<EscalationEvent>) {
    let (tx, rx) = mpsc::channel(buffer_size);
    (EscalationSender { tx }, rx)
}

/// Counters for monitoring verdicts, exposed via Prometheus.
pub struct MonitoringMetrics {
    pub escalations_received: AtomicU64,
    pub verdicts_produced: AtomicU64,
    pub verdicts_confirmed_threat: AtomicU64,
}

impl MonitoringMetrics {
    pub fn new() -> Self {
        Self {
            escalations_received: AtomicU64::new(0),
            verdicts_produced: AtomicU64::new(0),
            verdicts_confirmed_threat: AtomicU64::new(0),
        }
    }
}

impl Default for MonitoringMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Observation-only hook that watches for block/escalate decisions
/// from Tier 1 hooks and forwards them to the monitoring channel.
///
/// This hook always returns `Continue` — it never modifies arguments,
/// results, or blocks tool calls. It sits at the end of the hook
/// pipeline and observes outcomes.
pub struct MonitoringHook {
    sender: EscalationSender,
}

impl MonitoringHook {
    pub fn new(sender: EscalationSender) -> Self {
        Self { sender }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }
}

#[async_trait::async_trait]
impl Hook for MonitoringHook {
    fn name(&self) -> &str {
        "monitoring"
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        result: &CallToolResult,
        ctx: &CallContext,
    ) -> HookDecision {
        // Observe error results — these indicate a prior hook blocked
        // the call or the tool itself failed. We escalate blocked calls.
        if result.is_error == Some(true) {
            let reason = result
                .content
                .first()
                .and_then(|c| match &c.raw {
                    navra_protocol::RawContent::Text(t) => Some(t.text.clone()),
                    _ => None,
                })
                .unwrap_or_default();

            // Heuristic: blocked by policy/hook vs runtime error
            let (source, severity) = classify_error(&reason);

            self.sender.send(EscalationEvent {
                timestamp_ms: Self::now_ms(),
                session_id: ctx.session_id.clone(),
                agent_name: ctx.agent.name.clone(),
                tool_name: tool_name.to_string(),
                source,
                severity,
                reason,
                tool_args_summary: None,
            });
        }

        HookDecision::Continue
    }
}

fn classify_error(reason: &str) -> (EscalationSource, Severity) {
    let lower = reason.to_lowercase();
    if lower.contains("ifc")
        || lower.contains("taint")
        || lower.contains("no-write-down")
        || lower.contains("no-read-up")
    {
        (EscalationSource::IFCDenial, Severity::High)
    } else if lower.contains("acl")
        || lower.contains("permission denied")
        || lower.contains("cedar")
    {
        (EscalationSource::AclDenial, Severity::Medium)
    } else if lower.contains("safety") || lower.contains("content filter") {
        (EscalationSource::SafetyHook, Severity::High)
    } else if lower.contains("leakage") || lower.contains("exfiltration") {
        (EscalationSource::LeakageDetection, Severity::Critical)
    } else if lower.contains("egress") || lower.contains("blocked domain") {
        (EscalationSource::EgressFilter, Severity::Medium)
    } else if lower.contains("anomal") || lower.contains("drift") || lower.contains("entropy") {
        (EscalationSource::StatisticalGuardrail, Severity::Medium)
    } else if lower.contains("contract") || lower.contains("escalat") || lower.contains("temporal")
    {
        (EscalationSource::TemporalContract, Severity::Medium)
    } else if lower.contains("tool_guard") || lower.contains("malicious") {
        (EscalationSource::ToolGuard, Severity::High)
    } else {
        (EscalationSource::Other("unknown".into()), Severity::Low)
    }
}

/// Background task that consumes escalation events and produces verdicts.
///
/// This is the Tier 2 reasoning loop. In the initial implementation it
/// applies rule-based classification without LLM reasoning. LLM-backed
/// analysis is a future extension.
pub async fn monitoring_loop(
    mut rx: mpsc::Receiver<EscalationEvent>,
    metrics: Arc<MonitoringMetrics>,
    sink: Option<Arc<dyn VerdictSink>>,
) {
    tracing::info!("Monitoring agent started (detect-only, async)");

    while let Some(event) = rx.recv().await {
        metrics.escalations_received.fetch_add(1, Ordering::Relaxed);

        let verdict = analyze_event(&event);

        if let Some(ref s) = sink {
            s.record_verdict(&event, &verdict);
        }

        metrics.verdicts_produced.fetch_add(1, Ordering::Relaxed);
        if verdict.is_confirmed_threat {
            metrics
                .verdicts_confirmed_threat
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                session = %event.session_id,
                tool = %event.tool_name,
                severity = ?verdict.severity,
                technique = ?verdict.technique,
                "Monitoring verdict: confirmed threat"
            );
        } else {
            tracing::debug!(
                session = %event.session_id,
                tool = %event.tool_name,
                severity = ?verdict.severity,
                "Monitoring verdict: not confirmed"
            );
        }
    }

    tracing::info!("Monitoring agent stopped (channel closed)");
}

fn analyze_event(event: &EscalationEvent) -> Verdict {
    let (technique, is_threat) = match &event.source {
        EscalationSource::IFCDenial => (
            Some("information_flow_violation".to_string()),
            event.severity as u8 >= Severity::High as u8,
        ),
        EscalationSource::LeakageDetection => (Some("data_exfiltration".to_string()), true),
        EscalationSource::SafetyHook => (
            Some("content_policy_violation".to_string()),
            event.severity as u8 >= Severity::High as u8,
        ),
        EscalationSource::ToolGuard => (Some("malicious_tool_definition".to_string()), true),
        EscalationSource::StatisticalGuardrail => (Some("behavioral_anomaly".to_string()), false),
        EscalationSource::TemporalContract => {
            (Some("temporal_contract_violation".to_string()), false)
        }
        EscalationSource::EgressFilter => (
            Some("unauthorized_egress".to_string()),
            event.severity as u8 >= Severity::High as u8,
        ),
        EscalationSource::AclDenial => (Some("privilege_escalation_attempt".to_string()), false),
        EscalationSource::Other(_) => (None, false),
    };

    let recommendation = if is_threat {
        format!(
            "Review session {} for {} activity",
            event.session_id,
            technique.as_deref().unwrap_or("suspicious")
        )
    } else {
        "No action required — logged for audit".to_string()
    };

    Verdict {
        timestamp_ms: MonitoringHook::now_ms(),
        event_session_id: event.session_id.clone(),
        event_tool_name: event.tool_name.clone(),
        source: event.source.clone(),
        severity: event.severity,
        technique,
        evidence: vec![event.reason.clone()],
        recommendation,
        is_confirmed_threat: is_threat,
    }
}

/// Configuration for the monitoring agent.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct MonitoringConfig {
    /// Whether the monitoring agent is enabled. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Escalation channel buffer size. Default: 256.
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_buffer_size() -> usize {
    256
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            buffer_size: default_buffer_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_auth::auth::{AgentIdentity, CallContext};
    use navra_protocol::compat::CallToolResultExt;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("test-agent", "dev"), "test-session")
    }

    #[test]
    fn escalation_channel_send_receive() {
        let (sender, mut rx) = escalation_channel(16);

        let event = EscalationEvent {
            timestamp_ms: 1000,
            session_id: "s1".into(),
            agent_name: "agent-a".into(),
            tool_name: "file_write".into(),
            source: EscalationSource::IFCDenial,
            severity: Severity::High,
            reason: "no-write-down violation".into(),
            tool_args_summary: None,
        };

        sender.send(event.clone());
        let received = rx.try_recv().unwrap();
        assert_eq!(received.session_id, "s1");
        assert_eq!(received.tool_name, "file_write");
    }

    #[test]
    fn escalation_channel_drops_when_full() {
        let (sender, _rx) = escalation_channel(1);

        let event = EscalationEvent {
            timestamp_ms: 1000,
            session_id: "s1".into(),
            agent_name: "a".into(),
            tool_name: "t".into(),
            source: EscalationSource::SafetyHook,
            severity: Severity::Low,
            reason: "test".into(),
            tool_args_summary: None,
        };

        sender.send(event.clone());
        // Channel capacity is 1, this should not panic
        sender.send(event);
    }

    #[test]
    fn classify_error_ifc() {
        let (src, sev) = classify_error("IFC no-write-down violation");
        assert!(matches!(src, EscalationSource::IFCDenial));
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn classify_error_leakage() {
        let (src, sev) = classify_error("Leakage detected: data exfiltration attempt");
        assert!(matches!(src, EscalationSource::LeakageDetection));
        assert_eq!(sev, Severity::Critical);
    }

    #[test]
    fn classify_error_unknown() {
        let (src, sev) = classify_error("something went wrong");
        assert!(matches!(src, EscalationSource::Other(_)));
        assert_eq!(sev, Severity::Low);
    }

    #[test]
    fn analyze_event_ifc_is_threat() {
        let event = EscalationEvent {
            timestamp_ms: 1000,
            session_id: "s1".into(),
            agent_name: "a".into(),
            tool_name: "file_write".into(),
            source: EscalationSource::IFCDenial,
            severity: Severity::High,
            reason: "no-write-down".into(),
            tool_args_summary: None,
        };
        let verdict = analyze_event(&event);
        assert!(verdict.is_confirmed_threat);
        assert_eq!(
            verdict.technique.as_deref(),
            Some("information_flow_violation")
        );
    }

    #[test]
    fn analyze_event_statistical_not_threat() {
        let event = EscalationEvent {
            timestamp_ms: 1000,
            session_id: "s1".into(),
            agent_name: "a".into(),
            tool_name: "echo".into(),
            source: EscalationSource::StatisticalGuardrail,
            severity: Severity::Medium,
            reason: "entropy anomaly".into(),
            tool_args_summary: None,
        };
        let verdict = analyze_event(&event);
        assert!(!verdict.is_confirmed_threat);
        assert_eq!(verdict.technique.as_deref(), Some("behavioral_anomaly"));
    }

    #[test]
    fn verdict_serializes_to_json() {
        let verdict = Verdict {
            timestamp_ms: 1000,
            event_session_id: "s1".into(),
            event_tool_name: "file_write".into(),
            source: EscalationSource::IFCDenial,
            severity: Severity::High,
            technique: Some("information_flow_violation".into()),
            evidence: vec!["no-write-down violation".into()],
            recommendation: "Review session".into(),
            is_confirmed_threat: true,
        };
        let json = serde_json::to_string(&verdict).unwrap();
        assert!(json.contains("information_flow_violation"));
        assert!(json.contains("\"is_confirmed_threat\":true"));
    }

    #[tokio::test]
    async fn monitoring_hook_continues_on_success() {
        let (sender, _rx) = escalation_channel(16);
        let hook = MonitoringHook::new(sender);

        let result = CallToolResult::text("success");
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn monitoring_hook_escalates_on_error() {
        let (sender, mut rx) = escalation_channel(16);
        let hook = MonitoringHook::new(sender);

        let result = CallToolResult::error_msg("IFC no-write-down violation");
        let decision = hook
            .post_tool_use("file_write", &serde_json::json!({}), &result, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));

        let event = rx.try_recv().unwrap();
        assert_eq!(event.tool_name, "file_write");
        assert!(matches!(event.source, EscalationSource::IFCDenial));
        assert_eq!(event.severity, Severity::High);
    }

    #[tokio::test]
    async fn monitoring_loop_processes_events() {
        let (sender, rx) = escalation_channel(16);
        let metrics = Arc::new(MonitoringMetrics::new());
        let metrics_clone = metrics.clone();

        let handle = tokio::spawn(monitoring_loop(rx, metrics_clone, None));

        sender.send(EscalationEvent {
            timestamp_ms: 1000,
            session_id: "s1".into(),
            agent_name: "a".into(),
            tool_name: "file_write".into(),
            source: EscalationSource::IFCDenial,
            severity: Severity::High,
            reason: "test".into(),
            tool_args_summary: None,
        });

        // Drop sender to close the channel and let the loop finish
        drop(sender);
        handle.await.unwrap();

        assert_eq!(metrics.escalations_received.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.verdicts_produced.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.verdicts_confirmed_threat.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn monitoring_config_defaults() {
        let cfg = MonitoringConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.buffer_size, 256);
    }

    #[test]
    fn monitoring_config_deserialize() {
        let toml = r#"
            enabled = true
            buffer_size = 512
        "#;
        let cfg: MonitoringConfig = toml::from_str(toml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.buffer_size, 512);
    }
}
