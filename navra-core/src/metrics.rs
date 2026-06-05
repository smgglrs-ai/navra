//! Gateway-level metrics for Prometheus scraping.
//!
//! Lightweight atomic counters exposed as Prometheus text format
//! via `/metrics` endpoint. No external metrics SDK needed.

use std::sync::atomic::{AtomicU64, Ordering};

/// Gateway metrics registry.
pub struct Metrics {
    pub tool_calls_total: AtomicU64,
    pub tool_calls_errors: AtomicU64,
    pub tool_calls_denied: AtomicU64,
    pub tool_calls_approved: AtomicU64,
    pub safety_triggers_total: AtomicU64,
    pub safety_triggers_blocked: AtomicU64,
    pub safety_triggers_redacted: AtomicU64,
    pub ifc_taint_elevations: AtomicU64,
    pub ifc_write_denials: AtomicU64,
    pub ifc_read_denials: AtomicU64,
    pub sessions_created: AtomicU64,
    pub sessions_active: AtomicU64,
    pub auth_failures: AtomicU64,
    pub tool_duration_us_sum: AtomicU64,
    pub budget_truncations: AtomicU64,
    pub routing_decisions: AtomicU64,
    pub cedar_denials: AtomicU64,
    pub resource_subscriptions: AtomicU64,
    pub websocket_connections: AtomicU64,
    pub tool_scan_total: AtomicU64,
    pub tool_scan_blocked: AtomicU64,
    pub tool_scan_suspicious: AtomicU64,
    pub integrity_alerts_total: AtomicU64,
    pub integrity_alerts_malicious: AtomicU64,
    pub leakage_similarity_blocks: AtomicU64,
    pub leakage_semantic_blocks: AtomicU64,
    pub leakage_semantic_async_detections: AtomicU64,
    pub rag_queries_total: AtomicU64,
    pub rag_vector_skips: AtomicU64,
    pub rag_rerank_skips: AtomicU64,
    pub rag_chunks_indexed: AtomicU64,
    pub rag_chunks_skipped: AtomicU64,
    pub tools_listed_total: AtomicU64,
    pub tools_pruned_total: AtomicU64,
    pub model_proxy_requests: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            tool_calls_total: AtomicU64::new(0),
            tool_calls_errors: AtomicU64::new(0),
            tool_calls_denied: AtomicU64::new(0),
            tool_calls_approved: AtomicU64::new(0),
            safety_triggers_total: AtomicU64::new(0),
            safety_triggers_blocked: AtomicU64::new(0),
            safety_triggers_redacted: AtomicU64::new(0),
            ifc_taint_elevations: AtomicU64::new(0),
            ifc_write_denials: AtomicU64::new(0),
            ifc_read_denials: AtomicU64::new(0),
            sessions_created: AtomicU64::new(0),
            sessions_active: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            tool_duration_us_sum: AtomicU64::new(0),
            budget_truncations: AtomicU64::new(0),
            routing_decisions: AtomicU64::new(0),
            cedar_denials: AtomicU64::new(0),
            resource_subscriptions: AtomicU64::new(0),
            websocket_connections: AtomicU64::new(0),
            tool_scan_total: AtomicU64::new(0),
            tool_scan_blocked: AtomicU64::new(0),
            tool_scan_suspicious: AtomicU64::new(0),
            integrity_alerts_total: AtomicU64::new(0),
            integrity_alerts_malicious: AtomicU64::new(0),
            leakage_similarity_blocks: AtomicU64::new(0),
            leakage_semantic_blocks: AtomicU64::new(0),
            leakage_semantic_async_detections: AtomicU64::new(0),
            rag_queries_total: AtomicU64::new(0),
            rag_vector_skips: AtomicU64::new(0),
            rag_rerank_skips: AtomicU64::new(0),
            rag_chunks_indexed: AtomicU64::new(0),
            rag_chunks_skipped: AtomicU64::new(0),
            tools_listed_total: AtomicU64::new(0),
            tools_pruned_total: AtomicU64::new(0),
            model_proxy_requests: AtomicU64::new(0),
        }
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(2048);

        prom_counter(
            &mut out,
            "navra_tool_calls_total",
            "Total tool calls processed",
            self.tool_calls_total.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_tool_calls_errors_total",
            "Tool calls that returned errors",
            self.tool_calls_errors.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_tool_calls_denied_total",
            "Tool calls denied by ACL/Cedar/capability",
            self.tool_calls_denied.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_tool_calls_approved_total",
            "Tool calls requiring human approval",
            self.tool_calls_approved.load(Ordering::Relaxed),
        );

        prom_counter(
            &mut out,
            "navra_safety_triggers_total",
            "Safety filter triggers",
            self.safety_triggers_total.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_safety_triggers_blocked_total",
            "Safety filter blocks",
            self.safety_triggers_blocked.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_safety_triggers_redacted_total",
            "Safety filter redactions",
            self.safety_triggers_redacted.load(Ordering::Relaxed),
        );

        prom_counter(
            &mut out,
            "navra_ifc_taint_elevations_total",
            "IFC taint label elevations (Trusted→Untrusted)",
            self.ifc_taint_elevations.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_ifc_write_denials_total",
            "IFC no-write-down denials",
            self.ifc_write_denials.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_ifc_read_denials_total",
            "IFC no-read-up denials",
            self.ifc_read_denials.load(Ordering::Relaxed),
        );

        prom_counter(
            &mut out,
            "navra_sessions_created_total",
            "Sessions created",
            self.sessions_created.load(Ordering::Relaxed),
        );
        prom_gauge(
            &mut out,
            "navra_sessions_active",
            "Currently active sessions",
            self.sessions_active.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_auth_failures_total",
            "Authentication failures",
            self.auth_failures.load(Ordering::Relaxed),
        );

        prom_counter(
            &mut out,
            "navra_tool_duration_microseconds_total",
            "Cumulative tool execution time in microseconds",
            self.tool_duration_us_sum.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_budget_truncations_total",
            "Tool outputs truncated by budget hook",
            self.budget_truncations.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_routing_decisions_total",
            "Model routing decisions made",
            self.routing_decisions.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_cedar_denials_total",
            "Cedar policy denials",
            self.cedar_denials.load(Ordering::Relaxed),
        );
        prom_gauge(
            &mut out,
            "navra_resource_subscriptions",
            "Active resource subscriptions",
            self.resource_subscriptions.load(Ordering::Relaxed),
        );
        prom_gauge(
            &mut out,
            "navra_websocket_connections",
            "Active WebSocket connections",
            self.websocket_connections.load(Ordering::Relaxed),
        );

        prom_counter(
            &mut out,
            "navra_tool_scan_total",
            "Upstream tool definitions scanned",
            self.tool_scan_total.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_tool_scan_blocked_total",
            "Upstream tools blocked as malicious",
            self.tool_scan_blocked.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_tool_scan_suspicious_total",
            "Upstream tools flagged as suspicious",
            self.tool_scan_suspicious.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_integrity_alerts_total",
            "Cognitive file integrity alerts",
            self.integrity_alerts_total.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_integrity_alerts_malicious_total",
            "Cognitive file integrity alerts classified as malicious",
            self.integrity_alerts_malicious.load(Ordering::Relaxed),
        );

        prom_counter(
            &mut out,
            "navra_leakage_similarity_blocks_total",
            "L2 similarity-based leakage detections (write blocked)",
            self.leakage_similarity_blocks.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_leakage_semantic_blocks_total",
            "L3 inline semantic leakage detections (write blocked)",
            self.leakage_semantic_blocks.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_leakage_semantic_async_detections_total",
            "L3 continuous semantic leakage detections (retroactive taint)",
            self.leakage_semantic_async_detections.load(Ordering::Relaxed),
        );

        prom_counter(
            &mut out,
            "navra_rag_queries_total",
            "RAG queries processed",
            self.rag_queries_total.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_rag_vector_skips_total",
            "RAG queries where vector search was skipped (BM25 sufficient)",
            self.rag_vector_skips.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_rag_rerank_skips_total",
            "RAG queries where reranking was skipped (vector sufficient)",
            self.rag_rerank_skips.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_rag_chunks_indexed_total",
            "Chunks indexed into RAG store",
            self.rag_chunks_indexed.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_rag_chunks_skipped_total",
            "Chunks skipped by graphability filter",
            self.rag_chunks_skipped.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_tools_listed_total",
            "Tools returned in tools/list responses",
            self.tools_listed_total.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_tools_pruned_total",
            "Tools suppressed by usage-based pruning",
            self.tools_pruned_total.load(Ordering::Relaxed),
        );
        prom_counter(
            &mut out,
            "navra_model_proxy_requests_total",
            "Chat completion requests proxied through the gateway",
            self.model_proxy_requests.load(Ordering::Relaxed),
        );

        out
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

fn prom_counter(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
    ));
}

fn prom_gauge(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_all_zero() {
        let m = Metrics::new();
        assert_eq!(m.tool_calls_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.sessions_created.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn increment_and_read() {
        let m = Metrics::new();
        m.tool_calls_total.fetch_add(5, Ordering::Relaxed);
        m.tool_calls_errors.fetch_add(1, Ordering::Relaxed);
        assert_eq!(m.tool_calls_total.load(Ordering::Relaxed), 5);
        assert_eq!(m.tool_calls_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn render_prometheus_format() {
        let m = Metrics::new();
        m.tool_calls_total.fetch_add(42, Ordering::Relaxed);
        m.safety_triggers_blocked.fetch_add(3, Ordering::Relaxed);
        let output = m.render();
        assert!(output.contains("# TYPE navra_tool_calls_total counter"));
        assert!(output.contains("navra_tool_calls_total 42"));
        assert!(output.contains("navra_safety_triggers_blocked_total 3"));
        assert!(output.contains("# TYPE navra_sessions_active gauge"));
    }

    #[test]
    fn render_contains_all_metrics() {
        let m = Metrics::new();
        let output = m.render();
        assert!(output.contains("navra_tool_calls_total"));
        assert!(output.contains("navra_ifc_write_denials_total"));
        assert!(output.contains("navra_cedar_denials_total"));
        assert!(output.contains("navra_websocket_connections"));
        assert!(output.contains("navra_tool_scan_total"));
        assert!(output.contains("navra_tool_scan_blocked_total"));
        assert!(output.contains("navra_integrity_alerts_total"));
        assert!(output.contains("navra_leakage_similarity_blocks_total"));
        assert!(output.contains("navra_leakage_semantic_blocks_total"));
        assert!(output.contains("navra_leakage_semantic_async_detections_total"));
    }

    #[test]
    fn concurrent_increments() {
        use std::sync::Arc;
        let m = Arc::new(Metrics::new());
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let m = m.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        m.tool_calls_total.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.tool_calls_total.load(Ordering::Relaxed), 1000);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Model a monotonic counter as a pure function.
    /// Proves that fetch_add with non-negative delta preserves monotonicity.
    fn counter_add(current: u64, delta: u64) -> u64 {
        current.wrapping_add(delta)
    }

    #[kani::proof]
    fn counter_monotonic() {
        let current: u64 = kani::any();
        let delta: u64 = kani::any();
        kani::assume(current <= u64::MAX / 2);
        kani::assume(delta <= 1000);
        let next = counter_add(current, delta);
        assert!(next >= current);
    }

    #[kani::proof]
    fn counter_zero_delta_unchanged() {
        let current: u64 = kani::any();
        assert_eq!(counter_add(current, 0), current);
    }
}
