//! Hook pipeline wiring.
//!
//! Registers BudgetHook, SafetyHook, statistical guardrail, temporal
//! contracts, memory extraction, causal provenance, monitoring,
//! tool usage pruning, and DMN guardrails.

use crate::config;
use crate::setup::safety::{SafetyFilterState, build_safety_pipeline};
use std::sync::Arc;

/// Wire all hooks onto the server builder.
///
/// Returns the builder and the usage tracker (needed externally).
pub(crate) fn wire_hooks(
    mut builder: navra_core::McpServerBuilder,
    cfg: &config::Config,
    safety_state: &SafetyFilterState,
    knowledge_store: &Option<Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>>,
) -> navra_core::McpServerBuilder {
    // --- BudgetHook + SafetyHook ---
    if cfg.budget.max_tool_output_tokens > 0 {
        use navra_core::hooks::{BudgetHook, TruncationStrategy};

        let strategy = match cfg.budget.truncation_strategy.as_str() {
            "truncate" => TruncationStrategy::Truncate,
            "head_tail" => TruncationStrategy::HeadTail {
                head_ratio: cfg.budget.head_ratio,
            },
            "summarize" => TruncationStrategy::Summarize,
            other => {
                tracing::warn!(
                    strategy = %other,
                    "Unknown truncation strategy, defaulting to head_tail"
                );
                TruncationStrategy::HeadTail {
                    head_ratio: cfg.budget.head_ratio,
                }
            }
        };

        // Build SafetyHook using the shared pipeline builder
        let mut safety_hook = navra_core::hooks::SafetyHook::new(std::collections::HashMap::new());
        for (name, pset) in &cfg.permissions {
            let pipeline =
                build_safety_pipeline(pset, name, &cfg.models, safety_state, &cfg.canary_tokens);
            safety_hook.add_pipeline(name.clone(), pipeline);
        }
        builder = builder.hook(safety_hook);

        // Egress endpoint filtering
        {
            let mut allowed = Vec::new();
            let mut blocked = Vec::new();
            let mut deny_all = false;
            for pset in cfg.permissions.values() {
                allowed.extend(pset.egress_allowed_domains.iter().cloned());
                blocked.extend(pset.egress_blocked_domains.iter().cloned());
                if pset.egress_deny_all_external {
                    deny_all = true;
                }
            }
            if deny_all || !allowed.is_empty() || !blocked.is_empty() {
                let egress_config = navra_core::hooks::EgressConfig {
                    enabled: true,
                    allowed_domains: allowed,
                    blocked_domains: blocked,
                    deny_all_external: deny_all,
                    block_tainted_egress: true,
                };
                builder = builder.hook(navra_core::hooks::EgressFilterHook::new(egress_config));
                tracing::info!("Egress endpoint filtering enabled from permission config");
            }
        }

        // Supply chain argument guard
        builder = builder.hook(navra_core::hooks::SupplyChainGuardHook);

        builder = builder.hook(BudgetHook::new(cfg.budget.max_tool_output_tokens, strategy));
        tracing::info!(
            max_tokens = cfg.budget.max_tool_output_tokens,
            strategy = %cfg.budget.truncation_strategy,
            "Context budget enforcement enabled"
        );
    }

    // --- Statistical guardrail ---
    if cfg.statistical.enabled {
        let hook_config = cfg.statistical.to_hook_config();
        tracing::info!(
            cosine_window = hook_config.cosine_window,
            cosine_z_threshold = hook_config.cosine_z_threshold,
            entropy_window = hook_config.entropy_window,
            entropy_min = hook_config.entropy_min,
            entropy_max = hook_config.entropy_max,
            block_on_anomaly = hook_config.block_on_anomaly,
            "Statistical guardrail enabled"
        );
        builder = builder.hook(navra_core::hooks::StatisticalGuardrailHook::new(
            hook_config,
        ));
    }

    // --- Temporal behavioral contracts ---
    if cfg.temporal_contracts.enabled && !cfg.temporal_contracts.contracts.is_empty() {
        let action_log = Arc::new(navra_core::hooks::SessionActionLog::new(
            cfg.temporal_contracts.max_history_per_session,
        ));
        let mut contracts = Vec::new();
        for tc in &cfg.temporal_contracts.contracts {
            match serde_json::from_value::<navra_core::hooks::TemporalContract>(serde_json::json!({
                "name": tc.name,
                "description": tc.description,
                "predicate": tc.predicate,
                "action": tc.action,
                "applies_to": tc.applies_to,
            })) {
                Ok(contract) => contracts.push(contract),
                Err(e) => {
                    tracing::warn!(
                        contract = %tc.name,
                        error = %e,
                        "Failed to parse temporal contract — skipping"
                    );
                }
            }
        }
        tracing::info!(
            count = contracts.len(),
            "Temporal behavioral contracts enabled"
        );
        builder = builder.hook(navra_core::hooks::TemporalContractHook::new(
            action_log, contracts,
        ));
    }

    // --- Memory extraction hook ---
    if let Some(ks) = knowledge_store {
        struct KnowledgeExtractionStore(Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>);
        impl navra_core::hooks::ExtractionStore for KnowledgeExtractionStore {
            fn store_extraction(
                &self,
                title: &str,
                content: &str,
                session_id: &str,
                tags: &[String],
            ) {
                if let Ok(store) = self.0.lock() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let entry = navra_memory::MemoryEntry {
                        id: uuid::Uuid::new_v4().to_string(),
                        memory_type: navra_memory::MemoryType::Fact,
                        title: title.to_string(),
                        content: content.to_string(),
                        tags: tags.to_vec(),
                        created_at: now,
                        updated_at: None,
                    };
                    let scope = navra_memory::MemoryScope {
                        session_id: Some(session_id.to_string()),
                        ..Default::default()
                    };
                    let _ = store.store_scoped(&entry, &scope, None);
                }
            }
        }
        let hook = navra_core::hooks::MemoryExtractionHook::new(
            Arc::new(KnowledgeExtractionStore(Arc::clone(ks))),
            navra_core::hooks::MemoryExtractionConfig::default(),
        );
        builder = builder.hook(hook);
        tracing::info!("Memory extraction hook enabled");
    }

    // --- Causal provenance hook ---
    {
        let causal_db_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra")
            .join("causal_provenance.db");
        match navra_flow::causal_graph::CausalGraphStore::open(&causal_db_path) {
            Ok(store) => {
                let store = Arc::new(store);
                tracing::info!(
                    path = %causal_db_path.display(),
                    "Causal provenance graph enabled"
                );
                builder = builder.hook(navra_core::hooks::ProvenanceHook::new(
                    store as Arc<dyn navra_core::hooks::CausalSink>,
                ));
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to open causal provenance DB — provenance tracking disabled"
                );
            }
        }
    }

    // --- Monitoring agent ---
    if cfg.monitoring.enabled {
        let (escalation_tx, escalation_rx) =
            navra_core::hooks::escalation_channel(cfg.monitoring.buffer_size);

        builder = builder.hook(navra_core::hooks::MonitoringHook::new(escalation_tx));

        let monitoring_metrics = Arc::new(navra_core::hooks::MonitoringMetrics::new());

        struct BlackboxVerdictSink(Arc<navra_core::blackbox::Blackbox>);
        impl navra_core::hooks::VerdictSink for BlackboxVerdictSink {
            fn record_verdict(
                &self,
                event: &navra_core::hooks::EscalationEvent,
                verdict: &navra_core::hooks::Verdict,
            ) {
                let verdict_json = serde_json::to_string(verdict).unwrap_or_default();
                let event_json = serde_json::to_string(event).unwrap_or_default();
                self.0.record(
                    "monitoring-agent",
                    "read-only",
                    &event.session_id,
                    "monitor_verdict",
                    &event_json,
                    &verdict_json,
                    "verdict",
                    0,
                    "Trusted",
                    "",
                );
            }
        }

        let bb_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra/blackbox.db");
        let verdict_sink: Option<Arc<dyn navra_core::hooks::VerdictSink>> =
            navra_core::blackbox::Blackbox::open(&bb_path)
                .ok()
                .map(|bb| Arc::new(BlackboxVerdictSink(Arc::new(bb))) as _);

        let mm = monitoring_metrics.clone();
        tokio::spawn(navra_core::hooks::monitoring_loop(
            escalation_rx,
            mm,
            verdict_sink,
        ));

        tracing::info!(
            buffer_size = cfg.monitoring.buffer_size,
            "Monitoring agent enabled (detect-only, async)"
        );
    }

    // --- Tool usage pruning filter ---
    let usage_tracker = Arc::new(navra_core::ToolUsageTracker::new(5));
    builder = builder.tool_filter(navra_core::UsagePruningFilter::new(usage_tracker.clone()));

    // --- DMN decision table guardrails ---
    for (name, perm) in &cfg.permissions {
        if let (Some(dmn_path), Some(dmn_decision)) = (&perm.dmn_policies, &perm.dmn_decision) {
            match navra_core::permissions::DmnEngine::from_file(dmn_path, dmn_decision) {
                Ok(engine) => {
                    tracing::info!(
                        permission_set = %name,
                        path = %dmn_path,
                        decision = %dmn_decision,
                        "DMN decision table loaded"
                    );
                    builder = builder.dmn_engine(engine);
                }
                Err(e) => {
                    tracing::error!(
                        permission_set = %name,
                        path = %dmn_path,
                        error = %e,
                        "Failed to load DMN decision table"
                    );
                }
            }
        }
    }

    builder
}
