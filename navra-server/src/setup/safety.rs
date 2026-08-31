//! Safety pipeline construction.
//!
//! Builds per-permission-set `FilterPipeline` instances with custom PII,
//! NER, ML, and privacy filters. Used both for builder-level safety
//! profiles and for the `SafetyHook` in the hook pipeline.

use crate::config;
use std::collections::HashMap;
use std::sync::Arc;

/// Wrapper around `Arc<CustomPiiFilter>` that implements `ContentFilter`.
///
/// Allows sharing a single custom PII filter across multiple pipelines.
pub(crate) struct SharedCustomPiiFilter(pub(crate) Arc<navra_core::safety::CustomPiiFilter>);

impl navra_core::safety::ContentFilter for SharedCustomPiiFilter {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn scan(
        &self,
        content: &str,
        ctx: &navra_core::safety::FilterContext,
    ) -> Vec<navra_core::safety::Finding> {
        self.0.scan(content, ctx)
    }
}

/// Shared filter state created during model/filter loading, passed
/// to [`build_safety_pipeline`] so both call sites use the same
/// filter instances.
pub(crate) struct SafetyFilterState {
    pub(crate) custom_pii_filter: Option<Arc<navra_core::safety::CustomPiiFilter>>,
    #[cfg(feature = "onnx")]
    pub(crate) pii_ner_filter: Option<Arc<navra_core::safety::NerFilter>>,
    #[cfg(feature = "onnx")]
    pub(crate) privacy_filter: Option<Arc<navra_core::safety::PrivacyFilterModel>>,
    pub(crate) models: HashMap<String, Arc<dyn navra_model::ModelBackend>>,
}

/// Build a safety `FilterPipeline` for a single permission set.
///
/// Applies: base profile, custom PII filter, custom regex patterns,
/// ML classification, NER, and privacy-filter models.
pub(crate) fn build_safety_pipeline(
    pset: &config::PermissionSet,
    name: &str,
    model_configs: &HashMap<String, config::ModelConfig>,
    state: &SafetyFilterState,
    canary_tokens: &[config::CanaryTokenConfig],
) -> navra_core::safety::FilterPipeline {
    let mut pipeline = navra_core::safety::build_pipeline(&pset.safety);

    // Add canary tokens if configured
    if !canary_tokens.is_empty() {
        match pset.safety.as_str() {
            "standard" | "guardian" | "guardian-deep" | "block" | "multi-label" | "pseudonymize" => {
                let configs: Vec<(String, String, bool)> = canary_tokens
                    .iter()
                    .map(|ct| (ct.name.clone(), ct.value.clone(), ct.is_regex))
                    .collect();
                let canary = navra_core::safety::CanaryFilter::from_config(configs);
                if canary.has_tokens() {
                    tracing::info!(
                        permission_set = %name,
                        tokens = canary_tokens.len(),
                        "Canary tokens"
                    );
                    pipeline.add_filter(canary);
                }
            }
            _ => {}
        }
    }

    // Add global custom PII filter to profiles that use content filtering
    if let Some(ref pii_filter) = state.custom_pii_filter {
        match pset.safety.as_str() {
            "standard" | "guardian" | "guardian-deep" | "block" | "multi-label" => {
                pipeline.add_filter(SharedCustomPiiFilter(Arc::clone(pii_filter)));
            }
            _ => {}
        }
    }

    // Add custom regex patterns if configured
    if !pset.safety_patterns.is_empty() {
        let patterns: Vec<(String, String)> = pset
            .safety_patterns
            .iter()
            .map(|p| (p.category.clone(), p.pattern.clone()))
            .collect();
        let custom = navra_core::safety::CustomFilter::new(patterns);
        if custom.has_patterns() {
            tracing::info!(
                permission_set = %name,
                patterns = pset.safety_patterns.len(),
                "Custom safety patterns"
            );
            pipeline.add_filter(custom);
        }
    }

    // Add ML safety filter from any loaded classification model
    for (model_name, model_cfg) in model_configs {
        if model_cfg.task == "classification"
            && let Some(model) = state.models.get(model_name)
        {
            let classifier: Arc<dyn navra_core::safety::Classifier> =
                Arc::new(navra_safety_hooks::bridge::ClassifierBridge::new(
                    model.clone(),
                ));
            if pset.safety == "multi-label" && !pset.safety_thresholds.is_empty() {
                pipeline.add_model_filter(
                    navra_core::safety::MultiLabelFilter::from_thresholds(
                        classifier,
                        pset.safety_thresholds.clone(),
                    ),
                );
                tracing::info!(
                    permission_set = %name,
                    categories = pset.safety_thresholds.len(),
                    "Multi-label safety filter"
                );
            } else {
                let threshold = model_cfg.threshold.unwrap_or(0.5);
                pipeline.add_model_filter(navra_core::safety::MlFilter::new(
                    classifier,
                    threshold,
                    "ml-unsafe",
                ));
            }
        }
    }

    #[cfg(feature = "onnx")]
    if let Some(ref ner) = state.pii_ner_filter {
        match pset.safety.as_str() {
            "standard" | "guardian" | "guardian-deep" | "block" | "multi-label" => {
                pipeline.add_ner_filter_shared(Arc::clone(ner));
            }
            _ => {}
        }
    }

    #[cfg(feature = "onnx")]
    if let Some(ref pf) = state.privacy_filter {
        match pset.safety.as_str() {
            "standard" | "guardian" | "guardian-deep" | "block" | "multi-label" => {
                pipeline.add_privacy_filter_shared(Arc::clone(pf));
            }
            _ => {}
        }
    }

    pipeline
}

/// Register safety profiles and per-tool permissions for all
/// permission sets on the server builder.
pub(crate) fn wire_safety_profiles(
    mut builder: navra_core::McpServerBuilder,
    cfg: &config::Config,
    state: &SafetyFilterState,
) -> navra_core::McpServerBuilder {
    use navra_core::permissions::{ToolPermissions, ToolPolicy, ToolRule};

    for (name, pset) in &cfg.permissions {
        let pipeline = build_safety_pipeline(pset, name, &cfg.models, state, &cfg.canary_tokens);

        tracing::info!(
            permission_set = %name,
            safety = %pset.safety,
            "Safety profile"
        );
        builder = builder.safety_profile(name.clone(), pipeline);

        // Log compliance tags for audit trail
        if !pset.compliance.is_empty() {
            tracing::info!(
                permission_set = %name,
                tags = ?pset.compliance,
                "Compliance tags"
            );
        }

        // Build per-tool permission rules if any are configured
        if !pset.tool_rules.is_empty() {
            let rules: Vec<ToolRule> = pset
                .tool_rules
                .iter()
                .map(|r| ToolRule {
                    tool: r.tool.clone(),
                    policy: match r.policy.as_str() {
                        "deny" => ToolPolicy::Deny,
                        "approve" => ToolPolicy::Approve,
                        _ => ToolPolicy::Allow,
                    },
                })
                .collect();
            let default = match pset.default_tool_policy.as_str() {
                "deny" => ToolPolicy::Deny,
                "approve" => ToolPolicy::Approve,
                _ => ToolPolicy::Allow,
            };
            tracing::info!(
                permission_set = %name,
                rules = rules.len(),
                "Tool permission rules"
            );
            builder = builder.tool_permissions(name.clone(), ToolPermissions::new(rules, default));
        }

        if !pset.operations.is_empty() {
            let ops: std::collections::HashSet<String> = pset.operations.iter().cloned().collect();
            builder = builder.agent_operations(name.clone(), ops);
        }

        if !pset.tool_disclosure_include.is_empty() || !pset.tool_disclosure_exclude.is_empty() {
            let disclosure = navra_core::permissions::ToolDisclosure::new(
                pset.tool_disclosure_include.clone(),
                pset.tool_disclosure_exclude.clone(),
            );
            tracing::info!(
                permission_set = %name,
                include = pset.tool_disclosure_include.len(),
                exclude = pset.tool_disclosure_exclude.len(),
                "Tool disclosure rules"
            );
            builder = builder.tool_disclosure(name.clone(), disclosure);
        }

        // Domain-based permission rules.
        let domain_rules = if !pset.domain_rules.is_empty() {
            let mut rules_map = std::collections::HashMap::new();
            for rule in &pset.domain_rules {
                let domain: navra_core::permissions::Domain = match rule.domain.parse() {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!(
                            permission_set = %name,
                            domain = %rule.domain,
                            "Invalid domain in domain_rules: {e}, skipping"
                        );
                        continue;
                    }
                };
                let ops: std::collections::HashSet<navra_core::permissions::Operation> = rule
                    .operations
                    .iter()
                    .filter_map(|s| match s.parse() {
                        Ok(o) => Some(o),
                        Err(e) => {
                            tracing::error!(
                                permission_set = %name,
                                operation = %s,
                                "Invalid operation in domain_rules: {e}, skipping"
                            );
                            None
                        }
                    })
                    .collect();
                rules_map.insert(domain, ops);
            }
            tracing::info!(
                permission_set = %name,
                domains = rules_map.len(),
                source = "explicit",
                "Domain permission rules"
            );
            navra_core::permissions::DomainRules::new(rules_map)
        } else {
            let ops: std::collections::HashSet<navra_core::permissions::Operation> = pset
                .operations
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            let mut rules_map = std::collections::HashMap::new();
            rules_map.insert(navra_core::permissions::Domain::Unknown, ops);
            tracing::info!(
                permission_set = %name,
                operations = ?pset.operations,
                source = "synthesized from operations",
                "Domain permission rules"
            );
            navra_core::permissions::DomainRules::new(rules_map)
        };
        builder = builder.domain_rules(name.clone(), domain_rules);

        // Per-tool classification overrides from permission set config
        if !pset.tool_class.is_empty() {
            let mut classes = std::collections::HashMap::new();
            for (tool_name, tc) in &pset.tool_class {
                match (tc.domain.parse(), tc.operation.parse()) {
                    (Ok(domain), Ok(operation)) => {
                        classes.insert(
                            tool_name.clone(),
                            navra_core::permissions::ResourceClass::new(domain, operation),
                        );
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        tracing::error!(
                            permission_set = %name,
                            tool = %tool_name,
                            "Invalid tool_class: {e}, skipping"
                        );
                    }
                }
            }
            if !classes.is_empty() {
                tracing::info!(
                    permission_set = %name,
                    overrides = classes.len(),
                    "Tool classification overrides"
                );
                builder = builder.merge_tool_classifications(classes);
            }
        }
    }

    // Cost-aware model routing hook
    if cfg.routing.enabled {
        let hook = navra_core::hooks::RoutingHook::from_config(&cfg.routing);
        tracing::info!(
            tiers = cfg.routing.tiers.len(),
            default = %cfg.routing.default_tier,
            "Routing hook enabled"
        );
        builder = builder.hook(hook);
    }

    builder
}
