//! Policy equivalence verification.
//!
//! Exhaustively compares Cedar and OPA/Rego policy decisions across
//! all meaningful input partitions to prove they produce identical
//! results. The policy domain is finite (bounded action set × small
//! context value sets), making exhaustive comparison tractable.

#[cfg(feature = "cedar")]
use super::cedar::{CedarDecision, CedarEngine};
#[cfg(feature = "opa")]
use super::opa::{OpaDecision, OpaEngine};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TestVector {
    pub agent: String,
    pub action: String,
    pub resource: String,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Divergence {
    pub vector: TestVector,
    pub cedar_decision: String,
    pub opa_decision: String,
}

#[derive(Debug)]
pub struct EquivalenceResult {
    pub total_vectors: usize,
    pub cedar_allow: usize,
    pub cedar_deny: usize,
    pub opa_allow: usize,
    pub opa_deny: usize,
    pub divergences: Vec<Divergence>,
}

impl EquivalenceResult {
    pub fn is_equivalent(&self) -> bool {
        self.divergences.is_empty()
    }
}

/// Generates test vectors from the policy-relevant input partitions.
///
/// Rather than testing all 2^N combinations of context fields, we
/// generate vectors for each action with the context values that
/// the policy actually checks. This is sound because the policies
/// only branch on specific field values — all other values are
/// equivalent from the policy's perspective.
pub fn generate_test_vectors() -> Vec<TestVector> {
    let actions = [
        "file_read",
        "file_write",
        "file_delete",
        "file_tree",
        "git_status",
        "git_log",
        "git_diff",
        "git_push",
        "exec_command",
        "github_pr_create",
        "upstream_tool_call",
        "upstream_discover",
        "http_request",
        "response_send",
        "capability_delegate",
        "memory_query",
        "rag_search",
        "unknown_action",
    ];

    let trust_states = ["normal", "suspended", "read_only"];
    let approval_values = ["true", "false"];
    let risk_tiers = ["low", "high", "critical"];

    let agents = ["agent", "trusted", "untrusted"];
    let resource = "_default";

    let mut vectors = Vec::new();

    for action in &actions {
        for agent in &agents {
            for trust_state in &trust_states {
                for approval in &approval_values {
                    let mut ctx = HashMap::new();
                    ctx.insert("trust_state".into(), trust_state.to_string());
                    ctx.insert("approval_granted".into(), approval.to_string());

                    vectors.push(TestVector {
                        agent: agent.to_string(),
                        action: action.to_string(),
                        resource: resource.to_string(),
                        context: ctx,
                    });
                }
            }
        }
    }

    // Additional vectors for specific context fields that specific
    // actions check.
    let specific_contexts: Vec<(&str, Vec<(&str, &str)>)> = vec![
        (
            "upstream_tool_call",
            vec![
                ("manifest_verified", "false"),
                ("trust_score", "low"),
                ("trust_state", "normal"),
            ],
        ),
        (
            "upstream_tool_call",
            vec![
                ("manifest_verified", "false"),
                ("trust_score", "high"),
                ("trust_state", "normal"),
            ],
        ),
        (
            "upstream_tool_call",
            vec![("scan_category_blocked", "true"), ("trust_state", "normal")],
        ),
        (
            "upstream_discover",
            vec![
                ("manifest_signed", "false"),
                ("trust_on_first_use", "false"),
                ("trust_state", "normal"),
            ],
        ),
        (
            "upstream_discover",
            vec![
                ("manifest_signed", "false"),
                ("trust_on_first_use", "true"),
                ("trust_state", "normal"),
            ],
        ),
        (
            "http_request",
            vec![("egress_allowed", "false"), ("trust_state", "normal")],
        ),
        (
            "http_request",
            vec![
                ("ifc_confidentiality", "pii"),
                ("destination_trust", "external"),
                ("trust_state", "normal"),
            ],
        ),
        (
            "http_request",
            vec![
                ("ifc_confidentiality", "pii"),
                ("destination_trust", "internal"),
                ("trust_state", "normal"),
            ],
        ),
        (
            "response_send",
            vec![
                ("safety_filtered", "false"),
                ("safety_required", "true"),
                ("trust_state", "normal"),
            ],
        ),
        (
            "capability_delegate",
            vec![("exceeds_parent_scope", "true"), ("trust_state", "normal")],
        ),
        (
            "file_read",
            vec![("circuit_breaker", "open"), ("trust_state", "normal")],
        ),
        (
            "file_read",
            vec![("rate_limited", "true"), ("trust_state", "normal")],
        ),
        (
            "file_read",
            vec![
                ("cognitive_integrity", "violated"),
                ("trust_state", "normal"),
            ],
        ),
        (
            "exec_command",
            vec![
                ("risk_tier", "critical"),
                ("approval_granted", "false"),
                ("trust_state", "normal"),
            ],
        ),
        (
            "exec_command",
            vec![
                ("risk_tier", "critical"),
                ("approval_granted", "true"),
                ("trust_state", "normal"),
            ],
        ),
    ];

    for (action, ctx_pairs) in &specific_contexts {
        let mut ctx = HashMap::new();
        for (k, v) in ctx_pairs {
            ctx.insert(k.to_string(), v.to_string());
        }
        vectors.push(TestVector {
            agent: "agent".into(),
            action: action.to_string(),
            resource: resource.to_string(),
            context: ctx,
        });
    }

    // Vectors for risk_tier interactions with write actions
    for action in ["file_write", "file_delete"] {
        for risk_tier in &risk_tiers {
            for approval in &approval_values {
                let mut ctx = HashMap::new();
                ctx.insert("trust_state".into(), "normal".into());
                ctx.insert("risk_tier".into(), risk_tier.to_string());
                ctx.insert("approval_granted".into(), approval.to_string());
                vectors.push(TestVector {
                    agent: "agent".into(),
                    action: action.into(),
                    resource: resource.into(),
                    context: ctx,
                });
            }
        }
    }

    vectors
}

/// Check a single input vector against both engines.
#[cfg(all(feature = "cedar", feature = "opa"))]
pub fn check_single(
    cedar: &CedarEngine,
    opa: &mut OpaEngine,
    vector: &TestVector,
) -> Option<Divergence> {
    let cedar_result = cedar.is_authorized(
        &vector.agent,
        &vector.action,
        &vector.resource,
        &vector.context,
    );
    let opa_result = opa.is_authorized(
        &vector.agent,
        &vector.action,
        &vector.resource,
        &vector.context,
    );

    let cedar_allows = matches!(cedar_result, CedarDecision::Allow);
    let opa_allows = matches!(opa_result, OpaDecision::Allow);

    if cedar_allows != opa_allows {
        Some(Divergence {
            vector: vector.clone(),
            cedar_decision: if cedar_allows {
                "Allow".into()
            } else {
                "Deny".into()
            },
            opa_decision: if opa_allows {
                "Allow".into()
            } else {
                "Deny".into()
            },
        })
    } else {
        None
    }
}

/// Run the full equivalence check across all test vectors.
#[cfg(all(feature = "cedar", feature = "opa"))]
pub fn check_equivalence(cedar: &CedarEngine, opa: &mut OpaEngine) -> EquivalenceResult {
    let vectors = generate_test_vectors();
    let mut result = EquivalenceResult {
        total_vectors: vectors.len(),
        cedar_allow: 0,
        cedar_deny: 0,
        opa_allow: 0,
        opa_deny: 0,
        divergences: Vec::new(),
    };

    for vector in &vectors {
        let cedar_result = cedar.is_authorized(
            &vector.agent,
            &vector.action,
            &vector.resource,
            &vector.context,
        );
        let opa_result = opa.is_authorized(
            &vector.agent,
            &vector.action,
            &vector.resource,
            &vector.context,
        );

        let cedar_allows = matches!(cedar_result, CedarDecision::Allow);
        let opa_allows = matches!(opa_result, OpaDecision::Allow);

        if cedar_allows {
            result.cedar_allow += 1;
        } else {
            result.cedar_deny += 1;
        }
        if opa_allows {
            result.opa_allow += 1;
        } else {
            result.opa_deny += 1;
        }

        if cedar_allows != opa_allows {
            result.divergences.push(Divergence {
                vector: vector.clone(),
                cedar_decision: if cedar_allows {
                    "Allow".into()
                } else {
                    "Deny".into()
                },
                opa_decision: if opa_allows {
                    "Allow".into()
                } else {
                    "Deny".into()
                },
            });
        }
    }

    result
}

#[cfg(test)]
#[cfg(all(feature = "cedar", feature = "opa"))]
mod tests {
    use super::*;

    fn load_cedar_baseline() -> CedarEngine {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../policies/owasp-asi-baseline.cedar"
        );
        CedarEngine::from_file(path).expect("Cedar baseline should parse")
    }

    fn load_opa_baseline() -> OpaEngine {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../policies/owasp-asi-baseline.rego"
        );
        OpaEngine::from_file(path, "navra.authz").expect("Rego baseline should parse")
    }

    #[test]
    fn baselines_are_equivalent() {
        let cedar = load_cedar_baseline();
        let mut opa = load_opa_baseline();
        let result = check_equivalence(&cedar, &mut opa);

        if !result.is_equivalent() {
            for d in &result.divergences {
                eprintln!(
                    "DIVERGENCE: action={} agent={} context={:?} cedar={} opa={}",
                    d.vector.action,
                    d.vector.agent,
                    d.vector.context,
                    d.cedar_decision,
                    d.opa_decision,
                );
            }
        }

        assert!(
            result.is_equivalent(),
            "{} divergences found out of {} vectors",
            result.divergences.len(),
            result.total_vectors,
        );
        assert!(result.total_vectors > 100, "should test >100 vectors");
        assert!(result.cedar_allow > 0, "should have some allows");
        assert!(result.cedar_deny > 0, "should have some denies");
        assert_eq!(result.cedar_allow, result.opa_allow);
        assert_eq!(result.cedar_deny, result.opa_deny);
    }

    #[test]
    fn divergence_detected_on_modified_rego() {
        let cedar = load_cedar_baseline();
        // Create a Rego policy that differs: allow file_write without approval
        let modified_rego = r#"
package navra.authz

import rego.v1

default allow = false
default deny = false

allow if {
    input.action == "file_write"
    input.trust_state == "normal"
}

deny if { not allow }
"#;
        let mut opa = OpaEngine::from_policies(modified_rego, "navra.authz").unwrap();

        let vector = TestVector {
            agent: "agent".into(),
            action: "file_write".into(),
            resource: "_default".into(),
            context: HashMap::from([
                ("trust_state".into(), "normal".into()),
                ("approval_granted".into(), "false".into()),
            ]),
        };

        let divergence = check_single(&cedar, &mut opa, &vector);
        assert!(divergence.is_some(), "should detect divergence");
        let d = divergence.unwrap();
        assert_eq!(d.cedar_decision, "Deny");
        assert_eq!(d.opa_decision, "Allow");
    }

    #[test]
    fn test_vector_coverage() {
        let vectors = generate_test_vectors();
        assert!(
            vectors.len() > 300,
            "should generate >300 vectors, got {}",
            vectors.len()
        );

        let actions: std::collections::HashSet<&str> =
            vectors.iter().map(|v| v.action.as_str()).collect();
        assert!(actions.contains("file_read"));
        assert!(actions.contains("file_write"));
        assert!(actions.contains("git_push"));
        assert!(actions.contains("exec_command"));
        assert!(actions.contains("upstream_tool_call"));
    }
}
