//! OPA/Rego policy engine integration.
//!
//! Provides an optional in-process OPA evaluator (via `regorus`) that
//! acts as a second gate after TOML ACLs — same role as the Cedar
//! engine. OPA can only further restrict access; it cannot grant
//! permissions beyond what TOML allows.
//!
//! Operators who manage OpenShell sandboxes (which use OPA/Rego for
//! network policy) can write a single Rego policy that governs both
//! layers, eliminating policy drift.

use regorus::Engine;
use std::collections::HashMap;

pub struct OpaEngine {
    engine: Engine,
    package: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpaDecision {
    Allow,
    Deny(String),
}

impl OpaEngine {
    /// Create an OPA engine from a Rego policy string.
    ///
    /// The `package` argument selects which Rego package to query
    /// (e.g., `"navra.authz"`). The engine evaluates
    /// `data.<package>.allow` and `data.<package>.deny`.
    pub fn from_policies(policies: &str, package: &str) -> Result<Self, String> {
        let mut engine = Engine::new();
        engine
            .add_policy("policy.rego".into(), policies.into())
            .map_err(|e| format!("Failed to parse Rego policy: {e}"))?;
        Ok(Self {
            engine,
            package: package.to_string(),
        })
    }

    /// Create an OPA engine from a Rego policy file.
    pub fn from_file(path: &str, package: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read policy file '{path}': {e}"))?;
        Self::from_policies(&content, package)
    }

    /// Evaluate whether an action is authorized.
    ///
    /// Builds an OPA input document:
    /// ```json
    /// {
    ///   "agent": "<agent_name>",
    ///   "action": "<tool_name>",
    ///   "resource": "<resource>",
    ///   ...context_map entries
    /// }
    /// ```
    ///
    /// Queries `data.<package>.deny`. If any deny rule returns true,
    /// the request is denied. If no deny rule fires, the request is
    /// allowed (default-allow at this layer, since TOML ACLs already
    /// applied the default-deny).
    pub fn is_authorized(
        &mut self,
        agent_name: &str,
        tool_name: &str,
        resource: &str,
        context_map: &HashMap<String, String>,
    ) -> OpaDecision {
        let mut input = serde_json::Map::new();
        input.insert("agent".into(), serde_json::Value::String(agent_name.into()));
        input.insert("action".into(), serde_json::Value::String(tool_name.into()));
        input.insert(
            "resource".into(),
            serde_json::Value::String(resource.into()),
        );
        for (k, v) in context_map {
            input.insert(k.clone(), serde_json::Value::String(v.clone()));
        }

        let input_value =
            regorus::Value::from_json_str(&serde_json::to_string(&input).unwrap_or_default());
        let input_value = match input_value {
            Ok(v) => v,
            Err(e) => return OpaDecision::Deny(format!("Invalid input: {e}")),
        };

        self.engine.set_input(input_value);

        let query = format!("data.{}.deny", self.package);
        match self.engine.eval_rule(query.clone()) {
            Ok(results) => {
                if is_truthy(&results) {
                    let reason_query = format!("data.{}.deny_reasons", self.package);
                    let reasons = self
                        .engine
                        .eval_rule(reason_query)
                        .ok()
                        .and_then(|v| extract_strings(&v))
                        .unwrap_or_default();

                    let msg = if reasons.is_empty() {
                        "Access denied by OPA policy".to_string()
                    } else {
                        reasons.join("; ")
                    };

                    tracing::info!(
                        query = %query,
                        reasons = %msg,
                        "OPA policy denied"
                    );
                    OpaDecision::Deny(msg)
                } else {
                    OpaDecision::Allow
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, query = %query, "OPA evaluation failed, denying");
                OpaDecision::Deny(format!("OPA evaluation error: {e}"))
            }
        }
    }
}

fn is_truthy(value: &regorus::Value) -> bool {
    match value {
        regorus::Value::Bool(b) => *b,
        regorus::Value::Set(s) if !s.is_empty() => true,
        regorus::Value::Array(a) if !a.is_empty() => true,
        regorus::Value::String(s) if !s.is_empty() => true,
        _ => false,
    }
}

fn extract_strings(value: &regorus::Value) -> Option<Vec<String>> {
    match value {
        regorus::Value::Set(s) => Some(
            s.iter()
                .filter_map(|v| match v {
                    regorus::Value::String(s) => Some(s.to_string()),
                    _ => None,
                })
                .collect(),
        ),
        regorus::Value::Array(a) => Some(
            a.iter()
                .filter_map(|v| match v {
                    regorus::Value::String(s) => Some(s.to_string()),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC_POLICY: &str = r#"
package navra.authz

default deny = false

deny if {
    input.action == "file_write"
    input.trust_state == "read_only"
}

deny if {
    input.action == "git_push"
    not input.approval_granted == "true"
}

deny if {
    input.trust_state == "suspended"
}
"#;

    #[test]
    fn allow_by_default() {
        let mut engine = OpaEngine::from_policies(BASIC_POLICY, "navra.authz").unwrap();
        let result = engine.is_authorized("agent", "file_read", "/tmp", &HashMap::new());
        assert_eq!(result, OpaDecision::Allow);
    }

    #[test]
    fn deny_read_only_write() {
        let mut engine = OpaEngine::from_policies(BASIC_POLICY, "navra.authz").unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("trust_state".into(), "read_only".into());
        let result = engine.is_authorized("agent", "file_write", "/tmp/out", &ctx);
        assert!(matches!(result, OpaDecision::Deny(_)));
    }

    #[test]
    fn deny_push_without_approval() {
        let mut engine = OpaEngine::from_policies(BASIC_POLICY, "navra.authz").unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("trust_state".into(), "normal".into());
        let result = engine.is_authorized("agent", "git_push", "origin/main", &ctx);
        assert!(matches!(result, OpaDecision::Deny(_)));
    }

    #[test]
    fn allow_push_with_approval() {
        let mut engine = OpaEngine::from_policies(BASIC_POLICY, "navra.authz").unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("trust_state".into(), "normal".into());
        ctx.insert("approval_granted".into(), "true".into());
        let result = engine.is_authorized("agent", "git_push", "origin/main", &ctx);
        assert_eq!(result, OpaDecision::Allow);
    }

    #[test]
    fn deny_suspended_agent() {
        let mut engine = OpaEngine::from_policies(BASIC_POLICY, "navra.authz").unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("trust_state".into(), "suspended".into());
        let result = engine.is_authorized("agent", "file_read", "/tmp", &ctx);
        assert!(matches!(result, OpaDecision::Deny(_)));
    }

    #[test]
    fn agent_specific_policy() {
        let policy = r#"
package navra.authz

default deny = false

deny if {
    input.agent == "untrusted"
    input.action == "exec_command"
}
"#;
        let mut engine = OpaEngine::from_policies(policy, "navra.authz").unwrap();
        assert_eq!(
            engine.is_authorized("trusted", "exec_command", "any", &HashMap::new()),
            OpaDecision::Allow,
        );
        assert!(matches!(
            engine.is_authorized("untrusted", "exec_command", "any", &HashMap::new()),
            OpaDecision::Deny(_),
        ));
    }

    #[test]
    fn deny_reasons() {
        let policy = r#"
package navra.authz

default deny = false

deny if {
    input.trust_state == "suspended"
}

deny_reasons contains reason if {
    input.trust_state == "suspended"
    reason := "Agent trust is suspended"
}
"#;
        let mut engine = OpaEngine::from_policies(policy, "navra.authz").unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("trust_state".into(), "suspended".into());
        match engine.is_authorized("agent", "file_read", "/tmp", &ctx) {
            OpaDecision::Deny(msg) => assert!(msg.contains("suspended"), "got: {msg}"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn invalid_policy() {
        assert!(OpaEngine::from_policies("this is not valid rego {{{", "test").is_err());
    }

    #[test]
    fn load_from_nonexistent_file() {
        assert!(OpaEngine::from_file("/nonexistent/policy.rego", "test").is_err());
    }

    #[test]
    fn pii_egress_policy() {
        let policy = r#"
package navra.authz

default deny = false

deny if {
    input.ifc_confidentiality == "pii"
    input.destination_trust == "external"
}
"#;
        let mut engine = OpaEngine::from_policies(policy, "navra.authz").unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("ifc_confidentiality".into(), "pii".into());
        ctx.insert("destination_trust".into(), "external".into());
        assert!(matches!(
            engine.is_authorized("agent", "http_request", "https://evil.com", &ctx),
            OpaDecision::Deny(_),
        ));

        let mut ctx_internal = HashMap::new();
        ctx_internal.insert("ifc_confidentiality".into(), "pii".into());
        ctx_internal.insert("destination_trust".into(), "internal".into());
        assert_eq!(
            engine.is_authorized(
                "agent",
                "http_request",
                "https://internal.corp",
                &ctx_internal
            ),
            OpaDecision::Allow,
        );
    }
}
