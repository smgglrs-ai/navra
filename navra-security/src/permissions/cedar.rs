//! Cedar policy engine integration.
//!
//! Provides an optional in-process Cedar policy engine that acts as a
//! second gate after TOML ACLs. Cedar can only further restrict access —
//! it cannot grant permissions beyond what TOML allows.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request, RestrictedExpression,
};
use std::collections::HashMap;
use std::str::FromStr;

pub struct CedarEngine {
    policy_set: PolicySet,
    authorizer: Authorizer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CedarDecision {
    Allow,
    Deny(String),
}

fn make_uid(type_name: &str, id: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(type_name).expect("valid type name"),
        EntityId::from_str(id).expect("valid entity id"),
    )
}

impl CedarEngine {
    pub fn from_policies(policies: &str) -> Result<Self, String> {
        let policy_set = PolicySet::from_str(policies)
            .map_err(|e| format!("Failed to parse Cedar policies: {e}"))?;
        Ok(Self {
            policy_set,
            authorizer: Authorizer::new(),
        })
    }

    pub fn from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read policy file '{path}': {e}"))?;
        Self::from_policies(&content)
    }

    pub fn is_authorized(
        &self,
        agent_name: &str,
        tool_name: &str,
        resource: &str,
        context_map: &HashMap<String, String>,
    ) -> CedarDecision {
        let principal = make_uid("Agent", agent_name);
        let action = make_uid("Action", tool_name);
        let resource_uid = make_uid("Resource", resource);

        let pairs: Vec<(String, RestrictedExpression)> = context_map
            .iter()
            .map(|(k, v)| (k.clone(), RestrictedExpression::new_string(v.clone())))
            .collect();

        let context = match Context::from_pairs(pairs) {
            Ok(c) => c,
            Err(e) => return CedarDecision::Deny(format!("Invalid context: {e}")),
        };

        let request = match Request::new(principal, action, resource_uid, context, None) {
            Ok(r) => r,
            Err(e) => return CedarDecision::Deny(format!("Invalid request: {e}")),
        };

        let entities = Entities::empty();
        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &entities);

        match response.decision() {
            Decision::Allow => CedarDecision::Allow,
            Decision::Deny => {
                let reasons: Vec<String> = response
                    .diagnostics()
                    .reason()
                    .map(|id| id.to_string())
                    .collect();
                let msg = if reasons.is_empty() {
                    "Cedar policy denied (default deny)".to_string()
                } else {
                    format!("Cedar policy denied by: {}", reasons.join(", "))
                };
                CedarDecision::Deny(msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_policy() {
        let engine = CedarEngine::from_policies(r#"permit(principal, action, resource);"#).unwrap();
        let result = engine.is_authorized("claude", "file_read", "/tmp/test", &HashMap::new());
        assert_eq!(result, CedarDecision::Allow);
    }

    #[test]
    fn deny_by_default() {
        let engine = CedarEngine::from_policies("").unwrap();
        let result = engine.is_authorized("claude", "file_read", "/tmp/test", &HashMap::new());
        assert!(matches!(result, CedarDecision::Deny(_)));
    }

    #[test]
    fn explicit_forbid_overrides_permit() {
        let engine = CedarEngine::from_policies(
            r#"
            permit(principal, action, resource);
            forbid(principal, action == Action::"github_pr_create", resource);
            "#,
        )
        .unwrap();
        assert_eq!(
            engine.is_authorized("claude", "file_read", "any", &HashMap::new()),
            CedarDecision::Allow,
        );
        assert!(matches!(
            engine.is_authorized("claude", "github_pr_create", "any", &HashMap::new()),
            CedarDecision::Deny(_),
        ));
    }

    #[test]
    fn agent_specific_policy() {
        let engine = CedarEngine::from_policies(
            r#"permit(principal == Agent::"trusted", action, resource);"#,
        )
        .unwrap();
        assert_eq!(
            engine.is_authorized("trusted", "file_read", "any", &HashMap::new()),
            CedarDecision::Allow,
        );
        assert!(matches!(
            engine.is_authorized("untrusted", "file_read", "any", &HashMap::new()),
            CedarDecision::Deny(_),
        ));
    }

    #[test]
    fn resource_specific_policy() {
        let engine = CedarEngine::from_policies(
            r#"permit(principal, action, resource == Resource::"public/repo");"#,
        )
        .unwrap();
        assert_eq!(
            engine.is_authorized("claude", "github_pr_list", "public/repo", &HashMap::new()),
            CedarDecision::Allow,
        );
        assert!(matches!(
            engine.is_authorized("claude", "github_pr_list", "private/repo", &HashMap::new()),
            CedarDecision::Deny(_),
        ));
    }

    #[test]
    fn context_based_policy() {
        let engine = CedarEngine::from_policies(
            r#"
            permit(principal, action, resource)
            when { context.environment == "production" };
            "#,
        )
        .unwrap();

        let mut ctx = HashMap::new();
        ctx.insert("environment".to_string(), "production".to_string());
        assert_eq!(
            engine.is_authorized("claude", "file_read", "any", &ctx),
            CedarDecision::Allow
        );

        let mut ctx_dev = HashMap::new();
        ctx_dev.insert("environment".to_string(), "development".to_string());
        assert!(matches!(
            engine.is_authorized("claude", "file_read", "any", &ctx_dev),
            CedarDecision::Deny(_),
        ));
    }

    #[test]
    fn multiple_policies_combined() {
        let engine = CedarEngine::from_policies(
            r#"
            permit(principal, action == Action::"github_pr_list", resource);
            permit(principal, action == Action::"github_pr_view", resource);
            forbid(principal == Agent::"readonly", action == Action::"github_pr_create", resource);
            "#,
        )
        .unwrap();
        assert_eq!(
            engine.is_authorized("readonly", "github_pr_list", "repo", &HashMap::new()),
            CedarDecision::Allow,
        );
        assert!(matches!(
            engine.is_authorized("readonly", "github_pr_create", "repo", &HashMap::new()),
            CedarDecision::Deny(_),
        ));
    }

    #[test]
    fn invalid_policy_returns_error() {
        assert!(CedarEngine::from_policies("this is not valid cedar").is_err());
    }

    #[test]
    fn load_from_nonexistent_file() {
        assert!(CedarEngine::from_file("/nonexistent/policy.cedar").is_err());
    }
}
