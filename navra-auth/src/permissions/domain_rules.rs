//! Domain-based permission rules.
//!
//! A `DomainRules` set declares which operations are allowed per domain
//! for a given permission set. `Domain::Unknown` acts as a wildcard
//! default for domains not explicitly listed.

use super::resource_class::{Domain, Operation, ResourceClass};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPolicy {
    Allow,
    Deny,
}

/// Per-domain operation allowlist for a permission set.
///
/// Evaluation:
/// 1. Look up the tool's domain → if found, check if operation is in the set
/// 2. If domain not found, check `Domain::Unknown` as wildcard default
/// 3. If no wildcard either → Deny (fail-closed)
///
/// An empty operation set for a domain means all operations are denied
/// for that domain (explicit deny).
#[derive(Debug, Clone)]
pub struct DomainRules {
    rules: HashMap<Domain, HashSet<Operation>>,
}

impl DomainRules {
    pub fn new(rules: HashMap<Domain, HashSet<Operation>>) -> Self {
        Self { rules }
    }

    pub fn check(&self, class: &ResourceClass) -> DomainPolicy {
        if let Some(ops) = self.rules.get(&class.domain) {
            if ops.contains(&class.operation) {
                return DomainPolicy::Allow;
            }
            return DomainPolicy::Deny;
        }

        // Wildcard: Domain::Unknown acts as default for unlisted domains
        if let Some(ops) = self.rules.get(&Domain::Unknown) {
            if ops.contains(&class.operation) {
                return DomainPolicy::Allow;
            }
            return DomainPolicy::Deny;
        }

        DomainPolicy::Deny
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(entries: &[(&str, &[&str])]) -> DomainRules {
        let mut map = HashMap::new();
        for (domain, ops) in entries {
            let d: Domain = domain.parse().unwrap();
            let o: HashSet<Operation> = ops.iter().map(|s| s.parse().unwrap()).collect();
            map.insert(d, o);
        }
        DomainRules::new(map)
    }

    fn class(s: &str) -> ResourceClass {
        s.parse().unwrap()
    }

    #[test]
    fn explicit_domain_allow() {
        let r = rules(&[("filesystem", &["read", "write"])]);
        assert_eq!(r.check(&class("filesystem:read")), DomainPolicy::Allow);
        assert_eq!(r.check(&class("filesystem:write")), DomainPolicy::Allow);
    }

    #[test]
    fn explicit_domain_deny_operation() {
        let r = rules(&[("filesystem", &["read"])]);
        assert_eq!(r.check(&class("filesystem:write")), DomainPolicy::Deny);
        assert_eq!(r.check(&class("filesystem:delete")), DomainPolicy::Deny);
    }

    #[test]
    fn empty_ops_denies_all() {
        let r = rules(&[("shell", &[])]);
        assert_eq!(r.check(&class("shell:read")), DomainPolicy::Deny);
        assert_eq!(r.check(&class("shell:execute")), DomainPolicy::Deny);
    }

    #[test]
    fn unlisted_domain_denied_without_wildcard() {
        let r = rules(&[("filesystem", &["read"])]);
        assert_eq!(r.check(&class("github:read")), DomainPolicy::Deny);
        assert_eq!(r.check(&class("shell:execute")), DomainPolicy::Deny);
    }

    #[test]
    fn wildcard_allows_unlisted_domains() {
        let r = rules(&[("shell", &[]), ("unknown", &["read"])]);
        // Explicit domain with empty ops → deny
        assert_eq!(r.check(&class("shell:read")), DomainPolicy::Deny);
        // Unlisted domain falls through to wildcard
        assert_eq!(r.check(&class("filesystem:read")), DomainPolicy::Allow);
        assert_eq!(r.check(&class("github:read")), DomainPolicy::Allow);
        // Wildcard doesn't allow write
        assert_eq!(r.check(&class("filesystem:write")), DomainPolicy::Deny);
    }

    #[test]
    fn explicit_domain_takes_precedence_over_wildcard() {
        let r = rules(&[("git", &["read"]), ("unknown", &["read", "write"])]);
        // git is explicit → only read allowed
        assert_eq!(r.check(&class("git:read")), DomainPolicy::Allow);
        assert_eq!(r.check(&class("git:write")), DomainPolicy::Deny);
        // other domains fall through to wildcard → read + write
        assert_eq!(r.check(&class("filesystem:write")), DomainPolicy::Allow);
    }

    #[test]
    fn readonly_permission_set() {
        let r = rules(&[("shell", &[]), ("unknown", &["read"])]);
        assert_eq!(r.check(&class("filesystem:read")), DomainPolicy::Allow);
        assert_eq!(r.check(&class("git:read")), DomainPolicy::Allow);
        assert_eq!(r.check(&class("filesystem:write")), DomainPolicy::Deny);
        assert_eq!(r.check(&class("shell:execute")), DomainPolicy::Deny);
        assert_eq!(r.check(&class("prompt:read")), DomainPolicy::Allow);
    }

    #[test]
    fn developer_permission_set() {
        let r = rules(&[("shell", &[]), ("unknown", &["read", "write"])]);
        assert_eq!(r.check(&class("filesystem:read")), DomainPolicy::Allow);
        assert_eq!(r.check(&class("filesystem:write")), DomainPolicy::Allow);
        assert_eq!(r.check(&class("git:write")), DomainPolicy::Allow);
        assert_eq!(r.check(&class("shell:execute")), DomainPolicy::Deny);
    }

    #[test]
    fn empty_rules_denies_all() {
        let r = DomainRules::new(HashMap::new());
        assert!(r.is_empty());
        assert_eq!(r.check(&class("filesystem:read")), DomainPolicy::Deny);
    }
}
