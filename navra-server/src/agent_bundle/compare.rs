use std::fmt;

use crate::config::{DomainRuleConfig, PermissionSet, ToolRuleConfig};

use super::manifest::RequestedPermissions;

#[derive(Debug)]
pub struct PermissionDiff {
    pub allowed: bool,
    pub denied_operations: Vec<String>,
    pub denied_tool_rules: Vec<ToolRuleConfig>,
    pub denied_domain_rules: Vec<DomainRuleConfig>,
    pub ifc_violations: Vec<String>,
}

pub fn compare_permissions(
    requested: &RequestedPermissions,
    max_allowed: &PermissionSet,
) -> PermissionDiff {
    let mut denied_operations = Vec::new();
    let mut denied_tool_rules = Vec::new();
    let mut denied_domain_rules = Vec::new();
    let mut ifc_violations = Vec::new();

    for op in &requested.operations {
        if !max_allowed.operations.contains(op) {
            denied_operations.push(op.clone());
        }
    }

    for rule in &requested.tool_rules {
        if rule.policy == "allow" {
            let blocked = max_allowed
                .tool_rules
                .iter()
                .any(|r| glob_matches(&r.tool, &rule.tool) && r.policy == "deny");

            if blocked || max_allowed.default_tool_policy == "deny" {
                denied_tool_rules.push(rule.clone());
            }
        }
    }

    for rule in &requested.domain_rules {
        let granted = max_allowed
            .domain_rules
            .iter()
            .find(|r| r.domain == rule.domain || r.domain == "*");
        match granted {
            None => {
                denied_domain_rules.push(rule.clone());
            }
            Some(allowed_rule) => {
                let missing: Vec<_> = rule
                    .operations
                    .iter()
                    .filter(|op| !allowed_rule.operations.contains(op))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    denied_domain_rules.push(DomainRuleConfig {
                        domain: rule.domain.clone(),
                        operations: missing,
                    });
                }
            }
        }
    }

    if let Some(ifc) = &requested.ifc {
        if ifc.reads == "untrusted" && max_allowed.tainted_write_policy == "deny" {
            let has_writes = requested.operations.iter().any(|o| o.contains("write"))
                || requested
                    .domain_rules
                    .iter()
                    .any(|r| r.operations.iter().any(|o| o == "write"));
            if has_writes {
                ifc_violations.push(
                    "Agent reads untrusted data and writes, but tainted_write_policy is \"deny\""
                        .to_string(),
                );
            }
        }

        if ifc.writes == "sensitive" {
            ifc_violations
                .push("Agent declares sensitive writes — requires operator review".to_string());
        }
    }

    let allowed = denied_operations.is_empty()
        && denied_tool_rules.is_empty()
        && denied_domain_rules.is_empty()
        && ifc_violations.is_empty();

    PermissionDiff {
        allowed,
        denied_operations,
        denied_tool_rules,
        denied_domain_rules,
        ifc_violations,
    }
}

fn glob_matches(pattern: &str, target: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return target.starts_with(prefix);
    }
    pattern == target
}

impl fmt::Display for PermissionDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.allowed {
            return write!(f, "All requested permissions are within operator policy.");
        }

        writeln!(
            f,
            "Permission check FAILED — bundle exceeds operator policy:\n"
        )?;

        if !self.denied_operations.is_empty() {
            writeln!(f, "  Denied operations:")?;
            for op in &self.denied_operations {
                writeln!(f, "    - {op}")?;
            }
        }

        if !self.denied_tool_rules.is_empty() {
            writeln!(f, "  Denied tool rules:")?;
            for rule in &self.denied_tool_rules {
                writeln!(f, "    - {} ({})", rule.tool, rule.policy)?;
            }
        }

        if !self.denied_domain_rules.is_empty() {
            writeln!(f, "  Denied domain rules:")?;
            for rule in &self.denied_domain_rules {
                writeln!(
                    f,
                    "    - domain={}, operations=[{}]",
                    rule.domain,
                    rule.operations.join(", ")
                )?;
            }
        }

        if !self.ifc_violations.is_empty() {
            writeln!(f, "  IFC violations:")?;
            for v in &self.ifc_violations {
                writeln!(f, "    - {v}")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DomainRuleConfig;

    fn make_permissive_policy() -> PermissionSet {
        PermissionSet {
            operations: vec![
                "filesystem.read".to_string(),
                "filesystem.write".to_string(),
                "git.read".to_string(),
            ],
            domain_rules: vec![
                DomainRuleConfig {
                    domain: "filesystem".to_string(),
                    operations: vec!["read".to_string(), "write".to_string()],
                },
                DomainRuleConfig {
                    domain: "git".to_string(),
                    operations: vec!["read".to_string()],
                },
            ],
            default_tool_policy: "allow".to_string(),
            tainted_write_policy: "allow".to_string(),
            ..Default::default()
        }
    }

    fn make_restrictive_policy() -> PermissionSet {
        PermissionSet {
            operations: vec!["filesystem.read".to_string()],
            domain_rules: vec![DomainRuleConfig {
                domain: "filesystem".to_string(),
                operations: vec!["read".to_string()],
            }],
            default_tool_policy: "deny".to_string(),
            tainted_write_policy: "deny".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn subset_permissions_allowed() {
        let requested = RequestedPermissions {
            operations: vec!["filesystem.read".to_string()],
            domain_rules: vec![DomainRuleConfig {
                domain: "filesystem".to_string(),
                operations: vec!["read".to_string()],
            }],
            ..Default::default()
        };
        let diff = compare_permissions(&requested, &make_permissive_policy());
        assert!(diff.allowed);
    }

    #[test]
    fn excess_operations_denied() {
        let requested = RequestedPermissions {
            operations: vec!["filesystem.read".to_string(), "shell.execute".to_string()],
            ..Default::default()
        };
        let diff = compare_permissions(&requested, &make_restrictive_policy());
        assert!(!diff.allowed);
        assert!(
            diff.denied_operations
                .contains(&"shell.execute".to_string())
        );
    }

    #[test]
    fn tool_rule_conflict_detected() {
        let requested = RequestedPermissions {
            tool_rules: vec![ToolRuleConfig {
                tool: "shell_exec".to_string(),
                policy: "allow".to_string(),
            }],
            ..Default::default()
        };
        let diff = compare_permissions(&requested, &make_restrictive_policy());
        assert!(!diff.allowed);
        assert_eq!(diff.denied_tool_rules.len(), 1);
    }

    #[test]
    fn domain_rule_excess_denied() {
        let requested = RequestedPermissions {
            domain_rules: vec![DomainRuleConfig {
                domain: "filesystem".to_string(),
                operations: vec!["read".to_string(), "write".to_string()],
            }],
            ..Default::default()
        };
        let diff = compare_permissions(&requested, &make_restrictive_policy());
        assert!(!diff.allowed);
        assert_eq!(diff.denied_domain_rules.len(), 1);
        assert!(
            diff.denied_domain_rules[0]
                .operations
                .contains(&"write".to_string())
        );
    }

    #[test]
    fn unknown_domain_denied() {
        let requested = RequestedPermissions {
            domain_rules: vec![DomainRuleConfig {
                domain: "shell".to_string(),
                operations: vec!["execute".to_string()],
            }],
            ..Default::default()
        };
        let diff = compare_permissions(&requested, &make_restrictive_policy());
        assert!(!diff.allowed);
        assert_eq!(diff.denied_domain_rules.len(), 1);
    }

    #[test]
    fn ifc_tainted_write_violation() {
        use super::super::manifest::IfcDeclaration;

        let requested = RequestedPermissions {
            operations: vec!["filesystem.write".to_string()],
            ifc: Some(IfcDeclaration {
                reads: "untrusted".to_string(),
                writes: "public".to_string(),
            }),
            ..Default::default()
        };
        let diff = compare_permissions(&requested, &make_restrictive_policy());
        assert!(!diff.allowed);
        assert!(!diff.ifc_violations.is_empty());
    }

    #[test]
    fn display_shows_denied_details() {
        let requested = RequestedPermissions {
            operations: vec!["shell.execute".to_string()],
            ..Default::default()
        };
        let diff = compare_permissions(&requested, &make_restrictive_policy());
        let output = format!("{diff}");
        assert!(output.contains("shell.execute"));
        assert!(output.contains("FAILED"));
    }
}
