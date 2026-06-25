//! Sandbox profiles for protocol-level capability sandboxing.
//!
//! A `SandboxProfile` defines per-tool rules that transform how the gateway
//! presents tools to an agent. Tools can be simulated (fake responses),
//! have their output redacted, be rate-limited, or have path arguments
//! rewritten.
//!
//! Profiles are attached to capability tokens and enforced in the hook
//! pipeline via `SandboxHook`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A complete sandbox profile attached to a capability token.
///
/// Contains per-tool rules that define how the gateway transforms
/// tool behavior for the token holder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SandboxProfile {
    /// Per-tool sandbox rules, keyed by tool name glob.
    #[serde(default)]
    pub rules: HashMap<String, ToolSandboxRule>,
}

/// Sandbox rule for a single tool (or tool glob pattern).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolSandboxRule {
    /// The action to take when this tool is called.
    pub action: SandboxAction,
}

/// Actions the sandbox can apply to a tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SandboxAction {
    /// Return a canned response without executing the tool.
    Simulate {
        /// The fake response text to return.
        response: String,
    },
    /// Execute the tool but redact matching patterns from the output.
    Redact {
        /// Regex patterns to redact from the output.
        patterns: Vec<String>,
        /// Replacement string (defaults to "\[REDACTED\]").
        #[serde(default = "default_replacement")]
        replacement: String,
    },
    /// Execute the tool but enforce a per-tool rate limit.
    RateLimit {
        /// Maximum calls per window.
        max_calls: u32,
        /// Window duration in seconds.
        window_secs: u64,
    },
    /// Execute the tool but rewrite path arguments.
    PathRewrite {
        /// Prefix to strip from paths.
        strip_prefix: String,
        /// Prefix to add to paths.
        add_prefix: String,
    },
}

fn default_replacement() -> String {
    "[REDACTED]".to_string()
}

/// Check if a child sandbox action is a valid attenuation of a parent action.
/// Extracted for Kani verification — operates on primitive types without HashMap/String.
fn check_action_attenuation(
    parent: &SandboxAction,
    child: &SandboxAction,
) -> Result<(), &'static str> {
    if matches!(parent, SandboxAction::Simulate { .. })
        && !matches!(child, SandboxAction::Simulate { .. })
    {
        return Err("weakens Simulate");
    }
    if let SandboxAction::RateLimit {
        max_calls: p_max,
        window_secs: p_win,
    } = parent
    {
        if let SandboxAction::RateLimit {
            max_calls: c_max,
            window_secs: c_win,
        } = child
        {
            if c_max > p_max {
                return Err("escalates rate limit");
            }
            if c_win > p_win {
                return Err("extends rate window");
            }
        }
    }
    Ok(())
}

impl SandboxProfile {
    /// Find the matching rule for a tool name, checking exact match first
    /// then glob patterns.
    pub fn rule_for(&self, tool_name: &str) -> Option<&ToolSandboxRule> {
        // Exact match first
        if let Some(rule) = self.rules.get(tool_name) {
            return Some(rule);
        }
        // Glob match
        for (pattern, rule) in &self.rules {
            if let Ok(glob) = glob::Pattern::new(pattern) {
                if glob.matches(tool_name) {
                    return Some(rule);
                }
            }
        }
        None
    }

    /// Validate that a child sandbox profile is a valid attenuation of a parent.
    ///
    /// Attenuation rules:
    /// - Child can add new rules (further restrict) but cannot remove parent rules.
    /// - Child cannot weaken a Simulate rule (e.g., change it to PathRewrite).
    /// - Child can tighten a RateLimit (lower max_calls or shorter window).
    pub fn validate_attenuation(&self, child: &SandboxProfile) -> Result<(), String> {
        for (tool_pattern, parent_rule) in &self.rules {
            match child.rules.get(tool_pattern) {
                None => {
                    return Err(format!(
                        "sandbox attenuation error: child removes rule for '{}'",
                        tool_pattern
                    ));
                }
                Some(child_rule) => {
                    check_action_attenuation(&parent_rule.action, &child_rule.action).map_err(
                        |e| format!("sandbox attenuation error: {} for '{}'", e, tool_pattern),
                    )?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_profile_matches_nothing() {
        let profile = SandboxProfile::default();
        assert!(profile.rule_for("file_read").is_none());
    }

    #[test]
    fn exact_match_takes_priority() {
        let mut profile = SandboxProfile::default();
        profile.rules.insert(
            "file_read".to_string(),
            ToolSandboxRule {
                action: SandboxAction::Simulate {
                    response: "exact".to_string(),
                },
            },
        );
        profile.rules.insert(
            "file_*".to_string(),
            ToolSandboxRule {
                action: SandboxAction::Simulate {
                    response: "glob".to_string(),
                },
            },
        );

        let rule = profile.rule_for("file_read").unwrap();
        match &rule.action {
            SandboxAction::Simulate { response } => assert_eq!(response, "exact"),
            _ => panic!("expected Simulate"),
        }
    }

    #[test]
    fn glob_match_works() {
        let mut profile = SandboxProfile::default();
        profile.rules.insert(
            "git_*".to_string(),
            ToolSandboxRule {
                action: SandboxAction::Simulate {
                    response: "simulated".to_string(),
                },
            },
        );

        assert!(profile.rule_for("git_status").is_some());
        assert!(profile.rule_for("git_commit").is_some());
        assert!(profile.rule_for("file_read").is_none());
    }

    #[test]
    fn sandbox_action_simulate_serde_roundtrip() {
        let action = SandboxAction::Simulate {
            response: "fake output".to_string(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let decoded: SandboxAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, decoded);
    }

    #[test]
    fn sandbox_action_redact_serde_roundtrip() {
        let action = SandboxAction::Redact {
            patterns: vec![r"\d{3}-\d{2}-\d{4}".to_string()],
            replacement: "***".to_string(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let decoded: SandboxAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, decoded);
    }

    #[test]
    fn sandbox_action_rate_limit_serde_roundtrip() {
        let action = SandboxAction::RateLimit {
            max_calls: 10,
            window_secs: 60,
        };
        let json = serde_json::to_string(&action).unwrap();
        let decoded: SandboxAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, decoded);
    }

    #[test]
    fn sandbox_action_path_rewrite_serde_roundtrip() {
        let action = SandboxAction::PathRewrite {
            strip_prefix: "/real/".to_string(),
            add_prefix: "/sandbox/".to_string(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let decoded: SandboxAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, decoded);
    }

    #[test]
    fn profile_cbor_roundtrip() {
        let mut profile = SandboxProfile::default();
        profile.rules.insert(
            "file_write".to_string(),
            ToolSandboxRule {
                action: SandboxAction::Simulate {
                    response: "write simulated".to_string(),
                },
            },
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&profile, &mut buf).unwrap();
        let decoded: SandboxProfile = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(profile, decoded);
    }

    #[test]
    fn default_replacement_is_redacted() {
        let json = r#"{"type":"redact","patterns":["secret"]}"#;
        let action: SandboxAction = serde_json::from_str(json).unwrap();
        match action {
            SandboxAction::Redact { replacement, .. } => {
                assert_eq!(replacement, "[REDACTED]");
            }
            _ => panic!("expected Redact"),
        }
    }

    #[test]
    fn attenuation_allows_adding_rules() {
        let parent = SandboxProfile::default();
        let mut child = SandboxProfile::default();
        child.rules.insert(
            "file_write".to_string(),
            ToolSandboxRule {
                action: SandboxAction::Simulate {
                    response: "blocked".to_string(),
                },
            },
        );
        // Parent has no rules, child adds new ones — valid
        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn attenuation_rejects_removing_rules() {
        let mut parent = SandboxProfile::default();
        parent.rules.insert(
            "file_write".to_string(),
            ToolSandboxRule {
                action: SandboxAction::Simulate {
                    response: "blocked".to_string(),
                },
            },
        );
        let child = SandboxProfile::default();
        let err = parent.validate_attenuation(&child).unwrap_err();
        assert!(err.contains("removes rule"));
    }

    #[test]
    fn attenuation_rejects_weakening_simulate() {
        let mut parent = SandboxProfile::default();
        parent.rules.insert(
            "file_write".to_string(),
            ToolSandboxRule {
                action: SandboxAction::Simulate {
                    response: "blocked".to_string(),
                },
            },
        );
        let mut child = SandboxProfile::default();
        child.rules.insert(
            "file_write".to_string(),
            ToolSandboxRule {
                action: SandboxAction::PathRewrite {
                    strip_prefix: "/a".to_string(),
                    add_prefix: "/b".to_string(),
                },
            },
        );
        let err = parent.validate_attenuation(&child).unwrap_err();
        assert!(err.contains("weakens Simulate"));
    }

    #[test]
    fn attenuation_rejects_rate_limit_escalation() {
        let mut parent = SandboxProfile::default();
        parent.rules.insert(
            "file_read".to_string(),
            ToolSandboxRule {
                action: SandboxAction::RateLimit {
                    max_calls: 5,
                    window_secs: 60,
                },
            },
        );
        let mut child = SandboxProfile::default();
        child.rules.insert(
            "file_read".to_string(),
            ToolSandboxRule {
                action: SandboxAction::RateLimit {
                    max_calls: 10,
                    window_secs: 60,
                },
            },
        );
        let err = parent.validate_attenuation(&child).unwrap_err();
        assert!(err.contains("escalates rate limit"));
    }

    #[test]
    fn attenuation_allows_tightening_rate_limit() {
        let mut parent = SandboxProfile::default();
        parent.rules.insert(
            "file_read".to_string(),
            ToolSandboxRule {
                action: SandboxAction::RateLimit {
                    max_calls: 10,
                    window_secs: 60,
                },
            },
        );
        let mut child = SandboxProfile::default();
        child.rules.insert(
            "file_read".to_string(),
            ToolSandboxRule {
                action: SandboxAction::RateLimit {
                    max_calls: 5,
                    window_secs: 30,
                },
            },
        );
        assert!(parent.validate_attenuation(&child).is_ok());
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn arbitrary_action() -> SandboxAction {
        match kani::any::<u8>() % 4 {
            0 => SandboxAction::Simulate {
                response: String::new(),
            },
            1 => SandboxAction::Redact {
                patterns: vec![],
                replacement: String::new(),
            },
            2 => SandboxAction::RateLimit {
                max_calls: kani::any(),
                window_secs: kani::any(),
            },
            _ => SandboxAction::PathRewrite {
                strip_prefix: String::new(),
                add_prefix: String::new(),
            },
        }
    }

    #[kani::proof]
    fn simulate_weakening_rejected() {
        let parent = SandboxAction::Simulate {
            response: String::new(),
        };
        let child = arbitrary_action();
        if !matches!(child, SandboxAction::Simulate { .. }) {
            assert!(check_action_attenuation(&parent, &child).is_err());
        }
    }

    #[kani::proof]
    fn rate_limit_escalation_rejected() {
        let p_max: u32 = kani::any();
        let p_win: u64 = kani::any();
        let c_max: u32 = kani::any();
        let c_win: u64 = kani::any();
        kani::assume(p_max <= 100);
        kani::assume(p_win <= 3600);
        kani::assume(c_max <= 100);
        kani::assume(c_win <= 3600);
        let parent = SandboxAction::RateLimit {
            max_calls: p_max,
            window_secs: p_win,
        };
        let child = SandboxAction::RateLimit {
            max_calls: c_max,
            window_secs: c_win,
        };
        let result = check_action_attenuation(&parent, &child);
        if c_max > p_max || c_win > p_win {
            assert!(result.is_err());
        }
    }

    #[kani::proof]
    fn rate_limit_tightening_accepted() {
        let p_max: u32 = kani::any();
        let p_win: u64 = kani::any();
        let c_max: u32 = kani::any();
        let c_win: u64 = kani::any();
        kani::assume(p_max <= 100);
        kani::assume(p_win <= 3600);
        kani::assume(c_max <= p_max);
        kani::assume(c_win <= p_win);
        let parent = SandboxAction::RateLimit {
            max_calls: p_max,
            window_secs: p_win,
        };
        let child = SandboxAction::RateLimit {
            max_calls: c_max,
            window_secs: c_win,
        };
        assert!(check_action_attenuation(&parent, &child).is_ok());
    }

    #[kani::proof]
    fn non_simulate_parent_any_child_accepted() {
        let parent = arbitrary_action();
        let child = arbitrary_action();
        if !matches!(parent, SandboxAction::Simulate { .. })
            && !matches!(parent, SandboxAction::RateLimit { .. })
        {
            assert!(check_action_attenuation(&parent, &child).is_ok());
        }
    }
}
