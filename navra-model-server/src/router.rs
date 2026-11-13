//! Within-session cost routing for the OpenAI-compatible inference API.
//!
//! The gateway rewrites the requested model per request based on
//! conversation complexity, transparently downgrading simple turns to a
//! cheaper model and upgrading back when the task demands it. The client
//! keeps requesting the frontier model name throughout — the response
//! `model` field and the `x-navra-routed-model` header preserve
//! transparency and auditability respectively.
//!
//! Two signals drive the decision:
//!
//! - **Complexity**: reasoning keywords in recent messages or tool use
//!   in the request keep the session on the frontier model. Simple
//!   follow-up turns (after `min_messages` of history) downgrade.
//! - **Compaction boundary**: the router tracks conversation size per
//!   session; a significant shrink means the caller compacted its
//!   context. Rules with `switch_only_at_compaction = true` defer
//!   downgrades to that boundary, mirroring the prompt-cache economics
//!   of remote providers (a switch there costs nothing extra because
//!   the cache is invalidated anyway). Local targets have no cache
//!   cost, so rules targeting them can switch freely.
//!
//! Sessions are identified by a hash of the requested model plus the
//! first message content — stateless OpenAI-compatible clients resend
//! full history each turn, so the prefix is stable within a session.

use std::collections::HashMap;
use std::sync::Mutex;

/// A single routing rule: requests for `from` may be served by `to`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RoutingRule {
    /// The frontier (expensive) model, as named by the client.
    pub from: String,
    /// The cheap model to downgrade to.
    pub to: String,
    /// Only switch models at compaction boundaries (recommended when
    /// `to` is a remote provider with server-side prompt caching).
    #[serde(default)]
    pub switch_only_at_compaction: bool,
}

/// Configuration for within-session cost routing.
#[derive(
    Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct RoutingConfig {
    /// Master switch. Routing is inert without rules, so this only
    /// provides an explicit kill switch.
    #[serde(default)]
    pub enabled: bool,
    /// Routing rules, matched by the requested model name.
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    /// Minimum conversation length (in messages) before downgrading.
    /// Early turns rarely reveal task difficulty, so the first
    /// exchanges always run on the requested model.
    #[serde(default = "default_min_messages")]
    pub min_messages: usize,
}

fn default_min_messages() -> usize {
    2
}

/// Per-session routing state.
#[derive(Debug, Default)]
struct SessionState {
    /// Total message content size at the previous request.
    last_total_chars: usize,
    /// Model currently serving this session (starts as requested).
    current_model: Option<String>,
}

/// The outcome of a routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingDecision {
    /// The model that should serve this request.
    pub model: String,
    /// Whether the decision differs from the requested model.
    pub routed: bool,
    /// Machine-readable reason (for tracing and tests).
    pub reason: &'static str,
}

impl RoutingDecision {
    fn passthrough(model: impl Into<String>, reason: &'static str) -> Self {
        Self {
            model: model.into(),
            routed: false,
            reason,
        }
    }
}

/// Keywords that signal a complex turn. Substring match,
/// case-insensitive — same style as `task_requirements` in
/// navra-server's team model selection.
const COMPLEXITY_KEYWORDS: &[&str] = &[
    "analyz",
    "architect",
    "debug",
    "diagnos",
    "investigat",
    "plan ",
    "reason",
    "refactor",
    "review",
    "root cause",
    "strategiz",
    "synthesiz",
    "trace",
];

/// A compaction boundary is detected when total content size drops
/// by at least this fraction since the previous request.
const COMPACTION_DROP_NUM: usize = 3;
const COMPACTION_DROP_DEN: usize = 4;

/// Number of trailing messages scanned for complexity keywords.
const COMPLEXITY_WINDOW: usize = 4;

/// Stateless-request session router.
///
/// Thread-safe: session state lives behind a `Mutex` and decisions
/// are pure functions of the request plus tracked history size.
pub struct SessionRouter {
    config: RoutingConfig,
    sessions: Mutex<HashMap<u64, SessionState>>,
}

impl SessionRouter {
    /// Create a router from configuration.
    pub fn new(config: RoutingConfig) -> Self {
        Self {
            config,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Decide which model serves this request.
    ///
    /// `available` lists models present in the registry; rules whose
    /// target is not loaded are ignored (never route to a missing
    /// model).
    pub fn decide(
        &self,
        requested: &str,
        messages: &[serde_json::Value],
        tools_present: bool,
        available: &[String],
    ) -> RoutingDecision {
        if !self.config.enabled {
            return RoutingDecision::passthrough(requested, "disabled");
        }

        let Some(rule) = self.config.rules.iter().find(|r| r.from == requested) else {
            return RoutingDecision::passthrough(requested, "no-rule");
        };

        if !available.iter().any(|m| m == &rule.to) {
            return RoutingDecision::passthrough(requested, "target-unavailable");
        }

        let session_key = session_key(requested, messages);
        let total_chars: usize = messages
            .iter()
            .map(|m| {
                m.get("content")
                    .and_then(|c| c.as_str())
                    .map_or(0, str::len)
            })
            .sum();

        let complex = tools_present || is_complex(messages);

        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let state = sessions.entry(session_key).or_default();

        // Compaction: the caller's history shrank (context compaction
        // or summarization). A model switch here forfeits no cache.
        let compaction = state.last_total_chars > 0
            && total_chars * COMPACTION_DROP_DEN <= state.last_total_chars * COMPACTION_DROP_NUM;
        state.last_total_chars = total_chars;

        // Until history accumulates, always serve the requested model:
        // early prompts rarely reveal task difficulty.
        let desired = if complex || messages.len() < self.config.min_messages {
            rule.from.clone()
        } else {
            rule.to.clone()
        };

        let current = state
            .current_model
            .get_or_insert_with(|| requested.to_string())
            .clone();

        if desired == current {
            let reason = if desired == rule.to {
                "stay-cheap"
            } else {
                "stay-frontier"
            };
            return RoutingDecision::passthrough(current, reason);
        }

        // Downgrades can be deferred to compaction boundaries so
        // remote prompt caches survive; upgrades are never deferred —
        // complexity demands the frontier model now.
        if desired == rule.to && rule.switch_only_at_compaction && !compaction {
            return RoutingDecision::passthrough(current, "deferred-to-compaction");
        }

        state.current_model = Some(desired.clone());
        let reason = if desired == rule.to {
            if compaction {
                "downgrade-at-compaction"
            } else {
                "downgrade-simple"
            }
        } else {
            "upgrade-complex"
        };
        RoutingDecision {
            model: desired,
            routed: true,
            reason,
        }
    }

    /// Forget all session state (tests, registry reloads).
    pub fn reset(&self) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

/// Whether recent messages contain complexity keywords.
fn is_complex(messages: &[serde_json::Value]) -> bool {
    messages
        .iter()
        .rev()
        .take(COMPLEXITY_WINDOW)
        .filter_map(|m| m.get("content").and_then(|c| c.as_str()))
        .any(|text| {
            let lower = text.to_lowercase();
            COMPLEXITY_KEYWORDS.iter().any(|kw| lower.contains(kw))
        })
}

/// Hash a session identity: requested model + first message content.
fn session_key(requested: &str, messages: &[serde_json::Value]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    requested.hash(&mut hasher);
    if let Some(first) = messages.first()
        && let Some(content) = first.get("content").and_then(|c| c.as_str())
    {
        content.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule_config() -> RoutingConfig {
        RoutingConfig {
            enabled: true,
            rules: vec![RoutingRule {
                from: "frontier".to_string(),
                to: "cheap".to_string(),
                switch_only_at_compaction: false,
            }],
            min_messages: 2,
        }
    }

    fn msgs(contents: &[&str]) -> Vec<serde_json::Value> {
        contents
            .iter()
            .map(|c| json!({"role": "user", "content": c}))
            .collect()
    }

    fn available() -> Vec<String> {
        vec!["frontier".to_string(), "cheap".to_string()]
    }

    #[test]
    fn passthrough_when_disabled() {
        let mut config = rule_config();
        config.enabled = false;
        let router = SessionRouter::new(config);
        let d = router.decide("frontier", &msgs(&["a", "b"]), false, &available());
        assert_eq!(d.model, "frontier");
        assert!(!d.routed);
        assert_eq!(d.reason, "disabled");
    }

    #[test]
    fn passthrough_when_no_rule_matches() {
        let router = SessionRouter::new(rule_config());
        let d = router.decide("other", &msgs(&["a", "b"]), false, &available());
        assert_eq!(d.model, "other");
        assert_eq!(d.reason, "no-rule");
    }

    #[test]
    fn passthrough_when_target_not_loaded() {
        let router = SessionRouter::new(rule_config());
        let d = router.decide(
            "frontier",
            &msgs(&["a", "b"]),
            false,
            &["frontier".to_string()],
        );
        assert_eq!(d.model, "frontier");
        assert_eq!(d.reason, "target-unavailable");
    }

    #[test]
    fn no_downgrade_before_min_messages() {
        let router = SessionRouter::new(rule_config());
        let d = router.decide("frontier", &msgs(&["just one"]), false, &available());
        assert_eq!(d.model, "frontier");
        assert_eq!(d.reason, "stay-frontier");
    }

    #[test]
    fn downgrades_simple_conversation() {
        let router = SessionRouter::new(rule_config());
        let d = router.decide("frontier", &msgs(&["hello", "thanks"]), false, &available());
        assert_eq!(d.model, "cheap");
        assert!(d.routed);
        assert_eq!(d.reason, "downgrade-simple");
    }

    #[test]
    fn keeps_frontier_for_reasoning_keywords() {
        let router = SessionRouter::new(rule_config());
        let d = router.decide(
            "frontier",
            &msgs(&["hello", "please review this diff"]),
            false,
            &available(),
        );
        assert_eq!(d.model, "frontier");
        assert_eq!(d.reason, "stay-frontier");
    }

    #[test]
    fn keeps_frontier_when_tools_present() {
        let router = SessionRouter::new(rule_config());
        let d = router.decide("frontier", &msgs(&["hello", "run it"]), true, &available());
        assert_eq!(d.model, "frontier");
        assert_eq!(d.reason, "stay-frontier");
    }

    #[test]
    fn stays_on_cheap_for_follow_ups() {
        let router = SessionRouter::new(rule_config());
        let msgs = msgs(&["hello", "thanks"]);
        assert!(router.decide("frontier", &msgs, false, &available()).routed);
        let d = router.decide("frontier", &msgs, false, &available());
        assert_eq!(d.model, "cheap");
        assert_eq!(d.reason, "stay-cheap");
    }

    #[test]
    fn upgrades_back_on_complexity() {
        let router = SessionRouter::new(rule_config());
        let simple = msgs(&["hello", "thanks"]);
        assert!(
            router
                .decide("frontier", &simple, false, &available())
                .routed
        );

        // Next turn turns complex — must return to the frontier model.
        let mut complex = simple.clone();
        complex.push(json!({"role": "user", "content": "now analyze the failure"}));
        let d = router.decide("frontier", &complex, false, &available());
        assert_eq!(d.model, "frontier");
        assert!(d.routed);
        assert_eq!(d.reason, "upgrade-complex");
    }

    #[test]
    fn defers_downgrade_until_compaction() {
        let mut config = rule_config();
        config.rules[0].switch_only_at_compaction = true;
        let router = SessionRouter::new(config);

        // The system prompt is stable across the session — it survives
        // compaction, so the session identity holds.
        let system = json!({"role": "system", "content": "you are a helper"});

        // Simple conversation — downgrade deferred.
        let mut growing = msgs(&["hello", "thanks a lot for the help"]);
        growing.insert(0, system.clone());
        let d = router.decide("frontier", &growing, false, &available());
        assert_eq!(d.model, "frontier");
        assert_eq!(d.reason, "deferred-to-compaction");

        // History shrinks (compaction) — downgrade now allowed.
        let mut compacted = msgs(&["summary", "go"]);
        compacted.insert(0, system);
        let d = router.decide("frontier", &compacted, false, &available());
        assert_eq!(d.model, "cheap");
        assert_eq!(d.reason, "downgrade-at-compaction");
    }

    #[test]
    fn compaction_upgrades_are_never_deferred() {
        let mut config = rule_config();
        config.rules[0].switch_only_at_compaction = true;
        let router = SessionRouter::new(config);

        let system = json!({"role": "system", "content": "you are a helper"});

        // Simple turns stay on frontier (downgrade deferred)...
        let mut big = msgs(&["hello", "thanks a lot for all the help"]);
        big.insert(0, system.clone());
        assert_eq!(
            router.decide("frontier", &big, false, &available()).reason,
            "deferred-to-compaction"
        );

        // ...and complex turns are served by the frontier model too.
        let mut complex = big.clone();
        complex.push(json!({"role": "user", "content": "trace this bug"}));
        assert_eq!(
            router
                .decide("frontier", &complex, false, &available())
                .model,
            "frontier"
        );

        // Downgrade happens at compaction...
        let mut compacted = msgs(&["summary", "go"]);
        compacted.insert(0, system);
        assert_eq!(
            router
                .decide("frontier", &compacted, false, &available())
                .model,
            "cheap"
        );

        // ...then an upgrade on complexity needs no compaction.
        let mut complex2 = compacted.clone();
        complex2.push(json!({"role": "user", "content": "reason about this"}));
        let d = router.decide("frontier", &complex2, false, &available());
        assert_eq!(d.model, "frontier");
        assert_eq!(d.reason, "upgrade-complex");
    }

    #[test]
    fn sessions_are_isolated() {
        let router = SessionRouter::new(rule_config());

        // Session A accumulates history.
        let a = msgs(&["session a opener", "thanks"]);
        assert!(router.decide("frontier", &a, false, &available()).routed);

        // Session B (different first message) is fresh: no downgrade.
        let b = msgs(&["session b opener", "thanks"]);
        let d = router.decide("frontier", &b, false, &available());
        assert_eq!(d.model, "cheap"); // simple → still downgrades (fresh state)
        assert!(d.routed);

        // But B's complexity upgrade works independently of A.
        let mut b2 = b.clone();
        b2.push(json!({"role": "user", "content": "debug this now"}));
        assert_eq!(
            router.decide("frontier", &b2, false, &available()).model,
            "frontier"
        );
    }

    #[test]
    fn reset_clears_session_state() {
        let router = SessionRouter::new(rule_config());
        let history = msgs(&["hello", "thanks"]);
        assert!(
            router
                .decide("frontier", &history, false, &available())
                .routed
        );
        router.reset();
        // Fresh state: the same simple conversation downgrades again
        // (deterministic), and a larger history is not misread as a
        // compaction shrink.
        let bigger = msgs(&["hello", "thanks", "and more text here"]);
        let d = router.decide("frontier", &bigger, false, &available());
        assert_eq!(d.reason, "downgrade-simple");
    }

    #[test]
    fn min_messages_config_is_respected() {
        let mut config = rule_config();
        config.min_messages = 5;
        let router = SessionRouter::new(config);
        let d = router.decide(
            "frontier",
            &msgs(&["a", "b", "c", "d"]),
            false,
            &available(),
        );
        assert_eq!(d.model, "frontier");
        assert_eq!(d.reason, "stay-frontier");
    }

    #[test]
    fn config_deserializes_from_toml_shape() {
        let config: RoutingConfig = serde_json::from_str(
            r#"{
                "enabled": true,
                "rules": [
                    {"from": "claude-opus", "to": "granite-code:8b", "switch_only_at_compaction": true}
                ],
                "min_messages": 3
            }"#,
        )
        .unwrap();
        assert!(config.enabled);
        assert_eq!(config.min_messages, 3);
        assert_eq!(config.rules.len(), 1);
        assert!(config.rules[0].switch_only_at_compaction);
    }
}
