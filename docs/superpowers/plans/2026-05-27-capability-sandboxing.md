# Protocol-Level Capability Sandboxing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the gateway itself the sandbox — agents get a different "view of reality" based on their capability token, with tools that simulate, redact, rate-limit, or rewrite transparently.

**Architecture:** New `SandboxProfile` in capability tokens. New `HookDecision::Simulate` variant for short-circuit responses. `SandboxHook` as pre+post hook reading profile from `CallContext`. Pipeline return type extended to `PreHookOutcome` enum.

**Tech Stack:** Rust, ciborium (CBOR), serde, async-trait, regex, tokio.

**Environment:** `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1` required for all cargo commands.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `navra-security/src/auth/sandbox_profile.rs` | Create | SandboxProfile, rules, serde |
| `navra-security/src/hooks/sandbox.rs` | Create | SandboxHook pre+post impl |
| `navra-security/src/hooks/mod.rs` | Modify | Add Simulate variant, new modules |
| `navra-security/src/hooks/pipeline.rs` | Modify | PreHookOutcome return type |
| `navra-security/src/auth/capability.rs` | Modify (line 51-76) | Add sandbox field |
| `navra-security/src/auth/mod.rs` | Modify | Extend ResolvedCapabilities, add pub mod |
| `navra-core/src/server/handlers.rs` | Modify (line 341-356) | Handle Simulated outcome |

---

### Task 1: SandboxProfile types

**Files:**
- Create: `navra-security/src/auth/sandbox_profile.rs`
- Modify: `navra-security/src/auth/mod.rs`

- [ ] **Step 1: Write failing tests**

Create `navra-security/src/auth/sandbox_profile.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_profile_default_is_empty() {
        let profile = SandboxProfile::default();
        assert!(profile.simulate_tools.is_empty());
        assert!(profile.redact_patterns.is_empty());
        assert!(profile.rate_limits.is_empty());
        assert!(profile.path_rewrites.is_empty());
    }

    #[test]
    fn simulation_rule_matches_glob() {
        let rule = SimulationRule {
            tool_pattern: "file_write*".to_string(),
            strategy: SimulationStrategy::Static("Write simulated".to_string()),
        };
        assert!(rule.matches("file_write"));
        assert!(rule.matches("file_write_batch"));
        assert!(!rule.matches("file_read"));
    }

    #[test]
    fn sandbox_profile_serde_roundtrip() {
        let profile = SandboxProfile {
            simulate_tools: vec![SimulationRule {
                tool_pattern: "file_write".to_string(),
                strategy: SimulationStrategy::Static("ok".to_string()),
            }],
            redact_patterns: vec![RedactionRule {
                tool_pattern: "*".to_string(),
                pattern: r"\d{3}-\d{2}-\d{4}".to_string(),
                replacement: "[REDACTED]".to_string(),
            }],
            rate_limits: vec![RateLimitRule {
                tool_pattern: "git_*".to_string(),
                delay_ms: 1000,
            }],
            path_rewrites: vec![PathRewriteRule {
                from_prefix: "/sandbox/".to_string(),
                to_prefix: "/real/".to_string(),
            }],
        };
        let json = serde_json::to_string(&profile).unwrap();
        let restored: SandboxProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.simulate_tools.len(), 1);
        assert_eq!(restored.redact_patterns.len(), 1);
        assert_eq!(restored.rate_limits.len(), 1);
        assert_eq!(restored.path_rewrites.len(), 1);
    }

    #[test]
    fn find_simulation_returns_matching_rule() {
        let profile = SandboxProfile {
            simulate_tools: vec![
                SimulationRule {
                    tool_pattern: "file_write".to_string(),
                    strategy: SimulationStrategy::Static("simulated".to_string()),
                },
                SimulationRule {
                    tool_pattern: "git_*".to_string(),
                    strategy: SimulationStrategy::DryRun,
                },
            ],
            ..Default::default()
        };
        assert!(profile.find_simulation("file_write").is_some());
        assert!(profile.find_simulation("git_commit").is_some());
        assert!(profile.find_simulation("file_read").is_none());
    }

    #[test]
    fn find_rate_limit_returns_delay() {
        let profile = SandboxProfile {
            rate_limits: vec![RateLimitRule {
                tool_pattern: "git_*".to_string(),
                delay_ms: 500,
            }],
            ..Default::default()
        };
        assert_eq!(profile.find_rate_limit("git_commit"), Some(500));
        assert_eq!(profile.find_rate_limit("file_read"), None);
    }
}
```

- [ ] **Step 2: Register module**

In `navra-security/src/auth/mod.rs`, add:

```rust
pub mod sandbox_profile;
```

- [ ] **Step 3: Run tests — compile failure**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security sandbox_profile -- --nocapture 2>&1 | tail -5`

- [ ] **Step 4: Implement SandboxProfile**

Write at the top of `sandbox_profile.rs`:

```rust
//! Sandbox profiles for protocol-level capability sandboxing.
//!
//! A `SandboxProfile` defines how the gateway modifies tool behavior
//! for an agent: simulation, redaction, rate limiting, path rewriting.

use serde::{Deserialize, Serialize};

/// A sandbox profile embedded in capability tokens.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxProfile {
    #[serde(default)]
    pub simulate_tools: Vec<SimulationRule>,
    #[serde(default)]
    pub redact_patterns: Vec<RedactionRule>,
    #[serde(default)]
    pub rate_limits: Vec<RateLimitRule>,
    #[serde(default)]
    pub path_rewrites: Vec<PathRewriteRule>,
}

impl SandboxProfile {
    pub fn is_empty(&self) -> bool {
        self.simulate_tools.is_empty()
            && self.redact_patterns.is_empty()
            && self.rate_limits.is_empty()
            && self.path_rewrites.is_empty()
    }

    pub fn find_simulation(&self, tool_name: &str) -> Option<&SimulationRule> {
        self.simulate_tools.iter().find(|r| r.matches(tool_name))
    }

    pub fn find_rate_limit(&self, tool_name: &str) -> Option<u64> {
        self.rate_limits
            .iter()
            .find(|r| glob_match(&r.tool_pattern, tool_name))
            .map(|r| r.delay_ms)
    }

    pub fn matching_redactions(&self, tool_name: &str) -> Vec<&RedactionRule> {
        self.redact_patterns
            .iter()
            .filter(|r| glob_match(&r.tool_pattern, tool_name))
            .collect()
    }

    pub fn find_path_rewrite(&self, path: &str) -> Option<String> {
        for rule in &self.path_rewrites {
            if path.starts_with(&rule.from_prefix) {
                return Some(format!(
                    "{}{}",
                    rule.to_prefix,
                    &path[rule.from_prefix.len()..]
                ));
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationRule {
    pub tool_pattern: String,
    pub strategy: SimulationStrategy,
}

impl SimulationRule {
    pub fn matches(&self, tool_name: &str) -> bool {
        glob_match(&self.tool_pattern, tool_name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SimulationStrategy {
    Static(String),
    DryRun,
    Fixture(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionRule {
    pub tool_pattern: String,
    pub pattern: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    pub tool_pattern: String,
    pub delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRewriteRule {
    pub from_prefix: String,
    pub to_prefix: String,
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return text.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return text.ends_with(suffix);
    }
    pattern == text
}
```

- [ ] **Step 5: Run tests**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security sandbox_profile -- --nocapture 2>&1 | tail -10`

Expected: 5 tests pass.

- [ ] **Step 6: Commit**

```bash
git add navra-security/src/auth/sandbox_profile.rs navra-security/src/auth/mod.rs
git commit -s -m "feat(security): add SandboxProfile types for capability sandboxing"
```

---

### Task 2: Extend HookDecision with Simulate + PreHookOutcome

**Files:**
- Modify: `navra-security/src/hooks/mod.rs` (line 32-43)
- Modify: `navra-security/src/hooks/pipeline.rs` (line 45-93)

- [ ] **Step 1: Add Simulate variant to HookDecision**

In `navra-security/src/hooks/mod.rs`, change `HookDecision`:

```rust
/// Decision returned by a hook after processing an event.
#[derive(Debug)]
pub enum HookDecision {
    /// Continue processing unchanged.
    Continue,
    /// Replace the tool arguments (pre-hook only).
    ModifyArgs(serde_json::Value),
    /// Replace the tool result (post-hook only).
    ModifyResult(CallToolResult),
    /// Block execution and return an error (pre-hook only).
    Block(String),
    /// Short-circuit: return this result without executing the tool.
    /// Used by sandbox simulation in pre-hooks.
    Simulate(CallToolResult),
}
```

- [ ] **Step 2: Add PreHookOutcome enum and update pipeline.rs**

In `pipeline.rs`, add after the imports:

```rust
/// Outcome of running pre-hooks.
pub enum PreHookOutcome {
    /// Continue with (possibly modified) arguments.
    Proceed(serde_json::Value),
    /// Blocked with error message.
    Blocked(String),
    /// Short-circuited with a simulated result.
    Simulated(CallToolResult),
}
```

Change the `run_pre` method signature from:

```rust
    pub async fn run_pre(
        &self,
        tool_name: &str,
        mut arguments: serde_json::Value,
        ctx: &CallContext,
    ) -> Result<serde_json::Value, String> {
```

to:

```rust
    pub async fn run_pre(
        &self,
        tool_name: &str,
        mut arguments: serde_json::Value,
        ctx: &CallContext,
    ) -> PreHookOutcome {
```

Update the body — change `Ok(arguments)` to `PreHookOutcome::Proceed(arguments)`, `Err(reason)` to `PreHookOutcome::Blocked(reason)`, and add the `Simulate` arm:

```rust
                HookDecision::Block(reason) => {
                    tracing::info!(
                        hook = hook.name(),
                        tool = tool_name,
                        reason = %reason,
                        "Pre-hook blocked tool execution"
                    );
                    return PreHookOutcome::Blocked(reason);
                }
                HookDecision::Simulate(result) => {
                    tracing::info!(
                        hook = hook.name(),
                        tool = tool_name,
                        "Pre-hook simulated tool execution"
                    );
                    return PreHookOutcome::Simulated(result);
                }
```

Return `PreHookOutcome::Proceed(arguments)` at the end instead of `Ok(arguments)`.

- [ ] **Step 3: Add PreHookOutcome to pub use in mod.rs**

```rust
pub use pipeline::{HookPipeline, PreHookOutcome};
```

- [ ] **Step 4: Update handlers.rs to use PreHookOutcome**

In `navra-core/src/server/handlers.rs`, change the pre-hook handling (lines 341-356) from:

```rust
let arguments = if self.hooks.has_hooks() {
    match self
        .hooks
        .run_pre(&params.name, resolved.arguments, &ctx)
        .await
    {
        Ok(args) => args,
        Err(reason) => {
            self.process_table
                .complete_call(&ctx.agent.name, &params.name);
            return CallToolResult::error(reason);
        }
    }
} else {
    resolved.arguments
};
```

to:

```rust
let arguments = if self.hooks.has_hooks() {
    match self
        .hooks
        .run_pre(&params.name, resolved.arguments, &ctx)
        .await
    {
        navra_security::hooks::PreHookOutcome::Proceed(args) => args,
        navra_security::hooks::PreHookOutcome::Blocked(reason) => {
            self.process_table
                .complete_call(&ctx.agent.name, &params.name);
            return CallToolResult::error(reason);
        }
        navra_security::hooks::PreHookOutcome::Simulated(result) => {
            self.process_table
                .complete_call(&ctx.agent.name, &params.name);
            return result;
        }
    }
} else {
    resolved.arguments
};
```

- [ ] **Step 5: Fix pipeline tests**

Update existing tests in `pipeline.rs` that assert on `Result` to use `PreHookOutcome`:

```rust
    #[tokio::test]
    async fn empty_pipeline_passes_through() {
        let pipeline = HookPipeline::new(Duration::from_secs(5));
        let args = serde_json::json!({"key": "value"});
        let result = pipeline.run_pre("echo", args.clone(), &test_ctx()).await;
        assert!(matches!(result, PreHookOutcome::Proceed(ref a) if *a == args));
    }

    #[tokio::test]
    async fn pre_hook_blocks_execution() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(BlockingHook { block_tool: "dangerous".to_string() });
        let result = pipeline.run_pre("dangerous", serde_json::json!({}), &test_ctx()).await;
        assert!(matches!(result, PreHookOutcome::Blocked(ref r) if r.contains("blocked by policy")));
    }

    #[tokio::test]
    async fn pre_hook_allows_other_tools() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(BlockingHook { block_tool: "dangerous".to_string() });
        let result = pipeline.run_pre("safe_tool", serde_json::json!({}), &test_ctx()).await;
        assert!(matches!(result, PreHookOutcome::Proceed(_)));
    }

    #[tokio::test]
    async fn pre_hook_modifies_args() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(ArgModifyHook);
        let result = pipeline.run_pre("echo", serde_json::json!({"original": true}), &test_ctx()).await;
        match result {
            PreHookOutcome::Proceed(args) => {
                assert_eq!(args["original"], true);
                assert_eq!(args["injected"], true);
            }
            _ => panic!("expected Proceed"),
        }
    }

    #[tokio::test]
    async fn pre_hook_block_short_circuits() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(BlockingHook { block_tool: "echo".to_string() });
        pipeline.add(ArgModifyHook);
        let result = pipeline.run_pre("echo", serde_json::json!({}), &test_ctx()).await;
        assert!(matches!(result, PreHookOutcome::Blocked(_)));
    }

    #[tokio::test]
    async fn timeout_blocks_on_slow_hook() {
        let mut pipeline = HookPipeline::new(Duration::from_millis(50));
        pipeline.add(SlowHook);
        let result = pipeline.run_pre("echo", serde_json::json!({}), &test_ctx()).await;
        assert!(matches!(result, PreHookOutcome::Blocked(_)));
    }
```

- [ ] **Step 6: Build and test**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test --workspace 2>&1 | tail -20`

Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add navra-security/src/hooks/mod.rs navra-security/src/hooks/pipeline.rs navra-core/src/server/handlers.rs
git commit -s -m "feat(security): add HookDecision::Simulate and PreHookOutcome"
```

---

### Task 3: SandboxHook implementation

**Files:**
- Create: `navra-security/src/hooks/sandbox.rs`
- Modify: `navra-security/src/hooks/mod.rs`

- [ ] **Step 1: Write failing tests**

Create `navra-security/src/hooks/sandbox.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AgentIdentity, CallContext};
    use crate::auth::sandbox_profile::{
        RateLimitRule, RedactionRule, SandboxProfile, SimulationRule, SimulationStrategy,
    };
    use navra_protocol::CallToolResult;

    fn ctx_with_sandbox(profile: SandboxProfile) -> CallContext {
        let mut ctx = CallContext::new(AgentIdentity::new("tester", "sandboxed"), "test-session");
        ctx.sandbox = Some(profile);
        ctx
    }

    #[tokio::test]
    async fn simulate_static_returns_canned_response() {
        let hook = SandboxHook;
        let profile = SandboxProfile {
            simulate_tools: vec![SimulationRule {
                tool_pattern: "file_write".to_string(),
                strategy: SimulationStrategy::Static("Write simulated successfully".to_string()),
            }],
            ..Default::default()
        };
        let ctx = ctx_with_sandbox(profile);
        let decision = hook
            .pre_tool_use("file_write", &serde_json::json!({"path": "/tmp/test"}), &ctx)
            .await;
        match decision {
            HookDecision::Simulate(result) => {
                assert!(!result.is_error);
                let text = match &result.content[0] {
                    navra_protocol::Content::Text(t) => &t.text,
                    _ => panic!("expected text"),
                };
                assert_eq!(text, "Write simulated successfully");
            }
            other => panic!("expected Simulate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_sandbox_continues() {
        let hook = SandboxHook;
        let ctx = CallContext::new(AgentIdentity::new("tester", "dev"), "test-session");
        let decision = hook
            .pre_tool_use("file_write", &serde_json::json!({}), &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn redaction_removes_patterns() {
        let hook = SandboxHook;
        let profile = SandboxProfile {
            redact_patterns: vec![RedactionRule {
                tool_pattern: "*".to_string(),
                pattern: r"\d{3}-\d{2}-\d{4}".to_string(),
                replacement: "[SSN-REDACTED]".to_string(),
            }],
            ..Default::default()
        };
        let ctx = ctx_with_sandbox(profile);
        let result = CallToolResult::text("SSN is 123-45-6789 in the file");
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &ctx)
            .await;
        match decision {
            HookDecision::ModifyResult(modified) => {
                let text = match &modified.content[0] {
                    navra_protocol::Content::Text(t) => &t.text,
                    _ => panic!("expected text"),
                };
                assert_eq!(text, "SSN is [SSN-REDACTED] in the file");
            }
            other => panic!("expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_redaction_patterns_continues() {
        let hook = SandboxHook;
        let profile = SandboxProfile::default();
        let ctx = ctx_with_sandbox(profile);
        let result = CallToolResult::text("nothing to redact");
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }
}
```

- [ ] **Step 2: Register module**

In `navra-security/src/hooks/mod.rs`, add:

```rust
pub mod sandbox;
```

And to pub use:

```rust
pub use sandbox::SandboxHook;
```

- [ ] **Step 3: Add sandbox field to CallContext**

In `navra-security/src/auth/mod.rs`, add to `CallContext`:

```rust
    pub sandbox: Option<crate::auth::sandbox_profile::SandboxProfile>,
```

Update `CallContext::new()` to set `sandbox: None`.

- [ ] **Step 4: Run tests — compile failure**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security sandbox::tests -- --nocapture 2>&1 | tail -5`

- [ ] **Step 5: Implement SandboxHook**

Write at the top of `sandbox.rs`:

```rust
//! Protocol-level capability sandboxing hook.
//!
//! Pre-hook: simulates tool calls and applies rate limits.
//! Post-hook: redacts patterns from tool results.

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use navra_protocol::{CallToolResult, Content};

/// Hook that applies sandbox profile directives from capability tokens.
///
/// Reads `ctx.sandbox` — if `None`, this hook is a no-op.
pub struct SandboxHook;

#[async_trait::async_trait]
impl Hook for SandboxHook {
    fn name(&self) -> &str {
        "sandbox"
    }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        ctx: &CallContext,
    ) -> HookDecision {
        let profile = match &ctx.sandbox {
            Some(p) => p,
            None => return HookDecision::Continue,
        };

        // Rate limiting: inject artificial delay
        if let Some(delay_ms) = profile.find_rate_limit(tool_name) {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }

        // Simulation: return canned response without executing tool
        if let Some(rule) = profile.find_simulation(tool_name) {
            use crate::auth::sandbox_profile::SimulationStrategy;
            let result = match &rule.strategy {
                SimulationStrategy::Static(response) => CallToolResult::text(response.clone()),
                SimulationStrategy::DryRun => {
                    CallToolResult::text(format!("{tool_name}: dry-run completed"))
                }
                SimulationStrategy::Fixture(path) => {
                    match std::fs::read_to_string(path) {
                        Ok(content) => CallToolResult::text(content),
                        Err(e) => CallToolResult::error(format!("fixture load failed: {e}")),
                    }
                }
            };
            tracing::info!(
                tool = tool_name,
                strategy = ?rule.strategy,
                "Sandbox: simulated tool call"
            );
            return HookDecision::Simulate(result);
        }

        HookDecision::Continue
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        result: &CallToolResult,
        ctx: &CallContext,
    ) -> HookDecision {
        let profile = match &ctx.sandbox {
            Some(p) => p,
            None => return HookDecision::Continue,
        };

        let redactions = profile.matching_redactions(tool_name);
        if redactions.is_empty() {
            return HookDecision::Continue;
        }

        let mut modified_content = Vec::new();
        let mut any_changed = false;

        for content in &result.content {
            match content {
                Content::Text(t) => {
                    let mut text = t.text.clone();
                    for rule in &redactions {
                        if let Ok(re) = regex::Regex::new(&rule.pattern) {
                            let replaced = re.replace_all(&text, rule.replacement.as_str());
                            if replaced != text {
                                any_changed = true;
                                text = replaced.into_owned();
                            }
                        }
                    }
                    modified_content.push(Content::Text(navra_protocol::TextContent {
                        text,
                    }));
                }
                other => modified_content.push(other.clone()),
            }
        }

        if any_changed {
            HookDecision::ModifyResult(CallToolResult {
                content: modified_content,
                is_error: result.is_error,
                label: result.label,
            })
        } else {
            HookDecision::Continue
        }
    }
}
```

- [ ] **Step 6: Add regex dependency if not present**

Check `navra-security/Cargo.toml` for `regex`. If missing, add:

```toml
regex = "1"
```

- [ ] **Step 7: Run tests**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security sandbox -- --nocapture 2>&1 | tail -15`

Expected: 4 tests pass.

- [ ] **Step 8: Commit**

```bash
git add navra-security/src/hooks/sandbox.rs navra-security/src/hooks/mod.rs navra-security/src/auth/mod.rs navra-security/Cargo.toml
git commit -s -m "feat(security): add SandboxHook with simulation and redaction"
```

---

### Task 4: Extend CapabilityPayload with sandbox field

**Files:**
- Modify: `navra-security/src/auth/capability.rs` (line 51-76)

- [ ] **Step 1: Write test for sandbox in token roundtrip**

Add to capability.rs tests:

```rust
    #[test]
    fn capability_with_sandbox_roundtrips() {
        let (signing, verifying) = test_keypair();
        let sandbox = crate::auth::sandbox_profile::SandboxProfile {
            simulate_tools: vec![crate::auth::sandbox_profile::SimulationRule {
                tool_pattern: "file_write".to_string(),
                strategy: crate::auth::sandbox_profile::SimulationStrategy::DryRun,
            }],
            ..Default::default()
        };
        let mut payload = build_payload("did:key:issuer", "did:key:subject",
            CapabilitySet { paths: vec![], operations: vec![], tools: vec![], credentials: vec![] },
            0, 3600);
        payload.sandbox = Some(sandbox);
        let token = encode(&payload, &signing).unwrap();
        let decoded = decode_and_verify(&token, &verifying, None).unwrap();
        assert!(decoded.sandbox.is_some());
        assert_eq!(decoded.sandbox.unwrap().simulate_tools.len(), 1);
    }
```

- [ ] **Step 2: Add sandbox field to CapabilityPayload**

In `capability.rs`, add to the `CapabilityPayload` struct after the `obo` field:

```rust
    /// Optional sandbox profile restricting tool behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<crate::auth::sandbox_profile::SandboxProfile>,
```

- [ ] **Step 3: Add sandbox to delegation attenuation**

In `build_delegated_payload`, ensure sandbox is inherited and cannot be removed:

```rust
    // Sandbox directives: inherit from parent (cannot be removed)
    let sandbox = parent.sandbox.clone();
```

Set `sandbox` in the returned payload.

- [ ] **Step 4: Run tests**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security capability -- --nocapture 2>&1 | tail -10`

Expected: All capability tests pass.

- [ ] **Step 5: Commit**

```bash
git add navra-security/src/auth/capability.rs
git commit -s -m "feat(security): add sandbox field to CapabilityPayload"
```

---

### Task 5: Wire sandbox into CallContext from capability tokens + final verification

**Files:**
- Modify: `navra-core/src/server/handlers.rs`

- [ ] **Step 1: Populate ctx.sandbox from resolved capabilities**

Find where `CallContext` is constructed in `handlers.rs` and add after capability resolution:

```rust
    // Populate sandbox profile from capability token
    if let Some(ref caps) = ctx.agent.capabilities {
        // Load sandbox from the original capability payload if available
        // The sandbox is already on the resolved payload
    }
```

The exact wiring depends on how `ResolvedCapabilities` is populated — check and add `sandbox: Option<SandboxProfile>` to `ResolvedCapabilities`, then copy it to `ctx.sandbox` after auth.

- [ ] **Step 2: Build full workspace**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build --workspace 2>&1 | tail -5`

- [ ] **Step 3: Run full test suite**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test --workspace 2>&1 | tail -20`

Expected: All tests pass.

- [ ] **Step 4: Run clippy**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo clippy --workspace 2>&1 | tail -10`

Expected: 0 warnings.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat(server): wire SandboxHook and sandbox profile from capability tokens"
```
