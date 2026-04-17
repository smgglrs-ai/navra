//! Hook pipeline: ordered execution of hooks with timeout enforcement.

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use myelix_protocol::CallToolResult;
use std::time::Duration;

/// An ordered collection of hooks with timeout enforcement.
///
/// Pre-hooks run in registration order; post-hooks run in reverse order
/// (so the first-registered hook is the outermost wrapper).
pub struct HookPipeline {
    hooks: Vec<Box<dyn Hook>>,
    timeout: Duration,
}

impl HookPipeline {
    /// Create an empty pipeline with the given per-hook timeout.
    pub fn new(timeout: Duration) -> Self {
        Self {
            hooks: Vec::new(),
            timeout,
        }
    }

    /// Add a hook to the pipeline.
    pub fn add(&mut self, hook: impl Hook) {
        self.hooks.push(Box::new(hook));
    }

    /// Add a boxed hook to the pipeline.
    pub fn add_boxed(&mut self, hook: Box<dyn Hook>) {
        self.hooks.push(hook);
    }

    /// Returns true if the pipeline has any hooks registered.
    pub fn has_hooks(&self) -> bool {
        !self.hooks.is_empty()
    }

    /// Run all pre-tool-use hooks in order.
    ///
    /// Returns the (possibly modified) arguments, or an error message
    /// if a hook blocked execution.
    pub async fn run_pre(
        &self,
        tool_name: &str,
        mut arguments: serde_json::Value,
        ctx: &CallContext,
    ) -> Result<serde_json::Value, String> {
        for hook in &self.hooks {
            let decision = tokio::time::timeout(
                self.timeout,
                hook.pre_tool_use(tool_name, &arguments, ctx),
            )
            .await
            .unwrap_or_else(|_| {
                tracing::error!(
                    hook = hook.name(),
                    tool = tool_name,
                    "Pre-hook timed out — blocking (fail-closed)"
                );
                HookDecision::Block("hook timed out: security check failed".into())
            });

            match decision {
                HookDecision::Continue => {}
                HookDecision::ModifyArgs(new_args) => {
                    tracing::debug!(
                        hook = hook.name(),
                        tool = tool_name,
                        "Pre-hook modified arguments"
                    );
                    arguments = new_args;
                }
                HookDecision::Block(reason) => {
                    tracing::info!(
                        hook = hook.name(),
                        tool = tool_name,
                        reason = %reason,
                        "Pre-hook blocked tool execution"
                    );
                    return Err(reason);
                }
                HookDecision::ModifyResult(_) => {
                    tracing::warn!(
                        hook = hook.name(),
                        tool = tool_name,
                        "Pre-hook returned ModifyResult (ignored in pre-phase)"
                    );
                }
            }
        }
        Ok(arguments)
    }

    /// Run all post-tool-use hooks in reverse order.
    ///
    /// Returns the (possibly modified) result.
    pub async fn run_post(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        mut result: CallToolResult,
        ctx: &CallContext,
    ) -> CallToolResult {
        for hook in self.hooks.iter().rev() {
            let decision = tokio::time::timeout(
                self.timeout,
                hook.post_tool_use(tool_name, arguments, &result, ctx),
            )
            .await
            .unwrap_or_else(|_| {
                tracing::error!(
                    hook = hook.name(),
                    tool = tool_name,
                    "Post-hook timed out — blocking (fail-closed)"
                );
                HookDecision::Block("hook timed out: security check failed".into())
            });

            match decision {
                HookDecision::Continue => {}
                HookDecision::ModifyResult(new_result) => {
                    tracing::debug!(
                        hook = hook.name(),
                        tool = tool_name,
                        "Post-hook modified result"
                    );
                    result = new_result;
                }
                HookDecision::Block(reason) => {
                    tracing::info!(
                        hook = hook.name(),
                        tool = tool_name,
                        reason = %reason,
                        "Post-hook blocked result"
                    );
                    return CallToolResult::error(reason);
                }
                HookDecision::ModifyArgs(_) => {
                    tracing::warn!(
                        hook = hook.name(),
                        tool = tool_name,
                        "Post-hook returned ModifyArgs (ignored in post-phase)"
                    );
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AgentIdentity, CallContext};

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
    }

    /// A hook that blocks tool calls matching a specific name.
    struct BlockingHook {
        block_tool: String,
    }

    #[async_trait::async_trait]
    impl Hook for BlockingHook {
        fn name(&self) -> &str {
            "blocking-hook"
        }

        async fn pre_tool_use(
            &self,
            tool_name: &str,
            _arguments: &serde_json::Value,
            _ctx: &CallContext,
        ) -> HookDecision {
            if tool_name == self.block_tool {
                HookDecision::Block(format!("blocked by policy: {tool_name}"))
            } else {
                HookDecision::Continue
            }
        }
    }

    /// A hook that modifies arguments by injecting a field.
    struct ArgModifyHook;

    #[async_trait::async_trait]
    impl Hook for ArgModifyHook {
        fn name(&self) -> &str {
            "arg-modify-hook"
        }

        async fn pre_tool_use(
            &self,
            _tool_name: &str,
            arguments: &serde_json::Value,
            _ctx: &CallContext,
        ) -> HookDecision {
            let mut args = arguments.clone();
            args["injected"] = serde_json::json!(true);
            HookDecision::ModifyArgs(args)
        }
    }

    /// A hook that modifies results by appending text.
    struct ResultModifyHook {
        suffix: String,
    }

    #[async_trait::async_trait]
    impl Hook for ResultModifyHook {
        fn name(&self) -> &str {
            "result-modify-hook"
        }

        async fn post_tool_use(
            &self,
            _tool_name: &str,
            _arguments: &serde_json::Value,
            result: &CallToolResult,
            _ctx: &CallContext,
        ) -> HookDecision {
            let text = match &result.content[0] {
                myelix_protocol::Content::Text(t) => &t.text,
            };
            HookDecision::ModifyResult(CallToolResult::text(format!(
                "{}{}",
                text, self.suffix
            )))
        }
    }

    /// A hook that sleeps longer than the timeout.
    struct SlowHook;

    #[async_trait::async_trait]
    impl Hook for SlowHook {
        fn name(&self) -> &str {
            "slow-hook"
        }

        async fn pre_tool_use(
            &self,
            _tool_name: &str,
            _arguments: &serde_json::Value,
            _ctx: &CallContext,
        ) -> HookDecision {
            tokio::time::sleep(Duration::from_secs(10)).await;
            HookDecision::Block("should not reach".to_string())
        }
    }

    #[tokio::test]
    async fn empty_pipeline_passes_through() {
        let pipeline = HookPipeline::new(Duration::from_secs(5));
        let args = serde_json::json!({"key": "value"});

        let result = pipeline.run_pre("echo", args.clone(), &test_ctx()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), args);
    }

    #[tokio::test]
    async fn pre_hook_blocks_execution() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(BlockingHook {
            block_tool: "dangerous".to_string(),
        });

        let result = pipeline
            .run_pre("dangerous", serde_json::json!({}), &test_ctx())
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("blocked by policy"));
    }

    #[tokio::test]
    async fn pre_hook_allows_other_tools() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(BlockingHook {
            block_tool: "dangerous".to_string(),
        });

        let result = pipeline
            .run_pre("safe_tool", serde_json::json!({}), &test_ctx())
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn pre_hook_modifies_args() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(ArgModifyHook);

        let result = pipeline
            .run_pre("echo", serde_json::json!({"original": true}), &test_ctx())
            .await;

        let args = result.unwrap();
        assert_eq!(args["original"], true);
        assert_eq!(args["injected"], true);
    }

    #[tokio::test]
    async fn post_hook_modifies_result() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(ResultModifyHook {
            suffix: " [filtered]".to_string(),
        });

        let original = CallToolResult::text("hello");
        let result = pipeline
            .run_post("echo", &serde_json::json!({}), original, &test_ctx())
            .await;

        match &result.content[0] {
            myelix_protocol::Content::Text(t) => {
                assert_eq!(t.text, "hello [filtered]");
            }
        }
    }

    #[tokio::test]
    async fn post_hooks_run_in_reverse_order() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(ResultModifyHook {
            suffix: " [A]".to_string(),
        });
        pipeline.add(ResultModifyHook {
            suffix: " [B]".to_string(),
        });

        let original = CallToolResult::text("base");
        let result = pipeline
            .run_post("echo", &serde_json::json!({}), original, &test_ctx())
            .await;

        // Post-hooks run in reverse: B first, then A
        match &result.content[0] {
            myelix_protocol::Content::Text(t) => {
                assert_eq!(t.text, "base [B] [A]");
            }
        }
    }

    #[tokio::test]
    async fn pre_hook_block_short_circuits() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(BlockingHook {
            block_tool: "echo".to_string(),
        });
        pipeline.add(ArgModifyHook); // should never run

        let result = pipeline
            .run_pre("echo", serde_json::json!({}), &test_ctx())
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn timeout_blocks_on_slow_hook() {
        let mut pipeline = HookPipeline::new(Duration::from_millis(50));
        pipeline.add(SlowHook);

        let result = pipeline
            .run_pre("echo", serde_json::json!({}), &test_ctx())
            .await;

        // Slow hook times out — fail-closed (blocks the tool call)
        assert!(result.is_err());
    }
}
