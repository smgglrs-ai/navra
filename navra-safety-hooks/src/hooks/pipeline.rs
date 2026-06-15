//! Hook pipeline: ordered execution of hooks with timeout enforcement.

use super::{
    Hook, HookDecision, ModelCallContext, PostModelDecision, PostModelOutcome, PreHookOutcome,
    PreModelDecision, PreModelOutcome,
};
use navra_auth::auth::CallContext;
use navra_model::{CreateResponseRequest, ModelResponse};
use navra_protocol::CallToolResult;
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
    /// Returns a `PreHookOutcome` indicating whether to proceed with
    /// (possibly modified) arguments, short-circuit with a simulated
    /// result, block execution, or pause pending approval.
    pub async fn run_pre(
        &self,
        tool_name: &str,
        mut arguments: serde_json::Value,
        ctx: &CallContext,
    ) -> PreHookOutcome {
        for hook in &self.hooks {
            let decision =
                tokio::time::timeout(self.timeout, hook.pre_tool_use(tool_name, &arguments, ctx))
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
                    return PreHookOutcome::Blocked(reason);
                }
                HookDecision::Simulate(result) => {
                    tracing::info!(
                        hook = hook.name(),
                        tool = tool_name,
                        "Pre-hook simulated tool result (skipping handler)"
                    );
                    return PreHookOutcome::Simulated(result);
                }
                HookDecision::Pending(id) => {
                    tracing::info!(
                        hook = hook.name(),
                        tool = tool_name,
                        request_id = %id,
                        "Pre-hook suspended execution pending approval"
                    );
                    return PreHookOutcome::Pending {
                        request_id: id.clone(),
                        reason: format!(
                            "hook '{}' requires approval for '{}'",
                            hook.name(),
                            tool_name
                        ),
                    };
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
        PreHookOutcome::Proceed(arguments)
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
                HookDecision::Simulate(_) => {
                    tracing::warn!(
                        hook = hook.name(),
                        tool = tool_name,
                        "Post-hook returned Simulate (ignored in post-phase)"
                    );
                }
                HookDecision::Pending(_) => {
                    tracing::warn!(
                        hook = hook.name(),
                        tool = tool_name,
                        "Post-hook returned Pending (ignored in post-phase)"
                    );
                }
            }
        }
        result
    }

    /// Run all pre-model-call hooks in order.
    pub async fn run_pre_model(
        &self,
        mut request: CreateResponseRequest,
        ctx: &ModelCallContext,
    ) -> PreModelOutcome {
        for hook in &self.hooks {
            let decision = tokio::time::timeout(self.timeout, hook.pre_model_call(&request, ctx))
                .await
                .unwrap_or_else(|_| {
                    tracing::error!(
                        hook = hook.name(),
                        "Pre-model hook timed out — blocking (fail-closed)"
                    );
                    PreModelDecision::Block("hook timed out: model call blocked".into())
                });

            match decision {
                PreModelDecision::Continue => {}
                PreModelDecision::ModifyRequest(new_req) => {
                    tracing::debug!(hook = hook.name(), "Pre-model hook modified request");
                    request = new_req;
                }
                PreModelDecision::Block(reason) => {
                    tracing::info!(
                        hook = hook.name(),
                        reason = %reason,
                        "Pre-model hook blocked model call"
                    );
                    return PreModelOutcome::Blocked(reason);
                }
            }
        }
        PreModelOutcome::Proceed(request)
    }

    /// Run all post-model-call hooks in reverse order.
    pub async fn run_post_model(
        &self,
        request: &CreateResponseRequest,
        mut response: ModelResponse,
        ctx: &ModelCallContext,
    ) -> PostModelOutcome {
        for hook in self.hooks.iter().rev() {
            let decision =
                tokio::time::timeout(self.timeout, hook.post_model_call(request, &response, ctx))
                    .await
                    .unwrap_or_else(|_| {
                        tracing::error!(
                            hook = hook.name(),
                            "Post-model hook timed out — blocking (fail-closed)"
                        );
                        PostModelDecision::Block("hook timed out: model response blocked".into())
                    });

            match decision {
                PostModelDecision::Continue => {}
                PostModelDecision::ModifyResponse(new_resp) => {
                    tracing::debug!(hook = hook.name(), "Post-model hook modified response");
                    response = new_resp;
                }
                PostModelDecision::Retry(new_req) => {
                    tracing::info!(hook = hook.name(), "Post-model hook requested retry");
                    return PostModelOutcome::Retry(new_req);
                }
                PostModelDecision::Block(reason) => {
                    tracing::info!(
                        hook = hook.name(),
                        reason = %reason,
                        "Post-model hook blocked response"
                    );
                    return PostModelOutcome::Blocked(reason);
                }
            }
        }
        PostModelOutcome::Accept(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_auth::auth::{AgentIdentity, CallContext};

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
                navra_protocol::Content::Text(t) => &t.text,
                _ => return HookDecision::Continue,
            };
            HookDecision::ModifyResult(CallToolResult::text(format!("{}{}", text, self.suffix)))
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

        let outcome = pipeline.run_pre("echo", args.clone(), &test_ctx()).await;
        match outcome {
            PreHookOutcome::Proceed(result_args) => assert_eq!(result_args, args),
            other => panic!("expected Proceed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pre_hook_blocks_execution() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(BlockingHook {
            block_tool: "dangerous".to_string(),
        });

        let outcome = pipeline
            .run_pre("dangerous", serde_json::json!({}), &test_ctx())
            .await;
        match outcome {
            PreHookOutcome::Blocked(reason) => assert!(reason.contains("blocked by policy")),
            other => panic!("expected Blocked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pre_hook_allows_other_tools() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(BlockingHook {
            block_tool: "dangerous".to_string(),
        });

        let outcome = pipeline
            .run_pre("safe_tool", serde_json::json!({}), &test_ctx())
            .await;
        assert!(matches!(outcome, PreHookOutcome::Proceed(_)));
    }

    #[tokio::test]
    async fn pre_hook_modifies_args() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(ArgModifyHook);

        let outcome = pipeline
            .run_pre("echo", serde_json::json!({"original": true}), &test_ctx())
            .await;

        match outcome {
            PreHookOutcome::Proceed(args) => {
                assert_eq!(args["original"], true);
                assert_eq!(args["injected"], true);
            }
            other => panic!("expected Proceed, got {:?}", other),
        }
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
            navra_protocol::Content::Text(t) => {
                assert_eq!(t.text, "hello [filtered]");
            }
            _ => panic!("expected text content"),
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
            navra_protocol::Content::Text(t) => {
                assert_eq!(t.text, "base [B] [A]");
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn pre_hook_block_short_circuits() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(BlockingHook {
            block_tool: "echo".to_string(),
        });
        pipeline.add(ArgModifyHook); // should never run

        let outcome = pipeline
            .run_pre("echo", serde_json::json!({}), &test_ctx())
            .await;

        assert!(matches!(outcome, PreHookOutcome::Blocked(_)));
    }

    #[tokio::test]
    async fn timeout_blocks_on_slow_hook() {
        let mut pipeline = HookPipeline::new(Duration::from_millis(50));
        pipeline.add(SlowHook);

        let outcome = pipeline
            .run_pre("echo", serde_json::json!({}), &test_ctx())
            .await;

        // Slow hook times out — fail-closed (blocks the tool call)
        assert!(matches!(outcome, PreHookOutcome::Blocked(_)));
    }

    // --- Model-call hook tests ---

    struct ModelBlockHook;

    #[async_trait::async_trait]
    impl Hook for ModelBlockHook {
        fn name(&self) -> &str {
            "model-block"
        }

        async fn pre_model_call(
            &self,
            _request: &CreateResponseRequest,
            ctx: &ModelCallContext,
        ) -> PreModelDecision {
            if ctx.tokens_consumed >= ctx.token_budget {
                PreModelDecision::Block("token budget exceeded".into())
            } else {
                PreModelDecision::Continue
            }
        }
    }

    struct TempOverrideHook {
        temperature: f32,
    }

    #[async_trait::async_trait]
    impl Hook for TempOverrideHook {
        fn name(&self) -> &str {
            "temp-override"
        }

        async fn pre_model_call(
            &self,
            request: &CreateResponseRequest,
            _ctx: &ModelCallContext,
        ) -> PreModelDecision {
            let mut req = request.clone();
            req.temperature = Some(self.temperature);
            PreModelDecision::ModifyRequest(req)
        }
    }

    struct PostModelBlockHook;

    #[async_trait::async_trait]
    impl Hook for PostModelBlockHook {
        fn name(&self) -> &str {
            "post-model-block"
        }

        async fn post_model_call(
            &self,
            _request: &CreateResponseRequest,
            _response: &ModelResponse,
            _ctx: &ModelCallContext,
        ) -> PostModelDecision {
            PostModelDecision::Block("response rejected".into())
        }
    }

    struct RetryHook;

    #[async_trait::async_trait]
    impl Hook for RetryHook {
        fn name(&self) -> &str {
            "retry-hook"
        }

        async fn post_model_call(
            &self,
            request: &CreateResponseRequest,
            _response: &ModelResponse,
            _ctx: &ModelCallContext,
        ) -> PostModelDecision {
            let mut req = request.clone();
            req.temperature = Some(0.0);
            PostModelDecision::Retry(req)
        }
    }

    fn model_ctx() -> ModelCallContext {
        ModelCallContext {
            run_id: "test-run".into(),
            iteration: 0,
            tokens_consumed: 100,
            token_budget: 500_000,
        }
    }

    fn empty_request() -> CreateResponseRequest {
        CreateResponseRequest::new(String::new(), vec![])
    }

    fn empty_response() -> ModelResponse {
        ModelResponse {
            id: "test".into(),
            object: "response".into(),
            created_at: None,
            completed_at: None,
            status: navra_model::ResponseStatus::Completed,
            model: None,
            output: vec![],
            usage: None,
            error: None,
            previous_response_id: None,
            instructions: None,
            tools: vec![],
            tool_choice: None,
            text: None,
            reasoning: None,
            truncation: None,
            temperature: None,
            max_output_tokens: None,
            metadata: std::collections::HashMap::new(),
            incomplete_details: None,
            extra: std::collections::HashMap::new(),
        }
    }

    #[tokio::test]
    async fn empty_pipeline_passes_model_request_through() {
        let pipeline = HookPipeline::new(Duration::from_secs(5));
        let request = empty_request();
        let outcome = pipeline.run_pre_model(request, &model_ctx()).await;
        assert!(matches!(outcome, PreModelOutcome::Proceed(_)));
    }

    #[tokio::test]
    async fn empty_pipeline_passes_model_response_through() {
        let pipeline = HookPipeline::new(Duration::from_secs(5));
        let request = empty_request();
        let response = empty_response();
        let outcome = pipeline
            .run_post_model(&request, response, &model_ctx())
            .await;
        assert!(matches!(outcome, PostModelOutcome::Accept(_)));
    }

    #[tokio::test]
    async fn pre_model_hook_modifies_request() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(TempOverrideHook { temperature: 0.1 });

        let request = empty_request();
        let outcome = pipeline.run_pre_model(request, &model_ctx()).await;

        match outcome {
            PreModelOutcome::Proceed(req) => {
                assert_eq!(req.temperature, Some(0.1));
            }
            other => panic!("expected Proceed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pre_model_hook_blocks_on_budget() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(ModelBlockHook);

        let ctx = ModelCallContext {
            run_id: "test".into(),
            iteration: 5,
            tokens_consumed: 500_000,
            token_budget: 500_000,
        };
        let outcome = pipeline.run_pre_model(empty_request(), &ctx).await;
        assert!(matches!(outcome, PreModelOutcome::Blocked(_)));
    }

    #[tokio::test]
    async fn post_model_hook_blocks_response() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(PostModelBlockHook);

        let outcome = pipeline
            .run_post_model(&empty_request(), empty_response(), &model_ctx())
            .await;
        match outcome {
            PostModelOutcome::Blocked(reason) => assert!(reason.contains("rejected")),
            other => panic!("expected Blocked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn post_model_hook_requests_retry() {
        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(RetryHook);

        let outcome = pipeline
            .run_post_model(&empty_request(), empty_response(), &model_ctx())
            .await;

        match outcome {
            PostModelOutcome::Retry(req) => {
                assert_eq!(req.temperature, Some(0.0));
            }
            other => panic!("expected Retry, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pre_model_timeout_blocks() {
        struct SlowModelHook;

        #[async_trait::async_trait]
        impl Hook for SlowModelHook {
            fn name(&self) -> &str {
                "slow-model"
            }
            async fn pre_model_call(
                &self,
                _request: &CreateResponseRequest,
                _ctx: &ModelCallContext,
            ) -> PreModelDecision {
                tokio::time::sleep(Duration::from_secs(10)).await;
                PreModelDecision::Continue
            }
        }

        let mut pipeline = HookPipeline::new(Duration::from_millis(50));
        pipeline.add(SlowModelHook);

        let outcome = pipeline.run_pre_model(empty_request(), &model_ctx()).await;
        assert!(matches!(outcome, PreModelOutcome::Blocked(_)));
    }

    #[tokio::test]
    async fn pre_hook_simulate_short_circuits() {
        struct SimulateHook;

        #[async_trait::async_trait]
        impl Hook for SimulateHook {
            fn name(&self) -> &str {
                "simulate-hook"
            }
            async fn pre_tool_use(
                &self,
                _tool_name: &str,
                _arguments: &serde_json::Value,
                _ctx: &CallContext,
            ) -> HookDecision {
                HookDecision::Simulate(CallToolResult::text("simulated response"))
            }
        }

        let mut pipeline = HookPipeline::new(Duration::from_secs(5));
        pipeline.add(SimulateHook);
        pipeline.add(ArgModifyHook); // should never run

        let outcome = pipeline
            .run_pre("echo", serde_json::json!({}), &test_ctx())
            .await;

        match outcome {
            PreHookOutcome::Simulated(result) => match &result.content[0] {
                navra_protocol::Content::Text(t) => {
                    assert_eq!(t.text, "simulated response");
                }
                _ => panic!("expected text content"),
            },
            other => panic!("expected Simulated, got {:?}", other),
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Model the pre-hook decision dispatch as a pure function.
    /// Proves that Block/Simulate always short-circuit, and
    /// ModifyResult is safely ignored in pre-phase.
    #[derive(Debug, Clone, Copy)]
    enum Decision {
        Continue,
        ModifyArgs,
        Block,
        Simulate,
        ModifyResult,
    }

    impl kani::Arbitrary for Decision {
        fn any_array<const N: usize>() -> [Self; N] {
            [Self::Continue; N]
        }

        fn any() -> Self {
            match kani::any::<u8>() % 5 {
                0 => Decision::Continue,
                1 => Decision::ModifyArgs,
                2 => Decision::Block,
                3 => Decision::Simulate,
                _ => Decision::ModifyResult,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Outcome {
        Proceed,
        Blocked,
        Simulated,
    }

    /// Pure model of run_pre for a single hook.
    fn pre_dispatch(decision: Decision) -> (Outcome, bool) {
        match decision {
            Decision::Continue => (Outcome::Proceed, false),
            Decision::ModifyArgs => (Outcome::Proceed, false),
            Decision::Block => (Outcome::Blocked, true),
            Decision::Simulate => (Outcome::Simulated, true),
            Decision::ModifyResult => (Outcome::Proceed, false), // ignored in pre-phase
        }
    }

    #[kani::proof]
    fn block_always_short_circuits() {
        let d: Decision = kani::any();
        let (outcome, short_circuits) = pre_dispatch(d);
        if matches!(d, Decision::Block) {
            assert_eq!(outcome, Outcome::Blocked);
            assert!(short_circuits);
        }
    }

    #[kani::proof]
    fn simulate_always_short_circuits() {
        let d: Decision = kani::any();
        let (outcome, short_circuits) = pre_dispatch(d);
        if matches!(d, Decision::Simulate) {
            assert_eq!(outcome, Outcome::Simulated);
            assert!(short_circuits);
        }
    }

    #[kani::proof]
    fn modify_result_ignored_in_pre_phase() {
        let (outcome, short_circuits) = pre_dispatch(Decision::ModifyResult);
        assert_eq!(outcome, Outcome::Proceed);
        assert!(!short_circuits);
    }

    /// Fail-closed: timeout → Block. Models the unwrap_or_else behavior.
    #[kani::proof]
    fn timeout_is_fail_closed() {
        let timed_out: bool = kani::any();
        let hook_decision: Decision = kani::any();
        let effective = if timed_out {
            Decision::Block
        } else {
            hook_decision
        };
        let (outcome, _) = pre_dispatch(effective);
        if timed_out {
            assert_eq!(outcome, Outcome::Blocked);
        }
    }
}
