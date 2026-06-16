//! Hook/middleware system for intercepting tool calls.
//!
//! Hooks allow pluggable pre- and post-processing of tool calls.
//! Pre-hooks can modify arguments or block execution; post-hooks
//! can modify results. Safety filtering is implemented as a built-in
//! post-hook.

pub mod approval_gate;
mod budget;
pub mod egress;
pub mod field_filter;
pub mod leakage;
mod memory_extraction;
mod pipeline;
mod policy_yaml;
pub mod provenance_hook;
mod routing;
mod safety_hook;
mod sandbox_hook;
pub mod skill_hook;
pub mod statistical;
pub mod temporal_contract;
pub mod verifier;
mod tool_guard;

pub use approval_gate::{ApprovalGateConfig, ApprovalGateHook, ApprovalStatus, PendingApproval};
pub use budget::{estimate_tokens, BudgetHook, TruncationStrategy};
pub use egress::{EgressConfig, EgressFilterHook};
pub use field_filter::{FieldFilterConfig, FieldFilterHook};
pub use leakage::{
    SemanticLeakageConfig, SemanticLeakageJudge, SimilarityLeakageConfig, SimilarityLeakageHook,
};
pub use memory_extraction::{ExtractionStore, MemoryExtractionConfig, MemoryExtractionHook};
pub use pipeline::HookPipeline;
pub use policy_yaml::PolicyYamlHook;
pub use provenance_hook::{CausalSink, ProvenanceHook};
pub use routing::{ModelTier, ModelTierConfig, RoutingConfig, RoutingHook};
pub use safety_hook::SafetyHook;
pub use sandbox_hook::SandboxHook;
pub use skill_hook::{Intervention, SkillHook, SkillRule};
pub use statistical::{StatisticalConfig, StatisticalGuardrailHook};
pub use temporal_contract::{
    ContractAction, SessionActionLog, TemporalContract, TemporalContractHook, TemporalPredicate,
};
pub use tool_guard::ToolGuardHook;
pub use verifier::{VerifierConfig, VerifierHook, VerifierStats};

use async_trait::async_trait;
use navra_auth::auth::CallContext;
use navra_model::{CreateResponseRequest, ModelResponse};
use navra_protocol::CallToolResult;

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
    /// Short-circuit: return a simulated result without executing the tool (pre-hook only).
    Simulate(CallToolResult),
    /// Suspend execution pending human approval (pre-hook only).
    Pending(String),
}

/// Context available during model-call hook phases.
///
/// Unlike `CallContext` (gateway-side, authenticated), this carries
/// agent-side metadata available in the tool loop.
#[derive(Debug, Clone)]
pub struct ModelCallContext {
    pub run_id: String,
    pub iteration: usize,
    pub tokens_consumed: u64,
    pub token_budget: u64,
}

/// Decision returned by a hook in the pre-model-call phase.
#[derive(Debug)]
pub enum PreModelDecision {
    Continue,
    ModifyRequest(CreateResponseRequest),
    Block(String),
}

/// Decision returned by a hook in the post-model-call phase.
#[derive(Debug)]
pub enum PostModelDecision {
    Continue,
    ModifyResponse(ModelResponse),
    Retry(CreateResponseRequest),
    Block(String),
}

/// Outcome of running pre-model-call hooks through the pipeline.
#[derive(Debug)]
pub enum PreModelOutcome {
    Proceed(CreateResponseRequest),
    Blocked(String),
}

/// Outcome of running post-model-call hooks through the pipeline.
#[derive(Debug)]
pub enum PostModelOutcome {
    Accept(ModelResponse),
    Retry(CreateResponseRequest),
    Blocked(String),
}

/// Outcome of running pre-hooks through the pipeline.
///
/// Distinguishes between "proceed with (possibly modified) arguments"
/// and "short-circuit with a simulated result" so the caller in
/// `handlers.rs` can skip the real tool handler when appropriate.
#[derive(Debug)]
pub enum PreHookOutcome {
    /// Continue to the real tool handler with these arguments.
    Proceed(serde_json::Value),
    /// Skip the tool handler and return this result directly.
    Simulated(CallToolResult),
    /// Block execution and return this error message.
    Blocked(String),
    /// Awaiting human approval before proceeding.
    Pending { request_id: String, reason: String },
}

/// Trait for hook implementations.
///
/// Hooks intercept tool calls at two points:
/// - `pre_tool_use`: before the handler runs (can modify args or block)
/// - `post_tool_use`: after the handler returns (can modify results)
///
/// Default implementations return `Continue` (no-op), so hooks only
/// need to implement the events they care about.
#[async_trait]
pub trait Hook: Send + Sync + 'static {
    /// Hook name for logging and diagnostics.
    fn name(&self) -> &str;

    /// Called before a tool handler executes.
    async fn pre_tool_use(
        &self,
        _tool_name: &str,
        _arguments: &serde_json::Value,
        _ctx: &CallContext,
    ) -> HookDecision {
        HookDecision::Continue
    }

    /// Called after a tool handler returns.
    async fn post_tool_use(
        &self,
        _tool_name: &str,
        _arguments: &serde_json::Value,
        _result: &CallToolResult,
        _ctx: &CallContext,
    ) -> HookDecision {
        HookDecision::Continue
    }

    /// Called before a model call in the agent tool loop.
    async fn pre_model_call(
        &self,
        _request: &CreateResponseRequest,
        _ctx: &ModelCallContext,
    ) -> PreModelDecision {
        PreModelDecision::Continue
    }

    /// Called after a model call returns in the agent tool loop.
    async fn post_model_call(
        &self,
        _request: &CreateResponseRequest,
        _response: &ModelResponse,
        _ctx: &ModelCallContext,
    ) -> PostModelDecision {
        PostModelDecision::Continue
    }

    /// Called when a session ends (explicit close or expiry).
    ///
    /// Runs before session state is removed. Use for cross-session
    /// fact extraction, audit summarization, or cleanup.
    /// Returning `Block` is a no-op — session cleanup always proceeds.
    async fn on_session_end(
        &self,
        _session_id: &str,
        _agent_name: &str,
        _tool_count: usize,
    ) {
    }
}
