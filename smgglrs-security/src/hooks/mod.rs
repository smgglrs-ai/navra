//! Hook/middleware system for intercepting tool calls.
//!
//! Hooks allow pluggable pre- and post-processing of tool calls.
//! Pre-hooks can modify arguments or block execution; post-hooks
//! can modify results. Safety filtering is implemented as a built-in
//! post-hook.

mod budget;
pub mod field_filter;
mod memory_extraction;
mod pipeline;
mod routing;
mod safety_hook;
pub mod skill_hook;
pub mod statistical;
pub mod temporal_contract;
mod tool_guard;

pub use budget::{estimate_tokens, BudgetHook, TruncationStrategy};
pub use field_filter::{FieldFilterConfig, FieldFilterHook};
pub use memory_extraction::{ExtractionStore, MemoryExtractionConfig, MemoryExtractionHook};
pub use pipeline::HookPipeline;
pub use routing::{ModelTier, ModelTierConfig, RoutingConfig, RoutingHook};
pub use safety_hook::SafetyHook;
pub use skill_hook::{Intervention, SkillHook, SkillRule};
pub use statistical::{StatisticalConfig, StatisticalGuardrailHook};
pub use temporal_contract::{
    ContractAction, SessionActionLog, TemporalContract, TemporalContractHook, TemporalPredicate,
};
pub use tool_guard::ToolGuardHook;

use crate::auth::CallContext;
use async_trait::async_trait;
use smgglrs_protocol::CallToolResult;

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
}
