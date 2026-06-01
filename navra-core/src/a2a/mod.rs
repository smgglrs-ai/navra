//! A2A task store and message dispatch logic.
//!
//! Maps incoming A2A messages to MCP tool calls. The skill/tool name
//! is resolved from `message.metadata["skill"]`, a `DataPart` with
//! a `"tool"` key, or by matching the message text against registered
//! tool names.

mod dispatch;
mod store;

pub use dispatch::{
    handle_message_send, handle_message_stream, handle_tasks_cancel, handle_tasks_get,
};
pub use store::TaskStore;

#[cfg(test)]
mod tests;
