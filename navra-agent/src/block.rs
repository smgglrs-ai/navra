//! Block-based tool execution model for structured output.

fn instant_now() -> std::time::Instant {
    std::time::Instant::now()
}

/// A single tool execution block — addressable, timed, renderable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolBlock {
    /// Unique identifier for this block.
    pub block_id: String,
    /// Name of the tool being executed.
    pub tool_name: String,
    /// Arguments passed to the tool.
    pub arguments: serde_json::Value,
    /// Current execution status.
    pub status: BlockStatus,
    /// When execution started (not serialized).
    #[serde(skip, default = "instant_now")]
    pub started_at: std::time::Instant,
    /// Wall-clock duration in milliseconds, set on completion/cancellation.
    pub duration_ms: Option<u64>,
    /// Truncated preview of the tool result.
    pub result_preview: Option<String>,
    /// Whether the tool returned an error.
    pub is_error: bool,
}

/// Status of a tool execution block.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockStatus {
    /// Queued but not yet started.
    Pending,
    /// Currently executing.
    Running,
    /// Finished successfully.
    Completed,
    /// Finished with an error.
    Failed,
    /// Execution was cancelled before completion.
    Cancelled,
}

impl ToolBlock {
    /// Create a new tool block in `Running` status.
    pub fn new(tool_name: &str, arguments: serde_json::Value) -> Self {
        Self {
            block_id: uuid::Uuid::new_v4().to_string(),
            tool_name: tool_name.to_string(),
            arguments,
            status: BlockStatus::Running,
            started_at: std::time::Instant::now(),
            duration_ms: None,
            result_preview: None,
            is_error: false,
        }
    }

    /// Mark the block as completed (or failed if `is_error` is true).
    pub fn complete(&mut self, result: &str, is_error: bool) {
        self.duration_ms = Some(self.started_at.elapsed().as_millis() as u64);
        self.is_error = is_error;
        self.status = if is_error {
            BlockStatus::Failed
        } else {
            BlockStatus::Completed
        };
        self.result_preview = Some(truncate(result, 200));
    }

    /// Mark the block as cancelled.
    pub fn cancel(&mut self) {
        self.duration_ms = Some(self.started_at.elapsed().as_millis() as u64);
        self.status = BlockStatus::Cancelled;
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn new_block_is_running() {
        let block = ToolBlock::new("git_status", json!({"path": "."}));
        assert!(!block.block_id.is_empty());
        assert_eq!(block.tool_name, "git_status");
        assert!(matches!(block.status, BlockStatus::Running));
        assert!(!block.is_error);
        assert!(block.duration_ms.is_none());
        assert!(block.result_preview.is_none());
    }

    #[test]
    fn complete_success() {
        let mut block = ToolBlock::new("file_read", json!({}));
        block.complete("file contents here", false);
        assert!(matches!(block.status, BlockStatus::Completed));
        assert!(!block.is_error);
        assert!(block.duration_ms.is_some());
        assert_eq!(block.result_preview.as_deref(), Some("file contents here"));
    }

    #[test]
    fn complete_error() {
        let mut block = ToolBlock::new("file_read", json!({}));
        block.complete("permission denied", true);
        assert!(matches!(block.status, BlockStatus::Failed));
        assert!(block.is_error);
    }

    #[test]
    fn cancel_sets_status() {
        let mut block = ToolBlock::new("long_task", json!({}));
        block.cancel();
        assert!(matches!(block.status, BlockStatus::Cancelled));
        assert!(block.duration_ms.is_some());
    }

    #[test]
    fn result_preview_truncated() {
        let mut block = ToolBlock::new("big_read", json!({}));
        let long_text = "x".repeat(500);
        block.complete(&long_text, false);
        let preview = block.result_preview.as_ref().unwrap();
        // 200 chars + ellipsis
        assert!(preview.len() <= 204);
        assert!(preview.ends_with('…'));
    }

    #[test]
    fn serialization_excludes_started_at() {
        let block = ToolBlock::new("test_tool", json!({"key": "val"}));
        let json_str = serde_json::to_string(&block).unwrap();
        assert!(!json_str.contains("started_at"));
        assert!(json_str.contains("block_id"));
        assert!(json_str.contains("tool_name"));
        assert!(json_str.contains("running"));
    }

    #[test]
    fn block_status_serializes_snake_case() {
        let statuses = vec![
            (BlockStatus::Pending, "pending"),
            (BlockStatus::Running, "running"),
            (BlockStatus::Completed, "completed"),
            (BlockStatus::Failed, "failed"),
            (BlockStatus::Cancelled, "cancelled"),
        ];
        for (status, expected) in statuses {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, format!("\"{expected}\""));
        }
    }
}
