//! Context budget enforcement hook.
//!
//! Truncates tool outputs that exceed a configured token budget,
//! preventing a single tool call from consuming the entire agent
//! context window.

use super::{Hook, HookDecision};
use navra_auth::auth::CallContext;
use navra_protocol::{CallToolResult, Content};

/// Strategy for reducing oversized tool outputs.
#[derive(Debug, Clone)]
pub enum TruncationStrategy {
    /// Hard truncate at token limit, add "[truncated]" marker.
    Truncate,
    /// Keep first `head_ratio` of the budget at the start and
    /// the remainder at the end, eliding the middle.
    HeadTail { head_ratio: f32 },
    /// Placeholder: falls back to `HeadTail { head_ratio: 0.7 }`.
    /// Real summarization would require an LLM call.
    Summarize,
}

impl Default for TruncationStrategy {
    fn default() -> Self {
        TruncationStrategy::HeadTail { head_ratio: 0.7 }
    }
}

/// Post-hook that enforces a token budget on tool outputs.
///
/// Checks the total estimated token count across all `Content::Text`
/// items in a `CallToolResult`. If the total exceeds the configured
/// limit, the text is truncated according to the chosen strategy.
///
/// Skips error results and non-text content.
pub struct BudgetHook {
    max_tool_output_tokens: usize,
    truncation_strategy: TruncationStrategy,
}

impl BudgetHook {
    /// Create a new budget hook with the given token limit and strategy.
    pub fn new(max_tool_output_tokens: usize, strategy: TruncationStrategy) -> Self {
        Self {
            max_tool_output_tokens,
            truncation_strategy: strategy,
        }
    }
}

/// Estimate token count from text using the ~4 chars/token heuristic.
pub fn estimate_tokens(text: &str) -> usize {
    (text.len() + 3) / 4
}

/// Convert a token count back to an approximate character count.
fn tokens_to_chars(tokens: usize) -> usize {
    tokens * 4
}

/// Truncate text to fit within `max_tokens`, preserving line boundaries.
///
/// Adds a `[truncated]` marker at the end.
fn truncate_hard(text: &str, max_tokens: usize) -> String {
    let char_budget = tokens_to_chars(max_tokens);
    // Find a line boundary at or before the char budget
    let cut = find_line_boundary_before(text, char_budget);
    let kept = &text[..cut];
    let dropped_tokens = estimate_tokens(&text[cut..]);
    format!("{kept}\n[truncated {dropped_tokens} tokens]")
}

/// Truncate text keeping the head and tail, eliding the middle.
///
/// `head_ratio` controls what fraction of `max_tokens` goes to the head.
fn truncate_head_tail(text: &str, max_tokens: usize, head_ratio: f32) -> String {
    let head_tokens = (max_tokens as f32 * head_ratio) as usize;
    let tail_tokens = max_tokens.saturating_sub(head_tokens);

    let head_chars = tokens_to_chars(head_tokens);
    let tail_chars = tokens_to_chars(tail_tokens);

    let head_end = find_line_boundary_before(text, head_chars);
    let tail_start = find_line_boundary_after(text, text.len().saturating_sub(tail_chars));

    // If the ranges overlap or are adjacent, no truncation needed
    if head_end >= tail_start {
        return text.to_string();
    }

    let dropped_tokens = estimate_tokens(&text[head_end..tail_start]);
    format!(
        "{}\n[... truncated {} tokens ...]\n{}",
        &text[..head_end],
        dropped_tokens,
        &text[tail_start..],
    )
}

/// Find the last line boundary (newline + 1) at or before `pos`.
/// Returns `pos` clamped to `text.len()` if no newline is found before it.
fn find_line_boundary_before(text: &str, pos: usize) -> usize {
    let pos = pos.min(text.len());
    // If we're already at the end, return as-is
    if pos == text.len() {
        return pos;
    }
    // Walk backwards to find a newline
    match text[..pos].rfind('\n') {
        Some(nl) => nl + 1,
        None => pos, // No newline found; cut at pos (may be mid-line)
    }
}

/// Find the first line boundary (start of a line) at or after `pos`.
fn find_line_boundary_after(text: &str, pos: usize) -> usize {
    let pos = pos.min(text.len());
    match text[pos..].find('\n') {
        Some(offset) => {
            let nl = pos + offset;
            if nl + 1 <= text.len() {
                nl + 1
            } else {
                text.len()
            }
        }
        None => pos,
    }
}

/// Apply the truncation strategy to a single text string.
fn apply_strategy(text: &str, max_tokens: usize, strategy: &TruncationStrategy) -> String {
    match strategy {
        TruncationStrategy::Truncate => truncate_hard(text, max_tokens),
        TruncationStrategy::HeadTail { head_ratio } => {
            truncate_head_tail(text, max_tokens, *head_ratio)
        }
        TruncationStrategy::Summarize => {
            // Stub: fall back to head+tail with 0.7 ratio
            truncate_head_tail(text, max_tokens, 0.7)
        }
    }
}

#[async_trait::async_trait]
impl Hook for BudgetHook {
    fn name(&self) -> &str {
        "budget"
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        result: &CallToolResult,
        _ctx: &CallContext,
    ) -> HookDecision {
        // Never truncate error results — error messages must be complete
        if result.is_error {
            return HookDecision::Continue;
        }

        // Count total tokens across all text content items
        let total_tokens: usize = result
            .content
            .iter()
            .filter_map(|c| match c {
                Content::Text(t) => Some(estimate_tokens(&t.text)),
                _ => None,
            })
            .sum();

        if total_tokens <= self.max_tool_output_tokens {
            return HookDecision::Continue;
        }

        tracing::info!(
            tool = %tool_name,
            original_tokens = total_tokens,
            budget = self.max_tool_output_tokens,
            "Tool output exceeds budget, truncating"
        );

        // Distribute the budget proportionally across text items
        let text_count = result
            .content
            .iter()
            .filter(|c| matches!(c, Content::Text(_)))
            .count();

        // If only one text item, give it the full budget.
        // If multiple, distribute proportionally by size.
        let mut truncated_content = Vec::with_capacity(result.content.len());
        let mut any_changed = false;

        for content in &result.content {
            match content {
                Content::Text(t) => {
                    let item_tokens = estimate_tokens(&t.text);
                    let item_budget = if text_count == 1 {
                        self.max_tool_output_tokens
                    } else {
                        // Proportional share of the budget
                        let share = item_tokens as f64 / total_tokens as f64;
                        (share * self.max_tool_output_tokens as f64) as usize
                    };

                    if item_tokens > item_budget {
                        let truncated =
                            apply_strategy(&t.text, item_budget, &self.truncation_strategy);
                        any_changed = true;
                        truncated_content.push(Content::text(truncated));
                    } else {
                        truncated_content.push(content.clone());
                    }
                }
                _ => {
                    // Pass through non-text content unchanged
                    truncated_content.push(content.clone());
                }
            }
        }

        if !any_changed {
            return HookDecision::Continue;
        }

        // Add a metadata note about truncation
        let new_total: usize = truncated_content
            .iter()
            .filter_map(|c| match c {
                Content::Text(t) => Some(estimate_tokens(&t.text)),
                _ => None,
            })
            .sum();

        truncated_content.push(Content::text(format!(
            "[Output truncated from {} to {} tokens]",
            total_tokens, new_total,
        )));

        HookDecision::ModifyResult(CallToolResult {
            content: truncated_content,
            is_error: result.is_error,
            label: result.label,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_auth::auth::AgentIdentity;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
    }

    // --- Token estimation ---

    #[test]
    fn estimate_tokens_empty() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn estimate_tokens_short() {
        // "hello" = 5 chars => (5 + 3) / 4 = 2 tokens
        assert_eq!(estimate_tokens("hello"), 2);
    }

    #[test]
    fn estimate_tokens_exact_multiple() {
        // 8 chars => (8 + 3) / 4 = 2 tokens
        assert_eq!(estimate_tokens("abcdefgh"), 2);
    }

    #[test]
    fn estimate_tokens_longer() {
        let text = "a".repeat(100);
        // 100 chars => (100 + 3) / 4 = 25 tokens
        assert_eq!(estimate_tokens(&text), 25);
    }

    // --- Hard truncation ---

    #[test]
    fn truncate_hard_over_budget() {
        let text = "line one\nline two\nline three\nline four\n";
        // Budget of 3 tokens = 12 chars
        let result = truncate_hard(text, 3);
        assert!(result.starts_with("line one\n"));
        assert!(result.contains("[truncated"));
        assert!(!result.contains("line four"));
    }

    // --- Head+tail truncation ---

    #[test]
    fn head_tail_preserves_small_output() {
        let text = "small output";
        let result = truncate_head_tail(text, 100, 0.7);
        assert_eq!(result, text);
    }

    #[test]
    fn head_tail_truncates_middle() {
        // Build a text with clear line structure
        let mut lines = Vec::new();
        for i in 0..100 {
            lines.push(format!("line {:03}", i));
        }
        let text = lines.join("\n");
        let total_tokens = estimate_tokens(&text);

        // Set budget to ~1/4 of total
        let budget = total_tokens / 4;
        let result = truncate_head_tail(&text, budget, 0.7);

        // Should have head, marker, tail
        assert!(result.contains("[... truncated"));
        assert!(result.starts_with("line 000"));
        assert!(result.contains("line 099"));
    }

    #[test]
    fn head_tail_respects_line_boundaries() {
        let text = "first line\nsecond line\nthird line\nfourth line\nfifth line\n";
        // Budget that forces truncation
        let result = truncate_head_tail(text, 5, 0.7);
        // Head should end at a line boundary
        let parts: Vec<&str> = result.split("[... truncated").collect();
        assert!(parts.len() == 2, "Expected truncation marker");
        let head = parts[0].trim_end_matches('\n');
        // Head should not cut mid-line
        assert!(
            head.ends_with("line") || head.ends_with('\n') || head.is_empty(),
            "Head cut mid-line: {:?}",
            head
        );
    }

    // --- Hook integration ---

    #[tokio::test]
    async fn small_output_passes_through() {
        let hook = BudgetHook::new(1000, TruncationStrategy::HeadTail { head_ratio: 0.7 });
        let result = CallToolResult::text("hello world");
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn large_output_gets_truncated() {
        let hook = BudgetHook::new(10, TruncationStrategy::HeadTail { head_ratio: 0.7 });
        // ~250 tokens
        let big_text = "a]".repeat(500);
        let result = CallToolResult::text(big_text);
        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &test_ctx())
            .await;
        match decision {
            HookDecision::ModifyResult(r) => {
                assert!(!r.is_error);
                // Should have truncation metadata
                let all_text: String = r
                    .content
                    .iter()
                    .filter_map(|c| match c {
                        Content::Text(t) => Some(t.text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("");
                assert!(all_text.contains("[Output truncated from"));
            }
            other => panic!("Expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn error_results_not_truncated() {
        let hook = BudgetHook::new(1, TruncationStrategy::Truncate);
        let mut result = CallToolResult::text("a]".repeat(500));
        result.is_error = true;
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn only_non_text_content_passes_through() {
        let hook = BudgetHook::new(1, TruncationStrategy::Truncate);
        // Result with no text items — total text tokens is 0, within budget
        let result = CallToolResult::success(vec![]);
        let decision = hook
            .post_tool_use(
                "vision_capture",
                &serde_json::json!({}),
                &result,
                &test_ctx(),
            )
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn multi_text_items_both_truncated() {
        let hook = BudgetHook::new(20, TruncationStrategy::Truncate);
        // Two text items, each ~125 tokens, total ~250 tokens, budget 20
        let result = CallToolResult::success(vec![
            Content::text("x".repeat(500)),
            Content::text("y".repeat(500)),
        ]);
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;
        match decision {
            HookDecision::ModifyResult(r) => {
                // Original 2 text items + 1 metadata note
                let text_items: Vec<_> = r
                    .content
                    .iter()
                    .filter_map(|c| match c {
                        Content::Text(t) => Some(&t.text),
                        _ => None,
                    })
                    .collect();
                // At least 3: two truncated items + metadata
                assert!(text_items.len() >= 3, "Expected at least 3 text items");
                assert!(text_items[0].contains("[truncated"));
                assert!(text_items[1].contains("[truncated"));
                assert!(text_items
                    .last()
                    .unwrap()
                    .contains("[Output truncated from"));
            }
            other => panic!("Expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn summarize_falls_back_to_head_tail() {
        let hook = BudgetHook::new(10, TruncationStrategy::Summarize);
        let big_text = (0..50)
            .map(|i| format!("line {i:03}\n"))
            .collect::<String>();
        let result = CallToolResult::text(big_text);
        let decision = hook
            .post_tool_use("echo", &serde_json::json!({}), &result, &test_ctx())
            .await;
        match decision {
            HookDecision::ModifyResult(r) => {
                let all_text: String = r
                    .content
                    .iter()
                    .filter_map(|c| match c {
                        Content::Text(t) => Some(t.text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("");
                assert!(all_text.contains("[... truncated"));
            }
            other => panic!("Expected ModifyResult, got {other:?}"),
        }
    }
}
