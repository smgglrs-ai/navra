//! Token budget allocator for context management.
//!
//! Allocates a fixed token budget across priority-ordered slots:
//! 1. System prompt (fixed, never truncated)
//! 2. Conversation history (reserved, compacted when over budget)
//! 3. Retrieved context (fills remaining space, truncated first)
//!
//! Token estimation uses a character-based approximation (4 chars/token
//! for English text). This is deliberately simple — exact tokenization
//! would require a model-specific tokenizer dependency.

/// Approximate tokens from character count.
/// English averages ~4 chars/token for most LLM tokenizers.
/// Conservative: slightly overestimates to avoid overflow.
pub fn estimate_tokens(text: &str) -> u32 {
    (text.len() as f64 / 3.5).ceil() as u32
}

/// Token budget with priority-ordered slots.
#[derive(Debug, Clone)]
pub struct ContextBudget {
    /// Total token limit for the context window.
    pub total: u32,
    /// Tokens consumed by the system prompt (fixed, not truncatable).
    pub system_prompt_tokens: u32,
    /// Tokens reserved for model output.
    pub output_reserve: u32,
}

impl ContextBudget {
    /// Create a budget for a given context window size.
    ///
    /// Reserves 20% for output by default.
    pub fn new(total_tokens: u32) -> Self {
        Self {
            total: total_tokens,
            system_prompt_tokens: 0,
            output_reserve: total_tokens / 5,
        }
    }

    /// Set the system prompt and lock its token count.
    pub fn set_system_prompt(&mut self, system_prompt: &str) {
        self.system_prompt_tokens = estimate_tokens(system_prompt);
    }

    /// Tokens available for conversation history + retrieved context.
    pub fn available(&self) -> u32 {
        self.total
            .saturating_sub(self.system_prompt_tokens)
            .saturating_sub(self.output_reserve)
    }

    /// Split available tokens between history and context.
    ///
    /// History gets 60% of remaining, context gets 40%.
    /// This reflects that conversation continuity matters more
    /// than retrieved documents for most agentic tasks.
    pub fn split(&self) -> (u32, u32) {
        let avail = self.available();
        let history = (avail as f64 * 0.6) as u32;
        let context = avail - history;
        (history, context)
    }

    /// Check if we're over the compaction threshold (80% of total).
    pub fn needs_compaction(&self, current_tokens: u32) -> bool {
        let threshold = (self.total as f64 * 0.8) as u32;
        current_tokens > threshold
    }
}

/// Truncate text to fit within a token budget.
///
/// Truncates at sentence boundaries when possible. Appends
/// "[truncated — N more chars]" when content is cut.
pub fn truncate_to_budget(text: &str, max_tokens: u32) -> String {
    let current = estimate_tokens(text);
    if current <= max_tokens {
        return text.to_string();
    }

    // Target character count from token budget
    let target_chars = (max_tokens as f64 * 3.5) as usize;
    if target_chars < 50 {
        return String::new();
    }

    // Reserve space for the truncation notice
    let notice_reserve = 40;
    let cut_at = target_chars.saturating_sub(notice_reserve);

    // Try to cut at a sentence boundary
    let slice = &text[..cut_at.min(text.len())];
    let cut_point = slice
        .rfind(". ")
        .or_else(|| slice.rfind(".\n"))
        .or_else(|| slice.rfind('\n'))
        .map(|p| p + 1)
        .unwrap_or(cut_at);

    let truncated = &text[..cut_point];
    let remaining = text.len() - cut_point;
    format!("{truncated}\n[truncated — {remaining} more chars]")
}

/// Compact conversation history by summarizing old turns.
///
/// Keeps the most recent `keep_recent` turns verbatim and replaces
/// older turns with a brief summary line per turn.
pub fn compact_history(turns: &[String], keep_recent: usize) -> Vec<String> {
    if turns.len() <= keep_recent {
        return turns.to_vec();
    }

    let split = turns.len() - keep_recent;
    let mut compacted = Vec::with_capacity(keep_recent + 1);

    // Summarize old turns as a single block
    let mut summary_parts = Vec::new();
    for (i, turn) in turns[..split].iter().enumerate() {
        // Extract first line as summary
        let first_line = turn.lines().next().unwrap_or("(empty)");
        let trimmed = if first_line.len() > 100 {
            format!("{}...", &first_line[..97])
        } else {
            first_line.to_string()
        };
        summary_parts.push(format!("  {}: {}", i + 1, trimmed));
    }

    compacted.push(format!(
        "[Prior conversation summary ({} turns)]\n{}",
        split,
        summary_parts.join("\n")
    ));

    // Keep recent turns verbatim
    compacted.extend_from_slice(&turns[split..]);
    compacted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_tokens_basic() {
        // "hello world" = 11 chars → ~3 tokens
        let t = estimate_tokens("hello world");
        assert!(t >= 3 && t <= 5);
    }

    #[test]
    fn estimate_tokens_empty() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn budget_available() {
        let mut budget = ContextBudget::new(4096);
        budget.set_system_prompt(&"x".repeat(1400)); // ~400 tokens
        // 4096 - 400 - 819(20%) ≈ 2877
        let avail = budget.available();
        assert!(avail > 2500 && avail < 3200, "available={avail}");
    }

    #[test]
    fn budget_split() {
        let mut budget = ContextBudget::new(10000);
        budget.system_prompt_tokens = 2000;
        budget.output_reserve = 2000;
        // available = 6000, history = 3600, context = 2400
        let (history, context) = budget.split();
        assert_eq!(history, 3600);
        assert_eq!(context, 2400);
    }

    #[test]
    fn truncate_within_budget() {
        let text = "Short text.";
        assert_eq!(truncate_to_budget(text, 100), text);
    }

    #[test]
    fn truncate_over_budget() {
        let text = "First sentence. Second sentence. Third sentence. Fourth sentence. Fifth sentence. Sixth sentence. Seventh sentence.";
        let result = truncate_to_budget(text, 20); // ~70 chars budget
        assert!(result.contains("truncated"), "result: {result}");
        assert!(result.len() < text.len());
    }

    #[test]
    fn compact_keeps_recent() {
        let turns: Vec<String> = (0..10)
            .map(|i| format!("Turn {i}: Some content here"))
            .collect();
        let compacted = compact_history(&turns, 3);
        // 1 summary block + 3 recent = 4
        assert_eq!(compacted.len(), 4);
        assert!(compacted[0].contains("Prior conversation summary (7 turns)"));
        assert!(compacted[3].contains("Turn 9"));
    }

    #[test]
    fn compact_few_turns_unchanged() {
        let turns = vec!["a".to_string(), "b".to_string()];
        let compacted = compact_history(&turns, 5);
        assert_eq!(compacted, turns);
    }

    #[test]
    fn needs_compaction_threshold() {
        let budget = ContextBudget::new(10000);
        assert!(!budget.needs_compaction(7000));
        assert!(budget.needs_compaction(8500));
    }
}
