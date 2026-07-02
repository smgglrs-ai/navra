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

use vstd::prelude::*;

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

/// Strategy for compacting conversation history when over budget.
///
/// Different models respond best to different compaction strategies.
/// Small-context models need aggressive pruning, while large-context
/// models can afford to keep more turns verbatim.
#[derive(Debug, Clone, PartialEq)]
pub enum CompactionStrategy {
    /// Keep last N turns verbatim, drop the rest entirely.
    KeepLastN(usize),
    /// Replace old turns with a one-line summary each (via `compact_history`).
    Summary,
    /// Drop all old turns, keep only the latest.
    DiscardAll,
}

/// Apply a compaction strategy to conversation turns.
///
/// `keep_recent` controls how many of the most recent turns are always
/// preserved verbatim (in addition to any strategy-specific behavior).
pub fn apply_compaction(
    turns: &[String],
    strategy: &CompactionStrategy,
    keep_recent: usize,
) -> Vec<String> {
    if turns.is_empty() {
        return Vec::new();
    }

    match strategy {
        CompactionStrategy::KeepLastN(n) => {
            let keep = (*n).min(turns.len());
            turns[turns.len() - keep..].to_vec()
        }
        CompactionStrategy::Summary => compact_history(turns, keep_recent),
        CompactionStrategy::DiscardAll => {
            vec![turns[turns.len() - 1].clone()]
        }
    }
}

/// Return a recommended compaction strategy based on model family.
///
/// Model families with smaller context windows get more aggressive
/// strategies. Models known for good summarization use the Summary
/// strategy. Large-context models keep more history.
pub fn recommended_strategy(model_family: &str) -> CompactionStrategy {
    match model_family.to_lowercase().as_str() {
        "granite" | "qwen" => CompactionStrategy::KeepLastN(5),
        "gemma" => CompactionStrategy::Summary,
        "claude" | "gpt" => CompactionStrategy::KeepLastN(10),
        _ => CompactionStrategy::Summary,
    }
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

    #[test]
    fn keep_last_n_drops_old_turns() {
        let turns: Vec<String> = (0..10).map(|i| format!("Turn {i}: content")).collect();
        let result = apply_compaction(&turns, &CompactionStrategy::KeepLastN(3), 3);
        assert_eq!(result.len(), 3);
        assert!(result[0].contains("Turn 7"));
        assert!(result[2].contains("Turn 9"));
    }

    #[test]
    fn keep_last_n_more_than_available() {
        let turns = vec!["a".to_string(), "b".to_string()];
        let result = apply_compaction(&turns, &CompactionStrategy::KeepLastN(5), 2);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn summary_uses_compact_history() {
        let turns: Vec<String> = (0..8)
            .map(|i| format!("Turn {i}: some content here"))
            .collect();
        let result = apply_compaction(&turns, &CompactionStrategy::Summary, 3);
        // compact_history produces 1 summary block + 3 recent = 4
        assert_eq!(result.len(), 4);
        assert!(result[0].contains("Prior conversation summary"));
        assert!(result[3].contains("Turn 7"));
    }

    #[test]
    fn discard_all_keeps_only_last() {
        let turns: Vec<String> = (0..10).map(|i| format!("Turn {i}: content")).collect();
        let result = apply_compaction(&turns, &CompactionStrategy::DiscardAll, 3);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("Turn 9"));
    }

    #[test]
    fn apply_compaction_empty_turns() {
        let result = apply_compaction(&[], &CompactionStrategy::Summary, 3);
        assert!(result.is_empty());
    }

    #[test]
    fn recommended_strategy_granite() {
        assert_eq!(
            recommended_strategy("granite"),
            CompactionStrategy::KeepLastN(5)
        );
    }

    #[test]
    fn recommended_strategy_qwen() {
        assert_eq!(
            recommended_strategy("qwen"),
            CompactionStrategy::KeepLastN(5)
        );
    }

    #[test]
    fn recommended_strategy_gemma() {
        assert_eq!(recommended_strategy("gemma"), CompactionStrategy::Summary);
    }

    #[test]
    fn recommended_strategy_claude() {
        assert_eq!(
            recommended_strategy("claude"),
            CompactionStrategy::KeepLastN(10)
        );
    }

    #[test]
    fn recommended_strategy_gpt() {
        assert_eq!(
            recommended_strategy("gpt"),
            CompactionStrategy::KeepLastN(10)
        );
    }

    #[test]
    fn recommended_strategy_unknown_defaults_to_summary() {
        assert_eq!(
            recommended_strategy("some-unknown-model"),
            CompactionStrategy::Summary
        );
    }

    #[test]
    fn recommended_strategy_case_insensitive() {
        assert_eq!(
            recommended_strategy("GRANITE"),
            CompactionStrategy::KeepLastN(5)
        );
        assert_eq!(
            recommended_strategy("Claude"),
            CompactionStrategy::KeepLastN(10)
        );
    }
}

verus! {

// available() = total.saturating_sub(sys).saturating_sub(reserve)
spec fn spec_available(total: nat, sys: nat, reserve: nat) -> nat {
    let after_sys: nat = if total > sys { (total - sys) as nat } else { 0 };
    if after_sys > reserve { (after_sys - reserve) as nat } else { 0 }
}

proof fn available_never_underflows(total: nat, sys: nat, reserve: nat)
    ensures spec_available(total, sys, reserve) <= total,
{}

// output_reserve = total / 5
proof fn default_budget_reserve_positive(total: nat)
    requires total >= 5,
    ensures total / 5 > 0 && total / 5 <= total,
{}

} // verus!

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn budget_split_sums_to_available() {
        let total: u32 = kani::any();
        let sys: u32 = kani::any();
        let reserve: u32 = kani::any();
        kani::assume(total <= 200_000);
        kani::assume(sys <= total);
        kani::assume(reserve <= total);
        let budget = ContextBudget {
            total,
            system_prompt_tokens: sys,
            output_reserve: reserve,
        };
        let avail = budget.available();
        let (history, context) = budget.split();
        assert_eq!(history + context, avail);
    }

    #[kani::proof]
    fn estimate_tokens_monotonic() {
        let len1: u8 = kani::any();
        let len2: u8 = kani::any();
        kani::assume(len2 >= len1);
        let s1 = "x".repeat(len1 as usize);
        let s2 = "x".repeat(len2 as usize);
        assert!(estimate_tokens(&s2) >= estimate_tokens(&s1));
    }

    #[kani::proof]
    fn default_budget_reserve_positive() {
        let total: u32 = kani::any();
        kani::assume(total >= 5 && total <= 200_000);
        let budget = ContextBudget::new(total);
        assert!(budget.output_reserve > 0);
        assert!(budget.output_reserve <= total);
    }

    #[kani::proof]
    fn available_never_underflows() {
        let total: u32 = kani::any();
        let sys: u32 = kani::any();
        let reserve: u32 = kani::any();
        kani::assume(total <= 200_000);
        kani::assume(sys <= 200_000);
        kani::assume(reserve <= 200_000);
        let budget = ContextBudget {
            total,
            system_prompt_tokens: sys,
            output_reserve: reserve,
        };
        // saturating_sub guarantees no underflow
        let avail = budget.available();
        assert!(avail <= total);
    }

    #[kani::proof]
    fn split_monotonic_in_available() {
        let avail1: u16 = kani::any();
        let avail2: u16 = kani::any();
        kani::assume(avail2 >= avail1);
        let h1 = (avail1 as f64 * 0.6) as u32;
        let h2 = (avail2 as f64 * 0.6) as u32;
        assert!(h2 >= h1);
    }
}
