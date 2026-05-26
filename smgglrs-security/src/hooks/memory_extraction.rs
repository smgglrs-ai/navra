//! Memory extraction hook: observes tool call results and stores
//! knowledge automatically.
//!
//! This is an observation-only post-hook — it never modifies results.
//! For each successful tool call whose output exceeds a minimum length
//! and is not in the exclusion list, the hook extracts text content
//! and stores it via a pluggable storage backend.

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use smgglrs_protocol::{CallToolResult, Content};
use std::sync::Arc;

/// Trait for the storage backend used by `MemoryExtractionHook`.
///
/// Defined here (in smgglrs-security) to avoid a circular dependency
/// on smgglrs-memory. The server wires the concrete implementation.
pub trait ExtractionStore: Send + Sync + 'static {
    /// Store extracted knowledge from a tool call.
    ///
    /// - `title`: short identifier, e.g. `"[file_read] /etc/hosts"`
    /// - `content`: the extracted text
    /// - `session_id`: session scope for the entry
    /// - `tags`: metadata tags (tool name, etc.)
    fn store_extraction(&self, title: &str, content: &str, session_id: &str, tags: &[String]);
}

/// Configuration for the memory extraction hook.
#[derive(Debug, Clone)]
pub struct MemoryExtractionConfig {
    pub enabled: bool,
    pub min_content_length: usize,
    pub max_content_length: usize,
    pub exclude_tools: Vec<String>,
}

impl Default for MemoryExtractionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_content_length: 100,
            max_content_length: 10_000,
            exclude_tools: vec!["smgglrs_var_*".to_string(), "memory_*".to_string()],
        }
    }
}

/// A post-hook that extracts knowledge from tool call results.
///
/// Observes every tool call result and stores non-trivial text
/// content in the knowledge store for later retrieval. This hook
/// never modifies results — it always returns `HookDecision::Continue`.
pub struct MemoryExtractionHook {
    store: Arc<dyn ExtractionStore>,
    min_content_length: usize,
    max_content_length: usize,
    exclude_tools: Vec<String>,
}

impl MemoryExtractionHook {
    /// Create a new memory extraction hook.
    pub fn new(store: Arc<dyn ExtractionStore>, config: MemoryExtractionConfig) -> Self {
        Self {
            store,
            min_content_length: config.min_content_length,
            max_content_length: config.max_content_length,
            exclude_tools: config.exclude_tools,
        }
    }

    /// Check whether a tool is excluded by glob pattern.
    fn is_excluded(&self, tool_name: &str) -> bool {
        for pattern in &self.exclude_tools {
            if glob_match(pattern, tool_name) {
                return true;
            }
        }
        false
    }

    /// Decide whether to extract from this tool call result.
    fn should_extract(&self, tool_name: &str, result: &CallToolResult) -> bool {
        if result.is_error {
            return false;
        }
        if self.is_excluded(tool_name) {
            return false;
        }
        let text_len = extract_text_length(result);
        text_len >= self.min_content_length
    }

    /// Extract text content and store it.
    fn extract_and_store(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        result: &CallToolResult,
        ctx: &CallContext,
    ) {
        let content = extract_text_content(result, self.max_content_length);
        if content.is_empty() {
            return;
        }

        // Build a short title with tool name and key argument
        let context_hint = extract_context_hint(tool_name, arguments);
        let title = if context_hint.is_empty() {
            format!("[{tool_name}]")
        } else {
            format!("[{tool_name}] {context_hint}")
        };

        let tags = vec![
            format!("tool:{tool_name}"),
            format!("agent:{}", ctx.agent.name),
            "auto-extracted".to_string(),
        ];

        self.store
            .store_extraction(&title, &content, &ctx.session_id, &tags);
    }
}

#[async_trait::async_trait]
impl Hook for MemoryExtractionHook {
    fn name(&self) -> &str {
        "memory-extraction"
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        result: &CallToolResult,
        ctx: &CallContext,
    ) -> HookDecision {
        if self.should_extract(tool_name, result) {
            self.extract_and_store(tool_name, arguments, result, ctx);
        }
        HookDecision::Continue
    }
}

// --- Helpers ---

/// Extract total text length from a tool result.
fn extract_text_length(result: &CallToolResult) -> usize {
    result
        .content
        .iter()
        .filter_map(|c| match c {
            Content::Text(t) => Some(t.text.len()),
            _ => None,
        })
        .sum()
}

/// Extract concatenated text content, truncated to max_len.
fn extract_text_content(result: &CallToolResult, max_len: usize) -> String {
    let mut buf = String::new();
    for content in &result.content {
        if let Content::Text(t) = content {
            if buf.len() + t.text.len() > max_len {
                let remaining = max_len.saturating_sub(buf.len());
                if remaining > 0 {
                    // Truncate at a char boundary
                    let slice = &t.text[..t.text.floor_char_boundary(remaining)];
                    buf.push_str(slice);
                    buf.push_str("...[truncated]");
                }
                break;
            }
            if !buf.is_empty() {
                buf.push('\n');
            }
            buf.push_str(&t.text);
        }
    }
    buf
}

/// Extract a short context hint from tool arguments (e.g., path, query).
fn extract_context_hint(tool_name: &str, arguments: &serde_json::Value) -> String {
    // Try common argument names in priority order
    let hint_keys = match tool_name {
        name if name.starts_with("file_") => &["path"][..],
        name if name.starts_with("git_") => &["ref", "path", "message"][..],
        _ => &["path", "query", "pattern", "command"][..],
    };

    for key in hint_keys {
        if let Some(val) = arguments.get(key).and_then(|v| v.as_str()) {
            // Truncate long values
            if val.len() > 80 {
                return format!("{}...", &val[..val.floor_char_boundary(77)]);
            }
            return val.to_string();
        }
    }
    String::new()
}

/// Simple glob matching supporting only `*` wildcards.
///
/// Patterns like `"memory_*"` match any tool starting with `"memory_"`.
/// A bare `*` matches everything.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AgentIdentity;
    use std::sync::Mutex;

    /// A test store that records extractions.
    struct TestStore {
        entries: Mutex<Vec<(String, String, String, Vec<String>)>>,
    }

    impl TestStore {
        fn new() -> Self {
            Self {
                entries: Mutex::new(Vec::new()),
            }
        }

        fn entries(&self) -> Vec<(String, String, String, Vec<String>)> {
            self.entries.lock().unwrap().clone()
        }
    }

    impl ExtractionStore for TestStore {
        fn store_extraction(&self, title: &str, content: &str, session_id: &str, tags: &[String]) {
            self.entries.lock().unwrap().push((
                title.to_string(),
                content.to_string(),
                session_id.to_string(),
                tags.to_vec(),
            ));
        }
    }

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), "test-session")
    }

    fn make_hook(store: Arc<TestStore>) -> MemoryExtractionHook {
        MemoryExtractionHook::new(store, MemoryExtractionConfig::default())
    }

    #[tokio::test]
    async fn extracts_from_long_tool_result() {
        let store = Arc::new(TestStore::new());
        let hook = make_hook(Arc::clone(&store));

        let content = "x".repeat(200);
        let result = CallToolResult::text(content.clone());
        let args = serde_json::json!({"path": "/etc/hosts"});

        let decision = hook
            .post_tool_use("file_read", &args, &result, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
        let entries = store.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "[file_read] /etc/hosts");
        assert_eq!(entries[0].1, content);
        assert_eq!(entries[0].2, "test-session");
        assert!(entries[0].3.contains(&"tool:file_read".to_string()));
        assert!(entries[0].3.contains(&"auto-extracted".to_string()));
    }

    #[tokio::test]
    async fn skips_error_results() {
        let store = Arc::new(TestStore::new());
        let hook = make_hook(Arc::clone(&store));

        let result = CallToolResult::error("something went wrong".repeat(20));

        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
        assert!(store.entries().is_empty());
    }

    #[tokio::test]
    async fn skips_short_content() {
        let store = Arc::new(TestStore::new());
        let hook = make_hook(Arc::clone(&store));

        let result = CallToolResult::text("short");

        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
        assert!(store.entries().is_empty());
    }

    #[tokio::test]
    async fn skips_excluded_tools_prefix() {
        let store = Arc::new(TestStore::new());
        let hook = make_hook(Arc::clone(&store));

        let content = "x".repeat(200);
        let result = CallToolResult::text(content);

        let decision = hook
            .post_tool_use("memory_store", &serde_json::json!({}), &result, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
        assert!(store.entries().is_empty());
    }

    #[tokio::test]
    async fn skips_excluded_tools_smgglrs_var() {
        let store = Arc::new(TestStore::new());
        let hook = make_hook(Arc::clone(&store));

        let content = "x".repeat(200);
        let result = CallToolResult::text(content);

        let decision = hook
            .post_tool_use(
                "smgglrs_var_get",
                &serde_json::json!({}),
                &result,
                &test_ctx(),
            )
            .await;

        assert!(matches!(decision, HookDecision::Continue));
        assert!(store.entries().is_empty());
    }

    #[tokio::test]
    async fn always_returns_continue() {
        let store = Arc::new(TestStore::new());
        let hook = make_hook(Arc::clone(&store));

        // Test with various scenarios — all must return Continue
        let scenarios: Vec<(&str, CallToolResult)> = vec![
            ("file_read", CallToolResult::text("x".repeat(200))),
            ("file_read", CallToolResult::error("error")),
            ("file_read", CallToolResult::text("short")),
            ("memory_store", CallToolResult::text("x".repeat(200))),
        ];

        for (tool, result) in scenarios {
            let decision = hook
                .post_tool_use(tool, &serde_json::json!({}), &result, &test_ctx())
                .await;
            assert!(
                matches!(decision, HookDecision::Continue),
                "Expected Continue for tool={tool}, is_error={}",
                result.is_error,
            );
        }
    }

    #[test]
    fn glob_match_prefix() {
        assert!(glob_match("memory_*", "memory_store"));
        assert!(glob_match("memory_*", "memory_query"));
        assert!(!glob_match("memory_*", "file_read"));
    }

    #[test]
    fn glob_match_suffix() {
        assert!(glob_match("*_read", "file_read"));
        assert!(!glob_match("*_read", "file_write"));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("file_read", "file_read"));
        assert!(!glob_match("file_read", "file_write"));
    }

    #[test]
    fn glob_match_star_matches_all() {
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn truncates_long_content() {
        let long_text = "a".repeat(20_000);
        let result = CallToolResult::text(long_text);
        let extracted = extract_text_content(&result, 10_000);
        assert!(extracted.len() <= 10_020); // max_len + "[truncated]" tag
        assert!(extracted.ends_with("...[truncated]"));
    }

    #[test]
    fn extract_context_hint_path() {
        let args = serde_json::json!({"path": "/home/user/file.rs"});
        assert_eq!(
            extract_context_hint("file_read", &args),
            "/home/user/file.rs"
        );
    }

    #[test]
    fn extract_context_hint_query() {
        let args = serde_json::json!({"query": "search term"});
        assert_eq!(extract_context_hint("rag_search", &args), "search term");
    }

    #[test]
    fn extract_context_hint_none() {
        let args = serde_json::json!({"foo": "bar"});
        assert_eq!(extract_context_hint("custom_tool", &args), "");
    }

    #[tokio::test]
    async fn stores_git_log_results() {
        let store = Arc::new(TestStore::new());
        let hook = make_hook(Arc::clone(&store));

        let content =
            "commit abc123\nAuthor: Test\nDate: 2026-01-01\n\n    Initial commit\n".repeat(5);
        let result = CallToolResult::text(content);
        let args = serde_json::json!({"ref": "main"});

        let decision = hook
            .post_tool_use("git_log", &args, &result, &test_ctx())
            .await;

        assert!(matches!(decision, HookDecision::Continue));
        let entries = store.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "[git_log] main");
    }

    #[tokio::test]
    async fn tags_include_agent_name() {
        let store = Arc::new(TestStore::new());
        let hook = make_hook(Arc::clone(&store));

        let result = CallToolResult::text("x".repeat(200));

        hook.post_tool_use("file_read", &serde_json::json!({}), &result, &test_ctx())
            .await;

        let entries = store.entries();
        assert!(entries[0].3.contains(&"agent:tester".to_string()));
    }
}
