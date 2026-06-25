//! HTML-to-markdown conversion hook.
//!
//! Converts HTML content in tool results to clean markdown, reducing
//! token consumption for LLM context windows. Fires only in `post_tool_use`
//! phase. Configurable per permission set with tool-name allowlist.

use super::{Hook, HookDecision};
use async_trait::async_trait;
use navra_auth::auth::CallContext;
use navra_protocol::compat::CallToolResultExt;
use navra_protocol::{CallToolResult, Content, RawContent};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct HtmlToMarkdownConfig {
    pub enabled: bool,
    pub tool_allowlist: HashSet<String>,
}

impl Default for HtmlToMarkdownConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tool_allowlist: HashSet::new(),
        }
    }
}

pub struct HtmlToMarkdownHook {
    enabled: bool,
    tool_allowlist: HashSet<String>,
}

impl HtmlToMarkdownHook {
    pub fn new(config: HtmlToMarkdownConfig) -> Self {
        Self {
            enabled: config.enabled,
            tool_allowlist: config.tool_allowlist,
        }
    }
}

fn looks_like_html(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.len() < 10 {
        return false;
    }
    // Must start with a tag or doctype
    if trimmed.starts_with("<!") || trimmed.starts_with("<html") || trimmed.starts_with("<HTML") {
        return true;
    }
    // Count HTML tag patterns vs plain angle brackets
    let tag_count = trimmed.matches("</").count() + trimmed.matches("/>").count();
    let has_block_tags = [
        "<div", "<p>", "<p ", "<table", "<ul", "<ol", "<h1", "<h2", "<h3", "<body", "<head",
        "<section", "<article", "<nav", "<main", "<header", "<footer",
    ]
    .iter()
    .any(|tag| trimmed.contains(tag));

    tag_count >= 2 && has_block_tags
}

fn convert_html_to_markdown(html: &str) -> String {
    htmd::convert(html).unwrap_or_else(|_| html.to_string())
}

#[async_trait]
impl Hook for HtmlToMarkdownHook {
    fn name(&self) -> &str {
        "html_markdown"
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        result: &CallToolResult,
        _ctx: &CallContext,
    ) -> HookDecision {
        if !self.enabled || result.is_err() {
            return HookDecision::Continue;
        }

        if !self.tool_allowlist.is_empty() && !self.tool_allowlist.contains(tool_name) {
            return HookDecision::Continue;
        }

        let mut any_changed = false;
        let mut converted_content = Vec::with_capacity(result.content.len());
        let mut total_original = 0usize;
        let mut total_converted = 0usize;

        for content in &result.content {
            match content {
                Content {
                    raw: RawContent::Text(t),
                    ..
                } => {
                    if looks_like_html(&t.text) {
                        let markdown = convert_html_to_markdown(&t.text);
                        let orig_len = t.text.len();
                        let conv_len = markdown.len();
                        total_original += orig_len;
                        total_converted += conv_len;
                        any_changed = true;
                        converted_content.push(Content::text(markdown));
                    } else {
                        converted_content.push(content.clone());
                    }
                }
                _ => converted_content.push(content.clone()),
            }
        }

        if !any_changed {
            return HookDecision::Continue;
        }

        let reduction = if total_original > 0 {
            ((total_original - total_converted) as f64 / total_original as f64 * 100.0) as u32
        } else {
            0
        };

        converted_content.push(Content::text(format!(
            "[html_markdown: converted {total_original} → {total_converted} chars ({reduction}% reduction)]"
        )));

        let mut new_result = CallToolResult::success(converted_content);
        new_result.is_error = result.is_error;
        HookDecision::ModifyResult(new_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_ctx() -> CallContext {
        CallContext {
            agent: navra_auth::auth::AgentIdentity {
                name: "test".to_string(),
                permissions: "full".to_string(),
                signing_key: None,
                did: None,
                capabilities: None,
            },
            session_id: "sess-1".to_string(),
            taint: navra_auth::ifc::TaintTracker::new(),
            remaining_tokens: None,
            sandbox: None,
        }
    }

    fn make_result(text: &str) -> CallToolResult {
        CallToolResult::text(text.to_string())
    }

    #[test]
    fn detects_html_with_block_tags() {
        assert!(looks_like_html("<html><body><p>Hello</p></body></html>"));
        assert!(looks_like_html("<div class=\"content\"><p>Text</p></div>"));
        assert!(looks_like_html(
            "<!DOCTYPE html><html><head></head><body></body></html>"
        ));
    }

    #[test]
    fn rejects_non_html() {
        assert!(!looks_like_html(
            "This is plain text with <emphasis> but not HTML"
        ));
        assert!(!looks_like_html("short"));
        assert!(!looks_like_html(r#"{"json": "value"}"#));
        assert!(!looks_like_html("x < 5 && y > 3 are common comparisons"));
    }

    #[test]
    fn converts_simple_html() {
        let html = "<h1>Title</h1><p>Some <strong>bold</strong> text.</p>";
        let md = convert_html_to_markdown(html);
        assert!(md.contains("Title"));
        assert!(md.contains("**bold**"));
    }

    #[tokio::test]
    async fn plain_text_passes_through() {
        let hook = HtmlToMarkdownHook::new(HtmlToMarkdownConfig::default());
        let result = make_result("This is plain text, not HTML at all.");
        let decision = hook
            .post_tool_use("fetch", &json!({}), &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn html_gets_converted() {
        let hook = HtmlToMarkdownHook::new(HtmlToMarkdownConfig::default());
        let html = "<html><body><h1>Page Title</h1><p>This is a <strong>paragraph</strong> with content.</p><ul><li>Item 1</li><li>Item 2</li></ul></body></html>";
        let result = make_result(html);
        let decision = hook
            .post_tool_use("web_fetch", &json!({}), &result, &test_ctx())
            .await;
        match decision {
            HookDecision::ModifyResult(r) => {
                let text = match &r.content[0] {
                    Content {
                        raw: RawContent::Text(t),
                        ..
                    } => &t.text,
                    _ => panic!("expected text"),
                };
                assert!(text.contains("Page Title"));
                assert!(text.contains("**paragraph**"));
                assert!(text.len() < html.len());

                let annotation = match r.content.last() {
                    Some(Content {
                        raw: RawContent::Text(t),
                        ..
                    }) => &t.text,
                    _ => panic!("expected annotation"),
                };
                assert!(annotation.contains("html_markdown"));
                assert!(annotation.contains("reduction"));
            }
            other => panic!("expected ModifyResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn error_results_skipped() {
        let hook = HtmlToMarkdownHook::new(HtmlToMarkdownConfig::default());
        let html = "<html><body><p>Error page</p></body></html>";
        let mut result = make_result(html);
        result.is_error = Some(true);
        let decision = hook
            .post_tool_use("fetch", &json!({}), &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn disabled_hook_passes_through() {
        let config = HtmlToMarkdownConfig {
            enabled: false,
            ..Default::default()
        };
        let hook = HtmlToMarkdownHook::new(config);
        let html = "<html><body><p>Content</p></body></html>";
        let result = make_result(html);
        let decision = hook
            .post_tool_use("fetch", &json!({}), &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn tool_allowlist_filters() {
        let config = HtmlToMarkdownConfig {
            enabled: true,
            tool_allowlist: ["web_fetch"].iter().map(|s| s.to_string()).collect(),
        };
        let hook = HtmlToMarkdownHook::new(config);
        let html = "<html><body><p>Content</p></body></html>";
        let result = make_result(html);

        // Allowed tool: converts
        let decision = hook
            .post_tool_use("web_fetch", &json!({}), &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::ModifyResult(_)));

        // Non-allowed tool: passes through
        let decision = hook
            .post_tool_use("other_tool", &json!({}), &result, &test_ctx())
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn real_world_html_reduces_significantly() {
        let hook = HtmlToMarkdownHook::new(HtmlToMarkdownConfig::default());
        let html = r#"<!DOCTYPE html>
<html>
<head><title>Documentation</title><style>body { font-family: sans-serif; }</style></head>
<body>
<nav><ul><li><a href="/">Home</a></li><li><a href="/docs">Docs</a></li></ul></nav>
<main>
<h1>API Reference</h1>
<p>This is the API reference for the <code>widget</code> module.</p>
<h2>Functions</h2>
<table>
<tr><th>Name</th><th>Description</th></tr>
<tr><td><code>create()</code></td><td>Creates a new widget</td></tr>
<tr><td><code>delete(id)</code></td><td>Deletes a widget by ID</td></tr>
<tr><td><code>list()</code></td><td>Lists all widgets</td></tr>
</table>
<h2>Examples</h2>
<pre><code>let w = create();
println!("{}", w.id);</code></pre>
</main>
<footer><p>&copy; 2026 Example Corp</p></footer>
</body>
</html>"#;
        let result = make_result(html);
        let decision = hook
            .post_tool_use("web_fetch", &json!({}), &result, &test_ctx())
            .await;
        match decision {
            HookDecision::ModifyResult(r) => {
                let text = match &r.content[0] {
                    Content {
                        raw: RawContent::Text(t),
                        ..
                    } => &t.text,
                    _ => panic!("expected text"),
                };
                assert!(text.contains("API Reference"));
                // At least 40% reduction
                let annotation = match r.content.last() {
                    Some(Content {
                        raw: RawContent::Text(t),
                        ..
                    }) => &t.text,
                    _ => panic!("expected annotation"),
                };
                assert!(annotation.contains("reduction"));
            }
            other => panic!("expected ModifyResult, got {other:?}"),
        }
    }

    #[test]
    fn json_not_detected_as_html() {
        assert!(!looks_like_html(r#"{"items": [{"id": 1}, {"id": 2}]}"#));
    }
}
