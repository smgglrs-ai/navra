//! Hermes-format trace export for agent conversations.
//!
//! Converts tool loop results and conversation context into the
//! Hermes agent reasoning trace format, compatible with
//! `lambda/hermes-agent-reasoning-traces`.
//!
//! Each JSONL line is a JSON object with a `conversations` array
//! containing messages in system/user/assistant/tool roles. Assistant
//! messages may contain `<think>...</think>` and
//! `<tool_call>...</tool_call>` blocks. Tool messages contain
//! `<tool_response>...</tool_response>` blocks.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::block::ToolBlock;

/// Synchronous content sanitizer for PII removal.
///
/// Same type as `navra_memory::pipeline::ContentSanitizer` — a
/// closure that accepts content and returns sanitized content.
pub type ContentSanitizer = std::sync::Arc<dyn Fn(&str) -> String + Send + Sync>;

/// A single message in Hermes format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HermesMessage {
    /// Message role: system, user, assistant, or tool.
    pub role: String,
    /// Message content, potentially containing XML-style blocks.
    pub content: String,
}

/// A conversation trace in Hermes format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HermesTrace {
    /// Ordered list of messages in the conversation.
    pub conversations: Vec<HermesMessage>,
}

impl HermesTrace {
    /// Serialize this trace as a single JSONL line.
    ///
    /// Returns a JSON object on one line (no trailing newline).
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Metadata for a trace record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMetadata {
    /// Unique run identifier.
    pub run_id: String,
    /// Agent name (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    /// Safety profile name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_profile: Option<String>,
    /// Permission set name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_set: Option<String>,
    /// Model used for inference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    /// Number of tool-call iterations.
    pub iteration_count: usize,
    /// Total input tokens consumed.
    pub input_tokens: u32,
    /// Total output tokens consumed.
    pub output_tokens: u32,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Whether the run completed successfully.
    pub success: bool,
}

/// A complete trace record: Hermes messages plus run metadata.
///
/// Serialized as a single JSON object per line (JSONL) with
/// `metadata` and `messages` fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    /// Run metadata.
    pub metadata: TraceMetadata,
    /// Hermes-format conversation messages.
    pub messages: Vec<HermesMessage>,
}

impl TraceRecord {
    /// Serialize as a single JSONL line (no trailing newline).
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Apply a content sanitizer to all message text.
    pub fn sanitize(&mut self, sanitizer: &ContentSanitizer) {
        for msg in &mut self.messages {
            msg.content = sanitizer(&msg.content);
        }
    }

    /// Write this record to a JSONL file at `{dir}/{run_id}.jsonl`.
    ///
    /// Creates the directory if it does not exist.
    pub fn write_to_dir(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{}.jsonl", self.metadata.run_id));
        let line = self.to_jsonl();
        std::fs::write(&path, format!("{line}\n"))
    }
}

/// A tool call entry for building assistant messages.
#[derive(Debug, Clone)]
pub struct ToolCallEntry {
    /// Tool name.
    pub name: String,
    /// JSON-encoded arguments.
    pub arguments: String,
}

/// A tool response entry for building tool messages.
#[derive(Debug, Clone)]
pub struct ToolResponseEntry {
    /// JSON-encoded result.
    pub result: String,
}

/// Converts agent conversation context into a [`HermesTrace`] or [`TraceRecord`].
pub struct TraceExporter;

impl TraceExporter {
    /// Build a [`TraceRecord`] from tool loop results.
    ///
    /// Reconstructs Hermes-format messages from the tool blocks and
    /// final response, attaching run metadata.
    pub fn build_record(
        system_prompt: Option<&str>,
        user_prompt: &str,
        blocks: &[ToolBlock],
        final_response: &str,
        run_id: &str,
        iteration_count: usize,
        input_tokens: u32,
        output_tokens: u32,
        success: bool,
    ) -> TraceRecord {
        let tool_calls: Vec<ToolCallEntry> = blocks
            .iter()
            .map(|b| ToolCallEntry {
                name: b.tool_name.clone(),
                arguments: serde_json::to_string(&b.arguments).unwrap_or_default(),
            })
            .collect();
        let tool_responses: Vec<ToolResponseEntry> = blocks
            .iter()
            .map(|b| ToolResponseEntry {
                result: b.result_preview.clone().unwrap_or_default(),
            })
            .collect();

        let trace = Self::build(
            system_prompt,
            user_prompt,
            None,
            &tool_calls,
            &tool_responses,
            final_response,
        );

        TraceRecord {
            metadata: TraceMetadata {
                run_id: run_id.to_string(),
                agent_name: None,
                safety_profile: None,
                permission_set: None,
                model_name: None,
                iteration_count,
                input_tokens,
                output_tokens,
                timestamp: chrono::Utc::now().to_rfc3339(),
                success,
            },
            messages: trace.conversations,
        }
    }

    /// Build a Hermes trace from conversation parts.
    ///
    /// # Arguments
    ///
    /// * `system_prompt` - Optional system prompt
    /// * `user_prompt` - The user's input
    /// * `thinking` - Optional chain-of-thought reasoning
    /// * `tool_calls` - Tool calls made by the assistant
    /// * `tool_responses` - Responses from tool execution (parallel to tool_calls)
    /// * `final_response` - The assistant's final text response
    pub fn build(
        system_prompt: Option<&str>,
        user_prompt: &str,
        thinking: Option<&str>,
        tool_calls: &[ToolCallEntry],
        tool_responses: &[ToolResponseEntry],
        final_response: &str,
    ) -> HermesTrace {
        let mut messages = Vec::new();

        // System prompt
        if let Some(system) = system_prompt {
            messages.push(HermesMessage {
                role: "system".to_string(),
                content: system.to_string(),
            });
        }

        // User prompt
        messages.push(HermesMessage {
            role: "user".to_string(),
            content: user_prompt.to_string(),
        });

        // Assistant message with think + tool_call blocks
        if !tool_calls.is_empty() {
            let mut content = String::new();

            if let Some(think) = thinking {
                content.push_str("<think>");
                content.push_str(think);
                content.push_str("</think>\n");
            }

            for tc in tool_calls {
                let call_json = serde_json::json!({
                    "name": tc.name,
                    "arguments": serde_json::from_str::<serde_json::Value>(&tc.arguments)
                        .unwrap_or(serde_json::Value::String(tc.arguments.clone()))
                });
                content.push_str("<tool_call>");
                content.push_str(&serde_json::to_string(&call_json).unwrap_or_default());
                content.push_str("</tool_call>");
            }

            messages.push(HermesMessage {
                role: "assistant".to_string(),
                content,
            });

            // Tool response messages
            for tr in tool_responses {
                let mut response_content = String::from("<tool_response>");
                response_content.push_str(&tr.result);
                response_content.push_str("</tool_response>");
                messages.push(HermesMessage {
                    role: "tool".to_string(),
                    content: response_content,
                });
            }
        }

        // Final assistant response
        if !final_response.is_empty() {
            let content = if tool_calls.is_empty() {
                // No tool calls: thinking goes in the final message
                match thinking {
                    Some(think) => format!("<think>{think}</think>\n{final_response}"),
                    None => final_response.to_string(),
                }
            } else {
                final_response.to_string()
            };
            messages.push(HermesMessage {
                role: "assistant".to_string(),
                content,
            });
        }

        HermesTrace {
            conversations: messages,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_exporter_produces_valid_jsonl() {
        let trace = TraceExporter::build(
            Some("You are a helper."),
            "What is the git status?",
            Some("I should check git status."),
            &[ToolCallEntry {
                name: "git_status".to_string(),
                arguments: r#"{"repo": "."}"#.to_string(),
            }],
            &[ToolResponseEntry {
                result: r#"{"status": "clean"}"#.to_string(),
            }],
            "The repository is clean.",
        );

        let jsonl = trace.to_jsonl();

        // Should be valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&jsonl).expect("JSONL output should be valid JSON");

        // Should have conversations array
        let conversations = parsed["conversations"]
            .as_array()
            .expect("Should have conversations array");

        // system + user + assistant(tool_call) + tool + assistant(final) = 5
        assert_eq!(conversations.len(), 5);
        assert_eq!(conversations[0]["role"], "system");
        assert_eq!(conversations[1]["role"], "user");
        assert_eq!(conversations[2]["role"], "assistant");
        assert_eq!(conversations[3]["role"], "tool");
        assert_eq!(conversations[4]["role"], "assistant");
    }

    #[test]
    fn think_blocks_properly_formatted() {
        let trace = TraceExporter::build(
            None,
            "Hello",
            Some("Let me think about this."),
            &[ToolCallEntry {
                name: "file_read".to_string(),
                arguments: r#"{"path": "/foo"}"#.to_string(),
            }],
            &[ToolResponseEntry {
                result: "file contents".to_string(),
            }],
            "Done.",
        );

        let assistant_msg = &trace.conversations[1]; // user is [0], assistant is [1]
        assert_eq!(assistant_msg.role, "assistant");
        assert!(
            assistant_msg.content.starts_with("<think>"),
            "Assistant content should start with <think>: {}",
            assistant_msg.content
        );
        assert!(
            assistant_msg.content.contains("</think>"),
            "Assistant content should contain </think>"
        );
        assert!(
            assistant_msg.content.contains("Let me think about this."),
            "Think block should contain reasoning"
        );
    }

    #[test]
    fn tool_calls_use_correct_tag_format() {
        let trace = TraceExporter::build(
            None,
            "Read file",
            None,
            &[ToolCallEntry {
                name: "file_read".to_string(),
                arguments: r#"{"path": "/foo"}"#.to_string(),
            }],
            &[ToolResponseEntry {
                result: r#"{"content": "bar"}"#.to_string(),
            }],
            "Got it.",
        );

        // Assistant message with tool call
        let assistant_msg = &trace.conversations[1];
        assert!(
            assistant_msg.content.contains("<tool_call>"),
            "Should contain <tool_call> tag"
        );
        assert!(
            assistant_msg.content.contains("</tool_call>"),
            "Should contain </tool_call> tag"
        );
        assert!(
            assistant_msg.content.contains("\"name\":\"file_read\""),
            "Tool call should contain tool name"
        );

        // Tool response
        let tool_msg = &trace.conversations[2];
        assert_eq!(tool_msg.role, "tool");
        assert!(
            tool_msg.content.starts_with("<tool_response>"),
            "Tool content should start with <tool_response>"
        );
        assert!(
            tool_msg.content.ends_with("</tool_response>"),
            "Tool content should end with </tool_response>"
        );
    }

    #[test]
    fn empty_trace_produces_valid_output() {
        let trace = TraceExporter::build(None, "", None, &[], &[], "");

        let jsonl = trace.to_jsonl();

        // Should be valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&jsonl).expect("Empty trace JSONL should be valid JSON");

        let conversations = parsed["conversations"]
            .as_array()
            .expect("Should have conversations array");

        // Only the user message (empty but present)
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0]["role"], "user");
    }

    #[test]
    fn no_tool_calls_thinking_in_final_response() {
        let trace = TraceExporter::build(
            Some("System."),
            "Hello",
            Some("Reasoning here."),
            &[],
            &[],
            "Final answer.",
        );

        // system + user + assistant(final with think) = 3
        assert_eq!(trace.conversations.len(), 3);
        let final_msg = &trace.conversations[2];
        assert_eq!(final_msg.role, "assistant");
        assert!(
            final_msg.content.contains("<think>Reasoning here.</think>"),
            "Final message should contain think block when no tool calls: {}",
            final_msg.content
        );
        assert!(
            final_msg.content.contains("Final answer."),
            "Final message should contain the answer"
        );
    }

    #[test]
    fn multiple_tool_calls() {
        let trace = TraceExporter::build(
            None,
            "Do stuff",
            None,
            &[
                ToolCallEntry {
                    name: "file_read".to_string(),
                    arguments: r#"{"path": "/a"}"#.to_string(),
                },
                ToolCallEntry {
                    name: "file_read".to_string(),
                    arguments: r#"{"path": "/b"}"#.to_string(),
                },
            ],
            &[
                ToolResponseEntry {
                    result: "content a".to_string(),
                },
                ToolResponseEntry {
                    result: "content b".to_string(),
                },
            ],
            "Both read.",
        );

        let assistant_msg = &trace.conversations[1];
        let tool_call_count = assistant_msg.content.matches("<tool_call>").count();
        assert_eq!(tool_call_count, 2, "Should have 2 tool_call blocks");

        // 2 tool response messages
        assert_eq!(trace.conversations[2].role, "tool");
        assert_eq!(trace.conversations[3].role, "tool");
        assert_eq!(trace.conversations[4].role, "assistant");
    }

    #[test]
    fn jsonl_roundtrip() {
        let trace = TraceExporter::build(
            Some("System prompt."),
            "User input.",
            None,
            &[],
            &[],
            "Response.",
        );

        let jsonl = trace.to_jsonl();
        let parsed: HermesTrace =
            serde_json::from_str(&jsonl).expect("Should roundtrip through JSON");
        assert_eq!(parsed.conversations.len(), trace.conversations.len());
        assert_eq!(parsed.conversations[0].role, "system");
        assert_eq!(parsed.conversations[0].content, "System prompt.");
    }

    // --- TraceRecord tests ---

    fn sample_blocks() -> Vec<ToolBlock> {
        let mut b = ToolBlock::new("git_status", serde_json::json!({"repo": "."}));
        b.complete("nothing to commit", false);
        vec![b]
    }

    #[test]
    fn trace_record_serialization_roundtrip() {
        let record = TraceExporter::build_record(
            Some("System."),
            "What is the status?",
            &sample_blocks(),
            "All clean.",
            "run-123",
            1,
            100,
            50,
            true,
        );

        let jsonl = record.to_jsonl();
        let parsed: TraceRecord =
            serde_json::from_str(&jsonl).expect("TraceRecord should roundtrip");

        assert_eq!(parsed.metadata.run_id, "run-123");
        assert_eq!(parsed.metadata.iteration_count, 1);
        assert_eq!(parsed.metadata.input_tokens, 100);
        assert_eq!(parsed.metadata.output_tokens, 50);
        assert!(parsed.metadata.success);
        // system + user + assistant(tool_call) + tool + assistant(final)
        assert!(parsed.messages.len() >= 4);
        assert_eq!(parsed.messages[0].role, "system");
    }

    #[test]
    fn trace_record_sanitizer_applied() {
        let mut record = TraceExporter::build_record(
            Some("System with email john@example.com."),
            "User prompt.",
            &[],
            "Response with SSN 123-45-6789.",
            "run-456",
            0,
            10,
            5,
            true,
        );

        let sanitizer: ContentSanitizer =
            std::sync::Arc::new(|s: &str| s.replace("john@example.com", "[REDACTED]"));
        record.sanitize(&sanitizer);

        assert!(
            !record.messages[0].content.contains("john@example.com"),
            "Sanitizer should remove email from system message"
        );
        assert!(
            record.messages[0].content.contains("[REDACTED]"),
            "Sanitizer should insert redaction marker"
        );
    }

    #[test]
    fn trace_record_write_to_dir() {
        let dir = tempfile::tempdir().unwrap();
        let record = TraceExporter::build_record(
            None,
            "Hello",
            &[],
            "World",
            "test-write-run",
            0,
            10,
            5,
            true,
        );

        record.write_to_dir(dir.path()).unwrap();

        let path = dir.path().join("test-write-run.jsonl");
        assert!(path.exists(), "Trace file should be created");

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: TraceRecord =
            serde_json::from_str(content.trim()).expect("File should contain valid TraceRecord");
        assert_eq!(parsed.metadata.run_id, "test-write-run");
    }

    #[test]
    fn trace_record_write_creates_dir() {
        let base = tempfile::tempdir().unwrap();
        let nested = base.path().join("sub").join("traces");

        let record = TraceExporter::build_record(
            None,
            "Hello",
            &[],
            "World",
            "nested-run",
            0,
            0,
            0,
            true,
        );

        record.write_to_dir(&nested).unwrap();
        assert!(nested.join("nested-run.jsonl").exists());
    }

    #[test]
    fn build_record_with_tool_blocks() {
        let mut b1 = ToolBlock::new("file_read", serde_json::json!({"path": "/etc/hosts"}));
        b1.complete("127.0.0.1 localhost", false);
        let mut b2 = ToolBlock::new("git_status", serde_json::json!({}));
        b2.complete("clean", false);

        let record = TraceExporter::build_record(
            Some("You are helpful."),
            "Read file and check status",
            &[b1, b2],
            "Done.",
            "multi-tool-run",
            2,
            200,
            100,
            true,
        );

        // Should have: system + user + assistant(2 tool_calls) + 2 tool + assistant(final)
        assert_eq!(record.messages.len(), 6);
        assert_eq!(record.messages[0].role, "system");
        assert_eq!(record.messages[1].role, "user");
        assert_eq!(record.messages[2].role, "assistant");
        assert_eq!(record.messages[3].role, "tool");
        assert_eq!(record.messages[4].role, "tool");
        assert_eq!(record.messages[5].role, "assistant");

        let assistant_msg = &record.messages[2];
        assert_eq!(
            assistant_msg.content.matches("<tool_call>").count(),
            2,
            "Should have 2 tool_call blocks"
        );
    }
}
