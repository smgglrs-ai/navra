//! MCP protocol types — re-exported from rmcp with navra additions.
//!
//! Core MCP types (Tool, CallToolResult, Content, Prompt, Resource, etc.)
//! come from the `rmcp` SDK. This module adds navra-specific types that
//! don't exist in rmcp (pagination, server capabilities with permissions,
//! protocol version constants, notification method strings).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vstd::prelude::*;

// ========================================================================
// Re-exports from rmcp
// ========================================================================

// --- Common ---
pub use rmcp::model::Annotated;

// --- Tools ---
pub use rmcp::model::CallToolRequestParams as CallToolParams;
pub use rmcp::model::CallToolResult;
pub use rmcp::model::ListToolsResult;
pub use rmcp::model::Tool as ToolDefinition;
pub use rmcp::model::ToolAnnotations;

// --- Content ---
pub use rmcp::model::Content;
pub use rmcp::model::RawAudioContent as AudioContent;
pub use rmcp::model::RawContent;
pub use rmcp::model::RawEmbeddedResource as EmbeddedResourceContent;
pub use rmcp::model::RawImageContent as ImageContent;
pub use rmcp::model::RawTextContent as TextContent;
pub use rmcp::model::ResourceContents as ResourceContent;

// --- Prompts ---
pub use rmcp::model::GetPromptRequestParams as GetPromptParams;
pub use rmcp::model::GetPromptResult;
pub use rmcp::model::ListPromptsResult;
pub use rmcp::model::Prompt as PromptDefinition;
pub use rmcp::model::PromptArgument;
pub use rmcp::model::PromptMessage;
pub use rmcp::model::PromptMessageContent;
pub use rmcp::model::PromptMessageRole as PromptRole;

// --- Resources ---
pub use rmcp::model::ListResourceTemplatesResult;
pub use rmcp::model::ListResourcesResult;
pub use rmcp::model::RawResource;
pub use rmcp::model::RawResourceTemplate;
pub use rmcp::model::ReadResourceRequestParams as ReadResourceParams;
pub use rmcp::model::ReadResourceResult;
pub use rmcp::model::Resource as ResourceDefinition;
pub use rmcp::model::ResourceTemplate;
pub use rmcp::model::ResourceUpdatedNotificationParam as ResourceUpdatedParams;

// --- Capabilities ---
pub use rmcp::model::ClientCapabilities;
pub use rmcp::model::PromptsCapability;
pub use rmcp::model::ResourcesCapability;
pub use rmcp::model::ToolsCapability;

// --- Initialize ---
pub use rmcp::model::Implementation as ServerInfo;
pub use rmcp::model::Implementation as ClientInfo;
pub use rmcp::model::InitializeRequestParams as InitializeParams;
pub use rmcp::model::InitializeResult;
pub use rmcp::model::ProtocolVersion;

// --- Logging ---
pub use rmcp::model::LoggingLevel;
pub use rmcp::model::LoggingMessageNotificationParam as LoggingMessageNotification;
pub use rmcp::model::SetLevelRequestParams as SetLevelParams;

// --- Progress ---
pub use rmcp::model::Meta as RequestMeta;
pub use rmcp::model::ProgressNotificationParam as ProgressParams;

// --- Completions ---
pub use rmcp::model::ArgumentInfo as CompletionArgument;
pub use rmcp::model::CompleteRequestParams as CompleteParams;
pub use rmcp::model::CompleteResult;

// ========================================================================
// Protocol version constants
// ========================================================================

pub const PROTOCOL_VERSION: &str = "2025-03-26";
pub const PROTOCOL_VERSION_2026: &str = "2026-07-28";

// ========================================================================
// Server-initiated notification methods
// ========================================================================

pub const NOTIFY_TOOLS_LIST_CHANGED: &str = "notifications/tools/list_changed";
pub const NOTIFY_RESOURCES_LIST_CHANGED: &str = "notifications/resources/list_changed";
pub const NOTIFY_RESOURCES_UPDATED: &str = "notifications/resources/updated";
pub const NOTIFY_PROMPTS_LIST_CHANGED: &str = "notifications/prompts/list_changed";
pub const NOTIFY_PROGRESS: &str = "notifications/progress";
pub const NOTIFY_INITIALIZED: &str = "notifications/initialized";

// ========================================================================
// Navra-specific: Server capabilities with permissions extension
// ========================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<crate::permissions::PermissionsCapability>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extensions: HashMap<String, serde_json::Value>,
}

// ========================================================================
// Navra-specific: Content type helper (HTTP content negotiation)
// ========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Json,
    EventStream,
}

impl ContentType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::EventStream => "text/event-stream",
        }
    }
}

// ========================================================================
// Navra-specific: Pagination (offset-cursor encoding)
// ========================================================================

pub const DEFAULT_PAGE_SIZE: usize = 100;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl PaginatedRequest {
    pub fn decode_offset(&self) -> Option<usize> {
        match &self.cursor {
            None => Some(0),
            Some(cursor) => {
                let bytes = URL_SAFE_NO_PAD.decode(cursor).ok()?;
                let s = std::str::from_utf8(&bytes).ok()?;
                s.parse::<usize>().ok()
            }
        }
    }
}

pub fn encode_cursor(offset: usize) -> String {
    URL_SAFE_NO_PAD.encode(offset.to_string().as_bytes())
}

pub fn paginate<T: Clone>(
    items: &[T],
    offset: usize,
    page_size: usize,
) -> (Vec<T>, Option<String>) {
    if offset >= items.len() {
        return (Vec::new(), None);
    }
    let end = (offset + page_size).min(items.len());
    let page = items[offset..end].to_vec();
    let next_cursor = if end < items.len() {
        Some(encode_cursor(end))
    } else {
        None
    };
    (page, next_cursor)
}

// ========================================================================
// Tests
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paginated_request_no_cursor_decodes_to_zero() {
        let req = PaginatedRequest { cursor: None };
        assert_eq!(req.decode_offset(), Some(0));
    }

    #[test]
    fn cursor_roundtrip() {
        let offset = 42usize;
        let cursor = encode_cursor(offset);
        let req = PaginatedRequest {
            cursor: Some(cursor),
        };
        assert_eq!(req.decode_offset(), Some(42));
    }

    #[test]
    fn invalid_cursor_returns_none() {
        let req = PaginatedRequest {
            cursor: Some("!!!invalid!!!".to_string()),
        };
        assert_eq!(req.decode_offset(), None);
    }

    #[test]
    fn paginate_all_items_no_next_cursor() {
        let items: Vec<i32> = (0..5).collect();
        let (page, next) = paginate(&items, 0, 100);
        assert_eq!(page.len(), 5);
        assert!(next.is_none());
    }

    #[test]
    fn paginate_first_page_with_next_cursor() {
        let items: Vec<i32> = (0..10).collect();
        let (page, next) = paginate(&items, 0, 3);
        assert_eq!(page, vec![0, 1, 2]);
        assert!(next.is_some());
        let req = PaginatedRequest { cursor: next };
        let offset = req.decode_offset().unwrap();
        assert_eq!(offset, 3);
        let (page2, next2) = paginate(&items, offset, 3);
        assert_eq!(page2, vec![3, 4, 5]);
        assert!(next2.is_some());
    }

    #[test]
    fn paginate_last_page_no_next_cursor() {
        let items: Vec<i32> = (0..10).collect();
        let (page, next) = paginate(&items, 9, 3);
        assert_eq!(page, vec![9]);
        assert!(next.is_none());
    }

    #[test]
    fn paginate_offset_past_end() {
        let items: Vec<i32> = (0..5).collect();
        let (page, next) = paginate(&items, 100, 3);
        assert!(page.is_empty());
        assert!(next.is_none());
    }

    #[test]
    fn paginate_empty_list() {
        let items: Vec<i32> = vec![];
        let (page, next) = paginate(&items, 0, 10);
        assert!(page.is_empty());
        assert!(next.is_none());
    }

    #[test]
    fn content_text_constructor() {
        let content = Content::text("hello world");
        assert_eq!(content.raw.as_text().unwrap().text, "hello world");
    }

    #[test]
    fn tool_definition_construction() {
        let tool = ToolDefinition::new(
            "file_search",
            "Search documents",
            crate::compat::tool_input_schema(
                Some(HashMap::from([(
                    "query".to_string(),
                    serde_json::json!({"type": "string", "description": "Search query"}),
                )])),
                Some(vec!["query".to_string()]),
            ),
        );
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["name"], "file_search");
        assert_eq!(json["inputSchema"]["type"], "object");
        assert!(json["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("query")));
    }

    #[test]
    fn tool_result_success() {
        use crate::compat::CallToolResultExt;
        let result = CallToolResult::text("hello");
        assert!(!result.is_err());
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["content"][0]["type"], "text");
        assert_eq!(json["content"][0]["text"], "hello");
    }

    #[test]
    fn tool_result_error() {
        use crate::compat::CallToolResultExt;
        let result = CallToolResult::error_msg("something went wrong");
        assert!(result.is_err());
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["isError"].as_bool().unwrap());
    }

    #[test]
    fn protocol_version_2026_constant() {
        assert_eq!(PROTOCOL_VERSION_2026, "2026-07-28");
    }
}

verus! {

spec fn spec_paginate(item_count: nat, offset: nat, page_size: nat) -> (nat, bool) {
    if offset >= item_count {
        (0, false)
    } else {
        let end: nat = if offset + page_size < item_count { offset + page_size } else { item_count };
        ((end - offset) as nat, end < item_count)
    }
}

proof fn paginate_offset_past_end_empty(item_count: nat, offset: nat, page_size: nat)
    requires offset >= item_count, page_size >= 1,
    ensures spec_paginate(item_count, offset, page_size) == (0nat, false),
{}

proof fn paginate_page_size_bounded(item_count: nat, offset: nat, page_size: nat)
    requires page_size >= 1,
    ensures spec_paginate(item_count, offset, page_size).0 <= page_size,
{}

} // verus!

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn paginate_pure(item_count: usize, offset: usize, page_size: usize) -> (usize, bool) {
        if offset >= item_count {
            return (0, false);
        }
        let end = (offset + page_size).min(item_count);
        let page_len = end - offset;
        let has_next = end < item_count;
        (page_len, has_next)
    }

    #[kani::proof]
    fn paginate_offset_past_end_empty() {
        let count: u8 = kani::any();
        let offset: u8 = kani::any();
        let page_size: u8 = kani::any();
        kani::assume(count <= 20);
        kani::assume(page_size >= 1 && page_size <= 10);
        kani::assume(offset >= count);
        let (page_len, has_next) =
            paginate_pure(count as usize, offset as usize, page_size as usize);
        assert_eq!(page_len, 0);
        assert!(!has_next);
    }

    #[kani::proof]
    fn paginate_page_size_bounded() {
        let count: u8 = kani::any();
        let offset: u8 = kani::any();
        let page_size: u8 = kani::any();
        kani::assume(count <= 20);
        kani::assume(offset <= 20);
        kani::assume(page_size >= 1 && page_size <= 10);
        let (page_len, _) = paginate_pure(count as usize, offset as usize, page_size as usize);
        assert!(page_len <= page_size as usize);
    }

    #[kani::proof]
    fn cursor_roundtrip() {
        let offset: u8 = kani::any();
        let encoded = encode_cursor(offset as usize);
        let req = PaginatedRequest {
            cursor: Some(encoded),
        };
        let decoded = req.decode_offset().unwrap();
        assert_eq!(decoded, offset as usize);
    }
}
