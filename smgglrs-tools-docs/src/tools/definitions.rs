use smgglrs_core::protocol::{ToolDefinition, ToolInputSchema};
use std::collections::HashMap;

pub(super) fn search_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_search".to_string(),
        description: Some("Full-text search across indexed documents".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "query".to_string(),
                    serde_json::json!({"type": "string", "description": "Search query"}),
                ),
                (
                    "limit".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max results (default 10)", "default": 10}),
                ),
            ])),
            required: Some(vec!["query".to_string()]),
        },
    }
}

pub(super) fn read_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_read".to_string(),
        description: Some("Read a document by path. Supports partial reads with offset and limit (line-based).".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Absolute path to document"}),
                ),
                (
                    "offset".to_string(),
                    serde_json::json!({"type": "integer", "description": "Line number to start from (1-based, default 1)"}),
                ),
                (
                    "limit".to_string(),
                    serde_json::json!({"type": "integer", "description": "Number of lines to read (default: all)"}),
                ),
            ])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

pub(super) fn list_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_list".to_string(),
        description: Some("List files and directories at a path".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!({"type": "string", "description": "Directory path"}),
            )])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

pub(super) fn tree_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_tree".to_string(),
        description: Some(
            "List files under a directory. Returns relative paths and line counts. \
             For large projects, use max_depth to get a high-level overview first, \
             then drill into specific directories. Default max_files is 500 — if \
             the project has more, increase it or use max_depth=2 to get the \
             directory structure without listing every file."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Directory path (optional — defaults to project root)"}),
                ),
                (
                    "pattern".to_string(),
                    serde_json::json!({"type": "string", "description": "Optional file extension filter (e.g. 'rs', 'py')"}),
                ),
                (
                    "max_depth".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max directory depth to recurse (default: unlimited)"}),
                ),
                (
                    "max_files".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max files to return (default: 500). Truncated results show total count."}),
                ),
            ])),
            required: None,
        },
    }
}

pub(super) fn grep_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_grep".to_string(),
        description: Some(
            "Search for a text pattern across all files in a directory. Returns \
             matching lines with file paths and line numbers. Use this for \
             broad codebase searches like finding all .unwrap() calls, unsafe \
             blocks, or specific function names across the entire project."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Root directory to search"}),
                ),
                (
                    "pattern".to_string(),
                    serde_json::json!({"type": "string", "description": "Text pattern to search for (substring match, not regex)"}),
                ),
                (
                    "extension".to_string(),
                    serde_json::json!({"type": "string", "description": "Optional file extension filter (e.g. 'rs')"}),
                ),
                (
                    "max_results".to_string(),
                    serde_json::json!({"type": "integer", "description": "Maximum matches to return (default: 100)"}),
                ),
            ])),
            required: Some(vec!["path".to_string(), "pattern".to_string()]),
        },
    }
}

pub(super) fn write_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_write".to_string(),
        description: Some("Create or overwrite a document".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Absolute path"}),
                ),
                (
                    "content".to_string(),
                    serde_json::json!({"type": "string", "description": "Document content"}),
                ),
            ])),
            required: Some(vec!["path".to_string(), "content".to_string()]),
        },
    }
}

pub(super) fn edit_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_edit".to_string(),
        description: Some(
            "Edit a document by replacing a string. The old_string must be unique in the file. \
             Use enough surrounding context to ensure uniqueness."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Absolute path to file"}),
                ),
                (
                    "old_string".to_string(),
                    serde_json::json!({"type": "string", "description": "Exact string to find and replace"}),
                ),
                (
                    "new_string".to_string(),
                    serde_json::json!({"type": "string", "description": "Replacement string"}),
                ),
            ])),
            required: Some(vec![
                "path".to_string(),
                "old_string".to_string(),
                "new_string".to_string(),
            ]),
        },
    }
}

pub(super) fn info_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_info".to_string(),
        description: Some("Get file metadata without reading content (size, type, line count, modified time)".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!({"type": "string", "description": "Absolute path to file"}),
            )])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

pub(super) fn delete_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_delete".to_string(),
        description: Some("Delete a document. Requires write permission.".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!({"type": "string", "description": "Absolute path to file"}),
            )])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

pub(super) fn approve_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_approve".to_string(),
        description: Some(
            "Approve a pending operation. Call this with the request_id \
             returned by a tool that requires approval."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "request_id".to_string(),
                serde_json::json!({"type": "string", "description": "Approval request ID"}),
            )])),
            required: Some(vec!["request_id".to_string()]),
        },
    }
}

pub(super) fn deny_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_deny".to_string(),
        description: Some(
            "Deny a pending operation. Call this with the request_id \
             returned by a tool that requires approval."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "request_id".to_string(),
                serde_json::json!({"type": "string", "description": "Approval request ID"}),
            )])),
            required: Some(vec!["request_id".to_string()]),
        },
    }
}

pub(super) fn semantic_search_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_semantic_search".to_string(),
        description: Some(
            "Semantic search across indexed documents using vector similarity. \
             Finds documents with similar meaning, even if they don't share exact words."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "query".to_string(),
                    serde_json::json!({"type": "string", "description": "Natural language search query"}),
                ),
                (
                    "limit".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max results (default 5)", "default": 5}),
                ),
            ])),
            required: Some(vec!["query".to_string()]),
        },
    }
}
