use crate::config::Config;
use crate::permissions::PermissionEngine;
use mcpd_core::auth::CallContext;
use mcpd_core::protocol::{CallToolResult, ToolDefinition, ToolInputSchema};
use mcpd_core::McpServer;
use std::collections::HashMap;
use std::sync::Arc;

pub fn build_server(
    _config: Config,
    perm_engine: Arc<PermissionEngine>,
) -> anyhow::Result<McpServer> {
    let pe = perm_engine.clone();
    let server = McpServer::builder()
        .name("mcpd-docs")
        .version(env!("CARGO_PKG_VERSION"))
        .tool(search_tool_def(), {
            let pe = pe.clone();
            move |args, ctx| {
                let pe = pe.clone();
                Box::pin(async move { handle_search(args, ctx, &pe) })
            }
        })
        .tool(read_tool_def(), {
            let pe = pe.clone();
            move |args, ctx| {
                let pe = pe.clone();
                Box::pin(async move { handle_read(args, ctx, &pe) })
            }
        })
        .tool(list_tool_def(), {
            let pe = pe.clone();
            move |args, ctx| {
                let pe = pe.clone();
                Box::pin(async move { handle_list(args, ctx, &pe) })
            }
        })
        .tool(write_tool_def(), {
            let pe = pe.clone();
            move |args, ctx| {
                let pe = pe.clone();
                Box::pin(async move { handle_write(args, ctx, &pe) })
            }
        })
        .build();

    Ok(server)
}

fn search_tool_def() -> ToolDefinition {
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
                    serde_json::json!({"type": "integer", "description": "Max results", "default": 10}),
                ),
            ])),
            required: Some(vec!["query".to_string()]),
        },
    }
}

fn read_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_read".to_string(),
        description: Some("Read a document by path".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!({"type": "string", "description": "Absolute path to document"}),
            )])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn list_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_list".to_string(),
        description: Some("List documents in a directory".to_string()),
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

fn write_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "docs_write".to_string(),
        description: Some("Write or update a document".to_string()),
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

fn handle_search(
    args: serde_json::Value,
    ctx: CallContext,
    perm_engine: &PermissionEngine,
) -> CallToolResult {
    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) => q,
        None => return CallToolResult::error("Missing required parameter: query"),
    };

    // Search operation doesn't have a specific path to check,
    // so we check if the agent has search permission at all.
    // Individual results will be filtered by path ACL.
    let _ = (ctx, perm_engine); // TODO: filter results by ACL

    CallToolResult::text(format!("TODO: search for '{query}'"))
}

fn handle_read(
    args: serde_json::Value,
    ctx: CallContext,
    perm_engine: &PermissionEngine,
) -> CallToolResult {
    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    // Check permissions
    let result = perm_engine.check(
        &ctx.agent.permissions,
        crate::permissions::Operation::Read,
        std::path::Path::new(path),
    );

    match result {
        crate::permissions::PermissionResult::Allowed => {
            CallToolResult::text(format!("TODO: read file at {path}"))
        }
        crate::permissions::PermissionResult::NeedsApproval => {
            CallToolResult::error(format!("Read access to {path} requires approval"))
        }
        _ => CallToolResult::error(format!("Access denied: {path}")),
    }
}

fn handle_list(
    args: serde_json::Value,
    ctx: CallContext,
    perm_engine: &PermissionEngine,
) -> CallToolResult {
    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let result = perm_engine.check(
        &ctx.agent.permissions,
        crate::permissions::Operation::List,
        std::path::Path::new(path),
    );

    match result {
        crate::permissions::PermissionResult::Allowed => {
            CallToolResult::text(format!("TODO: list files in {path}"))
        }
        _ => CallToolResult::error(format!("Access denied: {path}")),
    }
}

fn handle_write(
    args: serde_json::Value,
    ctx: CallContext,
    perm_engine: &PermissionEngine,
) -> CallToolResult {
    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let _content = match args.get("content").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return CallToolResult::error("Missing required parameter: content"),
    };

    let result = perm_engine.check(
        &ctx.agent.permissions,
        crate::permissions::Operation::Write,
        std::path::Path::new(path),
    );

    match result {
        crate::permissions::PermissionResult::Allowed => {
            CallToolResult::text(format!("TODO: write to {path}"))
        }
        crate::permissions::PermissionResult::NeedsApproval => {
            CallToolResult::error(format!("Write to {path} requires approval — TODO: create approval request"))
        }
        _ => CallToolResult::error(format!("Access denied: {path}")),
    }
}
