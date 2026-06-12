//! Adapts an Upstream into the Module trait.
//!
//! An `UpstreamModule` wraps an `Upstream` client and presents its
//! discovered tools, prompts, and resources as if they were a built-in
//! module. This lets the server builder, dispatch, and safety filtering
//! work unchanged.

use crate::module::{Module, PromptHandler, ResourceHandler};
use crate::protocol::{
    CallToolParams, CallToolResult, GetPromptParams, PromptDefinition, ReadResourceParams,
    ResourceDefinition, ToolDefinition,
};
use crate::server::ToolHandler;
use crate::upstream::{Upstream, UpstreamError};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Classified operation type for an upstream tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOperation {
    Read,
    Write,
    Deny,
}

fn classify_tool(def: &ToolDefinition) -> ToolOperation {
    if let Some(ref ann) = def.annotations {
        if ann.read_only_hint == Some(true) {
            return ToolOperation::Read;
        }
        if ann.destructive_hint == Some(true) {
            return ToolOperation::Write;
        }
    }
    if navra_auth::ifc::is_write_tool(&def.name, def.annotations.as_ref()) {
        return ToolOperation::Write;
    }
    ToolOperation::Read
}

/// A module backed by an upstream MCP server.
pub struct UpstreamModule {
    name: String,
    upstream: Arc<Mutex<Upstream>>,
    tools: Vec<ToolDefinition>,
    tool_operations: HashMap<String, ToolOperation>,
    prompts: Vec<PromptDefinition>,
    resources: Vec<ResourceDefinition>,
}

impl UpstreamModule {
    /// Connect to an upstream and discover its capabilities.
    ///
    /// Calls `tools/list`, `prompts/list`, and `resources/list` on the
    /// upstream, caching the definitions. Errors during discovery are
    /// logged but don't prevent the module from being created — the
    /// corresponding capability will simply be empty.
    pub async fn discover(
        upstream: Upstream,
        scanner: Option<&mut navra_auth::tool_scanner::ToolScanner>,
        tool_overrides: &HashMap<String, String>,
    ) -> Result<Self, UpstreamError> {
        let name = upstream.name().to_string();
        let upstream = Arc::new(Mutex::new(upstream));

        let tools = {
            let mut u = upstream.lock().await;
            u.list_tools().await.unwrap_or_else(|e| {
                tracing::warn!(upstream = %name, error = %e, "Failed to discover tools");
                Vec::new()
            })
        };

        let tools = if let Some(scanner) = scanner {
            use navra_auth::tool_scanner::ScanVerdict;
            let results = scanner.scan_tools(&name, &tools);
            let mut filtered = Vec::new();
            for (tool, result) in tools.into_iter().zip(results.iter()) {
                match &result.verdict {
                    ScanVerdict::Malicious { reasons } => {
                        tracing::error!(
                            upstream = %name,
                            tool = %result.tool_name,
                            reasons = ?reasons,
                            "BLOCKED malicious upstream tool"
                        );
                    }
                    ScanVerdict::Suspicious { reasons } => {
                        tracing::warn!(
                            upstream = %name,
                            tool = %result.tool_name,
                            reasons = ?reasons,
                            "Suspicious upstream tool (allowed)"
                        );
                        filtered.push(tool);
                    }
                    ScanVerdict::Safe => {
                        filtered.push(tool);
                    }
                }
            }
            filtered
        } else {
            tools
        };

        let mut tool_operations = HashMap::new();
        let mut accepted_tools = Vec::new();
        for def in tools {
            let op = if let Some(override_str) = tool_overrides.get(&def.name) {
                match override_str.as_str() {
                    "read" => ToolOperation::Read,
                    "write" => ToolOperation::Write,
                    "deny" => ToolOperation::Deny,
                    other => {
                        tracing::warn!(
                            upstream = %name,
                            tool = %def.name,
                            override_value = %other,
                            "Unknown tool_override value, using auto-classification"
                        );
                        classify_tool(&def)
                    }
                }
            } else {
                classify_tool(&def)
            };

            if op == ToolOperation::Deny {
                tracing::info!(
                    upstream = %name,
                    tool = %def.name,
                    "Denied upstream tool by policy"
                );
                continue;
            }

            tracing::debug!(
                upstream = %name,
                tool = %def.name,
                operation = ?op,
                "Classified upstream tool"
            );
            tool_operations.insert(def.name.clone(), op);
            accepted_tools.push(def);
        }

        let prompts = {
            let mut u = upstream.lock().await;
            u.list_prompts().await.unwrap_or_else(|e| {
                tracing::warn!(upstream = %name, error = %e, "Failed to discover prompts");
                Vec::new()
            })
        };

        let resources = {
            let mut u = upstream.lock().await;
            u.list_resources().await.unwrap_or_else(|e| {
                tracing::warn!(upstream = %name, error = %e, "Failed to discover resources");
                Vec::new()
            })
        };

        tracing::info!(
            upstream = %name,
            tools = accepted_tools.len(),
            prompts = prompts.len(),
            resources = resources.len(),
            "Discovered upstream capabilities"
        );

        Ok(Self {
            name,
            upstream,
            tools: accepted_tools,
            tool_operations,
            prompts,
            resources,
        })
    }

    /// Return the upstream's discovered prompt definitions.
    ///
    /// Used at startup to scan for `persona:` prefixed prompts and
    /// auto-register them in the ForgeService.
    pub fn discovered_prompts(&self) -> &[PromptDefinition] {
        &self.prompts
    }

    /// Return the upstream name.
    pub fn upstream_name(&self) -> &str {
        &self.name
    }

    /// Return the tool operation classifications.
    pub fn tool_operations(&self) -> &HashMap<String, ToolOperation> {
        &self.tool_operations
    }
}

impl Module for UpstreamModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        self.tools
            .iter()
            .map(|def| {
                let upstream = self.upstream.clone();
                let tool_name = def.name.clone();
                let handler: ToolHandler = Arc::new(move |args, _ctx| {
                    let upstream = upstream.clone();
                    let name = tool_name.clone();
                    Box::pin(async move {
                        let params = CallToolParams {
                            name,
                            arguments: args,
                            meta: None,
                        };
                        let mut u = upstream.lock().await;
                        match u.call_tool(params).await {
                            Ok(result) => result,
                            Err(e) => CallToolResult::error(format!("upstream error: {e}")),
                        }
                    })
                });

                (def.clone(), handler)
            })
            .collect()
    }

    fn prompts(&self) -> Vec<(PromptDefinition, PromptHandler)> {
        self.prompts
            .iter()
            .map(|def| {
                let upstream = self.upstream.clone();
                let prompt_name = def.name.clone();
                let handler: PromptHandler = Arc::new(move |args: HashMap<String, String>| {
                    let upstream = upstream.clone();
                    let name = prompt_name.clone();
                    Box::pin(async move {
                        let params = GetPromptParams {
                            name,
                            arguments: args,
                        };
                        let mut u = upstream.lock().await;
                        match u.get_prompt(params).await {
                            Ok(result) => result,
                            Err(e) => crate::protocol::GetPromptResult {
                                description: Some(format!("upstream error: {e}")),
                                messages: vec![],
                            },
                        }
                    })
                });

                (def.clone(), handler)
            })
            .collect()
    }

    fn resources(&self) -> Vec<(ResourceDefinition, ResourceHandler)> {
        self.resources
            .iter()
            .map(|def| {
                let upstream = self.upstream.clone();
                let handler: ResourceHandler = Arc::new(move |uri: String| {
                    let upstream = upstream.clone();
                    Box::pin(async move {
                        let params = ReadResourceParams { uri: uri.clone() };
                        let mut u = upstream.lock().await;
                        match u.read_resource(params).await {
                            Ok(result) => result,
                            Err(e) => crate::protocol::ReadResourceResult {
                                contents: vec![crate::protocol::ResourceContent {
                                    uri,
                                    mime_type: Some("text/plain".to_string()),
                                    text: Some(format!("upstream error: {e}")),
                                    blob: None,
                                }],
                            },
                        }
                    })
                });

                (def.clone(), handler)
            })
            .collect()
    }
}
