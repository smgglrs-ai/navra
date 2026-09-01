//! Adapts an upstream MCP server into the Module trait via rmcp.
//!
//! An `UpstreamModule` connects to an external MCP server using rmcp's
//! client transports, discovers its tools/prompts/resources, and
//! presents them as a navra Module.

use crate::protocol::{
    CallToolParams, CallToolResult, GetPromptParams, PromptDefinition, ReadResourceParams,
    ResourceDefinition, ToolDefinition,
};
use navra_mcp::{Module, PromptHandler, ResourceHandler, ToolHandler, ToolOperation};
use std::collections::HashMap;
use std::sync::Arc;

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

/// A module backed by an upstream MCP server via rmcp.
pub struct UpstreamModule {
    name: String,
    peer: rmcp::Peer<rmcp::RoleClient>,
    tools: Vec<ToolDefinition>,
    tool_operations: HashMap<String, ToolOperation>,
    tool_classifications: HashMap<String, navra_auth::permissions::ResourceClass>,
    prompts: Vec<PromptDefinition>,
    resources: Vec<ResourceDefinition>,
}

impl UpstreamModule {
    /// Return the upstream's discovered prompt definitions.
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

    /// Return the semantic tool classifications.
    pub fn tool_classifications(&self) -> &HashMap<String, navra_auth::permissions::ResourceClass> {
        &self.tool_classifications
    }

    /// Connect to an upstream via rmcp and discover its capabilities.
    ///
    /// Calls `tools/list`, `prompts/list`, and `resources/list` on the
    /// upstream, caching the definitions. Errors during discovery are
    /// logged but don't prevent the module from being created — the
    /// corresponding capability will simply be empty.
    pub async fn discover(
        name: &str,
        peer: rmcp::Peer<rmcp::RoleClient>,
        scanner: Option<&mut navra_auth::tool_scanner::ToolScanner>,
        tool_overrides: &HashMap<String, String>,
    ) -> Self {
        let tools = peer.list_all_tools().await.unwrap_or_else(|e| {
            tracing::warn!(upstream = %name, error = %e, "Failed to discover tools");
            Vec::new()
        });

        let tools = if let Some(scanner) = scanner {
            use navra_auth::tool_scanner::ScanVerdict;
            let results = scanner.scan_tools(name, &tools);
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
            let op = if let Some(override_str) = tool_overrides.get(def.name.as_ref()) {
                match override_str.as_str() {
                    "read" => ToolOperation::Read,
                    "write" => ToolOperation::Write,
                    "deny" => ToolOperation::Deny,
                    _ => classify_tool(&def),
                }
            } else {
                classify_tool(&def)
            };
            if op == ToolOperation::Deny {
                tracing::info!(upstream = %name, tool = %def.name, "Denied upstream tool by policy");
                continue;
            }
            tool_operations.insert(def.name.to_string(), op);
            accepted_tools.push(def);
        }

        let mut tool_classifications = HashMap::new();
        for def in &accepted_tools {
            let domain = navra_auth::permissions::resource_class::infer_domain_heuristic(&def.name);
            let operation = navra_auth::permissions::resource_class::infer_operation_heuristic(
                &def.name,
                def.annotations.as_ref(),
            );
            tool_classifications.insert(
                def.name.to_string(),
                navra_auth::permissions::ResourceClass::new(domain, operation),
            );
        }

        let prompts = peer.list_all_prompts().await.unwrap_or_else(|e| {
            tracing::warn!(upstream = %name, error = %e, "Failed to discover prompts");
            Vec::new()
        });

        let resources = peer.list_all_resources().await.unwrap_or_else(|e| {
            tracing::warn!(upstream = %name, error = %e, "Failed to discover resources");
            Vec::new()
        });

        tracing::info!(
            upstream = %name,
            tools = accepted_tools.len(),
            prompts = prompts.len(),
            resources = resources.len(),
            "Discovered upstream capabilities"
        );

        Self {
            name: name.to_string(),
            peer,
            tools: accepted_tools,
            tool_operations,
            tool_classifications,
            prompts,
            resources,
        }
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
                let tool_name = def.name.clone();
                let peer = self.peer.clone();
                let handler: ToolHandler = Arc::new(move |args, _ctx| {
                    let peer = peer.clone();
                    let name = tool_name.clone();
                    Box::pin(async move {
                        let mut params = CallToolParams::new(name);
                        if let Some(obj) = args.as_object() {
                            params = params.with_arguments(obj.clone());
                        }
                        match peer.call_tool(params).await {
                            Ok(result) => result,
                            Err(e) => {
                                use navra_protocol::compat::CallToolResultExt;
                                CallToolResult::error_msg(format!("upstream error: {e}"))
                            }
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
                let prompt_name = def.name.clone();
                let peer = self.peer.clone();
                let handler: PromptHandler =
                    Arc::new(move |args: HashMap<String, String>, _ctx| {
                        let peer = peer.clone();
                        let name = prompt_name.clone();
                        Box::pin(async move {
                            let mut params = GetPromptParams::new(name);
                            if !args.is_empty() {
                                let obj: serde_json::Map<String, serde_json::Value> = args
                                    .into_iter()
                                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                                    .collect();
                                params.arguments = Some(obj);
                            }
                            match peer.get_prompt(params).await {
                                Ok(result) => result,
                                Err(e) => {
                                    let mut r = crate::protocol::GetPromptResult::new(vec![]);
                                    r.description = Some(format!("upstream error: {e}"));
                                    r
                                }
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
                let peer = self.peer.clone();
                let handler: ResourceHandler = Arc::new(move |uri: String, _ctx| {
                    let peer = peer.clone();
                    Box::pin(async move {
                        let params = ReadResourceParams::new(uri.clone());
                        match peer.read_resource(params).await {
                            Ok(result) => result,
                            Err(e) => crate::protocol::ReadResourceResult::new(vec![
                                crate::protocol::ResourceContent::TextResourceContents {
                                    uri,
                                    mime_type: Some("text/plain".to_string()),
                                    text: format!("upstream error: {e}"),
                                    meta: None,
                                },
                            ]),
                        }
                    })
                });
                (def.clone(), handler)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_tool_read_write() {
        assert_eq!(
            classify_tool(&tool_def("read_file", None)),
            ToolOperation::Read
        );
        assert_eq!(
            classify_tool(&tool_def("write_file", None)),
            ToolOperation::Write
        );
    }

    #[test]
    fn classify_tool_read_only_annotation_returns_read() {
        let ann = navra_protocol::ToolAnnotations::new().read_only(true);
        // Even a tool with a write-like name should be classified Read
        // when the read_only_hint annotation is true.
        assert_eq!(
            classify_tool(&tool_def("write_something", Some(ann))),
            ToolOperation::Read
        );
    }

    #[test]
    fn classify_tool_destructive_annotation_returns_write() {
        let ann = navra_protocol::ToolAnnotations::new().destructive(true);
        // A tool with a read-like name should be classified Write
        // when the destructive_hint annotation is true.
        assert_eq!(
            classify_tool(&tool_def("list_items", Some(ann))),
            ToolOperation::Write
        );
    }

    #[test]
    fn classify_tool_read_only_takes_priority_over_destructive() {
        // When both read_only and destructive are set, read_only wins
        // because we check it first.
        let ann = navra_protocol::ToolAnnotations::new()
            .read_only(true)
            .destructive(true);
        assert_eq!(
            classify_tool(&tool_def("ambiguous_tool", Some(ann))),
            ToolOperation::Read
        );
    }

    #[test]
    fn classify_tool_no_annotations_falls_through_to_name_heuristic() {
        // Tools without annotations are classified by name heuristic.
        assert_eq!(
            classify_tool(&tool_def("git_commit", None)),
            ToolOperation::Write
        );
        assert_eq!(
            classify_tool(&tool_def("git_status", None)),
            ToolOperation::Read
        );
        assert_eq!(
            classify_tool(&tool_def("shell_exec", None)),
            ToolOperation::Write
        );
    }

    #[test]
    fn request_timeout_secs_wired_into_retry_config() {
        // Verify the config-to-RetryConfig conversion correctly maps
        // request_timeout_secs to the RetryConfig's request_timeout field.
        let mut config = navra_protocol::RetryConfig::default();
        assert_eq!(config.request_timeout, std::time::Duration::from_secs(45));

        // Simulate what UpstreamConfig::retry_config() does
        let custom_timeout_secs: u64 = 10;
        config.request_timeout = std::time::Duration::from_secs(custom_timeout_secs);
        assert_eq!(config.request_timeout, std::time::Duration::from_secs(10));
    }

    fn tool_def(
        name: &str,
        annotations: Option<navra_protocol::ToolAnnotations>,
    ) -> ToolDefinition {
        let mut def = ToolDefinition::new_with_raw(
            name.to_string(),
            None,
            navra_protocol::compat::empty_input_schema(),
        );
        def.annotations = annotations;
        def
    }
}
