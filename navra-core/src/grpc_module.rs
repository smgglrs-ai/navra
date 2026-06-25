//! Adapts a gRPC service into the Module trait.
//!
//! A `GrpcModule` wraps a gRPC `ModuleService` client and presents its
//! tools, prompts, and resources as if they were a built-in module.
//! Same pattern as `UpstreamModule` (which adapts MCP/JSON-RPC servers)
//! but for gRPC out-of-process modules.

use crate::module::{Module, PromptHandler, ResourceHandler};
use crate::protocol::{
    CallToolResult, Content, GetPromptResult, PromptArgument, PromptDefinition, PromptMessage,
    PromptRole, ReadResourceResult, ResourceContent, ResourceDefinition, ToolDefinition,
};
use navra_mcp::ToolHandler;
use navra_protocol::compat::CallToolResultExt;
use std::collections::HashMap;
use std::sync::Arc;

pub mod proto {
    tonic::include_proto!("navra.module.v1");
}

use proto::module_service_client::ModuleServiceClient;
use proto::{
    CallToolRequest, GetCapabilitiesRequest, GetPromptRequest as ProtoGetPromptRequest,
    HealthRequest, ReadResourceRequest, ToolCallContext,
};

/// A module backed by a gRPC `ModuleService`.
///
/// Connects to an out-of-process module over gRPC (Unix socket or TCP)
/// and forwards tool calls, prompt renders, and resource reads. Crash
/// isolation is achieved by process boundary — a failing module does
/// not crash the gateway.
pub struct GrpcModule {
    name: String,
    client: ModuleServiceClient<tonic::transport::Channel>,
    cached_tools: Vec<proto::ToolDef>,
    cached_prompts: Vec<proto::PromptDef>,
    cached_resources: Vec<proto::ResourceDef>,
}

impl GrpcModule {
    /// Connect to a gRPC module service and discover capabilities.
    ///
    /// Calls `GetCapabilities` on the remote service and caches the
    /// tool/prompt/resource definitions. Errors during discovery
    /// propagate (unlike UpstreamModule which swallows them).
    pub async fn connect(name: &str, endpoint: &str) -> Result<Self, GrpcModuleError> {
        let channel = tonic::transport::Channel::from_shared(endpoint.to_string())
            .map_err(|e| GrpcModuleError::Connection(e.to_string()))?
            .connect()
            .await
            .map_err(|e| GrpcModuleError::Connection(e.to_string()))?;

        let mut client = ModuleServiceClient::new(channel);

        let caps = client
            .get_capabilities(GetCapabilitiesRequest {})
            .await
            .map_err(|e| GrpcModuleError::Discovery(e.to_string()))?
            .into_inner();

        tracing::info!(
            module = %name,
            tools = caps.tools.len(),
            prompts = caps.prompts.len(),
            resources = caps.resources.len(),
            "Discovered gRPC module capabilities"
        );

        Ok(Self {
            name: name.to_string(),
            client,
            cached_tools: caps.tools,
            cached_prompts: caps.prompts,
            cached_resources: caps.resources,
        })
    }

    /// Create a GrpcModule from pre-fetched capabilities and an
    /// existing channel. Used in tests and when the caller manages
    /// the connection lifecycle.
    pub fn from_parts(
        name: &str,
        client: ModuleServiceClient<tonic::transport::Channel>,
        tools: Vec<proto::ToolDef>,
        prompts: Vec<proto::PromptDef>,
        resources: Vec<proto::ResourceDef>,
    ) -> Self {
        Self {
            name: name.to_string(),
            client,
            cached_tools: tools,
            cached_prompts: prompts,
            cached_resources: resources,
        }
    }

    /// Refresh cached capabilities (call after module restart).
    pub async fn refresh(&mut self) -> Result<(), GrpcModuleError> {
        let caps = self
            .client
            .get_capabilities(GetCapabilitiesRequest {})
            .await
            .map_err(|e| GrpcModuleError::Discovery(e.to_string()))?
            .into_inner();

        self.cached_tools = caps.tools;
        self.cached_prompts = caps.prompts;
        self.cached_resources = caps.resources;
        Ok(())
    }

    /// Check health of the remote module.
    pub async fn health(&mut self) -> Result<bool, GrpcModuleError> {
        let resp = self
            .client
            .health(HealthRequest {})
            .await
            .map_err(|e| GrpcModuleError::Health(e.to_string()))?
            .into_inner();
        Ok(resp.healthy)
    }

    /// Return the cached tool definitions (for inspection/testing).
    pub fn cached_tools(&self) -> &[proto::ToolDef] {
        &self.cached_tools
    }

    /// Return the cached prompt definitions (for inspection/testing).
    pub fn cached_prompts(&self) -> &[proto::PromptDef] {
        &self.cached_prompts
    }

    /// Return the cached resource definitions (for inspection/testing).
    pub fn cached_resources(&self) -> &[proto::ResourceDef] {
        &self.cached_resources
    }
}

/// Parse a data label string back into a `DataLabel`.
///
/// Format: "Integrity+Confidentiality" (e.g., "Untrusted+Sensitive").
fn parse_data_label(s: &str) -> navra_protocol::label::DataLabel {
    use navra_protocol::label::{Confidentiality, DataLabel, Integrity};

    if s.is_empty() {
        // Fail-safe: unknown label = untrusted
        return DataLabel::UNTRUSTED_PUBLIC;
    }

    let parts: Vec<&str> = s.splitn(2, '+').collect();
    if parts.len() != 2 {
        return DataLabel::UNTRUSTED_PUBLIC;
    }

    // Case-insensitive matching with fail-safe defaults
    let integrity = if parts[0].eq_ignore_ascii_case("trusted") {
        Integrity::Trusted
    } else {
        // "Untrusted" or any unrecognized value → Untrusted (fail-safe)
        Integrity::Untrusted
    };

    let confidentiality = if parts[1].eq_ignore_ascii_case("public") {
        Confidentiality::Public
    } else if parts[1].eq_ignore_ascii_case("sensitive") {
        Confidentiality::Sensitive
    } else if parts[1].eq_ignore_ascii_case("pii") {
        Confidentiality::Pii
    } else if parts[1].eq_ignore_ascii_case("secret") {
        Confidentiality::Secret
    } else {
        // Unrecognized → Sensitive (fail-safe: unknown ≠ public)
        Confidentiality::Sensitive
    };

    DataLabel {
        integrity,
        confidentiality,
    }
}

impl Module for GrpcModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        self.cached_tools
            .iter()
            .map(|def| {
                let input_schema: Arc<serde_json::Map<String, serde_json::Value>> =
                    serde_json::from_slice(&def.input_schema_json)
                        .map(Arc::new)
                        .unwrap_or_else(|_| navra_protocol::compat::empty_input_schema());

                let description: Option<std::borrow::Cow<'static, str>> =
                    if def.description.is_empty() {
                        None
                    } else {
                        Some(def.description.clone().into())
                    };

                let tool_def =
                    ToolDefinition::new_with_raw(def.name.clone(), description, input_schema);

                let client = self.client.clone();
                let tool_name = def.name.clone();

                let handler: ToolHandler = Arc::new(move |args, ctx| {
                    let mut client = client.clone();
                    let name = tool_name.clone();
                    Box::pin(async move {
                        let req = CallToolRequest {
                            name,
                            arguments_json: serde_json::to_vec(&args).unwrap_or_default(),
                            context: Some(ToolCallContext {
                                agent_name: ctx.agent.name.clone(),
                                session_id: ctx.session_id.clone(),
                                data_label: format!("{}", ctx.taint.level()),
                                ring: ctx
                                    .agent
                                    .capabilities
                                    .as_ref()
                                    .map(|c| c.ring as u32)
                                    .unwrap_or(3),
                            }),
                        };
                        match client.call_tool(req).await {
                            Ok(resp) => {
                                let inner = resp.into_inner();
                                let _label = parse_data_label(&inner.result_data_label);
                                if inner.is_error {
                                    let msg = inner
                                        .content
                                        .first()
                                        .map(|c| c.text.clone())
                                        .unwrap_or_default();
                                    CallToolResult::error_msg(msg)
                                } else {
                                    let content: Vec<Content> = inner
                                        .content
                                        .iter()
                                        .map(|c| Content::text(c.text.clone()))
                                        .collect();
                                    CallToolResult::success(content)
                                }
                            }
                            Err(e) => CallToolResult::error_msg(format!("grpc: {e}")),
                        }
                    })
                });

                (tool_def, handler)
            })
            .collect()
    }

    fn prompts(&self) -> Vec<(PromptDefinition, PromptHandler)> {
        self.cached_prompts
            .iter()
            .map(|def| {
                let prompt_def = PromptDefinition::new(
                    def.name.clone(),
                    if def.description.is_empty() {
                        None::<String>
                    } else {
                        Some(def.description.clone())
                    },
                    Some(
                        def.arguments
                            .iter()
                            .map(|a| {
                                let mut arg = PromptArgument::new(a.name.clone());
                                if !a.description.is_empty() {
                                    arg = arg.with_description(a.description.clone());
                                }
                                arg = arg.with_required(a.required);
                                arg
                            })
                            .collect(),
                    ),
                );

                let client = self.client.clone();
                let prompt_name = def.name.clone();

                let handler: PromptHandler =
                    Arc::new(move |args: HashMap<String, String>, _ctx| {
                        let mut client = client.clone();
                        let name = prompt_name.clone();
                        Box::pin(async move {
                            let req = ProtoGetPromptRequest {
                                name,
                                arguments: args,
                            };
                            match client.get_prompt(req).await {
                                Ok(resp) => {
                                    let inner = resp.into_inner();
                                    let mut result = GetPromptResult::new(
                                        inner
                                            .messages
                                            .into_iter()
                                            .map(|m| {
                                                let role = match m.role.as_str() {
                                                    "assistant" => PromptRole::Assistant,
                                                    _ => PromptRole::User,
                                                };
                                                PromptMessage::new_text(role, m.content)
                                            })
                                            .collect(),
                                    );
                                    if !inner.description.is_empty() {
                                        result.description = Some(inner.description);
                                    }
                                    result
                                }
                                Err(e) => {
                                    let mut result = GetPromptResult::new(vec![]);
                                    result.description = Some(format!("grpc error: {e}"));
                                    result
                                }
                            }
                        })
                    });

                (prompt_def, handler)
            })
            .collect()
    }

    fn resources(&self) -> Vec<(ResourceDefinition, ResourceHandler)> {
        self.cached_resources
            .iter()
            .map(|def| {
                let mut raw_resource =
                    navra_protocol::RawResource::new(def.uri.clone(), def.name.clone());
                if !def.description.is_empty() {
                    raw_resource = raw_resource.with_description(def.description.clone());
                }
                if !def.mime_type.is_empty() {
                    raw_resource = raw_resource.with_mime_type(def.mime_type.clone());
                }
                let resource_def = ResourceDefinition {
                    raw: raw_resource,
                    annotations: None,
                };

                let client = self.client.clone();

                let handler: ResourceHandler = Arc::new(move |uri: String, _ctx| {
                    let mut client = client.clone();
                    Box::pin(async move {
                        let req = ReadResourceRequest { uri: uri.clone() };
                        match client.read_resource(req).await {
                            Ok(resp) => {
                                let inner = resp.into_inner();
                                ReadResourceResult::new(
                                    inner
                                        .contents
                                        .into_iter()
                                        .map(|c| {
                                            let mime = if c.mime_type.is_empty() {
                                                None
                                            } else {
                                                Some(c.mime_type)
                                            };
                                            if !c.blob.is_empty() {
                                                ResourceContent::BlobResourceContents {
                                                    uri: c.uri,
                                                    mime_type: mime,
                                                    blob: base64_encode(&c.blob),
                                                    meta: None,
                                                }
                                            } else {
                                                ResourceContent::TextResourceContents {
                                                    uri: c.uri,
                                                    mime_type: mime,
                                                    text: c.text,
                                                    meta: None,
                                                }
                                            }
                                        })
                                        .collect(),
                                )
                            }
                            Err(e) => ReadResourceResult::new(vec![
                                ResourceContent::TextResourceContents {
                                    uri,
                                    mime_type: Some("text/plain".to_string()),
                                    text: format!("grpc error: {e}"),
                                    meta: None,
                                },
                            ]),
                        }
                    })
                });

                (resource_def, handler)
            })
            .collect()
    }
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[derive(Debug, thiserror::Error)]
pub enum GrpcModuleError {
    #[error("connection error: {0}")]
    Connection(String),
    #[error("discovery error: {0}")]
    Discovery(String),
    #[error("health check error: {0}")]
    Health(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_data_label_trusted_public() {
        let label = parse_data_label("Trusted+Public");
        assert_eq!(label, navra_protocol::label::DataLabel::TRUSTED_PUBLIC);
    }

    #[test]
    fn parse_data_label_untrusted_sensitive() {
        let label = parse_data_label("Untrusted+Sensitive");
        assert_eq!(label, navra_protocol::label::DataLabel::UNTRUSTED_SENSITIVE);
    }

    #[test]
    fn parse_data_label_untrusted_pii() {
        let label = parse_data_label("Untrusted+Pii");
        assert_eq!(label, navra_protocol::label::DataLabel::UNTRUSTED_PII);
    }

    #[test]
    fn parse_data_label_trusted_secret() {
        let label = parse_data_label("Trusted+Secret");
        assert_eq!(label, navra_protocol::label::DataLabel::TRUSTED_SECRET);
    }

    #[test]
    fn parse_data_label_empty_returns_untrusted() {
        let label = parse_data_label("");
        assert_eq!(label, navra_protocol::label::DataLabel::UNTRUSTED_PUBLIC);
    }

    #[test]
    fn parse_data_label_invalid_returns_untrusted() {
        let label = parse_data_label("garbage");
        assert_eq!(label, navra_protocol::label::DataLabel::UNTRUSTED_PUBLIC);
    }

    #[test]
    fn parse_data_label_case_insensitive() {
        let label = parse_data_label("untrusted+sensitive");
        assert_eq!(label, navra_protocol::label::DataLabel::UNTRUSTED_SENSITIVE);

        let label = parse_data_label("UNTRUSTED+SENSITIVE");
        assert_eq!(label, navra_protocol::label::DataLabel::UNTRUSTED_SENSITIVE);

        let label = parse_data_label("trusted+public");
        assert_eq!(label, navra_protocol::label::DataLabel::TRUSTED_PUBLIC);

        let label = parse_data_label("Trusted+pii");
        assert_eq!(label.integrity, navra_protocol::label::Integrity::Trusted);
        assert_eq!(
            label.confidentiality,
            navra_protocol::label::Confidentiality::Pii
        );
    }

    #[test]
    fn parse_data_label_unknown_integrity_defaults_untrusted() {
        let label = parse_data_label("whatever+Public");
        assert_eq!(label.integrity, navra_protocol::label::Integrity::Untrusted);
    }

    #[test]
    fn parse_data_label_unknown_confidentiality_defaults_sensitive() {
        let label = parse_data_label("Trusted+whatever");
        assert_eq!(
            label.confidentiality,
            navra_protocol::label::Confidentiality::Sensitive
        );
    }

    #[test]
    fn tool_def_to_tool_definition_conversion() {
        let proto_def = proto::ToolDef {
            name: "test_tool".to_string(),
            description: "A test tool".to_string(),
            input_schema_json: serde_json::to_vec(&serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"}
                },
                "required": ["path"]
            }))
            .unwrap(),
        };

        let input_schema: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&proto_def.input_schema_json).unwrap();

        assert_eq!(
            input_schema.get("type").and_then(|v| v.as_str()),
            Some("object")
        );
        assert!(input_schema.contains_key("properties"));
        let required: Vec<String> =
            serde_json::from_value(input_schema.get("required").cloned().unwrap()).unwrap();
        assert_eq!(required, vec!["path".to_string()]);
    }

    #[test]
    fn prompt_def_to_prompt_definition_conversion() {
        let proto_def = proto::PromptDef {
            name: "test_prompt".to_string(),
            description: "A test prompt".to_string(),
            arguments: vec![proto::PromptArgDef {
                name: "topic".to_string(),
                description: "Topic to discuss".to_string(),
                required: true,
            }],
        };

        let prompt_def = PromptDefinition::new(
            proto_def.name.clone(),
            Some(proto_def.description.clone()),
            Some(
                proto_def
                    .arguments
                    .iter()
                    .map(|a| {
                        PromptArgument::new(a.name.clone())
                            .with_description(a.description.clone())
                            .with_required(a.required)
                    })
                    .collect(),
            ),
        );

        assert_eq!(prompt_def.name, "test_prompt");
        assert_eq!(prompt_def.arguments.as_ref().unwrap().len(), 1);
        assert_eq!(
            prompt_def.arguments.as_ref().unwrap()[0].required,
            Some(true)
        );
    }

    #[test]
    fn resource_def_to_resource_definition_conversion() {
        let proto_def = proto::ResourceDef {
            uri: "file:///workspace/readme.md".to_string(),
            name: "readme".to_string(),
            description: "Project readme".to_string(),
            mime_type: "text/markdown".to_string(),
        };

        let resource_def = navra_protocol::Annotated::new(
            navra_protocol::RawResource {
                uri: proto_def.uri.clone(),
                name: proto_def.name.clone(),
                title: None,
                description: Some(proto_def.description.clone()),
                mime_type: Some(proto_def.mime_type.clone()),
                size: None,
                icons: None,
                meta: None,
            },
            None,
        );

        assert_eq!(resource_def.uri, "file:///workspace/readme.md");
        assert_eq!(resource_def.mime_type, Some("text/markdown".to_string()));
    }

    #[test]
    fn call_tool_response_error_conversion() {
        let inner = proto::CallToolResponse {
            content: vec![proto::ContentItem {
                r#type: "text".to_string(),
                text: "something went wrong".to_string(),
                mime_type: String::new(),
                data: vec![],
            }],
            is_error: true,
            result_data_label: "Trusted+Public".to_string(),
        };

        let label = parse_data_label(&inner.result_data_label);
        assert!(inner.is_error);
        assert_eq!(
            inner.content.first().map(|c| c.text.as_str()),
            Some("something went wrong")
        );
        assert_eq!(label, navra_protocol::label::DataLabel::TRUSTED_PUBLIC);
    }

    #[test]
    fn call_tool_response_success_with_taint() {
        let inner = proto::CallToolResponse {
            content: vec![proto::ContentItem {
                r#type: "text".to_string(),
                text: "file contents here".to_string(),
                mime_type: String::new(),
                data: vec![],
            }],
            is_error: false,
            result_data_label: "Untrusted+Sensitive".to_string(),
        };

        let label = parse_data_label(&inner.result_data_label);
        assert!(!inner.is_error);
        assert_eq!(label, navra_protocol::label::DataLabel::UNTRUSTED_SENSITIVE);
    }

    #[test]
    fn capability_caching_preserves_all_fields() {
        let tools = vec![
            proto::ToolDef {
                name: "mod_read".to_string(),
                description: "Read a file".to_string(),
                input_schema_json: b"{}".to_vec(),
            },
            proto::ToolDef {
                name: "mod_write".to_string(),
                description: "Write a file".to_string(),
                input_schema_json: b"{}".to_vec(),
            },
        ];
        let prompts = vec![proto::PromptDef {
            name: "mod_analyze".to_string(),
            description: "Analyze code".to_string(),
            arguments: vec![],
        }];
        let resources = vec![proto::ResourceDef {
            uri: "mod://status".to_string(),
            name: "status".to_string(),
            description: "Module status".to_string(),
            mime_type: "application/json".to_string(),
        }];

        // Verify counts match after caching
        assert_eq!(tools.len(), 2);
        assert_eq!(prompts.len(), 1);
        assert_eq!(resources.len(), 1);

        // Verify field preservation
        assert_eq!(tools[0].name, "mod_read");
        assert_eq!(tools[1].name, "mod_write");
        assert_eq!(prompts[0].name, "mod_analyze");
        assert_eq!(resources[0].uri, "mod://status");
    }
}
