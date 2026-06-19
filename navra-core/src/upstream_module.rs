//! Adapts an Upstream into the Module trait.
//!
//! An `UpstreamModule` wraps an `Upstream` client and presents its
//! discovered tools, prompts, and resources as if they were a built-in
//! module. This lets the server builder, dispatch, and safety filtering
//! work unchanged.

use crate::protocol::{
    CallToolParams, CallToolResult, GetPromptParams, PromptDefinition, ReadResourceParams,
    ResourceDefinition, ToolDefinition,
};
use crate::upstream::{Upstream, UpstreamError};
use navra_mcp::{Module, PromptHandler, ResourceHandler, ToolHandler, ToolOperation};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

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

/// Classify a tool's domain using embedding similarity against domain exemplars.
///
/// Returns the best-matching domain if cosine similarity exceeds the threshold,
/// otherwise returns `None` (caller falls back to heuristic).
/// Runs at discovery time only — results are cached.
async fn classify_domain_semantic(
    tool: &ToolDefinition,
    embed_backend: &dyn navra_model::ModelBackend,
    exemplar_embeddings: &[(navra_auth::permissions::Domain, Vec<f32>)],
    threshold: f32,
) -> Option<navra_auth::permissions::Domain> {
    let text = format!(
        "{}: {}",
        tool.name,
        tool.description.as_deref().unwrap_or("")
    );
    let req = navra_model::EmbedRequest { text };
    let resp = match embed_backend.embed(&req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(tool = %tool.name, error = %e, "Embedding failed, using heuristic");
            return None;
        }
    };

    let mut best_domain = None;
    let mut best_score = threshold;
    for (domain, exemplar_emb) in exemplar_embeddings {
        let score = cosine_similarity(&resp.embedding, exemplar_emb);
        if score > best_score {
            best_score = score;
            best_domain = Some(*domain);
        }
    }
    if let Some(domain) = best_domain {
        tracing::debug!(
            tool = %tool.name,
            domain = %domain,
            score = best_score,
            "Semantic domain classification"
        );
    }
    best_domain
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

/// Pre-compute embeddings for all domain exemplars.
///
/// Returns empty vec if embedding fails (graceful degradation).
async fn embed_domain_exemplars(
    backend: &dyn navra_model::ModelBackend,
) -> Vec<(navra_auth::permissions::Domain, Vec<f32>)> {
    let mut result = Vec::new();
    for (domain, text) in navra_auth::permissions::resource_class::DOMAIN_EXEMPLARS {
        let req = navra_model::EmbedRequest {
            text: text.to_string(),
        };
        match backend.embed(&req).await {
            Ok(resp) => result.push((*domain, resp.embedding)),
            Err(e) => {
                tracing::warn!(domain = %domain, error = %e, "Failed to embed domain exemplar");
                return Vec::new();
            }
        }
    }
    result
}

/// A module backed by an upstream MCP server.
pub struct UpstreamModule {
    name: String,
    upstream: Arc<Mutex<Upstream>>,
    tools: Vec<ToolDefinition>,
    tool_operations: HashMap<String, ToolOperation>,
    tool_classifications: HashMap<String, navra_auth::permissions::ResourceClass>,
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
        Self::discover_with_embeddings(upstream, scanner, tool_overrides, None).await
    }

    pub async fn discover_with_embeddings(
        upstream: Upstream,
        scanner: Option<&mut navra_auth::tool_scanner::ToolScanner>,
        tool_overrides: &HashMap<String, String>,
        embed_backend: Option<&dyn navra_model::ModelBackend>,
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

        // Semantic classification: embed tool descriptions and match against
        // domain exemplars. Falls back to heuristic if no model available.
        let exemplar_embeddings = if let Some(backend) = embed_backend {
            let embs = embed_domain_exemplars(backend).await;
            if embs.is_empty() {
                tracing::info!(
                    upstream = %name,
                    "Embedding unavailable, using heuristic classification"
                );
            } else {
                tracing::info!(
                    upstream = %name,
                    exemplars = embs.len(),
                    "Domain exemplar embeddings ready"
                );
            }
            embs
        } else {
            Vec::new()
        };

        let mut tool_classifications = HashMap::new();
        for def in &accepted_tools {
            let domain = if !exemplar_embeddings.is_empty() {
                if let Some(backend) = embed_backend {
                    classify_domain_semantic(def, backend, &exemplar_embeddings, 0.3)
                        .await
                        .unwrap_or_else(|| {
                            navra_auth::permissions::resource_class::infer_domain_heuristic(
                                &def.name,
                            )
                        })
                } else {
                    navra_auth::permissions::resource_class::infer_domain_heuristic(&def.name)
                }
            } else {
                navra_auth::permissions::resource_class::infer_domain_heuristic(&def.name)
            };
            let operation = navra_auth::permissions::resource_class::infer_operation_heuristic(
                &def.name,
                def.annotations.as_ref(),
            );
            let class = navra_auth::permissions::ResourceClass::new(domain, operation);
            tracing::debug!(
                upstream = %name,
                tool = %def.name,
                class = %class,
                "Classified upstream tool"
            );
            tool_classifications.insert(def.name.clone(), class);
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
            tool_classifications,
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

    /// Return the semantic tool classifications.
    pub fn tool_classifications(&self) -> &HashMap<String, navra_auth::permissions::ResourceClass> {
        &self.tool_classifications
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
                let handler: PromptHandler =
                    Arc::new(move |args: HashMap<String, String>, _ctx| {
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
                let handler: ResourceHandler = Arc::new(move |uri: String, _ctx| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_identical_vectors() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_orthogonal_vectors() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        assert!(cosine_similarity(&a, &b).abs() < 1e-6);
    }

    #[test]
    fn cosine_opposite_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![-1.0, 0.0];
        assert!((cosine_similarity(&a, &b) + 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_empty_vectors() {
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
    }

    #[test]
    fn cosine_mismatched_lengths() {
        let a = vec![1.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert_eq!(cosine_similarity(&a, &b), 0.0);
    }

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

    fn tool_def(
        name: &str,
        annotations: Option<navra_protocol::ToolAnnotations>,
    ) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: None,
            input_schema: navra_protocol::ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
            annotations,
            ttl_ms: None,
            cache_scope: None,
        }
    }
}
