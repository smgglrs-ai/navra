//! Upstream MCP server wiring.
//!
//! Connects to upstream MCP servers (stdio, HTTP, SSE, OpenAPI bridge),
//! applies credential injection, and registers as upstream modules.

use crate::config;
use crate::util;
use navra_core::credentials::CredentialStore as _;
use std::sync::Arc;

/// Wire all configured upstream MCP servers onto the builder.
///
/// When `endpoint_registry` is provided, tool-to-domain mappings are
/// populated for policy sync with OpenShell.
pub(crate) async fn wire_upstream(
    mut builder: navra_core::McpServerBuilder,
    cfg: &config::Config,
    credential_store: &Arc<navra_core::credentials::MappedCredentialStore>,
    forge: &mut navra_cognitive::ForgeService,
    endpoint_registry: Option<&crate::policy_sync::ToolEndpointRegistry>,
) -> navra_core::McpServerBuilder {
    for upstream_cfg in &cfg.upstream {
        if !upstream_cfg.enabled.unwrap_or(true) {
            tracing::info!(upstream = %upstream_cfg.name, "Upstream disabled, skipping");
            continue;
        }

        // OpenAPI bridge — parse spec directly, skip MCP transport
        if let Some(ref spec_source) = upstream_cfg.openapi {
            builder = wire_openapi_upstream(builder, upstream_cfg, spec_source).await;
            continue;
        }

        let module_result = match upstream_cfg.transport.as_str() {
            "stdio" => {
                wire_stdio_upstream(upstream_cfg, credential_store).await
            }
            "http" | "streamable-http" | "sse" => {
                wire_http_upstream(upstream_cfg).await
            }
            other => {
                tracing::error!(
                    upstream = %upstream_cfg.name,
                    transport = %other,
                    "Unknown transport type, skipping"
                );
                continue;
            }
        };

        match module_result {
            Ok(module) => {
                tracing::info!(
                    upstream = %upstream_cfg.name,
                    transport = %upstream_cfg.transport,
                    "Connected upstream (rmcp)"
                );

                for prompt_def in module.discovered_prompts() {
                    if let Some(persona_name) = prompt_def.name.strip_prefix("persona:") {
                        let description = prompt_def.description.as_deref().unwrap_or("");
                        forge.register_upstream_persona(
                            persona_name,
                            module.upstream_name(),
                            &prompt_def.name,
                            description,
                        );
                    }
                }

                builder = builder.merge_tool_operations(module.tool_operations().clone());
                builder = builder.merge_tool_classifications(module.tool_classifications().clone());
                builder = builder.upstream_module(&upstream_cfg.name);

                if !upstream_cfg.tool_class.is_empty() {
                    let mut classes = std::collections::HashMap::new();
                    for (tool_name, tc) in &upstream_cfg.tool_class {
                        match (tc.domain.parse(), tc.operation.parse()) {
                            (Ok(domain), Ok(operation)) => {
                                classes.insert(
                                    tool_name.clone(),
                                    navra_core::permissions::ResourceClass::new(domain, operation),
                                );
                            }
                            (Err(e), _) | (_, Err(e)) => {
                                tracing::error!(
                                    upstream = %upstream_cfg.name,
                                    tool = %tool_name,
                                    "Invalid tool_class: {e}, skipping"
                                );
                            }
                        }
                    }
                    if !classes.is_empty() {
                        tracing::info!(
                            upstream = %upstream_cfg.name,
                            overrides = classes.len(),
                            "Upstream tool classification overrides"
                        );
                        builder = builder.merge_tool_classifications(classes);
                    }
                }

                // Register tool-to-domain mapping for policy sync.
                if let Some(registry) = endpoint_registry {
                    let tool_names: Vec<String> =
                        module.tool_operations().keys().cloned().collect();
                    let domains = upstream_cfg
                        .network
                        .as_ref()
                        .map(|n| n.allowed_domains.clone())
                        .or_else(|| {
                            crate::network_discovery::known_server_domains(
                                &upstream_cfg.name,
                                &upstream_cfg.command,
                            )
                        })
                        .unwrap_or_default();
                    if !domains.is_empty() {
                        tracing::debug!(
                            upstream = %upstream_cfg.name,
                            tools = tool_names.len(),
                            domains = domains.len(),
                            "Registered tool-to-domain mapping"
                        );
                        registry.register_upstream(&tool_names, domains);
                    }
                }

                builder = builder.module(module);
            }
            Err(e) => {
                tracing::error!(
                    upstream = %upstream_cfg.name,
                    error = %e,
                    "Failed to connect upstream, skipping"
                );
            }
        }
    }

    builder
}

/// Wire an OpenAPI bridge upstream (no MCP transport needed).
async fn wire_openapi_upstream(
    mut builder: navra_core::McpServerBuilder,
    upstream_cfg: &config::UpstreamConfig,
    spec_source: &str,
) -> navra_core::McpServerBuilder {
    let auth = util::resolve_openapi_auth(&upstream_cfg.auth);
    let spec_source = util::resolve_env_vars(spec_source);
    let timeout = upstream_cfg
        .request_timeout_secs
        .map(std::time::Duration::from_secs);
    let max_response_bytes = upstream_cfg.max_response_bytes.or(Some(32768));
    match navra_openapi::OpenApiModule::from_spec_with_timeout(
        &upstream_cfg.name,
        &spec_source,
        auth,
        &upstream_cfg.tool_filter,
        timeout,
        max_response_bytes,
    )
    .await
    {
        Ok(mut module) => {
            if !upstream_cfg.tool_overrides.is_empty() {
                module.apply_overrides(&upstream_cfg.tool_overrides);
            }

            tracing::info!(
                upstream = %upstream_cfg.name,
                tools = module.tool_count(),
                "Connected OpenAPI upstream"
            );

            let mut ops = module.tool_operations();
            for (tool_name, override_str) in &upstream_cfg.tool_overrides {
                match override_str.as_str() {
                    "read" => {
                        ops.insert(tool_name.clone(), navra_core::ToolOperation::Read);
                    }
                    "write" => {
                        ops.insert(tool_name.clone(), navra_core::ToolOperation::Write);
                    }
                    "deny" => {
                        ops.insert(tool_name.clone(), navra_core::ToolOperation::Deny);
                    }
                    _ => {
                        tracing::warn!(
                            upstream = %upstream_cfg.name,
                            tool = %tool_name,
                            value = %override_str,
                            "Invalid tool_overrides value, expected read/write/deny"
                        );
                    }
                }
            }
            builder = builder.merge_tool_operations(ops);

            if !upstream_cfg.tool_class.is_empty() {
                let mut classes = std::collections::HashMap::new();
                for (tool_name, tc) in &upstream_cfg.tool_class {
                    match (tc.domain.parse(), tc.operation.parse()) {
                        (Ok(domain), Ok(operation)) => {
                            classes.insert(
                                tool_name.clone(),
                                navra_core::permissions::ResourceClass::new(domain, operation),
                            );
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            tracing::error!(
                                upstream = %upstream_cfg.name,
                                tool = %tool_name,
                                "Invalid tool_class: {e}, skipping"
                            );
                        }
                    }
                }
                if !classes.is_empty() {
                    builder = builder.merge_tool_classifications(classes);
                }
            }

            builder = builder.module(module);
        }
        Err(e) => {
            tracing::error!(
                upstream = %upstream_cfg.name,
                error = %e,
                "Failed to parse OpenAPI spec, skipping"
            );
        }
    }

    builder
}

/// Connect a stdio-transport upstream.
async fn wire_stdio_upstream(
    upstream_cfg: &config::UpstreamConfig,
    credential_store: &Arc<navra_core::credentials::MappedCredentialStore>,
) -> Result<navra_core::UpstreamModule, String> {
    let mut cmd = tokio::process::Command::new(&upstream_cfg.command[0]);
    for arg in &upstream_cfg.command[1..] {
        cmd.arg(arg);
    }
    if let Some(ref cwd) = upstream_cfg.cwd {
        cmd.current_dir(cwd);
    }
    for (key, val) in &upstream_cfg.env {
        cmd.env(key, val);
    }
    for (env_var, label) in &upstream_cfg.credentials {
        match credential_store.resolve(label) {
            Ok(secret) => {
                if let Some(val) = secret.as_str() {
                    cmd.env(env_var, val);
                    tracing::debug!(
                        upstream = %upstream_cfg.name,
                        env = %env_var,
                        label = %label,
                        "Credential injected"
                    );
                } else {
                    tracing::warn!(
                        upstream = %upstream_cfg.name,
                        label = %label,
                        "Credential is not valid UTF-8, skipping"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    upstream = %upstream_cfg.name,
                    label = %label,
                    error = %e,
                    "Failed to resolve credential, upstream may fail"
                );
            }
        }
    }
    match rmcp::transport::TokioChildProcess::new(cmd) {
        Ok(transport) => {
            match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await {
                Ok(client) => {
                    let peer = client.peer().clone();
                    tokio::spawn(async move {
                        let _ = client.waiting().await;
                    });
                    Ok(navra_core::UpstreamModule::discover(
                        &upstream_cfg.name,
                        peer,
                        None,
                        &upstream_cfg.tool_overrides,
                    )
                    .await)
                }
                Err(e) => Err(format!("rmcp init failed: {e}")),
            }
        }
        Err(e) => Err(format!("spawn failed: {e}")),
    }
}

/// Connect an HTTP/SSE/streamable-HTTP upstream.
async fn wire_http_upstream(
    upstream_cfg: &config::UpstreamConfig,
) -> Result<navra_core::UpstreamModule, String> {
    let url = match &upstream_cfg.url {
        Some(u) => u.as_str(),
        None => {
            return Err(format!(
                "HTTP/SSE upstream '{}' requires 'url' field",
                upstream_cfg.name
            ));
        }
    };
    let transport = rmcp::transport::StreamableHttpClientTransport::from_uri(url);
    match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await {
        Ok(client) => {
            let peer = client.peer().clone();
            tokio::spawn(async move {
                let _ = client.waiting().await;
            });
            Ok(navra_core::UpstreamModule::discover(
                &upstream_cfg.name,
                peer,
                None,
                &upstream_cfg.tool_overrides,
            )
            .await)
        }
        Err(e) => Err(format!("rmcp init failed: {e}")),
    }
}
