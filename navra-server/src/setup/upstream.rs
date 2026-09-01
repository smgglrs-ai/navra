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
                wire_http_upstream(upstream_cfg, upstream_cfg.tls.as_ref()).await
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
    tls_config: Option<&navra_protocol::TlsConfig>,
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

    let transport = if let Some(tls) = tls_config {
        let client = build_tls_client(tls, &upstream_cfg.name)?;
        let config = rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(url);
        rmcp::transport::StreamableHttpClientTransport::with_client(client, config)
    } else {
        rmcp::transport::StreamableHttpClientTransport::from_uri(url)
    };

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

/// Build a reqwest client with custom TLS settings.
fn build_tls_client(
    tls: &navra_protocol::TlsConfig,
    upstream_name: &str,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::ClientBuilder::new();

    if let Some(ca_path) = &tls.ca_cert {
        let pem = std::fs::read(ca_path)
            .map_err(|e| format!("upstream '{upstream_name}': failed to read CA cert {ca_path}: {e}"))?;
        let cert = reqwest::tls::Certificate::from_pem(&pem)
            .map_err(|e| format!("upstream '{upstream_name}': invalid CA cert PEM: {e}"))?;
        builder = builder.add_root_certificate(cert);
        tracing::info!(upstream = %upstream_name, ca = %ca_path, "Custom CA certificate loaded");
    }

    match (&tls.client_cert, &tls.client_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path)
                .map_err(|e| format!("upstream '{upstream_name}': failed to read client cert {cert_path}: {e}"))?;
            let key_pem = std::fs::read(key_path)
                .map_err(|e| format!("upstream '{upstream_name}': failed to read client key {key_path}: {e}"))?;
            let mut combined = cert_pem;
            combined.extend_from_slice(b"\n");
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::tls::Identity::from_pem(&combined)
                .map_err(|e| format!("upstream '{upstream_name}': invalid client certificate/key: {e}"))?;
            builder = builder.identity(identity);
            tracing::info!(upstream = %upstream_name, "Mutual TLS client certificate loaded");
        }
        (Some(_), None) => {
            tracing::warn!(
                upstream = %upstream_name,
                "mTLS not configured: client_cert is set but client_key is missing — both are required"
            );
        }
        (None, Some(_)) => {
            tracing::warn!(
                upstream = %upstream_name,
                "mTLS not configured: client_key is set but client_cert is missing — both are required"
            );
        }
        (None, None) => {}
    }

    if tls.danger_skip_verify {
        tracing::warn!(upstream = %upstream_name, "TLS certificate verification DISABLED — development only");
        builder = builder.danger_accept_invalid_certs(true);
    }

    builder
        .build()
        .map_err(|e| format!("upstream '{upstream_name}': failed to build TLS client: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_tls_client_default_succeeds() {
        let tls = navra_protocol::TlsConfig::default();
        let client = build_tls_client(&tls, "test");
        assert!(client.is_ok());
    }

    #[test]
    fn build_tls_client_skip_verify_succeeds() {
        let tls = navra_protocol::TlsConfig {
            danger_skip_verify: true,
            ..Default::default()
        };
        let client = build_tls_client(&tls, "test");
        assert!(client.is_ok());
    }

    #[test]
    fn build_tls_client_missing_ca_cert_fails() {
        let tls = navra_protocol::TlsConfig {
            ca_cert: Some("/nonexistent/ca.pem".to_string()),
            ..Default::default()
        };
        let result = build_tls_client(&tls, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to read CA cert"));
    }

    #[test]
    fn build_tls_client_missing_client_cert_fails() {
        let tls = navra_protocol::TlsConfig {
            client_cert: Some("/nonexistent/client.pem".to_string()),
            client_key: Some("/nonexistent/key.pem".to_string()),
            ..Default::default()
        };
        let result = build_tls_client(&tls, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to read client cert"));
    }

    #[test]
    fn mtls_half_config_cert_without_key_warns() {
        // When client_cert is set but client_key is missing, the function
        // should succeed (no mTLS configured) but log a warning.
        // We verify it doesn't panic and the client is still usable.
        let tls = navra_protocol::TlsConfig {
            client_cert: Some("/some/cert.pem".to_string()),
            client_key: None,
            ..Default::default()
        };
        let result = build_tls_client(&tls, "half-config");
        assert!(result.is_ok(), "half-configured mTLS should not error");
    }

    #[test]
    fn mtls_half_config_key_without_cert_warns() {
        // When client_key is set but client_cert is missing, same behavior.
        let tls = navra_protocol::TlsConfig {
            client_cert: None,
            client_key: Some("/some/key.pem".to_string()),
            ..Default::default()
        };
        let result = build_tls_client(&tls, "half-config");
        assert!(result.is_ok(), "half-configured mTLS should not error");
    }

    #[test]
    fn tls_config_deserializes_from_toml() {
        let toml_str = r#"
            ca_cert = "/etc/pki/ca.pem"
            client_cert = "/etc/pki/client.pem"
            client_key = "/etc/pki/key.pem"
            danger_skip_verify = false
        "#;
        let tls: navra_protocol::TlsConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(tls.ca_cert.as_deref(), Some("/etc/pki/ca.pem"));
        assert_eq!(tls.client_cert.as_deref(), Some("/etc/pki/client.pem"));
        assert_eq!(tls.client_key.as_deref(), Some("/etc/pki/key.pem"));
        assert!(!tls.danger_skip_verify);
    }
}
