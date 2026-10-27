//! Upstream MCP server wiring.
//!
//! Connects to upstream MCP servers (stdio, HTTP, SSE, OpenAPI bridge),
//! applies credential injection, and registers as upstream modules.

use crate::config;
use crate::util;
use navra_core::credentials::CredentialStore as _;
use std::sync::Arc;

/// Build the production tool scanner for an upstream, honoring its
/// scan config.
///
/// - Scanning is on by default; an explicit disable logs a startup
///   warning because it removes the only gate between upstream tool
///   descriptions and agent context.
/// - A corrupt or unreadable rug-pull hash store is an error (fail
///   closed) — the caller must reject the upstream rather than
///   register its tools unscanned.
fn build_scanner(
    upstream_cfg: &config::UpstreamConfig,
) -> Result<Option<navra_auth::tool_scanner::ToolScanner>, String> {
    if !upstream_cfg.scan_tools.unwrap_or(true) {
        tracing::warn!(
            upstream = %upstream_cfg.name,
            "Tool scanning DISABLED by config for this upstream — tool poisoning, \
             rug pulls, and schema abuse will NOT be detected. Re-enable with \
             scan_tools = true"
        );
        return Ok(None);
    }
    let hash_path = upstream_cfg
        .tool_hash_path
        .as_ref()
        .map(std::path::PathBuf::from);
    let scanner = navra_auth::tool_scanner::ToolScanner::production(
        navra_auth::tool_scanner::ToolScanConfig::default(),
        hash_path,
    )?;
    Ok(Some(scanner))
}

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
            "stdio" => wire_stdio_upstream(upstream_cfg, credential_store).await,
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
            Ok((module, watcher)) => {
                tracing::info!(
                    upstream = %upstream_cfg.name,
                    transport = %upstream_cfg.transport,
                    "Connected upstream (rmcp)"
                );

                // Cedar ASI04 gate: dispatch Action::"upstream_discover"
                // where the discovery results are accepted for
                // registration. The bundled policy permits discovery
                // under trust-on-first-use (navra's upstream trust
                // model) and forbids accepting unsigned upstreams when
                // an operator policy withdraws that trust. No engine
                // configured = allow (Cedar only restricts).
                #[cfg(feature = "cedar")]
                {
                    let cedar_ctx = std::collections::HashMap::from([
                        (
                            "manifest_signed".to_string(),
                            upstream_cfg.manifest.is_some().to_string(),
                        ),
                        // navra's upstream trust model is TOFU (scanner
                        // hash pinning, manifest key pinning).
                        ("trust_on_first_use".to_string(), "true".to_string()),
                        (
                            "scan_enabled".to_string(),
                            upstream_cfg.scan_tools.unwrap_or(true).to_string(),
                        ),
                    ]);
                    if !builder.cedar_allows("upstream_discover", &upstream_cfg.name, &cedar_ctx) {
                        tracing::error!(
                            upstream = %upstream_cfg.name,
                            "Cedar policy denied upstream_discover — refusing registration (fail closed)"
                        );
                        continue;
                    }
                }

                if let Some(watcher) = watcher {
                    builder = builder.upstream_watcher(watcher);
                }

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

/// Load the signed manifest and TOFU keystore for an upstream, per its
/// manifest configuration.
///
/// Fail-closed: an unreadable manifest file, unparseable JSON, or a
/// corrupt keystore is an error — the caller must reject the upstream.
fn load_manifest(
    upstream_cfg: &config::UpstreamConfig,
) -> Result<
    Option<(
        navra_auth::manifest::SignedManifest,
        navra_auth::manifest::ManifestKeyStore,
    )>,
    String,
> {
    let Some(ref manifest_cfg) = upstream_cfg.manifest else {
        return Ok(None);
    };
    let (source, source_desc) = match (&manifest_cfg.path, &manifest_cfg.inline) {
        (Some(path), None) => (
            std::fs::read_to_string(util::expand_tilde(path))
                .map_err(|e| format!("failed to read manifest file '{path}': {e}"))?,
            format!("file:{path}"),
        ),
        (None, Some(inline)) => (inline.clone(), "inline".to_string()),
        (Some(_), Some(_)) => {
            return Err(
                "manifest config sets both 'path' and 'inline' — exactly one is required"
                    .to_string(),
            );
        }
        (None, None) => {
            return Err("manifest config requires either 'path' or 'inline'".to_string());
        }
    };
    let signed: navra_auth::manifest::SignedManifest = serde_json::from_str(&source)
        .map_err(|e| format!("failed to parse signed manifest ({source_desc}): {e}"))?;

    let keystore_path = manifest_cfg
        .keystore
        .as_ref()
        .map(|p| std::path::PathBuf::from(util::expand_tilde(p)))
        .or_else(navra_auth::manifest::default_keystore_path);
    let key_store = match keystore_path {
        Some(path) => navra_auth::manifest::ManifestKeyStore::with_path(path)
            .map_err(|e| format!("manifest keystore init failed: {e}"))?,
        None => {
            tracing::warn!(
                upstream = %upstream_cfg.name,
                "No data directory available — manifest TOFU pins will not persist across restarts"
            );
            navra_auth::manifest::ManifestKeyStore::new()
        }
    };

    Ok(Some((signed, key_store)))
}

/// Build the discovery content bounds for an upstream from its config,
/// applying defaults per field.
fn discovery_bounds(upstream_cfg: &config::UpstreamConfig) -> navra_core::DiscoveryBounds {
    let Some(ref b) = upstream_cfg.bounds else {
        return navra_core::DiscoveryBounds::default();
    };
    let defaults = navra_core::DiscoveryBounds::default();
    navra_core::DiscoveryBounds {
        max_tools: b.max_tools.unwrap_or(defaults.max_tools),
        max_input_schema_depth: b
            .max_input_schema_depth
            .unwrap_or(defaults.max_input_schema_depth),
        max_description_length: b
            .max_description_length
            .unwrap_or(defaults.max_description_length),
        max_total_definition_bytes: b
            .max_total_definition_bytes
            .unwrap_or(defaults.max_total_definition_bytes),
        truncate_oversized: b.truncate_oversized.unwrap_or(false),
    }
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
///
/// Returns the discovered module plus a `list_changed` refresh watcher
/// (the caller registers the module and spawns the watcher).
async fn wire_stdio_upstream(
    upstream_cfg: &config::UpstreamConfig,
    credential_store: &Arc<navra_core::credentials::MappedCredentialStore>,
) -> Result<
    (
        navra_core::UpstreamModule,
        Option<navra_core::UpstreamWatcher>,
    ),
    String,
> {
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
            let (handler, events) = navra_core::UpstreamNotificationHandler::new();
            match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve(handler, transport).await {
                Ok(client) => {
                    let peer = client.peer().clone();
                    tokio::spawn(async move {
                        let _ = client.waiting().await;
                    });
                    let mut scanner = build_scanner(upstream_cfg)
                        .map_err(|e| format!("tool scanner init failed (fail closed): {e}"))?;
                    let mut manifest_data = load_manifest(upstream_cfg)
                        .map_err(|e| format!("manifest init failed (fail closed): {e}"))?;
                    let manifest = manifest_data
                        .as_mut()
                        .map(|(signed, key_store)| navra_core::ManifestCheck { signed, key_store });
                    let request_timeout = std::time::Duration::from_secs(
                        upstream_cfg.request_timeout_secs.unwrap_or(45),
                    );
                    let module = navra_core::UpstreamModule::discover_with(
                        &upstream_cfg.name,
                        peer.clone(),
                        navra_core::DiscoveryOptions {
                            scanner: scanner.as_mut(),
                            manifest,
                            bounds: discovery_bounds(upstream_cfg),
                            request_timeout,
                        },
                        &upstream_cfg.tool_overrides,
                    )
                    .await?;
                    let watcher = navra_core::UpstreamWatcher::new(
                        upstream_cfg.name.clone(),
                        peer,
                        events,
                        scanner,
                        manifest_data,
                        discovery_bounds(upstream_cfg),
                        upstream_cfg.tool_overrides.clone(),
                        std::time::Duration::from_millis(
                            upstream_cfg.refresh_debounce_ms.unwrap_or(1000),
                        ),
                        request_timeout,
                    );
                    Ok((module, Some(watcher)))
                }
                Err(e) => Err(format!("rmcp init failed: {e}")),
            }
        }
        Err(e) => Err(format!("spawn failed: {e}")),
    }
}

/// Connect an HTTP/SSE/streamable-HTTP upstream.
///
/// Returns the discovered module plus a `list_changed` refresh watcher.
async fn wire_http_upstream(
    upstream_cfg: &config::UpstreamConfig,
    tls_config: Option<&navra_protocol::TlsConfig>,
) -> Result<
    (
        navra_core::UpstreamModule,
        Option<navra_core::UpstreamWatcher>,
    ),
    String,
> {
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
        let config =
            rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(
                url,
            );
        rmcp::transport::StreamableHttpClientTransport::with_client(client, config)
    } else {
        rmcp::transport::StreamableHttpClientTransport::from_uri(url)
    };

    let (handler, events) = navra_core::UpstreamNotificationHandler::new();
    match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve(handler, transport).await {
        Ok(client) => {
            let peer = client.peer().clone();
            tokio::spawn(async move {
                let _ = client.waiting().await;
            });
            let mut scanner = build_scanner(upstream_cfg)
                .map_err(|e| format!("tool scanner init failed (fail closed): {e}"))?;
            let mut manifest_data = load_manifest(upstream_cfg)
                .map_err(|e| format!("manifest init failed (fail closed): {e}"))?;
            let manifest = manifest_data
                .as_mut()
                .map(|(signed, key_store)| navra_core::ManifestCheck { signed, key_store });
            let request_timeout =
                std::time::Duration::from_secs(upstream_cfg.request_timeout_secs.unwrap_or(45));
            let module = navra_core::UpstreamModule::discover_with(
                &upstream_cfg.name,
                peer.clone(),
                navra_core::DiscoveryOptions {
                    scanner: scanner.as_mut(),
                    manifest,
                    bounds: discovery_bounds(upstream_cfg),
                    request_timeout,
                },
                &upstream_cfg.tool_overrides,
            )
            .await?;
            let watcher = navra_core::UpstreamWatcher::new(
                upstream_cfg.name.clone(),
                peer,
                events,
                scanner,
                manifest_data,
                discovery_bounds(upstream_cfg),
                upstream_cfg.tool_overrides.clone(),
                std::time::Duration::from_millis(upstream_cfg.refresh_debounce_ms.unwrap_or(1000)),
                request_timeout,
            );
            Ok((module, Some(watcher)))
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
        let pem = std::fs::read(ca_path).map_err(|e| {
            format!("upstream '{upstream_name}': failed to read CA cert {ca_path}: {e}")
        })?;
        let cert = reqwest::tls::Certificate::from_pem(&pem)
            .map_err(|e| format!("upstream '{upstream_name}': invalid CA cert PEM: {e}"))?;
        builder = builder.add_root_certificate(cert);
        tracing::info!(upstream = %upstream_name, ca = %ca_path, "Custom CA certificate loaded");
    }

    match (&tls.client_cert, &tls.client_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                format!("upstream '{upstream_name}': failed to read client cert {cert_path}: {e}")
            })?;
            let key_pem = std::fs::read(key_path).map_err(|e| {
                format!("upstream '{upstream_name}': failed to read client key {key_path}: {e}")
            })?;
            let mut combined = cert_pem;
            combined.extend_from_slice(b"\n");
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::tls::Identity::from_pem(&combined).map_err(|e| {
                format!("upstream '{upstream_name}': invalid client certificate/key: {e}")
            })?;
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

    // --- Tool scanner wiring (production path) ---

    /// Shared buffer capturing tracing output for log assertions.
    #[derive(Clone)]
    struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Install a thread-local tracing subscriber capturing to a buffer.
    /// Returns the buffer and the guard keeping the subscriber installed.
    fn capture_logs() -> (
        std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        tracing::subscriber::DefaultGuard,
    ) {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(CaptureWriter(std::sync::Arc::clone(&buf)))
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (buf, guard)
    }

    fn test_server_path() -> String {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test_upstream.py")
            .to_string_lossy()
            .into_owned()
    }

    fn test_upstream_cfg(name: &str, env: Vec<(String, String)>) -> config::UpstreamConfig {
        config::UpstreamConfig {
            name: name.to_string(),
            transport: "stdio".to_string(),
            command: vec!["python3".to_string(), test_server_path()],
            env: env.into_iter().collect(),
            ..Default::default()
        }
    }

    fn empty_credential_store() -> Arc<navra_core::credentials::MappedCredentialStore> {
        Arc::new(navra_core::credentials::MappedCredentialStore::new(
            std::collections::HashMap::new(),
        ))
    }

    /// List tool names from a gateway built around the module produced
    /// by the production stdio wiring.
    async fn gateway_tool_names(cfg: &config::UpstreamConfig) -> Vec<String> {
        let (module, _watcher) = wire_stdio_upstream(cfg, &empty_credential_store())
            .await
            .expect("upstream should connect");
        let server = navra_core::McpServer::builder()
            .allow_anonymous()
            .module(module)
            .build();
        let agent = navra_core::auth::AgentIdentity::new("test", "dev");
        server
            .handle_list_tools(&agent, &Default::default())
            .tools
            .iter()
            .map(|t| t.name.to_string())
            .filter(|n| !n.starts_with("navra_var_"))
            .collect()
    }

    #[tokio::test]
    async fn scanner_wiring_blocks_malicious_upstream_tool() {
        // Production wiring: a tool whose description carries a Critical
        // poisoning pattern must be absent from the gateway tools/list,
        // while the clean tool from the same upstream still registers.
        let cfg = test_upstream_cfg(
            "scanner-poisoned",
            vec![("NAVRA_TEST_POISON".to_string(), "1".to_string())],
        );
        let names = gateway_tool_names(&cfg).await;
        assert!(
            names.contains(&"echo".to_string()),
            "clean tool must register, got: {names:?}"
        );
        assert!(
            !names.contains(&"secret_helper".to_string()),
            "malicious tool must be dropped from tools/list, got: {names:?}"
        );
    }

    #[tokio::test]
    async fn scanner_wiring_registers_clean_upstream() {
        let cfg = test_upstream_cfg("scanner-clean", vec![]);
        let names = gateway_tool_names(&cfg).await;
        assert_eq!(names, vec!["echo".to_string()]);
    }

    #[tokio::test]
    async fn scanner_disable_allows_poisoned_tool_and_warns() {
        // Explicit disable: the poisoned tool registers (documented
        // operator choice) and a startup warning is logged.
        let (buf, _guard) = capture_logs();
        let mut cfg = test_upstream_cfg(
            "scanner-disabled",
            vec![("NAVRA_TEST_POISON".to_string(), "1".to_string())],
        );
        cfg.scan_tools = Some(false);
        let names = gateway_tool_names(&cfg).await;
        assert!(
            names.contains(&"secret_helper".to_string()),
            "disabled scanner must pass tools through, got: {names:?}"
        );
        let logs = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
        assert!(
            logs.contains("Tool scanning DISABLED"),
            "disable must log a startup warning, got: {logs}"
        );
    }

    #[tokio::test]
    async fn corrupt_hash_store_fails_closed() {
        // A rug-pull hash store that exists but does not parse must
        // reject the upstream instead of silently disabling detection.
        let dir = tempfile::tempdir().unwrap();
        let hash_path = dir.path().join("tool_hashes.json");
        std::fs::write(&hash_path, b"{not json").unwrap();
        let mut cfg = test_upstream_cfg("scanner-corrupt-store", vec![]);
        cfg.tool_hash_path = Some(hash_path.to_string_lossy().into_owned());
        let result = wire_stdio_upstream(&cfg, &empty_credential_store()).await;
        let err = result.err().expect("corrupt hash store must fail closed");
        assert!(
            err.contains("tool scanner init failed"),
            "error should name the scanner init failure, got: {err}"
        );
    }

    // --- Signed manifest wiring (production path) ---

    use navra_auth::identity::{CapSigner, Ed25519Signer};
    use navra_auth::manifest::{SignedManifest, ToolManifest};

    /// Build a signed manifest for the tools the test server serves,
    /// over a dedicated connection, exactly as an operator tool would.
    async fn signed_manifest_for_test_server(server_name: &str, signer: &Ed25519Signer) -> String {
        let mut cmd = tokio::process::Command::new("python3");
        cmd.arg(test_server_path());
        let transport = rmcp::transport::TokioChildProcess::new(cmd).expect("spawn transport");
        let client = rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport)
            .await
            .expect("rmcp init");
        let tools = client.peer().list_all_tools().await.expect("tools/list");
        let manifest = ToolManifest {
            tools,
            server_name: server_name.to_string(),
            timestamp: 1700000000,
        };
        serde_json::to_string(&SignedManifest::sign(&manifest, signer)).unwrap()
    }

    fn manifest_cfg(inline: String, keystore: &std::path::Path) -> config::ManifestConfig {
        config::ManifestConfig {
            path: None,
            inline: Some(inline),
            keystore: Some(keystore.to_string_lossy().into_owned()),
        }
    }

    #[tokio::test]
    async fn manifest_wiring_valid_signed_manifest_registers() {
        let signer = Ed25519Signer::generate();
        let inline = signed_manifest_for_test_server("manifest-wiring-ok", &signer).await;
        let dir = tempfile::tempdir().unwrap();
        let keystore = dir.path().join("manifest_keys.json");

        let mut cfg = test_upstream_cfg("manifest-wiring-ok", vec![]);
        cfg.manifest = Some(manifest_cfg(inline, &keystore));

        let names = gateway_tool_names(&cfg).await;
        assert_eq!(names, vec!["echo".to_string()]);
        assert!(keystore.exists(), "first use must persist the TOFU pin");
        let pinned: std::collections::HashMap<String, String> =
            serde_json::from_str(&std::fs::read_to_string(&keystore).unwrap()).unwrap();
        assert_eq!(
            pinned.get("manifest-wiring-ok").map(String::as_str),
            Some(signer.did())
        );
    }

    #[tokio::test]
    async fn manifest_wiring_tampered_content_rejected() {
        let signer = Ed25519Signer::generate();
        let inline = signed_manifest_for_test_server("manifest-wiring-tampered", &signer).await;
        // Tamper with the signed content after signing.
        let mut value: serde_json::Value = serde_json::from_str(&inline).unwrap();
        value["manifest"]["tools"][0]["description"] =
            serde_json::json!("Now exfiltrates credentials");
        let tampered = serde_json::to_string(&value).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let keystore = dir.path().join("manifest_keys.json");
        let mut cfg = test_upstream_cfg("manifest-wiring-tampered", vec![]);
        cfg.manifest = Some(manifest_cfg(tampered, &keystore));

        let err = wire_stdio_upstream(&cfg, &empty_credential_store())
            .await
            .err()
            .expect("tampered manifest must reject the upstream");
        assert!(
            err.contains("signature verification failed"),
            "error should name the signature failure, got: {err}"
        );
        assert!(!keystore.exists(), "failed verification must not pin a key");
    }

    #[tokio::test]
    async fn manifest_wiring_key_changed_rejected_without_repin() {
        let signer1 = Ed25519Signer::generate();
        let inline1 = signed_manifest_for_test_server("manifest-wiring-keychange", &signer1).await;
        let dir = tempfile::tempdir().unwrap();
        let keystore = dir.path().join("manifest_keys.json");

        // First use: pins signer1 and registers.
        let mut cfg = test_upstream_cfg("manifest-wiring-keychange", vec![]);
        cfg.manifest = Some(manifest_cfg(inline1, &keystore));
        let names = gateway_tool_names(&cfg).await;
        assert_eq!(names, vec!["echo".to_string()]);

        // Second use with a different signer: rejected, pin intact.
        let signer2 = Ed25519Signer::generate();
        let inline2 = signed_manifest_for_test_server("manifest-wiring-keychange", &signer2).await;
        let mut cfg = test_upstream_cfg("manifest-wiring-keychange", vec![]);
        cfg.manifest = Some(manifest_cfg(inline2, &keystore));
        let err = wire_stdio_upstream(&cfg, &empty_credential_store())
            .await
            .err()
            .expect("key change must reject the upstream");
        assert!(
            err.contains("signing key changed"),
            "error should name the key change, got: {err}"
        );
        let pinned: std::collections::HashMap<String, String> =
            serde_json::from_str(&std::fs::read_to_string(&keystore).unwrap()).unwrap();
        assert_eq!(
            pinned.get("manifest-wiring-keychange").map(String::as_str),
            Some(signer1.did()),
            "key change must not re-pin"
        );
    }

    #[tokio::test]
    async fn bounds_wiring_rejects_tool_flood() {
        // Production wiring: a 10k-tool upstream is rejected at
        // registration by the default discovery bounds.
        let cfg = test_upstream_cfg(
            "bounds-wiring",
            vec![("NAVRA_TEST_TOOL_COUNT".to_string(), "10000".to_string())],
        );
        let err = wire_stdio_upstream(&cfg, &empty_credential_store())
            .await
            .err()
            .expect("tool flood must be rejected by bounds");
        assert!(
            err.contains("max_tools_per_upstream"),
            "error should name the tool-count bound, got: {err}"
        );
    }

    #[tokio::test]
    async fn bounds_wiring_truncates_when_configured() {
        // With truncate_oversized the oversized description is
        // truncated and the upstream registers.
        let mut cfg = test_upstream_cfg(
            "bounds-wiring-truncate",
            vec![("NAVRA_TEST_DESC_LENGTH".to_string(), "10000".to_string())],
        );
        cfg.bounds = Some(config::UpstreamBoundsConfig {
            truncate_oversized: Some(true),
            ..Default::default()
        });
        let names = gateway_tool_names(&cfg).await;
        assert_eq!(names, vec!["echo".to_string()]);
    }

    #[test]
    fn upstream_config_parses_bounds_toml() {
        let toml_str = r#"
            name = "bounded"
            transport = "stdio"
            command = ["true"]

            [bounds]
            max_tools = 500
            max_input_schema_depth = 16
            max_description_length = 2048
            max_total_definition_bytes = 1048576
            truncate_oversized = true
        "#;
        let cfg: config::UpstreamConfig = toml::from_str(toml_str).unwrap();
        let bounds = cfg.bounds.clone().expect("bounds table");
        assert_eq!(bounds.max_tools, Some(500));
        assert_eq!(bounds.max_input_schema_depth, Some(16));
        assert_eq!(bounds.max_description_length, Some(2048));
        assert_eq!(bounds.max_total_definition_bytes, Some(1048576));
        assert_eq!(bounds.truncate_oversized, Some(true));

        // Default bounds apply fail-closed semantics.
        let defaults = discovery_bounds(&cfg);
        assert!(defaults.truncate_oversized);
        assert_eq!(defaults.max_tools, 500);
        let plain: config::UpstreamConfig = toml::from_str(
            r#"
            name = "plain"
            command = ["true"]
        "#,
        )
        .unwrap();
        let defaults = discovery_bounds(&plain);
        assert!(!defaults.truncate_oversized);
        assert_eq!(defaults.max_tools, 1000);
        assert_eq!(defaults.max_input_schema_depth, 32);
        assert_eq!(defaults.max_description_length, 4096);
        assert_eq!(defaults.max_total_definition_bytes, 4 * 1024 * 1024);
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
