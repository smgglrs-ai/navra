//! Transport setup: server build, axum router, socket binding,
//! system tray, mDNS advertising, and shutdown signal handling.

use crate::config;
use crate::{flow_api, flow_tools, mdns, tray, ui, ui_events};
use navra_core::identity::{CapSigner, Ed25519Signer};
use std::sync::Arc;

/// All state the transport layer needs from `serve_inner`.
pub(crate) struct TransportState {
    pub(crate) server: Arc<navra_core::McpServer>,
    pub(crate) broadcaster: navra_core::transport::SseBroadcaster,
    pub(crate) cfg: config::Config,
    pub(crate) root_signer: Arc<Ed25519Signer>,
    pub(crate) approvals: Arc<navra_core::permissions::ApprovalStore>,
    pub(crate) flow_registry: Arc<flow_tools::FlowRegistry>,
    pub(crate) resolved_flow_dirs: Vec<String>,
    pub(crate) models: std::collections::HashMap<String, Arc<dyn navra_model::ModelBackend>>,
    pub(crate) trigger_webhook_router: Option<axum::Router>,
    pub(crate) rag_context_retriever: Option<Arc<dyn navra_agent::ContextRetriever>>,
    pub(crate) pii_metrics: Option<Arc<navra_core::safety::PiiMetrics>>,
    pub(crate) mdns_enabled: bool,
}

/// Run the HTTP transport: build router, bind sockets, run until shutdown.
///
/// Returns when the server shuts down (SIGINT/SIGTERM).
pub(crate) async fn run_http_transport(
    state: TransportState,
    no_tray: bool,
) -> anyhow::Result<()> {
    // Keep the mDNS daemon alive for advertising — drop stops it.
    let mut _mdns_daemon: Option<mdns_sd::ServiceDaemon> = None;

    // --- mDNS advertising ---
    if state.mdns_enabled {
        let tcp_port = state
            .cfg
            .server
            .tcp
            .as_ref()
            .and_then(|addr| addr.rsplit(':').next())
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(9315);

        match mdns::advertise(&state.server.server_info().name, tcp_port, "/mcp") {
            Ok(daemon) => {
                tracing::info!(port = tcp_port, "Advertising via mDNS on _mcp._tcp.local.");
                _mdns_daemon = Some(daemon);
            }
            Err(e) => {
                tracing::warn!("mDNS advertising failed: {e}");
            }
        }
    }

    // --- System tray ---
    if !no_tray {
        match tray::spawn_tray().await {
            Ok((cmd_rx, handle)) => {
                tracing::info!("System tray icon active");
                tokio::spawn(tray::run_tray_updater(
                    handle,
                    state.approvals.clone(),
                    state.server.pause_flag(),
                    cmd_rx,
                ));
            }
            Err(e) => {
                tracing::warn!("System tray unavailable: {e}");
            }
        }
    }

    // --- Build registry entries ---
    let mut registry_entries: Vec<serde_json::Value> = Vec::new();

    if let Some(ref discovery) = state.cfg.server.discovery {
        registry_entries.push(serde_json::json!({
            "server": {
                "name": state.server.server_info().name,
                "description": format!(
                    "{}",
                    discovery.description.as_deref().unwrap_or("navra MCP gateway")
                ),
                "version": state.server.server_info().version,
                "remotes": [{
                    "type": "streamable-http",
                    "url": &discovery.url,
                }],
            },
            "_meta": {
                "source": "self",
            }
        }));
    }

    for entry in &state.cfg.registry {
        registry_entries.push(serde_json::json!({
            "server": {
                "name": &entry.name,
                "description": &entry.description,
                "remotes": [{
                    "type": &entry.remote_type,
                    "url": &entry.url,
                }],
                "repository": entry.repository.as_ref().map(|r| serde_json::json!({"url": r})),
            },
            "_meta": {
                "source": "whitelist",
            }
        }));
    }

    if !registry_entries.is_empty() {
        tracing::info!(
            entries = registry_entries.len(),
            "Registry serving {} entries at /v0.1/servers",
            registry_entries.len()
        );
    }

    // --- HTTP transport with SSE broadcaster ---
    let has_discovery = state.cfg.server.discovery.is_some() || !registry_entries.is_empty();
    let (router, server) = if has_discovery {
        let aid_record = state.cfg.server.discovery.as_ref().map(|discovery| {
            let mut aid = serde_json::json!({
                "v": "aid1",
                "u": &discovery.url,
                "p": "mcp",
                "a": &discovery.auth,
            });
            if let Some(ref desc) = discovery.description {
                aid["s"] = serde_json::json!(desc);
            }
            if let Some(ref docs) = discovery.docs_url {
                aid["d"] = serde_json::json!(docs);
            }
            let pubkey_multibase = format!(
                "z{}",
                bs58::encode({
                    let mut bytes = vec![0xed, 0x01];
                    bytes.extend_from_slice(&state.root_signer.public_key_bytes());
                    bytes
                })
                .into_string()
            );
            aid["k"] = serde_json::json!(pubkey_multibase);
            aid["i"] = serde_json::json!("root-1");
            tracing::info!(
                url = %discovery.url,
                did = %state.root_signer.did(),
                "AID discovery at /.well-known/agent (with PKA)"
            );
            aid
        });
        let a2a_endpoint = state.cfg.server.discovery.as_ref().map(|d| d.url.clone());
        if a2a_endpoint.is_some() {
            tracing::info!("A2A Agent Card at /.well-known/agent.json");
        }
        let root_did_str = Some(state.root_signer.did().to_string());
        let api_server_ref = Arc::clone(&state.server);
        let router = navra_core::transport::build_router_with_discovery(
            state.server,
            state.broadcaster,
            aid_record,
            registry_entries,
            a2a_endpoint,
            root_did_str,
        );
        (router, api_server_ref)
    } else {
        let api_server_ref = Arc::clone(&state.server);
        let router = navra_core::transport::build_router_with_broadcaster(
            state.server,
            state.broadcaster,
        );
        (router, api_server_ref)
    };

    // --- ACP transport ---
    let acp_chat_model: Option<Arc<dyn navra_model::ModelBackend>> = state
        .cfg
        .models
        .iter()
        .find(|(_, m)| m.task == "chat" || m.task == "generate")
        .map(|(name, _)| name.clone())
        .and_then(|name| state.models.get(&name))
        .cloned();

    let acp_flow_summaries = build_acp_flow_summaries(&state.resolved_flow_dirs);

    let acp_router = if let Some(model) = acp_chat_model {
        let dispatcher = Arc::new(crate::acp_agent::AgentDispatcher::new(model));
        tracing::info!(
            flows = acp_flow_summaries.len(),
            "ACP agent-driven dispatcher active"
        );
        navra_core::transport::build_acp_router_with_dispatcher(
            server.clone(),
            dispatcher,
            acp_flow_summaries,
            None,
        )
    } else {
        tracing::info!("ACP tool-only dispatcher (no chat model configured)");
        navra_core::transport::build_acp_router(server.clone())
    };
    let router = router.merge(acp_router);
    tracing::info!("ACP v0.2.0 endpoints at /acp/*");

    // --- Webhook triggers ---
    let router = if let Some(webhook_router) = state.trigger_webhook_router {
        tracing::info!("Webhook trigger routes merged at /hook/{{name}}");
        router.merge(webhook_router)
    } else {
        router
    };

    // --- Flow event log ---
    let flow_event_log = {
        let event_log_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra")
            .join("flow_events.db");
        if let Some(parent) = event_log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match navra_flow::event_log::EventLog::open(&event_log_path) {
            Ok(log) => {
                tracing::info!(path = %event_log_path.display(), "Flow event log opened");
                Some(Arc::new(log))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to open flow event log — SSE disabled");
                None
            }
        }
    };

    // --- Flow graph API ---
    let flow_api =
        flow_api::flow_api_router(Arc::clone(&state.flow_registry), flow_event_log.clone());
    let router = router.merge(flow_api);
    tracing::info!("Flow graph API at /flows/{{id}}/graph, /graph/dot, /graph/bpmn, /events");

    // --- Web UI ---
    let ollama_fallback: Option<String> = if let Ok(resp) = reqwest::Client::new()
        .get("http://localhost:11434/api/tags")
        .send()
        .await
    {
        resp.json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|tags| tags["models"][0]["name"].as_str().map(String::from))
    } else {
        None
    };
    let ui_broadcaster = Arc::new(ui_events::UiBroadcaster::new(256));
    ui_events::start_polling_bridge(Arc::clone(&ui_broadcaster), Arc::clone(&server));
    let config_path = config::Config::find_config_path();
    let config_state = Arc::new(tokio::sync::RwLock::new(state.cfg.clone()));
    let router = ui::attach_ui_routes(
        router,
        &state.cfg,
        &server,
        &state.models,
        ollama_fallback.as_deref(),
        Some(ui_broadcaster),
        state.rag_context_retriever.clone(),
        state.pii_metrics.clone(),
        Arc::clone(&config_state),
        config_path,
    );

    tracing::info!(
        "Web UI at http://localhost:{}",
        state
            .cfg
            .server
            .tcp
            .as_deref()
            .and_then(|a| a.rsplit(':').next())
            .unwrap_or("9315")
    );

    // --- Listen on Unix socket, TCP, or both ---
    if let Some(ref socket_path) = state.cfg.server.socket {
        let tcp_addr = state.cfg.server.tcp.clone();

        if let Some(parent) = std::path::Path::new(socket_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        if std::path::Path::new(socket_path).exists() {
            std::fs::remove_file(socket_path)?;
        }

        let unix_listener = tokio::net::UnixListener::bind(socket_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        }

        tracing::info!("Listening on unix:{socket_path}");

        let shutdown = shutdown_signal();

        if let Some(addr) = tcp_addr {
            let tcp_listener = tokio::net::TcpListener::bind(&addr).await?;
            tracing::info!("Listening on tcp:{addr}");

            let tcp_router = router.clone();
            tokio::select! {
                result = axum::serve(unix_listener, router)
                    .with_graceful_shutdown(shutdown) => result?,
                result = axum::serve(tcp_listener, tcp_router) => result?,
            }
        } else {
            axum::serve(unix_listener, router)
                .with_graceful_shutdown(shutdown)
                .await?;
        }
    } else {
        let addr = state.cfg.server.listen_addr();
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!("Listening on tcp:{addr}");

        let shutdown = shutdown_signal();

        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await?;
    }

    Ok(())
}

/// Build ACP flow summaries from flow directories.
fn build_acp_flow_summaries(
    flow_dirs: &[String],
) -> Vec<navra_core::acp::types::FlowSummary> {
    let mut summaries = Vec::new();
    for dir in flow_dirs {
        let expanded = if dir.starts_with('~') {
            dirs::home_dir()
                .map(|h| dir.replacen('~', &h.display().to_string(), 1))
                .unwrap_or_else(|| dir.clone())
        } else {
            dir.clone()
        };
        if let Ok(entries) = std::fs::read_dir(&expanded) {
            for entry in entries.flatten() {
                let p = entry.path();
                let ext = p.extension().and_then(|e| e.to_str());
                if !matches!(ext, Some("yml" | "yaml" | "bpmn")) {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(&p) {
                    if ext == Some("bpmn") {
                        if let Ok(dag) =
                            navra_flow::load_bpmn_file(p.to_str().unwrap_or_default())
                        {
                            summaries.push(navra_core::acp::types::FlowSummary {
                                name: dag.name.clone(),
                                description: dag
                                    .description
                                    .clone()
                                    .unwrap_or_else(|| dag.name.clone()),
                                nodes: dag
                                    .tasks
                                    .iter()
                                    .map(|t| navra_core::acp::types::FlowNodeSummary {
                                        id: t.id.clone(),
                                        description: t.mandate.clone(),
                                    })
                                    .collect(),
                            });
                        }
                    } else if let Ok(flow) = serde_yaml::from_str::<
                        navra_flow::yaml_loader::FlowFile,
                    >(&content)
                    {
                        summaries.push(navra_core::acp::types::FlowSummary {
                            name: flow.name.clone(),
                            description: flow
                                .description
                                .unwrap_or_else(|| flow.name.clone()),
                            nodes: flow
                                .tasks
                                .iter()
                                .map(|t| navra_core::acp::types::FlowNodeSummary {
                                    id: t.id.clone(),
                                    description: t.mandate.clone(),
                                })
                                .collect(),
                        });
                    }
                }
            }
        }
    }
    summaries
}

/// Wait for SIGINT or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
    #[cfg(unix)]
    tokio::select! {
        _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
    }
    #[cfg(not(unix))]
    ctrl_c.await.ok();
}
