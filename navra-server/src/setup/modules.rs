//! Module registration: exec, RAG, voice, vision, forge, discovery, gRPC.
//!
//! Each block is conditionally enabled based on the config and wired
//! onto the server builder.

use crate::config;
use crate::discover;
use crate::exec_tools;
use crate::grpc_manager;
use crate::mdns;
use crate::util;
use navra_core::Module;
use navra_core::permissions::PermissionEngine;
use std::sync::Arc;

/// Aggregate output of module registration — items that downstream
/// phases (tools, resources, transport) still need.
pub(crate) struct ModuleOutputs {
    pub(crate) exec_module: Option<Arc<exec_tools::ExecState>>,
    pub(crate) shared_chunk_store: Option<Arc<navra_rag::ChunkStore>>,
    pub(crate) rag_context_retriever: Option<Arc<dyn navra_agent::ContextRetriever>>,
    pub(crate) forge: navra_cognitive::ForgeService,
    pub(crate) embedding_model: Option<Arc<dyn navra_model::ModelBackend>>,
    pub(crate) _grpc_manager: Option<grpc_manager::GrpcModuleManager>,
    pub(crate) _mdns_daemon: Option<mdns_sd::ServiceDaemon>,
}

/// Register all feature modules on the builder.
pub(crate) async fn wire_modules(
    mut builder: navra_core::McpServerBuilder,
    cfg: &config::Config,
    models: &std::collections::HashMap<String, Arc<dyn navra_model::ModelBackend>>,
    perm_engine: &Arc<PermissionEngine>,
    metrics: &Arc<navra_core::metrics::Metrics>,
    credential_store: &Arc<navra_core::credentials::MappedCredentialStore>,
    endpoint_registry: &Arc<crate::policy_sync::ToolEndpointRegistry>,
) -> (navra_core::McpServerBuilder, ModuleOutputs) {
    // --- Resolve named models for modules ---
    let embedding_model_name = cfg
        .models
        .iter()
        .find(|(_, m)| m.task == "embedding")
        .map(|(name, _)| name.clone());
    let embedding_model = embedding_model_name
        .as_ref()
        .and_then(|name| models.get(name))
        .cloned();

    // --- Git module (upstream MCP server) ---
    if cfg.git_enabled() {
        let has_git_upstream = cfg
            .upstream
            .iter()
            .any(|u| u.name == "git" || u.name == "mcp-git");
        if !has_git_upstream {
            tracing::warn!(
                "[modules.git] is enabled but no [[upstream]] named 'git' found. \
                 Add to config.toml:\n\
                 [[upstream]]\n\
                 name = \"git\"\n\
                 transport = \"stdio\"\n\
                 command = [\"podman\", \"run\", \"--rm\", \"-i\", \"docker.io/mcp/git\"]"
            );
        }
    }

    // --- Exec module (OpenShell agent sandboxing) ---
    let exec_module: Option<Arc<exec_tools::ExecState>> =
        if let Some(ref gateway) = cfg.server.openshell_gateway {
            let channel = tonic::transport::Channel::from_shared(gateway.clone())
                .expect("valid OpenShell gateway URL")
                .connect_lazy();
            let client = navra_model_runtime::openshell::ComputeDriverClient::new(channel);
            let state = Arc::new(exec_tools::ExecState::new(client));
            tracing::info!(gateway = %gateway, "Tool 'exec_run' enabled (OpenShell)");
            let (def, handler) = exec_tools::exec_run_tool(Arc::clone(&state));
            builder = builder.tool(def, move |args, ctx| {
                let h = Arc::clone(&handler);
                Box::pin(async move { h(args, ctx).await })
            });
            Some(state)
        } else {
            None
        };

    // --- RAG module ---
    let mut shared_chunk_store: Option<Arc<navra_rag::ChunkStore>> = None;
    let mut rag_context_retriever: Option<Arc<dyn navra_agent::ContextRetriever>> = None;

    if cfg.rag_enabled() {
        if let Some(ref model) = embedding_model {
            let rag_db_path = cfg.rag_db_path();
            let dims = embedding_model_name
                .as_ref()
                .and_then(|name| cfg.models.get(name))
                .and_then(|m| m.dimensions)
                .unwrap_or(768);
            match navra_rag::ChunkStore::open(&rag_db_path, dims) {
                Ok(store) => {
                    // Enable semantic query cache if TTL > 0
                    let cache_ttl = cfg.rag_query_cache_ttl_secs();
                    let store = if cache_ttl > 0 {
                        let cache_config = navra_rag::QueryCacheConfig {
                            capacity: cfg.rag_query_cache_max_entries(),
                            ttl: std::time::Duration::from_secs(cache_ttl),
                            ..navra_rag::QueryCacheConfig::default()
                        };
                        tracing::info!(
                            ttl_secs = cache_ttl,
                            max_entries = cfg.rag_query_cache_max_entries(),
                            "RAG query cache enabled"
                        );
                        store.with_query_cache(cache_config)
                    } else {
                        store
                    };

                    let store_arc = Arc::new(store);
                    shared_chunk_store = Some(Arc::clone(&store_arc));

                    // Load cross-encoder reranker if configured
                    let reranker: Arc<dyn navra_rag::Reranker> = {
                        let model_path = cfg.rag_reranker_model_path();
                        let tokenizer_path = cfg.rag_reranker_tokenizer_path();
                        let r = navra_rag::load_reranker(
                            model_path
                                .as_ref()
                                .map(|p| std::path::Path::new(p.as_str())),
                            tokenizer_path
                                .as_ref()
                                .map(|p| std::path::Path::new(p.as_str())),
                        );
                        Arc::from(r)
                    };

                    let chunk_config = navra_rag::ChunkConfig {
                        graphability_threshold: Some(0.3),
                        ..navra_rag::ChunkConfig::default()
                    };
                    let cascade = navra_rag::CascadeConfig {
                        bm25_skip_vector_threshold: Some(0.0000001),
                        vector_skip_rerank_threshold: Some(2.0),
                    };
                    let reranker_for_retriever = reranker.clone();
                    let cascade_for_retriever = cascade.clone();
                    let rag = navra_rag::RagModule::with_reranker(
                        store_arc,
                        model.clone(),
                        chunk_config,
                        perm_engine.clone(),
                        reranker,
                    )
                    .with_cascade(cascade)
                    .with_metrics(metrics.clone());
                    rag_context_retriever =
                        Some(Arc::new(crate::rag_retriever::RagRetriever::new(
                            Arc::clone(
                                shared_chunk_store
                                    .as_ref()
                                    .expect("chunk store must be initialized before RAG retriever"),
                            ),
                            model.clone(),
                            reranker_for_retriever,
                            cascade_for_retriever,
                            Some(metrics.clone()),
                        )));
                    tracing::info!(
                        "Module 'rag' enabled (db: {rag_db_path}, dims: {dims}, cascade: on, graphability: 0.3)"
                    );
                    builder = builder.module(rag);
                }
                Err(e) => {
                    tracing::error!("Failed to open RAG store: {e}");
                }
            }
        } else {
            tracing::warn!("RAG module requires an embedding model, skipping");
        }
    }

    // --- Voice module ---
    if let Some(voice_cfg) = cfg.modules.voice.as_ref().filter(|_| cfg.voice_enabled()) {
        let asr = models.get(&voice_cfg.asr_model).cloned();
        let tts = models.get(&voice_cfg.tts_model).cloned();

        match (asr, tts) {
            (Some(asr_model), Some(tts_model)) => {
                let voice = navra_modal_voice::VoiceModule::with_config(
                    asr_model,
                    tts_model,
                    voice_cfg.vad_threshold,
                    voice_cfg.max_record_secs,
                    voice_cfg.silence_timeout_ms,
                    voice_cfg.voice.clone(),
                    perm_engine.clone(),
                );
                tracing::info!(
                    asr = %voice_cfg.asr_model,
                    tts = %voice_cfg.tts_model,
                    "Module 'voice' enabled"
                );
                builder = builder.module(voice);
            }
            (None, _) => {
                tracing::warn!(
                    model = %voice_cfg.asr_model,
                    "Voice module: ASR model '{}' not found, skipping",
                    voice_cfg.asr_model
                );
            }
            (_, None) => {
                tracing::warn!(
                    model = %voice_cfg.tts_model,
                    "Voice module: TTS model '{}' not found, skipping",
                    voice_cfg.tts_model
                );
            }
        }
    }

    // --- Vision module ---
    if let Some(vision_cfg) = cfg.modules.vision.as_ref().filter(|_| cfg.vision_enabled()) {
        if let Some(vision_model) = models.get(&vision_cfg.model).cloned() {
            let vision = navra_modal_vision::VisionModule::new(vision_model, perm_engine.clone());
            tracing::info!(model = %vision_cfg.model, "Module 'vision' enabled");
            builder = builder.module(vision);
        } else {
            tracing::warn!(
                model = %vision_cfg.model,
                "Vision module: model '{}' not found, skipping",
                vision_cfg.model
            );
        }
    }

    // --- Load ForgeService for persona auto-discovery ---
    let mut forge = if let Some(ref cc_path) = cfg.cognitive_core {
        let expanded = util::expand_tilde(cc_path);
        match navra_cognitive::ForgeService::load(std::path::Path::new(&expanded)) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load cognitive core, using empty forge");
                navra_cognitive::ForgeService::empty()
            }
        }
    } else {
        navra_cognitive::ForgeService::empty()
    };

    // --- AID upstream discovery ---
    if !cfg.discover.is_empty() {
        tracing::info!(
            domains = cfg.discover.len(),
            "Discovering upstream MCP servers via AID"
        );
        let discovery_timeout = cfg
            .server
            .discovery
            .as_ref()
            .map(|d| std::time::Duration::from_secs(d.timeout_secs))
            .unwrap_or_else(|| std::time::Duration::from_secs(10));
        let discovered =
            discover::discover_all_with_timeout(&cfg.discover, discovery_timeout).await;
        for endpoint in &discovered {
            tracing::info!(
                domain = %endpoint.domain,
                url = %endpoint.url,
                description = ?endpoint.description,
                auth = ?endpoint.auth,
                "Discovered MCP endpoint"
            );
            let transport =
                rmcp::transport::StreamableHttpClientTransport::from_uri(endpoint.url.clone());
            match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await {
                Ok(client) => {
                    let peer = client.peer().clone();
                    tokio::spawn(async move {
                        let _ = client.waiting().await;
                    });
                    let module = navra_core::UpstreamModule::discover(
                        &endpoint.domain,
                        peer,
                        None,
                        &Default::default(),
                    )
                    .await;
                    tracing::info!(
                        domain = %endpoint.domain,
                        "Connected discovered upstream (rmcp)"
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
                    builder = builder.module(module);
                }
                Err(e) => {
                    tracing::warn!(
                        domain = %endpoint.domain,
                        error = %e,
                        "Failed to connect to discovered endpoint"
                    );
                }
            }
        }
        if discovered.is_empty() && !cfg.discover.is_empty() {
            tracing::info!("No MCP endpoints discovered via AID");
        }
    }

    // --- mDNS/DNS-SD LAN discovery ---
    let mdns_enabled = cfg
        .server
        .discovery
        .as_ref()
        .map(|d| d.mdns)
        .unwrap_or(false);
    let mut _mdns_daemon: Option<mdns_sd::ServiceDaemon> = None;

    if mdns_enabled {
        let mdns_browse_secs = cfg
            .server
            .discovery
            .as_ref()
            .map(|d| d.mdns_browse_secs)
            .unwrap_or(3);
        tracing::info!("Browsing LAN for MCP servers via mDNS...");
        let lan_servers = mdns::browse(std::time::Duration::from_secs(mdns_browse_secs)).await;

        for server in &lan_servers {
            let url = server.url();
            let transport = rmcp::transport::StreamableHttpClientTransport::from_uri(url.clone());
            match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await {
                Ok(client) => {
                    let peer = client.peer().clone();
                    tokio::spawn(async move {
                        let _ = client.waiting().await;
                    });
                    let module = navra_core::UpstreamModule::discover(
                        &server.name,
                        peer,
                        None,
                        &Default::default(),
                    )
                    .await;
                    tracing::info!(
                        name = %server.name,
                        url = %url,
                        "Connected LAN upstream (rmcp)"
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
                    builder = builder.module(module);
                }
                Err(e) => {
                    tracing::debug!(
                        name = %server.name,
                        error = %e,
                        "Failed to connect to LAN upstream"
                    );
                }
            }
        }
    }

    // --- Upstream MCP servers ---
    builder = crate::setup::upstream::wire_upstream(
        builder,
        cfg,
        credential_store,
        &mut forge,
        Some(endpoint_registry),
    )
    .await;

    // --- gRPC out-of-process modules ---
    let _grpc_manager = if !cfg.grpc_modules.is_empty() {
        let mut manager = grpc_manager::GrpcModuleManager::new(cfg.grpc_modules.clone());
        let modules = manager.start_all().await;
        for module in modules {
            tracing::info!(module = module.name(), "Connected gRPC module");
            builder = builder.module(module);
        }
        Some(manager)
    } else {
        None
    };

    (
        builder,
        ModuleOutputs {
            exec_module,
            shared_chunk_store,
            rag_context_retriever,
            forge,
            embedding_model,
            _grpc_manager,
            _mdns_daemon,
        },
    )
}
