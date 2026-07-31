//! Tool registration for all gateway-level tools.
//!
//! Registers cap_delegate, sys_status, flow orchestration, team
//! orchestration, memory, registry proxy, audit_query, plan_execute,
//! and build_test tools.

use crate::config;
use crate::exec_tools;
use crate::flow_tools;
use crate::memory_tools;
use crate::registry_tools;
use crate::team_tools;
use crate::triggers;
use crate::util;
use navra_core::identity::Ed25519Signer;
use navra_core::permissions::PermissionEngine;
use navra_protocol::compat::CallToolResultExt;
use std::sync::Arc;

/// Register the `cap_delegate` tool if any agent can delegate.
pub(crate) fn wire_cap_delegate(
    mut builder: navra_core::McpServerBuilder,
    cfg: &config::Config,
    root_signer: &Arc<Ed25519Signer>,
) -> navra_core::McpServerBuilder {
    if !cfg.permissions.values().any(|ps| ps.can_delegate) {
        return builder;
    }

    let delegate_signer = Arc::clone(root_signer);
    let delegate_permissions = cfg.permissions.clone();
    let max_depth: u8 = cfg
        .server
        .identity
        .as_ref()
        .map(|i| i.max_delegation_depth as u8)
        .unwrap_or(3);
    let default_ttl = cfg
        .server
        .identity
        .as_ref()
        .map(|i| i.token_ttl)
        .unwrap_or(3600);

    builder = builder.tool(
        navra_core::protocol::ToolDefinition::new(
            "cap_delegate",
            "Issue an attenuated capability token for a sub-agent. \
                 The new token grants a subset of the caller's capabilities.",
            navra_protocol::compat::tool_input_schema(
                {
                    let mut props = std::collections::HashMap::new();
                    props.insert(
                        "subject_did".to_string(),
                        serde_json::json!({
                            "type": "string",
                            "description": "DID of the sub-agent receiving the token"
                        }),
                    );
                    props.insert(
                        "ring".to_string(),
                        serde_json::json!({
                            "type": "integer",
                            "description": "Ring level (must be >= caller's ring)"
                        }),
                    );
                    props.insert(
                        "operations".to_string(),
                        serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Operations to grant (subset of caller's)"
                        }),
                    );
                    props.insert(
                        "tools".to_string(),
                        serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Tool globs to grant (subset of caller's)"
                        }),
                    );
                    props.insert(
                        "paths".to_string(),
                        serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Path globs to grant (subset of caller's)"
                        }),
                    );
                    props.insert(
                        "credentials".to_string(),
                        serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Credential labels to grant (subset of caller's)"
                        }),
                    );
                    props.insert(
                        "ttl".to_string(),
                        serde_json::json!({
                            "type": "integer",
                            "description": "Token TTL in seconds"
                        }),
                    );
                    Some(props)
                },
                Some(vec!["subject_did".to_string()]),
            ),
        ),
        move |args, ctx| {
            let signer = Arc::clone(&delegate_signer);
            let permissions = delegate_permissions.clone();
            let max_depth = max_depth;
            let default_ttl = default_ttl;
            Box::pin(async move {
                handle_cap_delegate(args, ctx, signer, permissions, max_depth, default_ttl).await
            })
        },
    );
    tracing::info!("Registered cap_delegate tool");
    builder
}

async fn handle_cap_delegate(
    args: serde_json::Value,
    ctx: navra_core::auth::CallContext,
    signer: Arc<Ed25519Signer>,
    permissions: std::collections::HashMap<String, config::PermissionSet>,
    max_depth: u8,
    default_ttl: u64,
) -> navra_core::protocol::CallToolResult {
    use navra_core::auth::capability::{
        CapabilitySet, build_payload, encode_token, validate_delegation,
    };
    use navra_core::identity::CapSigner;
    use navra_core::protocol::CallToolResult;

    let parent_caps = match &ctx.agent.capabilities {
        Some(caps) => {
            if !caps.tools.iter().any(|t| t == "cap_delegate") {
                return CallToolResult::error_msg(
                    "Permission denied: cap_delegate must be explicitly \
                     listed in capability token tools (wildcard not accepted)",
                );
            }
            caps
        }
        None => {
            let perm_name = &ctx.agent.permissions;
            let can_delegate = permissions
                .get(perm_name)
                .map(|ps| ps.can_delegate)
                .unwrap_or(false);
            if !can_delegate {
                return CallToolResult::error_msg(
                    "Permission denied: delegation not allowed for this agent",
                );
            }
            return CallToolResult::error_msg(
                "Delegation requires a capability token. \
                 Use a capability-token-authenticated session.",
            );
        }
    };

    let subject_did = args
        .get("subject_did")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if subject_did.is_empty() {
        return CallToolResult::error_msg("subject_did is required");
    }

    let ring = args
        .get("ring")
        .and_then(|v| v.as_u64())
        .unwrap_or(parent_caps.ring as u64) as u8;

    let operations: Vec<String> = args
        .get("operations")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| parent_caps.operations.iter().cloned().collect());

    let tools: Vec<String> = args
        .get("tools")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| parent_caps.tools.clone());

    let paths: Vec<String> = args
        .get("paths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| parent_caps.paths.clone());

    let credentials: Vec<String> = args
        .get("credentials")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| parent_caps.credentials.clone());

    let ttl = args
        .get("ttl")
        .and_then(|v| v.as_u64())
        .unwrap_or(default_ttl);

    let cap_set = CapabilitySet {
        paths,
        operations,
        tools,
        credentials,
    };

    let issuer_did = ctx
        .agent
        .did
        .clone()
        .unwrap_or_else(|| format!("agent:{}", ctx.agent.name));

    let mut child_payload = build_payload(&issuer_did, &subject_did, cap_set, ring, ttl);

    let parent_payload = navra_core::auth::capability::CapabilityPayload {
        v: 1,
        iss: signer.did().to_string(),
        sub: issuer_did.clone(),
        cap: CapabilitySet {
            paths: parent_caps.paths.clone(),
            operations: parent_caps.operations.iter().cloned().collect(),
            tools: parent_caps.tools.clone(),
            credentials: parent_caps.credentials.clone(),
        },
        ring: parent_caps.ring,
        iat: 0,
        exp: parent_caps.expires_at,
        nonce: navra_core::auth::capability::generate_nonce(),
        parent: None,
        obo: None,
        sandbox: None,
        aud: None,
        act_chain: Vec::new(),
    };

    child_payload.parent = Some(parent_payload.nonce);

    if let Err(e) = validate_delegation(&parent_payload, &child_payload, max_depth) {
        return CallToolResult::error_msg(format!("Delegation denied: {e}"));
    }

    match encode_token(&child_payload, signer.as_ref()) {
        Ok(token) => {
            tracing::info!(
                issuer = %issuer_did,
                subject = %subject_did,
                ring = ring,
                "Delegated capability token"
            );
            CallToolResult::text(token)
        }
        Err(e) => CallToolResult::error_msg(format!("Failed to sign token: {e}")),
    }
}

/// Register the `sys_status` tool.
pub(crate) fn wire_sys_status(
    builder: navra_core::McpServerBuilder,
) -> navra_core::McpServerBuilder {
    builder.tool(
        navra_core::protocol::ToolDefinition::new(
            "sys_status",
            "Show AI OS process table: active agents, their rings, \
                 call counts, and active tool calls.",
            navra_protocol::compat::tool_input_schema(None, None),
        ),
        |_args, _ctx| {
            Box::pin(async {
                navra_core::protocol::CallToolResult::text(
                    "sys_status: use GET /sys/status for process table",
                )
            })
        },
    )
}

/// Register flow orchestration tools (flow_status, flow_result, flow_list).
/// Returns the flow_registry for later use and resolved flow dirs.
pub(crate) fn wire_flow_tools(
    mut builder: navra_core::McpServerBuilder,
    cfg: &config::Config,
    flow_registry: &Arc<flow_tools::FlowRegistry>,
    audit_log: &Arc<navra_memory::AuditLog>,
) -> navra_core::McpServerBuilder {
    // flow_status
    let registry = Arc::clone(flow_registry);
    builder = builder.tool(flow_tools::flow_status_tool_def(), move |args, _ctx| {
        let registry = Arc::clone(&registry);
        Box::pin(flow_tools::handle_flow_status(args, registry))
    });

    // flow_result
    let registry = Arc::clone(flow_registry);
    let fr_audit = Arc::clone(audit_log);
    builder = builder.tool(flow_tools::flow_result_tool_def(), move |args, _ctx| {
        let registry = Arc::clone(&registry);
        let audit = Arc::clone(&fr_audit);
        Box::pin(flow_tools::handle_flow_result(args, registry, Some(audit)))
    });

    // flow_list
    let flow_dirs = resolve_flow_dirs(cfg);
    builder = builder.tool(flow_tools::flow_list_tool_def(), move |_args, _ctx| {
        let flow_dirs = flow_dirs.clone();
        Box::pin(flow_tools::handle_flow_list(flow_dirs))
    });

    tracing::info!(
        "Registered flow orchestration tools (flow_start, flow_status, flow_result, flow_list, flow_escalate)"
    );

    builder
}

/// Resolve flow directories (auto-discover if not configured).
pub(crate) fn resolve_flow_dirs(cfg: &config::Config) -> Vec<String> {
    let mut dirs = cfg.flow_dirs.clone();
    if dirs.is_empty() {
        for candidate in &["examples/flows", "flows"] {
            if std::path::Path::new(candidate).is_dir() {
                dirs.push(candidate.to_string());
            }
        }
    }
    dirs
}

/// Register team orchestration tools and flow_start/flow_escalate/flow_resume.
///
/// This is the largest block: builds model cards, team registry,
/// containerized execution, and all team_* + flow_start/escalate/resume tools.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn wire_team_tools(
    mut builder: navra_core::McpServerBuilder,
    cfg: &config::Config,
    root_signer: &Arc<Ed25519Signer>,
    _models: &std::collections::HashMap<String, Arc<dyn navra_model::ModelBackend>>,
    exec_module: &Option<Arc<exec_tools::ExecState>>,
    embedding_model: &Option<Arc<dyn navra_model::ModelBackend>>,
    flow_registry: &Arc<flow_tools::FlowRegistry>,
    audit_log: &Arc<navra_memory::AuditLog>,
    resolved_flow_dirs: &[String],
    reasoning_pii_filter: &Option<Arc<navra_core::safety::FilterPipeline>>,
    running_endpoints: &mut Vec<(
        Box<dyn navra_model_runtime::ModelRuntime>,
        navra_model_runtime::Endpoint,
    )>,
) -> (
    navra_core::McpServerBuilder,
    Arc<team_tools::TeamRegistry>,
    Option<triggers::TriggerRegistry>,
    Option<axum::Router>,
) {
    use navra_core::identity::CapSigner;

    // Pre-fetch Ollama model metadata
    let mut ollama_meta: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();
    if let Ok(resp) = reqwest::Client::new()
        .get("http://localhost:11434/api/tags")
        .send()
        .await
        && let Ok(tags) = resp.json::<serde_json::Value>().await
        && let Some(model_list) = tags["models"].as_array()
    {
        for m in model_list {
            if let Some(name) = m["name"].as_str() {
                if let Ok(show_resp) = reqwest::Client::new()
                    .post("http://localhost:11434/api/show")
                    .json(&serde_json::json!({"name": name}))
                    .send()
                    .await
                    && let Ok(info) = show_resp.json::<serde_json::Value>().await
                {
                    ollama_meta.insert(name.to_string(), info);
                }
            }
        }
    }
    if !ollama_meta.is_empty() {
        tracing::info!(
            models = ollama_meta.len(),
            "Fetched Ollama model metadata for model cards"
        );
    }

    // Build composite model cards
    let model_cards = build_model_cards(cfg, &ollama_meta);

    let team_registry = Arc::new(team_tools::TeamRegistry::new().with_models(model_cards));

    // Containerized agent execution
    let containerized = match cfg.server.containerized {
        Some(true) => {
            if team_tools::is_podman_available() {
                true
            } else {
                tracing::warn!(
                    "Containerized mode requested but Podman not available, falling back to in-process"
                );
                false
            }
        }
        Some(false) => false,
        None => team_tools::is_podman_available(),
    };

    let model_server_url: Option<String> = if containerized {
        match crate::start_model_server_container(cfg).await {
            Ok((url, port, name)) => {
                tracing::info!(url = %url, container = %name, "Shared model server started");
                running_endpoints.push((
                    Box::new(navra_model_runtime::podman::PodmanRuntime::new(
                        navra_model_runtime::Engine::LlamaCpp,
                    )),
                    navra_model_runtime::Endpoint {
                        url: format!("http://127.0.0.1:{port}"),
                        id: name,
                        backend: navra_model_runtime::RuntimeBackend::new(
                            navra_model_runtime::Engine::LlamaCpp,
                            navra_model_runtime::Isolation::Podman,
                        ),
                    },
                ));
                Some(url)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to start model server container, agents will use Ollama");
                None
            }
        }
    } else {
        None
    };

    let gpu_semaphore = Arc::new(tokio::sync::Semaphore::new(
        if cfg.budget.max_parallel == 0 {
            64
        } else {
            cfg.budget.max_parallel
        },
    ));

    if containerized {
        tracing::info!(
            agent_image = %cfg.server.agent_image,
            model_server = ?model_server_url,
            "Containerized agent execution enabled"
        );
    }

    // team_create
    let reg = Arc::clone(&team_registry);
    let tc_budget_cfg = cfg.budget.clone();
    builder = builder.tool(team_tools::team_create_def(), move |args, ctx| {
        let reg = Arc::clone(&reg);
        let budget_cfg = tc_budget_cfg.clone();
        let agent_name = ctx.agent.name.clone();
        Box::pin(async move {
            team_tools::handle_team_create(args, reg, &budget_cfg, &agent_name).await
        })
    });

    // team_add
    let reg = Arc::clone(&team_registry);
    builder = builder.tool(team_tools::team_add_def(), move |args, _ctx| {
        let reg = Arc::clone(&reg);
        Box::pin(team_tools::handle_team_add(args, reg))
    });

    // Root capability payload for teammate token delegation
    let root_cap = navra_core::auth::capability::CapabilitySet {
        paths: vec!["**".to_string()],
        operations: vec![
            "read".to_string(),
            "write".to_string(),
            "search".to_string(),
            "list".to_string(),
            "git.status".to_string(),
            "git.diff".to_string(),
            "git.log".to_string(),
            "git.commit".to_string(),
            "git.branch".to_string(),
        ],
        tools: vec!["*".to_string()],
        credentials: vec![],
    };
    let root_payload = navra_core::auth::capability::build_payload(
        root_signer.did(),
        root_signer.did(),
        root_cap,
        1,
        86400,
    );

    // team_message
    let msg_spawn_ctx = Arc::new(team_tools::TeammateSpawnContext {
        team_registry: Arc::clone(&team_registry),
        navra_addr: cfg.server.listen_addr(),
        signer: Arc::clone(root_signer),
        forge: cfg.cognitive_core.as_ref().and_then(|p| {
            let expanded = util::expand_tilde(p);
            navra_cognitive::ForgeService::load(std::path::Path::new(&expanded))
                .map(Arc::new)
                .ok()
        }),
        root_payload: Some(root_payload.clone()),
        pii_filter: reasoning_pii_filter.clone(),
        audit_log: Some(Arc::clone(audit_log)),
        cognitive_core_path: cfg.cognitive_core.as_ref().map(|p| util::expand_tilde(p)),
        model_server_url: model_server_url.clone(),
        gpu_semaphore: Arc::clone(&gpu_semaphore),
        containerized,
        agent_image: cfg.server.agent_image.clone(),
        container_memory: cfg.server.container_memory.clone(),
        container_cpus: cfg.server.container_cpus.clone(),
        container_pids: cfg.server.container_pids,
        embedding_model: embedding_model.clone(),
        openshell_gateway: cfg.server.openshell_gateway.clone(),
        exec_state: exec_module.clone(),
        workspace_provider: None,
        max_tokens_per_run: cfg.budget.max_tokens_per_run,
        compression_start_ratio: cfg.budget.compression_start_ratio,
        compaction_keep_recent: cfg.budget.compaction_keep_recent,
        compaction_trigger_ratio: cfg.budget.compaction_trigger_ratio,
    });
    builder = builder.tool(team_tools::team_message_def(), move |args, _ctx| {
        let spawn_ctx = Arc::clone(&msg_spawn_ctx);
        Box::pin(async move { team_tools::handle_team_message(args, &spawn_ctx).await })
    });

    // team_status
    let reg = Arc::clone(&team_registry);
    builder = builder.tool(team_tools::team_status_def(), move |args, _ctx| {
        let reg = Arc::clone(&reg);
        Box::pin(team_tools::handle_team_status(args, reg))
    });

    // team_result
    let reg = Arc::clone(&team_registry);
    builder = builder.tool(team_tools::team_result_def(), move |args, _ctx| {
        let reg = Arc::clone(&reg);
        Box::pin(team_tools::handle_team_result(args, reg))
    });

    // team_shutdown
    let reg = Arc::clone(&team_registry);
    builder = builder.tool(team_tools::team_shutdown_def(), move |args, _ctx| {
        let reg = Arc::clone(&reg);
        Box::pin(team_tools::handle_team_shutdown(args, reg))
    });

    // agent_signal
    let reg = Arc::clone(&team_registry);
    builder = builder.tool(team_tools::agent_signal_def(), move |args, _ctx| {
        let reg = Arc::clone(&reg);
        Box::pin(team_tools::handle_agent_signal(args, reg))
    });

    // models_list
    let cards = team_registry.model_cards.clone();
    builder = builder.tool(team_tools::models_list_def(), move |_args, _ctx| {
        let cards = cards.clone();
        Box::pin(team_tools::handle_models_list(cards))
    });

    // personas_list
    let persona_data: Vec<serde_json::Value> = if let Some(ref cc_path) = cfg.cognitive_core {
        let expanded = util::expand_tilde(cc_path);
        match navra_cognitive::ForgeService::load(std::path::Path::new(&expanded)) {
            Ok(forge) => forge
                .persona_names()
                .iter()
                .filter_map(|name| {
                    forge.get_persona(name).map(|p| {
                        serde_json::json!({
                            "name": p.persona_name,
                            "display_name": p.display_name,
                            "mandate": p.core_mandate.lines().next().unwrap_or(""),
                            "heuristics": p.heuristics.len(),
                            "tools": p.tools,
                        })
                    })
                })
                .collect(),
            Err(_) => vec![],
        }
    } else {
        vec![]
    };
    builder = builder.tool(team_tools::personas_list_def(), move |_args, _ctx| {
        let data = persona_data.clone();
        Box::pin(team_tools::handle_personas_list(data))
    });

    // team_bb_publish
    let reg = Arc::clone(&team_registry);
    builder = builder.tool(team_tools::team_bb_publish_def(), move |args, ctx| {
        let reg = Arc::clone(&reg);
        let agent_name = ctx.agent.name.clone();
        let label = ctx.taint.level();
        Box::pin(async move {
            team_tools::handle_team_bb_publish(args, reg, &agent_name, label).await
        })
    });

    // team_bb_read
    let reg = Arc::clone(&team_registry);
    builder = builder.tool(team_tools::team_bb_read_def(), move |args, _ctx| {
        let reg = Arc::clone(&reg);
        Box::pin(team_tools::handle_team_bb_read(args, reg))
    });

    // team_bb_notifications
    let reg = Arc::clone(&team_registry);
    builder = builder.tool(team_tools::team_bb_notifications_def(), move |args, ctx| {
        let reg = Arc::clone(&reg);
        let agent_name = ctx.agent.name.clone();
        Box::pin(async move {
            team_tools::handle_team_bb_notifications(args, reg, &agent_name).await
        })
    });

    tracing::info!(
        "Registered team tools (team_create, team_add, team_message, team_status, team_result, team_shutdown, team_bb_publish, team_bb_read, team_bb_notifications, models_list)"
    );

    // Initialize checkpoint store
    let checkpoint = if cfg.budget.checkpoint {
        let db_path = util::expand_tilde(&cfg.budget.checkpoint_db);
        match navra_flow::DagCheckpoint::open(std::path::Path::new(&db_path)) {
            Ok(cp) => {
                tracing::info!(path = %db_path, "Flow checkpoint store opened");
                if let Ok(incomplete) = cp.list_incomplete()
                    && !incomplete.is_empty()
                {
                    tracing::info!(
                        count = incomplete.len(),
                        flows = ?incomplete,
                        "Found incomplete flows from previous run (use flow_resume to continue)"
                    );
                }
                Some(Arc::new(cp))
            }
            Err(e) => {
                tracing::warn!(path = %db_path, error = %e, "Failed to open checkpoint store — checkpointing disabled");
                None
            }
        }
    } else {
        None
    };

    // flow_start and flow_escalate — shared context
    let flow_ctx = Arc::new(flow_tools::FlowContext {
        flow_registry: Arc::clone(flow_registry),
        team_registry: Arc::clone(&team_registry),
        navra_addr: cfg.server.listen_addr(),
        signer: Arc::clone(root_signer),
        forge: cfg.cognitive_core.as_ref().and_then(|p| {
            let expanded = util::expand_tilde(p);
            navra_cognitive::ForgeService::load(std::path::Path::new(&expanded))
                .ok()
                .map(Arc::new)
        }),
        budget_cfg: cfg.budget.clone(),
        flow_dirs: resolved_flow_dirs.to_vec(),
        docs_root: cfg
            .modules
            .file
            .as_ref()
            .and_then(|d| d.default_root.clone())
            .or_else(|| cfg.cognitive_core.clone()),
        root_payload: Some(root_payload.clone()),
        pii_filter: reasoning_pii_filter.clone(),
        audit_log: Some(Arc::clone(audit_log)),
        cognitive_core_path: cfg.cognitive_core.as_ref().map(|p| util::expand_tilde(p)),
        model_server_url: model_server_url.clone(),
        gpu_semaphore: Arc::clone(&gpu_semaphore),
        containerized,
        agent_image: cfg.server.agent_image.clone(),
        container_memory: cfg.server.container_memory.clone(),
        container_cpus: cfg.server.container_cpus.clone(),
        container_pids: cfg.server.container_pids,
        embedding_model: embedding_model.clone(),
        openshell_gateway: cfg.server.openshell_gateway.clone(),
        exec_state: exec_module.clone(),
        workspace_provider: None,
        checkpoint,
    });

    // flow_start
    let fs_ctx = Arc::clone(&flow_ctx);
    builder = builder.tool(flow_tools::flow_start_tool_def(), move |args, ctx| {
        let flow_ctx = Arc::clone(&fs_ctx);
        let agent_name = ctx.agent.name.clone();
        Box::pin(async move { flow_tools::handle_flow_start(args, flow_ctx, &agent_name).await })
    });

    // flow_escalate
    let fe_ctx = Arc::clone(&flow_ctx);
    builder = builder.tool(flow_tools::flow_escalate_tool_def(), move |args, ctx| {
        let flow_ctx = Arc::clone(&fe_ctx);
        let agent_name = ctx.agent.name.clone();
        Box::pin(
            async move { flow_tools::handle_flow_escalate(args, flow_ctx, &agent_name).await },
        )
    });

    let fr_ctx = Arc::clone(&flow_ctx);
    builder = builder.tool(flow_tools::flow_resume_tool_def(), move |args, ctx| {
        let flow_ctx = Arc::clone(&fr_ctx);
        let agent = ctx.agent.name.clone();
        Box::pin(async move { flow_tools::handle_flow_resume(args, flow_ctx, &agent).await })
    });

    tracing::info!("Registered flow tools (flow_escalate, flow_resume)");

    // --- Event-driven triggers ---
    let mut _trigger_registry = None;
    let mut trigger_webhook_router = None;
    if !cfg.triggers.is_empty() {
        let (registry, webhook_router) =
            triggers::TriggerRegistry::start(&cfg.triggers, Arc::clone(&flow_ctx));
        tracing::info!(count = cfg.triggers.len(), "Trigger infrastructure started");
        _trigger_registry = Some(registry);
        trigger_webhook_router = Some(webhook_router);
    }

    (
        builder,
        team_registry,
        _trigger_registry,
        trigger_webhook_router,
    )
}

/// Register memory tools (memory_store, memory_query, memory_forget, etc.).
pub(crate) fn wire_memory_tools(
    mut builder: navra_core::McpServerBuilder,
    cfg: &config::Config,
    knowledge_store: &Option<Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>>,
    shared_chunk_store: &Option<Arc<navra_rag::ChunkStore>>,
    pii_sanitizer: &Option<Arc<navra_core::safety::FilterPipeline>>,
    pii_metrics: &Option<Arc<navra_core::safety::PiiMetrics>>,
) -> navra_core::McpServerBuilder {
    let Some(ks) = knowledge_store.clone() else {
        return builder;
    };

    let ks_store = Arc::clone(&ks);
    let sanitizer_for_store = pii_sanitizer.clone();
    builder = builder.tool(memory_tools::memory_store_def(), move |args, _ctx| {
        let ks = Arc::clone(&ks_store);
        let sanitizer = sanitizer_for_store.clone();
        Box::pin(memory_tools::handle_memory_store(args, ks, sanitizer))
    });

    let ks_query = Arc::clone(&ks);
    builder = builder.tool(memory_tools::memory_query_def(), move |args, _ctx| {
        let ks = Arc::clone(&ks_query);
        Box::pin(memory_tools::handle_memory_query(args, ks))
    });

    let ks_forget = Arc::clone(&ks);
    let cs_forget = shared_chunk_store.clone();
    builder = builder.tool(memory_tools::memory_forget_def(), move |args, _ctx| {
        let ks = Arc::clone(&ks_forget);
        let cs = cs_forget.clone();
        Box::pin(memory_tools::handle_memory_forget(args, ks, cs))
    });

    let ks_purge = Arc::clone(&ks);
    let sanitizer_for_purge = pii_sanitizer.clone();
    let cs_purge = shared_chunk_store.clone();
    builder = builder.tool(memory_tools::memory_purge_pii_def(), move |args, _ctx| {
        let ks = Arc::clone(&ks_purge);
        let sanitizer = sanitizer_for_purge.clone();
        let cs = cs_purge.clone();
        Box::pin(memory_tools::handle_memory_purge_pii(
            args, ks, sanitizer, cs,
        ))
    });

    let ks_forget_content = Arc::clone(&ks);
    let cs_forget_content = shared_chunk_store.clone();
    builder = builder.tool(
        memory_tools::memory_forget_by_content_def(),
        move |args, _ctx| {
            let ks = Arc::clone(&ks_forget_content);
            let cs = cs_forget_content.clone();
            Box::pin(memory_tools::handle_memory_forget_by_content(args, ks, cs))
        },
    );

    // pii_report
    let ks_report = Arc::clone(&ks);
    let metrics_for_report = pii_metrics.clone();
    let retention_days = cfg.memory_retention_days();
    let pii_retention_days = cfg.memory_pii_retention_days();
    let audit_retention_days = cfg.memory_audit_retention_days();
    builder = builder.tool(memory_tools::pii_report_def(), move |args, _ctx| {
        let ks = Arc::clone(&ks_report);
        let metrics = metrics_for_report.clone();
        Box::pin(memory_tools::handle_pii_report(
            args,
            ks,
            metrics,
            retention_days,
            pii_retention_days,
            audit_retention_days,
        ))
    });

    // memory_consent
    let ks_consent = Arc::clone(&ks);
    builder = builder.tool(memory_tools::memory_consent_def(), move |args, _ctx| {
        let ks = Arc::clone(&ks_consent);
        Box::pin(memory_tools::handle_memory_consent(args, ks))
    });

    // --- Data retention sweep at startup ---
    {
        let store = ks.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(days) = cfg.memory_retention_days() {
            match store.expire_older_than(days) {
                Ok(n) if n > 0 => tracing::info!(
                    deleted = n,
                    days = days,
                    "Retention: expired old knowledge entries"
                ),
                _ => {}
            }
        }
        if let Some(days) = cfg.memory_pii_retention_days() {
            match store.expire_pii_older_than(days) {
                Ok(n) if n > 0 => tracing::info!(
                    deleted = n,
                    days = days,
                    "Retention: expired PII-flagged knowledge entries"
                ),
                _ => {}
            }
        }
    }

    tracing::info!(
        "Registered memory tools (memory_store, memory_query, memory_forget, memory_purge_pii, memory_forget_by_content, pii_report, memory_consent)"
    );

    builder
}

/// Register registry proxy tools.
pub(crate) fn wire_registry_tools(
    mut builder: navra_core::McpServerBuilder,
    cfg: &config::Config,
) -> navra_core::McpServerBuilder {
    if !cfg.registry_enabled() || cfg.registry.is_empty() {
        return builder;
    }

    let registry_state = Arc::new(registry_tools::RegistryState::new(
        cfg.registry.clone(),
        cfg.registry_cache_ttl_secs(),
    ));

    let rs = Arc::clone(&registry_state);
    builder = builder.tool(registry_tools::registry_search_def(), move |args, _ctx| {
        let rs = Arc::clone(&rs);
        Box::pin(registry_tools::handle_registry_search(args, rs))
    });

    let rs = Arc::clone(&registry_state);
    builder = builder.tool(registry_tools::registry_list_def(), move |args, _ctx| {
        let rs = Arc::clone(&rs);
        Box::pin(registry_tools::handle_registry_list(args, rs))
    });

    let rs = Arc::clone(&registry_state);
    builder = builder.tool(
        registry_tools::registry_describe_def(),
        move |args, _ctx| {
            let rs = Arc::clone(&rs);
            Box::pin(registry_tools::handle_registry_describe(args, rs))
        },
    );

    tracing::info!(
        registries = cfg.registry.len(),
        "Registered registry proxy tools (registry_search, registry_list, registry_describe)"
    );

    builder
}

/// Register audit_query tool.
pub(crate) fn wire_audit_query(
    builder: navra_core::McpServerBuilder,
    audit_log: &Arc<navra_memory::AuditLog>,
) -> navra_core::McpServerBuilder {
    let audit = Arc::clone(audit_log);
    let builder = builder.tool(
        navra_core::protocol::ToolDefinition::new(
            "audit_query",
            "Query the structured audit log. Returns tool calls, model calls, \
                 and run summaries from past agent executions. Use to inspect \
                 what tools were called, with what arguments, and what results \
                 were returned.",
            navra_protocol::compat::tool_input_schema(
                {
                    let mut props = std::collections::HashMap::new();
                    props.insert(
                        "run_id".to_string(),
                        serde_json::json!({
                            "type": "string",
                            "description": "Filter by run ID (returns tool calls for that run)"
                        }),
                    );
                    props.insert("summary".to_string(), serde_json::json!({
                        "type": "boolean",
                        "description": "If true, return a summary instead of individual entries"
                    }));
                    Some(props)
                },
                None,
            ),
        ),
        move |args, _ctx| {
            let audit = Arc::clone(&audit);
            Box::pin(async move {
                use navra_core::protocol::CallToolResult;

                let run_id = args.get("run_id").and_then(|v| v.as_str());

                if let Some(rid) = run_id {
                    let summary = args
                        .get("summary")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if summary {
                        match audit.get_summary(rid) {
                            Ok(s) => CallToolResult::text(
                                serde_json::to_string_pretty(&s).unwrap_or_default(),
                            ),
                            Err(e) => {
                                CallToolResult::error_msg(format!("Audit query failed: {e}"))
                            }
                        }
                    } else {
                        match audit.get_tool_calls(rid) {
                            Ok(calls) => CallToolResult::text(
                                serde_json::to_string_pretty(&calls).unwrap_or_default(),
                            ),
                            Err(e) => {
                                CallToolResult::error_msg(format!("Audit query failed: {e}"))
                            }
                        }
                    }
                } else {
                    match audit.get_run("latest") {
                        Ok(run) => CallToolResult::text(
                            serde_json::to_string_pretty(&run).unwrap_or_default(),
                        ),
                        Err(_) => CallToolResult::text(
                            "No audit runs found. Run a demo first.".to_string(),
                        ),
                    }
                }
            })
        },
    );
    tracing::info!("Registered audit_query tool");
    builder
}

/// Register plan_execute and build_test tools.
pub(crate) fn wire_late_tools(
    mut builder: navra_core::McpServerBuilder,
    cfg: &config::Config,
    perm_engine: &Arc<PermissionEngine>,
    server_cell: &Arc<std::sync::OnceLock<Arc<navra_core::McpServer>>>,
) -> navra_core::McpServerBuilder {
    // plan_execute
    {
        let cell = Arc::clone(server_cell);
        let allow_direct = cfg.server.allow_direct_execution;
        builder = builder.tool(
            crate::plan_execute::plan_execute_tool_def(),
            move |args, ctx| {
                let cell = Arc::clone(&cell);
                Box::pin(async move {
                    match cell.get() {
                        Some(server) => {
                            crate::plan_execute::handle_plan_execute(
                                args,
                                server,
                                ctx,
                                allow_direct,
                            )
                            .await
                        }
                        None => navra_core::protocol::CallToolResult::error_msg(
                            "Server not yet initialized",
                        ),
                    }
                })
            },
        );
        tracing::info!("Registered plan_execute tool");
    }

    // build_test
    {
        let perm = Arc::clone(perm_engine);
        builder = builder.tool(
            crate::build_tools::build_test_tool_def(),
            move |args, ctx| {
                let perm = Arc::clone(&perm);
                Box::pin(async move { crate::build_tools::handle_build_test(args, ctx, perm).await })
            },
        );
        tracing::info!("Registered build_test tool");
    }

    builder
}

/// Build composite model cards from config + discovered Ollama models.
fn build_model_cards(
    cfg: &config::Config,
    ollama_meta: &std::collections::HashMap<String, serde_json::Value>,
) -> Vec<team_tools::ModelCard> {
    let mut model_keys: Vec<(String, Option<&config::ModelConfig>)> = cfg
        .models
        .iter()
        .map(|(k, v)| (k.clone(), Some(v)))
        .collect();
    let configured_sources: std::collections::HashSet<String> = cfg
        .models
        .values()
        .filter_map(|m| m.source.as_ref())
        .filter_map(|s| s.strip_prefix("ollama://"))
        .map(|s| s.to_string())
        .collect();
    for name in ollama_meta.keys() {
        if !configured_sources.contains(name) {
            model_keys.push((name.clone(), None));
        }
    }

    model_keys
        .iter()
        .map(|(name, mcfg_opt)| {
            let mcfg_ref = mcfg_opt.as_ref();
            let display_name = mcfg_ref
                .and_then(|m| m.model_name.as_deref())
                .unwrap_or(name);
            let uri_str = mcfg_ref
                .and_then(|m| m.source.as_deref())
                .unwrap_or(display_name);
            let mut card = navra_model_hub::ModelCard::new(uri_str);

            // Populate vendor metadata from config
            if let Some(mcfg) = mcfg_ref {
                card.vendor.source = Some(
                    if mcfg.source.is_some() {
                        match mcfg.source.as_deref() {
                            Some(s) if s.starts_with("ollama://") => "ollama",
                            Some(s) if s.starts_with("hf://") => "huggingface",
                            Some(s) if s.starts_with("oci://") => "oci",
                            _ => "local",
                        }
                    } else {
                        "local"
                    }
                    .into(),
                );
                card.vendor.context_window = mcfg.context_size;
                card.vendor.tasks = match mcfg.task.as_str() {
                    "chat" | "generate" => vec!["text-generation".into()],
                    "embedding" => vec!["feature-extraction".into()],
                    "classification" => vec!["text-classification".into()],
                    _ => vec![],
                };
                if let Some(runtime) = &mcfg.runtime {
                    card.vendor.runtime = Some(runtime.clone());
                }
            }

            // Enrich with Ollama /api/show metadata
            if let Some(info) = ollama_meta.get(display_name) {
                card.vendor.source = Some("ollama".into());
                if let Some(model_info) = info.get("model_info") {
                    for (key, val) in model_info.as_object().into_iter().flatten() {
                        if key.ends_with(".context_length")
                            && let Some(ctx) = val.as_u64()
                        {
                            card.vendor.context_window = Some(ctx as u32);
                        }
                        if key.ends_with(".embedding_length")
                            && let Some(dim) = val.as_u64()
                        {
                            card.vendor
                                .custom
                                .insert("embedding_dim".into(), serde_json::json!(dim));
                        }
                    }
                    if let Some(params) = model_info.get("general.parameter_count")
                        && let Some(p) = params.as_u64()
                    {
                        let label = if p >= 1_000_000_000 {
                            format!("{}B", p / 1_000_000_000)
                        } else if p >= 1_000_000 {
                            format!("{}M", p / 1_000_000)
                        } else {
                            format!("{p}")
                        };
                        card.vendor.parameters = Some(label);
                    }
                    if let Some(arch) = model_info.get("general.architecture")
                        && let Some(a) = arch.as_str()
                    {
                        card.vendor.family = Some(a.to_string());
                    }
                }
                if let Some(details) = info.get("details") {
                    if let Some(quant) = details.get("quantization_level")
                        && let Some(q) = quant.as_str()
                    {
                        card.vendor.quantization = Some(q.to_string());
                    }
                    if let Some(family) = details.get("family")
                        && card.vendor.family.is_none()
                    {
                        card.vendor.family = family.as_str().map(|s| s.to_string());
                    }
                }
                if let Some(license) = info.get("license")
                    && let Some(l) = license.as_str()
                {
                    card.vendor.license = l.lines().next().map(|s| s.to_string());
                }
                card.vendor.format = Some("gguf".into());
            }

            // Detect Claude/Anthropic models
            if display_name.starts_with("claude") {
                card.vendor.source = Some("anthropic".into());
                card.vendor.family = Some("claude".into());
                if display_name.contains("sonnet") {
                    card.vendor.parameters = Some("medium".into());
                } else if display_name.contains("opus") {
                    card.vendor.parameters = Some("large".into());
                } else if display_name.contains("haiku") {
                    card.vendor.parameters = Some("small".into());
                }
            }

            // Merge operator-defined agentic metadata
            if let Some(mcfg) = mcfg_ref
                && let Some(agentic_cfg) = &mcfg.agentic
            {
                card.merge_agentic(&agentic_cfg.to_agentic_meta());
            }

            card
        })
        .collect()
}
