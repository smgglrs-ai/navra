mod cli;
mod config;
mod demo;
mod discover;
mod flow_tools;
mod mdns;
mod memory_tools;
mod registry_tools;
mod team_tools;
mod tray;
mod ui;

use clap::Parser;
use smgglrs_core::auth::{AgentIdentity, TokenAuthenticator};
use smgglrs_core::identity::{self, CapSigner, Ed25519Signer};
use smgglrs_core::permissions::{PathAcl, PermissionEngine, ToolPermissions, ToolPolicy, ToolRule};
use std::sync::Arc;

use cli::{Cli, Commands, ModelAction, TokenAction};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("smgglrs=info".parse()?),
        )
        .init();

    match cli.command {
        Commands::Serve { config: config_path, no_tray } => {
            let cfg = config::Config::load(config_path.as_deref())?;
            serve(cfg, no_tray).await?;
        }
        Commands::Token { action } => {
            match action {
                TokenAction::Generate { name, permissions } => {
                    let token = config::generate_token();
                    let hash = TokenAuthenticator::hash_token(&token);
                    println!("Agent: {name}");
                    println!("Permissions: {permissions}");
                    println!("Token: {token}");
                    println!("Hash:  {hash}");
                    println!("\nAdd to config.toml:");
                    println!("[[agents]]");
                    println!("name = \"{name}\"");
                    println!("token_hash = \"{hash}\"");
                    println!("permissions = \"{permissions}\"");
                }
                TokenAction::List => {
                    let cfg = config::Config::load(None)?;
                    if cfg.agents.is_empty() {
                        println!("No agents configured.");
                    } else {
                        println!("{:<20} {:<20}", "NAME", "PERMISSIONS");
                        println!("{:<20} {:<20}", "----", "-----------");
                        for agent in &cfg.agents {
                            println!("{:<20} {:<20}", agent.name, agent.permissions);
                        }
                    }
                }
            }
        }
        Commands::Approve { id } => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            approve_or_deny(&addr, &id, true).await?;
        }
        Commands::Deny { id } => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            approve_or_deny(&addr, &id, false).await?;
        }
        Commands::Status => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            query_status(&addr).await?;
        }
        Commands::Install => {
            install_systemd_units()?;
        }
        Commands::Uninstall => {
            uninstall_systemd_units()?;
        }
        Commands::Model { action } => match action {
            ModelAction::Pull { name } => {
                cli::model_pull(&name).await?;
            }
            ModelAction::List => {
                cli::model_list()?;
            }
            ModelAction::Available => {
                cli::model_available();
            }
        },
        Commands::Run { prompt, model, persona, endpoint, token, max_iterations, upstream_prompts } => {
            run_agent(&prompt, model.as_deref(), &persona, &endpoint, token.as_deref(), max_iterations, &upstream_prompts).await?;
        }
        Commands::Audit { limit, detail, agent, tool, verify } => {
            audit_command(limit, detail, agent, tool, verify)?;
        }
        Commands::Demo { project, live, model, max_rounds, files_per_round, min_delta, prompt, writable, allow_read, allow_write } => {
            if live {
                demo::run_demo_live(&project, &model, max_rounds, files_per_round, min_delta, prompt.as_deref(), writable, &allow_read, &allow_write).await?;
            } else {
                demo::run_demo(&project).await?;
            }
        }
    }

    Ok(())
}

/// Bootstrap the root identity from config.
///
/// If `[server.identity]` specifies a `key_path`, loads or creates
/// a file-based identity. Otherwise, uses the OS keyring.
fn bootstrap_identity(cfg: &config::Config) -> anyhow::Result<Ed25519Signer> {
    if let Some(ref identity_cfg) = cfg.server.identity {
        if let Some(ref key_path) = identity_cfg.key_path {
            let path = std::path::Path::new(key_path);
            return identity::load_or_create_file_identity(path);
        }
    }
    // Default: try OS keyring, fall back to file
    match identity::load_or_create_keyring_identity() {
        Ok(signer) => Ok(signer),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Keyring unavailable, falling back to file identity"
            );
            let default_path = dirs::config_dir()
                .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory for identity key"))?
                .join("smgglrs/identity.key");
            identity::load_or_create_file_identity(&default_path)
        }
    }
}

/// Build the permission engine from config.
fn build_perm_engine(cfg: &config::Config) -> PermissionEngine {
    let mut engine = PermissionEngine::new();
    for (name, pset) in &cfg.permissions {
        let acl = PathAcl {
            ring: pset.ring,
            allow: pset.allow.clone(),
            deny: pset.deny.clone(),
            operations: pset.operations.iter().cloned().collect(),
            requires_approval: pset.approve.iter().cloned().collect(),
        };
        engine.add_permission_set(name.clone(), acl);

        if let Some(ring) = pset.ring {
            tracing::info!(
                permission_set = %name,
                ring = ring,
                "Permission ring"
            );
        }
    }

    // When no agents are configured, anonymous access uses the "readonly"
    // permission set. If it's missing, tools will fail with DeniedUnknown.
    // Warn loudly at startup so the operator knows why.
    if cfg.agents.is_empty() && !cfg.permissions.contains_key("readonly") {
        tracing::warn!(
            "No [permissions.readonly] in config. Anonymous agents use the \
             'readonly' permission set — without it, all path-based tools \
             (file_read, file_tree, etc.) will be denied. Add a \
             [permissions.readonly] section to grant access."
        );
    }

    engine.apply_ring_inheritance();
    engine
}

async fn serve(cfg: config::Config, no_tray: bool) -> anyhow::Result<()> {
    tracing::info!("Starting smgglrs");

    // Bootstrap root identity (DID:key from Ed25519)
    let root_signer = Arc::new(bootstrap_identity(&cfg)?);
    tracing::info!(
        root_did = %root_signer.did(),
        algorithm = %root_signer.algorithm(),
        "Root identity"
    );

    // Build credential store from config mappings
    let _credential_store = Arc::new(
        smgglrs_core::credentials::MappedCredentialStore::new(cfg.credentials.clone())
    );
    if !cfg.credentials.is_empty() {
        tracing::info!(
            count = cfg.credentials.len(),
            "Credential mappings loaded"
        );
    }

    let perm_engine = Arc::new(build_perm_engine(&cfg));

    // Build quota engine from rate limits in permission sets
    let mut quota_engine = smgglrs_core::quota::QuotaEngine::new();
    for (name, pset) in &cfg.permissions {
        if let Some(ref rate_limit_str) = pset.rate_limit {
            if let Some((max_str, window_str)) = rate_limit_str.split_once('/') {
                if let (Ok(max_calls), Ok(window_secs)) =
                    (max_str.parse::<u64>(), window_str.parse::<u64>())
                {
                    quota_engine.add_limit(
                        name.clone(),
                        smgglrs_core::quota::RateLimit {
                            max_calls,
                            window_secs,
                        },
                    );
                    tracing::info!(
                        permission_set = %name,
                        max_calls = max_calls,
                        window_secs = window_secs,
                        "Rate limit"
                    );
                }
            }
        }
    }

    // Build server, registering enabled modules
    let mut builder = smgglrs_core::McpServer::builder()
        .name("smgglrs")
        .version(env!("CARGO_PKG_VERSION"))
        .hook_timeout(std::time::Duration::from_secs(cfg.server.hook_timeout_secs));

    // Persistent session store (SQLite) — sessions survive restarts
    {
        let session_db_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("smgglrs/sessions.db");
        if let Some(parent) = session_db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match smgglrs_memory::SqliteSessionBackend::open(&session_db_path) {
            Ok(backend) => {
                let existing = {
                    use smgglrs_core::session::SessionBackend;
                    backend.count()
                };
                let store = smgglrs_core::session::SessionStore::with_backend(
                    std::sync::Arc::new(backend),
                );
                builder = builder.session_store(store);
                tracing::info!(
                    path = %session_db_path.display(),
                    sessions = existing,
                    "Persistent session store enabled"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to open session DB, falling back to in-memory sessions"
                );
            }
        }
    }

    // Gateway blackbox — always on, append-only, hash-chained
    {
        let bb_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("smgglrs/blackbox.db");
        if let Some(parent) = bb_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match smgglrs_core::blackbox::Blackbox::open(&bb_path) {
            Ok(bb) => {
                let count = bb.count();
                builder = builder.blackbox(bb);
                tracing::info!(
                    path = %bb_path.display(),
                    entries = count,
                    "Blackbox enabled (append-only, hash-chained)"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to open blackbox — tool calls will NOT be recorded");
            }
        }
    }

    // Wire IFC policies and trusted paths from permission sets
    for (name, pset) in &cfg.permissions {
        let policy = smgglrs_core::ifc::TaintedWritePolicy::from_str(&pset.tainted_write_policy);
        if policy != smgglrs_core::ifc::TaintedWritePolicy::Allow {
            builder = builder.ifc_policy(name.clone(), policy.clone());
            tracing::info!(
                permission_set = %name,
                policy = %pset.tainted_write_policy,
                "IFC tainted write policy"
            );
        }
        if !pset.trusted_paths.is_empty() {
            tracing::info!(
                permission_set = %name,
                count = pset.trusted_paths.len(),
                "IFC trusted paths configured"
            );
            builder = builder.trusted_paths(name.clone(), pset.trusted_paths.clone());
        }
    }

    if quota_engine.has_limits() {
        builder = builder.quota_engine(quota_engine);
    }

    // Register authenticator chain if agents are configured
    if !cfg.agents.is_empty() {
        let has_cap_agents = cfg.agents.iter().any(|a| a.capability_token);

        // Issue capability tokens for agents that request them
        if has_cap_agents {
            let default_ttl = cfg
                .server
                .identity
                .as_ref()
                .map(|i| i.token_ttl)
                .unwrap_or(3600);

            for agent in &cfg.agents {
                if !agent.capability_token {
                    continue;
                }
                let pset = cfg.permissions.get(&agent.permissions);
                let (ring, paths, ops, creds) = match pset {
                    Some(ps) => (
                        ps.ring.unwrap_or(0),
                        ps.allow.clone(),
                        ps.operations.clone(),
                        ps.credentials.clone(),
                    ),
                    None => (0, vec![], vec![], vec![]),
                };
                let ttl = agent.token_ttl.unwrap_or(default_ttl);
                let subject_did = agent
                    .did
                    .clone()
                    .unwrap_or_else(|| format!("agent:{}", agent.name));

                let cap_set = smgglrs_core::auth::capability::CapabilitySet {
                    paths,
                    operations: ops,
                    tools: pset
                        .map(|ps| {
                            ps.tool_rules
                                .iter()
                                .filter(|r| r.policy == "allow")
                                .map(|r| r.tool.clone())
                                .collect::<Vec<_>>()
                        })
                        .filter(|v: &Vec<String>| !v.is_empty())
                        .unwrap_or_else(|| vec!["*".to_string()]),
                    credentials: creds,
                };

                let payload = smgglrs_core::auth::capability::build_payload(
                    root_signer.did(),
                    &subject_did,
                    cap_set,
                    ring,
                    ttl,
                );

                match smgglrs_core::auth::capability::encode_token(&payload, &root_signer) {
                    Ok(token) => {
                        // Log token prefix only — full token is a bearer credential
                        let token_prefix = if token.len() > 20 {
                            format!("{}...", &token[..20])
                        } else {
                            token.clone()
                        };
                        tracing::info!(
                            agent = %agent.name,
                            subject_did = %subject_did,
                            ring = ring,
                            ttl_secs = ttl,
                            token_prefix = %token_prefix,
                            "Issued capability token"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            agent = %agent.name,
                            error = %e,
                            "Failed to issue capability token"
                        );
                    }
                }
            }
        }

        let mut blake3_auth = TokenAuthenticator::new();
        for agent in &cfg.agents {
            blake3_auth.register_hash(
                &agent.token_hash,
                AgentIdentity {
                    name: agent.name.clone(),
                    permissions: agent.permissions.clone(),
                    signing_key: agent.signing_key.clone(),
                    did: agent.did.clone(),
                    capabilities: None,
                },
            );
            if agent.pubkey.is_some() {
                tracing::debug!(agent = %agent.name, "Agent has pubkey configured");
            }
            tracing::info!(agent = %agent.name, permissions = %agent.permissions, "Registered agent");
        }

        let nonce_cache_ttl = std::time::Duration::from_secs(
            cfg.server.identity.as_ref()
                .map(|i| i.nonce_cache_ttl_secs)
                .unwrap_or(7200),
        );

        if has_cap_agents {
            // Build ChainAuthenticator: capability tokens first, then BLAKE3
            let cap_auth = smgglrs_core::auth::chain::CapabilityAuthenticator::with_nonce_ttl(
                Box::new(Arc::clone(&root_signer)),
                nonce_cache_ttl,
            );
            let chain = smgglrs_core::auth::chain::ChainAuthenticator::new()
                .add(cap_auth)
                .add(blake3_auth);
            builder = builder.authenticator(chain);
            tracing::info!("Authenticator chain: capability tokens + BLAKE3");
        } else {
            builder = builder.authenticator(blake3_auth);
        }
    } else {
        // No agents configured, but flow tasks and teammates use capability
        // tokens minted by the server. Register CapabilityAuthenticator so
        // those tokens are verified (with proper DID identity), falling back
        // to anonymous for external clients.
        let nonce_cache_ttl = std::time::Duration::from_secs(
            cfg.server.identity.as_ref()
                .map(|i| i.nonce_cache_ttl_secs)
                .unwrap_or(7200),
        );
        let cap_auth = smgglrs_core::auth::chain::CapabilityAuthenticator::with_nonce_ttl(
            Box::new(Arc::clone(&root_signer)),
            nonce_cache_ttl,
        );
        let no_auth = smgglrs_core::auth::NoAuthenticator {
            default_identity: AgentIdentity::new("anonymous", "readonly"),
        };
        let chain = smgglrs_core::auth::chain::ChainAuthenticator::new()
            .add(cap_auth)
            .add(no_auth);
        builder = builder.authenticator(chain);
        tracing::warn!(
            "No agents configured — external requests accepted as anonymous. \
             Flow tasks and teammates authenticate via capability tokens."
        );
    }

    // --- Load models into registry ---
    let mut models: std::collections::HashMap<String, Arc<dyn smgglrs_model::ModelBackend>> =
        std::collections::HashMap::new();
    let mut running_endpoints: Vec<(Box<dyn smgglrs_model_runtime::ModelRuntime>, smgglrs_model_runtime::Endpoint)> =
        Vec::new();

    let hub = smgglrs_model_hub::ModelHub::new().ok();

    for (name, model_cfg) in &cfg.models {
        // --- Resolve model path: hub source or local file ---
        let resolved_path = if let Some(ref source) = model_cfg.source {
            // Pull from hub
            let Some(ref hub) = hub else {
                tracing::error!(model = %name, "Model hub unavailable, skipping");
                continue;
            };
            let uri = match smgglrs_model_hub::ModelUri::parse(source) {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!(model = %name, source = %source, error = %e, "Invalid model URI, skipping");
                    continue;
                }
            };
            match hub.pull(&uri).await {
                Ok(p) => {
                    tracing::info!(model = %name, source = %source, path = %p.display(), "Model pulled from hub");
                    p
                }
                Err(e) => {
                    tracing::error!(model = %name, source = %source, error = %e, "Failed to pull model, skipping");
                    continue;
                }
            }
        } else if let Some(ref path_str) = model_cfg.model_path {
            let expanded = expand_tilde(path_str);
            std::path::PathBuf::from(&expanded)
        } else {
            tracing::warn!(model = %name, "No source or model_path, skipping");
            continue;
        };

        if !resolved_path.exists() {
            tracing::warn!(
                model = %name,
                path = %resolved_path.display(),
                "Model file not found, skipping"
            );
            continue;
        }

        // --- Choose backend based on task ---
        let backend: Arc<dyn smgglrs_model::ModelBackend> = match model_cfg.task.as_str() {
            "embedding" => {
                let dims = model_cfg.dimensions.unwrap_or(768);
                let task = smgglrs_model::ModelTask::Embedding { dimensions: dims };
                let tokenizer_path = model_cfg
                    .tokenizer_path
                    .as_ref()
                    .map(|p| std::path::PathBuf::from(expand_tilde(p)));
                match smgglrs_model::OnnxBackend::load(name, &resolved_path, tokenizer_path.as_deref(), task) {
                    Ok(model) => Arc::new(model),
                    Err(e) => {
                        tracing::error!(model = %name, error = %e, "Failed to load ONNX model, skipping");
                        continue;
                    }
                }
            }
            "classification" => {
                let labels = if model_cfg.labels.is_empty() {
                    vec!["safe".to_string(), "unsafe".to_string()]
                } else {
                    model_cfg.labels.clone()
                };
                let task = smgglrs_model::ModelTask::Classification { labels };
                let tokenizer_path = model_cfg
                    .tokenizer_path
                    .as_ref()
                    .map(|p| std::path::PathBuf::from(expand_tilde(p)));
                match smgglrs_model::OnnxBackend::load(name, &resolved_path, tokenizer_path.as_deref(), task) {
                    Ok(model) => Arc::new(model),
                    Err(e) => {
                        tracing::error!(model = %name, error = %e, "Failed to load ONNX model, skipping");
                        continue;
                    }
                }
            }
            "chat" | "generate" => {
                // Serve via runtime and wrap in OpenAiBackend
                let runtime_kind = model_cfg.runtime.as_deref().unwrap_or("auto");
                let runtime: Box<dyn smgglrs_model_runtime::ModelRuntime> = match runtime_kind {
                    "auto" => match smgglrs_model_runtime::auto_runtime().await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::error!(model = %name, error = %e, "No runtime available, skipping");
                            continue;
                        }
                    },
                    "podman" => Box::new(smgglrs_model_runtime::podman::PodmanRuntime::new()),
                    "direct" => Box::new(smgglrs_model_runtime::direct::DirectRuntime::new()),
                    "none" => {
                        tracing::warn!(model = %name, "Task is chat/generate but runtime=none, skipping");
                        continue;
                    }
                    other => {
                        tracing::warn!(model = %name, runtime = %other, "Unknown runtime, skipping");
                        continue;
                    }
                };

                let gpus = smgglrs_model_runtime::detect_gpus();
                let serve_cfg = smgglrs_model_runtime::ServeConfig {
                    model_path: resolved_path,
                    gpus,
                    context_size: model_cfg.context_size.unwrap_or(4096),
                    parallel: model_cfg.parallel.unwrap_or(1),
                    ..Default::default()
                };

                let endpoint = match runtime.serve(&serve_cfg).await {
                    Ok(ep) => ep,
                    Err(e) => {
                        tracing::error!(model = %name, error = %e, "Failed to start model runtime, skipping");
                        continue;
                    }
                };

                tracing::info!(
                    model = %name,
                    url = %endpoint.url,
                    backend = ?endpoint.backend,
                    "Model served via runtime"
                );

                let model_id = model_cfg.model_name.clone().unwrap_or_else(|| name.clone());
                let backend: Arc<dyn smgglrs_model::ModelBackend> = Arc::new(
                    smgglrs_model::OpenAiBackend::new(
                        &endpoint.url,
                        &model_id,
                        None,
                        smgglrs_model::Locality::Local,
                    ),
                );

                running_endpoints.push((runtime, endpoint));
                backend
            }
            other => {
                tracing::warn!(model = %name, task = %other, "Unknown model task, skipping");
                continue;
            }
        };

        tracing::info!(model = %name, task = %model_cfg.task, "Model loaded");
        models.insert(name.clone(), backend);
    }

    tracing::info!(count = models.len(), "Model registry ready");

    // Register safety profiles and per-tool permissions per permission set
    for (name, pset) in &cfg.permissions {
        let mut pipeline = smgglrs_core::safety::build_pipeline(&pset.safety);

        // Add custom regex patterns if configured
        if !pset.safety_patterns.is_empty() {
            let patterns: Vec<(String, String)> = pset
                .safety_patterns
                .iter()
                .map(|p| (p.category.clone(), p.pattern.clone()))
                .collect();
            let custom = smgglrs_core::safety::CustomFilter::new(patterns);
            if custom.has_patterns() {
                tracing::info!(
                    permission_set = %name,
                    patterns = pset.safety_patterns.len(),
                    "Custom safety patterns"
                );
                pipeline.add_filter(custom);
            }
        }

        // Add ML safety filter from any loaded classification model
        for (model_name, model_cfg) in &cfg.models {
            if model_cfg.task == "classification" {
                if let Some(model) = models.get(model_name) {
                    let threshold = model_cfg.threshold.unwrap_or(0.5);
                    pipeline.add_model_filter(smgglrs_core::safety::MlFilter::new(
                        model.clone(),
                        threshold,
                        "ml-unsafe",
                    ));
                }
            }
        }

        tracing::info!(
            permission_set = %name,
            safety = %pset.safety,
            "Safety profile"
        );
        builder = builder.safety_profile(name.clone(), pipeline);

        // Log compliance tags for audit trail
        if !pset.compliance.is_empty() {
            tracing::info!(
                permission_set = %name,
                tags = ?pset.compliance,
                "Compliance tags"
            );
        }

        // Build per-tool permission rules if any are configured
        if !pset.tool_rules.is_empty() {
            let rules: Vec<ToolRule> = pset
                .tool_rules
                .iter()
                .map(|r| ToolRule {
                    tool: r.tool.clone(),
                    policy: match r.policy.as_str() {
                        "deny" => ToolPolicy::Deny,
                        "approve" => ToolPolicy::Approve,
                        _ => ToolPolicy::Allow,
                    },
                })
                .collect();
            let default = match pset.default_tool_policy.as_str() {
                "deny" => ToolPolicy::Deny,
                "approve" => ToolPolicy::Approve,
                _ => ToolPolicy::Allow,
            };
            tracing::info!(
                permission_set = %name,
                rules = rules.len(),
                "Tool permission rules"
            );
            builder = builder.tool_permissions(name.clone(), ToolPermissions::new(rules, default));
        }
    }

    // Build shared approval infrastructure
    let approvals = Arc::new(smgglrs_core::permissions::ApprovalStore::with_grant_ttl(
        cfg.approval.timeout_secs,
        cfg.approval.grant_ttl_secs,
    ));
    let notifier: Arc<dyn smgglrs_core::notify::Notifier> = match cfg.approval.notify.as_str() {
        "dbus" => {
            match smgglrs_core::notify::DbusNotifier::new().await {
                Ok(n) => {
                    tracing::info!("D-Bus notifier connected");
                    Arc::new(n)
                }
                Err(e) => {
                    tracing::warn!("D-Bus unavailable ({e}), falling back to CLI-only approvals");
                    Arc::new(smgglrs_core::notify::NoopNotifier)
                }
            }
        }
        _ => Arc::new(smgglrs_core::notify::NoopNotifier),
    };

    // --- Resolve named models for modules ---
    // Find the first embedding model in the registry.
    let embedding_model_name = cfg
        .models
        .iter()
        .find(|(_, m)| m.task == "embedding")
        .map(|(name, _)| name.clone());
    let embedding_model = embedding_model_name
        .as_ref()
        .and_then(|name| models.get(name))
        .cloned();

    // --- Docs module ---
    // Keep watcher handle alive for the lifetime of the server.
    let mut _watcher_handle: Option<smgglrs_tools_docs::WatcherHandle> = None;
    if cfg.docs_enabled() {
        let db_path = cfg.docs_db_path();
        let mut index = smgglrs_tools_docs::IndexStore::open(&db_path)?;

        // Enable vector search if an embedding model is loaded
        if embedding_model.is_some() {
            let dims = embedding_model_name
                .as_ref()
                .and_then(|name| cfg.models.get(name))
                .and_then(|m| m.dimensions)
                .unwrap_or(768);
            index.enable_vectors(dims)?;
            tracing::info!(dimensions = dims, "Vector search enabled");
        }

        let index = Arc::new(index);

        let docs = if let Some(ref model) = embedding_model {
            smgglrs_tools_docs::DocsModule::with_embeddings(
                perm_engine.clone(),
                index.clone(),
                approvals.clone(),
                notifier.clone(),
                model.clone(),
            )
        } else {
            smgglrs_tools_docs::DocsModule::new(
                perm_engine.clone(),
                index.clone(),
                approvals.clone(),
                notifier.clone(),
            )
        };
        // Set default root for file_tree.
        // Priority: [modules.docs] default_root > top-level cognitive_core
        let mut docs = docs;
        let docs_root = cfg.modules.docs.as_ref()
            .and_then(|d| d.default_root.as_deref())
            .or(cfg.cognitive_core.as_deref());
        if let Some(root_path) = docs_root {
            let expanded = expand_tilde(root_path);
            if let Ok(canonical) = std::fs::canonicalize(&expanded) {
                let root = canonical.display().to_string();
                tracing::info!(default_root = %root, "Setting file_tree default root");
                docs.set_default_root(root);
            }
        }
        tracing::info!("Module 'docs' enabled (db: {db_path})");
        builder = builder.module(docs);

        // Start file watcher if watch directories are configured
        let watch_dirs: Vec<_> = cfg
            .modules
            .docs
            .as_ref()
            .map(|d| &d.watch)
            .into_iter()
            .flatten()
            .map(|dir| {
                if dir.starts_with("~/") {
                    dirs::home_dir()
                        .map(|h| h.join(&dir[2..]))
                        .unwrap_or_else(|| std::path::PathBuf::from(dir))
                } else {
                    std::path::PathBuf::from(dir)
                }
            })
            .filter_map(|p| match p.canonicalize() {
                Ok(canonical) => Some(canonical),
                Err(e) => {
                    tracing::warn!(path = %p.display(), error = %e, "Skipping watch directory: canonicalization failed");
                    None
                }
            })
            .collect();
        if !watch_dirs.is_empty() {
            match smgglrs_tools_docs::start_watcher_with_embeddings(
                watch_dirs,
                index,
                embedding_model.clone(),
            ) {
                Ok(handle) => {
                    tracing::info!("File watcher active");
                    _watcher_handle = Some(handle);
                }
                Err(e) => {
                    tracing::warn!("Failed to start file watcher: {e}");
                }
            }
        }
    }

    // --- Git module ---
    if cfg.git_enabled() {
        let git = smgglrs_tools_git::GitModule::new(
            perm_engine.clone(),
            approvals.clone(),
            notifier.clone(),
        );
        tracing::info!("Module 'git' enabled");
        builder = builder.module(git);
    }

    // --- RAG module ---
    if cfg.rag_enabled() {
        if let Some(ref model) = embedding_model {
            let rag_db_path = cfg.rag_db_path();
            let dims = embedding_model_name
                .as_ref()
                .and_then(|name| cfg.models.get(name))
                .and_then(|m| m.dimensions)
                .unwrap_or(768);
            match smgglrs_rag::ChunkStore::open(&rag_db_path, dims) {
                Ok(store) => {
                    let rag = smgglrs_rag::RagModule::new(
                        std::sync::Arc::new(store),
                        model.clone(),
                        perm_engine.clone(),
                    );
                    tracing::info!("Module 'rag' enabled (db: {rag_db_path}, dims: {dims})");
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
                let voice = smgglrs_modal_voice::VoiceModule::with_config(
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
            let vision = smgglrs_modal_vision::VisionModule::new(vision_model, perm_engine.clone());
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
    // Loaded once here so upstream persona: prompts can be registered
    // before the forge is shared with other subsystems.
    let mut forge = if let Some(ref cc_path) = cfg.cognitive_core {
        let expanded = expand_tilde(cc_path);
        match smgglrs_cognitive::ForgeService::load(std::path::Path::new(&expanded)) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load cognitive core, using empty forge");
                smgglrs_cognitive::ForgeService::empty()
            }
        }
    } else {
        smgglrs_cognitive::ForgeService::empty()
    };

    // --- AID upstream discovery ---
    if !cfg.discover.is_empty() {
        tracing::info!(
            domains = cfg.discover.len(),
            "Discovering upstream MCP servers via AID"
        );
        let discovery_timeout = cfg.server.discovery.as_ref()
            .map(|d| std::time::Duration::from_secs(d.timeout_secs))
            .unwrap_or_else(|| std::time::Duration::from_secs(10));
        let discovered = discover::discover_all_with_timeout(&cfg.discover, discovery_timeout).await;
        for endpoint in &discovered {
            tracing::info!(
                domain = %endpoint.domain,
                url = %endpoint.url,
                description = ?endpoint.description,
                auth = ?endpoint.auth,
                "Discovered MCP endpoint"
            );
            match smgglrs_core::Upstream::http(&endpoint.domain, &endpoint.url).await {
                Ok(upstream) => match smgglrs_core::UpstreamModule::discover(upstream).await {
                    Ok(module) => {
                        tracing::info!(
                            domain = %endpoint.domain,
                            "Connected discovered upstream"
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
                            "Failed to discover capabilities of AID endpoint"
                        );
                    }
                },
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
    // Keep the daemon alive for advertising — drop stops it.
    let mut _mdns_daemon: Option<mdns_sd::ServiceDaemon> = None;

    if mdns_enabled {
        let mdns_browse_secs = cfg.server.discovery.as_ref()
            .map(|d| d.mdns_browse_secs)
            .unwrap_or(3);
        tracing::info!("Browsing LAN for MCP servers via mDNS...");
        let lan_servers =
            mdns::browse(std::time::Duration::from_secs(mdns_browse_secs)).await;

        for server in &lan_servers {
            let url = server.url();
            match smgglrs_core::Upstream::http(&server.name, &url).await {
                Ok(upstream) => match smgglrs_core::UpstreamModule::discover(upstream).await {
                    Ok(module) => {
                        tracing::info!(
                            name = %server.name,
                            url = %url,
                            "Connected LAN upstream"
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
                            "Failed to discover LAN upstream capabilities"
                        );
                    }
                },
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
    for upstream_cfg in &cfg.upstream {
        if !upstream_cfg.enabled.unwrap_or(true) {
            tracing::info!(upstream = %upstream_cfg.name, "Upstream disabled, skipping");
            continue;
        }

        let retry_config = upstream_cfg.retry_config();
        let connect_result = match upstream_cfg.transport.as_str() {
            "stdio" => {
                if let Some(rc) = retry_config {
                    tracing::info!(
                        upstream = %upstream_cfg.name,
                        "Using resilient transport (retry enabled)"
                    );
                    smgglrs_core::Upstream::spawn_resilient(
                        &upstream_cfg.name,
                        &upstream_cfg.command,
                        upstream_cfg.cwd.as_deref(),
                        rc,
                    )
                    .await
                } else {
                    smgglrs_core::Upstream::spawn(
                        &upstream_cfg.name,
                        &upstream_cfg.command,
                        upstream_cfg.cwd.as_deref(),
                    )
                    .await
                }
            }
            "http" | "streamable-http" => {
                let url = match &upstream_cfg.url {
                    Some(u) => u.as_str(),
                    None => {
                        tracing::error!(
                            upstream = %upstream_cfg.name,
                            "HTTP upstream requires 'url' field, skipping"
                        );
                        continue;
                    }
                };
                if let Some(rc) = retry_config {
                    tracing::info!(
                        upstream = %upstream_cfg.name,
                        "Using resilient transport (retry enabled)"
                    );
                    smgglrs_core::Upstream::http_resilient(&upstream_cfg.name, url, rc).await
                } else {
                    smgglrs_core::Upstream::http(&upstream_cfg.name, url).await
                }
            }
            "sse" => {
                let url = match &upstream_cfg.url {
                    Some(u) => u.as_str(),
                    None => {
                        tracing::error!(
                            upstream = %upstream_cfg.name,
                            "SSE upstream requires 'url' field, skipping"
                        );
                        continue;
                    }
                };
                if let Some(rc) = retry_config {
                    tracing::info!(
                        upstream = %upstream_cfg.name,
                        "Using resilient transport (retry enabled)"
                    );
                    smgglrs_core::Upstream::sse_resilient(&upstream_cfg.name, url, rc).await
                } else {
                    smgglrs_core::Upstream::sse(&upstream_cfg.name, url).await
                }
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

        match connect_result {
            Ok(upstream) => match smgglrs_core::UpstreamModule::discover(upstream).await {
                Ok(module) => {
                    tracing::info!(
                        upstream = %upstream_cfg.name,
                        transport = %upstream_cfg.transport,
                        "Connected upstream"
                    );

                    // Auto-discover persona prompts from this upstream.
                    // Prompts named "persona:<name>" are registered as
                    // personas in the ForgeService. Local YAML personas
                    // take precedence over auto-discovered ones.
                    for prompt_def in module.discovered_prompts() {
                        if let Some(persona_name) = prompt_def.name.strip_prefix("persona:") {
                            let description = prompt_def
                                .description
                                .as_deref()
                                .unwrap_or("");
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
                    tracing::error!(
                        upstream = %upstream_cfg.name,
                        error = %e,
                        "Failed to discover upstream capabilities, skipping"
                    );
                }
            },
            Err(e) => {
                tracing::error!(
                    upstream = %upstream_cfg.name,
                    error = %e,
                    "Failed to connect upstream, skipping"
                );
            }
        }
    }

    // Register cap_delegate tool if any agent can delegate
    if cfg
        .permissions
        .values()
        .any(|ps| ps.can_delegate)
    {
        let delegate_signer = Arc::clone(&root_signer);
        let delegate_permissions = cfg.permissions.clone();
        let max_depth = cfg
            .server
            .identity
            .as_ref()
            .map(|i| i.max_delegation_depth)
            .unwrap_or(3);
        let default_ttl = cfg
            .server
            .identity
            .as_ref()
            .map(|i| i.token_ttl)
            .unwrap_or(3600);

        builder = builder.tool(
            smgglrs_core::protocol::ToolDefinition {
                name: "cap_delegate".to_string(),
                description: Some(
                    "Issue an attenuated capability token for a sub-agent. \
                     The new token grants a subset of the caller's capabilities."
                        .to_string(),
                ),
                input_schema: smgglrs_core::protocol::ToolInputSchema {
                    schema_type: "object".to_string(),
                    properties: {
                        let mut props = std::collections::HashMap::new();
                        props.insert("subject_did".to_string(), serde_json::json!({
                            "type": "string",
                            "description": "DID of the sub-agent receiving the token"
                        }));
                        props.insert("ring".to_string(), serde_json::json!({
                            "type": "integer",
                            "description": "Ring level (must be >= caller's ring)"
                        }));
                        props.insert("operations".to_string(), serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Operations to grant (subset of caller's)"
                        }));
                        props.insert("tools".to_string(), serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Tool globs to grant (subset of caller's)"
                        }));
                        props.insert("paths".to_string(), serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Path globs to grant (subset of caller's)"
                        }));
                        props.insert("credentials".to_string(), serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Credential labels to grant (subset of caller's)"
                        }));
                        props.insert("ttl".to_string(), serde_json::json!({
                            "type": "integer",
                            "description": "Token TTL in seconds"
                        }));
                        Some(props)
                    },
                    required: Some(vec!["subject_did".to_string()]),
                },
            },
            move |args, ctx| {
                let signer = Arc::clone(&delegate_signer);
                let permissions = delegate_permissions.clone();
                let max_depth = max_depth;
                let default_ttl = default_ttl;
                Box::pin(async move {
                    use smgglrs_core::auth::capability::{
                        build_payload, encode_token, validate_delegation, CapabilitySet,
                    };
                    use smgglrs_core::protocol::CallToolResult;

                    // Check caller has capabilities (must be cap-token authenticated)
                    // Reject callers with wildcard tool access — cap_delegate must
                    // be explicitly listed in the token's tools (CWE-269).
                    let parent_caps = match &ctx.agent.capabilities {
                        Some(caps) => {
                            if !caps.tools.iter().any(|t| t == "cap_delegate") {
                                return CallToolResult::error(
                                    "Permission denied: cap_delegate must be explicitly \
                                     listed in capability token tools (wildcard not accepted)"
                                );
                            }
                            caps
                        }
                        None => {
                            // Legacy agent — check can_delegate via permission set
                            let perm_name = &ctx.agent.permissions;
                            let can_delegate = permissions
                                .get(perm_name)
                                .map(|ps| ps.can_delegate)
                                .unwrap_or(false);
                            if !can_delegate {
                                return CallToolResult::error(
                                    "Permission denied: delegation not allowed for this agent",
                                );
                            }
                            // Build a pseudo-parent from permission set for validation
                            return CallToolResult::error(
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
                        return CallToolResult::error("subject_did is required");
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

                    let mut child_payload = build_payload(
                        &issuer_did,
                        &subject_did,
                        cap_set,
                        ring,
                        ttl,
                    );

                    // Build parent payload for validation
                    let parent_payload =
                        smgglrs_core::auth::capability::CapabilityPayload {
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
                            nonce: smgglrs_core::auth::capability::generate_nonce(),
                            parent: None,
                        };

                    // Set parent nonce reference
                    child_payload.parent = Some(parent_payload.nonce);

                    // Validate attenuation
                    if let Err(e) = validate_delegation(&parent_payload, &child_payload, max_depth) {
                        return CallToolResult::error(format!("Delegation denied: {e}"));
                    }

                    // Sign with root key (smgglrs signs all tokens)
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
                        Err(e) => CallToolResult::error(format!("Failed to sign token: {e}")),
                    }
                })
            },
        );
        tracing::info!("Registered cap_delegate tool");
    }

    // Register sys_status tool (process table viewer)
    {
        builder = builder.tool(
            smgglrs_core::protocol::ToolDefinition {
                name: "sys_status".to_string(),
                description: Some(
                    "Show AI OS process table: active agents, their rings, \
                     call counts, and active tool calls."
                        .to_string(),
                ),
                input_schema: smgglrs_core::protocol::ToolInputSchema {
                    schema_type: "object".to_string(),
                    properties: None,
                    required: None,
                },
            },
            |_args, _ctx| {
                // The actual data comes from the server's process table,
                // but the handler doesn't have access to &self.
                // We return a placeholder — the real implementation
                // will be added when we refactor tool handlers to
                // receive a server reference.
                Box::pin(async {
                    smgglrs_core::protocol::CallToolResult::text(
                        "sys_status: use GET /sys/status for process table"
                    )
                })
            },
        );
    }

    // Resolve flow directories (auto-discover if not configured)
    let resolved_flow_dirs = {
        let mut dirs = cfg.flow_dirs.clone();
        if dirs.is_empty() {
            for candidate in &["examples/flows", "flows"] {
                if std::path::Path::new(candidate).is_dir() {
                    dirs.push(candidate.to_string());
                }
            }
        }
        dirs
    };

    // Register flow orchestration tools
    let flow_registry = Arc::new(flow_tools::FlowRegistry::new());
    {
        // flow_start — registered later, after team_registry is created

        // flow_status — check progress of a flow
        let registry = Arc::clone(&flow_registry);
        builder = builder.tool(
            flow_tools::flow_status_tool_def(),
            move |args, _ctx| {
                let registry = Arc::clone(&registry);
                Box::pin(flow_tools::handle_flow_status(args, registry))
            },
        );

        // flow_result — get output from a completed flow or node
        let registry = Arc::clone(&flow_registry);
        builder = builder.tool(
            flow_tools::flow_result_tool_def(),
            move |args, _ctx| {
                let registry = Arc::clone(&registry);
                Box::pin(flow_tools::handle_flow_result(args, registry))
            },
        );

        // flow_list — list available YAML flows from configured directories
        let flow_dirs = resolved_flow_dirs.clone();
        builder = builder.tool(
            flow_tools::flow_list_tool_def(),
            move |_args, _ctx| {
                let flow_dirs = flow_dirs.clone();
                Box::pin(flow_tools::handle_flow_list(flow_dirs))
            },
        );

        tracing::info!("Registered flow orchestration tools (flow_start, flow_status, flow_result, flow_list, flow_escalate)");
    }

    // Register team orchestration tools
    {
        // Pre-fetch Ollama model metadata for all locally running models.
        // This populates vendor fields (family, parameters, context_window)
        // so the lead agent can make informed model selection decisions.
        let mut ollama_meta: std::collections::HashMap<String, serde_json::Value> =
            std::collections::HashMap::new();
        if let Ok(resp) = reqwest::Client::new()
            .get("http://localhost:11434/api/tags")
            .send()
            .await
        {
            if let Ok(tags) = resp.json::<serde_json::Value>().await {
                if let Some(models) = tags["models"].as_array() {
                    for m in models {
                        if let Some(name) = m["name"].as_str() {
                            // Query /api/show for detailed model info
                            if let Ok(show_resp) = reqwest::Client::new()
                                .post("http://localhost:11434/api/show")
                                .json(&serde_json::json!({"name": name}))
                                .send()
                                .await
                            {
                                if let Ok(info) = show_resp.json::<serde_json::Value>().await {
                                    ollama_meta.insert(name.to_string(), info);
                                }
                            }
                        }
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

        // Build composite model cards from config + vendor metadata + operator agentic metadata.
        // If no [models.*] configured, auto-discover from Ollama.
        let model_keys: Vec<(String, Option<&config::ModelConfig>)> = if cfg.models.is_empty() {
            ollama_meta.keys().map(|name| (name.clone(), None)).collect()
        } else {
            cfg.models.iter().map(|(k, v)| (k.clone(), Some(v))).collect()
        };

        let model_cards: Vec<team_tools::ModelCard> = model_keys.iter().map(|(name, mcfg_opt)| {
            let mcfg_ref = mcfg_opt.as_ref();
            let display_name = mcfg_ref.and_then(|m| m.model_name.as_deref()).unwrap_or(name);
            let uri_str = mcfg_ref.and_then(|m| m.source.as_deref()).unwrap_or(display_name);
            let mut card = smgglrs_model_hub::ModelCard::new(uri_str);

            // Populate vendor metadata from config (if available)
            if let Some(mcfg) = mcfg_ref {
                card.vendor.source = Some(if mcfg.source.is_some() {
                    match mcfg.source.as_deref() {
                        Some(s) if s.starts_with("ollama://") => "ollama",
                        Some(s) if s.starts_with("hf://") => "huggingface",
                        Some(s) if s.starts_with("oci://") => "oci",
                        _ => "local",
                    }
                } else {
                    "local"
                }.into());
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

            // Enrich with Ollama /api/show metadata if available
            if let Some(info) = ollama_meta.get(display_name) {
                card.vendor.source = Some("ollama".into());
                // model_info contains parameter count, architecture, etc.
                if let Some(model_info) = info.get("model_info") {
                    // Extract context window from model metadata
                    for (key, val) in model_info.as_object().into_iter().flatten() {
                        if key.ends_with(".context_length") {
                            if let Some(ctx) = val.as_u64() {
                                card.vendor.context_window = Some(ctx as u32);
                            }
                        }
                        if key.ends_with(".embedding_length") {
                            if let Some(dim) = val.as_u64() {
                                card.vendor.custom.insert(
                                    "embedding_dim".into(),
                                    serde_json::json!(dim),
                                );
                            }
                        }
                    }
                    // Parameter count from general.parameter_count
                    if let Some(params) = model_info.get("general.parameter_count") {
                        if let Some(p) = params.as_u64() {
                            let label = if p >= 1_000_000_000 {
                                format!("{}B", p / 1_000_000_000)
                            } else if p >= 1_000_000 {
                                format!("{}M", p / 1_000_000)
                            } else {
                                format!("{p}")
                            };
                            card.vendor.parameters = Some(label);
                        }
                    }
                    // Architecture / family
                    if let Some(arch) = model_info.get("general.architecture") {
                        if let Some(a) = arch.as_str() {
                            card.vendor.family = Some(a.to_string());
                        }
                    }
                }
                // Quantization from details
                if let Some(details) = info.get("details") {
                    if let Some(quant) = details.get("quantization_level") {
                        if let Some(q) = quant.as_str() {
                            card.vendor.quantization = Some(q.to_string());
                        }
                    }
                    if let Some(family) = details.get("family") {
                        if card.vendor.family.is_none() {
                            card.vendor.family = family.as_str().map(|s| s.to_string());
                        }
                    }
                }
                // License from license field
                if let Some(license) = info.get("license") {
                    if let Some(l) = license.as_str() {
                        // Take first line as the license identifier
                        card.vendor.license = l.lines().next().map(|s| s.to_string());
                    }
                }
                card.vendor.format = Some("gguf".into());
            }

            // Detect Claude/Anthropic models
            if display_name.starts_with("claude") {
                card.vendor.source = Some("anthropic".into());
                card.vendor.family = Some("claude".into());
                // Extract parameter hint from model name (e.g. "sonnet", "opus")
                if display_name.contains("sonnet") {
                    card.vendor.parameters = Some("medium".into());
                } else if display_name.contains("opus") {
                    card.vendor.parameters = Some("large".into());
                } else if display_name.contains("haiku") {
                    card.vendor.parameters = Some("small".into());
                }
            }

            // Merge operator-defined agentic metadata from config
            if let Some(mcfg) = mcfg_ref {
                if let Some(agentic_cfg) = &mcfg.agentic {
                    card.merge_agentic(&agentic_cfg.to_agentic_meta());
                }
            }

            card
        }).collect();

        let team_registry = Arc::new(team_tools::TeamRegistry::new().with_models(model_cards));

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

        // Root capability payload for teammate token delegation.
        // Grants all operations and tools that teammates could possibly use.
        // Individual teammate tokens are scoped down from this via
        // build_delegated_payload (attenuation-only delegation chain).
        let root_cap = smgglrs_core::auth::capability::CapabilitySet {
            paths: vec!["**".to_string()],
            operations: vec![
                "read".to_string(), "write".to_string(), "search".to_string(),
                "list".to_string(), "git.status".to_string(), "git.diff".to_string(),
                "git.log".to_string(), "git.commit".to_string(), "git.branch".to_string(),
            ],
            tools: vec!["*".to_string()],
            credentials: vec![],
        };
        let root_payload = smgglrs_core::auth::capability::build_payload(
            root_signer.did(), root_signer.did(), root_cap, 1, 86400,
        );

        // team_message — async: spawns full agent teammate in background
        let msg_spawn_ctx = Arc::new(team_tools::TeammateSpawnContext {
            team_registry: Arc::clone(&team_registry),
            smgglrs_addr: cfg.server.listen_addr(),
            signer: Arc::clone(&root_signer),
            forge: cfg.cognitive_core.as_ref().and_then(|p| {
                let expanded = expand_tilde(p);
                smgglrs_cognitive::ForgeService::load(std::path::Path::new(&expanded))
                    .map(Arc::new)
                    .ok()
            }),
            root_payload: Some(root_payload.clone()),
        });
        builder = builder.tool(team_tools::team_message_def(), move |args, _ctx| {
            let spawn_ctx = Arc::clone(&msg_spawn_ctx);
            Box::pin(async move {
                team_tools::handle_team_message(args, &spawn_ctx).await
            })
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

        // models_list
        let cards = team_registry.model_cards.clone();
        builder = builder.tool(team_tools::models_list_def(), move |_args, _ctx| {
            let cards = cards.clone();
            Box::pin(team_tools::handle_models_list(cards))
        });

        // personas_list
        let persona_data: Vec<serde_json::Value> = if let Some(ref cc_path) = cfg.cognitive_core {
            let expanded = expand_tilde(cc_path);
            match smgglrs_cognitive::ForgeService::load(std::path::Path::new(&expanded)) {
                Ok(forge) => {
                    forge.persona_names().iter().filter_map(|name| {
                        forge.get_persona(name).map(|p| serde_json::json!({
                            "name": p.persona_name,
                            "display_name": p.display_name,
                            "mandate": p.core_mandate.lines().next().unwrap_or(""),
                            "heuristics": p.heuristics.len(),
                            "tools": p.tools,
                        }))
                    }).collect()
                }
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
            Box::pin(async move {
                team_tools::handle_team_bb_publish(args, reg, &agent_name).await
            })
        });

        // team_bb_read
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_bb_read_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_team_bb_read(args, reg))
        });

        tracing::info!("Registered team tools (team_create, team_add, team_message, team_status, team_result, team_shutdown, team_bb_publish, team_bb_read, models_list)");

        // flow_start and flow_escalate — shared context
        let flow_ctx = Arc::new(flow_tools::FlowContext {
            flow_registry: Arc::clone(&flow_registry),
            team_registry: Arc::clone(&team_registry),
            smgglrs_addr: cfg.server.listen_addr(),
            signer: Arc::clone(&root_signer),
            forge: cfg.cognitive_core.as_ref().and_then(|p| {
                let expanded = expand_tilde(p);
                smgglrs_cognitive::ForgeService::load(std::path::Path::new(&expanded)).ok().map(Arc::new)
            }),
            budget_cfg: cfg.budget.clone(),
            flow_dirs: resolved_flow_dirs.clone(),
            docs_root: cfg.modules.docs.as_ref()
                .and_then(|d| d.default_root.clone())
                .or_else(|| cfg.cognitive_core.clone()),
            root_payload: Some(root_payload.clone()),
        });

        // flow_start
        let fs_ctx = Arc::clone(&flow_ctx);
        builder = builder.tool(
            flow_tools::flow_start_tool_def(),
            move |args, ctx| {
                let flow_ctx = Arc::clone(&fs_ctx);
                let agent_name = ctx.agent.name.clone();
                Box::pin(async move {
                    flow_tools::handle_flow_start(args, flow_ctx, &agent_name).await
                })
            },
        );

        // flow_escalate
        let fe_ctx = Arc::clone(&flow_ctx);
        builder = builder.tool(
            flow_tools::flow_escalate_tool_def(),
            move |args, ctx| {
                let flow_ctx = Arc::clone(&fe_ctx);
                let agent_name = ctx.agent.name.clone();
                Box::pin(async move {
                    flow_tools::handle_flow_escalate(args, flow_ctx, &agent_name).await
                })
            },
        );

        tracing::info!("Registered flow escalation tool (flow_escalate)");
    }

    // --- Knowledge memory tools ---
    let knowledge_store: Option<Arc<std::sync::Mutex<smgglrs_memory::KnowledgeStore>>> = {
        let kb_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("smgglrs/knowledge.db");
        if let Some(parent) = kb_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match smgglrs_memory::KnowledgeStore::open(&kb_path) {
            Ok(store) => {
                tracing::info!(path = %kb_path.display(), "Knowledge store opened");
                Some(Arc::new(std::sync::Mutex::new(store)))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to open knowledge store, memory tools disabled");
                None
            }
        }
    };

    if knowledge_store.is_some() {
        let ks = knowledge_store.clone().unwrap();

        let ks_store = Arc::clone(&ks);
        builder = builder.tool(memory_tools::memory_store_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_store);
            Box::pin(memory_tools::handle_memory_store(args, ks))
        });

        let ks_query = Arc::clone(&ks);
        builder = builder.tool(memory_tools::memory_query_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_query);
            Box::pin(memory_tools::handle_memory_query(args, ks))
        });

        let ks_forget = Arc::clone(&ks);
        builder = builder.tool(memory_tools::memory_forget_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_forget);
            Box::pin(memory_tools::handle_memory_forget(args, ks))
        });

        tracing::info!("Registered memory tools (memory_store, memory_query, memory_forget)");
    }

    // --- Registry proxy module ---
    if cfg.registry_enabled() && !cfg.registry.is_empty() {
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
        builder = builder.tool(registry_tools::registry_describe_def(), move |args, _ctx| {
            let rs = Arc::clone(&rs);
            Box::pin(registry_tools::handle_registry_describe(args, rs))
        });

        tracing::info!(
            registries = cfg.registry.len(),
            "Registered registry proxy tools (registry_search, registry_list, registry_describe)"
        );
    }

    // Register audit_query tool
    {
        let audit_db_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("smgglrs/audit.db");
        if let Some(parent) = audit_db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let audit_log = match smgglrs_memory::audit::AuditLog::open(&audit_db_path) {
            Ok(log) => {
                tracing::info!(path = %audit_db_path.display(), "Audit log enabled");
                Arc::new(log)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to open audit DB, using in-memory");
                Arc::new(smgglrs_memory::audit::AuditLog::open_memory().unwrap())
            }
        };

        let audit = Arc::clone(&audit_log);
        builder = builder.tool(
            smgglrs_core::protocol::ToolDefinition {
                name: "audit_query".to_string(),
                description: Some(
                    "Query the structured audit log. Returns tool calls, model calls, \
                     and run summaries from past agent executions. Use to inspect \
                     what tools were called, with what arguments, and what results \
                     were returned."
                        .to_string(),
                ),
                input_schema: smgglrs_core::protocol::ToolInputSchema {
                    schema_type: "object".to_string(),
                    properties: {
                        let mut props = std::collections::HashMap::new();
                        props.insert("run_id".to_string(), serde_json::json!({
                            "type": "string",
                            "description": "Filter by run ID (returns tool calls for that run)"
                        }));
                        props.insert("summary".to_string(), serde_json::json!({
                            "type": "boolean",
                            "description": "If true, return a summary instead of individual entries"
                        }));
                        Some(props)
                    },
                    required: None,
                },
            },
            move |args, _ctx| {
                let audit = Arc::clone(&audit);
                Box::pin(async move {
                    use smgglrs_core::protocol::CallToolResult;

                    let run_id = args.get("run_id").and_then(|v| v.as_str());

                    if let Some(rid) = run_id {
                        let summary = args.get("summary").and_then(|v| v.as_bool()).unwrap_or(false);
                        if summary {
                            match audit.get_summary(rid) {
                                Ok(s) => CallToolResult::text(
                                    serde_json::to_string_pretty(&s).unwrap_or_default()
                                ),
                                Err(e) => CallToolResult::error(format!("Audit query failed: {e}")),
                            }
                        } else {
                            match audit.get_tool_calls(rid) {
                                Ok(calls) => CallToolResult::text(
                                    serde_json::to_string_pretty(&calls).unwrap_or_default()
                                ),
                                Err(e) => CallToolResult::error(format!("Audit query failed: {e}")),
                            }
                        }
                    } else {
                        // No run_id — list recent runs
                        match audit.get_run("latest") {
                            Ok(run) => CallToolResult::text(
                                serde_json::to_string_pretty(&run).unwrap_or_default()
                            ),
                            Err(_) => CallToolResult::text("No audit runs found. Run a demo first.".to_string()),
                        }
                    }
                })
            },
        );
        tracing::info!("Registered audit_query tool");
    }

    let server = Arc::new(builder.build());
    tracing::info!(
        tools = server.tool_count(),
        prompts = server.prompt_count(),
        resources = server.resource_count(),
        "Server ready"
    );

    // --- mDNS advertising ---
    if mdns_enabled {
        // Extract port from TCP address for advertising
        let tcp_port = cfg
            .server
            .tcp
            .as_ref()
            .and_then(|addr| addr.rsplit(':').next())
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(9315);

        match mdns::advertise(&server.server_info().name, tcp_port, "/mcp") {
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
                    approvals.clone(),
                    server.pause_flag(),
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

    // Add smgglrs's own entry (from its server card data)
    if let Some(ref discovery) = cfg.server.discovery {
        registry_entries.push(serde_json::json!({
            "server": {
                "name": server.server_info().name,
                "description": format!(
                    "{}",
                    discovery.description.as_deref().unwrap_or("smgglrs MCP gateway")
                ),
                "version": server.server_info().version,
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

    // Add whitelisted entries from config
    for entry in &cfg.registry {
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
    let broadcaster = smgglrs_core::transport::SseBroadcaster::new();
    let has_discovery = cfg.server.discovery.is_some() || !registry_entries.is_empty();
    let (router, server) = if has_discovery {
        let aid_record = cfg.server.discovery.as_ref().map(|discovery| {
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
            // Populate PKA field with root Ed25519 public key
            let pubkey_multibase = format!(
                "z{}",
                bs58::encode({
                    let mut bytes = vec![0xed, 0x01];
                    bytes.extend_from_slice(&root_signer.public_key_bytes());
                    bytes
                })
                .into_string()
            );
            aid["k"] = serde_json::json!(pubkey_multibase);
            aid["i"] = serde_json::json!("root-1");
            tracing::info!(
                url = %discovery.url,
                did = %root_signer.did(),
                "AID discovery at /.well-known/agent (with PKA)"
            );
            aid
        });
        let a2a_endpoint = cfg.server.discovery.as_ref().map(|d| d.url.clone());
        if a2a_endpoint.is_some() {
            tracing::info!("A2A Agent Card at /.well-known/agent.json");
        }
        let root_did_str = Some(root_signer.did().to_string());
        let api_server_ref = Arc::clone(&server);
        let router = smgglrs_core::transport::build_router_with_discovery(
            server, broadcaster, aid_record, registry_entries, a2a_endpoint, root_did_str,
        );
        (router, api_server_ref)
    } else {
        let api_server_ref = Arc::clone(&server);
        let router = smgglrs_core::transport::build_router_with_broadcaster(server, broadcaster);
        (router, api_server_ref)
    };

    // --- ACP (Agent Client Protocol) transport ---
    let acp_router = smgglrs_core::transport::build_acp_router(server.clone());
    let router = router.merge(acp_router);
    tracing::info!("ACP endpoint at POST /acp");

    // --- Web UI: shared state + API routes ---
    let router = ui::attach_ui_routes(router, &cfg, &server, &models);

    tracing::info!("Web UI at http://localhost:{}", cfg.server.tcp.as_deref().and_then(|a| a.rsplit(':').next()).unwrap_or("9315"));

    // Listen on Unix socket, TCP, or both
    if let Some(ref socket_path) = cfg.server.socket {
        let tcp_addr = cfg.server.tcp.clone();

        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(socket_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Remove stale socket file if it exists
        if std::path::Path::new(socket_path).exists() {
            std::fs::remove_file(socket_path)?;
        }

        let unix_listener = tokio::net::UnixListener::bind(socket_path)?;

        // Set socket permissions to owner-only (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        }

        tracing::info!("Listening on unix:{socket_path}");

        // Graceful shutdown on SIGTERM/SIGINT
        let shutdown = async {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ).expect("failed to install SIGTERM handler");
            #[cfg(unix)]
            tokio::select! {
                _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
                _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
            }
            #[cfg(not(unix))]
            ctrl_c.await.ok();
        };

        if let Some(addr) = tcp_addr {
            // Both Unix socket and TCP
            let tcp_listener = tokio::net::TcpListener::bind(&addr).await?;
            tracing::info!("Listening on tcp:{addr}");

            let tcp_router = router.clone();
            tokio::select! {
                result = axum::serve(unix_listener, router)
                    .with_graceful_shutdown(shutdown) => result?,
                result = axum::serve(tcp_listener, tcp_router) => result?,
            }
        } else {
            // Unix socket only
            axum::serve(unix_listener, router)
                .with_graceful_shutdown(shutdown).await?;
        }
    } else {
        // TCP only (fallback)
        let addr = cfg.server.listen_addr();
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!("Listening on tcp:{addr}");

        let shutdown = async {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ).expect("failed to install SIGTERM handler");
            #[cfg(unix)]
            tokio::select! {
                _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
                _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
            }
            #[cfg(not(unix))]
            ctrl_c.await.ok();
        };

        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown).await?;
    }

    // --- Stop runtime-served models ---
    for (runtime, endpoint) in &running_endpoints {
        tracing::info!(url = %endpoint.url, backend = ?endpoint.backend, "Stopping model runtime");
        if let Err(e) = runtime.stop(endpoint).await {
            tracing::error!(error = %e, "Failed to stop model runtime");
        }
    }

    Ok(())
}

/// Send an approve or deny request to the running server via JSON-RPC.
async fn approve_or_deny(addr: &str, request_id: &str, approve: bool) -> anyhow::Result<()> {
    let tool_name = if approve { "file_approve" } else { "file_deny" };
    let action = if approve { "Approved" } else { "Denied" };

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": tool_name,
            "arguments": {
                "request_id": request_id
            }
        }
    });

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Server returned {status}: {text}");
    }

    let result: serde_json::Value = resp.json().await?;
    if let Some(error) = result.get("error") {
        let msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("unknown");
        anyhow::bail!("Server error: {msg}");
    }

    println!("{action} request {request_id}");
    Ok(())
}

/// Query the running server for status via the initialize endpoint.
async fn query_status(addr: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 1,
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "smgglrs-cli",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let result: serde_json::Value = r.json().await?;
            if let Some(info) = result.get("result") {
                let name = info
                    .get("serverInfo")
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");
                let version = info
                    .get("serverInfo")
                    .and_then(|s| s.get("version"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let has_tools = info
                    .get("capabilities")
                    .and_then(|c| c.get("tools"))
                    .is_some();
                let has_prompts = info
                    .get("capabilities")
                    .and_then(|c| c.get("prompts"))
                    .is_some();
                let has_resources = info
                    .get("capabilities")
                    .and_then(|c| c.get("resources"))
                    .is_some();

                println!("Server: {name} v{version}");
                println!("Status: running");
                println!("Address: {addr}");
                println!(
                    "Capabilities: {}",
                    [
                        has_tools.then_some("tools"),
                        has_prompts.then_some("prompts"),
                        has_resources.then_some("resources"),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(", ")
                );
            }
        }
        Ok(r) => {
            println!("Server at {addr} returned {}", r.status());
        }
        Err(_) => {
            println!("Server at {addr} is not reachable.");
            println!("Is smgglrs running? Start it with: smgglrs serve");
        }
    }
    Ok(())
}

/// Install systemd user units for smgglrs.
fn install_systemd_units() -> anyhow::Result<()> {
    let unit_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?
        .join("systemd/user");
    std::fs::create_dir_all(&unit_dir)?;

    let service_content = include_str!("../systemd/smgglrs.service");
    let socket_content = include_str!("../systemd/smgglrs.socket");

    let service_path = unit_dir.join("smgglrs.service");
    let socket_path = unit_dir.join("smgglrs.socket");

    std::fs::write(&service_path, service_content)?;
    println!("Installed {}", service_path.display());

    std::fs::write(&socket_path, socket_content)?;
    println!("Installed {}", socket_path.display());

    // Reload systemd and enable
    let reload = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    if let Ok(status) = reload {
        if status.success() {
            println!("Reloaded systemd user daemon");
        }
    }

    let enable = std::process::Command::new("systemctl")
        .args(["--user", "enable", "smgglrs.service", "smgglrs.socket"])
        .status();
    if let Ok(status) = enable {
        if status.success() {
            println!("Enabled smgglrs.service and smgglrs.socket");
        }
    }

    println!("\nTo start now:  systemctl --user start smgglrs.service");
    println!("To check logs: journalctl --user -u smgglrs.service -f");
    Ok(())
}

/// Uninstall systemd user units for smgglrs.
fn uninstall_systemd_units() -> anyhow::Result<()> {
    // Stop and disable first
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "smgglrs.service", "smgglrs.socket"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "smgglrs.service", "smgglrs.socket"])
        .status();

    let unit_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?
        .join("systemd/user");

    let service_path = unit_dir.join("smgglrs.service");
    let socket_path = unit_dir.join("smgglrs.socket");

    if service_path.exists() {
        std::fs::remove_file(&service_path)?;
        println!("Removed {}", service_path.display());
    }
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
        println!("Removed {}", socket_path.display());
    }

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    println!("smgglrs systemd units uninstalled");
    Ok(())
}

/// Expand `~` to the user's home directory in a path string.
async fn run_agent(
    prompt: &str,
    model_name: Option<&str>,
    persona_name: &str,
    endpoint: &str,
    token: Option<&str>,
    max_iterations: usize,
    upstream_prompts: &[String],
) -> anyhow::Result<()> {
    // Auto-detect model from Ollama if not specified
    let model_name = if let Some(m) = model_name {
        m.to_string()
    } else {
        // Pick first available Ollama model
        let resp = reqwest::Client::new()
            .get("http://localhost:11434/api/tags")
            .send()
            .await
            .ok()
            .and_then(|r| futures_util::FutureExt::now_or_never(r.json::<serde_json::Value>()));
        match resp {
            Some(Ok(tags)) => {
                tags["models"].as_array()
                    .and_then(|m| m.first())
                    .and_then(|m| m["name"].as_str())
                    .unwrap_or("gemma4:26b")
                    .to_string()
            }
            _ => "gemma4:26b".to_string(),
        }
    };

    eprintln!("Model:    {model_name}");
    eprintln!("Persona:  {persona_name}");
    eprintln!("Endpoint: {endpoint}");
    eprintln!();

    // Build model backend
    let backend = smgglrs_model::OpenAiBackend::new(
        "http://localhost:11434/v1",
        &model_name,
        None,
        smgglrs_model::Locality::Local,
    );

    // Load persona if cognitive_core exists
    let forge = smgglrs_cognitive::ForgeService::load(std::path::Path::new("cognitive_core"))
        .ok()
        .or_else(|| {
            // Try common locations
            for p in ["../cognitive_core", "/etc/smgglrs/cognitive_core"] {
                if let Ok(f) = smgglrs_cognitive::ForgeService::load(std::path::Path::new(p)) {
                    return Some(f);
                }
            }
            None
        });

    // Build agent
    let mut builder = smgglrs_agent::Agent::builder()
        .endpoint(endpoint)
        .await?
        .model(backend)
        .max_iterations(max_iterations)
        .temperature(0.0)
        .max_tokens(8192)
        .force_tool_iterations(5)
        .non_progress_tools(vec![
            "team_status".to_string(),
            "team_result".to_string(),
            "team_bb_read".to_string(),
            "models_list".to_string(),
            "personas_list".to_string(),
            "flow_status".to_string(),
            "flow_result".to_string(),
        ]);

    // Apply auth token
    let auth_token = token
        .map(String::from)
        .or_else(|| std::env::var("MCPD_TOKEN").ok());
    if let Some(ref t) = auth_token {
        builder = builder.auth_token(t.clone());
    }

    // Parse --upstream-prompt flags into McpPromptRef entries
    let cli_prompt_refs: Vec<smgglrs_cognitive::McpPromptRef> = upstream_prompts
        .iter()
        .filter_map(|s| {
            let (upstream, prompt_name) = s.split_once(':')?;
            Some(smgglrs_cognitive::McpPromptRef {
                upstream: upstream.to_string(),
                prompt: prompt_name.to_string(),
                inject_position: smgglrs_cognitive::InjectPosition::AfterExamples,
                arguments: None,
            })
        })
        .collect();

    if !cli_prompt_refs.is_empty() {
        eprintln!("Upstream prompts: {}", cli_prompt_refs.len());
    }

    // Apply persona
    if let Some(ref forge) = forge {
        if forge.get_persona(persona_name).is_some() {
            let persona = forge.get_persona(persona_name).unwrap();

            // Check if this is an MCP-sourced persona
            let has_source = persona.source.is_some();

            // Collect persona-defined mcp_prompts and CLI-provided ones
            let all_refs: Vec<smgglrs_cognitive::McpPromptRef> = persona
                .mcp_prompts
                .iter()
                .cloned()
                .chain(cli_prompt_refs.iter().cloned())
                .collect();

            if has_source || !all_refs.is_empty() {
                // Need an MCP connection to resolve source and/or prompts
                let temp_upstream = if let Some(ref t) = auth_token {
                    smgglrs_agent::Upstream::http_with_auth("resolver", endpoint, t).await?
                } else {
                    smgglrs_agent::Upstream::http("resolver", endpoint).await?
                };
                let mut resolver_client = smgglrs_agent::McpClient::new(temp_upstream);

                if has_source {
                    // MCP-sourced persona: resolve source + mcp_prompts together
                    builder = builder
                        .persona_from_mcp(forge, persona_name, &mut resolver_client, prompt)
                        .await?;

                    // Also resolve any CLI-provided upstream prompts
                    if !cli_prompt_refs.is_empty() {
                        let extra_resolved = smgglrs_agent::resolve::resolve_mcp_prompts(
                            &mut resolver_client,
                            &cli_prompt_refs,
                            prompt,
                        )
                        .await?;

                        if !extra_resolved.is_empty() {
                            eprintln!("Resolved {} CLI upstream prompt(s)", extra_resolved.len());
                        }
                    }

                    eprintln!("Loaded MCP-sourced persona: {persona_name}");
                } else {
                    // Local persona with upstream prompts to resolve
                    let resolved = smgglrs_agent::resolve::resolve_mcp_prompts(
                        &mut resolver_client,
                        &all_refs,
                        prompt,
                    )
                    .await?;

                    if !resolved.is_empty() {
                        eprintln!("Resolved {} upstream prompt(s)", resolved.len());
                    }

                    builder = builder.persona_with_prompts(forge, persona_name, &resolved)?;
                }
            } else {
                builder = builder.persona(forge, persona_name)?;
            }

            eprintln!("Loaded persona: {persona_name}");
        }
    } else if !cli_prompt_refs.is_empty() {
        // No persona loaded but CLI prompts were specified — resolve and append
        let temp_upstream = if let Some(ref t) = auth_token {
            smgglrs_agent::Upstream::http_with_auth("resolver", endpoint, t).await?
        } else {
            smgglrs_agent::Upstream::http("resolver", endpoint).await?
        };
        let mut resolver_client = smgglrs_agent::McpClient::new(temp_upstream);

        let resolved = smgglrs_agent::resolve::resolve_mcp_prompts(
            &mut resolver_client,
            &cli_prompt_refs,
            prompt,
        )
        .await?;

        if !resolved.is_empty() {
            let extra = resolved
                .iter()
                .map(|rp| format!("## Upstream Prompt: {}\n\n{}", rp.label, rp.content))
                .collect::<Vec<_>>()
                .join("\n\n");

            builder = builder.system_prompt(extra);
            eprintln!("Resolved {} upstream prompt(s) (no persona)", resolved.len());
        }
    }

    let mut agent = builder.build().await?;

    // List tools
    let tools = agent.client().list_tools().await?;
    eprintln!("{} tools available", tools.len());
    eprintln!();

    // Run
    let start = std::time::Instant::now();
    match agent.run(prompt).await {
        Ok(result) => {
            // Print report to stdout (pipeable)
            println!("{}", result.response);

            // Print stats to stderr
            eprintln!();
            eprintln!("---");
            eprintln!("Iterations: {}", result.iterations);
            eprintln!("Tokens:     {} in + {} out", result.input_tokens, result.output_tokens);
            eprintln!("Time:       {:.1}s", start.elapsed().as_secs_f64());
            eprintln!("Taint:      {:?}", result.taint);
            eprintln!("Blackbox:   smgglrs audit");
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}

pub(crate) fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.display(), &path[1..]);
        }
    }
    path.to_string()
}

fn audit_command(limit: usize, detail: bool, agent: Option<String>, tool: Option<String>, verify: bool) -> anyhow::Result<()> {
    let bb_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("smgglrs/blackbox.db");
    if !bb_path.exists() {
        anyhow::bail!("No blackbox found at {}. Start the server first.", bb_path.display());
    }
    let bb = smgglrs_core::blackbox::Blackbox::open(&bb_path)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if verify {
        let (valid, broken) = bb.verify_chain();
        match broken {
            None => println!("Blackbox integrity: OK ({valid} entries, chain valid)"),
            Some(seq) => println!("Blackbox integrity: BROKEN at seq {seq} ({valid} valid entries before break)"),
        }
        return Ok(());
    }

    println!("Blackbox: {} ({} entries)\n", bb_path.display(), bb.count());

    let entries = bb.recent(limit);
    let filtered: Vec<_> = entries.iter().rev()
        .filter(|e| agent.as_ref().map_or(true, |a| e.agent_name == *a))
        .filter(|e| tool.as_ref().map_or(true, |t| e.tool_name == *t))
        .collect();

    if detail {
        for e in &filtered {
            println!("seq={} agent={} tool={} outcome={} duration={}us",
                e.seq, e.agent_name, e.tool_name, e.outcome, e.duration_us);
            let args_short = if e.tool_args.len() > 120 { &e.tool_args[..120] } else { &e.tool_args };
            let result_short = if e.tool_result.len() > 120 { &e.tool_result[..120] } else { &e.tool_result };
            println!("  args:   {}", args_short);
            println!("  result: {}", result_short);
            println!("  ifc:    {}", e.ifc_label);
            println!();
        }
    } else {
        println!("{:<6} {:<12} {:<12} {:<20} {:<8} {}", "SEQ", "AGENT", "OUTCOME", "TOOL", "US", "IFC");
        println!("{}", "-".repeat(80));
        for e in &filtered {
            let ifc_short = e.ifc_label
                .replace("DataLabel { integrity: ", "")
                .replace(", confidentiality: ", "/")
                .replace(" }", "");
            println!("{:<6} {:<12} {:<12} {:<20} {:<8} {}",
                e.seq, e.agent_name, e.outcome, e.tool_name, e.duration_us, ifc_short);
        }
    }

    println!("\n{} entries shown", filtered.len());
    Ok(())
}
